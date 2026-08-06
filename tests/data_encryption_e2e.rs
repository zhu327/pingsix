//! End-to-end test for field-level data encryption with encryption ENABLED.
//!
//! Covers the full logical round-trip that the review called for:
//!   Admin PUT (encrypt) → raw etcd confidentiality
//!     → GET/LIST view (decrypt-then-redact of the logical resource)
//!     → control-plane reload (decrypt back to plaintext).
//!
//! The process-wide keyring is a write-once global, so this lives in its own
//! integration binary where enabling encryption cannot poison other tests.

use pingsix::config::{init_data_encryption, transform_resource_secrets, SecretOp};
use pingsix::proxy::graph_mutation::{redact, restore_redacted_secrets, ResourceKind};

const ENVELOPE_SCHEME: &str = "$pingsix-enc:";

fn enable_encryption() {
    // First call wins; safe to call once per test binary.
    init_data_encryption(true, &["primary-key".into(), "previous-key".into()])
        .expect("keyring init must succeed");
}

fn is_ciphertext(v: &serde_json::Value) -> bool {
    v.as_str()
        .map(|s| s.starts_with(ENVELOPE_SCHEME))
        .unwrap_or(false)
}

#[test]
fn route_secret_lifecycle_encrypt_redact_reload() {
    enable_encryption();

    // What the user PUTs (plaintext).
    let plaintext = serde_json::json!({
        "id": "r1",
        "uri": "/",
        "plugins": {
            "basic-auth": { "username": "demo", "password": "s3cret" }
        },
        "upstream": {
            "nodes": { "127.0.0.1:443": 1 },
            "type": "roundrobin",
            "scheme": "https",
            "tls": {
                "client_cert": "cert-pem",
                "client_key": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----"
            }
        }
    });

    // 1) Admin PUT encrypts marked fields before storage.
    let mut stored = plaintext.clone();
    transform_resource_secrets("routes", &mut stored, SecretOp::Encrypt).unwrap();

    // Raw-etcd confidentiality: secrets are ciphertext; non-secrets untouched.
    assert!(is_ciphertext(&stored["plugins"]["basic-auth"]["password"]));
    assert!(is_ciphertext(&stored["upstream"]["tls"]["client_key"]));
    assert_ne!(stored["plugins"]["basic-auth"]["password"], "s3cret");
    assert_eq!(stored["plugins"]["basic-auth"]["username"], "demo");
    assert_eq!(stored["upstream"]["tls"]["client_cert"], "cert-pem");

    // 2) GET/LIST view: decrypt the logical resource, then redact secrets.
    let mut view = stored.clone();
    transform_resource_secrets("routes", &mut view, SecretOp::Decrypt).unwrap();
    let mut shown = view;
    redact(ResourceKind::Route, &mut shown);

    assert_eq!(shown["plugins"]["basic-auth"]["password"], "***");
    assert_eq!(shown["upstream"]["tls"]["client_key"], "***");
    assert_eq!(shown["plugins"]["basic-auth"]["username"], "demo");
    assert_eq!(shown["upstream"]["tls"]["client_cert"], "cert-pem");
    // No ciphertext may leak into the API response.
    assert!(!serde_json::to_string(&shown)
        .unwrap()
        .contains(ENVELOPE_SCHEME));

    // 3) Control-plane reload decrypts back to plaintext for the data plane.
    let mut reloaded = stored.clone();
    transform_resource_secrets("routes", &mut reloaded, SecretOp::Decrypt).unwrap();
    assert_eq!(reloaded["plugins"]["basic-auth"]["password"], "s3cret");
    assert_eq!(
        reloaded["upstream"]["tls"]["client_key"],
        plaintext["upstream"]["tls"]["client_key"]
    );
}

#[test]
fn ssl_key_lifecycle_encrypt_redact_reload() {
    enable_encryption();

    let plaintext = serde_json::json!({
        "id": "s1",
        "cert": "cert-pem",
        "key": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
        "snis": ["example.com"],
    });

    let mut stored = plaintext.clone();
    transform_resource_secrets("ssls", &mut stored, SecretOp::Encrypt).unwrap();
    assert!(is_ciphertext(&stored["key"]));
    assert_eq!(stored["cert"], "cert-pem");

    let mut view = stored.clone();
    transform_resource_secrets("ssls", &mut view, SecretOp::Decrypt).unwrap();
    let mut shown = view;
    redact(ResourceKind::Ssl, &mut shown);
    assert_eq!(shown["key"], "***");
    assert_eq!(shown["cert"], "cert-pem");
    assert!(!serde_json::to_string(&shown)
        .unwrap()
        .contains(ENVELOPE_SCHEME));

    let mut reloaded = stored.clone();
    transform_resource_secrets("ssls", &mut reloaded, SecretOp::Decrypt).unwrap();
    assert_eq!(reloaded["key"], plaintext["key"]);
}

/// Resaving a redacted GET body must not persist the `"***"` sentinel: the
/// admin PUT path restores untouched secrets from the stored resource before
/// validation/encryption.
#[test]
fn resaving_redacted_body_preserves_secret() {
    enable_encryption();

    let plaintext = serde_json::json!({
        "id": "s2",
        "cert": "cert-pem",
        "key": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
    });

    // Stored (encrypted) then read back as the redacted view a client would GET.
    let mut stored = plaintext.clone();
    transform_resource_secrets("ssls", &mut stored, SecretOp::Encrypt).unwrap();
    let mut view = stored.clone();
    transform_resource_secrets("ssls", &mut view, SecretOp::Decrypt).unwrap();
    let mut redacted_get = view;
    redact(ResourceKind::Ssl, &mut redacted_get);
    assert_eq!(redacted_get["key"], "***");

    // Client edits a non-secret and PUTs the redacted body back. Restoration
    // (driven by the stored plaintext) swaps the sentinel for the real key.
    let existing_plaintext = plaintext.clone();
    let mut resave = redacted_get;
    resave["cert"] = serde_json::json!("cert-pem-v2");
    restore_redacted_secrets(ResourceKind::Ssl, &mut resave, &existing_plaintext);

    assert_eq!(resave["key"], plaintext["key"]);
    assert_eq!(resave["cert"], "cert-pem-v2");
    assert_ne!(resave["key"], "***");
}

/// Migration-on-resave: a resource written to etcd while encryption was OFF is
/// still plaintext after encryption is turned ON (accepted, lazy migration).
/// Re-issuing the same request (resaving the redacted body) restores the secret
/// from the in-memory stored value and the write path encrypts it, so etcd
/// transitions plaintext -> ciphertext without the client re-entering the secret.
#[test]
fn plaintext_in_etcd_becomes_ciphertext_on_resave() {
    enable_encryption();

    // Written while encryption was disabled: raw etcd holds plaintext.
    let stored_plaintext = serde_json::json!({
        "id": "s3",
        "cert": "cert-pem",
        "key": "-----BEGIN PRIVATE KEY-----\nkey\n-----END PRIVATE KEY-----",
    });
    assert!(!is_ciphertext(&stored_plaintext["key"]));

    // GET with encryption now ON: decrypt-for-read is a no-op on plaintext,
    // then redaction masks the key.
    let mut view = stored_plaintext.clone();
    transform_resource_secrets("ssls", &mut view, SecretOp::Decrypt).unwrap();
    assert_eq!(view["key"], stored_plaintext["key"]);
    let mut redacted_get = view;
    redact(ResourceKind::Ssl, &mut redacted_get);
    assert_eq!(redacted_get["key"], "***");

    // Client resaves the redacted body verbatim. Restore pulls the still-plaintext
    // stored key back in (the "in-memory" value)...
    let mut resave = redacted_get;
    restore_redacted_secrets(ResourceKind::Ssl, &mut resave, &stored_plaintext);
    assert_eq!(resave["key"], stored_plaintext["key"]);

    // ...and the write path encrypts it: etcd now transitions to ciphertext.
    transform_resource_secrets("ssls", &mut resave, SecretOp::Encrypt).unwrap();
    assert!(is_ciphertext(&resave["key"]));

    // Round-trips back to the original secret on the next load.
    let mut reloaded = resave.clone();
    transform_resource_secrets("ssls", &mut reloaded, SecretOp::Decrypt).unwrap();
    assert_eq!(reloaded["key"], stored_plaintext["key"]);
}

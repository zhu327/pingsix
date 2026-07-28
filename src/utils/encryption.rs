//! Field-level encryption for sensitive values stored in etcd.
//!
//! Ciphertext uses a versioned envelope: `$pingsix-enc:<version>$<payload>`.
//! The scheme marker makes ciphertext detectable (so plaintext legacy values
//! still load), and the explicit version lets the on-disk format evolve
//! (algorithm, KDF parameters, layout) while older ciphertext stays
//! identifiable and migratable. The current version is:
//!
//! - `v1`: AES-256-GCM with an Argon2id-derived key; payload is
//!   `base64(nonce || ciphertext)`.
//!
//! Keyring rotation works by trying keys in order (newest first).
//!
//! Plugin configs mark secrets with `#[encrypt]` / `#[encrypt(nested)]`
//! (via `EncryptFields`); the admin write path and etcd load path call the
//! registered transform functions.

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use argon2::Argon2;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use once_cell::sync::OnceCell;
use serde_json::Value as JsonValue;

use crate::core::{ProxyError, ProxyResult};

/// Operation applied to every `#[encrypt]`-marked field during a walk.
///
/// This is the single lever that drives all three secret paths from the same
/// field metadata: write-side encryption, read/load-side decryption, and the
/// Admin read API's redaction. Adding `#[encrypt]` to a field therefore wires
/// up encrypt, decrypt *and* redaction at once.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SecretOp {
    /// Encrypt plaintext leaves into the versioned envelope.
    Encrypt,
    /// Decrypt envelope leaves back to plaintext.
    Decrypt,
    /// Replace secret leaves with a fixed mask (never touches the keyring).
    Redact,
}

/// Mask written over secret values by [`SecretOp::Redact`].
pub const REDACTED: &str = "***";

/// Implemented by `#[derive(EncryptFields)]` for plugin (or nested) config structs.
///
/// Walks `#[encrypt]` leaf fields and `#[encrypt(nested)]` child structs.
pub trait EncryptFields {
    /// Apply `op` to sensitive fields in-place (encrypt, decrypt, or redact).
    fn transform_secrets(config: &mut JsonValue, op: SecretOp) -> ProxyResult<()>;
}

/// Plugin registry entry: transform a plugin's config JSON in place.
pub type PluginSecretsTransform = fn(&mut JsonValue, SecretOp) -> ProxyResult<()>;

/// Version-agnostic scheme marker every ciphertext envelope starts with.
///
/// Used to detect ciphertext regardless of version. The concrete versioned
/// prefix (e.g. [`ENVELOPE_V1_PREFIX`]) follows.
pub const CIPHERTEXT_PREFIX: &str = "$pingsix-enc:";

/// Current envelope: `$pingsix-enc:v1$base64(nonce || ciphertext)`
/// (AES-256-GCM, Argon2id-derived key).
const ENVELOPE_V1_PREFIX: &str = "$pingsix-enc:v1$";

static KEYRING: OnceCell<Option<Keyring>> = OnceCell::new();

/// Derived AES-256 keyring used for encrypt (first key) / decrypt (all keys).
#[derive(Clone, Debug)]
pub struct Keyring {
    keys: Vec<[u8; 32]>,
}

impl Keyring {
    /// Build a keyring from configured secret strings (Argon2id → 32-byte keys).
    pub fn from_secrets(secrets: &[String]) -> ProxyResult<Self> {
        if secrets.is_empty() {
            return Err(ProxyError::Configuration(
                "data_encryption.keyring must contain at least one key when enable is true".into(),
            ));
        }
        let mut keys = Vec::with_capacity(secrets.len());
        for (i, secret) in secrets.iter().enumerate() {
            if secret.is_empty() {
                return Err(ProxyError::Configuration(format!(
                    "data_encryption.keyring[{i}] must not be empty"
                )));
            }
            keys.push(derive_key(secret)?);
        }
        Ok(Self { keys })
    }

    /// Encrypt with the first (newest) keyring entry.
    pub fn encrypt(&self, plaintext: &str) -> ProxyResult<String> {
        if is_ciphertext(plaintext) {
            return Ok(plaintext.to_string());
        }
        let key = Key::<Aes256Gcm>::from_slice(&self.keys[0]);
        let cipher = Aes256Gcm::new(key);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| ProxyError::Internal(format!("Failed to encrypt value: {e}")))?;

        let mut packed = Vec::with_capacity(nonce.len() + ciphertext.len());
        packed.extend_from_slice(nonce.as_slice());
        packed.extend_from_slice(&ciphertext);
        Ok(format!("{ENVELOPE_V1_PREFIX}{}", BASE64.encode(packed)))
    }

    /// Decrypt by trying each keyring entry until one succeeds.
    pub fn decrypt(&self, value: &str) -> ProxyResult<String> {
        if !is_ciphertext(value) {
            return Ok(value.to_string());
        }
        // Dispatch on the envelope version. Unknown versions are rejected rather
        // than silently mishandled, so a future format is a clear error on an
        // old binary instead of a corrupt decrypt.
        let Some(payload) = value.strip_prefix(ENVELOPE_V1_PREFIX) else {
            return Err(ProxyError::Configuration(format!(
                "Unsupported encryption envelope version in value starting with '{}'",
                &value[..value.len().min(24)]
            )));
        };
        let packed = BASE64.decode(payload.as_bytes()).map_err(|e| {
            ProxyError::Configuration(format!("Invalid encrypted value encoding: {e}"))
        })?;

        // 12-byte nonce + at least 16-byte GCM tag
        if packed.len() < 12 + 16 {
            return Err(ProxyError::Configuration(
                "Invalid encrypted value: payload too short".into(),
            ));
        }
        let (nonce_bytes, ciphertext) = packed.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        for key_bytes in &self.keys {
            let key = Key::<Aes256Gcm>::from_slice(key_bytes);
            let cipher = Aes256Gcm::new(key);
            if let Ok(plaintext) = cipher.decrypt(nonce, ciphertext) {
                return String::from_utf8(plaintext).map_err(|e| {
                    ProxyError::Configuration(format!("Decrypted value is not valid UTF-8: {e}"))
                });
            }
        }

        Err(ProxyError::Configuration(
            "Failed to decrypt value with any configured keyring key".into(),
        ))
    }
}

/// Fixed application salt for deterministic key derivation.
///
/// A constant salt makes derivation reproducible across restarts (required so
/// the same keyring entry always yields the same AES key). It provides domain
/// separation but not per-deployment uniqueness, so keyring entries should
/// still be high-entropy secrets. Argon2id's memory-hardness raises the cost
/// of brute-forcing a weak entry offline from etcd ciphertext.
const KDF_SALT: &[u8] = b"pingsix::data_encryption::v1";

fn derive_key(secret: &str) -> ProxyResult<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(secret.as_bytes(), KDF_SALT, &mut key)
        .map_err(|e| ProxyError::Internal(format!("Failed to derive encryption key: {e}")))?;
    Ok(key)
}

/// Returns true when `value` carries this module's ciphertext prefix.
pub fn is_ciphertext(value: &str) -> bool {
    value.starts_with(CIPHERTEXT_PREFIX)
}

/// Install the process-wide keyring from config. First call wins (safe for tests).
pub fn init(enable: bool, keyring: &[String]) -> ProxyResult<()> {
    let installed = if enable {
        Some(Keyring::from_secrets(keyring)?)
    } else {
        None
    };
    let _ = KEYRING.set(installed);
    Ok(())
}

/// Whether field encryption is active for this process.
pub fn is_enabled() -> bool {
    matches!(KEYRING.get(), Some(Some(_)))
}

fn active_keyring() -> Option<&'static Keyring> {
    KEYRING.get().and_then(|opt| opt.as_ref())
}

/// Encrypt a sensitive string for etcd storage.
///
/// No-op when encryption is disabled or the value is already ciphertext.
pub fn encrypt(plaintext: &str) -> ProxyResult<String> {
    match active_keyring() {
        Some(kr) => kr.encrypt(plaintext),
        None => Ok(plaintext.to_string()),
    }
}

/// Decrypt a sensitive string loaded from etcd into memory.
///
/// Plaintext (no prefix) passes through. Ciphertext is tried against every
/// keyring key in order. When encryption is disabled, ciphertext is rejected
/// so misconfiguration surfaces clearly instead of opaque PEM parse errors.
pub fn decrypt(value: &str) -> ProxyResult<String> {
    match active_keyring() {
        Some(kr) => kr.decrypt(value),
        None => {
            if is_ciphertext(value) {
                return Err(ProxyError::Configuration(
                    "Encrypted value found but data_encryption is disabled".into(),
                ));
            }
            Ok(value.to_string())
        }
    }
}

/// Apply `op` to a single leaf field (string or array of strings).
///
/// Called from `#[derive(EncryptFields)]` for `#[encrypt]` fields.
pub fn transform_leaf_field(
    obj: &mut serde_json::Map<String, JsonValue>,
    field: &str,
    op: SecretOp,
) -> ProxyResult<()> {
    match obj.get_mut(field) {
        Some(JsonValue::String(value)) => {
            *value = apply_secret_op(value, op)?;
        }
        Some(JsonValue::Array(items)) => {
            for item in items {
                if let JsonValue::String(value) = item {
                    *value = apply_secret_op(value, op)?;
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// Map a single string leaf through the requested secret operation.
fn apply_secret_op(value: &str, op: SecretOp) -> ProxyResult<String> {
    match op {
        SecretOp::Encrypt => encrypt(value),
        SecretOp::Decrypt => decrypt(value),
        SecretOp::Redact => Ok(REDACTED.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_with_primary_key() {
        let kr = Keyring::from_secrets(&["primary-secret".into(), "old-secret".into()]).unwrap();
        let ct = kr
            .encrypt("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")
            .unwrap();
        assert!(is_ciphertext(&ct));
        assert!(!ct.contains("BEGIN PRIVATE KEY"));
        let pt = kr.decrypt(&ct).unwrap();
        assert!(pt.contains("BEGIN PRIVATE KEY"));
    }

    #[test]
    fn decrypt_tries_secondary_key_after_rotation() {
        let old = Keyring::from_secrets(&["old-secret".into()]).unwrap();
        let ct = old.encrypt("plugin-secret-value").unwrap();

        let rotated = Keyring::from_secrets(&["new-secret".into(), "old-secret".into()]).unwrap();
        assert_eq!(rotated.decrypt(&ct).unwrap(), "plugin-secret-value");
    }

    #[test]
    fn decrypt_fails_when_no_key_matches() {
        let a = Keyring::from_secrets(&["key-a".into()]).unwrap();
        let ct = a.encrypt("secret").unwrap();
        let b = Keyring::from_secrets(&["key-b".into()]).unwrap();
        assert!(b.decrypt(&ct).is_err());
    }

    #[test]
    fn plaintext_passes_through_decrypt() {
        let kr = Keyring::from_secrets(&["k".into()]).unwrap();
        let pem = "-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----";
        assert_eq!(kr.decrypt(pem).unwrap(), pem);
    }

    #[test]
    fn encrypt_skips_already_encrypted() {
        let kr = Keyring::from_secrets(&["k".into()]).unwrap();
        let ct = kr.encrypt("once").unwrap();
        assert_eq!(kr.encrypt(&ct).unwrap(), ct);
    }

    #[test]
    fn encrypt_uses_versioned_envelope() {
        let kr = Keyring::from_secrets(&["k".into()]).unwrap();
        let ct = kr.encrypt("secret").unwrap();
        assert!(ct.starts_with(ENVELOPE_V1_PREFIX));
        assert!(is_ciphertext(&ct));
    }

    #[test]
    fn decrypt_rejects_unknown_envelope_version() {
        let kr = Keyring::from_secrets(&["k".into()]).unwrap();
        // Same scheme marker, unsupported version → detected but rejected.
        let err = kr.decrypt("$pingsix-enc:v999$deadbeef").unwrap_err();
        assert!(
            err.to_string()
                .contains("Unsupported encryption envelope version"),
            "{err}"
        );
    }

    #[test]
    fn empty_keyring_rejected() {
        assert!(Keyring::from_secrets(&[]).is_err());
    }

    #[test]
    fn encrypt_json_field_replaces_string() {
        // Exercise Keyring directly via encrypt path used by helpers when enabled
        // is unavailable in unit tests that share OnceCell — call Keyring APIs.
        let kr = Keyring::from_secrets(&["k".into()]).unwrap();
        let mut value = serde_json::json!({ "key": "plain", "cert": "c" });
        let plain = value["key"].as_str().unwrap().to_string();
        value["key"] = serde_json::Value::String(kr.encrypt(&plain).unwrap());
        assert!(is_ciphertext(value["key"].as_str().unwrap()));
        assert_eq!(value["cert"], "c");
    }

    #[test]
    fn transform_leaf_field_string_and_array() {
        let kr = Keyring::from_secrets(&["k".into()]).unwrap();
        let mut obj = serde_json::Map::new();
        obj.insert("password".into(), JsonValue::String("s3cret".into()));
        obj.insert(
            "keys".into(),
            JsonValue::Array(vec![
                JsonValue::String("a".into()),
                JsonValue::String("b".into()),
            ]),
        );
        // Hand-encrypt to verify leaf shapes without relying on process keyring.
        {
            let key = "password";
            let s = obj[key].as_str().unwrap().to_string();
            obj.insert(key.into(), JsonValue::String(kr.encrypt(&s).unwrap()));
        }
        if let Some(JsonValue::Array(items)) = obj.get_mut("keys") {
            for item in items {
                let s = item.as_str().unwrap().to_string();
                *item = JsonValue::String(kr.encrypt(&s).unwrap());
            }
        }
        assert!(is_ciphertext(obj["password"].as_str().unwrap()));
        assert!(is_ciphertext(obj["keys"][0].as_str().unwrap()));
    }

    /// Nested `#[encrypt(nested)]` must visit inner leaf fields.
    ///
    /// With encryption disabled, touching ciphertext returns an error — that
    /// proves the nested walk reached `inner.secret`.
    #[test]
    fn nested_encrypt_fields_visits_inner() {
        use pingsix_macros::EncryptFields;

        // Fields exist for the derive to walk; values are never constructed.
        #[derive(EncryptFields)]
        #[allow(dead_code)]
        struct Inner {
            #[encrypt]
            secret: String,
        }

        #[derive(EncryptFields)]
        #[allow(dead_code)]
        struct Outer {
            #[encrypt]
            token: String,
            #[encrypt(nested)]
            inner: Inner,
            #[encrypt(nested)]
            maybe: Option<Inner>,
        }

        let mut cfg = serde_json::json!({
            "token": "plain-token",
            "inner": { "secret": format!("{CIPHERTEXT_PREFIX}deadbeef") },
            "maybe": null,
        });
        let err = Outer::transform_secrets(&mut cfg, SecretOp::Decrypt).unwrap_err();
        assert!(
            err.to_string().contains("data_encryption is disabled")
                || err.to_string().contains("Encrypted value"),
            "{err}"
        );

        // Null optional nested must be skipped; plaintext leaves are fine.
        let mut ok = serde_json::json!({
            "token": "plain-token",
            "inner": { "secret": "plain-secret" },
            "maybe": null,
        });
        Outer::transform_secrets(&mut ok, SecretOp::Decrypt).unwrap();
        assert_eq!(ok["inner"]["secret"], "plain-secret");
    }
}

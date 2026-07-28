//! Runtime tests for `#[derive(EncryptFields)]`.
//!
//! The derive expands against `crate::utils::encryption` / `crate::core`, so this
//! integration test provides lightweight stubs and a deterministic `enc:` codec.

#![allow(dead_code)]

mod core {
    pub type ProxyResult<T> = Result<T, String>;
}

mod utils {
    pub mod encryption {
        use serde_json::Value;

        use crate::core::ProxyResult;

        #[derive(Clone, Copy, PartialEq, Eq)]
        pub enum SecretOp {
            Encrypt,
            Decrypt,
            Redact,
        }

        pub trait EncryptFields {
            fn transform_secrets(config: &mut Value, op: SecretOp) -> ProxyResult<()>;
        }

        pub type PluginSecretsTransform = fn(&mut Value, SecretOp) -> ProxyResult<()>;

        pub fn transform_leaf_field(
            obj: &mut serde_json::Map<String, Value>,
            field: &str,
            op: SecretOp,
        ) -> ProxyResult<()> {
            match obj.get_mut(field) {
                Some(Value::String(value)) => {
                    *value = transform_string(value, op);
                }
                Some(Value::Array(items)) => {
                    for item in items {
                        if let Value::String(value) = item {
                            *value = transform_string(value, op);
                        }
                    }
                }
                _ => {}
            }
            Ok(())
        }

        fn transform_string(value: &str, op: SecretOp) -> String {
            match op {
                SecretOp::Encrypt => {
                    if value.starts_with("enc:") {
                        value.to_string()
                    } else {
                        format!("enc:{value}")
                    }
                }
                SecretOp::Decrypt => value.strip_prefix("enc:").unwrap_or(value).to_string(),
                SecretOp::Redact => "***".to_string(),
            }
        }
    }
}

use pingsix_macros::EncryptFields;
use serde::Deserialize;
use utils::encryption::{EncryptFields, SecretOp};

#[derive(EncryptFields)]
struct LeafConfig {
    username: String,
    #[encrypt]
    password: String,
}

#[derive(EncryptFields)]
struct ArrayConfig {
    #[encrypt]
    keys: Vec<String>,
}

#[derive(EncryptFields)]
struct Credentials {
    #[encrypt]
    password: String,
}

#[derive(EncryptFields)]
#[encrypt_fields(export)]
struct NestedConfig {
    #[encrypt]
    api_key: String,
    #[encrypt(nested)]
    credentials: Credentials,
    #[encrypt(nested)]
    optional: Option<Credentials>,
}

#[derive(Deserialize, EncryptFields)]
struct RenamedConfig {
    #[encrypt]
    #[serde(rename = "pass")]
    password: String,
}

#[derive(Deserialize, EncryptFields)]
#[serde(rename_all = "camelCase")]
struct RenameAllConfig {
    #[encrypt]
    api_key: String,
    // Field-level rename still wins over container rename_all.
    #[encrypt]
    #[serde(rename = "pw")]
    pass_word: String,
}

#[test]
fn leaf_encrypt_decrypt_round_trip() {
    let mut cfg = serde_json::json!({
        "username": "demo",
        "password": "s3cret",
    });
    LeafConfig::transform_secrets(&mut cfg, SecretOp::Encrypt).unwrap();
    assert_eq!(cfg["username"], "demo");
    assert_eq!(cfg["password"], "enc:s3cret");

    LeafConfig::transform_secrets(&mut cfg, SecretOp::Decrypt).unwrap();
    assert_eq!(cfg["password"], "s3cret");
}

#[test]
fn string_array_encrypts_each_element() {
    let mut cfg = serde_json::json!({ "keys": ["a", "b"] });
    ArrayConfig::transform_secrets(&mut cfg, SecretOp::Encrypt).unwrap();
    assert_eq!(cfg["keys"], serde_json::json!(["enc:a", "enc:b"]));

    ArrayConfig::transform_secrets(&mut cfg, SecretOp::Decrypt).unwrap();
    assert_eq!(cfg["keys"], serde_json::json!(["a", "b"]));
}

#[test]
fn nested_and_optional_nested() {
    let mut cfg = serde_json::json!({
        "api_key": "k",
        "credentials": { "password": "p" },
        "optional": null,
    });
    NestedConfig::transform_secrets(&mut cfg, SecretOp::Encrypt).unwrap();
    assert_eq!(cfg["api_key"], "enc:k");
    assert_eq!(cfg["credentials"]["password"], "enc:p");
    assert!(cfg["optional"].is_null());

    let mut with_opt = serde_json::json!({
        "api_key": "k",
        "credentials": { "password": "p" },
        "optional": { "password": "q" },
    });
    NestedConfig::transform_secrets(&mut with_opt, SecretOp::Encrypt).unwrap();
    assert_eq!(with_opt["optional"]["password"], "enc:q");
}

#[test]
fn export_emits_module_level_secrets_transform() {
    let mut via_const = serde_json::json!({
        "api_key": "k",
        "credentials": { "password": "p" },
        "optional": null,
    });
    let mut via_trait = via_const.clone();
    (SECRETS_TRANSFORM)(&mut via_const, SecretOp::Encrypt).unwrap();
    NestedConfig::transform_secrets(&mut via_trait, SecretOp::Encrypt).unwrap();
    assert_eq!(via_const, via_trait);
    assert_eq!(via_const["api_key"], "enc:k");
    assert_eq!(via_const["credentials"]["password"], "enc:p");
}

#[test]
fn serde_rename_uses_json_key() {
    let mut cfg = serde_json::json!({ "pass": "secret" });
    RenamedConfig::transform_secrets(&mut cfg, SecretOp::Encrypt).unwrap();
    assert_eq!(cfg["pass"], "enc:secret");
    assert!(cfg.get("password").is_none());
}

#[test]
fn rename_all_maps_field_to_wire_key() {
    let mut cfg = serde_json::json!({ "apiKey": "k", "pw": "s" });
    RenameAllConfig::transform_secrets(&mut cfg, SecretOp::Encrypt).unwrap();
    assert_eq!(cfg["apiKey"], "enc:k");
    assert_eq!(cfg["pw"], "enc:s");
    // The snake_case idents must not be treated as wire keys.
    assert!(cfg.get("api_key").is_none());
    assert!(cfg.get("pass_word").is_none());
}

#[test]
fn encrypt_is_idempotent_on_already_marked_values() {
    let mut cfg = serde_json::json!({ "password": "enc:s3cret", "username": "u" });
    LeafConfig::transform_secrets(&mut cfg, SecretOp::Encrypt).unwrap();
    assert_eq!(cfg["password"], "enc:s3cret");
}

#[test]
fn redact_masks_marked_leaves_only() {
    let mut cfg = serde_json::json!({ "username": "demo", "password": "s3cret" });
    LeafConfig::transform_secrets(&mut cfg, SecretOp::Redact).unwrap();
    assert_eq!(cfg["username"], "demo");
    assert_eq!(cfg["password"], "***");

    let mut arr = serde_json::json!({ "keys": ["a", "b"] });
    ArrayConfig::transform_secrets(&mut arr, SecretOp::Redact).unwrap();
    assert_eq!(arr["keys"], serde_json::json!(["***", "***"]));
}

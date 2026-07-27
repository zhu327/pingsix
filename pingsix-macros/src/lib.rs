//! Derive macros for Pingsix.
//!
//! `EncryptFields` walks struct fields marked with `#[encrypt]` /
//! `#[encrypt(nested)]` so the runtime can encrypt/decrypt those JSON values
//! when persisting plugin config to etcd.
//!
//! Add `#[encrypt_fields(export)]` on the **root** config struct to emit a
//! module-level `SECRETS_TRANSFORM` for `PLUGIN_ENCRYPT_FIELDS` registration.

use proc_macro::TokenStream;
use quote::quote;
use syn::{
    parse_macro_input, Data, DeriveInput, Error, Fields, GenericArgument, PathArguments, Result,
    Type,
};

/// Derive `EncryptFields` for a config struct (plugin root or nested).
///
/// - `#[encrypt]` — encrypt this string (or string-array) field
/// - `#[encrypt(nested)]` — recurse into a nested struct that also derives
///   `EncryptFields` (supports `Option<T>` and plain `T`)
/// - `#[encrypt_fields(export)]` on the struct — emit module-level
///   `pub(crate) const SECRETS_TRANSFORM` (use once per module, on the root)
///
/// ```ignore
/// #[derive(EncryptFields)]
/// struct Credentials {
///     #[encrypt]
///     password: String,
/// }
///
/// #[derive(EncryptFields)]
/// #[encrypt_fields(export)]
/// struct PluginConfig {
///     #[encrypt]
///     api_key: String,
///     #[encrypt(nested)]
///     credentials: Credentials,
/// }
/// // → pub(crate) const SECRETS_TRANSFORM: PluginSecretsTransform = ...;
/// ```
#[proc_macro_derive(EncryptFields, attributes(encrypt, encrypt_fields))]
pub fn derive_encrypt_fields(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as DeriveInput);
    match expand_encrypt_fields(&input) {
        Ok(tokens) => tokens.into(),
        Err(err) => err.to_compile_error().into(),
    }
}

enum EncryptKind {
    /// Leaf string / string-array at this JSON key.
    Leaf,
    /// Nested object that implements `EncryptFields`.
    Nested { ty: Box<Type> },
    /// Map of `plugin name -> config` (e.g. a resource's `plugins`); each entry
    /// is transformed via the `PLUGIN_ENCRYPT_FIELDS` registry.
    Plugins,
}

fn expand_encrypt_fields(input: &DeriveInput) -> Result<proc_macro2::TokenStream> {
    let name = &input.ident;
    let export = parse_export_attr(input)?;
    let rename_all = parse_rename_all(input)?;
    let fields = match &input.data {
        Data::Struct(data) => match &data.fields {
            Fields::Named(named) => &named.named,
            _ => {
                return Err(Error::new_spanned(
                    name,
                    "EncryptFields only supports structs with named fields",
                ))
            }
        },
        _ => {
            return Err(Error::new_spanned(
                name,
                "EncryptFields can only be derived for structs",
            ))
        }
    };

    let mut transform_stmts = Vec::new();
    for field in fields {
        let Some(kind) = parse_encrypt_attr(field)? else {
            continue;
        };
        let ident = field
            .ident
            .as_ref()
            .ok_or_else(|| Error::new_spanned(field, "EncryptFields requires named fields"))?;
        let json_name = serde_rename(field)
            .or_else(|| rename_all.map(|rule| rule.apply(&ident.to_string())))
            .unwrap_or_else(|| ident.to_string());

        match kind {
            EncryptKind::Leaf => {
                transform_stmts.push(quote! {
                    crate::utils::encryption::transform_leaf_field(
                        __obj,
                        #json_name,
                        __encrypting,
                    )?;
                });
            }
            EncryptKind::Nested { ty } => {
                let inner_ty = unwrap_option(&ty).unwrap_or(&ty);
                transform_stmts.push(quote! {
                    if let Some(__nested) = __obj.get_mut(#json_name) {
                        if !__nested.is_null() {
                            <#inner_ty as crate::utils::encryption::EncryptFields>::transform_secrets(
                                __nested,
                                __encrypting,
                            )?;
                        }
                    }
                });
            }
            EncryptKind::Plugins => {
                transform_stmts.push(quote! {
                    if let Some(__plugins) = __obj.get_mut(#json_name) {
                        if let Some(__map) = __plugins.as_object_mut() {
                            for (__name, __cfg) in __map.iter_mut() {
                                if let Some(__transform) =
                                    crate::plugins::PLUGIN_ENCRYPT_FIELDS.get(__name.as_str())
                                {
                                    __transform(__cfg, __encrypting)?;
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    let export_tokens = if export {
        quote! {
            /// Module-level `fn` pointer for `PLUGIN_ENCRYPT_FIELDS`.
            ///
            /// Emitted by `#[encrypt_fields(export)]`
            pub(crate) const SECRETS_TRANSFORM: crate::utils::encryption::PluginSecretsTransform =
                <#name as crate::utils::encryption::EncryptFields>::transform_secrets;
        }
    } else {
        quote! {}
    };

    Ok(quote! {
        impl crate::utils::encryption::EncryptFields for #name {
            fn transform_secrets(
                config: &mut serde_json::Value,
                encrypting: bool,
            ) -> crate::core::ProxyResult<()> {
                let Some(__obj) = config.as_object_mut() else {
                    return Ok(());
                };
                let __encrypting = encrypting;
                #(#transform_stmts)*
                Ok(())
            }
        }

        #export_tokens
    })
}

/// `#[encrypt_fields(export)]` on the struct → emit module-level `SECRETS_TRANSFORM`.
fn parse_export_attr(input: &DeriveInput) -> Result<bool> {
    let mut export = false;
    for attr in &input.attrs {
        if !attr.path().is_ident("encrypt_fields") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("export") {
                export = true;
                Ok(())
            } else {
                Err(meta
                    .error("unsupported encrypt_fields attribute; use #[encrypt_fields(export)]"))
            }
        })?;
    }
    Ok(export)
}

/// Container-level `#[serde(rename_all = "...")]` conventions.
///
/// Field idents are assumed snake_case (Rust convention), matching how serde
/// derives the wire name so the encrypt/decrypt walk hits the right JSON key.
#[derive(Clone, Copy)]
enum RenameRule {
    Lower,
    Upper,
    Pascal,
    Camel,
    Snake,
    ScreamingSnake,
    Kebab,
    ScreamingKebab,
}

impl RenameRule {
    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "lowercase" => RenameRule::Lower,
            "UPPERCASE" => RenameRule::Upper,
            "PascalCase" => RenameRule::Pascal,
            "camelCase" => RenameRule::Camel,
            "snake_case" => RenameRule::Snake,
            "SCREAMING_SNAKE_CASE" => RenameRule::ScreamingSnake,
            "kebab-case" => RenameRule::Kebab,
            "SCREAMING-KEBAB-CASE" => RenameRule::ScreamingKebab,
            _ => return None,
        })
    }

    /// Mirror serde's `RenameRule::apply_to_field` for a snake_case ident.
    fn apply(&self, field: &str) -> String {
        match self {
            RenameRule::Lower | RenameRule::Snake => field.to_owned(),
            RenameRule::Upper | RenameRule::ScreamingSnake => field.to_ascii_uppercase(),
            RenameRule::Pascal => pascal_case(field),
            RenameRule::Camel => {
                let pascal = pascal_case(field);
                let mut chars = pascal.chars();
                match chars.next() {
                    Some(first) => first.to_ascii_lowercase().to_string() + chars.as_str(),
                    None => pascal,
                }
            }
            RenameRule::Kebab => field.replace('_', "-"),
            RenameRule::ScreamingKebab => field.to_ascii_uppercase().replace('_', "-"),
        }
    }
}

fn pascal_case(field: &str) -> String {
    let mut out = String::with_capacity(field.len());
    let mut capitalize = true;
    for ch in field.chars() {
        if ch == '_' {
            capitalize = true;
        } else if capitalize {
            out.push(ch.to_ascii_uppercase());
            capitalize = false;
        } else {
            out.push(ch);
        }
    }
    out
}

/// Read container-level `#[serde(rename_all = "...")]` so encrypted field keys
/// match serde's wire format. Unknown rename rules are a compile error.
fn parse_rename_all(input: &DeriveInput) -> Result<Option<RenameRule>> {
    let mut rule = None;
    for attr in &input.attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("rename_all") {
                let value: syn::LitStr = meta.value()?.parse()?;
                match RenameRule::from_str(&value.value()) {
                    Some(parsed) => rule = Some(parsed),
                    None => {
                        return Err(meta.error(format!(
                            "EncryptFields does not support serde rename_all = \"{}\"",
                            value.value()
                        )))
                    }
                }
            } else if meta.input.peek(syn::Token![=]) {
                let _: syn::Expr = meta.value()?.parse()?;
            }
            Ok(())
        })?;
    }
    Ok(rule)
}

fn parse_encrypt_attr(field: &syn::Field) -> Result<Option<EncryptKind>> {
    let mut found = None;
    for attr in &field.attrs {
        if !attr.path().is_ident("encrypt") {
            continue;
        }
        if found.is_some() {
            return Err(Error::new_spanned(
                attr,
                "duplicate #[encrypt] attribute on field",
            ));
        }
        // Bare `#[encrypt]` → leaf. `#[encrypt(nested)]` → nested.
        if matches!(attr.meta, syn::Meta::Path(_)) {
            found = Some(EncryptKind::Leaf);
            continue;
        }
        let mut modifier: Option<&'static str> = None;
        attr.parse_nested_meta(|meta| {
            if meta.path.is_ident("nested") {
                modifier = Some("nested");
                Ok(())
            } else if meta.path.is_ident("plugins") {
                modifier = Some("plugins");
                Ok(())
            } else {
                Err(meta.error(
                    "unsupported encrypt attribute; use #[encrypt], #[encrypt(nested)] or #[encrypt(plugins)]",
                ))
            }
        })?;
        found = Some(match modifier {
            Some("nested") => EncryptKind::Nested {
                ty: Box::new(field.ty.clone()),
            },
            Some("plugins") => EncryptKind::Plugins,
            _ => EncryptKind::Leaf,
        });
    }
    Ok(found)
}

/// `Option<T>` → `Some(T)`, otherwise `None`.
fn unwrap_option(ty: &Type) -> Option<&Type> {
    let Type::Path(path) = ty else {
        return None;
    };
    let seg = path.path.segments.last()?;
    if seg.ident != "Option" {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &seg.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        GenericArgument::Type(inner) => Some(inner),
        _ => None,
    })
}

/// Read `#[serde(rename = "name")]` when present so JSON paths match wire format.
fn serde_rename(field: &syn::Field) -> Option<String> {
    for attr in &field.attrs {
        if !attr.path().is_ident("serde") {
            continue;
        }
        let mut renamed = None;
        if attr
            .parse_nested_meta(|meta| {
                if meta.path.is_ident("rename") {
                    let value: syn::LitStr = meta.value()?.parse()?;
                    renamed = Some(value.value());
                } else if meta.input.peek(syn::Token![=]) {
                    let _: syn::Expr = meta.value()?.parse()?;
                }
                Ok(())
            })
            .is_ok()
        {
            if let Some(name) = renamed {
                return Some(name);
            }
        }
    }
    None
}

use std::sync::Arc;

use async_trait::async_trait;
use log;
use matchit::Router as MatchRouter;
use pingora::listeners::TlsAccept;
use pingora::tls::ext;
use pingora::tls::pkey::PKey;
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use pingora_error::Result;

use crate::{
    config::{self, Identifiable},
    core::ProxyError,
};

use super::runtime::RuntimeStore;

static DEFAULT_SERVER_NAME: &str = "*";

/// Proxy SSL.
pub struct ProxySSL {
    pub inner: config::SSL,
    // Store parsed leaf cert, intermediate chain, and private key, handling
    // parsing errors during creation/update.
    parsed_cert: X509,
    parsed_chain: Vec<X509>,
    parsed_key: PKey<pingora::tls::pkey::Private>,
}

impl TryFrom<config::SSL> for ProxySSL {
    type Error = ProxyError;

    fn try_from(value: config::SSL) -> std::result::Result<Self, Self::Error> {
        for sni in &value.snis {
            let wildcard_count = sni.bytes().filter(|b| *b == b'*').count();
            let valid_wildcard = sni == "*"
                || (wildcard_count == 1
                    && sni.starts_with("*.")
                    && sni.len() > 2
                    && !sni[2..].starts_with('.')
                    && !sni.ends_with('.'));
            if wildcard_count > 0 && !valid_wildcard {
                return Err(ProxyError::Configuration(format!(
                    "Unsupported TLS wildcard SNI '{sni}' for '{}'; use '*' or '*.example.com'",
                    value.id
                )));
            }
        }

        let mut cert_chain = X509::stack_from_pem(value.cert.as_bytes()).map_err(|e| {
            ProxyError::Configuration(format!("Failed to parse cert for '{}': {e}", value.id))
        })?;
        if cert_chain.is_empty() {
            return Err(ProxyError::Configuration(format!(
                "No certificates found in cert PEM for '{}'",
                value.id
            )));
        }
        let parsed_cert = cert_chain.remove(0);
        let parsed_chain = cert_chain;
        let parsed_key = PKey::private_key_from_pem(value.key.as_bytes()).map_err(|e| {
            ProxyError::Configuration(format!("Failed to parse key for '{}': {e}", value.id))
        })?;

        if !parsed_cert
            .public_key()
            .map_err(|e| {
                ProxyError::Configuration(format!(
                    "Failed to read certificate public key for '{}': {e}",
                    value.id
                ))
            })?
            .public_eq(&parsed_key)
        {
            return Err(ProxyError::Configuration(format!(
                "TLS certificate and private key do not match for '{}'",
                value.id
            )));
        }

        Ok(Self {
            inner: value,
            parsed_cert,
            parsed_chain,
            parsed_key,
        })
    }
}

impl Identifiable for ProxySSL {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxySSL {
    /// Gets the list of SNIs for the SSL.
    fn get_snis(&self) -> &[String] {
        &self.inner.snis
    }
}

/// TLS SNI matcher.
///
/// Wildcard SNI patterns (`*.example.com`) match exactly **one** DNS label,
/// mirroring standard certificate wildcard semantics (RFC 6125): a request
/// for `a.b.example.com` does NOT match a `*.example.com` certificate. HTTP
/// route host wildcards intentionally keep broader (multi-label) semantics;
/// that is a separate product decision and lives in `route.rs`.
#[derive(Default)]
pub struct MatchEntry {
    /// Exact (non-wildcard) SNI hosts, stored reversed so matchit matches by
    /// suffix. An exact entry always beats any wildcard.
    snis: MatchRouter<Arc<ProxySSL>>,
    /// `*.suffix` wildcards. Sorted longest-suffix-first at build time so the
    /// most specific match wins. Each matches a single label in front of
    /// `suffix`.
    wildcards: Vec<(String, Arc<ProxySSL>)>,
    /// Bare `*` catch-all, matching any SNI. Lower priority than exact and any
    /// concrete wildcard.
    catch_all: Option<Arc<ProxySSL>>,
}

impl MatchEntry {
    pub(crate) fn build(
        ssls: &std::collections::HashMap<String, Arc<ProxySSL>>,
    ) -> std::result::Result<Self, ProxyError> {
        let mut matcher = Self::default();
        for ssl in ssls.values() {
            matcher.insert_ssl(ssl.clone())?;
        }
        // Longest suffix first so the most specific wildcard wins.
        matcher
            .wildcards
            .sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));
        Ok(matcher)
    }

    /// Inserts an SSL into the match entry.
    ///
    /// Supports wildcard SNI patterns (`*.example.com`), which match exactly
    /// one DNS label, plus the explicit bare `*` catch-all. Unsupported forms
    /// are rejected while constructing [`ProxySSL`]. Duplicate patterns are
    /// rejected here so certificate selection is deterministic.
    fn insert_ssl(&mut self, proxy_ssl: Arc<ProxySSL>) -> Result<(), ProxyError> {
        for sni in proxy_ssl.get_snis() {
            let normalized = sni.to_ascii_lowercase();
            if normalized == "*" {
                if self.catch_all.is_some() {
                    return Err(ProxyError::Configuration(
                        "Duplicate TLS catch-all SNI '*'".to_string(),
                    ));
                }
                self.catch_all = Some(proxy_ssl.clone());
                continue;
            }
            if let Some(suffix) = normalized.strip_prefix("*.") {
                if self
                    .wildcards
                    .iter()
                    .any(|(existing, _)| existing == suffix)
                {
                    return Err(ProxyError::Configuration(format!(
                        "Duplicate TLS wildcard SNI '*.{suffix}'"
                    )));
                }
                self.wildcards.push((suffix.to_string(), proxy_ssl.clone()));
                continue;
            }
            let reversed: String = normalized.chars().rev().collect();
            self.snis
                .insert(reversed, proxy_ssl.clone())
                .map_err(|error| {
                    ProxyError::Configuration(format!(
                        "Failed to insert TLS SNI '{sni}' for '{}': {error}",
                        proxy_ssl.inner.id
                    ))
                })?;
        }

        Ok(())
    }

    /// Matches an SNI to an SSL (ASCII case-insensitive).
    pub(crate) fn match_sni(&self, sni: &str) -> Option<Arc<ProxySSL>> {
        let normalized = sni.to_ascii_lowercase();

        log::debug!("match sni: {sni:?}");

        // 1. Exact SNI (reversed, case-insensitive).
        let reversed: String = normalized.chars().rev().collect();
        if let Ok(v) = self.snis.at(&reversed) {
            return Some(v.value.clone());
        }

        // 2. Single-label wildcard, most specific first.
        for (suffix, ssl) in &self.wildcards {
            if Self::host_matches_wildcard(&normalized, suffix) {
                return Some(ssl.clone());
            }
        }

        // 3. Bare `*` catch-all.
        self.catch_all.clone()
    }

    /// True when `host` is exactly `<one-label>.<suffix>` with a single label
    /// before the suffix. `api.example.com` matches `*.example.com`;
    /// `a.b.example.com` and `example.com` do not.
    fn host_matches_wildcard(host: &str, suffix: &str) -> bool {
        if suffix.is_empty() {
            return !host.is_empty() && !host.contains('.');
        }
        let Some(prefix) = host.strip_suffix(suffix) else {
            return false;
        };
        let Some(label) = prefix.strip_suffix('.') else {
            return false;
        };
        !label.is_empty() && !label.contains('.')
    }
}

pub struct DynamicCert {
    default: Arc<ProxySSL>,
    runtime: Arc<RuntimeStore>,
}

impl DynamicCert {
    pub fn new(tls: &config::Tls, runtime: Arc<RuntimeStore>) -> Result<Box<Self>, ProxyError> {
        let cert_bytes = std::fs::read(&tls.cert_path).map_err(|e| {
            ProxyError::Configuration(format!(
                "Failed to read TLS certificate file '{}': {}",
                tls.cert_path, e
            ))
        })?;

        let key_bytes = std::fs::read(&tls.key_path).map_err(|e| {
            ProxyError::Configuration(format!(
                "Failed to read TLS private key file '{}': {}",
                tls.key_path, e
            ))
        })?;

        let ssl_config = config::SSL {
            id: String::new(),
            cert: String::from_utf8(cert_bytes).map_err(|e| {
                ProxyError::Configuration(format!(
                    "Failed to convert certificate bytes to UTF-8 string: {e}"
                ))
            })?,
            key: String::from_utf8(key_bytes).map_err(|e| {
                ProxyError::Configuration(format!(
                    "Failed to convert private key bytes to UTF-8 string: {e}"
                ))
            })?,
            snis: Vec::new(),
        };

        let proxy_ssl = ProxySSL::try_from(ssl_config)?;
        Ok(Box::new(Self {
            default: Arc::new(proxy_ssl),
            runtime,
        }))
    }
}

#[async_trait]
impl TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or(DEFAULT_SERVER_NAME);

        let runtime = self.runtime.load();
        let proxy_ssl = runtime
            .ssl_matcher
            .match_sni(sni)
            .unwrap_or_else(|| self.default.clone());

        if let Err(e) = ext::ssl_use_certificate(ssl, &proxy_ssl.parsed_cert) {
            log::error!("Failed to use certificate: {e}");
        }
        for chain_cert in &proxy_ssl.parsed_chain {
            if let Err(e) = ext::ssl_add_chain_cert(ssl, chain_cert) {
                log::error!("Failed to add intermediate certificate to chain: {e}");
            }
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &proxy_ssl.parsed_key) {
            log::error!("Failed to use private key: {e}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SSL;
    use std::sync::Arc;

    const CERT: &str = include_str!("testdata/example.crt");
    const KEY: &str = include_str!("testdata/example.key");
    const OTHER_KEY: &str = include_str!("testdata/other.key");

    #[test]
    fn sni_key_normalization_lowercases() {
        let input = "API.Example.COM";
        let normalized = input.to_ascii_lowercase();
        assert_eq!(normalized, "api.example.com");
        let reversed: String = normalized.chars().rev().collect();
        assert_eq!(reversed, "moc.elpmaxe.ipa");
    }

    #[test]
    fn invalid_cert_pem_is_rejected() {
        let ssl = SSL {
            id: "bad".into(),
            cert: "not-a-cert".into(),
            key: "not-a-key".into(),
            snis: vec!["example.com".into()],
        };
        assert!(ProxySSL::try_from(ssl).is_err());
    }

    #[test]
    fn cert_key_mismatch_is_rejected() {
        let ssl = SSL {
            id: "mismatch".into(),
            cert: CERT.into(),
            key: OTHER_KEY.into(),
            snis: vec!["example.com".into()],
        };
        match ProxySSL::try_from(ssl) {
            Err(e) => assert!(e.to_string().contains("do not match"), "{e}"),
            Ok(_) => panic!("expected cert/key mismatch error"),
        }
    }

    #[test]
    fn matching_cert_key_accepted_and_sni_is_case_insensitive() {
        let ssl = SSL {
            id: "ok".into(),
            cert: CERT.into(),
            key: KEY.into(),
            snis: vec!["Example.COM".into()],
        };
        let proxy = Arc::new(ProxySSL::try_from(ssl).unwrap());
        let mut matcher = MatchEntry::default();
        matcher.insert_ssl(proxy).unwrap();
        assert!(matcher.match_sni("example.com").is_some());
        assert!(matcher.match_sni("EXAMPLE.COM").is_some());
        assert!(matcher.match_sni("other.com").is_none());
    }

    fn ssl_for(sni: &str) -> Arc<ProxySSL> {
        Arc::new(
            ProxySSL::try_from(SSL {
                id: sni.into(),
                cert: CERT.into(),
                key: KEY.into(),
                snis: vec![sni.into()],
            })
            .unwrap(),
        )
    }

    #[test]
    fn wildcard_matches_exactly_one_label() {
        let mut matcher = MatchEntry::default();
        matcher.insert_ssl(ssl_for("*.example.com")).unwrap();

        assert!(matcher.match_sni("api.example.com").is_some());
        // Wildcard must NOT match the bare suffix (no label in front).
        assert!(matcher.match_sni("example.com").is_none());
        // Standard certificate wildcards cover exactly one label.
        assert!(matcher.match_sni("a.b.example.com").is_none());
        assert!(matcher.match_sni("api.other.com").is_none());
    }

    #[test]
    fn exact_sni_beats_wildcard() {
        let mut matcher = MatchEntry::default();
        matcher.insert_ssl(ssl_for("*.example.com")).unwrap();
        matcher.insert_ssl(ssl_for("api.example.com")).unwrap();

        let matched = matcher.match_sni("api.example.com").unwrap();
        assert_eq!(matched.inner.id, "api.example.com");
    }

    #[test]
    fn longer_wildcard_suffix_wins() {
        let mut matcher = MatchEntry::default();
        matcher.insert_ssl(ssl_for("*.com")).unwrap();
        matcher.insert_ssl(ssl_for("*.example.com")).unwrap();
        matcher
            .wildcards
            .sort_by_key(|(suffix, _)| std::cmp::Reverse(suffix.len()));

        let matched = matcher.match_sni("api.example.com").unwrap();
        assert_eq!(matched.inner.id, "*.example.com");
    }

    #[test]
    fn unsupported_and_duplicate_wildcards_are_rejected() {
        let invalid = ProxySSL::try_from(SSL {
            id: "invalid".into(),
            cert: CERT.into(),
            key: KEY.into(),
            snis: vec!["*.a.*.example.com".into()],
        });
        assert!(invalid.is_err());

        let mut matcher = MatchEntry::default();
        matcher.insert_ssl(ssl_for("*.example.com")).unwrap();
        assert!(matcher.insert_ssl(ssl_for("*.example.com")).is_err());
    }

    #[test]
    fn certificate_bundle_loads_leaf_and_intermediate_chain() {
        let bundled_pem = format!("{CERT}\n{CERT}");
        let proxy = ProxySSL::try_from(SSL {
            id: "chain".into(),
            cert: bundled_pem,
            key: KEY.into(),
            snis: vec!["example.com".into()],
        })
        .expect("PEM bundle with intermediate cert must parse");
        assert_eq!(proxy.parsed_chain.len(), 1);
    }

    #[test]
    fn multibyte_utf8_sni_does_not_panic_in_wildcard_match() {
        let mut matcher = MatchEntry::default();
        matcher.insert_ssl(ssl_for("*.example.com")).unwrap();
        // Byte length minus "example.com".len() lands inside a 2-byte UTF-8 char.
        assert!(matcher.match_sni("ééééééé").is_none());
        assert!(matcher.match_sni("ééééééé.example.com").is_some());
    }
}

use std::sync::Arc;

use async_trait::async_trait;
use log;
use matchit::{InsertError, Router as MatchRouter};
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

use super::runtime::RUNTIME;

static DEFAULT_SERVER_NAME: &str = "*";

/// Proxy SSL.
pub struct ProxySSL {
    pub inner: config::SSL,
    // Store parsed cert and key, handle parsing errors during creation/update
    parsed_cert: X509,
    parsed_key: PKey<pingora::tls::pkey::Private>,
}

impl TryFrom<config::SSL> for ProxySSL {
    type Error = ProxyError;

    fn try_from(value: config::SSL) -> std::result::Result<Self, Self::Error> {
        let parsed_cert = X509::from_pem(value.cert.as_bytes()).map_err(|e| {
            ProxyError::Configuration(format!("Failed to parse cert for '{}': {e}", value.id))
        })?;
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

#[derive(Default)]
pub struct MatchEntry {
    snis: MatchRouter<Arc<ProxySSL>>,
}

impl MatchEntry {
    pub(crate) fn build(
        ssls: &std::collections::HashMap<String, Arc<ProxySSL>>,
    ) -> std::result::Result<Self, ProxyError> {
        let mut matcher = Self::default();
        for ssl in ssls.values() {
            matcher.insert_ssl(ssl.clone()).map_err(|e| {
                ProxyError::Configuration(format!(
                    "Failed to build SSL matcher for '{}': {e}",
                    ssl.inner.id
                ))
            })?;
        }
        Ok(matcher)
    }

    /// Inserts an SSL into the match entry.
    /// Supports wildcard SNI patterns (e.g., "*.example.com") by converting them to matchit format.
    fn insert_ssl(&mut self, proxy_ssl: Arc<ProxySSL>) -> Result<(), InsertError> {
        for sni in proxy_ssl.get_snis() {
            let normalized = sni.to_ascii_lowercase();
            let processed_sni = if let Some(domain_part) = normalized.strip_prefix('*') {
                let reversed_domain: String = domain_part.chars().rev().collect();
                format!("{reversed_domain}{{*subdomain}}")
            } else {
                normalized.chars().rev().collect()
            };

            self.snis.insert(processed_sni, proxy_ssl.clone())?;
        }

        Ok(())
    }

    /// Matches an SNI to an SSL (ASCII case-insensitive, same as HTTP Host matcher).
    pub(crate) fn match_sni(&self, sni: &str) -> Option<Arc<ProxySSL>> {
        let normalized = sni.to_ascii_lowercase();
        let reversed_sni = normalized.chars().rev().collect::<String>();

        log::debug!("match sni: {sni:?}");

        if let Ok(v) = self.snis.at(&reversed_sni) {
            return Some(v.value.clone());
        }
        None
    }
}

pub struct DynamicCert {
    default: Arc<ProxySSL>,
}

impl DynamicCert {
    pub fn new(tls: &config::Tls) -> Result<Box<Self>, ProxyError> {
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
        }))
    }
}

#[async_trait]
impl TlsAccept for DynamicCert {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let sni = ssl
            .servername(NameType::HOST_NAME)
            .unwrap_or(DEFAULT_SERVER_NAME);

        let runtime = RUNTIME.load();
        let proxy_ssl = runtime
            .ssl_matcher
            .match_sni(sni)
            .unwrap_or_else(|| self.default.clone());

        if let Err(e) = ext::ssl_use_certificate(ssl, &proxy_ssl.parsed_cert) {
            log::error!("Failed to use certificate: {e}");
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
}

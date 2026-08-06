//! Process-level gateway runtime.
//!
//! [`GatewayRuntime`] owns initialization order (defaults → config source →
//! server → services → listeners), service registration, and bounded shutdown
//! of the configuration graph. `main` is a thin CLI/fatal-error adapter.

pub mod http;
pub mod status;

use std::ops::DerefMut;
use std::sync::Arc;

use async_trait::async_trait;
use pingora::services::listening::Service;
use pingora_core::{
    apps::HttpServerOptions,
    listeners::tls::TlsSettings,
    server::{configuration::Opt, Server, ShutdownWatch},
};
use pingora_proxy::{http_proxy_service_with_name, HttpProxy};
use sentry::IntoDsn;

use crate::admin::AdminHttpApp;
use crate::config::{self, etcd::EtcdConfigSync, Config};
use crate::core;
use crate::logging::Logger;
use crate::proxy::{
    graph_mutation::ConfigurationGraph, ssl::DynamicCert, upstream::SHARED_HEALTH_CHECK_SERVICE,
};
use crate::service::{http::HttpService, status::StatusHttpApp};

// Service name constants
const PINGSIX_SERVICE: &str = "pingsix";

/// The complete gateway process: owns startup order, service registration, and
/// the configuration graph's lifecycle.
pub struct GatewayRuntime {
    server: Server,
    http_service: Option<Service<HttpProxy<HttpService>>>,
}

impl GatewayRuntime {
    /// Build the full process from a loaded configuration.
    ///
    /// Order is significant: logging, then `pingsix.defaults` and data
    /// encryption (plugins and upstream peers bake these in at construction),
    /// then the configuration source (etcd graph or static YAML), then the
    /// server, services, and listeners. A failure here aborts startup before
    /// any listener accepts traffic.
    pub fn build(opt: Opt, config: Config) -> Result<Self, String> {
        let logger = init_logger(&config);
        init_pingsix_defaults(&config.pingsix)?;

        let (etcd_sync, config_graph) = init_config_source(&config)?;

        let mut server = Server::new_with_opt_and_conf(Some(opt), config.pingora);

        // Register logger service to enable centralized log handling across all workers.
        if let Some(log_service) = logger {
            log::debug!("Initializing log sync service");
            server.add_service(log_service);
        }

        // Register etcd service for real-time config synchronization in cluster deployments.
        if let Some(etcd_service) = etcd_sync {
            log::debug!("Initializing etcd config sync service");
            server.add_service(etcd_service);
        }

        // Shared health check service reduces overhead by consolidating upstream
        // health monitoring and DNS refresh.
        log::debug!("Initializing shared health check service");
        server.add_service(SHARED_HEALTH_CHECK_SERVICE.clone());

        // The runtime owns the graph's shutdown: a lifecycle service stops the
        // preparation worker on process shutdown, so the etcd transport never
        // reaches into the graph authority.
        if let Some(graph) = config_graph.clone() {
            server.add_service(GraphShutdownService { graph });
        }

        add_optional_services(&mut server, &config.pingsix, config_graph)?;

        let http_service = build_proxy_service(&server.configuration, &config.pingsix)
            .map_err(|e| format!("Failed to configure listeners: {e}"))?;

        Ok(Self {
            server,
            http_service: Some(http_service),
        })
    }

    /// Bootstrap the server, attach the proxy service, and run until shutdown.
    pub fn run(mut self) {
        log::info!("Starting pingsix server");
        self.server.bootstrap();
        log::debug!("Server bootstrapped, adding services");
        self.server
            .add_service(self.http_service.take().expect("proxy service was built"));

        log::info!("Pingsix server running");
        self.server.run_forever();
    }
}

/// Stops the configuration graph's preparation worker when the process shuts
/// down. Keeps graph lifecycle ownership in the runtime instead of the etcd
/// transport.
struct GraphShutdownService {
    graph: Arc<ConfigurationGraph>,
}

#[async_trait]
impl pingora_core::services::Service for GraphShutdownService {
    async fn start_service(
        &mut self,
        _fds: Option<pingora_core::server::ListenFds>,
        mut shutdown: ShutdownWatch,
        _listeners_per_fd: usize,
    ) {
        tokio::select! {
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    log::debug!("Process shutdown: stopping configuration graph worker");
                    self.graph.shutdown().await;
                }
            }
        }
    }

    fn name(&self) -> &str {
        "GraphShutdown"
    }

    fn threads(&self) -> Option<usize> {
        Some(1)
    }
}

/// Set up process-wide logging. Returns the logger service to register, if any.
fn init_logger(config: &Config) -> Option<Logger> {
    if let Some(log_cfg) = &config.pingsix.log {
        let logger = Logger::new(log_cfg.clone());
        logger.init_env_logger();
        Some(logger)
    } else {
        env_logger::init();
        None
    }
}

/// Choose the configuration source: etcd for dynamic updates in distributed
/// environments, or static file for simple setups.
fn init_config_source(
    config: &Config,
) -> Result<(Option<EtcdConfigSync>, Option<Arc<ConfigurationGraph>>), String> {
    if let Some(etcd_cfg) = &config.pingsix.etcd {
        log::debug!(
            "Initializing etcd config sync with prefix: {}",
            etcd_cfg.prefix
        );
        let graph = Arc::new(ConfigurationGraph::new(Arc::new(
            crate::config::etcd::EtcdGraphStore::new(etcd_cfg.clone()),
        )));
        Ok((
            Some(EtcdConfigSync::new(etcd_cfg.clone(), graph.clone())),
            Some(graph),
        ))
    } else {
        log::debug!("Loading static configurations from config file");
        ConfigurationGraph::load_static(config)
            .map_err(|e| format!("Failed to load static configurations: {e}"))?;
        Ok((None, None))
    }
}

/// Configures HTTP/HTTPS listeners with TLS settings.
///
/// Uses dynamic cert loading to enable SNI support without server restart.
/// H2 and H2C are enabled separately because they require different TLS negotiation.
fn build_proxy_service(
    server_conf: &Arc<pingora::server::configuration::ServerConf>,
    cfg: &config::Pingsix,
) -> Result<Service<HttpProxy<HttpService>>, Box<dyn std::error::Error>> {
    let mut http_service =
        http_proxy_service_with_name(server_conf, HttpService {}, PINGSIX_SERVICE);

    for list_cfg in cfg.listeners.iter() {
        if let Some(tls) = &list_cfg.tls {
            let dynamic_cert = DynamicCert::new(tls).map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("Failed to initialize TLS certificate: {e}"),
                )
            })?;
            let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert)?;

            // Enforce TLS 1.2+ for security - older versions have known vulnerabilities
            // Set both minimum and maximum to prevent negotiation of TLS 1.0/1.1
            tls_settings
                .deref_mut()
                .set_min_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_2))?;
            tls_settings
                .deref_mut()
                .set_max_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_3))?;

            if list_cfg.offer_h2 {
                tls_settings.enable_h2();
            }
            http_service.add_tls_with_settings(&list_cfg.address.to_string(), None, tls_settings);
        } else {
            // Enable H2C (HTTP/2 over cleartext) for better performance without TLS overhead
            if list_cfg.offer_h2c {
                let http_logic = http_service
                    .app_logic_mut()
                    .ok_or("Failed to get app logic")?;
                let mut http_server_options = HttpServerOptions::default();
                http_server_options.h2c = true;
                http_logic.server_options = Some(http_server_options);
            }
            http_service.add_tcp(&list_cfg.address.to_string());
        }
    }
    Ok(http_service)
}

/// Conditionally enables monitoring and admin services based on configuration.
///
/// Invalid Sentry configuration only disables Sentry; Admin/Status/Prometheus still start.
/// Admin interface is only available when etcd is enabled.
fn add_optional_services(
    server: &mut Server,
    cfg: &config::Pingsix,
    config_graph: Option<Arc<ConfigurationGraph>>,
) -> Result<(), String> {
    if let Some(sentry_cfg) = &cfg.sentry {
        if is_example_sentry_dsn(&sentry_cfg.dsn) {
            log::warn!("Ignoring example Sentry DSN, Sentry disabled");
        } else {
            log::debug!("Configuring Sentry monitoring");
            match sentry_cfg.dsn.clone().into_dsn() {
                Ok(Some(dsn)) => {
                    server.set_sentry_config(sentry::ClientOptions {
                        dsn: Some(dsn),
                        ..Default::default()
                    });
                    log::info!("Sentry monitoring enabled");
                }
                Ok(None) => {
                    log::warn!("Sentry DSN is empty, Sentry monitoring disabled");
                }
                Err(e) => {
                    log::error!("Invalid Sentry DSN configuration, Sentry disabled: {e}");
                }
            }
        }
    }

    if let (Some(graph), Some(admin_cfg)) = (config_graph, &cfg.admin) {
        admin_cfg.validate_bind_safety().map_err(|e| {
            log::error!("{e}");
            e
        })?;
        log::debug!("Configuring admin HTTP interface");
        if let Some(admin_service_http) = AdminHttpApp::admin_http_service(cfg, graph) {
            server.add_service(admin_service_http);
            log::info!("Admin HTTP interface enabled");
        } else {
            log::error!("Admin HTTP interface not configured (missing admin or etcd config)");
        }
    }

    if let Some(status_cfg) = &cfg.status {
        status_cfg.log_bind_safety();
        core::status::configure_status_policy(
            status_cfg.config_stale_after.unwrap_or(300),
            status_cfg.fail_readiness_when_stale,
        );
        log::debug!("Configuring status HTTP endpoint on {}", status_cfg.address);
        let status_service_http = StatusHttpApp::status_http_service(status_cfg);
        server.add_service(status_service_http);
        log::info!("Status HTTP endpoint enabled on {}", status_cfg.address);
    }

    if let Some(prometheus_cfg) = &cfg.prometheus {
        log::debug!(
            "Configuring Prometheus metrics endpoint on {}",
            prometheus_cfg.address
        );
        let mut prometheus_service_http = Service::prometheus_http_service();
        prometheus_service_http.add_tcp(&prometheus_cfg.address.to_string());
        server.add_service(prometheus_service_http);
        log::info!(
            "Prometheus metrics endpoint enabled on {}",
            prometheus_cfg.address
        );
    }
    Ok(())
}

/// Apply `pingsix.defaults` before any static/etcd resource graph is built.
///
/// Cache plugins and upstream peers resolve their fallbacks at construction time;
/// initializing after static/etcd graph publication would leave the baked-in
/// 1 MiB / absent-timeout fallbacks in place for the entire process lifetime.
fn init_pingsix_defaults(cfg: &config::Pingsix) -> Result<(), String> {
    if let Some(cache) = cfg.defaults.as_ref().and_then(|d| d.cache.as_ref()) {
        crate::service::http::init_cache_defaults(cache);
    }
    if let Some(defaults) = &cfg.defaults {
        crate::config::init_dns_resolution_timeout(defaults.dns_resolution_timeout);
        crate::config::init_dns_refresh_interval(defaults.dns_refresh_interval);
    }
    crate::config::init_default_upstream_timeout(
        cfg.defaults
            .as_ref()
            .and_then(|d| d.upstream_timeout.clone()),
    );
    let (enable, keyring) = match &cfg.data_encryption {
        Some(c) => (c.enable, c.keyring.as_slice()),
        None => (false, &[][..]),
    };
    crate::config::init_data_encryption(enable, keyring).map_err(|e| e.to_string())?;
    if enable {
        log::info!(
            "Data encryption enabled with {} keyring key(s)",
            keyring.len()
        );
    }
    Ok(())
}

/// Returns true if the Sentry DSN is the well-known placeholder used in docs/examples.
///
/// Starting up with this DSN would still ship (empty) events to a real project, so we
/// detect and ignore it to avoid accidental telemetry from default configs.
fn is_example_sentry_dsn(dsn: &str) -> bool {
    dsn.contains("examplePublicKey") || dsn.contains("o0.ingest.sentry.io/0")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_example_sentry_dsn_detected() {
        assert!(is_example_sentry_dsn(
            "https://examplePublicKey@o0.ingest.sentry.io/0"
        ));
        assert!(!is_example_sentry_dsn("https://real@o1.ingest.sentry.io/1"));
    }

    #[test]
    fn init_pingsix_defaults_rejects_bad_encryption_keyring() {
        let mut config = config::Config::default();
        config.pingsix.data_encryption = Some(config::DataEncryption {
            enable: true,
            keyring: vec![],
        });
        assert!(init_pingsix_defaults(&config.pingsix).is_err());
    }
}

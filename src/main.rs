use std::ops::DerefMut;

use pingora::services::listening::Service;
use pingora_core::{
    apps::HttpServerOptions,
    listeners::tls::TlsSettings,
    server::{configuration::Opt, Server},
};
use pingora_proxy::{http_proxy_service_with_name, HttpProxy};
use sentry::IntoDsn;

use pingsix::admin::AdminHttpApp;
use pingsix::config::{self, etcd::EtcdConfigSync, Config};
use pingsix::core;
use pingsix::logging::Logger;
use pingsix::proxy::{
    control_plane::load_static_configurations, event::ProxyEventHandler, ssl::DynamicCert,
    upstream::SHARED_HEALTH_CHECK_SERVICE,
};
use pingsix::service::{http::HttpService, status::StatusHttpApp};

// Service name constants
const PINGSIX_SERVICE: &str = "pingsix";

fn main() {
    // Parse CLI args and load config - exit early on failure to prevent silent misconfiguration
    let cli_options = Opt::parse_args();
    let config = match Config::load_yaml_with_opt_override(&cli_options) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {e}");
            std::process::exit(1);
        }
    };

    // Setup logging early to capture all subsequent initialization events
    let logger = if let Some(log_cfg) = &config.pingsix.log {
        let logger = Logger::new(log_cfg.clone());
        logger.init_env_logger();
        Some(logger)
    } else {
        env_logger::init();
        None
    };

    // Defaults must be initialized before any plugin/upstream build so static YAML
    // snapshots bake in `pingsix.defaults` (cache object size, upstream timeout).
    init_pingsix_defaults(&config.pingsix);

    // Choose config source: etcd for dynamic updates in distributed env, or static file for simple setups
    let etcd_sync = if let Some(etcd_cfg) = &config.pingsix.etcd {
        log::debug!(
            "Initializing etcd config sync with prefix: {}",
            etcd_cfg.prefix
        );
        let event_handler = ProxyEventHandler::new();
        Some(EtcdConfigSync::new(
            etcd_cfg.clone(),
            Box::new(event_handler),
        ))
    } else {
        log::debug!("Loading static configurations from config file");
        if let Err(e) = load_static_configurations(&config) {
            log::error!("Failed to load static configurations: {e}");
            std::process::exit(1);
        }
        None
    };

    let mut pingsix_server = Server::new_with_opt_and_conf(Some(cli_options), config.pingora);

    // Register logger service to enable centralized log handling across all workers
    if let Some(log_service) = logger {
        log::debug!("Initializing log sync service");
        pingsix_server.add_service(log_service);
    }

    // Register etcd service for real-time config synchronization in cluster deployments
    if let Some(etcd_service) = etcd_sync {
        log::debug!("Initializing etcd config sync service");
        pingsix_server.add_service(etcd_service);
    }

    // Create main HTTP proxy service - core request handling logic
    let mut http_service = http_proxy_service_with_name(
        &pingsix_server.configuration,
        HttpService {},
        PINGSIX_SERVICE,
    );

    log::debug!("Configuring listeners");
    if let Err(e) = add_listeners(&mut http_service, &config.pingsix) {
        log::error!("Failed to add listeners: {e}");
        std::process::exit(1);
    }

    // Shared health check service reduces overhead by consolidating upstream health monitoring
    log::debug!("Initializing shared health check service");
    pingsix_server.add_service(SHARED_HEALTH_CHECK_SERVICE.clone());

    add_optional_services(&mut pingsix_server, &config.pingsix);

    log::info!("Starting pingsix server");
    pingsix_server.bootstrap();
    log::debug!("Server bootstrapped, adding services");
    pingsix_server.add_service(http_service);

    log::info!("Pingsix server running");
    pingsix_server.run_forever();
}

/// Configures HTTP/HTTPS listeners with TLS settings.
///
/// Uses dynamic cert loading to enable SNI support without server restart.
/// H2 and H2C are enabled separately because they require different TLS negotiation.
fn add_listeners(
    http_service: &mut Service<HttpProxy<HttpService>>,
    cfg: &config::Pingsix,
) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

/// Conditionally enables monitoring and admin services based on configuration.
///
/// Invalid Sentry configuration only disables Sentry; Admin/Status/Prometheus still start.
/// Admin interface is only available when etcd is enabled.
fn add_optional_services(server: &mut Server, cfg: &config::Pingsix) {
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

    if cfg.etcd.is_some() && cfg.admin.is_some() {
        if let Some(admin_cfg) = &cfg.admin {
            if let Err(e) = validate_admin_bind(admin_cfg) {
                log::error!("{e}");
                std::process::exit(1);
            }
            log::debug!("Configuring admin HTTP interface");
            let admin_service_http = AdminHttpApp::admin_http_service(cfg);
            server.add_service(admin_service_http);
            log::info!("Admin HTTP interface enabled");
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
}

/// Apply `pingsix.defaults` before any static/etcd resource graph is built.
///
/// Cache plugins and upstream peers resolve their fallbacks at construction time;
/// initializing after `load_static_configurations` would leave the baked-in
/// 1 MiB / absent-timeout fallbacks in place for the entire process lifetime.
fn init_pingsix_defaults(cfg: &config::Pingsix) {
    if let Some(cache) = cfg.defaults.as_ref().and_then(|d| d.cache.as_ref()) {
        pingsix::service::http::init_cache_defaults(cache);
    }
    if let Some(defaults) = &cfg.defaults {
        pingsix::config::init_dns_resolution_timeout(defaults.dns_resolution_timeout);
    }
    pingsix::config::init_default_upstream_timeout(
        cfg.defaults
            .as_ref()
            .and_then(|d| d.upstream_timeout.clone()),
    );
}

fn validate_admin_bind(admin_cfg: &config::Admin) -> Result<(), String> {
    admin_cfg.validate_bind_safety()
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
}

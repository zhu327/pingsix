#![allow(clippy::upper_case_acronyms)]
mod admin;
mod config;
mod core;
mod logging;
mod plugin;
mod proxy;
mod service;
mod utils;

use std::ops::DerefMut;

use pingora::services::listening::Service;
use pingora_core::{
    apps::HttpServerOptions,
    listeners::tls::TlsSettings,
    server::{configuration::Opt, Server},
};
use pingora_proxy::{http_proxy_service_with_name, HttpProxy};
use sentry::IntoDsn;

use admin::AdminHttpApp;
use config::{etcd::EtcdConfigSync, Config};
use logging::Logger;
use proxy::{
    event::ProxyEventHandler,
    global_rule::load_static_global_rules,
    route::load_static_routes,
    service::load_static_services,
    ssl::{load_static_ssls, DynamicCert},
    upstream::{load_static_upstreams, SHARED_HEALTH_CHECK_SERVICE},
};
use service::http::HttpService;

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
        if let Err(e) = load_static_ssls(&config) {
            log::error!("Failed to load static SSLs: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_upstreams(&config) {
            log::error!("Failed to load static upstreams: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_services(&config) {
            log::error!("Failed to load static services: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_global_rules(&config) {
            log::error!("Failed to load static global rules: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_routes(&config) {
            log::error!("Failed to load static routes: {e}");
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
            let dynamic_cert = DynamicCert::new(tls);
            let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert)?;

            // Enforce TLS 1.3 for security - older versions have known vulnerabilities
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
/// Sentry integration requires valid DSN to prevent silent failures in production.
/// Admin interface is only available when etcd is enabled for security reasons.
fn add_optional_services(server: &mut Server, cfg: &config::Pingsix) {
    if let Some(sentry_cfg) = &cfg.sentry {
        log::debug!("Configuring Sentry monitoring");
        let dsn = match sentry_cfg.dsn.clone().into_dsn() {
            Ok(Some(dsn)) => dsn,
            Ok(None) => {
                log::warn!("Sentry DSN is empty, monitoring disabled");
                return;
            }
            Err(e) => {
                log::error!("Invalid Sentry DSN configuration: {e}");
                return; // Fail fast on invalid DSN to avoid silent monitoring failures
            }
        };
        server.sentry = Some(sentry::ClientOptions {
            dsn: Some(dsn),
            ..Default::default()
        });
        log::info!("Sentry monitoring enabled");
    }

    // Admin interface requires etcd for config validation and security
    if cfg.etcd.is_some() && cfg.admin.is_some() {
        log::debug!("Configuring admin HTTP interface");
        let admin_service_http = AdminHttpApp::admin_http_service(cfg);
        server.add_service(admin_service_http);
        log::info!("Admin HTTP interface enabled");
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

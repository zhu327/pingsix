#![allow(clippy::upper_case_acronyms)]
mod admin;
mod config;
mod core;
mod logging;
mod migration;
mod orchestration;
mod plugin;
mod proxy;
mod service;
mod utils;

// Import new architecture components
use core::{ResourceRegistry, ServiceContainer};
use migration::MigrationManager;

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
    health_check::SHARED_HEALTH_CHECK_SERVICE,
    route::load_static_routes,
    service::load_static_services,
    ssl::{load_static_ssls, DynamicCert},
    upstream::load_static_upstreams,
};
use service::http::HttpService;

// Service name constants
const PINGSIX_SERVICE: &str = "pingsix";

fn main() {
    // Check if we should use the new architecture
    if cfg!(feature = "new-architecture") {
        log::info!("Using new dependency injection architecture");
        new_main_with_di();
        return;
    }

    // Fallback to original implementation
    log::info!("Using legacy architecture");
    original_main();
}

/// New main function using dependency injection architecture
fn new_main_with_di() {
    // Load configuration and command-line arguments
    let cli_options = Opt::parse_args();
    let config = match Config::load_yaml_with_opt_override(&cli_options) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {e}");
            std::process::exit(1);
        }
    };

    // Initialize logging
    let logger = if let Some(log_cfg) = &config.pingsix.log {
        let logger = Logger::new(log_cfg.clone());
        logger.init_env_logger();
        Some(logger)
    } else {
        env_logger::init();
        None
    };

    // Create service container and migration manager
    let container = std::sync::Arc::new(ServiceContainer::new());
    let migration_manager = MigrationManager::new(container.clone());

    // Initialize new architecture or migrate from existing
    let etcd_sync = if let Some(etcd_cfg) = &config.pingsix.etcd {
        log::info!("Adding etcd config sync with new architecture...");
        let event_handler = ProxyEventHandler::new();
        Some(EtcdConfigSync::new(
            etcd_cfg.clone(),
            Box::new(event_handler),
        ))
    } else {
        log::info!("Loading static resources with new architecture...");
        
        // Load SSL certificates (still using old implementation)
        if let Err(e) = load_static_ssls(&config) {
            eprintln!("Failed to load static SSLs: {e}");
            std::process::exit(1);
        }
        
        // Use new migration manager to load resources
        if let Err(e) = migration_manager.migrate_static_config(&config) {
            eprintln!("Failed to migrate static configuration: {e}");
            std::process::exit(1);
        }
        
        None
    };

    // Continue with server setup...
    new_main_server_setup(config, logger, etcd_sync, container);
}

/// Original main function (preserved for compatibility)
fn original_main() {
    // Load configuration and command-line arguments
    let cli_options = Opt::parse_args();
    let config = match Config::load_yaml_with_opt_override(&cli_options) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("Error loading configuration: {e}");
            std::process::exit(1);
        }
    };

    // Initialize logging
    let logger = if let Some(log_cfg) = &config.pingsix.log {
        let logger = Logger::new(log_cfg.clone());
        logger.init_env_logger();
        Some(logger)
    } else {
        env_logger::init();
        None
    };

    // If etcd is enabled, start config sync service; otherwise, load static configs
    let etcd_sync = if let Some(etcd_cfg) = &config.pingsix.etcd {
        log::info!("Adding etcd config sync...");
        let event_handler = ProxyEventHandler::new();
        Some(EtcdConfigSync::new(
            etcd_cfg.clone(),
            Box::new(event_handler),
        ))
    } else {
        log::info!("Loading static services, upstreams, and routes...");
        if let Err(e) = load_static_ssls(&config) {
            eprintln!("Failed to load static SSLs: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_upstreams(&config) {
            eprintln!("Failed to load static upstreams: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_services(&config) {
            eprintln!("Failed to load static services: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_global_rules(&config) {
            eprintln!("Failed to load static global rules: {e}");
            std::process::exit(1);
        }
        if let Err(e) = load_static_routes(&config) {
            eprintln!("Failed to load static routes: {e}");
            std::process::exit(1);
        }
        None
    };

    // Continue with original server setup
    original_main_server_setup(config, logger, etcd_sync);
}

/// Server setup for new architecture
fn new_main_server_setup(
    config: Config,
    logger: Option<Logger>,
    etcd_sync: Option<EtcdConfigSync>,
    container: std::sync::Arc<ServiceContainer>,
) {
    // Create server instance
    let mut pingsix_server = Server::new_with_opt_and_conf(None, config.pingora.clone());

    // Add log service
    if let Some(log_service) = logger {
        log::info!("Adding log sync service...");
        pingsix_server.add_service(log_service);
    }

    // Add Etcd config sync service
    if let Some(etcd_service) = etcd_sync {
        log::info!("Adding etcd config sync service...");
        pingsix_server.add_service(etcd_service);
    }

    // Initialize HTTP service with new architecture
    let new_http_service = service::new_http::NewHttpService::new(container);
    let mut http_service = http_proxy_service_with_name(
        &pingsix_server.configuration,
        new_http_service,
        PINGSIX_SERVICE,
    );

    // Add listeners
    log::info!("Adding listeners...");
    if let Err(e) = add_listeners_new(&mut http_service, &config.pingsix) {
        eprintln!("Failed to add listeners: {e}");
        std::process::exit(1);
    }

    // Add shared health check service
    log::info!("Adding shared health check service...");
    pingsix_server.add_service(SHARED_HEALTH_CHECK_SERVICE.clone());

    // Add optional services (Sentry, Prometheus, Admin)
    add_optional_services(&mut pingsix_server, &config.pingsix);

    // Start server
    log::info!("Bootstrapping...");
    pingsix_server.bootstrap();
    log::info!("Bootstrapped. Adding Services...");
    pingsix_server.add_service(http_service);

    log::info!("Starting Server...");
    pingsix_server.run_forever();
}

/// Original server setup (preserved for compatibility)
fn original_main_server_setup(
    config: Config,
    logger: Option<Logger>,
    etcd_sync: Option<EtcdConfigSync>,
) {
    // Create server instance
    let mut pingsix_server = Server::new_with_opt_and_conf(None, config.pingora.clone());

    // Add log service
    if let Some(log_service) = logger {
        log::info!("Adding log sync service...");
        pingsix_server.add_service(log_service);
    }

    // Add Etcd config sync service
    if let Some(etcd_service) = etcd_sync {
        log::info!("Adding etcd config sync service...");
        pingsix_server.add_service(etcd_service);
    }

    // Initialize HTTP service (original)
    let mut http_service = http_proxy_service_with_name(
        &pingsix_server.configuration,
        HttpService {},
        PINGSIX_SERVICE,
    );

    // Add listeners
    log::info!("Adding listeners...");
    if let Err(e) = add_listeners(&mut http_service, &config.pingsix) {
        eprintln!("Failed to add listeners: {e}");
        std::process::exit(1);
    }

    // Add shared health check service
    log::info!("Adding shared health check service...");
    pingsix_server.add_service(SHARED_HEALTH_CHECK_SERVICE.clone());

    // Add optional services (Sentry, Prometheus, Admin)
    add_optional_services(&mut pingsix_server, &config.pingsix);

    // Start server
    log::info!("Bootstrapping...");
    pingsix_server.bootstrap();
    log::info!("Bootstrapped. Adding Services...");
    pingsix_server.add_service(http_service);

    log::info!("Starting Server...");
    pingsix_server.run_forever();
}

/// Add listeners for new HTTP service, supporting TCP and TLS.
fn add_listeners_new(
    http_service: &mut Service<HttpProxy<service::new_http::NewHttpService>>,
    cfg: &config::Pingsix,
) -> Result<(), Box<dyn std::error::Error>> {
    for list_cfg in cfg.listeners.iter() {
        if let Some(tls) = &list_cfg.tls {
            // TLS configuration
            let dynamic_cert = DynamicCert::new(tls);
            let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert)?;

            tls_settings
                .deref_mut()
                .deref_mut()
                .set_max_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_3))?;

            if list_cfg.offer_h2 {
                tls_settings.enable_h2();
            }
            http_service.add_tls_with_settings(&list_cfg.address.to_string(), None, tls_settings);
        } else {
            // Non-TLS
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

/// Add listeners for HTTP service, supporting TCP and TLS.
fn add_listeners(
    http_service: &mut Service<HttpProxy<HttpService>>,
    cfg: &config::Pingsix,
) -> Result<(), Box<dyn std::error::Error>> {
    for list_cfg in cfg.listeners.iter() {
        if let Some(tls) = &list_cfg.tls {
            // TLS configuration
            let dynamic_cert = DynamicCert::new(tls);
            let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert)?;

            tls_settings
                .deref_mut()
                .deref_mut()
                .set_max_proto_version(Some(pingora::tls::ssl::SslVersion::TLS1_3))?;

            if list_cfg.offer_h2 {
                tls_settings.enable_h2();
            }
            http_service.add_tls_with_settings(&list_cfg.address.to_string(), None, tls_settings);
        } else {
            // Non-TLS
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

/// Add optional services (Sentry, Prometheus, Admin).
fn add_optional_services(server: &mut Server, cfg: &config::Pingsix) {
    if let Some(sentry_cfg) = &cfg.sentry {
        log::info!("Adding Sentry config...");
        let dsn = match sentry_cfg.dsn.clone().into_dsn() {
            Ok(Some(dsn)) => dsn,
            Ok(None) => {
                log::warn!("Sentry DSN is empty or invalid, Sentry disabled.");
                return;
            }
            Err(e) => {
                log::error!("Error parsing Sentry DSN: {e}");
                return; // Skip Sentry if DSN is invalid
            }
        };
        server.sentry = Some(sentry::ClientOptions {
            dsn: Some(dsn),
            ..Default::default()
        });
    }

    if cfg.etcd.is_some() && cfg.admin.is_some() {
        log::info!("Adding Admin HTTP...");
        let admin_service_http = AdminHttpApp::admin_http_service(cfg);
        server.add_service(admin_service_http);
    }

    if let Some(prometheus_cfg) = &cfg.prometheus {
        log::info!("Adding Prometheus HTTP...");
        let mut prometheus_service_http = Service::prometheus_http_service();
        prometheus_service_http.add_tcp(&prometheus_cfg.address.to_string());
        server.add_service(prometheus_service_http);
    }
}

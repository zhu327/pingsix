//! New main entry point using the refactored architecture
//!
//! This demonstrates how to use the new dependency injection and
//! trait-based architecture to eliminate circular dependencies.

#![allow(clippy::upper_case_acronyms)]

use std::sync::Arc;

use pingora::services::listening::Service;
use pingora_core::{
    apps::HttpServerOptions,
    listeners::tls::TlsSettings,
    server::{configuration::Opt, Server},
};
use pingora_proxy::{http_proxy_service_with_name, HttpProxy};
use sentry::IntoDsn;

use crate::{
    admin::AdminHttpApp,
    config::{etcd::EtcdConfigSync, Config},
    core::{ResourceLoader, ResourceRegistry, ServiceContainer},
    logging::Logger,
    orchestration::ComponentLifecycle,
    proxy::{
        event::ProxyEventHandler,
        health_check::SHARED_HEALTH_CHECK_SERVICE,
        ssl::{load_static_ssls, DynamicCert},
    },
    service::new_http::NewHttpService,
};

// Service name constants
const PINGSIX_SERVICE: &str = "pingsix";

/// New main function using dependency injection architecture
pub fn new_main() {
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

    // Create the service container and initialize components
    let container = Arc::new(ServiceContainer::new());
    let lifecycle = ComponentLifecycle::new(container.clone());

    // Initialize components
    if let Err(e) = tokio::runtime::Runtime::new().unwrap().block_on(lifecycle.initialize(&config)) {
        eprintln!("Failed to initialize components: {e}");
        std::process::exit(1);
    }

    // Load static resources if not using etcd
    let etcd_sync = if let Some(etcd_cfg) = &config.pingsix.etcd {
        log::info!("Adding etcd config sync...");
        let event_handler = ProxyEventHandler::new();
        Some(EtcdConfigSync::new(
            etcd_cfg.clone(),
            Box::new(event_handler),
        ))
    } else {
        log::info!("Loading static resources...");
        let loader = ResourceLoader::new(container.registry().clone());
        if let Err(e) = loader.load_static_resources(&config) {
            eprintln!("Failed to load static resources: {e}");
            std::process::exit(1);
        }
        
        // Load SSL certificates
        if let Err(e) = load_static_ssls(&config) {
            eprintln!("Failed to load static SSLs: {e}");
            std::process::exit(1);
        }
        
        None
    };

    // Create server instance
    let mut pingsix_server = Server::new_with_opt_and_conf(Some(cli_options), config.pingora);

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

    // Initialize HTTP service with dependency injection
    let http_service_impl = NewHttpService::new(container.clone());
    let mut http_service = http_proxy_service_with_name(
        &pingsix_server.configuration,
        http_service_impl,
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

/// Add listeners for HTTP service, supporting TCP and TLS
fn add_listeners(
    http_service: &mut Service<HttpProxy<NewHttpService>>,
    cfg: &crate::config::Pingsix,
) -> Result<(), Box<dyn std::error::Error>> {
    for list_cfg in cfg.listeners.iter() {
        if let Some(tls) = &list_cfg.tls {
            // TLS configuration
            let dynamic_cert = DynamicCert::new(tls);
            let mut tls_settings = TlsSettings::with_callbacks(dynamic_cert)?;

            tls_settings
                .as_mut()
                .as_mut()
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

/// Add optional services (Sentry, Prometheus, Admin)
fn add_optional_services(server: &mut Server, cfg: &crate::config::Pingsix) {
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
                return;
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
#![allow(clippy::upper_case_acronyms)]

use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_core::services::Service;
use pingora_proxy::http_proxy_service_with_name;

use config::{Config, Tls};
use proxy::{router::ProxyRouter, ProxyService};

mod config;
mod proxy;

fn main() {
    // Initialize logging
    env_logger::init();

    // Read command-line arguments
    let opt = Opt::parse_args();

    // Load configuration with optional override
    let config = Config::load_yaml_with_opt_override(&opt).unwrap();

    // Create Pingora server with optional configuration
    let mut pingsix_server = Server::new_with_opt_and_conf(Some(opt), config.pingora);

    // Apply proxy routers
    log::info!("Applying Routers...");
    let mut background_services: Vec<Box<dyn Service>> = vec![];

    // Create proxy service and configure routing
    let mut proxy_service = ProxyService::default();
    for router in config.routers {
        log::info!("Configuring Router: {}", router.id);
        let mut proxy_router = ProxyRouter::try_from(router).unwrap();
        if let Some(background_service) = proxy_router.upstream.take_background_service() {
            background_services.push(background_service);
        }

        proxy_service.matcher.insert_router(proxy_router).unwrap();
    }

    // Create HTTP proxy service with name
    let mut http_service =
        http_proxy_service_with_name(&pingsix_server.configuration, proxy_service, "pingsix");

    // Add listeners from configuration
    log::info!("Adding listeners...");
    for list_cfg in config.listeners {
        match list_cfg.tls {
            Some(Tls {
                cert_path,
                key_path,
            }) => {
                let mut settings = TlsSettings::intermediate(&cert_path, &key_path)
                    .expect("Adding TLS listener shouldn't fail");
                if list_cfg.offer_h2 {
                    settings.enable_h2();
                }
                http_service.add_tls_with_settings(&list_cfg.address.to_string(), None, settings);
            }
            None => {
                http_service.add_tcp(&list_cfg.address.to_string());
            }
        }
    }

    // Bootstrapping and server startup
    log::info!("Bootstrapping...");
    pingsix_server.bootstrap();

    log::info!("Bootstrapped. Adding Services...");
    pingsix_server.add_service(http_service);
    pingsix_server.add_services(background_services);

    log::info!("Starting Server...");
    pingsix_server.run_forever();
}

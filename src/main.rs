#![allow(clippy::upper_case_acronyms)]

use pingora_core::listeners::tls::TlsSettings;
use pingora_core::server::configuration::Opt;
use pingora_core::server::Server;
use pingora_proxy::http_proxy_service_with_name;

use config::{Config, Tls};
use proxy::{init_proxy_service, service::load_services, upstream::load_upstreams};

mod config;
mod proxy;

fn main() {
    // Initialize logging
    env_logger::init();

    // Read command-line arguments
    let opt = Opt::parse_args();

    // Load configuration with optional override
    let config = Config::load_yaml_with_opt_override(&opt).expect("Failed to load configuration");

    // Load services from configuration
    log::info!("Loading services...");
    load_services(&config).expect("Failed to load services");

    // Load upstreams from configuration
    log::info!("Loading upstreams...");
    load_upstreams(&config).expect("Failed to load upstreams");

    // Load routers from configuration
    log::info!("Loading routers...");
    let proxy_service = init_proxy_service(&config).expect("Failed to initialize proxy service");

    // Create Pingora server with optional configuration
    let mut pingsix_server = Server::new_with_opt_and_conf(Some(opt), config.pingora);

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

    log::info!("Starting Server...");
    pingsix_server.run_forever();
}

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
    env_logger::init();

    // read command line arguments
    let opt = Opt::parse_args();

    let config = Config::load_yaml_with_opt_override(&opt).unwrap();

    let mut pingsix_server = Server::new_with_opt_and_conf(Some(opt), config.pingora);

    log::info!("Applying Routers...");
    let mut background_services: Vec<Box<dyn Service>> = vec![];

    // init proxy service
    let mut proxy_service = ProxyService::new();
    for router in config.routers {
        log::info!("Configuring Router: {}", router.id);
        let mut proxy_router = ProxyRouter::from(router);
        if let Some(background_service) = proxy_router.lb.take_background_service() {
            background_services.push(background_service);
        }

        proxy_service.matcher.insert_router(proxy_router).unwrap();
    }

    let mut pingsix_service =
        http_proxy_service_with_name(&pingsix_server.configuration, proxy_service, "pingsix");

    // add listeners
    log::info!("Add listeners...");
    for list_cfg in config.listeners {
        if let Some(Tls {
            cert_path,
            key_path,
        }) = list_cfg.tls
        {
            let mut settings = TlsSettings::intermediate(&cert_path, &key_path)
                .expect("adding TLS listener shouldn't fail");
            if list_cfg.offer_h2 {
                settings.enable_h2();
            }

            pingsix_service.add_tls_with_settings(&list_cfg.address.to_string(), None, settings);
        } else {
            pingsix_service.add_tcp(&list_cfg.address.to_string());
        }
    }

    log::info!("Bootstrapping...");
    pingsix_server.bootstrap();

    log::info!("Bootstrapped. Adding Services...");
    pingsix_server.add_service(pingsix_service);
    pingsix_server.add_services(background_services);

    log::info!("Starting Server...");
    pingsix_server.run_forever();
}

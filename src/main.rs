use pingora_core::server::configuration::Opt;

use pingsix::config::Config;
use pingsix::service::GatewayRuntime;

/// Thin CLI/fatal-error adapter: parse options, load configuration, and hand
/// everything to [`GatewayRuntime`], which owns startup order, service
/// registration, and bounded shutdown.
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

    match GatewayRuntime::build(cli_options, config) {
        Ok(runtime) => runtime.run(),
        Err(e) => {
            eprintln!("Error initializing pingsix: {e}");
            std::process::exit(1);
        }
    }
}

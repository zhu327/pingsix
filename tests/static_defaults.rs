//! Static YAML defaults must be applied before the resource graph is built.
//!
//! This is a separate integration-test binary so `OnceCell` globals start fresh.

use pingsix::config::{
    init_default_upstream_timeout, init_dns_refresh_interval, init_dns_resolution_timeout,
    CacheDefaults, Defaults, Timeout,
};
use pingsix::plugins::cache::{default_max_object_bytes, resolved_max_file_size_bytes};
use pingsix::service::http::init_cache_defaults;

/// Mirrors `main::init_pingsix_defaults`: defaults first, then plugin construction.
fn init_defaults_like_main(defaults: &Defaults) {
    if let Some(cache) = &defaults.cache {
        init_cache_defaults(cache);
    }
    init_dns_resolution_timeout(defaults.dns_resolution_timeout);
    init_dns_refresh_interval(defaults.dns_refresh_interval);
    init_default_upstream_timeout(defaults.upstream_timeout.clone());
}

#[test]
fn static_cache_default_applies_before_plugin_build() {
    let defaults = Defaults {
        upstream_timeout: Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        }),
        dns_resolution_timeout: 3,
        dns_refresh_interval: Some(7),
        cache: Some(CacheDefaults {
            max_memory_bytes: 64 * 1024 * 1024,
            default_max_object_bytes: 10_485_760,
        }),
    };
    init_defaults_like_main(&defaults);

    assert_eq!(default_max_object_bytes(), 10_485_760);

    let size = resolved_max_file_size_bytes(serde_json::json!({ "ttl": 60 })).unwrap();
    assert_eq!(
        size, 10_485_760,
        "cache plugin must bake in YAML default_max_object_bytes, not the 1 MiB fallback"
    );

    // Global upstream timeout is available for peers that omit an explicit timeout.
    assert_eq!(
        pingsix::config::default_upstream_timeout(),
        Some(Timeout {
            connect: 5,
            send: 5,
            read: 5,
        })
    );

    assert_eq!(pingsix::config::dns_resolution_timeout(), 3);
    assert_eq!(pingsix::config::dns_refresh_interval(), Some(7));
}

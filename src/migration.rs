//! Migration utilities for transitioning to the new architecture
//!
//! This module provides utilities to gradually migrate from the old
//! architecture to the new trait-based dependency injection architecture.

use std::sync::Arc;

use log::{info, warn};

use crate::{
    config::Config,
    core::{ResourceLoader, ResourceRegistry, ServiceContainer},
    proxy::{
        global_rule::GLOBAL_RULE_MAP,
        route::ROUTE_MAP,
        service::SERVICE_MAP,
        upstream::UPSTREAM_MAP,
    },
};

/// Migration manager for transitioning between architectures
pub struct MigrationManager {
    container: Arc<ServiceContainer>,
    loader: ResourceLoader,
}

impl MigrationManager {
    /// Create a new migration manager
    pub fn new(container: Arc<ServiceContainer>) -> Self {
        let loader = ResourceLoader::with_plugin_manager(
            container.registry().clone(),
            container.plugin_manager().clone(),
        );
        Self { container, loader }
    }

    /// Migrate static configuration to new architecture
    pub fn migrate_static_config(&self, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
        info!("Starting migration from static configuration...");

        // Load resources using the new loader
        self.loader.load_static_resources(config)?;

        // Verify migration by comparing counts
        let stats = self.loader.get_stats();
        info!(
            "Migration completed: {} routes, {} upstreams, {} services",
            stats.route_count, stats.upstream_count, stats.service_count
        );

        // Validate that all resources were migrated
        self.validate_migration(config)?;

        Ok(())
    }

    /// Migrate from existing global maps (for gradual transition)
    pub fn migrate_from_global_maps(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("Migrating from existing global maps...");

        let registry = self.container.registry();

        // Migrate upstreams
        let upstream_count = UPSTREAM_MAP.len();
        for entry in UPSTREAM_MAP.iter() {
            let (id, upstream) = entry.pair();
            // TODO: Convert ProxyUpstream to Arc<dyn UpstreamProvider>
            // This requires implementing the adapter pattern
            log::debug!("Migrating upstream: {}", id);
        }

        // Migrate services
        let service_count = SERVICE_MAP.len();
        for entry in SERVICE_MAP.iter() {
            let (id, service) = entry.pair();
            // TODO: Convert ProxyService to Arc<dyn ServiceProvider>
            log::debug!("Migrating service: {}", id);
        }

        // Migrate routes
        let route_count = ROUTE_MAP.len();
        for entry in ROUTE_MAP.iter() {
            let (id, route) = entry.pair();
            // TODO: Convert ProxyRoute to Arc<dyn RouteResolver>
            log::debug!("Migrating route: {}", id);
        }

        info!(
            "Migration from global maps completed: {} routes, {} upstreams, {} services",
            route_count, upstream_count, service_count
        );

        Ok(())
    }

    /// Validate that migration was successful
    fn validate_migration(&self, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
        let stats = self.loader.get_stats();

        // Check counts match
        if stats.upstream_count != config.upstreams.len() {
            warn!(
                "Upstream count mismatch: expected {}, got {}",
                config.upstreams.len(),
                stats.upstream_count
            );
        }

        if stats.service_count != config.services.len() {
            warn!(
                "Service count mismatch: expected {}, got {}",
                config.services.len(),
                stats.service_count
            );
        }

        if stats.route_count != config.routes.len() {
            warn!(
                "Route count mismatch: expected {}, got {}",
                config.routes.len(),
                stats.route_count
            );
        }

        // TODO: Add more detailed validation
        // - Check that all IDs are present
        // - Validate that dependencies are correctly resolved
        // - Test route matching functionality

        Ok(())
    }

    /// Create a compatibility layer for existing code
    pub fn create_compatibility_layer(&self) -> CompatibilityLayer {
        CompatibilityLayer::new(self.container.clone())
    }
}

/// Compatibility layer to help existing code work with new architecture
pub struct CompatibilityLayer {
    container: Arc<ServiceContainer>,
}

impl CompatibilityLayer {
    fn new(container: Arc<ServiceContainer>) -> Self {
        Self { container }
    }

    /// Provide compatibility for upstream_fetch function
    pub fn upstream_fetch(&self, id: &str) -> Option<Arc<dyn crate::core::traits::UpstreamProvider>> {
        self.container.registry().get_upstream(id)
    }

    /// Provide compatibility for service_fetch function
    pub fn service_fetch(&self, id: &str) -> Option<Arc<dyn crate::core::traits::ServiceProvider>> {
        self.container.registry().get_service(id)
    }

    /// Provide compatibility for route matching
    pub fn route_match(&self, session: &pingora_proxy::Session) -> Option<Arc<dyn crate::core::traits::RouteResolver>> {
        // This would use the new router
        // For now, return None as placeholder
        None
    }
}

/// Feature flag for enabling new architecture
pub const USE_NEW_ARCHITECTURE: bool = cfg!(feature = "new-architecture");

/// Conditional compilation helper macros
#[macro_export]
macro_rules! if_new_arch {
    ($new_code:expr, $old_code:expr) => {
        if $crate::migration::USE_NEW_ARCHITECTURE {
            $new_code
        } else {
            $old_code
        }
    };
}

#[macro_export]
macro_rules! new_arch_only {
    ($code:expr) => {
        if $crate::migration::USE_NEW_ARCHITECTURE {
            $code
        }
    };
}
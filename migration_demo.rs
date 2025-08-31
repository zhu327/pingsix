//! Migration demonstration script
//!
//! This script demonstrates how to migrate from the old architecture
//! to the new dependency injection architecture.

use std::sync::Arc;

use pingsix::{
    config::Config,
    core::{ResourceLoader, ResourceRegistry, ServiceContainer},
    migration::MigrationManager,
    proxy::adapters::populate_registry_from_global_maps,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    env_logger::init();

    println!("🔄 PingSIX Architecture Migration Demo");
    println!("=====================================");

    // Load configuration
    let config = Config::load_from_yaml("config.yaml")?;
    println!("✅ Configuration loaded successfully");

    // Method 1: Direct migration from configuration
    println!("\n📋 Method 1: Direct migration from configuration");
    demo_direct_migration(&config)?;

    // Method 2: Migration from existing global maps
    println!("\n🔄 Method 2: Migration from existing global maps");
    demo_global_map_migration(&config)?;

    // Method 3: Hybrid approach (recommended)
    println!("\n🎯 Method 3: Hybrid approach (recommended)");
    demo_hybrid_migration(&config)?;

    println!("\n✅ All migration methods demonstrated successfully!");
    Ok(())
}

/// Demonstrate direct migration from configuration
fn demo_direct_migration(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // Create new service container
    let container = Arc::new(ServiceContainer::new());
    let loader = ResourceLoader::new(container.registry().clone());

    // Load resources directly from configuration
    loader.load_static_resources(config)?;

    // Print statistics
    let stats = loader.get_stats();
    println!(
        "   📊 Loaded: {} routes, {} upstreams, {} services",
        stats.route_count, stats.upstream_count, stats.service_count
    );

    Ok(())
}

/// Demonstrate migration from existing global maps
fn demo_global_map_migration(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // First, load using the old system to populate global maps
    // (In a real scenario, this would already be done)
    
    // Create new registry and populate from global maps
    let registry = Arc::new(ResourceRegistry::new());
    populate_registry_from_global_maps(&registry);

    let stats = registry.get_stats();
    println!(
        "   📊 Migrated: {} routes, {} upstreams, {} services",
        stats.route_count, stats.upstream_count, stats.service_count
    );

    Ok(())
}

/// Demonstrate hybrid migration approach
fn demo_hybrid_migration(config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    // Create service container and migration manager
    let container = Arc::new(ServiceContainer::new());
    let migration_manager = MigrationManager::new(container.clone());

    // Use migration manager for seamless transition
    migration_manager.migrate_static_config(config)?;

    // Create compatibility layer for existing code
    let compat_layer = migration_manager.create_compatibility_layer();

    // Demonstrate compatibility layer usage
    println!("   🔗 Testing compatibility layer...");
    
    // Test upstream fetch (would work with existing code)
    if let Some(_upstream) = compat_layer.upstream_fetch("test-upstream") {
        println!("   ✅ Upstream compatibility works");
    }

    let stats = container.registry().get_stats();
    println!(
        "   📊 Hybrid migration: {} routes, {} upstreams, {} services",
        stats.route_count, stats.upstream_count, stats.service_count
    );

    Ok(())
}
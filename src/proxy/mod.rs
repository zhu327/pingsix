//! Module for proxy context and resource management.
//!
//! This module defines the `ProxyContext` used per request and the generic
//! `MapOperations` trait for managing resources in a thread-safe map.

pub mod discovery;
pub mod event;
pub mod global_rule;
pub mod route;
pub mod service;
pub mod ssl;
pub mod upstream;

use std::{
    collections::{BTreeMap, HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use dashmap::DashMap;

use crate::{config::Identifiable, plugin::ProxyPluginExecutor};

use route::ProxyRoute;

/// Holds the context for each proxy request.
pub struct ProxyContext {
    /// The matched proxy route, if any.
    pub route: Option<Arc<ProxyRoute>>,
    /// Parameters extracted from the route pattern.
    pub route_params: Option<BTreeMap<String, String>>,
    /// Number of retry attempts so far.
    pub tries: usize,
    /// Timestamp when the request started.
    pub request_start: Instant,
    /// Executor for route-specific plugins.
    pub plugin: Arc<ProxyPluginExecutor>,
    /// Executor for global plugins.
    pub global_plugin: Arc<ProxyPluginExecutor>,
    /// Custom variables available to plugins.
    pub vars: HashMap<String, String>,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            route: None,
            route_params: None,
            tries: 0,
            request_start: Instant::now(),
            plugin: Arc::new(ProxyPluginExecutor::default()),
            global_plugin: Arc::new(ProxyPluginExecutor::default()),
            vars: HashMap::new(),
        }
    }
}

/// Trait for performing common operations on a map of resources.
///
/// Provides methods to fetch, bulk reload, and insert individual resources.
pub trait MapOperations<T> {
    /// Get a resource by its identifier.
    ///
    /// Returns `Some(Arc<T>)` if found, otherwise logs a warning and returns `None`.
    fn get(&self, id: &str) -> Option<Arc<T>>;

    /// Reload the entire set of resources.
    ///
    /// Removes entries not present in `resources`, and inserts or updates all given resources.
    fn reload_resources(&self, resources: Vec<Arc<T>>);

    /// Insert or update a single resource.
    fn insert_resource(&self, resource: Arc<T>);
}

impl<T> MapOperations<T> for DashMap<String, Arc<T>>
where
    T: Identifiable,
{
    fn get(&self, id: &str) -> Option<Arc<T>> {
        if let Some(entry) = self.get(id) {
            Some(entry.clone())
        } else {
            log::warn!("Resource with id '{}' not found", id);
            None
        }
    }

    fn reload_resources(&self, resources: Vec<Arc<T>>) {
        // Log incoming resources
        for resource in &resources {
            log::info!("Upserting resource: {}", resource.id());
        }

        // Build a set of IDs to keep
        let valid_ids: HashSet<String> = resources.iter().map(|r| r.id().to_string()).collect();

        // Remove entries not in the new set
        self.retain(|key, _| valid_ids.contains(key));

        // Insert or update all resources
        for resource in resources {
            let key = resource.id().to_string();
            log::info!("Inserting or updating resource '{}'", key);
            self.insert(key, resource);
        }
    }

    fn insert_resource(&self, resource: Arc<T>) {
        let key = resource.id();
        log::info!("Inserting resource '{}'", key);
        self.insert(key.to_string(), resource);
    }
}

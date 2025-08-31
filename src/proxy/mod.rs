//! Module for proxy context and resource management.
//!
//! This module defines resource management and the generic
//! `MapOperations` trait for managing resources in a thread-safe map.

pub mod discovery;
pub mod event;
pub mod global_rule;
pub mod health_check;
pub mod route;
pub mod service;
pub mod ssl;
pub mod upstream;

use std::{collections::HashSet, sync::Arc};

use dashmap::DashMap;

use crate::config::Identifiable;

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
            log::debug!("Resource '{}' not found in cache", id);
            None
        }
    }

    fn reload_resources(&self, resources: Vec<Arc<T>>) {
        // Log incoming resources for debug
        for resource in &resources {
            log::debug!("Reloading resource: {}", resource.id());
        }

        // Build a set of IDs to keep
        let valid_ids: HashSet<String> = resources.iter().map(|r| r.id().to_string()).collect();

        // Remove entries not in the new set
        self.retain(|key, _| valid_ids.contains(key));

        // Insert or update all resources
        for resource in resources {
            let key = resource.id().to_string();
            log::debug!("Inserting or updating resource '{}'", key);
            self.insert(key, resource);
        }
    }

    fn insert_resource(&self, resource: Arc<T>) {
        let key = resource.id();
        log::debug!("Inserting resource '{}'", key);
        self.insert(key.to_string(), resource);
    }
}

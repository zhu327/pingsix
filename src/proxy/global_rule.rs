use std::sync::Arc;

use arc_swap::ArcSwap;
use dashmap::DashMap;
use once_cell::sync::Lazy;

use crate::{
    config::{self, Identifiable},
    core::{
        sort_plugins_by_priority_desc, ProxyError, ProxyPlugin, ProxyPluginExecutor, ProxyResult,
    },
    plugins::build_plugin,
};

use super::MapOperations;

/// Represents a proxy service that manages upstreams.
pub struct ProxyGlobalRule {
    pub inner: config::GlobalRule,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl Identifiable for ProxyGlobalRule {
    fn id(&self) -> &str {
        &self.inner.id
    }

    fn set_id(&mut self, id: String) {
        self.inner.id = id;
    }
}

impl ProxyGlobalRule {
    pub fn new_with_plugins(rule: config::GlobalRule) -> ProxyResult<Self> {
        let mut proxy_global_rule = ProxyGlobalRule {
            inner: rule.clone(),
            plugins: Vec::with_capacity(rule.plugins.len()),
        };

        // Load plugins and log each one
        for (name, value) in rule.plugins {
            log::info!("Loading plugin: {name}");
            let plugin = build_plugin(&name, value).map_err(|e| {
                ProxyError::Plugin(format!(
                    "Failed to build plugin '{}' for global rule '{}': {}",
                    name, rule.id, e
                ))
            })?;
            proxy_global_rule.plugins.push(plugin);
        }

        // Ensure deterministic order for plugins inside a single global rule.
        sort_plugins_by_priority_desc(proxy_global_rule.plugins.as_mut_slice());

        Ok(proxy_global_rule)
    }
}

/// Global map to store global rules, initialized lazily.
pub static GLOBAL_RULE_MAP: Lazy<DashMap<String, Arc<ProxyGlobalRule>>> = Lazy::new(DashMap::new);
static GLOBAL_PLUGIN: Lazy<ArcSwap<ProxyPluginExecutor>> =
    Lazy::new(|| ArcSwap::new(Arc::new(ProxyPluginExecutor::default())));

pub fn global_plugin_fetch() -> Arc<ProxyPluginExecutor> {
    GLOBAL_PLUGIN.load().clone()
}

/// Reloads global plugin executor from all GlobalRules (Scheme B).
///
/// Semantics:
/// - Do NOT deduplicate by plugin name: multiple GlobalRules may contribute the same plugin type.
/// - Produce a deterministic execution order independent of DashMap iteration order:
///   sort by (priority desc, plugin name asc, global_rule_id asc).
pub fn reload_global_plugin() {
    // Collect all rules first, then sort deterministically by id (DashMap iteration is not stable).
    let mut rules: Vec<Arc<ProxyGlobalRule>> =
        GLOBAL_RULE_MAP.iter().map(|e| e.value().clone()).collect();
    rules.sort_by(|a, b| a.inner.id.cmp(&b.inner.id));

    // Flatten plugins while keeping the originating rule id for deterministic tie-breaking.
    let mut plugins_with_rule: Vec<(String, Arc<dyn ProxyPlugin>)> = Vec::new();
    for rule in rules {
        let rule_id = rule.inner.id.clone();
        for plugin in &rule.plugins {
            plugins_with_rule.push((rule_id.clone(), plugin.clone()));
        }
    }

    plugins_with_rule.sort_by(|(rule_a, plugin_a), (rule_b, plugin_b)| {
        plugin_b
            .priority()
            .cmp(&plugin_a.priority())
            .then_with(|| plugin_a.name().cmp(plugin_b.name()))
            .then_with(|| rule_a.cmp(rule_b))
    });

    let plugins: Vec<Arc<dyn ProxyPlugin>> = plugins_with_rule
        .into_iter()
        .map(|(_, plugin)| plugin)
        .collect();

    GLOBAL_PLUGIN.store(Arc::new(ProxyPluginExecutor { plugins }));
}

/// Loads services from the given configuration.
pub fn load_static_global_rules(config: &config::Config) -> ProxyResult<()> {
    let proxy_global_rules: Vec<Arc<ProxyGlobalRule>> = config
        .global_rules
        .iter()
        .map(|rule| {
            log::info!("Configuring GlobalRule: {}", rule.id);

            // Attempt to create a ProxyGlobalRule with plugins
            match ProxyGlobalRule::new_with_plugins(rule.clone()) {
                Ok(proxy_global_rule) => Ok(Arc::new(proxy_global_rule)),
                Err(e) => {
                    log::error!("Failed to configure GlobalRule {}: {}", rule.id, e);
                    Err(e)
                }
            }
        })
        .collect::<ProxyResult<Vec<_>>>()?;

    // Reload global rules into the map
    GLOBAL_RULE_MAP.reload_resources(proxy_global_rules);
    reload_global_plugin();

    Ok(())
}

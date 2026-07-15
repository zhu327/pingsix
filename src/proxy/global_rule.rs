use std::{collections::HashMap, sync::Arc};

use crate::{
    config::{self, Identifiable},
    core::{
        sort_plugins_by_priority_desc, ProxyError, ProxyPlugin, ProxyPluginExecutor, ProxyResult,
    },
    plugins::build_plugin_with_upstreams,
    proxy::upstream::ProxyUpstream,
};

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
    pub(crate) fn build(
        rule: config::GlobalRule,
        upstreams: &HashMap<String, Arc<ProxyUpstream>>,
    ) -> ProxyResult<Self> {
        let mut proxy_global_rule = ProxyGlobalRule {
            inner: rule.clone(),
            plugins: Vec::with_capacity(rule.plugins.len()),
        };

        // Load plugins and log each one
        for (name, value) in rule.plugins {
            log::info!("Loading plugin: {name}");
            let plugin = build_plugin_with_upstreams(&name, value, upstreams).map_err(|e| {
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

pub(crate) fn build_global_plugin_executor(
    rules: &HashMap<String, Arc<ProxyGlobalRule>>,
) -> Arc<ProxyPluginExecutor> {
    let mut rules: Vec<Arc<ProxyGlobalRule>> = rules.values().cloned().collect();
    rules.sort_by(|a, b| a.inner.id.cmp(&b.inner.id));

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

    Arc::new(ProxyPluginExecutor::new(
        plugins_with_rule
            .into_iter()
            .map(|(_, plugin)| plugin)
            .collect(),
    ))
}

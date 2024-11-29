use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use pingora_error::Result;

use crate::config;

use super::{
    plugin::{build_plugin, ProxyPlugin, ProxyPluginExecutor},
    Identifiable,
};

/// Global map to store global rules, initialized lazily.
static GLOBAL_RULE_MAP: Lazy<RwLock<HashMap<String, Arc<ProxyGlobalRule>>>> =
    Lazy::new(|| RwLock::new(HashMap::new()));
static GLOBAL_PLUGIN: Lazy<ArcSwap<ProxyPluginExecutor>> =
    Lazy::new(|| ArcSwap::new(Arc::new(ProxyPluginExecutor::default())));

pub fn global_plugin_fetch() -> Arc<ProxyPluginExecutor> {
    GLOBAL_PLUGIN.load().clone()
}

/// reload ProxyPluginExecutor
pub fn reload_global_plugin() {
    // 获取 GLOBAL_RULE_MAP 的可读锁
    let global_rules = GLOBAL_RULE_MAP.read().unwrap();

    // 创建一个 HashMap 用来去重插件
    let mut unique_plugins: HashMap<String, Arc<dyn ProxyPlugin>> = HashMap::new();

    // 遍历 GLOBAL_RULE_MAP 中的所有 ProxyGlobalRule
    for rule in global_rules.values() {
        for plugin in &rule.plugins {
            // 使用 plugin.name() 作为唯一标识符，去重
            let plugin_name = plugin.name(); // 假设 ProxyPlugin 实现了 name() 方法
            unique_plugins.insert(plugin_name.to_string(), plugin.clone());
        }
    }

    // 从 HashMap 获取去重后的插件并根据 priority 排序
    let mut plugins: Vec<_> = unique_plugins.into_values().collect();

    // 按照 ProxyPlugin.priority() 排序，优先级大的排前面
    plugins.sort_by_key(|b| std::cmp::Reverse(b.priority()));

    // 创建并返回 ProxyPluginExecutor
    GLOBAL_PLUGIN.store(Arc::new(ProxyPluginExecutor { plugins }));
}

/// Loads services from the given configuration.
pub fn load_global_rules(config: &config::Config) -> Result<()> {
    {
        let mut map = GLOBAL_RULE_MAP
            .write()
            .expect("Failed to acquire write lock on the global rule map");

        for rule in config.global_rules.iter() {
            log::info!("Configuring GlobalRule: {}", rule.id);
            let mut proxy_global_rule = ProxyGlobalRule::from(rule.clone());

            // load service plugins
            for (name, value) in rule.plugins.clone() {
                let plugin = build_plugin(&name, value)?;
                proxy_global_rule.plugins.push(plugin);
            }

            map.insert(rule.id.clone(), Arc::new(proxy_global_rule));
        }

        // release the write lock
    }

    reload_global_plugin();

    Ok(())
}

/// Represents a proxy service that manages upstreams.
pub struct ProxyGlobalRule {
    pub inner: config::GlobalRule,
    pub plugins: Vec<Arc<dyn ProxyPlugin>>,
}

impl Identifiable for ProxyGlobalRule {
    fn id(&self) -> String {
        self.inner.id.clone()
    }
}

impl From<config::GlobalRule> for ProxyGlobalRule {
    fn from(value: config::GlobalRule) -> Self {
        Self {
            inner: value,
            plugins: Vec::new(),
        }
    }
}

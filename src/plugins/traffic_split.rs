use async_trait::async_trait;
use pingora_error::Result;
use pingora_proxy::Session;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::{collections::HashMap, sync::Arc};
use validator::Validate;

use crate::config::{Upstream, UpstreamHashOn};
use crate::core::{
    HealthCheckSpec, ProxyContext, ProxyError, ProxyPlugin, ProxyResult, UpstreamSelector,
};
use crate::proxy::upstream::{traffic_split_key, PreparedUpstreams, ProxyUpstream};
use crate::utils::request::request_selector_key;

pub const PLUGIN_NAME: &str = "traffic-split";
const PRIORITY: i32 = 966;

#[derive(Debug, Serialize, Deserialize, Validate)]
struct WeightedUpstream {
    pub upstream_id: Option<String>,
    pub upstream: Option<Upstream>,
    #[validate(range(min = 0))]
    pub weight: u32,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct MatchRule {
    #[serde(default)]
    pub vars: Vec<Vec<String>>,
    #[validate(nested)]
    pub weighted_upstreams: Vec<WeightedUpstream>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[validate(nested)]
    pub rules: Vec<MatchRule>,
}

/// Weighted target after compilation. `PassThrough` keeps the route default upstream.
#[derive(Clone)]
enum WeightedTarget {
    Upstream(Arc<dyn UpstreamSelector>),
    PassThrough,
}

struct CompiledRule {
    targets: Vec<(u32, WeightedTarget)>,
    total_weight: u64,
}

pub struct PluginTrafficSplit {
    config: PluginConfig,
    rules: Vec<CompiledRule>,
    health_check_specs: Vec<HealthCheckSpec>,
}

#[async_trait]
impl ProxyPlugin for PluginTrafficSplit {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
    fn priority(&self) -> i32 {
        PRIORITY
    }

    fn health_check_targets(
        &self,
    ) -> Vec<(
        String,
        Arc<dyn pingora_core::services::background::BackgroundService + Send + Sync>,
    )> {
        self.health_check_specs
            .iter()
            .map(|spec| (spec.key.clone(), spec.service.clone()))
            .collect()
    }

    fn health_check_specs(&self) -> Option<Vec<HealthCheckSpec>> {
        Some(
            self.health_check_specs
                .iter()
                .map(|spec| HealthCheckSpec {
                    key: spec.key.clone(),
                    fingerprint: spec.fingerprint,
                    service: spec.service.clone(),
                })
                .collect(),
        )
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        for (rule_idx, rule) in self.config.rules.iter().enumerate() {
            if self.match_vars(session, &rule.vars) {
                match self.pick_upstream(rule_idx) {
                    Some(WeightedTarget::Upstream(selected)) => {
                        ctx.upstream_override = Some(selected);
                    }
                    Some(WeightedTarget::PassThrough) => {
                        ctx.upstream_override = None;
                    }
                    None => {}
                }
                return Ok(false);
            }
        }
        Ok(false)
    }
}

impl PluginTrafficSplit {
    fn match_vars(&self, session: &mut Session, vars: &[Vec<String>]) -> bool {
        if vars.is_empty() {
            return true;
        }

        for v in vars {
            if v.len() < 3 {
                continue;
            }
            let var_name = &v[0];
            let op = &v[1];
            let val = &v[2];

            let actual_val = if let Some(header_name) = var_name.strip_prefix("http_") {
                request_selector_key(session, &UpstreamHashOn::HEAD, header_name)
            } else {
                request_selector_key(session, &UpstreamHashOn::VARS, var_name)
            };

            match op.as_str() {
                "==" => {
                    if actual_val != *val {
                        return false;
                    }
                }
                "!=" => {
                    if actual_val == *val {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        true
    }

    fn pick_upstream(&self, rule_idx: usize) -> Option<WeightedTarget> {
        let rule = &self.rules[rule_idx];
        if rule.total_weight == 0 {
            return None;
        }

        let mut rng = rand::thread_rng();
        let mut n = rng.gen_range(0..rule.total_weight);

        for (weight, target) in &rule.targets {
            let w = u64::from(*weight);
            if n < w {
                return Some(target.clone());
            }
            n -= w;
        }
        None
    }
}

pub fn create_traffic_split_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    // Admin / registry path: structural validation only. Named upstream existence is
    // checked later by CandidateSnapshot against the same-version resource graph.
    create_traffic_split_plugin_with_upstreams(cfg, &HashMap::new(), &HashMap::new(), "admin")
}

/// Validate traffic-split JSON without resolving named upstreams (Admin pre-check).
pub fn validate_traffic_split_config(cfg: &JsonValue) -> ProxyResult<()> {
    let config: PluginConfig = serde_json::from_value(cfg.clone())
        .map_err(|e| ProxyError::Serialization(e.to_string()))?;
    config.validate()?;
    if config.rules.is_empty() {
        return Err(ProxyError::Plugin(
            "Traffic-split plugin requires at least one rule".to_string(),
        ));
    }
    for (rule_idx, rule) in config.rules.iter().enumerate() {
        if rule.weighted_upstreams.is_empty() {
            return Err(ProxyError::Plugin(format!(
                "Rule {rule_idx} must have at least one weighted upstream"
            )));
        }
        let total_weight = rule
            .weighted_upstreams
            .iter()
            .try_fold(0_u64, |acc, item| {
                acc.checked_add(u64::from(item.weight)).ok_or_else(|| {
                    ProxyError::Configuration("traffic-split weight overflow".into())
                })
            })?;
        if total_weight == 0 {
            return Err(ProxyError::Plugin(format!(
                "Rule {rule_idx} must have total weight greater than 0"
            )));
        }
        for wu in &rule.weighted_upstreams {
            if wu.upstream_id.is_some() && wu.upstream.is_some() {
                return Err(ProxyError::Configuration(
                    "traffic-split target cannot set both upstream_id and upstream".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Collect named `upstream_id` references from a traffic-split config value.
///
/// Used by Admin/graph validation so route/service/global-rule plugins are
/// checked against the same resource set as `CandidateSnapshot::build`.
pub fn named_upstream_ids(cfg: &JsonValue) -> ProxyResult<Vec<String>> {
    let config: PluginConfig = serde_json::from_value(cfg.clone())
        .map_err(|e| ProxyError::Serialization(e.to_string()))?;
    let mut ids = Vec::new();
    for rule in &config.rules {
        for wu in &rule.weighted_upstreams {
            if let Some(id) = wu.upstream_id.as_ref() {
                ids.push(id.clone());
            }
        }
    }
    Ok(ids)
}

pub(crate) fn create_traffic_split_plugin_with_upstreams(
    cfg: JsonValue,
    upstreams: &HashMap<String, Arc<ProxyUpstream>>,
    prepared: &PreparedUpstreams,
    owner: &str,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_json::from_value(cfg).map_err(|e| ProxyError::Serialization(e.to_string()))?;

    config.validate()?;

    if config.rules.is_empty() {
        return Err(ProxyError::Plugin(
            "Traffic-split plugin requires at least one rule".to_string(),
        ));
    }

    let mut rules = Vec::with_capacity(config.rules.len());
    let mut health_check_specs = Vec::new();

    for (rule_idx, rule) in config.rules.iter().enumerate() {
        if rule.weighted_upstreams.is_empty() {
            return Err(ProxyError::Plugin(format!(
                "Rule {rule_idx} must have at least one weighted upstream"
            )));
        }

        let total_weight = rule
            .weighted_upstreams
            .iter()
            .try_fold(0_u64, |acc, item| {
                acc.checked_add(u64::from(item.weight)).ok_or_else(|| {
                    ProxyError::Configuration("traffic-split weight overflow".into())
                })
            })?;

        if total_weight == 0 {
            return Err(ProxyError::Plugin(format!(
                "Rule {rule_idx} must have total weight greater than 0"
            )));
        }

        let mut targets = Vec::with_capacity(rule.weighted_upstreams.len());
        for (upstream_idx, wu) in rule.weighted_upstreams.iter().enumerate() {
            if wu.upstream_id.is_some() && wu.upstream.is_some() {
                return Err(ProxyError::Configuration(
                    "traffic-split target cannot set both upstream_id and upstream".into(),
                ));
            }
            let target = if let Some(id) = wu.upstream_id.as_deref() {
                WeightedTarget::Upstream(upstreams.get(id).cloned().ok_or_else(|| {
                    ProxyError::Configuration(format!(
                        "Traffic-split references missing upstream '{id}'"
                    ))
                })? as Arc<dyn UpstreamSelector>)
            } else if let Some(ref inline) = wu.upstream {
                let upstream = Arc::new(ProxyUpstream::build(
                    inline.clone(),
                    prepared
                        .get(&traffic_split_key(owner, rule_idx, upstream_idx))
                        .cloned()
                        .ok_or_else(|| ProxyError::Configuration(format!(
                            "Traffic-split inline upstream {rule_idx}/{upstream_idx} was not prepared"
                        )))?,
                )?);
                health_check_specs.push(HealthCheckSpec {
                    key: format!("traffic-split/{rule_idx}/{upstream_idx}"),
                    fingerprint: crate::proxy::runtime::fingerprint_upstream_for_health_check(
                        &upstream.inner,
                    ),
                    service: upstream.health_check_service(),
                });
                WeightedTarget::Upstream(upstream as Arc<dyn UpstreamSelector>)
            } else {
                WeightedTarget::PassThrough
            };
            targets.push((wu.weight, target));
        }

        rules.push(CompiledRule {
            targets,
            total_weight,
        });
    }

    Ok(Arc::new(PluginTrafficSplit {
        config,
        rules,
        health_check_specs,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{SelectionType, UpstreamHashOn, UpstreamPassHost, UpstreamScheme};

    fn sample_upstream(id: &str) -> Upstream {
        let mut nodes = HashMap::new();
        nodes.insert("127.0.0.1:8080".into(), 1);
        Upstream {
            id: id.into(),
            retries: None,
            retry_timeout: None,
            timeout: None,
            nodes,
            r#type: SelectionType::RoundRobin,
            checks: None,
            hash_on: UpstreamHashOn::VARS,
            key: "uri".into(),
            scheme: UpstreamScheme::HTTP,
            pass_host: UpstreamPassHost::PASS,
            upstream_host: None,
            tls: None,
        }
    }

    #[test]
    fn pass_through_target_is_allowed() {
        let cfg = serde_json::json!({
            "rules": [{
                "weighted_upstreams": [
                    { "weight": 1 },
                    { "upstream_id": "u1", "weight": 1 }
                ]
            }]
        });
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "u1".into(),
            Arc::new(ProxyUpstream::build_static(sample_upstream("u1")).unwrap()),
        );
        let plugin =
            create_traffic_split_plugin_with_upstreams(cfg, &upstreams, &HashMap::new(), "test")
                .unwrap();
        let specs = plugin.health_check_specs().unwrap();
        assert!(specs.is_empty());
    }

    #[test]
    fn large_weights_do_not_wrap_like_u32_sum() {
        // Summing as u32 would wrap u32::MAX + 1 to 0; u64 checked path accepts this.
        let cfg = serde_json::json!({
            "rules": [{
                "weighted_upstreams": [
                    { "upstream_id": "u1", "weight": u32::MAX },
                    { "upstream_id": "u1", "weight": 1 }
                ]
            }]
        });
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "u1".into(),
            Arc::new(ProxyUpstream::build_static(sample_upstream("u1")).unwrap()),
        );
        assert!(create_traffic_split_plugin_with_upstreams(
            cfg,
            &upstreams,
            &HashMap::new(),
            "test"
        )
        .is_ok());
    }

    #[test]
    fn zero_total_weight_is_rejected() {
        let cfg = serde_json::json!({
            "rules": [{
                "weighted_upstreams": [
                    { "weight": 0 },
                    { "upstream_id": "u1", "weight": 0 }
                ]
            }]
        });
        let mut upstreams = HashMap::new();
        upstreams.insert(
            "u1".into(),
            Arc::new(ProxyUpstream::build_static(sample_upstream("u1")).unwrap()),
        );
        assert!(create_traffic_split_plugin_with_upstreams(
            cfg,
            &upstreams,
            &HashMap::new(),
            "test"
        )
        .is_err());
    }

    #[test]
    fn missing_named_upstream_is_rejected() {
        let cfg = serde_json::json!({
            "rules": [{
                "weighted_upstreams": [
                    { "upstream_id": "missing", "weight": 1 }
                ]
            }]
        });
        let upstreams = HashMap::new();
        assert!(create_traffic_split_plugin_with_upstreams(
            cfg,
            &upstreams,
            &HashMap::new(),
            "test"
        )
        .is_err());
    }

    #[test]
    fn dual_upstream_id_and_inline_is_rejected() {
        let cfg = serde_json::json!({
            "rules": [{
                "weighted_upstreams": [{
                    "upstream_id": "u1",
                    "upstream": {
                        "nodes": { "127.0.0.1:8080": 1 },
                        "type": "roundrobin"
                    },
                    "weight": 1
                }]
            }]
        });
        assert!(validate_traffic_split_config(&cfg).is_err());
    }
}

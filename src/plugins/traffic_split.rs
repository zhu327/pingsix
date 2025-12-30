use async_trait::async_trait;
use pingora_error::Result;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::sync::Arc;
use validator::Validate;

use crate::config::{Upstream, UpstreamHashOn};
use crate::core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult, UpstreamSelector};
use crate::proxy::upstream::{upstream_fetch, ProxyUpstream};
use crate::utils::request::request_selector_key;

pub const PLUGIN_NAME: &str = "traffic-split";
const PRIORITY: i32 = 966;

// Context key for sharing upstream override between plugin and HttpService
pub const CTX_KEY_UPSTREAM_OVERRIDE: &str = "pingsix_upstream_override";

#[derive(Debug, Serialize, Deserialize, Validate)]
struct WeightedUpstream {
    pub upstream_id: Option<String>,
    pub upstream: Option<Upstream>, // Inline definition
    #[validate(range(min = 0))]
    pub weight: u32,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct MatchRule {
    #[serde(default)]
    pub vars: Vec<Vec<String>>, // [["arg_name", "==", "val"], ["http_x", "!=", "reg"]]
    #[validate(nested)]
    pub weighted_upstreams: Vec<WeightedUpstream>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[validate(nested)]
    pub rules: Vec<MatchRule>,
}

pub struct PluginTrafficSplit {
    config: PluginConfig,
    // Pre-compute inline upstream definitions for faster lookups
    rule_upstreams: Vec<Vec<Option<Arc<ProxyUpstream>>>>,
}

#[async_trait]
impl ProxyPlugin for PluginTrafficSplit {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool> {
        for (rule_idx, rule) in self.config.rules.iter().enumerate() {
            if self.match_vars(session, &rule.vars) {
                // Rule matched; run weighted upstream selection
                if let Some(selected_ups) = self.pick_upstream(rule_idx, &rule.weighted_upstreams) {
                    ctx.set(CTX_KEY_UPSTREAM_OVERRIDE, selected_ups);
                }
                return Ok(false); // Stop at the first matching rule
            }
        }
        Ok(false)
    }
}

impl PluginTrafficSplit {
    // Variable matching logic
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

            // Reuse the existing selector helpers for extracting values
            // If the name starts with http_, read from headers, otherwise read from vars.
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

    fn pick_upstream(
        &self,
        rule_idx: usize,
        upstreams: &[WeightedUpstream],
    ) -> Option<Arc<dyn UpstreamSelector>> {
        let total_weight: u32 = upstreams.iter().map(|u| u.weight).sum();
        if total_weight == 0 {
            return None;
        }

        let mut n = rand::random_range(0..total_weight);

        for (i, ups_cfg) in upstreams.iter().enumerate() {
            if n < ups_cfg.weight {
                // 1. Use the referenced upstream when upstream_id is present
                if let Some(ref id) = ups_cfg.upstream_id {
                    return upstream_fetch(id).map(|u| u as Arc<dyn UpstreamSelector>);
                }
                // 2. Fall back to the pre-created inline upstream for this rule
                if let Some(ref inline_ups) = self.rule_upstreams[rule_idx][i] {
                    return Some(inline_ups.clone() as Arc<dyn UpstreamSelector>);
                }
                // 3. If weight > 0 but no upstream declared, continue with the route's upstream
                return None;
            }
            n -= ups_cfg.weight;
        }
        None
    }
}

pub fn create_traffic_split_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig =
        serde_json::from_value(cfg).map_err(|e| ProxyError::Serialization(e.to_string()))?;

    // Validate configuration using validator crate
    config.validate()?;

    // Additional business logic validation
    if config.rules.is_empty() {
        return Err(ProxyError::Plugin(
            "Traffic-split plugin requires at least one rule".to_string(),
        ));
    }

    for (idx, rule) in config.rules.iter().enumerate() {
        if rule.weighted_upstreams.is_empty() {
            return Err(ProxyError::Plugin(format!(
                "Rule {idx} must have at least one weighted upstream"
            )));
        }

        let total_weight: u32 = rule.weighted_upstreams.iter().map(|u| u.weight).sum();
        if total_weight == 0 {
            return Err(ProxyError::Plugin(format!(
                "Rule {idx} must have total weight greater than 0"
            )));
        }

        // Validate that each weighted upstream has either upstream_id or inline upstream
        for (wu_idx, wu) in rule.weighted_upstreams.iter().enumerate() {
            if wu.upstream_id.is_none() && wu.upstream.is_none() {
                return Err(ProxyError::Plugin(format!(
                    "Rule {idx} weighted_upstream {wu_idx} must have either upstream_id or upstream defined"
                )));
            }
        }
    }

    let mut rule_upstreams = Vec::new();
    for rule in &config.rules {
        let mut ups_list = Vec::new();
        for wu in &rule.weighted_upstreams {
            if let Some(ref inline) = wu.upstream {
                let p_ups = ProxyUpstream::new_with_shared_health_check(inline.clone())?;
                ups_list.push(Some(Arc::new(p_ups)));
            } else {
                ups_list.push(None);
            }
        }
        rule_upstreams.push(ups_list);
    }

    Ok(Arc::new(PluginTrafficSplit {
        config,
        rule_upstreams,
    }))
}

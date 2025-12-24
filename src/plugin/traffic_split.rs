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

#[derive(Debug, Serialize, Deserialize, Validate)]
struct WeightedUpstream {
    pub upstream_id: Option<String>,
    pub upstream: Option<Upstream>, // 内联定义
    #[validate(range(min = 0))]
    pub weight: u32,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct MatchRule {
    #[serde(default)]
    pub vars: Vec<Vec<String>>, // 格式如 [["arg_name", "==", "val"], ["header_x", "~=", "reg"]]
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
    // 为了性能，预先将内联 upstream 转换为 ProxyUpstream
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
                // 命中规则，执行加权选择
                if let Some(selected_ups) = self.pick_upstream(rule_idx, &rule.weighted_upstreams) {
                    ctx.upstream_override = Some(selected_ups);
                }
                break; // 匹配到第一个规则即停止
            }
        }
        Ok(false)
    }
}

impl PluginTrafficSplit {
    // 变量匹配逻辑
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

            // 借助 PingSIX 现有的变量提取逻辑
            let actual_val = request_selector_key(session, &UpstreamHashOn::VARS, var_name);

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
                // 1. 如果有 upstream_id，从全局 Map 获取
                if let Some(ref id) = ups_cfg.upstream_id {
                    return upstream_fetch(id).map(|u| u as Arc<dyn UpstreamSelector>);
                }
                // 2. 如果是内联 upstream，使用预创建的对象
                if let Some(ref inline_ups) = self.rule_upstreams[rule_idx][i] {
                    return Some(inline_ups.clone() as Arc<dyn UpstreamSelector>);
                }
                // 3. 如果 weight > 0 但没给上游，表示使用 Route 默认上游（返回 None）
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

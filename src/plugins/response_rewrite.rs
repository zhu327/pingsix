use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    config::UpstreamHashOn,
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::request::request_selector_key,
};

pub const PLUGIN_NAME: &str = "response-rewrite";
const PRIORITY: i32 = 899;

pub fn create_response_rewrite_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    Ok(Arc::new(PluginResponseRewrite { config }))
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum HeadersConfig {
    /// Simple mode: {"Header": "Value"}
    Simple(HashMap<String, String>),
    /// Structured mode: {"set": {}, "add": [], "remove": []}
    Structured {
        #[serde(default)]
        add: Vec<String>,
        #[serde(default)]
        set: HashMap<String, String>,
        #[serde(default)]
        remove: Vec<String>,
    },
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    status_code: Option<u16>,
    headers: Option<HeadersConfig>,
    /// Format like [["arg_name", "==", "val"], ["http_x", "!=", "reg"]]
    vars: Option<Vec<Vec<String>>>,
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        let config: PluginConfig = serde_json::from_value(value).map_err(|e| {
            ProxyError::serialization_error("Failed to parse response-rewrite config", e)
        })?;
        config.validate()?;
        Ok(config)
    }
}

pub struct PluginResponseRewrite {
    config: PluginConfig,
}

impl PluginResponseRewrite {
    /// Variable matching logic (shared with the traffic-split plugin)
    fn match_vars(&self, session: &mut Session, vars: &Option<Vec<Vec<String>>>) -> bool {
        let Some(vars) = vars else { return true };
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

    /// Expand header templates by swapping `$var` placeholders with actual values.
    fn expand_vars(&self, session: &mut Session, val: &str) -> String {
        if !val.contains('$') {
            return val.to_string();
        }

        // Minimal implementation; extend with regex matching if more placeholders are introduced.
        let mut result = val.to_string();
        let placeholders = ["$remote_addr", "$upstream_addr", "$request_id"];

        for p in placeholders {
            if result.contains(p) {
                let actual = match p {
                    "$remote_addr" => {
                        request_selector_key(session, &UpstreamHashOn::VARS, "remote_addr")
                    }
                    _ => "".to_string(),
                };
                result = result.replace(p, &actual);
            }
        }
        result
    }
}

#[async_trait]
impl ProxyPlugin for PluginResponseRewrite {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }
    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn response_filter(
        &self,
        session: &mut Session,
        upstream_response: &mut ResponseHeader,
        _ctx: &mut ProxyContext,
    ) -> Result<()> {
        // 1. Check matching conditions
        if !self.match_vars(session, &self.config.vars) {
            return Ok(());
        }

        // 2. Override the status code when configured
        if let Some(code) = self.config.status_code {
            if let Ok(status) = StatusCode::from_u16(code) {
                let _ = upstream_response.set_status(status);
            }
        }

        // 3. Apply header mutations
        if let Some(ref h_cfg) = self.config.headers {
            match h_cfg {
                HeadersConfig::Simple(headers) => {
                    for (k, v) in headers {
                        let val = self.expand_vars(session, v);
                        upstream_response.insert_header(k.clone(), val)?;
                    }
                }
                HeadersConfig::Structured { add, set, remove } => {
                    // Remove
                    for k in remove {
                        upstream_response.remove_header(k);
                    }
                    // Set
                    for (k, v) in set {
                        let val = self.expand_vars(session, v);
                        upstream_response.insert_header(k.clone(), val)?;
                    }
                    // Add
                    for entry in add {
                        if let Some((k, v)) = entry.split_once(':') {
                            let val = self.expand_vars(session, v.trim());
                            upstream_response.append_header(k.trim().to_string(), val)?;
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

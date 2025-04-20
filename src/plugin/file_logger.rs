use std::sync::Arc;

use async_trait::async_trait;
use log::info;
use pingora_core::{Error, Result};
use pingora_error::{ErrorType::ReadError, OrErr};
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_yaml::Value as YamlValue;

use crate::{proxy::ProxyContext, utils::request};

use super::ProxyPlugin;

pub const PLUGIN_NAME: &str = "file-logger";
const PRIORITY: i32 = 399;

/// Creates a file logger plugin instance with the given configuration.
pub fn create_file_logger_plugin(cfg: YamlValue) -> Result<Arc<dyn ProxyPlugin>> {
    let config: PluginConfig = serde_yaml::from_value(cfg)
        .or_err_with(ReadError, || "Invalid file logger plugin config")?;

    let log_format = LogFormat::parse(&config.log_format)?;

    Ok(Arc::new(PluginFileLogger { log_format }))
}

/// Configuration for the file logger plugin.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PluginConfig {
    /// The log format string, containing static text and variables (e.g., `$remote_addr "$request_method $uri" $status`).
    /// Supported variables include: `request_method`, `uri`, `query_string`, `http_host`, `request_time`,
    /// `http_user_agent`, `http_referer`, `remote_addr`, `remote_port`, `server_addr`, `status`,
    /// `server_protocol`, `request_id`, `body_bytes_sent`, `error`, and custom variables via `var_<name>`.
    #[serde(default = "PluginConfig::default_log_format")]
    log_format: String,
}

impl PluginConfig {
    fn default_log_format() -> String {
        "$remote_addr \"$request_method $uri\" $status".to_string()
    }
}

/// File logger plugin implementation.
pub struct PluginFileLogger {
    log_format: LogFormat,
}

#[async_trait]
impl ProxyPlugin for PluginFileLogger {
    fn name(&self) -> &str {
        PLUGIN_NAME
    }

    fn priority(&self) -> i32 {
        PRIORITY
    }

    async fn logging(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) {
        info!("{}", self.log_format.render(session, e, ctx));
    }
}

#[derive(Debug)]
enum Segment {
    Static(String),
    Variable(String),
}

#[derive(Debug)]
struct LogFormat {
    segments: Vec<Segment>,
}

impl LogFormat {
    /// Parses a log format string into a `LogFormat` struct.
    /// Variables are identified by `$` prefix (e.g., `$remote_addr`).
    fn parse(format: &str) -> Result<Self> {
        let re = Regex::new(r"\$[a-zA-Z0-9_]+")
            .or_err_with(ReadError, || "Failed to parse log format")?;
        let mut segments = Vec::new();
        let mut last_pos = 0;

        for mat in re.find_iter(format) {
            // Add static part before the variable
            if last_pos < mat.start() {
                segments.push(Segment::Static(format[last_pos..mat.start()].to_string()));
            }
            // Add variable (remove $ prefix)
            segments.push(Segment::Variable(mat.as_str()[1..].to_string()));
            last_pos = mat.end();
        }

        // Add remaining static part
        if last_pos < format.len() {
            segments.push(Segment::Static(format[last_pos..].to_string()));
        }

        Ok(LogFormat { segments })
    }

    /// Renders the log format into a string, replacing variables with their values.
    /// Supports built-in variables (e.g., `request_method`, `status`) and custom variables
    /// via `var_<name>` (e.g., `var_my_custom_data` from `ctx.vars`).
    /// The `error` variable is populated from the `e` parameter, which is guaranteed by
    /// `Pingora::ProxyHttp::logging` to be passed correctly.
    fn render(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) -> String {
        // Pre-estimate capacity: template length + average variable value lengths
        let estimated_len = self.segments.iter().fold(0, |acc, seg| {
            acc + match seg {
                Segment::Static(s) => s.len(),
                Segment::Variable(var) => match var.as_str() {
                    "status" => 4,            // 3-4 bytes (e.g., "200")
                    "request_method" => 8,    // 3-7 bytes (e.g., "GET")
                    "request_id" => 36,       // UUID length
                    "http_user_agent" => 128, // Browser UA can be long
                    _ => 32,                  // Default for other variables
                },
            }
        });

        // Create output string with pre-allocated capacity
        let mut output = String::with_capacity(estimated_len);

        // Cache request header reference
        let req_header = session.req_header();

        for segment in &self.segments {
            match segment {
                Segment::Static(text) => output.push_str(text),
                Segment::Variable(var) => {
                    let value = if let Some(custom_var_name) = var.strip_prefix("var_") {
                        ctx.vars.get(custom_var_name).map_or("", |s| s.as_str())
                    } else {
                        match var.as_str() {
                            "request_method" => req_header.method.as_str(),
                            "uri" => req_header.uri.path(),
                            "query_string" => req_header.uri.query().unwrap_or_default(),
                            "http_host" => req_header.uri.host().unwrap_or_default(),
                            "request_time" => &ctx.request_start.elapsed().as_millis().to_string(),
                            "http_user_agent" => {
                                request::get_req_header_value(req_header, "user-agent")
                                    .unwrap_or_default()
                            }
                            "http_referer" => request::get_req_header_value(req_header, "referer")
                                .unwrap_or_default(),
                            "remote_addr" => &session
                                .client_addr()
                                .map(ToString::to_string)
                                .unwrap_or_default(),
                            "remote_port" => &session
                                .client_addr()
                                .and_then(|s| s.as_inet())
                                .map_or_else(|| "".to_string(), |i| i.port().to_string()),
                            "server_addr" => &session
                                .server_addr()
                                .map_or_else(|| "".to_string(), |addr| addr.to_string()),
                            "status" => &session
                                .response_written()
                                .map(|v| v.status.as_u16().to_string())
                                .unwrap_or_default(),
                            "server_protocol" => {
                                if session.is_http2() {
                                    "http/2"
                                } else {
                                    "http/1.1"
                                }
                            }
                            "request_id" => ctx.vars.get("request-id").map_or("", |s| s.as_str()),
                            "body_bytes_sent" => &session.body_bytes_sent().to_string(),
                            "error" => &e.map(|e| e.to_string()).unwrap_or_default(),
                            _ => "",
                        }
                    };
                    output.push_str(value);
                }
            }
        }

        output
    }
}

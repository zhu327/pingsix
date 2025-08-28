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
    estimated_capacity: usize, // Pre-calculated capacity estimation
}

impl LogFormat {
    /// Parses a log format string into a `LogFormat` struct.
    /// Variables are identified by `$` prefix (e.g., `$remote_addr`).
    fn parse(format: &str) -> Result<Self> {
        let re = Regex::new(r"\$[a-zA-Z0-9_]+")
            .or_err_with(ReadError, || "Failed to parse log format")?;
        let mut segments = Vec::new();
        let mut last_pos = 0;
        let mut estimated_capacity = 0;

        for mat in re.find_iter(format) {
            // Add static part before the variable
            if last_pos < mat.start() {
                let static_part = format[last_pos..mat.start()].to_string();
                estimated_capacity += static_part.len();
                segments.push(Segment::Static(static_part));
            }
            // Add variable (remove $ prefix)
            let var_name = mat.as_str()[1..].to_string();
            estimated_capacity += Self::estimate_variable_size(&var_name);
            segments.push(Segment::Variable(var_name));
            last_pos = mat.end();
        }

        // Add remaining static part
        if last_pos < format.len() {
            let static_part = format[last_pos..].to_string();
            estimated_capacity += static_part.len();
            segments.push(Segment::Static(static_part));
        }

        Ok(LogFormat {
            segments,
            estimated_capacity,
        })
    }

    /// Estimate the size of a variable for capacity pre-allocation
    fn estimate_variable_size(var_name: &str) -> usize {
        match var_name {
            "status" => 4,                           // 3-4 bytes (e.g., "200")
            "request_method" => 8,                   // 3-7 bytes (e.g., "GET")
            "request_id" => 36,                      // UUID length
            "http_user_agent" => 128,                // Browser UA can be long
            "uri" => 64,                             // Average URI length
            "query_string" => 32,                    // Average query string length
            "http_host" => 32,                       // Average host length
            "request_time" => 8,                     // Milliseconds as string
            "http_referer" => 64,                    // Average referer length
            "remote_addr" => 16,                     // IPv4/IPv6 address
            "remote_port" => 6,                      // Port number
            "server_addr" => 16,                     // Server address
            "server_protocol" => 8,                  // "http/1.1" or "http/2"
            "body_bytes_sent" => 12,                 // Large numbers
            "error" => 128,                          // Error messages can be long
            _ if var_name.starts_with("var_") => 32, // Custom variables
            _ => 16,                                 // Default for unknown variables
        }
    }

    /// Renders the log format into a string, replacing variables with their values.
    /// Supports built-in variables (e.g., `request_method`, `status`) and custom variables
    /// via `var_<name>` (e.g., `var_my_custom_data` from `ctx.vars`).
    /// The `error` variable is populated from the `e` parameter, which is guaranteed by
    /// `Pingora::ProxyHttp::logging` to be passed correctly.
    fn render(&self, session: &mut Session, e: Option<&Error>, ctx: &mut ProxyContext) -> String {
        // Create output string with pre-allocated capacity
        let mut output = String::with_capacity(self.estimated_capacity);

        for segment in &self.segments {
            match segment {
                Segment::Static(text) => output.push_str(text),
                Segment::Variable(var) => {
                    let value = self.get_variable_value(var, session, e, ctx);
                    output.push_str(value);
                }
            }
        }

        output
    }

    /// Extract variable value - separated for better readability and potential caching
    fn get_variable_value<'a>(
        &self,
        var: &str,
        session: &'a mut Session,
        e: Option<&'a Error>,
        ctx: &'a mut ProxyContext,
    ) -> &'a str {
        // Handle custom variables first
        if let Some(custom_var_name) = var.strip_prefix("var_") {
            return ctx.get_str(custom_var_name).unwrap_or("");
        }

        // Handle built-in variables
        match var {
            "request_method" => session.req_header().method.as_str(),
            "uri" => session.req_header().uri.path(),
            "query_string" => session.req_header().uri.query().unwrap_or_default(),
            "http_host" => session.req_header().uri.host().unwrap_or_default(),
            "request_time" => {
                // Store in context to avoid recalculation
                let key = "_log_request_time";
                if !ctx.contains(key) {
                    let time_str = ctx.request_start.elapsed().as_millis().to_string();
                    ctx.set(key, time_str);
                }
                ctx.get_str(key).unwrap_or("")
            }
            "http_user_agent" => request::get_req_header_value(session.req_header(), "user-agent")
                .unwrap_or_default(),
            "http_referer" => {
                request::get_req_header_value(session.req_header(), "referer").unwrap_or_default()
            }
            "remote_addr" => {
                // Cache remote address to avoid repeated computation
                let key = "_log_remote_addr";
                if !ctx.contains(key) {
                    let addr_str = session
                        .client_addr()
                        .map(|addr| addr.to_string())
                        .unwrap_or_default();
                    ctx.set(key, addr_str);
                }
                ctx.get_str(key).unwrap_or("")
            }
            "remote_port" => {
                // Cache remote port
                let key = "_log_remote_port";
                if !ctx.contains(key) {
                    let port_str = session
                        .client_addr()
                        .and_then(|s| s.as_inet())
                        .map_or_else(|| "".to_string(), |i| i.port().to_string());
                    ctx.set(key, port_str);
                }
                ctx.get_str(key).unwrap_or("")
            }
            "server_addr" => {
                // Cache server address
                let key = "_log_server_addr";
                if !ctx.contains(key) {
                    let addr_str = session
                        .server_addr()
                        .map_or_else(|| "".to_string(), |addr| addr.to_string());
                    ctx.set(key, addr_str);
                }
                ctx.get_str(key).unwrap_or("")
            }
            "status" => {
                // Cache status
                let key = "_log_status";
                if !ctx.contains(key) {
                    let status_str = session
                        .response_written()
                        .map(|v| v.status.as_u16().to_string())
                        .unwrap_or_default();
                    ctx.set(key, status_str);
                }
                ctx.get_str(key).unwrap_or("")
            }
            "server_protocol" => {
                if session.is_http2() {
                    "http/2"
                } else {
                    "http/1.1"
                }
            }
            "request_id" => ctx.get_str("request-id").unwrap_or(""),
            "body_bytes_sent" => {
                // Cache body bytes sent
                let key = "_log_body_bytes_sent";
                if !ctx.contains(key) {
                    let bytes_str = session.body_bytes_sent().to_string();
                    ctx.set(key, bytes_str);
                }
                ctx.get_str(key).unwrap_or("")
            }
            "error" => {
                // Cache error message
                let key = "_log_error";
                if !ctx.contains(key) {
                    let error_str = e.map(|e| e.to_string()).unwrap_or_default();
                    ctx.set(key, error_str);
                }
                ctx.get_str(key).unwrap_or("")
            }
            _ => "",
        }
    }
}

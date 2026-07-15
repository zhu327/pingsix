use std::sync::Arc;

use async_trait::async_trait;
use log::info;
use pingora_core::Error;
use pingora_error::Result;
use pingora_proxy::Session;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

use crate::{
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    utils::request,
};

pub const PLUGIN_NAME: &str = "file-logger";
const PRIORITY: i32 = 399;

fn push_escaped(output: &mut String, value: &str) {
    for character in value.chars() {
        match character {
            '\\' => output.push_str("\\\\"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character.is_control() => {
                use std::fmt::Write;
                let _ = write!(output, "\\u{{{:04x}}}", character as u32);
            }
            character => output.push(character),
        }
    }
}

fn redact_query(query: &str, names: &[String]) -> String {
    query
        .split('&')
        .map(|part| match part.split_once('=') {
            Some((name, _)) if names.iter().any(|candidate| candidate == name) => {
                format!("{name}=***")
            }
            _ => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Creates a file logger plugin instance with the given configuration.
pub fn create_file_logger_plugin(cfg: JsonValue) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let config = PluginConfig::try_from(cfg)?;
    let log_format = LogFormat::parse(&config.log_format)?;

    Ok(Arc::new(PluginFileLogger {
        log_format,
        redact_query_params: config.redact_query_params,
    }))
}

/// Configuration for the file logger plugin.
#[derive(Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PluginConfig {
    /// The log format string, containing static text and variables (e.g., `$remote_addr "$request_method $uri" $status`).
    /// Supported variables include: `request_method`, `uri`, `query_string`, `http_host`, `request_time`,
    /// `http_user_agent`, `http_referer`, `remote_addr`, `remote_port`, `server_addr`, `status`,
    /// `server_protocol`, `request_id`, `body_bytes_sent`, `error`, and custom variables via `var_<name>`.
    #[serde(default = "PluginConfig::default_log_format")]
    log_format: String,

    /// Query parameter names to redact from `$query_string` output.
    #[serde(default)]
    redact_query_params: Vec<String>,
}

impl PluginConfig {
    fn default_log_format() -> String {
        "$remote_addr \"$request_method $uri\" $status".to_string()
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
            .map_err(|e| ProxyError::serialization_error("Invalid file logger plugin config", e))
    }
}

/// File logger plugin implementation.
pub struct PluginFileLogger {
    log_format: LogFormat,
    redact_query_params: Vec<String>,
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
        info!(
            "{}",
            self.log_format
                .render(session, e, ctx, &self.redact_query_params)
        );
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
    fn parse(format: &str) -> ProxyResult<Self> {
        let re = Regex::new(r"\$[a-zA-Z0-9_]+")
            .map_err(|e| ProxyError::Internal(format!("Failed to parse log format: {e}")))?;
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
    fn render(
        &self,
        session: &mut Session,
        e: Option<&Error>,
        ctx: &mut ProxyContext,
        redact_query_params: &[String],
    ) -> String {
        // Create output string with pre-allocated capacity
        let mut output = String::with_capacity(self.estimated_capacity);

        for segment in &self.segments {
            match segment {
                Segment::Static(text) => output.push_str(text),
                Segment::Variable(var) => {
                    self.write_variable(&mut output, var, session, e, ctx, redact_query_params)
                }
            }
        }

        output
    }

    /// Writes a variable directly into the final buffer to avoid a temporary
    /// allocation for borrowed request fields.
    fn write_variable(
        &self,
        output: &mut String,
        var: &str,
        session: &mut Session,
        e: Option<&Error>,
        ctx: &mut ProxyContext,
        redact_query_params: &[String],
    ) {
        use std::fmt::Write;

        if let Some(custom_var_name) = var.strip_prefix("var_") {
            push_escaped(output, ctx.get_str(custom_var_name).unwrap_or(""));
            return;
        }

        match var {
            "request_method" => push_escaped(output, session.req_header().method.as_str()),
            "uri" => push_escaped(output, session.req_header().uri.path()),
            "query_string" => {
                let query = session.req_header().uri.query().unwrap_or_default();
                if redact_query_params.is_empty() {
                    push_escaped(output, query);
                } else {
                    push_escaped(output, &redact_query(query, redact_query_params));
                }
            }
            "http_host" => {
                push_escaped(output, session.req_header().uri.host().unwrap_or_default())
            }
            "request_time" => {
                let _ = write!(output, "{}", ctx.elapsed_ms());
            }
            "http_user_agent" => push_escaped(
                output,
                request::get_req_header_value(session.req_header(), "user-agent")
                    .unwrap_or_default(),
            ),
            "http_referer" => push_escaped(
                output,
                request::get_req_header_value(session.req_header(), "referer").unwrap_or_default(),
            ),
            "remote_addr" => {
                if let Some(addr) = session.client_addr() {
                    let _ = write!(output, "{addr}");
                }
            }
            "remote_port" => {
                if let Some(port) = session
                    .client_addr()
                    .and_then(|addr| addr.as_inet())
                    .map(|addr| addr.port())
                {
                    let _ = write!(output, "{port}");
                }
            }
            "server_addr" => {
                if let Some(addr) = session.server_addr() {
                    let _ = write!(output, "{addr}");
                }
            }
            "status" => {
                if let Some(response) = session.response_written() {
                    let _ = write!(output, "{}", response.status.as_u16());
                }
            }
            "server_protocol" => output.push_str(if session.is_http2() {
                "http/2"
            } else {
                "http/1.1"
            }),
            "request_id" => push_escaped(output, ctx.request_id().unwrap_or("")),
            "body_bytes_sent" => {
                let _ = write!(output, "{}", session.body_bytes_sent());
            }
            "error" => {
                if let Some(error) = e {
                    push_escaped(output, &format!("{error}"));
                }
            }
            _ => {}
        }
    }
}

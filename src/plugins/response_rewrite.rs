use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::{
    engine::general_purpose::{STANDARD, STANDARD_NO_PAD},
    Engine as _,
};
use bytes::{Bytes, BytesMut};
use http::StatusCode;
use pingora_error::Result;
use pingora_http::ResponseHeader;
use pingora_proxy::Session;
use regex::bytes as regex_bytes;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use validator::Validate;

use crate::{
    config::UpstreamHashOn,
    core::{ProxyContext, ProxyError, ProxyPlugin, ProxyResult},
    plugins::config::{parse_and_validate_plugin_config, HeaderValue},
    plugins::ctx_keys::next_instance_ctx_key,
    utils::{apisix_vars::match_apisix_vars, request::request_selector_key},
};

pub const PLUGIN_NAME: &str = "response-rewrite";
const PRIORITY: i32 = 899;

/// APISIX master default: 64 MiB.
const DEFAULT_MAX_RESP_BODY_SIZE: u64 = 64 * 1024 * 1024;
const DEFAULT_FILTER_OPTIONS: &str = "jo";

pub fn create_response_rewrite_plugin(
    cfg: JsonValue,
    _defaults: &crate::config::EffectiveDefaults,
) -> ProxyResult<Arc<dyn ProxyPlugin>> {
    let (config, compiled) = PluginConfig::build(cfg)?;
    Ok(Arc::new(PluginResponseRewrite { config, compiled }))
}

/// `PLUGIN_META::validate` capability: `PluginConfig::build` (also reachable
/// through `TryFrom`) performs every parse/compile check; validation runs it
/// and discards the artifact WITHOUT constructing the plugin.
pub fn validate_response_rewrite_config(cfg: &JsonValue) -> ProxyResult<()> {
    PluginConfig::try_from(cfg.clone())?;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
enum HeadersConfig {
    /// Simple mode: {"Header": "Value"}
    Simple(HashMap<String, HeaderValue>),
    /// Structured mode: {"set": {}, "add": [], "remove": []}
    Structured {
        #[serde(default)]
        add: Vec<String>,
        #[serde(default)]
        set: HashMap<String, HeaderValue>,
        #[serde(default)]
        remove: Vec<String>,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RegexScope {
    #[default]
    Once,
    Global,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct FilterConfig {
    #[validate(length(min = 1))]
    regex: String,
    #[serde(default)]
    scope: RegexScope,
    /// Replacement for each match. APISIX requires `replace` alongside
    /// `regex`; there is no default, so a porting mistake cannot silently
    /// delete body bytes. An empty replacement is expressible as `""`.
    replace: String,
    #[serde(default = "default_filter_options")]
    options: String,
}

fn default_filter_options() -> String {
    DEFAULT_FILTER_OPTIONS.to_string()
}

#[derive(Debug, Serialize, Deserialize, Validate)]
struct PluginConfig {
    #[validate(range(min = 200, max = 598))]
    status_code: Option<u16>,
    headers: Option<HeadersConfig>,
    /// Format like [["arg_name", "==", "val"], ["http_x", "!=", "reg"]]
    vars: Option<Vec<Vec<String>>>,
    /// Maximum response body size in bytes buffered when filters are applied.
    #[serde(default = "default_max_resp_body_size")]
    #[validate(range(min = 1))]
    max_resp_body_size: u64,
    /// Replacement body for the response.
    body: Option<String>,
    /// Whether `body` is base64 encoded.
    #[serde(default)]
    body_base64: bool,
    /// Regex substitution rules applied to the buffered response body.
    filters: Option<Vec<FilterConfig>>,
}

fn default_max_resp_body_size() -> u64 {
    DEFAULT_MAX_RESP_BODY_SIZE
}

impl PluginConfig {
    /// Parse, validate, and compile a response-rewrite configuration.
    fn build(value: JsonValue) -> ProxyResult<(Self, Compiled)> {
        let config: PluginConfig =
            parse_and_validate_plugin_config(value, "Failed to parse response-rewrite config")?;

        if let Some(headers) = &config.headers {
            validate_no_framing_headers(headers)?;
        }

        if config.body.is_some() && config.filters.is_some() {
            return Err(ProxyError::validation_error(
                "response-rewrite body and filters are mutually exclusive",
            ));
        }

        if config
            .filters
            .as_ref()
            .is_some_and(|filters| filters.is_empty())
        {
            return Err(ProxyError::validation_error(
                "response-rewrite filters must contain at least one filter",
            ));
        }

        for filter in config.filters.iter().flatten() {
            if filter.regex.is_empty() {
                return Err(ProxyError::validation_error(
                    "response-rewrite filter regex must not be empty",
                ));
            }
        }

        let compiled = config.compile()?;
        Ok((config, compiled))
    }

    /// Compile everything that must not be rebuilt per request: the
    /// replacement body bytes and the regex filters.
    fn compile(&self) -> ProxyResult<Compiled> {
        let replacement_body = match &self.body {
            Some(body) => {
                let bytes = if self.body_base64 {
                    decode_body_base64(body).map_err(|error| {
                        ProxyError::validation_error(format!(
                            "response-rewrite body is not valid base64: {error}"
                        ))
                    })?
                } else {
                    body.as_bytes().to_vec()
                };
                Some(Bytes::from(bytes))
            }
            None => {
                if self.body_base64 {
                    return Err(ProxyError::validation_error(
                        "response-rewrite body_base64 requires a body",
                    ));
                }
                None
            }
        };

        let filters = self
            .filters
            .as_deref()
            .unwrap_or(&[])
            .iter()
            .map(compile_filter)
            .collect::<ProxyResult<Vec<_>>>()?;

        Ok(Compiled {
            replacement_body,
            filters,
            max_resp_body_size: self.max_resp_body_size,
            keys: ContextKeys {
                matched: next_instance_ctx_key("pingsix_response_rewrite_matched_"),
                body_buffer: next_instance_ctx_key("pingsix_response_rewrite_body_buffer_"),
                body_too_large: next_instance_ctx_key("pingsix_response_rewrite_body_too_large_"),
                skip_body_rewrite: next_instance_ctx_key("pingsix_response_rewrite_skip_body_"),
            },
        })
    }
}

impl TryFrom<JsonValue> for PluginConfig {
    type Error = ProxyError;

    fn try_from(value: JsonValue) -> Result<Self, Self::Error> {
        Ok(Self::build(value)?.0)
    }
}

/// Decode standard base64. APISIX's `ngx.decode_base64` accepts both padded
/// and unpadded input, so try the canonical engine first and fall back to the
/// no-padding engine.
fn decode_body_base64(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    if encoded.is_empty() {
        return Err(base64::DecodeError::InvalidLength(0));
    }
    STANDARD
        .decode(encoded)
        .or_else(|padded_error| STANDARD_NO_PAD.decode(encoded).map_err(|_| padded_error))
}

/// Compile one APISIX filter into `(regex, replacement, global)`.
///
/// Byte-oriented regexes keep arbitrary (e.g. compressed) response bodies
/// intact; Lua's regex options map onto the Rust regex builder as follows:
/// `j` is a Perl inline modifier with no Rust equivalent and is ignored, `i`
/// enables case-insensitive matching, and `o` only means "compile once" in
/// Lua, which this gateway already does at plugin construction.
fn compile_filter(filter: &FilterConfig) -> ProxyResult<(regex_bytes::Regex, String, bool)> {
    let mut builder = regex_bytes::RegexBuilder::new(&filter.regex);
    for option in filter.options.chars() {
        match option {
            'j' | 'o' => {}
            'i' => {
                builder.case_insensitive(true);
            }
            other => {
                return Err(ProxyError::validation_error(format!(
                    "response-rewrite: unsupported regex option '{other}'"
                )));
            }
        }
    }

    let regex = builder.build().map_err(|error| {
        ProxyError::validation_error(format!(
            "response-rewrite filter regex \"{}\" does not compile: {error}",
            filter.regex
        ))
    })?;

    Ok((
        regex,
        filter.replace.clone(),
        filter.scope == RegexScope::Global,
    ))
}

/// Header names that must be owned by the HTTP framing layer. Overriding them
/// on a response (or removing them while the body is unchanged) can desync the
/// downstream connection, so they are rejected at configuration time.
fn is_framing_header(name: &str) -> bool {
    name.eq_ignore_ascii_case("content-length") || name.eq_ignore_ascii_case("transfer-encoding")
}

fn validate_no_framing_headers(headers: &HeadersConfig) -> ProxyResult<()> {
    let check = |name: &str| -> ProxyResult<()> {
        if is_framing_header(name) {
            return Err(ProxyError::validation_error(format!(
                "response-rewrite must not modify framing header '{name}'"
            )));
        }
        Ok(())
    };
    match headers {
        HeadersConfig::Simple(map) => {
            for name in map.keys() {
                check(name)?;
            }
        }
        HeadersConfig::Structured { add, set, remove } => {
            for entry in add {
                if let Some((name, _)) = entry.split_once(':') {
                    check(name.trim())?;
                }
            }
            for name in set.keys() {
                check(name)?;
            }
            for name in remove {
                check(name)?;
            }
        }
    }
    Ok(())
}

/// Per-instance context keys so a global and a route instance of the same
/// plugin never share request state.
struct ContextKeys {
    matched: String,
    body_buffer: String,
    body_too_large: String,
    skip_body_rewrite: String,
}

/// Precompiled response-rewrite behavior. Body/filter state that must live
/// per request is kept in the `ProxyContext` under [`Compiled::keys`].
struct Compiled {
    /// The full replacement body (already base64-decoded when configured).
    replacement_body: Option<Bytes>,
    /// `(regex, replacement, global)` in configuration order.
    filters: Vec<(regex_bytes::Regex, String, bool)>,
    max_resp_body_size: u64,
    keys: ContextKeys,
}

impl Compiled {
    fn rewrites_body(&self) -> bool {
        self.replacement_body.is_some() || !self.filters.is_empty()
    }

    fn matched(&self, ctx: &ProxyContext) -> bool {
        ctx.get::<bool>(&self.keys.matched)
            .copied()
            .unwrap_or(false)
    }

    /// Body-phase entry point, factored away from `Session` so the buffering
    /// and replacement logic can be tested with a bare `ProxyContext`.
    fn process_body_chunk(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) {
        if !self.matched(ctx) || !self.rewrites_body() {
            return;
        }
        // A compressed upstream body cannot be rewritten without a decoder;
        // pass it through unchanged (with its Content-Encoding intact) rather
        // than corrupting bytes downstream clients expect to decode.
        if ctx
            .get::<bool>(&self.keys.skip_body_rewrite)
            .copied()
            .unwrap_or(false)
        {
            return;
        }

        if let Some(replacement) = &self.replacement_body {
            self.process_replacement(replacement, body, end_of_stream);
        } else {
            self.process_filters(body, end_of_stream, ctx);
        }
    }

    /// Discard the original body chunk by chunk and emit the precomputed
    /// replacement only once the upstream signals end of stream. An
    /// empty-but-present body keeps the downstream stream open mid-stream.
    fn process_replacement(
        &self,
        replacement: &Bytes,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
    ) {
        let _ = body.take();
        if end_of_stream {
            *body = Some(replacement.clone());
        } else {
            *body = Some(Bytes::new());
        }
    }

    /// Buffer chunks until end of stream, then apply every filter in order.
    ///
    /// Once buffering would exceed `max_resp_body_size`, stop filtering this
    /// response: restore the overflow chunk so it and every later chunk pass
    /// through unchanged, and never apply the filters at end of stream.
    fn process_filters(
        &self,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) {
        if ctx
            .get::<bool>(&self.keys.body_too_large)
            .copied()
            .unwrap_or(false)
        {
            // The original chunk is left in `body` untouched.
            return;
        }

        let Some(chunk) = body.take() else {
            if end_of_stream {
                let buffered = self.take_buffer(ctx);
                let filtered = self.apply_filters_bytes(&buffered);
                *body = Some(Bytes::from(filtered));
            } else {
                *body = Some(Bytes::new());
            }
            return;
        };

        let buffered_len = self.buffer_len(ctx);
        if buffered_len as u64 + chunk.len() as u64 >= self.max_resp_body_size {
            // Filter the prefix up to `max_resp_body_size`, preserve any
            // trailing bytes from this crossing chunk verbatim, and pass all
            // later chunks through unchanged so no response bytes are lost.
            let max_bytes = usize::try_from(self.max_resp_body_size).unwrap_or(usize::MAX);
            let take = max_bytes.saturating_sub(buffered_len).min(chunk.len());
            let mut buffered = self.take_buffer(ctx);
            buffered.extend_from_slice(&chunk[..take]);
            let mut filtered = self.apply_filters_bytes(&buffered);
            if take < chunk.len() {
                filtered.extend_from_slice(&chunk[take..]);
            }
            *body = Some(Bytes::from(filtered));

            if !ctx
                .get::<bool>(&self.keys.body_too_large)
                .copied()
                .unwrap_or(false)
            {
                log::debug!(
                    "response-rewrite: response body reached max_resp_body_size {}; \
                     filtered prefix emitted and remaining bytes passed through unchanged",
                    self.max_resp_body_size
                );
            }
            ctx.set(self.keys.body_too_large.clone(), true);
            return;
        }

        let buffer = ctx
            .vars
            .get_or_insert_with(Default::default)
            .entry(self.keys.body_buffer.clone())
            .or_insert_with(|| Box::new(BytesMut::new()));
        let buffer = buffer
            .downcast_mut::<BytesMut>()
            .expect("response-rewrite body buffer");
        buffer.extend_from_slice(&chunk);

        if !end_of_stream {
            // Same contract as request-body buffering: an empty-but-present
            // placeholder keeps the stream open, while `None` would signal
            // the end of the body to Pingora's response pipeline.
            *body = Some(Bytes::new());
            return;
        }

        let buffered = self.take_buffer(ctx);
        let filtered = self.apply_filters_bytes(&buffered);
        *body = Some(Bytes::from(filtered));
    }

    fn buffer_len(&self, ctx: &ProxyContext) -> usize {
        ctx.get::<BytesMut>(&self.keys.body_buffer)
            .map(BytesMut::len)
            .unwrap_or(0)
    }

    fn take_buffer(&self, ctx: &mut ProxyContext) -> BytesMut {
        ctx.vars
            .as_mut()
            .and_then(|vars| vars.remove(&self.keys.body_buffer))
            .and_then(|boxed| boxed.downcast::<BytesMut>().ok())
            .map(|boxed| *boxed)
            .unwrap_or_default()
    }

    /// Apply all filters in configuration order. `once` replaces the first
    /// match, `global` replaces every match.
    #[cfg(test)]
    fn apply_filters(&self, body: &str) -> String {
        String::from_utf8_lossy(&self.apply_filters_bytes(body.as_bytes())).into_owned()
    }

    /// Byte-preserving filter application used by the body phase.
    fn apply_filters_bytes(&self, body: &[u8]) -> Vec<u8> {
        let mut current = body.to_vec();
        for (regex, replacement, global) in &self.filters {
            if *global {
                current = regex
                    .replace_all(&current, replacement.as_bytes())
                    .into_owned();
            } else {
                current = regex
                    .replacen(&current, 1, replacement.as_bytes())
                    .into_owned();
            }
        }
        current
    }
}

pub struct PluginResponseRewrite {
    config: PluginConfig,
    compiled: Compiled,
}

impl PluginResponseRewrite {
    /// Expand the documented response-rewrite variables. Unknown `$name`
    /// sequences are deliberately preserved rather than silently erased.
    fn expand_vars(&self, session: &mut Session, ctx: &ProxyContext, val: &str) -> String {
        let remote_addr = request_selector_key(session, &UpstreamHashOn::VARS, "remote_addr");
        Self::expand_template(
            val,
            &remote_addr,
            ctx.selected.as_ref().map(|selected| selected.node.as_str()),
            ctx.request_id(),
        )
    }

    fn expand_template(
        val: &str,
        remote_addr: &str,
        upstream_addr: Option<&str>,
        request_id: Option<&str>,
    ) -> String {
        if !val.contains('$') {
            return val.to_string();
        }
        // Replace only the three supported `$name` tokens by identifier
        // boundary, so a variable like `$request_id_suffix` or
        // `$remote_address` is preserved verbatim instead of being silently
        // rewritten by a prefix match.
        let mut out = String::with_capacity(val.len());
        let mut rest = val;
        while let Some(dollar) = rest.find('$') {
            out.push_str(&rest[..dollar]);
            let after = &rest[dollar + 1..];
            let name_len = after
                .find(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
                .unwrap_or(after.len());
            if name_len == 0 {
                // Lone '$' or '$' followed by a non-identifier char: keep '$'.
                out.push('$');
                rest = after;
                continue;
            }
            let name = &after[..name_len];
            // Known variable names expand even when the value is unavailable
            // (empty string). Unknown names are preserved verbatim. The
            // token boundary above ensures `$remote_address` is treated as an
            // unknown name, not a `$remote_addr` prefix match.
            match name {
                "remote_addr" => out.push_str(remote_addr),
                "upstream_addr" => out.push_str(upstream_addr.unwrap_or("")),
                "request_id" => out.push_str(request_id.unwrap_or("")),
                _ => {
                    out.push('$');
                    out.push_str(name);
                }
            }
            rest = &after[name_len..];
        }
        out.push_str(rest);
        out
    }
}

/// APISIX `clear_header_as_body_modified()`: body rewrites invalidate the
/// framing length and any validator/encoding that describes the old bytes.
pub(crate) fn clear_body_modified_headers(is_http2: bool, resp: &mut ResponseHeader) -> Result<()> {
    resp.remove_header("Content-Length");
    resp.remove_header("Content-Encoding");
    resp.remove_header("ETag");
    resp.remove_header("Last-Modified");
    // Pingora 0.8 decides whether H1 needs chunked framing before invoking
    // `response_filter`. If this plugin removes Content-Length afterwards, it
    // must establish framing itself for a persistent HTTP/1.x connection.
    if !is_http2 {
        resp.set_version(http::Version::HTTP_11);
        resp.insert_header("Transfer-Encoding", "chunked")?;
    }
    Ok(())
}

/// Whether this response header must be forwarded verbatim.
///
/// Pingora runs `response_filter` for every upstream header event, including
/// informational 1xx responses such as `100 Continue` and `103 Early Hints`
/// (and the `101 Switching Protocols` handshake that precedes an upgraded
/// connection). A 1xx is not the final answer: overriding its status,
/// rewriting its headers, or forcing `Transfer-Encoding: chunked` onto it
/// would desynchronize the downstream client (chunked framing implies a body
/// a 1xx must never carry). Response-phase plugins must therefore skip all
/// modifications and pass informational responses through unchanged.
pub(crate) fn is_informational_response(response: &ResponseHeader) -> bool {
    response.status.is_informational()
}

/// Whether this request's connection has been upgraded (101).
///
/// After a `101 Switching Protocols`, Pingora hands the upgraded protocol
/// bytes (e.g. WebSocket frames) to `response_body_filter` as
/// `HttpTask::UpgradedBody` tasks. Those bytes are not an HTTP body:
/// buffering, wrapping, replacing, or splitting them corrupts the upgraded
/// stream, so body-phase plugins must pass every chunk through unchanged.
pub(crate) fn is_upgraded_session(session: &Session) -> bool {
    session.was_upgraded()
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
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // Informational responses (e.g. 103 Early Hints) are forwarded
        // verbatim: overriding their status, rewriting their headers, or
        // forcing chunked framing would corrupt them. Skipping here also
        // leaves `matched` unset, so the body phase passes any chunks
        // through untouched (see `is_informational_response`).
        if is_informational_response(upstream_response) {
            return Ok(());
        }

        // 1. Check matching conditions
        let vars = self.config.vars.as_deref().unwrap_or(&[]);
        if !match_apisix_vars(session, vars) {
            return Ok(());
        }

        // 2. Remember the match so the body phase only rewrites responses
        // that passed the vars filter.
        ctx.set(self.compiled.keys.matched.clone(), true);

        // 3. Apply the final status before deciding whether a response is
        // allowed to carry a rewritten body.
        if let Some(code) = self.config.status_code {
            let status = StatusCode::from_u16(code).expect("status_code validated to 200..=598");
            let _ = upstream_response.set_status(status);
        }

        // 4. A rewritten body invalidates the original framing and validators.
        // Compressed upstream bodies cannot be rewritten without a decoder,
        // and 204/304/HEAD responses have no body to replace; in both cases
        // pass the response through unchanged instead of corrupting framing.
        if self.compiled.rewrites_body() {
            let content_encoding = upstream_response
                .headers
                .get("Content-Encoding")
                .and_then(|value| value.to_str().ok());
            let compressed = content_encoding
                .is_some_and(|encoding| !encoding.trim().eq_ignore_ascii_case("identity"));
            let bodyless = upstream_response.status == StatusCode::NO_CONTENT
                || upstream_response.status == StatusCode::NOT_MODIFIED
                || session.req_header().method == http::Method::HEAD;

            if compressed || bodyless {
                log::debug!(
                    "response-rewrite: skipping body rewrite (compressed={compressed}, bodyless={bodyless})"
                );
                ctx.set(self.compiled.keys.skip_body_rewrite.clone(), true);
            } else {
                log::debug!("response-rewrite: clearing body framing/validator headers");
                clear_body_modified_headers(session.is_http2(), upstream_response)?;
            }
        }

        // 5. Apply header mutations
        if let Some(ref h_cfg) = self.config.headers {
            match h_cfg {
                HeadersConfig::Simple(headers) => {
                    for (k, v) in headers {
                        let rendered = v.render();
                        let val = self.expand_vars(session, ctx, &rendered);
                        upstream_response.insert_header(k.clone(), val)?;
                    }
                }
                HeadersConfig::Structured { add, set, remove } => {
                    // APISIX applies add, then set, then remove.
                    for entry in add {
                        if let Some((k, v)) = entry.split_once(':') {
                            let val = self.expand_vars(session, ctx, v.trim());
                            upstream_response.append_header(k.trim().to_string(), val)?;
                        }
                    }
                    for (k, v) in set {
                        let rendered = v.render();
                        let val = self.expand_vars(session, ctx, &rendered);
                        upstream_response.insert_header(k.clone(), val)?;
                    }
                    for k in remove {
                        upstream_response.remove_header(k);
                    }
                }
            }
        }

        Ok(())
    }

    fn response_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut ProxyContext,
    ) -> Result<()> {
        // An upgraded connection (101) tunnels protocol bytes through this
        // hook; they are not an HTTP body and must pass through unchanged
        // (see `is_upgraded_session`).
        if is_upgraded_session(session) {
            return Ok(());
        }
        self.compiled.process_body_chunk(body, end_of_stream, ctx);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use http::StatusCode;
    use pingora_http::ResponseHeader;
    use pingora_proxy::Session;

    use super::{
        clear_body_modified_headers, create_response_rewrite_plugin, is_informational_response,
        is_upgraded_session, Compiled, PluginConfig, PluginResponseRewrite,
    };
    use crate::config::EffectiveDefaults;
    use crate::core::{ProxyContext, ProxyPlugin};
    use crate::plugins::config::HeaderValue;
    use bytes::{Bytes, BytesMut};

    fn build(cfg: serde_json::Value) -> (PluginConfig, Compiled) {
        PluginConfig::build(cfg).expect("valid response-rewrite config")
    }

    #[test]
    fn body_rewrites_clear_framing_and_validator_headers() {
        let mut resp =
            pingora_http::ResponseHeader::build(http::StatusCode::OK, None).expect("build");
        for (name, value) in [
            ("Content-Length", "10"),
            ("Content-Encoding", "gzip"),
            ("ETag", "\"abc\""),
            ("Last-Modified", "Wed, 21 Oct 2026 07:28:00 GMT"),
        ] {
            resp.insert_header(name, value).expect("insert");
        }
        clear_body_modified_headers(false, &mut resp).unwrap();
        for name in [
            "content-length",
            "content-encoding",
            "etag",
            "last-modified",
        ] {
            assert!(resp.headers.get(name).is_none(), "{name} must be cleared");
        }
        assert_eq!(resp.version, http::Version::HTTP_11);
        assert_eq!(resp.headers.get("transfer-encoding").unwrap(), "chunked");
    }

    #[test]
    fn rejects_content_length_and_transfer_encoding_headers() {
        for cfg in [
            serde_json::json!({"headers": {"Content-Length": "0"}}),
            serde_json::json!({
                "headers": {"set": {"transfer-encoding": "chunked"}}
            }),
            serde_json::json!({
                "headers": {"add": ["Content-Length: 0"]}
            }),
            serde_json::json!({
                "headers": {"remove": ["content-length"]}
            }),
        ] {
            assert!(
                PluginConfig::try_from(cfg).is_err(),
                "framing headers must be rejected"
            );
        }

        let ok = PluginConfig::try_from(serde_json::json!({
            "headers": {"set": {"X-Custom": "v"}}
        }))
        .unwrap();
        assert!(ok.headers.is_some());
    }

    #[test]
    fn applies_apisix_defaults() {
        let (config, compiled) = build(serde_json::json!({"headers": {"X-Test": "ok"}}));
        assert_eq!(config.max_resp_body_size, 64 * 1024 * 1024);
        assert!(!config.body_base64);
        assert!(compiled.replacement_body.is_none());
        assert!(compiled.filters.is_empty());
    }

    #[test]
    fn filter_defaults_are_once_scope_and_jo_options() {
        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "a", "replace": "b"}]
        }));
        assert_eq!(compiled.filters.len(), 1);
        let (regex, replacement, global) = &compiled.filters[0];
        assert_eq!(regex.as_str(), "a");
        assert_eq!(replacement, "b");
        assert!(!global);
    }

    #[test]
    fn filter_replace_is_required_and_empty_stays_expressible() {
        // APISIX requires both `regex` and `replace`; omitting `replace`
        // must fail loudly instead of silently deleting matched bytes.
        assert!(PluginConfig::build(serde_json::json!({
            "filters": [{"regex": "a"}]
        }))
        .is_err());

        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "foo", "replace": ""}]
        }));
        assert_eq!(compiled.apply_filters("foo bar"), " bar");
    }

    #[test]
    fn body_and_filters_are_mutually_exclusive() {
        assert!(PluginConfig::build(serde_json::json!({
            "body": "replacement",
            "filters": [{"regex": "a", "replace": "b"}]
        }))
        .is_err());
    }

    #[test]
    fn base64_body_is_validated_and_decoded_at_build_time() {
        let (_, compiled) = build(serde_json::json!({
            "body": "aGVsbG8=",
            "body_base64": true
        }));
        assert_eq!(
            compiled.replacement_body,
            Some(Bytes::from_static(b"hello"))
        );

        // APISIX's ngx.decode_base64 also accepts unpadded input.
        let (_, compiled) = build(serde_json::json!({
            "body": "aGVsbG8",
            "body_base64": true
        }));
        assert_eq!(
            compiled.replacement_body,
            Some(Bytes::from_static(b"hello"))
        );

        for invalid in [
            serde_json::json!({"body_base64": true}),
            serde_json::json!({"body": "", "body_base64": true}),
            serde_json::json!({"body": "!!!not-base64!!!", "body_base64": true}),
        ] {
            assert!(
                PluginConfig::build(invalid).is_err(),
                "invalid base64 bodies must be rejected"
            );
        }

        // An empty plain-text body is a legitimate replacement.
        let (_, compiled) = build(serde_json::json!({"body": ""}));
        assert_eq!(compiled.replacement_body, Some(Bytes::new()));
    }

    #[test]
    fn invalid_filters_are_rejected_at_build_time() {
        for invalid in [
            serde_json::json!({"filters": []}),
            serde_json::json!({"filters": [{"regex": "", "replace": "x"}]}),
            serde_json::json!({"filters": [{"regex": "[", "replace": "x"}]}),
            serde_json::json!({"filters": [{"regex": "a", "replace": "x", "scope": "sometimes"}]}),
            // APISIX requires `replace` alongside `regex` — a missing replace
            // (silent body deletion) must be a schema error.
            serde_json::json!({"filters": [{"regex": "a"}]}),
        ] {
            assert!(
                PluginConfig::build(invalid).is_err(),
                "invalid filters must be rejected"
            );
        }

        let error = match PluginConfig::build(serde_json::json!({
            "filters": [{"regex": "a", "replace": "x", "options": "x"}]
        })) {
            Ok(_) => panic!("unsupported option must be rejected"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("unsupported regex option"));
    }

    #[test]
    fn status_code_must_be_between_200_and_598() {
        for invalid in [199, 599] {
            assert!(
                PluginConfig::build(serde_json::json!({"status_code": invalid})).is_err(),
                "status {invalid} must be rejected"
            );
        }
        for valid in [200, 598] {
            let (config, _) = build(serde_json::json!({"status_code": valid}));
            assert_eq!(config.status_code, Some(valid));
        }
    }

    #[test]
    fn structured_header_operations_follow_apisix_order() {
        let (config, _) = build(serde_json::json!({
            "headers": {
                "add": ["X-Mix: added"],
                "set": {"X-Mix": "set"},
                "remove": ["X-Mix"]
            }
        }));
        match config.headers.as_ref().unwrap() {
            super::HeadersConfig::Structured { add, set, remove } => {
                assert_eq!(add, &["X-Mix: added"]);
                assert_eq!(set["X-Mix"].render(), "set");
                assert_eq!(remove, &["X-Mix"]);
            }
            _ => panic!("expected structured headers"),
        }
    }

    #[test]
    fn header_values_accept_numbers_and_render_as_strings() {
        assert_eq!(HeaderValue::Number(42.0).render(), "42");
        assert_eq!(HeaderValue::Number(1.5).render(), "1.5");
        assert_eq!(HeaderValue::Text("plain".to_string()).render(), "plain");

        let (config, _) = build(serde_json::json!({
            "headers": {
                "X-Count": 42,
                "X-Ratio": 1.5
            }
        }));
        match config.headers.as_ref().expect("simple headers") {
            super::HeadersConfig::Simple(map) => {
                assert_eq!(map["X-Count"].render(), "42");
                assert_eq!(map["X-Ratio"].render(), "1.5");
            }
            super::HeadersConfig::Structured { .. } => panic!("expected simple headers"),
        }

        let (config, _) = build(serde_json::json!({
            "headers": {
                "set": {"X-Count": 7},
                "add": ["X-Added: 8"],
                "remove": ["X-Gone"]
            }
        }));
        match config.headers.as_ref().expect("structured headers") {
            super::HeadersConfig::Simple(_) => panic!("expected structured headers"),
            super::HeadersConfig::Structured { add, set, remove } => {
                assert_eq!(set["X-Count"].render(), "7");
                assert_eq!(add, &["X-Added: 8"]);
                assert_eq!(remove, &["X-Gone"]);
            }
        }
    }

    #[test]
    fn filters_apply_in_order_once_or_globally() {
        let (_, compiled) = build(serde_json::json!({
            "filters": [
                {"regex": "foo", "replace": "bar"},
                {"regex": "bar", "replace": "baz", "scope": "global"}
            ]
        }));

        // "foo foo" -> first filter once -> "bar foo" -> second global -> "baz foo".
        assert_eq!(compiled.apply_filters("foo foo"), "baz foo");
    }

    #[test]
    fn filter_options_enable_case_insensitive_matching() {
        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "foo", "replace": "bar", "options": "i"}]
        }));
        assert_eq!(compiled.apply_filters("FOO"), "bar");

        // `jo` is the default and must not change matching semantics.
        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "foo", "replace": "bar"}]
        }));
        assert_eq!(compiled.apply_filters("FOO"), "FOO");
    }

    #[test]
    fn body_filter_ignores_unmatched_requests() {
        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "a", "replace": "b"}]
        }));
        let mut ctx = ProxyContext::default();
        let mut body = Some(Bytes::from_static(b"unchanged"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"unchanged")));
    }

    #[test]
    fn compressed_bodies_pass_through_when_rewrite_is_skipped() {
        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "a", "replace": "b"}]
        }));
        let mut ctx = ProxyContext::default();
        ctx.set(compiled.keys.matched.clone(), true);
        ctx.set(compiled.keys.skip_body_rewrite.clone(), true);

        let mut body = Some(Bytes::from_static(b"gzip-bytes"));
        compiled.process_body_chunk(&mut body, true, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"gzip-bytes")));
    }

    #[test]
    fn body_filters_buffer_chunks_and_apply_on_end_of_stream() {
        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "l+", "replace": "L", "scope": "global"}]
        }));
        let mut ctx = ProxyContext::default();
        ctx.set(compiled.keys.matched.clone(), true);

        let mut body = Some(Bytes::from_static(b"hel"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::new()));
        assert!(ctx.get::<BytesMut>(&compiled.keys.body_buffer).is_some());

        let mut body = Some(Bytes::from_static(b"lo"));
        compiled.process_body_chunk(&mut body, true, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"heLo")));
        assert!(ctx.get::<BytesMut>(&compiled.keys.body_buffer).is_none());
    }

    #[test]
    fn body_filters_finalize_buffered_body_when_eos_has_no_chunk() {
        let (_, compiled) = build(serde_json::json!({
            "filters": [{"regex": "l+", "replace": "L", "scope": "global"}]
        }));
        let mut ctx = ProxyContext::default();
        ctx.set(compiled.keys.matched.clone(), true);

        let mut body = Some(Bytes::from_static(b"hel"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::new()));

        // Pingora may signal end of stream without an accompanying chunk.
        let mut body = None;
        compiled.process_body_chunk(&mut body, true, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"heL")));
    }

    #[test]
    fn body_replacement_swallows_original_and_emits_on_end_of_stream() {
        let (_, compiled) = build(serde_json::json!({"body": "replacement"}));
        let mut ctx = ProxyContext::default();
        ctx.set(compiled.keys.matched.clone(), true);

        let mut body = Some(Bytes::from_static(b"original"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::new()));

        let mut body = Some(Bytes::from_static(b"chunk"));
        compiled.process_body_chunk(&mut body, true, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"replacement")));
    }

    #[test]
    fn oversized_filtered_body_stops_buffering_and_passes_remaining_chunks() {
        let (_, compiled) = build(serde_json::json!({
            "max_resp_body_size": 4,
            "filters": [{"regex": "foo", "replace": "bar"}]
        }));
        let mut ctx = ProxyContext::default();
        ctx.set(compiled.keys.matched.clone(), true);

        // Three bytes buffered, stream held open with an empty placeholder.
        let mut body = Some(Bytes::from_static(b"fo"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::new()));
        let mut body = Some(Bytes::from_static(b"o"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::new()));

        // Exactly at the limit (APISIX checks >=): the truncated buffered
        // prefix is filtered and emitted, then later chunks pass through.
        let mut body = Some(Bytes::from_static(b"x"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"barx")));
        assert!(ctx
            .get::<bool>(&compiled.keys.body_too_large)
            .copied()
            .unwrap_or(false));

        let mut body = Some(Bytes::from_static(b"tail"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"tail")));

        let mut body = Some(Bytes::from_static(b"end"));
        compiled.process_body_chunk(&mut body, true, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"end")));
    }

    #[test]
    fn oversized_crossing_chunk_preserves_trailing_bytes() {
        let (_, compiled) = build(serde_json::json!({
            "max_resp_body_size": 4,
            "filters": [{"regex": "foo", "replace": "bar"}]
        }));
        let mut ctx = ProxyContext::default();
        ctx.set(compiled.keys.matched.clone(), true);

        let mut body = Some(Bytes::from_static(b"fo"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::new()));

        // Crossing chunk carries bytes beyond max_resp_body_size: filter the
        // first 4 bytes ("foox" -> "barx") and preserve the overflow tail
        // ("12345") verbatim without dropping data.
        let mut body = Some(Bytes::from_static(b"ox12345"));
        compiled.process_body_chunk(&mut body, false, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"barx12345")));

        let mut body = Some(Bytes::from_static(b"end"));
        compiled.process_body_chunk(&mut body, true, &mut ctx);
        assert_eq!(body, Some(Bytes::from_static(b"end")));
    }

    #[test]
    fn expands_context_variables_and_preserves_unknown_variables() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "client=$remote_addr upstream=$upstream_addr id=$request_id unknown=$unknown",
                "192.0.2.1",
                Some("10.0.0.1:8080"),
                Some("request-123"),
            ),
            "client=192.0.2.1 upstream=10.0.0.1:8080 id=request-123 unknown=$unknown"
        );
    }

    #[test]
    fn missing_context_variables_expand_to_empty_strings() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "$upstream_addr/$request_id/$unknown",
                "192.0.2.1",
                None,
                None,
            ),
            "//$unknown"
        );
    }

    #[test]
    fn prefix_overlapping_variables_are_not_partially_rewritten() {
        // `$remote_address` must not be rewritten by the `$remote_addr` prefix,
        // and `$request_id_suffix` must not be rewritten by `$request_id`.
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "$remote_address-$request_id_suffix",
                "192.0.2.1",
                Some("10.0.0.1:8080"),
                Some("req-1"),
            ),
            "$remote_address-$request_id_suffix"
        );
    }

    #[test]
    fn adjacent_known_variables_are_all_replaced() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "$remote_addr$upstream_addr$request_id",
                "192.0.2.1",
                Some("10.0.0.1:8080"),
                Some("req-1"),
            ),
            "192.0.2.110.0.0.1:8080req-1"
        );
    }

    #[test]
    fn lone_dollar_sign_and_non_identifier_dollar_are_preserved() {
        assert_eq!(
            PluginResponseRewrite::expand_template(
                "price=$5 and trailing=$",
                "192.0.2.1",
                None,
                None,
            ),
            "price=$5 and trailing=$"
        );
    }

    // ------------------------------------------------------------------
    // Pingora session helpers (same pattern as the other plugin suites)
    // ------------------------------------------------------------------

    async fn session_for(wire: &str) -> Session {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(wire.as_bytes())
            .await
            .expect("write canned request");
        drop(server);
        let mut session = Session::new_h1(Box::new(client));
        session
            .downstream_session
            .read_request()
            .await
            .expect("canned request parses");
        session
    }

    /// A session whose H1 layer completed a 101 upgrade handshake, the same
    /// way Pingora's proxy loop marks a session upgraded before tunneling
    /// `HttpTask::UpgradedBody` chunks through `response_body_filter`.
    async fn upgraded_websocket_session() -> Session {
        use tokio::io::AsyncWriteExt;
        let (client, mut server) = tokio::io::duplex(4096);
        server
            .write_all(b"GET /ws HTTP/1.1\r\nHost: t\r\nUpgrade: websocket\r\n\r\n")
            .await
            .expect("write upgrade request");
        let mut session = Session::new_h1(Box::new(client));
        session
            .downstream_session
            .read_request()
            .await
            .expect("upgrade request parses");

        let mut switching =
            ResponseHeader::build(StatusCode::SWITCHING_PROTOCOLS, None).expect("build 101");
        switching
            .insert_header("Upgrade", "websocket")
            .expect("insert upgrade header");
        session
            .downstream_session
            .write_response_header(Box::new(switching))
            .await
            .expect("finish 101 handshake");
        assert!(is_upgraded_session(&session));
        drop(server);
        session
    }

    fn rewrite_plugin(cfg: serde_json::Value) -> Arc<dyn ProxyPlugin> {
        create_response_rewrite_plugin(cfg, &EffectiveDefaults::default())
            .expect("valid response-rewrite config")
    }

    #[test]
    fn informational_guard_classifies_only_1xx_responses() {
        for code in [100, 101, 103] {
            let resp = ResponseHeader::build(StatusCode::from_u16(code).unwrap(), None)
                .expect("build header");
            assert!(is_informational_response(&resp), "{code} is informational");
        }
        for code in [200, 204, 304] {
            let resp = ResponseHeader::build(StatusCode::from_u16(code).unwrap(), None)
                .expect("build header");
            assert!(!is_informational_response(&resp), "{code} is final");
        }
    }

    #[tokio::test]
    async fn informational_response_passes_through_verbatim() {
        let plugin = rewrite_plugin(serde_json::json!({
            "status_code": 500,
            "headers": {"X-Rewrite": "yes"},
            "body": "replaced"
        }));
        let mut session = session_for("GET / HTTP/1.1\r\nHost: t\r\n\r\n").await;
        let mut ctx = ProxyContext::default();

        let mut hints =
            ResponseHeader::build(StatusCode::from_u16(103).unwrap(), None).expect("build 103");
        hints
            .insert_header("Link", "</style.css>; rel=preload")
            .expect("insert link");
        hints
            .insert_header("Content-Length", "0")
            .expect("insert content length");

        plugin
            .response_filter(&mut session, &mut hints, &mut ctx)
            .await
            .expect("filter runs");

        // Status override, header mutation, and forced chunked framing are
        // all skipped: a 103 is not the final answer and carries no body.
        assert_eq!(hints.status.as_u16(), 103);
        assert_eq!(
            hints.headers.get("Link").unwrap().to_str().unwrap(),
            "</style.css>; rel=preload"
        );
        assert_eq!(hints.headers.get("Content-Length").unwrap(), "0");
        assert!(hints.headers.get("X-Rewrite").is_none());
        assert!(hints.headers.get("Transfer-Encoding").is_none());

        // The match marker was never set, so the body phase passes any
        // chunk through unchanged as well.
        let mut body = Some(Bytes::from_static(b"chunk"));
        plugin
            .response_body_filter(&mut session, &mut body, false, &mut ctx)
            .expect("body filter runs");
        assert_eq!(body, Some(Bytes::from_static(b"chunk")));
    }

    #[tokio::test]
    async fn upgraded_body_frames_pass_through_unchanged() {
        let (config, compiled) = build(serde_json::json!({"body": "replaced"}));
        let plugin = PluginResponseRewrite { config, compiled };
        let mut session = upgraded_websocket_session().await;
        let mut ctx = ProxyContext::default();

        // The 101 handshake itself is informational and passes through
        // response_filter verbatim (no forced chunked framing).
        let mut switching =
            ResponseHeader::build(StatusCode::SWITCHING_PROTOCOLS, None).expect("build 101");
        switching
            .insert_header("Upgrade", "websocket")
            .expect("insert upgrade header");
        plugin
            .response_filter(&mut session, &mut switching, &mut ctx)
            .await
            .expect("filter runs");
        assert_eq!(switching.status.as_u16(), 101);
        assert!(switching.headers.get("Transfer-Encoding").is_none());

        // Even with the match marker set, WebSocket frames tunneled as
        // UpgradedBody must be neither replaced, buffered, nor split.
        ctx.set(plugin.compiled.keys.matched.clone(), true);
        let mut frame = Some(Bytes::from_static(&[0x81, 0x02, 0x68, 0x69]));
        plugin
            .response_body_filter(&mut session, &mut frame, false, &mut ctx)
            .expect("body filter runs");
        assert_eq!(frame, Some(Bytes::from_static(&[0x81, 0x02, 0x68, 0x69])));

        let mut close_frame = Some(Bytes::from_static(&[0x88, 0x00]));
        plugin
            .response_body_filter(&mut session, &mut close_frame, true, &mut ctx)
            .expect("body filter runs");
        assert_eq!(close_frame, Some(Bytes::from_static(&[0x88, 0x00])));
    }
}

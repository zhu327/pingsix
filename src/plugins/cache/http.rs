//! HTTP cache policy helpers shared by the cache plugin and Pingora adapter.

use std::{borrow::Cow, sync::Arc};

use http::{
    header::{SET_COOKIE, VARY},
    StatusCode,
};
use pingora_cache::{
    cache_control::{CacheControl, DirectiveKey, DirectiveMap, DirectiveValue},
    filters::resp_cacheable,
    key::{CacheKey, HashBinary},
    CacheMeta, CacheMetaDefaults, NoCacheReason, RespCacheable, VarianceBuilder,
};
use pingora_error::{Error, ErrorSource, ErrorType, Result};
use pingora_http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;

use crate::{
    core::ProxyContext,
    plugins::cache::{should_bypass_authenticated_request, CacheSettings, CTX_KEY_CACHE_SETTINGS},
    utils::request::{
        get_query_value, get_req_header_value, get_request_host, render_apisix_template,
    },
};

const CACHE_DEFAULT: CacheMetaDefaults = CacheMetaDefaults::new(|_| None, 0, 0);

pub(crate) fn headers_indicate_shared_cache_credentials(headers: &http::HeaderMap) -> bool {
    headers.contains_key("authorization")
        || headers.contains_key("proxy-authorization")
        || headers.contains_key("cookie")
}

pub(crate) fn response_has_vary_star(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(VARY)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("*"))
}

pub(crate) fn cache_key_method(method: &str) -> &str {
    if method == "PURGE" {
        "GET"
    } else {
        method
    }
}

/// Resolve the nginx-style variables supported by APISIX `cache_key` and
/// `cache_bypass` templates. Unknown variables expand to an empty string.
fn resolve_cache_key_var<'a>(req: &'a RequestHeader, name: &str) -> Cow<'a, str> {
    if let Some(arg) = name.strip_prefix("arg_") {
        return Cow::Borrowed(get_query_value(req, arg).unwrap_or_default());
    }
    if let Some(header) = name.strip_prefix("http_") {
        let header_name = header.replace('_', "-");
        return Cow::Borrowed(get_req_header_value(req, &header_name).unwrap_or_default());
    }
    match name {
        "host" => Cow::Borrowed(get_request_host(req).unwrap_or_default()),
        "request_uri" => Cow::Borrowed(
            req.uri
                .path_and_query()
                .map_or_else(|| req.uri.path(), |pq| pq.as_str()),
        ),
        "uri" => Cow::Borrowed(req.uri.path()),
        "args" | "query_string" => Cow::Borrowed(req.uri.query().unwrap_or_default()),
        "request_method" => Cow::Borrowed(req.method.as_str()),
        _ => Cow::Borrowed(""),
    }
}

/// Render one APISIX `cache_key` / `cache_bypass` template against a request.
pub(crate) fn render_cache_key_template(req: &RequestHeader, template: &str) -> String {
    render_apisix_template(template, |name| {
        resolve_cache_key_var(req, name).into_owned()
    })
}

/// APISIX `cache_bypass` semantics: render every template, concatenate with
/// no separator, and bypass when the combined value is non-empty and not `"0"`.
pub(crate) fn cache_bypass_requested(templates: &[String], req: &RequestHeader) -> bool {
    apisix_templates_truthy(templates, req)
}

/// APISIX `no_cache` semantics: same template evaluation as `cache_bypass`.
pub(crate) fn no_cache_requested(templates: &[String], req: &RequestHeader) -> bool {
    apisix_templates_truthy(templates, req)
}

fn apisix_templates_truthy(templates: &[String], req: &RequestHeader) -> bool {
    let rendered: String = templates
        .iter()
        .map(|template| render_cache_key_template(req, template))
        .collect();
    !rendered.is_empty() && rendered != "0"
}

/// Digest of the credential-bearing headers used to isolate consumers when
/// both `cache_authenticated_requests` and `consumer_isolation` are enabled.
///
/// SHA-256 (rather than a fast 64-bit hash) keeps collisions at cryptographic
/// rather than birthday bounds: this digest is part of a cross-user security
/// boundary, not a cache performance hint.
pub(crate) fn credential_cache_key_component(req: &RequestHeader) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"pingsix-cache-consumer-isolation-v1\0");
    for name in ["authorization", "proxy-authorization", "cookie"] {
        hasher.update(name.as_bytes());
        hasher.update([u8::from(req.headers.contains_key(name))]);
        for value in req.headers.get_all(name) {
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
    }
    hex::encode(hasher.finalize())
}

/// Cache-key entries that already carry the request identity. When one of
/// these is present in the explicit `cache_key`, consumer isolation is a
/// no-op: the operator has opted into their own identity scheme (mirrors
/// APISIX `IDENTITY_VARS`; only `$http_authorization` renders in pingsix).
const IDENTITY_CACHE_KEY_VARS: [&str; 1] = ["$http_authorization"];

fn cache_key_has_identity(templates: &[String]) -> bool {
    templates
        .iter()
        .any(|template| IDENTITY_CACHE_KEY_VARS.contains(&template.as_str()))
}

/// Cache-key component isolating consumers when authenticated responses are
/// cached: combines the digest of the ORIGINAL standard credential headers
/// (captured in `early_request_filter`, before any plugin can strip them)
/// with the digest of the credential verified by an auth plugin (covering
/// carriers beyond the standard headers: custom headers, query params,
/// cookies). Anonymous requests share one stable bucket.
fn consumer_isolation_component(ctx: &ProxyContext) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"pingsix-cache-consumer-isolation-v1\0");
    hasher.update(ctx.original_credential_digest.as_deref().unwrap_or(""));
    hasher.update([0]);
    hasher.update(ctx.noted_credential_digest.as_deref().unwrap_or(""));
    hex::encode(hasher.finalize())
}

/// Whether a `PURGE` request may remove the matching cache entry.
///
/// PURGE is an opt-in because it is intentionally unauthenticated: an
/// unconditional purge lets any client force cache misses (stampede DoS).
/// Deployments that enable it must front the proxy with their own ACL.
pub(crate) fn should_enable_purge(settings: Option<&Arc<CacheSettings>>) -> bool {
    settings.is_some_and(|settings| settings.enable_purge)
}

fn request_has_no_cache_directive(headers: &http::HeaderMap) -> bool {
    headers
        .get_all(http::header::CACHE_CONTROL)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .map(|directive| directive.split('=').next().unwrap_or("").trim())
        .any(|directive| {
            directive.eq_ignore_ascii_case("no-cache") || directive.eq_ignore_ascii_case("no-store")
        })
}

pub(crate) fn should_enable_request_cache(
    headers: &http::HeaderMap,
    settings: Option<&Arc<CacheSettings>>,
    ctx: &ProxyContext,
) -> bool {
    // APISIX `cache_control` governs request-side directives: the bypass
    // applies unless the flag explicitly disables Cache-Control honoring
    // (`cache_control: false`); absent keeps the pingsix legacy behavior.
    if request_has_no_cache_directive(headers)
        && settings.is_none_or(|s| s.cache_control != Some(false))
    {
        log::debug!("Cache bypass requested via cache-control: no-cache/no-store");
        return false;
    }
    let Some(settings) = settings else {
        return false;
    };
    if should_bypass_authenticated_request(settings, ctx) {
        log::debug!("Skipping shared cache: request has credentials");
        return false;
    }
    true
}

pub(crate) fn cache_key(session: &Session, ctx: &ProxyContext) -> CacheKey {
    let req = session.req_header();
    let settings = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS);

    // APISIX `cache_key` templates win over pingsix's legacy
    // `METHOD host uri` primary key.
    let primary = match settings.and_then(|s| s.cache_key.as_ref()) {
        Some(templates) if !templates.is_empty() => templates
            .iter()
            .map(|template| render_cache_key_template(req, template))
            .collect::<Vec<_>>()
            .join("\n"),
        _ => {
            let host = req
                .headers
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("");
            format!(
                "{} {} {}",
                cache_key_method(req.method.as_str()),
                host,
                req.uri
            )
        }
    };

    let route_fp = ctx
        .route
        .as_ref()
        .map(|r| r.cache_namespace_fingerprint())
        .unwrap_or(0);
    let policy_fp = settings.map(|s| s.policy_fingerprint).unwrap_or(0);
    let upstream_key = if let Some(upstream) = ctx.upstream_override.as_ref() {
        upstream.cache_isolation_key()
    } else {
        ctx.route
            .as_ref()
            .and_then(|r| r.resolve_upstream())
            .map(|u| u.cache_isolation_key())
            .unwrap_or_default()
    };
    let scheme = if session
        .digest()
        .and_then(|d| d.ssl_digest.as_ref())
        .is_some()
    {
        "https"
    } else {
        "http"
    };
    let mut namespace = format!("rf={route_fp:x}|c={policy_fp:x}|u={upstream_key:x}|sch={scheme}");
    if settings.is_some_and(|s| {
        s.cache_authenticated_requests
            && s.consumer_isolation
            && !s
                .cache_key
                .as_ref()
                .is_some_and(|templates| cache_key_has_identity(templates))
    }) {
        namespace.push_str(&format!("|cc={}", consumer_isolation_component(ctx)));
    }
    // pingora 0.9 removed the `namespace` parameter: only `primary` is hashed.
    // Concatenating the former namespace and primary bytes preserves the legacy
    // hash, so cached entries stay addressable across the upgrade.
    CacheKey::new(format!("{namespace}{primary}"), "")
}

pub(crate) fn cache_vary(
    meta: &CacheMeta,
    ctx: &ProxyContext,
    req: &RequestHeader,
) -> Option<HashBinary> {
    let settings = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS)?;
    if response_has_vary_star(meta.headers()) {
        return None;
    }
    let mut headers: Vec<String> = meta
        .headers()
        .get_all(VARY)
        .iter()
        .flat_map(|v| v.to_str().unwrap_or("").split(','))
        .map(|v| v.trim().to_ascii_lowercase())
        .filter(|v| !v.is_empty())
        .collect();
    headers.extend(settings.vary.iter().cloned());
    if headers.is_empty() {
        return None;
    }
    headers.sort_unstable();
    headers.dedup();
    let mut key = VarianceBuilder::new();
    for name in &headers {
        let mut values = req.headers.get_all(name).iter();
        if let Some(first) = values.next() {
            key.add_value(name, first.as_bytes());
            for value in values {
                key.add_value(name, value.as_bytes());
            }
        } else {
            key.add_value(name, &[]);
        }
    }
    key.finalize()
}

pub(crate) fn response_cacheability(
    resp: &ResponseHeader,
    ctx: &ProxyContext,
) -> Result<RespCacheable> {
    let Some(settings) = ctx.get::<Arc<CacheSettings>>(CTX_KEY_CACHE_SETTINGS) else {
        return Ok(RespCacheable::Uncacheable(NoCacheReason::NeverEnabled));
    };
    if ctx
        .get::<bool>(&settings.no_cache_flag_key)
        .copied()
        .unwrap_or(false)
    {
        return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
    }
    if should_bypass_authenticated_request(settings, ctx)
        || !settings.statuses.contains(&resp.status.as_u16())
        || (!settings.cache_set_cookie_responses && resp.headers.contains_key(SET_COOKIE))
        || response_has_vary_star(&resp.headers)
    {
        return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
    }
    let control = CacheControl::from_resp_headers(resp);
    if origin_response_uncacheable(control.as_ref()) {
        return Ok(RespCacheable::Uncacheable(NoCacheReason::OriginNotCache));
    }
    // `ensure_max_age` preserves an origin `max-age`/`s-maxage` (unless the
    // APISIX `cache_control: false` flag pins storage freshness to the
    // configured `ttl`), so the origin's freshness overrides `ttl`; without
    // an origin directive the configured TTL is injected as before.
    let control = ensure_max_age(control, settings);
    let authorized = ctx.original_request_had_credentials || ctx.request_has_credentials;
    Ok(resp_cacheable(
        control.as_ref(),
        resp.clone(),
        authorized,
        &CACHE_DEFAULT,
    ))
}

pub(crate) fn error_status(error: &Error) -> u16 {
    match error.etype() {
        ErrorType::Custom(custom)
            if *custom == crate::plugins::client_control::ERROR_PAYLOAD_TOO_LARGE =>
        {
            StatusCode::PAYLOAD_TOO_LARGE.as_u16()
        }
        ErrorType::HTTPStatus(code) => *code,
        _ => match error.esource() {
            ErrorSource::Upstream => 502,
            ErrorSource::Downstream => match error.etype() {
                ErrorType::WriteError | ErrorType::ReadError | ErrorType::ConnectionClosed => 0,
                _ => 400,
            },
            ErrorSource::Internal | ErrorSource::Unset => 500,
        },
    }
}

/// APISIX always honors upstream directives that mark a response as
/// non-shared/non-storable, regardless of the `cache_control` flag. The flag
/// governs request-side semantics; these response directives are a safety
/// contract the application uses to mark personalized content.
fn origin_response_uncacheable(control: Option<&CacheControl>) -> bool {
    control.is_some_and(|cc| {
        cc.no_store() || cc.private() || cc.no_cache() || cc.no_cache_field_names().is_some()
    })
}

fn ensure_max_age(cc: Option<CacheControl>, settings: &CacheSettings) -> Option<CacheControl> {
    // APISIX `cache_control: false`: the configured TTL governs storage
    // freshness; drop the origin's `max-age`/`s-maxage` so they cannot
    // override `ttl` (other directives still apply — the unconditional
    // private/no-store/no-cache rejection has already run).
    let cc = if settings.cache_control == Some(false) {
        cc.map(|mut control| {
            control.directives.shift_remove(&DirectiveKey::MaxAge);
            control.directives.shift_remove(&DirectiveKey::SMaxAge);
            control
        })
    } else {
        cc
    };
    match cc {
        Some(existing) => {
            let has_max_age = existing.directives.contains_key(&DirectiveKey::MaxAge);
            let rewrite_smaxage = settings.respect_s_maxage
                && existing.directives.contains_key(&DirectiveKey::SMaxAge);
            let add_swr = settings.stale_while_revalidate.is_some_and(|_| {
                !existing
                    .directives
                    .contains_key(&DirectiveKey::StaleWhileRevalidate)
            });
            if has_max_age && !rewrite_smaxage && !add_swr {
                return Some(existing);
            }
            let mut directives = DirectiveMap::with_capacity(existing.directives.len() + 3);
            let mut final_has_max_age = false;
            for (key, value) in &existing.directives {
                let cloned = value.as_ref().map(|v| DirectiveValue(v.0.clone()));
                if settings.respect_s_maxage && *key == DirectiveKey::SMaxAge {
                    if let Some(value) = value {
                        directives
                            .insert(DirectiveKey::MaxAge, Some(DirectiveValue(value.0.clone())));
                        final_has_max_age = true;
                    }
                    directives.insert(key.clone(), cloned);
                } else {
                    if *key == DirectiveKey::MaxAge {
                        final_has_max_age = true;
                    }
                    directives.insert(key.clone(), cloned);
                }
            }
            if !final_has_max_age {
                directives.insert(
                    DirectiveKey::MaxAge,
                    Some(DirectiveValue(
                        settings.ttl.as_secs().to_string().into_bytes(),
                    )),
                );
            }
            if let Some(swr) = settings
                .stale_while_revalidate
                .filter(|_| !directives.contains_key(&DirectiveKey::StaleWhileRevalidate))
            {
                directives.insert(
                    DirectiveKey::StaleWhileRevalidate,
                    Some(DirectiveValue(swr.as_secs().to_string().into_bytes())),
                );
            }
            Some(CacheControl {
                directives,
                allow_float_seconds: false,
            })
        }
        None => {
            let mut directives =
                DirectiveMap::with_capacity(1 + settings.stale_while_revalidate.is_some() as usize);
            directives.insert(
                DirectiveKey::MaxAge,
                Some(DirectiveValue(
                    settings.ttl.as_secs().to_string().into_bytes(),
                )),
            );
            if let Some(swr) = settings.stale_while_revalidate {
                directives.insert(
                    DirectiveKey::StaleWhileRevalidate,
                    Some(DirectiveValue(swr.as_secs().to_string().into_bytes())),
                );
            }
            Some(CacheControl {
                directives,
                allow_float_seconds: false,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn control_for(value: &str) -> Option<CacheControl> {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("cache-control", value).unwrap();
        CacheControl::from_resp_headers(&resp)
    }

    fn test_request() -> RequestHeader {
        let mut req = RequestHeader::build("GET", b"/api/users?q=1&lang=en", None).unwrap();
        req.insert_header(http::header::HOST, "example.com")
            .unwrap();
        req.insert_header("x-custom-id", "abc-123").unwrap();
        req
    }

    #[test]
    fn cache_key_template_renders_supported_variables_and_literals() {
        let req = test_request();
        assert_eq!(render_cache_key_template(&req, "$host"), "example.com");
        assert_eq!(
            render_cache_key_template(&req, "$request_uri"),
            "/api/users?q=1&lang=en"
        );
        assert_eq!(render_cache_key_template(&req, "$uri"), "/api/users");
        assert_eq!(render_cache_key_template(&req, "$args"), "q=1&lang=en");
        assert_eq!(render_cache_key_template(&req, "$request_method"), "GET");
        assert_eq!(render_cache_key_template(&req, "$arg_q"), "1");
        assert_eq!(
            render_cache_key_template(&req, "$http_x_custom_id"),
            "abc-123"
        );
        assert_eq!(
            render_cache_key_template(&req, "v1:$host$uri:${args}"),
            "v1:example.com/api/users:q=1&lang=en"
        );
    }

    #[test]
    fn cache_key_template_unknown_variables_render_empty() {
        let req = test_request();
        assert_eq!(render_cache_key_template(&req, "$unknown"), "");
        assert_eq!(
            render_cache_key_template(&req, "prefix-$unknown-suffix"),
            "prefix--suffix"
        );
    }

    #[test]
    fn cache_bypass_triggers_on_any_non_empty_rendered_template() {
        let req = test_request();
        assert!(!cache_bypass_requested(&["$unknown".to_string()], &req));
        assert!(cache_bypass_requested(
            &["$unknown".to_string(), "$arg_q".to_string()],
            &req
        ));
        assert!(cache_bypass_requested(
            &["$request_method".to_string()],
            &req
        ));
        // APISIX treats a rendered "0" as falsy ...
        let req = RequestHeader::build("GET", b"/api?q=0", None).unwrap();
        assert!(!cache_bypass_requested(&["$arg_q".to_string()], &req));
        // ... but concatenated templates render "00", which is truthy.
        assert!(cache_bypass_requested(
            &["$arg_q".to_string(), "$arg_q".to_string()],
            &req
        ));
    }

    #[test]
    fn no_cache_templates_are_evaluated_per_request() {
        let mut req = test_request();
        assert!(no_cache_requested(&["$http_x_custom_id".to_string()], &req));
        assert!(!no_cache_requested(&["$arg_missing".to_string()], &req));

        req.remove_header("x-custom-id");
        assert!(!no_cache_requested(
            &["$http_x_custom_id".to_string()],
            &req
        ));
    }

    #[test]
    fn origin_response_directives_are_always_honored() {
        for directive in ["private", "no-store", "no-cache", "no-cache=\"set-cookie\""] {
            assert!(
                origin_response_uncacheable(control_for(directive).as_ref()),
                "{directive} must be uncacheable"
            );
        }
        assert!(!origin_response_uncacheable(
            control_for("public, max-age=60").as_ref()
        ));
        assert!(!origin_response_uncacheable(None));
    }

    #[test]
    fn request_no_cache_bypass_is_governed_by_cache_control_flag() {
        let mut req_headers = http::HeaderMap::new();
        req_headers.insert("cache-control", "no-cache".parse().unwrap());
        let ctx = ProxyContext::default();

        // Absent flag (pingsix legacy) and Some(true): request no-cache bypasses.
        assert!(!should_enable_request_cache(&req_headers, None, &ctx));
        assert!(!should_enable_request_cache(
            &req_headers,
            Some(&minimal_settings(None)),
            &ctx
        ));
        assert!(!should_enable_request_cache(
            &req_headers,
            Some(&minimal_settings(Some(true))),
            &ctx
        ));

        // APISIX `cache_control: false`: request-side directives are ignored.
        assert!(should_enable_request_cache(
            &req_headers,
            Some(&minimal_settings(Some(false))),
            &ctx
        ));

        // Without request directives the cache stays enabled, and unrelated
        // directives (max-age) do not bypass.
        let clean = http::HeaderMap::new();
        assert!(should_enable_request_cache(
            &clean,
            Some(&minimal_settings(Some(false))),
            &ctx
        ));
        let mut max_age_only = http::HeaderMap::new();
        max_age_only.insert("cache-control", "max-age=0".parse().unwrap());
        // Non-bypass request directives (max-age) do not disable the cache.
        assert!(should_enable_request_cache(
            &max_age_only,
            Some(&minimal_settings(None)),
            &ctx
        ));

        // Arbitrary client-supplied X-Bypass-Cache header must NOT bypass cache.
        let mut spoofed_bypass = http::HeaderMap::new();
        spoofed_bypass.insert("x-bypass-cache", "1".parse().unwrap());
        assert!(
            should_enable_request_cache(
                &spoofed_bypass,
                Some(&minimal_settings(Some(false))),
                &ctx
            ),
            "unconfigured x-bypass-cache header must not bypass cache"
        );

        // Case-insensitive and multi-header Cache-Control directives are honored.
        let mut multi_cc = http::HeaderMap::new();
        multi_cc.append(http::header::CACHE_CONTROL, "public".parse().unwrap());
        multi_cc.append(
            http::header::CACHE_CONTROL,
            "max-age=0, NO-STORE".parse().unwrap(),
        );
        assert!(!should_enable_request_cache(
            &multi_cc,
            Some(&minimal_settings(Some(true))),
            &ctx
        ));
        assert!(should_enable_request_cache(
            &multi_cc,
            Some(&minimal_settings(Some(false))),
            &ctx
        ));
    }

    fn minimal_settings(cache_control: Option<bool>) -> Arc<CacheSettings> {
        Arc::new(CacheSettings {
            ttl: Duration::from_secs(60),
            statuses: Arc::new(std::collections::HashSet::new()),
            vary: Arc::new(vec![]),
            hide_cache_headers: false,
            enable_purge: false,
            max_file_size_bytes: 0,
            stale_while_revalidate: None,
            respect_s_maxage: true,
            cache_authenticated_requests: false,
            cache_set_cookie_responses: false,
            cache_key: None,
            cache_bypass: Arc::new(vec![]),
            no_cache: Arc::new(vec![]),
            no_cache_flag_key: "test-flag".to_string(),
            cache_control,
            consumer_isolation: true,
            policy_fingerprint: 0,
        })
    }

    #[test]
    fn cache_control_false_pins_storage_ttl_over_origin_freshness() {
        // APISIX `cache_control: false`: the configured ttl governs; origin
        // max-age/s-maxage must not override it.
        let settings = minimal_settings(Some(false));
        for origin in ["public, max-age=999999", "public, s-maxage=999999"] {
            let control = ensure_max_age(control_for(origin), &settings).unwrap();
            let max_age = control
                .directives
                .get(&DirectiveKey::MaxAge)
                .and_then(|value| value.as_ref())
                .unwrap()
                .parse_as_delta_seconds()
                .unwrap();
            assert_eq!(max_age, 60, "origin {origin} must not override ttl");
        }

        // Legacy (absent flag): origin freshness is preserved.
        let legacy = minimal_settings(None);
        let control = ensure_max_age(control_for("public, max-age=999999"), &legacy).unwrap();
        assert_eq!(
            control
                .directives
                .get(&DirectiveKey::MaxAge)
                .and_then(|value| value.as_ref())
                .unwrap()
                .parse_as_delta_seconds()
                .unwrap(),
            999_999
        );
    }

    #[test]
    fn credential_digest_differs_with_credentials() {
        let anonymous = test_request();
        let mut authorized = test_request();
        authorized
            .insert_header(http::header::AUTHORIZATION, "Bearer token-a")
            .unwrap();
        let mut other = test_request();
        other
            .insert_header(http::header::AUTHORIZATION, "Bearer token-b")
            .unwrap();

        assert_eq!(
            credential_cache_key_component(&anonymous),
            credential_cache_key_component(&anonymous)
        );
        assert_ne!(
            credential_cache_key_component(&anonymous),
            credential_cache_key_component(&authorized)
        );
        assert_ne!(
            credential_cache_key_component(&authorized),
            credential_cache_key_component(&other)
        );
        // SHA-256 hex digest, not a fast 64-bit hash.
        assert_eq!(credential_cache_key_component(&anonymous).len(), 64);
    }

    #[test]
    fn consumer_isolation_component_partitions_on_captured_digests() {
        // The component is derived from ctx-captured digests (original
        // headers + auth-plugin-noted credentials), NOT from the current
        // request headers — auth plugins may already have stripped them by
        // the time the cache key is built.
        let anonymous = ProxyContext::default();
        let anonymous_component = consumer_isolation_component(&anonymous);

        let mut consumer_a = ProxyContext::default();
        consumer_a.note_request_credential("key-a");

        let mut consumer_b = ProxyContext::default();
        consumer_b.note_request_credential("key-b");

        let mut stripped = ProxyContext {
            original_credential_digest: Some(credential_cache_key_component(&test_request())),
            ..ProxyContext::default()
        };
        stripped.note_request_credential("key-a");

        // Different credentials partition; the same combination is stable.
        assert_ne!(
            anonymous_component,
            consumer_isolation_component(&consumer_a)
        );
        assert_ne!(
            consumer_isolation_component(&consumer_a),
            consumer_isolation_component(&consumer_b)
        );
        let mut consumer_a_again = ProxyContext::default();
        consumer_a_again.note_request_credential("key-a");
        assert_eq!(
            consumer_isolation_component(&consumer_a),
            consumer_isolation_component(&consumer_a_again)
        );
        // Combining the early-captured digest with the noted credential.
        assert_ne!(
            consumer_isolation_component(&consumer_a),
            consumer_isolation_component(&stripped)
        );
        assert_eq!(consumer_isolation_component(&stripped).len(), 64);
    }

    #[test]
    fn explicit_cache_key_with_identity_var_skips_consumer_isolation() {
        // Mirrors APISIX: an operator-supplied cache_key that already carries
        // the request identity opts out of consumer isolation.
        assert!(cache_key_has_identity(&[
            "$host".to_string(),
            "$http_authorization".to_string()
        ]));
        assert!(cache_key_has_identity(&[
            "$http_authorization".to_string(),
            "$uri".to_string()
        ]));
        assert!(!cache_key_has_identity(&[
            "$host".to_string(),
            "$request_uri".to_string()
        ]));
        // Vars pingsix cannot render do NOT count as identity: they render
        // empty, so isolation must stay on.
        assert!(!cache_key_has_identity(&["$consumer_name".to_string()]));
    }

    #[test]
    fn cache_vary_includes_all_values_for_repeated_headers() {
        let mut resp = ResponseHeader::build(200, None).unwrap();
        resp.insert_header("vary", "X-Custom").unwrap();
        resp.insert_header("cache-control", "public, max-age=60")
            .unwrap();
        let control = CacheControl::from_resp_headers(&resp);
        let RespCacheable::Cacheable(meta) =
            resp_cacheable(control.as_ref(), resp, false, &CACHE_DEFAULT)
        else {
            panic!("response should be cacheable");
        };

        let mut req1 = test_request();
        req1.append_header("x-custom", "a").unwrap();
        req1.append_header("x-custom", "b").unwrap();

        let mut req2 = test_request();
        req2.append_header("x-custom", "a").unwrap();
        req2.append_header("x-custom", "c").unwrap();

        let mut ctx = ProxyContext::default();
        ctx.set(CTX_KEY_CACHE_SETTINGS, minimal_settings(None));
        let v1 = cache_vary(&meta, &ctx, &req1);
        let v2 = cache_vary(&meta, &ctx, &req2);
        assert!(v1.is_some());
        assert_ne!(
            v1, v2,
            "second value of a repeated Vary header must affect the variance hash"
        );
    }
}

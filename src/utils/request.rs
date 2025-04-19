use std::str::FromStr;

use http::HeaderName;
use once_cell::sync::Lazy;
use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::config::UpstreamHashOn;

/// Build request selector key.
pub fn request_selector_key(session: &mut Session, hash_on: &UpstreamHashOn, key: &str) -> String {
    match hash_on {
        UpstreamHashOn::VARS => handle_vars(session, key),
        UpstreamHashOn::HEAD => get_req_header_value(session.req_header(), key)
            .unwrap_or_default()
            .to_string(),
        UpstreamHashOn::COOKIE => get_cookie_value(session.req_header(), key)
            .unwrap_or_default()
            .to_string(),
    }
}

/// Handles variable-based request selection.
fn handle_vars(session: &mut Session, key: &str) -> String {
    if key.starts_with("arg_") {
        if let Some(name) = key.strip_prefix("arg_") {
            return get_query_value(session.req_header(), name)
                .unwrap_or_default()
                .to_string();
        }
    }

    match key {
        "uri" => session.req_header().uri.path().to_string(),
        "request_uri" => session
            .req_header()
            .uri
            .path_and_query()
            .map_or_else(|| "".to_string(), |pq| pq.to_string()),
        "query_string" => session
            .req_header()
            .uri
            .query()
            .unwrap_or_default()
            .to_string(),
        "remote_addr" => session
            .client_addr()
            .map_or_else(|| "".to_string(), |addr| addr.to_string()),
        "remote_port" => session
            .client_addr()
            .and_then(|s| s.as_inet())
            .map_or_else(|| "".to_string(), |i| i.port().to_string()),
        "server_addr" => session
            .server_addr()
            .map_or_else(|| "".to_string(), |addr| addr.to_string()),
        _ => "".to_string(),
    }
}

pub fn get_query_value<'a>(req_header: &'a RequestHeader, name: &str) -> Option<&'a str> {
    if let Some(query) = req_header.uri.query() {
        for item in query.split('&') {
            if let Some((k, v)) = item.split_once('=') {
                if k == name {
                    return Some(v.trim());
                }
            }
        }
    }
    None
}

/// Remove query parameter from request header URI
///
/// # Arguments
/// * `req_header` - The HTTP request header to modify
/// * `name` - Name of the query parameter to remove
///
/// # Returns
/// Result indicating success or failure of the URI modification
pub fn remove_query_from_header(
    req_header: &mut RequestHeader,
    name: &str,
) -> Result<(), http::uri::InvalidUri> {
    if let Some(query) = req_header.uri.query() {
        let mut query_list = vec![];
        for item in query.split('&') {
            if let Some((k, v)) = item.split_once('=') {
                if k != name {
                    query_list.push(format!("{k}={v}"));
                }
            } else if item != name {
                query_list.push(item.to_string());
            }
        }
        let query = query_list.join("&");
        let mut new_path = req_header.uri.path().to_string();
        if !query.is_empty() {
            new_path = format!("{new_path}?{query}");
        }
        return new_path
            .parse::<http::Uri>()
            .map(|uri| req_header.set_uri(uri));
    }

    Ok(())
}

pub fn get_req_header_value<'a>(req_header: &'a RequestHeader, key: &str) -> Option<&'a str> {
    if let Some(value) = req_header.headers.get(key) {
        if let Ok(value) = value.to_str() {
            return Some(value);
        }
    }
    None
}

pub fn get_cookie_value<'a>(req_header: &'a RequestHeader, cookie_name: &str) -> Option<&'a str> {
    if let Some(cookie_value) = get_req_header_value(req_header, "Cookie") {
        for item in cookie_value.split(';') {
            if let Some((k, v)) = item.split_once('=') {
                if k == cookie_name {
                    return Some(v.trim());
                }
            }
        }
    }

    log::warn!("Cookie '{}' not found or malformed.", cookie_name);
    None
}

/// Retrieves the request host from the request header.
pub fn get_request_host(header: &RequestHeader) -> Option<&str> {
    if let Some(host) = header.uri.host() {
        return Some(host);
    }
    if let Some(host) = header.headers.get(http::header::HOST) {
        if let Ok(value) = host.to_str().map(|host| host.split(':').next()) {
            return value;
        }
    }
    None
}

static HTTP_HEADER_X_FORWARDED_FOR: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Forwarded-For").unwrap());

static HTTP_HEADER_X_REAL_IP: Lazy<http::HeaderName> =
    Lazy::new(|| HeaderName::from_str("X-Real-Ip").unwrap());

/// Get remote address from session.
fn get_remote_addr(session: &Session) -> Option<(String, u16)> {
    session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| (addr.ip().to_string(), addr.port()))
}

/// Gets client IP from `X-Forwarded-For`, `X-Real-IP`, or remote address.
pub fn get_client_ip(session: &Session) -> String {
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR.clone()) {
        if let Ok(forwarded) = value.to_str() {
            if let Some(ip) = forwarded.split(',').next() {
                return ip.trim().to_string();
            }
        }
    }

    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP.clone()) {
        if let Ok(real_ip) = value.to_str() {
            return real_ip.trim().to_string();
        }
    }

    if let Some((addr, _)) = get_remote_addr(session) {
        return addr;
    }

    "".to_string()
}

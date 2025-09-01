use http::HeaderName;
use once_cell::sync::Lazy;
use pingora_http::RequestHeader;
use pingora_proxy::Session;

use crate::config::UpstreamHashOn;

/// Build request selector key based on configuration.
///
/// Selects a value from the request (variable, header, or cookie) to be used,
/// typically for consistent upstream hashing.
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

/// Handles variable-based request selection by interpreting predefined variable names.
///
/// Supports variables like request URI components, client/server addresses, and query arguments (`arg_*`).
fn handle_vars(session: &mut Session, key: &str) -> String {
    // Handle query arguments prefixed with "arg_"
    if let Some(name) = key.strip_prefix("arg_") {
        return get_query_value(session.req_header(), name)
            .unwrap_or_default()
            .to_string();
    }

    // Handle predefined variable names
    match key {
        "uri" => session.req_header().uri.path().to_string(),
        "request_uri" => session.req_header().uri.path_and_query().map_or_else(
            || session.req_header().uri.path().to_string(),
            |pq| pq.to_string(),
        ), // Fallback to path if no query
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
        // Add other variables here if needed
        _ => {
            log::debug!("Unsupported variable key for hashing: {key}");
            "".to_string()
        }
    }
}

/// Extracts the value of a specific query parameter from the request URI.
///
/// Returns the first occurrence of the parameter's value.
pub fn get_query_value<'a>(req_header: &'a RequestHeader, name: &str) -> Option<&'a str> {
    req_header.uri.query().and_then(|query| {
        query.split('&').find_map(|pair| {
            if let Some((k, v)) = pair.split_once('=') {
                if k == name {
                    Some(v.trim()) // Trim whitespace from value
                } else {
                    None
                }
            } else if pair == name {
                // Handle key-only parameters if needed? Usually not.
                Some("") // Or None, depending on desired behavior for key-only params
            } else {
                None
            }
        })
    })
}

/// Removes a specified query parameter from the request header's URI.
///
/// Modifies the `req_header` in place.
///
/// # Arguments
/// * `req_header` - The HTTP request header to modify.
/// * `name` - Name of the query parameter to remove.
///
/// # Returns
/// `Ok(())` if the URI was successfully modified or if the parameter/query didn't exist.
/// `Err(http::uri::InvalidUri)` if reconstructing the URI fails.
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

/// Retrieves the value of a specific header from the request.
///
/// Returns `None` if the header is not present or its value is not valid UTF-8.
pub fn get_req_header_value<'a>(req_header: &'a RequestHeader, key: &str) -> Option<&'a str> {
    req_header
        .headers
        .get(key)
        .and_then(|value| value.to_str().ok())
}

/// Retrieves the value of a specific cookie from the `Cookie` header.
///
/// Parses the `Cookie` header string manually. This is sufficient for simple
/// key=value pairs but might not handle complex/encoded cookie values robustly.
/// Returns the first occurrence of the cookie's value.
pub fn get_cookie_value<'a>(req_header: &'a RequestHeader, cookie_name: &str) -> Option<&'a str> {
    if let Some(cookie_header_value) = get_req_header_value(req_header, "Cookie") {
        for item in cookie_header_value.split(';') {
            // Trim whitespace around the key-value pair
            let trimmed_item = item.trim();
            if let Some((k, v)) = trimmed_item.split_once('=') {
                // Trim whitespace around the key specifically before comparison
                if k.trim() == cookie_name {
                    // Return the value, trimming surrounding whitespace
                    return Some(v.trim());
                }
            }
            // Note: This simple parsing doesn't handle cookies without '=',
            // or cookies where the value contains ';', '=', or needs decoding.
        }
        log::debug!("Cookie '{cookie_name}' not found within Cookie header");
    } else {
        log::debug!("No Cookie header found");
    }

    None // Return None if the header doesn't exist or the cookie isn't found
}

/// Retrieves the request host (domain name) from the request header.
///
/// Prefers the host from the URI, falls back to the `Host` header.
/// Removes the port number if present in the `Host` header.
pub fn get_request_host(header: &RequestHeader) -> Option<&str> {
    // 1. Try host from URI (highest precedence, less likely to be ambiguous)
    if let Some(host) = header.uri.host() {
        // Check if it's not empty, as uri.host() can return "" in some cases
        if !host.is_empty() {
            return Some(host);
        }
    }
    // 2. Fallback to Host header
    if let Some(host_header_value) = header.headers.get(http::header::HOST) {
        if let Ok(host_str) = host_header_value.to_str() {
            // Remove port if present ":port"
            return Some(host_str.split(':').next().unwrap_or("")); // Take the part before the first ':'
        }
    }
    // 3. No host found
    None
}

// Use http::header constants where available for better readability and type safety
static HTTP_HEADER_X_FORWARDED_FOR: Lazy<HeaderName> =
    Lazy::new(|| HeaderName::from_static("x-forwarded-for"));

static HTTP_HEADER_X_REAL_IP: Lazy<HeaderName> = Lazy::new(|| HeaderName::from_static("x-real-ip"));

/// Gets the client's apparent IP address based on common proxy headers or the direct connection address.
///
/// The order of precedence is:
/// 1. `X-Forwarded-For` (first IP in the list)
/// 2. `X-Real-IP`
/// 3. Direct client address (`session.client_addr()`)
///
/// Returns an empty string if no IP address can be determined.
pub fn get_client_ip(session: &Session) -> String {
    // 1. Check X-Forwarded-For
    if let Some(value) = session.get_header(HTTP_HEADER_X_FORWARDED_FOR.clone()) {
        if let Ok(forwarded) = value.to_str() {
            // Note: Takes the *first* IP from the X-Forwarded-For list.
            // This is common practice but assumes the first IP is the actual client
            // and the header hasn't been spoofed by intermediate proxies or the client.
            // For environments requiring higher security, validate against a list
            // of trusted proxy IPs or implement more sophisticated logic.
            if let Some(ip) = forwarded.split(',').next() {
                let trimmed_ip = ip.trim();
                if !trimmed_ip.is_empty() {
                    return trimmed_ip.to_string();
                }
            }
        }
    }

    // 2. Check X-Real-IP
    if let Some(value) = session.get_header(HTTP_HEADER_X_REAL_IP.clone()) {
        if let Ok(real_ip) = value.to_str() {
            let trimmed_ip = real_ip.trim();
            if !trimmed_ip.is_empty() {
                return trimmed_ip.to_string();
            }
        }
    }

    // 3. Fallback to direct client address
    if let Some(addr) = session.client_addr() {
        // Return only the IP part, converting IPAddr to string
        return addr
            .as_inet()
            .map(|addr| addr.ip().to_string())
            .unwrap_or_default();
    }

    // 4. Unable to determine IP
    log::debug!("Could not determine client IP address");
    "".to_string()
}

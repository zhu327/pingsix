//! Unified error handling for PingSIX
//!
//! This module provides a centralized error type system that eliminates
//! the need for modules to depend on each other for error handling.

use std::fmt;

/// Unified error types for the proxy system
#[derive(Debug)]
pub enum ProxyError {
    /// Configuration-related errors
    Configuration(String),
    
    /// Network and I/O errors
    Network(std::io::Error),
    
    /// DNS resolution failures
    DnsResolution(String),
    
    /// Health check failures
    HealthCheck(String),
    
    /// Route matching failures
    RouteMatching(String),
    
    /// Upstream selection failures
    UpstreamSelection(String),
    
    /// SSL/TLS related errors
    Ssl(String),
    
    /// Plugin execution errors
    Plugin(String),
    
    /// Internal system errors
    Internal(String),
    
    /// Validation errors
    Validation(String),
    
    /// Resource not found errors
    NotFound(String),
    
    /// Authentication/Authorization errors
    Unauthorized(String),
    
    /// Rate limiting errors
    RateLimited(String),
    
    /// Pingora framework errors
    Pingora(pingora_error::Error),
}

impl fmt::Display for ProxyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyError::Configuration(msg) => write!(f, "Configuration error: {msg}"),
            ProxyError::Network(err) => write!(f, "Network error: {err}"),
            ProxyError::DnsResolution(msg) => write!(f, "DNS resolution failed: {msg}"),
            ProxyError::HealthCheck(msg) => write!(f, "Health check failed: {msg}"),
            ProxyError::RouteMatching(msg) => write!(f, "Route matching failed: {msg}"),
            ProxyError::UpstreamSelection(msg) => write!(f, "Upstream selection failed: {msg}"),
            ProxyError::Ssl(msg) => write!(f, "SSL/TLS error: {msg}"),
            ProxyError::Plugin(msg) => write!(f, "Plugin execution error: {msg}"),
            ProxyError::Internal(msg) => write!(f, "Internal error: {msg}"),
            ProxyError::Validation(msg) => write!(f, "Validation error: {msg}"),
            ProxyError::NotFound(msg) => write!(f, "Resource not found: {msg}"),
            ProxyError::Unauthorized(msg) => write!(f, "Unauthorized: {msg}"),
            ProxyError::RateLimited(msg) => write!(f, "Rate limited: {msg}"),
            ProxyError::Pingora(err) => write!(f, "Pingora error: {err}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProxyError::Network(err) => Some(err),
            ProxyError::Pingora(err) => Some(err),
            _ => None,
        }
    }
}

// Error conversions
impl From<std::io::Error> for ProxyError {
    fn from(err: std::io::Error) -> Self {
        ProxyError::Network(err)
    }
}

impl From<pingora_error::Error> for ProxyError {
    fn from(err: pingora_error::Error) -> Self {
        ProxyError::Pingora(err)
    }
}

impl From<ProxyError> for Box<pingora_error::Error> {
    fn from(err: ProxyError) -> Self {
        match err {
            ProxyError::Pingora(pingora_err) => Box::new(pingora_err),
            _ => Box::new(pingora_error::Error::new_str(&err.to_string())),
        }
    }
}

/// Result type alias for proxy operations
pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

/// Helper trait for adding context to errors
pub trait ErrorContext<T> {
    fn with_context(self, context: &str) -> ProxyResult<T>;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: fmt::Display,
{
    fn with_context(self, context: &str) -> ProxyResult<T> {
        self.map_err(|e| ProxyError::Internal(format!("{context}: {e}")))
    }
}

/// Convenience macros for error creation
#[macro_export]
macro_rules! config_error {
    ($msg:expr) => {
        ProxyError::Configuration($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        ProxyError::Configuration(format!($fmt, $($arg)*))
    };
}

#[macro_export]
macro_rules! internal_error {
    ($msg:expr) => {
        ProxyError::Internal($msg.to_string())
    };
    ($fmt:expr, $($arg:tt)*) => {
        ProxyError::Internal(format!($fmt, $($arg)*))
    };
}
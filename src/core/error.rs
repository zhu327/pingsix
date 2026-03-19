//! Error handling for the Pingsix proxy.
//!
//! Provides unified error types with context-aware handling and chaining support.

/// Unified error types for the pingsix proxy.
///
/// Provides context-aware error handling with chaining support for better debugging.
#[derive(Debug)]
pub enum ProxyError {
    Configuration(String),
    Network(std::io::Error),
    DnsResolution(String),
    HealthCheck(String),
    RouteMatching(String),
    UpstreamSelection(String),
    Ssl(String),
    Plugin(String),
    Internal(String),
    Pingora(pingora_error::Error),
    /// Validation errors (e.g., from validator crate)
    Validation(String),
    /// Structured validation errors preserving original ValidationErrors
    ValidationStructured(validator::ValidationErrors),
    /// Serialization/deserialization errors
    Serialization(String),
    /// Etcd-related errors
    Etcd(String),
    /// Authentication/authorization errors
    Auth(String),
    /// Rate limiting errors
    RateLimit(String),
    /// A generic error variant that can hold any error with context
    WithCause {
        message: String,
        cause: Box<dyn std::error::Error + Send + Sync>,
    },
}

macro_rules! fmt_err {
    ($f:expr, $prefix:literal, $val:expr) => {
        write!($f, concat!($prefix, "{}"), $val)
    };
}

impl std::fmt::Display for ProxyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProxyError::Configuration(msg) => fmt_err!(f, "Configuration error: ", msg),
            ProxyError::Network(err) => fmt_err!(f, "Network error: ", err),
            ProxyError::DnsResolution(msg) => fmt_err!(f, "DNS resolution failed: ", msg),
            ProxyError::HealthCheck(msg) => fmt_err!(f, "Health check failed: ", msg),
            ProxyError::RouteMatching(msg) => fmt_err!(f, "Route matching failed: ", msg),
            ProxyError::UpstreamSelection(msg) => fmt_err!(f, "Upstream selection failed: ", msg),
            ProxyError::Ssl(msg) => fmt_err!(f, "SSL/TLS error: ", msg),
            ProxyError::Plugin(msg) => fmt_err!(f, "Plugin execution error: ", msg),
            ProxyError::Internal(msg) => fmt_err!(f, "Internal error: ", msg),
            ProxyError::Pingora(err) => fmt_err!(f, "Pingora error: ", err),
            ProxyError::Validation(msg) => fmt_err!(f, "Validation error: ", msg),
            ProxyError::ValidationStructured(errors) => fmt_err!(f, "Validation error: ", errors),
            ProxyError::Serialization(msg) => fmt_err!(f, "Serialization error: ", msg),
            ProxyError::Etcd(msg) => fmt_err!(f, "Etcd error: ", msg),
            ProxyError::Auth(msg) => fmt_err!(f, "Authentication error: ", msg),
            ProxyError::RateLimit(msg) => fmt_err!(f, "Rate limit error: ", msg),
            ProxyError::WithCause { message, cause } => write!(f, "{message}: {cause}"),
        }
    }
}

impl std::error::Error for ProxyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProxyError::Network(err) => Some(err),
            ProxyError::Pingora(err) => Some(err),
            ProxyError::ValidationStructured(err) => Some(err),
            ProxyError::WithCause { cause, .. } => Some(cause.as_ref()),
            _ => None,
        }
    }
}

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

impl From<serde_json::Error> for ProxyError {
    fn from(err: serde_json::Error) -> Self {
        ProxyError::Serialization(err.to_string())
    }
}

impl From<validator::ValidationErrors> for ProxyError {
    fn from(err: validator::ValidationErrors) -> Self {
        ProxyError::ValidationStructured(err)
    }
}

impl From<validator::ValidationError> for ProxyError {
    fn from(err: validator::ValidationError) -> Self {
        ProxyError::Validation(err.to_string())
    }
}

impl From<Box<pingora_error::Error>> for ProxyError {
    fn from(err: Box<pingora_error::Error>) -> Self {
        ProxyError::Pingora(*err)
    }
}

fn pingora_error_type(err: &ProxyError) -> pingora_error::ErrorType {
    use pingora_error::ErrorType;
    match err {
        ProxyError::Configuration(_)
        | ProxyError::HealthCheck(_)
        | ProxyError::RouteMatching(_)
        | ProxyError::UpstreamSelection(_)
        | ProxyError::Plugin(_)
        | ProxyError::Internal(_)
        | ProxyError::Validation(_)
        | ProxyError::ValidationStructured(_)
        | ProxyError::Serialization(_)
        | ProxyError::Etcd(_) => ErrorType::InternalError,
        ProxyError::DnsResolution(_) => ErrorType::ConnectNoRoute,
        ProxyError::Ssl(_) => ErrorType::TLSHandshakeFailure,
        ProxyError::Auth(_) => ErrorType::HTTPStatus(401),
        ProxyError::RateLimit(_) => ErrorType::HTTPStatus(429),
        ProxyError::Network(_) | ProxyError::Pingora(_) | ProxyError::WithCause { .. } => {
            ErrorType::InternalError // unreachable in explain path
        }
    }
}

impl From<ProxyError> for Box<pingora_error::Error> {
    fn from(err: ProxyError) -> Self {
        use pingora_error::{Error, ErrorType};

        match err {
            ProxyError::Pingora(pingora_err) => Box::new(pingora_err),
            ProxyError::Network(io_err) => {
                Error::because(ErrorType::ConnectError, "Network error", io_err)
            }
            ProxyError::WithCause { message, cause } => {
                Error::because(ErrorType::InternalError, message, cause)
            }
            rest => Error::explain(pingora_error_type(&rest), rest.to_string()),
        }
    }
}

/// Result type alias for proxy operations
pub type ProxyResult<T> = std::result::Result<T, ProxyError>;

impl ProxyError {
    /// Create a new ProxyError with an underlying cause
    pub fn with_cause<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::WithCause {
            message: message.into(),
            cause: Box::new(cause),
        }
    }

    fn with_cause_prefixed<E, S>(prefix: &str, message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause(format!("{prefix}: {}", message.into()), cause)
    }

    /// Create a configuration error with cause
    pub fn config_error<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause_prefixed("Configuration error", message, cause)
    }

    /// Create a plugin error with cause
    pub fn plugin_error<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause_prefixed("Plugin execution error", message, cause)
    }

    /// Create a validation error (string-based, for backward compatibility)
    pub fn validation_error<S: Into<String>>(message: S) -> Self {
        ProxyError::Validation(message.into())
    }

    /// Create a structured validation error preserving ValidationErrors
    pub fn validation_error_structured(errors: validator::ValidationErrors) -> Self {
        ProxyError::ValidationStructured(errors)
    }

    /// Create a validation error with cause (uses WithCause for better error chaining)
    pub fn validation_error_with_cause<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause_prefixed("Validation error", message, cause)
    }

    /// Create a serialization error with cause
    pub fn serialization_error<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause_prefixed("Serialization error", message, cause)
    }

    /// Create an etcd error (string-based, for backward compatibility)
    pub fn etcd_error<S: Into<String>>(message: S) -> Self {
        ProxyError::Etcd(message.into())
    }

    /// Create an etcd error with cause (preserves original etcd_client::Error)
    pub fn etcd_error_with_cause<E, S>(message: S, cause: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
        S: Into<String>,
    {
        ProxyError::with_cause_prefixed("Etcd error", message, cause)
    }

    /// Create an authentication error
    pub fn auth_error<S: Into<String>>(message: S) -> Self {
        ProxyError::Auth(message.into())
    }

    /// Create a rate limit error
    pub fn rate_limit_error<S: Into<String>>(message: S) -> Self {
        ProxyError::RateLimit(message.into())
    }
}

/// Helper trait for converting errors with context
pub trait ErrorContext<T> {
    fn with_context(self, context: &str) -> ProxyResult<T>;
}

impl<T, E> ErrorContext<T> for std::result::Result<T, E>
where
    E: std::fmt::Display,
{
    fn with_context(self, context: &str) -> ProxyResult<T> {
        self.map_err(|e| ProxyError::Internal(format!("{context}: {e}")))
    }
}

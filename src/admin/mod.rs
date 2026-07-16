use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    marker::PhantomData,
};

use async_trait::async_trait;
use http::{header, Method, Response, StatusCode};
use matchit::{Match, Router};
use pingora::{
    apps::http_app::ServeHttp, protocols::http::ServerSession, services::listening::Service,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use validator::Validate;

use crate::{
    config::{
        self,
        etcd::{json_to_resource, EtcdClientWrapper},
        Admin, Identifiable, Pingsix,
    },
    core::{constant_time_eq, ProxyError},
    plugins::{build_plugin, traffic_split},
    proxy::{
        graph_mutation::{self, GraphMutationError},
        ssl::ProxySSL,
    },
    utils::response::{CommonErrors, ResponseBuilder},
};

#[derive(Debug)]
enum ApiError {
    EtcdGetError(String),
    ValidationError(String),
    MissingParameter(String),
    InvalidRequest(String),
    RequestBodyReadError(String),
    /// Resource does not exist (maps to 404).
    NotFound(String),
    /// Optimistic-concurrency (CAS) conflict or referential-integrity violation
    /// on delete (maps to 409).
    Conflict(String),
    /// Preserves the original ProxyError with full context
    ProxyError(ProxyError),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::EtcdGetError(msg) => write!(f, "Etcd get error: {msg}"),
            ApiError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            ApiError::MissingParameter(msg) => write!(f, "Missing parameter: {msg}"),
            ApiError::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            ApiError::RequestBodyReadError(msg) => write!(f, "Request body read error: {msg}"),
            ApiError::NotFound(msg) => write!(f, "Not found: {msg}"),
            ApiError::Conflict(msg) => write!(f, "Conflict: {msg}"),
            ApiError::ProxyError(err) => write!(f, "{err}"),
        }
    }
}

impl Error for ApiError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ApiError::ProxyError(err) => Some(err),
            _ => None,
        }
    }
}

impl From<ProxyError> for ApiError {
    fn from(err: ProxyError) -> Self {
        ApiError::ProxyError(err)
    }
}

impl From<GraphMutationError> for ApiError {
    fn from(err: GraphMutationError) -> Self {
        match err {
            GraphMutationError::NotFound(msg) => ApiError::NotFound(msg),
            GraphMutationError::ReferentialConflict(msg) => ApiError::Conflict(msg),
            GraphMutationError::InvalidCandidate(msg) => ApiError::ValidationError(msg),
            GraphMutationError::CasConflict(msg) => ApiError::Conflict(msg),
            GraphMutationError::Storage(proxy_err) => ApiError::from(proxy_err),
        }
    }
}

impl ApiError {
    fn into_response(self) -> ApiResponse {
        use ApiError::*;
        match self {
            EtcdGetError(msg) => {
                log::error!("Admin etcd get error: {msg}");
                CommonErrors::internal_server_error("Backend configuration store unavailable")
            }
            RequestBodyReadError(_) => CommonErrors::bad_request("Failed to read request body"),
            NotFound(_) => ResponseBuilder::error_http(StatusCode::NOT_FOUND, &self.to_string()),
            Conflict(_) => ResponseBuilder::error_http(StatusCode::CONFLICT, &self.to_string()),
            ValidationError(_) | MissingParameter(_) | InvalidRequest(_) => {
                CommonErrors::bad_request(&self.to_string())
            }
            ProxyError(proxy_err) => Self::proxy_error_response(&proxy_err),
        }
    }

    fn proxy_error_response(proxy_err: &ProxyError) -> ApiResponse {
        match proxy_err {
            ProxyError::ValidationStructured(validation_errors) => {
                let detailed_errors: HashMap<String, Vec<String>> = validation_errors
                    .field_errors()
                    .iter()
                    .map(|(field, errors)| {
                        (
                            field.to_string(),
                            errors.iter().map(|e| e.to_string()).collect(),
                        )
                    })
                    .collect();

                let response_body = serde_json::json!({
                    "error": "Validation failed",
                    "details": detailed_errors
                });

                Response::builder()
                    .status(400)
                    .header("Content-Type", "application/json")
                    .body(response_body.to_string().into_bytes())
                    .expect("Failed to build HTTP error response")
            }
            ProxyError::Validation(_) | ProxyError::Configuration(_) => {
                CommonErrors::bad_request(&proxy_err.to_string())
            }
            ProxyError::Etcd(_) => {
                // Do not echo etcd endpoints/keys in client responses.
                log::error!("Admin etcd error: {proxy_err}");
                CommonErrors::internal_server_error("Backend configuration store unavailable")
            }
            ProxyError::CasConflict(_) => {
                ResponseBuilder::error_http(StatusCode::CONFLICT, &proxy_err.to_string())
            }
            _ => {
                log::error!("Admin internal error: {proxy_err}");
                CommonErrors::internal_server_error("Internal server error")
            }
        }
    }
}

type ApiResult<T> = Result<T, ApiError>;
type ApiResponse = Response<Vec<u8>>;
type RequestParams = BTreeMap<String, String>;

// Maximum request body size for admin API (1 MB)
const MAX_BODY_SIZE: usize = 1_048_576;

/// Resource handling trait for simplified validation logic across admin APIs.
///
/// This trait provides a unified interface for validating and processing configuration
/// resources (routes, services, upstreams, etc.) through the admin API. It combines
/// JSON deserialization, field validation, and plugin-specific validation in a single step.
trait AdminResource: DeserializeOwned + Validate + Identifiable + Send + Sync + 'static {
    const RESOURCE_TYPE: &'static str;

    fn validate_resource(data: &[u8]) -> ApiResult<Self> {
        let resource = json_to_resource::<Self>(data)?;

        // Basic field validation using the validator crate
        resource
            .validate()
            .map_err(|e| ApiError::ProxyError(ProxyError::ValidationStructured(e)))?;

        // Additional plugin-specific validation if applicable
        Self::validate_plugins_if_supported(&resource)?;

        Ok(resource)
    }

    fn validate_plugins_if_supported(_resource: &Self) -> ApiResult<()> {
        // Default: no plugin validation needed
        Ok(())
    }
}

// Implement AdminResource for all supported configuration types
fn validate_plugins(plugins: &HashMap<String, serde_json::Value>) -> ApiResult<()> {
    for (name, value) in plugins {
        if name == "traffic-split" {
            // Do not resolve named upstreams against the live runtime; Candidate publish owns that.
            traffic_split::validate_traffic_split_config(value).map_err(|e| {
                ApiError::ValidationError(format!("Failed to validate plugin '{name}': {e}"))
            })?;
            continue;
        }
        build_plugin(name, value.clone()).map_err(|e| {
            ApiError::ValidationError(format!("Failed to build plugin '{name}': {e}"))
        })?;
    }
    Ok(())
}

impl AdminResource for config::Route {
    const RESOURCE_TYPE: &'static str = "routes";

    fn validate_plugins_if_supported(resource: &Self) -> ApiResult<()> {
        validate_plugins(&resource.plugins)
    }
}

impl AdminResource for config::Upstream {
    const RESOURCE_TYPE: &'static str = "upstreams";
}

impl AdminResource for config::Service {
    const RESOURCE_TYPE: &'static str = "services";

    fn validate_plugins_if_supported(resource: &Self) -> ApiResult<()> {
        validate_plugins(&resource.plugins)
    }
}

impl AdminResource for config::GlobalRule {
    const RESOURCE_TYPE: &'static str = "global_rules";

    fn validate_plugins_if_supported(resource: &Self) -> ApiResult<()> {
        validate_plugins(&resource.plugins)
    }
}

impl AdminResource for config::SSL {
    const RESOURCE_TYPE: &'static str = "ssls";

    fn validate_plugins_if_supported(resource: &Self) -> ApiResult<()> {
        ProxySSL::try_from(resource.clone())
            .map_err(|e| ApiError::ValidationError(format!("Invalid SSL certificate/key: {e}")))?;
        Ok(())
    }
}

macro_rules! admin_handler {
    ($name:ident) => {
        struct $name<T: AdminResource> {
            _phantom: PhantomData<T>,
        }
        impl<T: AdminResource> $name<T> {
            fn new() -> Self {
                Self {
                    _phantom: PhantomData,
                }
            }
        }
    };
}

admin_handler!(ResourceHandler);
admin_handler!(GetHandler);
admin_handler!(DeleteHandler);
admin_handler!(ListHandler);

impl<T: AdminResource> ResourceHandler<T> {
    fn extract_key(params: &RequestParams) -> ApiResult<String> {
        let id = params
            .get("id")
            .ok_or_else(|| ApiError::MissingParameter("id".into()))?;

        Ok(format!("{}/{}", T::RESOURCE_TYPE, id))
    }
}

#[async_trait]
trait Handler {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse>;
}

// PUT handler
#[async_trait]
impl<T: AdminResource> Handler for ResourceHandler<T> {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        http_session.validate_content_type()?;

        let body_data = read_request_body(http_session)
            .await
            .map_err(|e| ApiError::RequestBodyReadError(e.to_string()))?;

        let key = Self::extract_key(&params)?;

        // Use generic resource validation
        T::validate_resource(&body_data)?;

        let committed = graph_mutation::put_resource(etcd, &key, body_data).await?;

        let body = serde_json::json!({ "revision": committed });
        Ok(ResponseBuilder::success_json(&body))
    }
}

// GET handler - separate type needed to distinguish operation types
#[async_trait]
impl<T: AdminResource> Handler for GetHandler<T> {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let key = ResourceHandler::<T>::extract_key(&params)?;

        match etcd.get(&key).await {
            Err(e) => Err(ApiError::EtcdGetError(e.to_string())),
            Ok(Some(value)) => {
                let json_value: serde_json::Value =
                    serde_json::from_slice(&value).map_err(|e| {
                        ApiError::ProxyError(ProxyError::serialization_error(
                            "Failed to parse JSON",
                            e,
                        ))
                    })?;
                let wrapper = ValueWrapper {
                    value: redact(T::RESOURCE_TYPE, json_value),
                };
                Ok(ResponseBuilder::success_json(&wrapper))
            }
            Ok(None) => Err(ApiError::NotFound("Resource not found".into())),
        }
    }
}

// DELETE handler
#[async_trait]
impl<T: AdminResource> Handler for DeleteHandler<T> {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let key = ResourceHandler::<T>::extract_key(&params)?;

        graph_mutation::delete_resource(etcd, &key).await?;

        Ok(ResponseBuilder::success_http(Vec::new(), None))
    }
}

// LIST handler
#[async_trait]
impl<T: AdminResource> Handler for ListHandler<T> {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        _params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let response = etcd.list(T::RESOURCE_TYPE).await?;

        let mut list_items = Vec::new();
        for kv in response.kvs() {
            let key = String::from_utf8_lossy(kv.key()).to_string();
            let value: serde_json::Value = serde_json::from_slice(kv.value()).map_err(|e| {
                ApiError::ProxyError(ProxyError::serialization_error(
                    "Failed to parse resource JSON",
                    e,
                ))
            })?;

            let item = serde_json::json!({
                "key": key,
                "value": redact(T::RESOURCE_TYPE, value),
                "createdIndex": kv.create_revision(),
                "modifiedIndex": kv.mod_revision(),
            });

            list_items.push(item);
        }

        let result = serde_json::json!({
            "total": list_items.len(),
            "list": list_items,
        });

        Ok(ResponseBuilder::success_json(&result))
    }
}

#[derive(Serialize, Deserialize)]
struct ValueWrapper<T> {
    value: T,
}

type HttpHandler = Box<dyn Handler + Send + Sync>;

pub struct AdminHttpApp {
    config: Admin,
    etcd: EtcdClientWrapper,
    router: Router<HashMap<Method, HttpHandler>>,
}

impl AdminHttpApp {
    pub fn new(cfg: &Pingsix) -> Self {
        let mut this = Self {
            config: cfg.admin.clone().expect("Admin config must be present"),
            etcd: EtcdClientWrapper::new(cfg.etcd.clone().expect("Etcd config must be present")),
            router: Router::new(),
        };

        // Register routes with type safety and reduced boilerplate
        this.register_resource_routes::<config::Route>()
            .register_resource_routes::<config::Upstream>()
            .register_resource_routes::<config::Service>()
            .register_resource_routes::<config::GlobalRule>()
            .register_resource_routes::<config::SSL>();

        this
    }

    fn register_resource_routes<T: AdminResource>(&mut self) -> &mut Self {
        let path = format!("/apisix/admin/{}/{{id}}", T::RESOURCE_TYPE);
        let list_path = format!("/apisix/admin/{}", T::RESOURCE_TYPE);

        self.route(&path, Method::PUT, Box::new(ResourceHandler::<T>::new()))
            .route(&path, Method::GET, Box::new(GetHandler::<T>::new()))
            .route(&path, Method::DELETE, Box::new(DeleteHandler::<T>::new()))
            .route(&list_path, Method::GET, Box::new(ListHandler::<T>::new()));

        self
    }

    fn route(&mut self, path: &str, method: Method, handler: HttpHandler) -> &mut Self {
        if self.router.at(path).is_err() {
            let mut handlers = HashMap::new();
            handlers.insert(method, handler);
            if let Err(e) = self.router.insert(path, handlers) {
                log::error!("Failed to insert admin route '{path}': {e}");
            }
        } else if let Ok(routes) = self.router.at_mut(path) {
            routes.value.insert(method, handler);
        } else {
            log::error!("Failed to get mutable route for path '{path}'");
        }
        self
    }

    pub fn admin_http_service(cfg: &Pingsix) -> Service<Self> {
        let app = Self::new(cfg);
        let addr = &app.config.address.to_string();
        let mut service = Service::new("Admin HTTP".to_string(), app);
        service.add_tcp(addr);
        service
    }
}

#[async_trait]
impl ServeHttp for AdminHttpApp {
    async fn response(&self, http_session: &mut ServerSession) -> ApiResponse {
        http_session.set_keepalive(None);

        if http_session.validate_api_key(&self.config.api_key).is_err() {
            return CommonErrors::forbidden("Invalid API key");
        }

        let (path, method) = {
            let req_header = http_session.req_header();
            (req_header.uri.path().to_string(), req_header.method.clone())
        };

        match self.router.at(&path) {
            Ok(Match { value, params }) => match value.get(&method) {
                Some(handler) => {
                    let params: RequestParams = params
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    match handler.handle(&self.etcd, http_session, params).await {
                        Ok(resp) => resp,
                        Err(e) => e.into_response(),
                    }
                }
                None => ResponseBuilder::error_http(
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Method not allowed",
                ),
            },
            Err(_) => ResponseBuilder::error_http(StatusCode::NOT_FOUND, "Not Found"),
        }
    }
}

trait AdminSessionExt {
    fn validate_api_key(&self, api_key: &str) -> ApiResult<()>;
    fn validate_content_type(&self) -> ApiResult<()>;
}

impl AdminSessionExt for ServerSession {
    fn validate_api_key(&self, api_key: &str) -> ApiResult<()> {
        if api_key.trim().is_empty() {
            return Err(ApiError::InvalidRequest(
                "Must provide valid API key".into(),
            ));
        }

        let provided_key = self
            .get_header("x-api-key")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");

        if !provided_key.is_empty() && constant_time_eq(provided_key, api_key) {
            Ok(())
        } else {
            Err(ApiError::InvalidRequest(
                "Must provide valid API key".into(),
            ))
        }
    }

    fn validate_content_type(&self) -> ApiResult<()> {
        match self.get_header(header::CONTENT_TYPE) {
            Some(content_type) => {
                let ct_str = content_type.to_str().unwrap_or("");
                if is_json_content_type(ct_str) {
                    Ok(())
                } else {
                    Err(ApiError::InvalidRequest(
                        "Content-Type must be application/json".into(),
                    ))
                }
            }
            None => Err(ApiError::InvalidRequest(
                "Content-Type header is required".into(),
            )),
        }
    }
}

fn is_json_content_type(ct_str: &str) -> bool {
    ct_str
        .split(';')
        .next()
        .map(str::trim)
        .is_some_and(|media_type| media_type.eq_ignore_ascii_case("application/json"))
}

async fn read_request_body(http_session: &mut ServerSession) -> Result<Vec<u8>, ApiError> {
    let mut body_data = Vec::with_capacity(1024); // Initial capacity
    while let Some(bytes) = http_session
        .read_request_body()
        .await
        .map_err(|e| ApiError::RequestBodyReadError(e.to_string()))?
    {
        // Check if the cumulative size exceeds the limit
        if body_data.len() + bytes.len() > MAX_BODY_SIZE {
            return Err(ApiError::InvalidRequest("Request body too large".into()));
        }
        body_data.extend_from_slice(&bytes);
    }
    Ok(body_data)
}

/// Recursively redact sensitive fields in a JSON value.
///
/// Redaction is path/type-aware to avoid clobbering non-secret fields that
/// happen to share a name with a secret elsewhere (e.g. an Upstream's
/// `hash_on` `key`, whose value is something like `"uri"`). Sensitivity is
/// decided by `resource_type` plus the structural position of the field:
///
/// - `ssls`: top-level `key` (the private key) is redacted.
/// - `upstreams`: the `tls.client_key` field is redacted; the top-level `key`
///   (a `hash_on` selector) is left intact.
/// - `routes`/`services`/`global_rules`: inside a `plugins` object, the
///   plugin-specific credential fields are redacted:
///   `jwt-auth.secret`, `basic-auth.password`, `key-auth.keys[]`, `csrf.key`.
///
/// `in_upstream_tls` is set when the current object is an upstream's `tls`
/// object. `plugin_name` is `Some(name)` when the current object is a single
/// plugin's config inside a `plugins` map.
pub(crate) fn redact(resource_type: &str, value: serde_json::Value) -> serde_json::Value {
    redact_value(value, resource_type, false, None)
}

fn redact_value(
    value: serde_json::Value,
    resource_type: &str,
    in_upstream_tls: bool,
    plugin_name: Option<&str>,
) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (name, v) in map {
                let redacted = if in_upstream_tls && name == "client_key" {
                    redact_string(v)
                } else if let Some(plugin) = plugin_name {
                    match (plugin, name.as_str()) {
                        ("jwt-auth", "secret")
                        | ("basic-auth", "password")
                        | ("csrf", "key")
                        | ("key-auth", "key") => redact_string(v),
                        ("key-auth", "keys") => redact_keys_array(v),
                        _ => redact_value(v, resource_type, false, None),
                    }
                } else if resource_type == "ssls" && name == "key" {
                    redact_string(v)
                } else if name == "tls" {
                    redact_value(v, resource_type, true, None)
                } else if name == "plugins" {
                    redact_plugins(v, resource_type)
                } else {
                    redact_value(v, resource_type, false, None)
                };
                out.insert(name, redacted);
            }
            serde_json::Value::Object(out)
        }
        serde_json::Value::Array(arr) => serde_json::Value::Array(
            arr.into_iter()
                .map(|el| redact_value(el, resource_type, false, None))
                .collect(),
        ),
        other => other,
    }
}

/// Redact a `plugins` object whose keys are plugin names and whose values are
/// each plugin's config. Each plugin config is recursed with its name as
/// context so only plugin-specific credential fields are redacted.
fn redact_plugins(value: serde_json::Value, resource_type: &str) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (plugin_name, v) in map {
                let redacted = redact_value(v, resource_type, false, Some(plugin_name.as_str()));
                out.insert(plugin_name, redacted);
            }
            serde_json::Value::Object(out)
        }
        other => other,
    }
}

fn redact_string(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::String(_) => serde_json::Value::String("***".into()),
        other => other,
    }
}

fn redact_keys_array(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.into_iter().map(redact_string).collect())
        }
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn content_type_accepts_json_with_charset() {
        assert!(is_json_content_type("application/json"));
        assert!(is_json_content_type("application/json; charset=utf-8"));
        assert!(is_json_content_type("Application/JSON;charset=UTF-8"));
    }

    #[test]
    fn content_type_rejects_near_misses() {
        assert!(!is_json_content_type("application/json-malformed"));
        assert!(!is_json_content_type("text/json"));
        assert!(!is_json_content_type(""));
    }

    #[test]
    fn empty_api_key_config_is_rejected_by_validator() {
        use validator::Validate;
        let admin = config::Admin {
            address: "127.0.0.1:9181".parse().unwrap(),
            api_key: "   ".into(),
            allow_insecure_remote: false,
        };
        assert!(admin.validate().is_err());
    }

    #[test]
    fn redact_ssl_key() {
        let input = serde_json::json!({
            "cert": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
            "key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
        });
        let out = redact("ssls", input);
        assert_eq!(
            out["cert"],
            "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----"
        );
        assert_eq!(out["key"], "***");
    }

    #[test]
    fn redact_jwt_secret() {
        let input = serde_json::json!({
            "plugins": { "jwt-auth": { "secret": "abc" } },
        });
        let out = redact("routes", input);
        assert_eq!(out["plugins"]["jwt-auth"]["secret"], "***");
    }

    #[test]
    fn redact_basic_auth_password() {
        let input = serde_json::json!({
            "plugins": { "basic-auth": { "username": "u", "password": "p" } },
        });
        let out = redact("routes", input);
        assert_eq!(out["plugins"]["basic-auth"]["username"], "u");
        assert_eq!(out["plugins"]["basic-auth"]["password"], "***");
    }

    #[test]
    fn redact_key_auth_keys() {
        let input = serde_json::json!({
            "plugins": { "key-auth": { "key": "k0", "keys": ["k1", "k2"] } },
        });
        let out = redact("routes", input);
        assert_eq!(out["plugins"]["key-auth"]["key"], "***");
        assert_eq!(
            out["plugins"]["key-auth"]["keys"],
            serde_json::json!(["***", "***"])
        );
    }

    #[test]
    fn redact_csrf_key() {
        let input = serde_json::json!({
            "plugins": { "csrf": { "key": "secret-csrf" } },
        });
        let out = redact("global_rules", input);
        assert_eq!(out["plugins"]["csrf"]["key"], "***");
    }

    #[test]
    fn redact_nested_upstream_tls() {
        let input = serde_json::json!({
            "upstream": {
                "tls": {
                    "client_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
                    "client_cert": "cert-data",
                }
            }
        });
        for resource_type in ["routes", "services", "global_rules"] {
            let out = redact(resource_type, input.clone());
            assert_eq!(out["upstream"]["tls"]["client_key"], "***");
            assert_eq!(out["upstream"]["tls"]["client_cert"], "cert-data");
        }
    }

    #[test]
    fn redact_preserves_upstream_hash_on_key() {
        // An Upstream's top-level `key` is a hash_on selector (e.g. "uri"),
        // NOT a secret. It must survive redaction unchanged.
        let input = serde_json::json!({
            "key": "uri",
            "type": "roundrobin",
        });
        let out = redact("upstreams", input);
        assert_eq!(out["key"], "uri");
        assert_eq!(out["type"], "roundrobin");
    }

    #[test]
    fn redact_redacts_upstream_tls_client_key() {
        let input = serde_json::json!({
            "key": "uri",
            "type": "roundrobin",
            "tls": {
                "client_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
                "client_cert": "cert-data",
            },
        });
        let out = redact("upstreams", input);
        assert_eq!(out["key"], "uri");
        assert_eq!(out["tls"]["client_key"], "***");
        assert_eq!(out["tls"]["client_cert"], "cert-data");
    }

    #[test]
    fn redact_non_sensitive_unchanged() {
        let input = serde_json::json!({
            "id": "r1",
            "uri": "/x",
            "methods": ["GET"],
            "upstream_id": "u1",
        });
        let out = redact("routes", input.clone());
        assert_eq!(out, input);
    }

    #[test]
    fn not_found_maps_to_404() {
        let resp = ApiError::NotFound("Resource not found".into()).into_response();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn conflict_maps_to_409() {
        let resp = ApiError::Conflict("resource is referenced".into()).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn cas_conflict_proxy_error_maps_to_409() {
        let resp =
            ApiError::from(ProxyError::CasConflict("mod_revision mismatch".into())).into_response();
        assert_eq!(resp.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn candidate_build_rejects_dangling_upstream_id() {
        use crate::proxy::control_plane::{CandidateSnapshot, ResourceConfigSet};
        use crate::proxy::runtime::RUNTIME_TEST_LOCK;

        let _guard = RUNTIME_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let mut set = ResourceConfigSet::default();
        set.routes.insert(
            "r1".into(),
            crate::config::Route {
                id: "r1".into(),
                uri: Some("/".into()),
                uris: vec![],
                methods: vec![],
                host: None,
                hosts: vec![],
                priority: 0,
                plugins: Default::default(),
                upstream: None,
                upstream_id: Some("missing".into()),
                service_id: None,
                timeout: None,
            },
        );
        assert!(CandidateSnapshot::build(set).is_err());
    }
}

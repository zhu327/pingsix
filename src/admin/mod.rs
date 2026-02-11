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
    plugins::build_plugin,
    utils::response::{CommonErrors, ResponseBuilder},
};

#[derive(Debug)]
enum ApiError {
    EtcdGetError(String),
    ValidationError(String),
    MissingParameter(String),
    InvalidRequest(String),
    RequestBodyReadError(String),
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

impl ApiError {
    fn into_response(self) -> ApiResponse {
        match self {
            ApiError::EtcdGetError(_) | ApiError::RequestBodyReadError(_) => {
                CommonErrors::internal_server_error(&self.to_string())
            }
            ApiError::ValidationError(_)
            | ApiError::MissingParameter(_)
            | ApiError::InvalidRequest(_) => CommonErrors::bad_request(&self.to_string()),
            ApiError::ProxyError(proxy_err) => {
                // Handle different ProxyError types appropriately
                match &proxy_err {
                    ProxyError::ValidationStructured(validation_errors) => {
                        // For structured validation errors, we can provide detailed field-level errors
                        let detailed_errors: std::collections::HashMap<String, Vec<String>> =
                            validation_errors
                                .field_errors()
                                .iter()
                                .map(|(field, errors)| {
                                    let error_messages: Vec<String> =
                                        errors.iter().map(|e| e.to_string()).collect();
                                    (field.to_string(), error_messages)
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
                    _ => {
                        // For other errors, treat as internal server error
                        CommonErrors::internal_server_error(&proxy_err.to_string())
                    }
                }
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
impl AdminResource for config::Route {
    const RESOURCE_TYPE: &'static str = "routes";

    fn validate_plugins_if_supported(resource: &Self) -> ApiResult<()> {
        for (name, value) in &resource.plugins {
            build_plugin(name, value.clone()).map_err(|e| {
                ApiError::ValidationError(format!("Failed to build plugin '{name}': {e}"))
            })?;
        }
        Ok(())
    }
}

impl AdminResource for config::Upstream {
    const RESOURCE_TYPE: &'static str = "upstreams";
}

impl AdminResource for config::Service {
    const RESOURCE_TYPE: &'static str = "services";

    fn validate_plugins_if_supported(resource: &Self) -> ApiResult<()> {
        for (name, value) in &resource.plugins {
            build_plugin(name, value.clone()).map_err(|e| {
                ApiError::ValidationError(format!("Failed to build plugin '{name}': {e}"))
            })?;
        }
        Ok(())
    }
}

impl AdminResource for config::GlobalRule {
    const RESOURCE_TYPE: &'static str = "global_rules";

    fn validate_plugins_if_supported(resource: &Self) -> ApiResult<()> {
        for (name, value) in &resource.plugins {
            build_plugin(name, value.clone()).map_err(|e| {
                ApiError::ValidationError(format!("Failed to build plugin '{name}': {e}"))
            })?;
        }
        Ok(())
    }
}

impl AdminResource for config::SSL {
    const RESOURCE_TYPE: &'static str = "ssls";
}

// Generic handler that significantly reduces code duplication
struct ResourceHandler<T: AdminResource> {
    _phantom: PhantomData<T>,
}

impl<T: AdminResource> ResourceHandler<T> {
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

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
        validate_content_type(http_session)?;

        let body_data = read_request_body(http_session)
            .await
            .map_err(|e| ApiError::RequestBodyReadError(e.to_string()))?;

        let key = Self::extract_key(&params)?;

        // Use generic resource validation
        T::validate_resource(&body_data)?;

        etcd.put(&key, body_data).await?;

        Ok(ResponseBuilder::success_http(Vec::new(), None))
    }
}

// GET handler - separate type needed to distinguish operation types
struct GetHandler<T: AdminResource> {
    _phantom: PhantomData<T>,
}

impl<T: AdminResource> GetHandler<T> {
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

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
                let wrapper = ValueWrapper { value: json_value };
                Ok(ResponseBuilder::success_json(&wrapper))
            }
            Ok(None) => Err(ApiError::InvalidRequest("Resource not found".into())),
        }
    }
}

// DELETE handler
struct DeleteHandler<T: AdminResource> {
    _phantom: PhantomData<T>,
}

impl<T: AdminResource> DeleteHandler<T> {
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<T: AdminResource> Handler for DeleteHandler<T> {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<ApiResponse> {
        let key = ResourceHandler::<T>::extract_key(&params)?;

        etcd.delete(&key).await?;

        Ok(ResponseBuilder::success_http(Vec::new(), None))
    }
}

// LIST handler
struct ListHandler<T: AdminResource> {
    _phantom: PhantomData<T>,
}

impl<T: AdminResource> ListHandler<T> {
    fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

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
                "value": value,
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

        if validate_api_key(http_session, &self.config.api_key).is_err() {
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

fn validate_api_key(http_session: &ServerSession, api_key: &str) -> ApiResult<()> {
    // Defense-in-depth: reject misconfigured empty API keys even if validation was bypassed.
    if api_key.trim().is_empty() {
        return Err(ApiError::InvalidRequest(
            "Must provide valid API key".into(),
        ));
    }

    let provided_key = http_session
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

fn validate_content_type(http_session: &ServerSession) -> ApiResult<()> {
    match http_session.get_header(header::CONTENT_TYPE) {
        Some(content_type) => {
            let ct_str = content_type.to_str().unwrap_or("");
            // Accept application/json with or without charset parameters
            if ct_str.starts_with("application/json") {
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

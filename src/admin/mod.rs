use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
};

use async_trait::async_trait;
use http::{header, HeaderValue, Method, Response, StatusCode};
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
        Admin, Pingsix,
    },
    plugin::build_plugin,
};

#[derive(Debug)]
enum ApiError {
    EtcdGetError(String),
    EtcdPutError(String),
    EtcdDeleteError(String),
    ValidationError(String),
    MissingParameter(String),
    InvalidRequest(String),
    InternalError(String),
    RequestBodyReadError(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::EtcdGetError(msg) => write!(f, "Etcd get error: {}", msg),
            ApiError::EtcdPutError(msg) => write!(f, "Etcd put error: {}", msg),
            ApiError::EtcdDeleteError(msg) => write!(f, "Etcd delete error: {}", msg),
            ApiError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            ApiError::MissingParameter(msg) => write!(f, "Missing parameter: {}", msg),
            ApiError::InvalidRequest(msg) => write!(f, "Invalid request: {}", msg),
            ApiError::InternalError(msg) => write!(f, "Internal error: {}", msg),
            ApiError::RequestBodyReadError(msg) => write!(f, "Request body read error: {}", msg),
        }
    }
}

impl Error for ApiError {}

impl ApiError {
    fn into_response(self) -> Response<Vec<u8>> {
        match self {
            ApiError::EtcdGetError(_)
            | ApiError::EtcdPutError(_)
            | ApiError::EtcdDeleteError(_)
            | ApiError::InternalError(_)
            | ApiError::RequestBodyReadError(_) => {
                ResponseHelper::error(StatusCode::INTERNAL_SERVER_ERROR, &self.to_string())
            }
            ApiError::ValidationError(_)
            | ApiError::MissingParameter(_)
            | ApiError::InvalidRequest(_) => {
                ResponseHelper::error(StatusCode::BAD_REQUEST, &self.to_string())
            }
        }
    }
}

type ApiResult<T> = Result<T, ApiError>;
type RequestParams = BTreeMap<String, String>;
type HttpHandler = Box<dyn Handler + Send + Sync>;

// Unified response handler
struct ResponseHelper;

impl ResponseHelper {
    pub fn success(body: Vec<u8>, content_type: Option<&str>) -> Response<Vec<u8>> {
        let mut builder = Response::builder().status(StatusCode::OK);

        if let Some(ct) = content_type {
            match HeaderValue::from_str(ct) {
                Ok(header_value) => {
                    builder = builder.header(header::CONTENT_TYPE, header_value);
                }
                Err(e) => {
                    log::error!("Invalid content type '{}': {}", ct, e);
                }
            }
        }

        builder.body(body).unwrap_or_else(|e| {
            log::error!("Failed to build success response: {}", e);
            Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(b"Internal Server Error".to_vec())
                .unwrap()
        })
    }

    pub fn error(status: StatusCode, message: &str) -> Response<Vec<u8>> {
        Response::builder()
            .status(status)
            .body(message.as_bytes().to_vec())
            .unwrap_or_else(|e| {
                log::error!("Failed to build error response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(b"Internal Server Error".to_vec())
                    .unwrap()
            })
    }
}

#[async_trait]
trait Handler {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<Response<Vec<u8>>>;
}

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

        this.route(
            "/apisix/admin/{resource}/{id}",
            Method::PUT,
            Box::new(ResourcePutHandler {}),
        )
        .route(
            "/apisix/admin/{resource}/{id}",
            Method::GET,
            Box::new(ResourceGetHandler {}),
        )
        .route(
            "/apisix/admin/{resource}/{id}",
            Method::DELETE,
            Box::new(ResourceDeleteHandler {}),
        );

        this
    }

    fn route(&mut self, path: &str, method: Method, handler: HttpHandler) -> &mut Self {
        if self.router.at(path).is_err() {
            let mut handlers = HashMap::new();
            handlers.insert(method, handler);
            self.router
                .insert(path, handlers)
                .expect("Route insertion should not fail");
        } else {
            let routes = self
                .router
                .at_mut(path)
                .expect("Route should exist after check");
            routes.value.insert(method, handler);
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
    async fn response(&self, http_session: &mut ServerSession) -> Response<Vec<u8>> {
        http_session.set_keepalive(None);

        if validate_api_key(http_session, &self.config.api_key).is_err() {
            return ResponseHelper::error(StatusCode::FORBIDDEN, "Invalid API key");
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
                None => ResponseHelper::error(StatusCode::METHOD_NOT_ALLOWED, "Method not allowed"),
            },
            Err(_) => ResponseHelper::error(StatusCode::NOT_FOUND, "Not Found"),
        }
    }
}

struct ResourcePutHandler;

#[async_trait]
impl Handler for ResourcePutHandler {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<Response<Vec<u8>>> {
        validate_content_type(http_session)?;

        let body_data = read_request_body(http_session)
            .await
            .map_err(|e| ApiError::RequestBodyReadError(e.to_string()))?;
        let resource_type = params
            .get("resource")
            .ok_or_else(|| ApiError::MissingParameter("resource".into()))?;
        let key = format!(
            "{}/{}",
            resource_type,
            params
                .get("id")
                .ok_or_else(|| ApiError::MissingParameter("id".into()))?
        );

        validate_resource(resource_type, &body_data)?;
        etcd.put(&key, body_data)
            .await
            .map_err(|e| ApiError::EtcdPutError(e.to_string()))?;
        Ok(ResponseHelper::success(Vec::new(), None))
    }
}

#[derive(Serialize, Deserialize)]
struct ValueWrapper<T> {
    value: T,
}

struct ResourceGetHandler;

#[async_trait]
impl Handler for ResourceGetHandler {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<Response<Vec<u8>>> {
        let resource_type = params
            .get("resource")
            .ok_or_else(|| ApiError::MissingParameter("resource".into()))?;
        let key = format!(
            "{}/{}",
            resource_type,
            params
                .get("id")
                .ok_or_else(|| ApiError::MissingParameter("id".into()))?
        );

        match etcd.get(&key).await {
            Err(e) => Err(ApiError::EtcdGetError(e.to_string())),
            Ok(Some(value)) => {
                let json_value: serde_json::Value = serde_json::from_slice(&value)
                    .map_err(|e| ApiError::InvalidRequest(format!("Invalid JSON data: {}", e)))?;
                let wrapper = ValueWrapper { value: json_value };
                let json_vec = serde_json::to_vec(&wrapper)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?;
                Ok(ResponseHelper::success(json_vec, Some("application/json")))
            }
            Ok(None) => Err(ApiError::InvalidRequest("Resource not found".into())),
        }
    }
}

struct ResourceDeleteHandler;

#[async_trait]
impl Handler for ResourceDeleteHandler {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        params: RequestParams,
    ) -> ApiResult<Response<Vec<u8>>> {
        let key = format!(
            "{}/{}",
            params
                .get("resource")
                .ok_or_else(|| ApiError::MissingParameter("resource".into()))?,
            params
                .get("id")
                .ok_or_else(|| ApiError::MissingParameter("id".into()))?
        );

        etcd.delete(&key)
            .await
            .map_err(|e| ApiError::EtcdDeleteError(e.to_string()))?;
        Ok(ResponseHelper::success(Vec::new(), None))
    }
}

fn validate_api_key(http_session: &ServerSession, api_key: &str) -> ApiResult<()> {
    match http_session.get_header("x-api-key") {
        Some(key) if key.as_bytes() == api_key.as_bytes() => Ok(()),
        _ => Err(ApiError::InvalidRequest(
            "Must provide valid API key".into(),
        )),
    }
}

fn validate_content_type(http_session: &ServerSession) -> ApiResult<()> {
    match http_session.get_header(header::CONTENT_TYPE) {
        Some(content_type) if content_type.as_bytes() == b"application/json" => Ok(()),
        _ => Err(ApiError::InvalidRequest(
            "Content-Type must be application/json".into(),
        )),
    }
}

async fn read_request_body(http_session: &mut ServerSession) -> Result<Vec<u8>, ApiError> {
    let mut body_data = Vec::new();
    while let Some(bytes) = http_session
        .read_request_body()
        .await
        .map_err(|e| ApiError::RequestBodyReadError(e.to_string()))?
    {
        body_data.extend_from_slice(&bytes);
    }
    Ok(body_data)
}

fn validate_resource(resource_type: &str, body_data: &[u8]) -> ApiResult<()> {
    match resource_type {
        "routes" => {
            let route = validate_with_plugins::<config::Route>(body_data)?;
            route
                .validate()
                .map_err(|e| ApiError::ValidationError(format!("Route validation failed: {}", e)))
        }
        "upstreams" => {
            let upstream = json_to_resource::<config::Upstream>(body_data).map_err(|e| {
                ApiError::InvalidRequest(format!("Invalid upstream JSON data: {}", e))
            })?;
            upstream.validate().map_err(|e| {
                ApiError::ValidationError(format!("Upstream validation failed: {}", e))
            })
        }
        "services" => {
            let service = validate_with_plugins::<config::Service>(body_data)?;
            service
                .validate()
                .map_err(|e| ApiError::ValidationError(format!("Service validation failed: {}", e)))
        }
        "global_rules" => {
            let rule = validate_with_plugins::<config::GlobalRule>(body_data)?;
            rule.validate().map_err(|e| {
                ApiError::ValidationError(format!("GlobalRule validation failed: {}", e))
            })
        }
        "ssls" => {
            let ssl = json_to_resource::<config::SSL>(body_data)
                .map_err(|e| ApiError::InvalidRequest(format!("Invalid SSL JSON data: {}", e)))?;
            ssl.validate()
                .map_err(|e| ApiError::ValidationError(format!("SSL validation failed: {}", e)))
        }
        _ => Err(ApiError::InvalidRequest(format!(
            "Unsupported resource type: {}",
            resource_type
        ))),
    }
}

fn validate_with_plugins<T: PluginValidatable + DeserializeOwned>(
    body_data: &[u8],
) -> ApiResult<T> {
    let resource = json_to_resource::<T>(body_data)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid JSON data for resource: {}", e)))?;
    resource
        .validate_plugins()
        .map_err(|e| ApiError::ValidationError(format!("Plugin validation failed: {}", e)))?;
    Ok(resource)
}

trait PluginValidatable {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>>;
}

impl PluginValidatable for config::Route {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>> {
        for (name, value) in &self.plugins {
            build_plugin(name, value.clone())
                .map_err(|e| format!("Failed to build plugin '{}': {}", name, e))?;
        }
        Ok(())
    }
}

impl PluginValidatable for config::Service {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>> {
        for (name, value) in &self.plugins {
            build_plugin(name, value.clone())
                .map_err(|e| format!("Failed to build plugin '{}': {}", name, e))?;
        }
        Ok(())
    }
}

impl PluginValidatable for config::GlobalRule {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>> {
        for (name, value) in &self.plugins {
            build_plugin(name, value.clone())
                .map_err(|e| format!("Failed to build plugin '{}': {}", name, e))?;
        }
        Ok(())
    }
}

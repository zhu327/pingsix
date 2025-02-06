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
    proxy::plugin::build_plugin,
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
        }
    }
}

impl Error for ApiError {}

impl From<ApiError> for Response<Vec<u8>> {
    fn from(error: ApiError) -> Self {
        match error {
            // ... 匹配不同的错误类型，返回不同的状态码和错误信息
            ApiError::EtcdGetError(_)
            | ApiError::EtcdPutError(_)
            | ApiError::EtcdDeleteError(_)
            | ApiError::InternalError(_) => {
                ResponseHelper::error(StatusCode::INTERNAL_SERVER_ERROR, &error.to_string())
            }
            ApiError::ValidationError(_)
            | ApiError::MissingParameter(_)
            | ApiError::InvalidRequest(_) => {
                ResponseHelper::error(StatusCode::BAD_REQUEST, &error.to_string())
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
            if let Ok(header_value) = HeaderValue::from_str(ct) {
                builder = builder.header(header::CONTENT_TYPE, header_value);
            } else {
                // 如果 content_type 无法转换为 HeaderValue，可以选择日志记录或忽略
                log::error!("Invalid content type: {}", ct);
            }
        }

        builder.body(body).unwrap()
    }

    pub fn error(status: StatusCode, message: &str) -> Response<Vec<u8>> {
        Response::builder()
            .status(status)
            .body(message.as_bytes().to_vec())
            .unwrap()
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
            config: cfg.admin.clone().unwrap(),
            etcd: EtcdClientWrapper::new(cfg.etcd.clone().unwrap()),
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
            self.router.insert(path, handlers).unwrap();
        } else {
            let routes = self.router.at_mut(path).unwrap();
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
                        Err(e) => e.into(),
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

        let body_data = read_request_body(http_session).await?;
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
        Some(key) if key.to_str().unwrap_or("") == api_key => Ok(()),
        _ => Err(ApiError::InvalidRequest("Must provide API key".into())),
    }
}

fn validate_content_type(http_session: &ServerSession) -> ApiResult<()> {
    match http_session.get_header(header::CONTENT_TYPE) {
        Some(content_type) if content_type.to_str().unwrap_or("") == "application/json" => Ok(()),
        _ => Err(ApiError::InvalidRequest(
            "Content-Type must be application/json".into(),
        )),
    }
}

async fn read_request_body(http_session: &mut ServerSession) -> ApiResult<Vec<u8>> {
    let mut body_data = Vec::new();
    while let Some(bytes) = http_session
        .read_request_body()
        .await
        .map_err(|e| ApiError::InternalError(e.to_string()))?
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
                .map_err(|e| ApiError::ValidationError(e.to_string()))
        }
        "upstreams" => {
            let upstream = json_to_resource::<config::Upstream>(body_data)
                .map_err(|e| ApiError::InvalidRequest(format!("Invalid JSON data: {}", e)))?;
            upstream
                .validate()
                .map_err(|e| ApiError::ValidationError(e.to_string()))
        }
        "services" => {
            let service = validate_with_plugins::<config::Service>(body_data)?;
            service
                .validate()
                .map_err(|e| ApiError::ValidationError(e.to_string()))
        }
        "global_rules" => {
            let rule = validate_with_plugins::<config::GlobalRule>(body_data)?;
            rule.validate()
                .map_err(|e| ApiError::ValidationError(e.to_string()))
        }
        _ => Err(ApiError::InvalidRequest("Unsupported resource type".into())),
    }
}

fn validate_with_plugins<T: PluginValidatable + DeserializeOwned>(
    body_data: &[u8],
) -> ApiResult<T> {
    let resource = json_to_resource::<T>(body_data)
        .map_err(|e| ApiError::InvalidRequest(format!("Invalid JSON data: {}", e)))?;
    resource
        .validate_plugins()
        .map_err(|e| ApiError::ValidationError(e.to_string()))?;
    Ok(resource)
}

trait PluginValidatable {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>>;
}

impl PluginValidatable for config::Route {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>> {
        for (name, value) in &self.plugins {
            build_plugin(name, value.clone())?;
        }
        Ok(())
    }
}

impl PluginValidatable for config::Service {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>> {
        for (name, value) in &self.plugins {
            build_plugin(name, value.clone())?;
        }
        Ok(())
    }
}

impl PluginValidatable for config::GlobalRule {
    fn validate_plugins(&self) -> Result<(), Box<dyn Error>> {
        for (name, value) in &self.plugins {
            build_plugin(name, value.clone())?;
        }
        Ok(())
    }
}

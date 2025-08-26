use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt,
    marker::PhantomData,
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
        Admin, Identifiable, Pingsix,
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
            ApiError::EtcdGetError(msg) => write!(f, "Etcd get error: {msg}"),
            ApiError::EtcdPutError(msg) => write!(f, "Etcd put error: {msg}"),
            ApiError::EtcdDeleteError(msg) => write!(f, "Etcd delete error: {msg}"),
            ApiError::ValidationError(msg) => write!(f, "Validation error: {msg}"),
            ApiError::MissingParameter(msg) => write!(f, "Missing parameter: {msg}"),
            ApiError::InvalidRequest(msg) => write!(f, "Invalid request: {msg}"),
            ApiError::InternalError(msg) => write!(f, "Internal error: {msg}"),
            ApiError::RequestBodyReadError(msg) => write!(f, "Request body read error: {msg}"),
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
                    log::error!("Invalid content type '{ct}': {e}");
                }
            }
        }

        builder.body(body).unwrap_or_else(|e| {
            log::error!("Failed to build success response: {e}");
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
                log::error!("Failed to build error response: {e}");
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(b"Internal Server Error".to_vec())
                    .unwrap()
            })
    }
}

// 新的资源处理trait，简化资源验证逻辑
trait AdminResource: DeserializeOwned + Validate + Identifiable + Send + Sync + 'static {
    const RESOURCE_TYPE: &'static str;

    fn validate_resource(data: &[u8]) -> ApiResult<Self> {
        let resource = json_to_resource::<Self>(data)
            .map_err(|e| ApiError::InvalidRequest(format!("Invalid JSON data: {e}")))?;

        // 基础验证
        resource.validate().map_err(|e| {
            ApiError::ValidationError(format!("{} validation failed: {e}", Self::RESOURCE_TYPE))
        })?;

        // 插件验证（如果适用）
        Self::validate_plugins_if_supported(&resource)?;

        Ok(resource)
    }

    fn validate_plugins_if_supported(_resource: &Self) -> ApiResult<()> {
        // 默认实现：无插件验证
        Ok(())
    }
}

// 为所有支持的资源类型实现AdminResource
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

// 泛型handler，大大简化了代码
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
        let resource_type = params
            .get("resource")
            .ok_or_else(|| ApiError::MissingParameter("resource".into()))?;
        let id = params
            .get("id")
            .ok_or_else(|| ApiError::MissingParameter("id".into()))?;

        // 验证资源类型匹配
        if resource_type != T::RESOURCE_TYPE {
            return Err(ApiError::InvalidRequest(format!(
                "Resource type mismatch: expected {}, got {resource_type}",
                T::RESOURCE_TYPE
            )));
        }

        Ok(format!("{resource_type}/{id}"))
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

// PUT handler
#[async_trait]
impl<T: AdminResource> Handler for ResourceHandler<T> {
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

        let key = Self::extract_key(&params)?;

        // 使用泛型资源验证
        T::validate_resource(&body_data)?;

        etcd.put(&key, body_data)
            .await
            .map_err(|e| ApiError::EtcdPutError(e.to_string()))?;

        Ok(ResponseHelper::success(Vec::new(), None))
    }
}

// GET handler - 为了区分操作类型，我们需要单独的类型
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
    ) -> ApiResult<Response<Vec<u8>>> {
        let key = ResourceHandler::<T>::extract_key(&params)?;

        match etcd.get(&key).await {
            Err(e) => Err(ApiError::EtcdGetError(e.to_string())),
            Ok(Some(value)) => {
                let json_value: serde_json::Value = serde_json::from_slice(&value)
                    .map_err(|e| ApiError::InvalidRequest(format!("Invalid JSON data: {e}")))?;
                let wrapper = ValueWrapper { value: json_value };
                let json_vec = serde_json::to_vec(&wrapper)
                    .map_err(|e| ApiError::InternalError(e.to_string()))?;
                Ok(ResponseHelper::success(json_vec, Some("application/json")))
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
    ) -> ApiResult<Response<Vec<u8>>> {
        let key = ResourceHandler::<T>::extract_key(&params)?;

        etcd.delete(&key)
            .await
            .map_err(|e| ApiError::EtcdDeleteError(e.to_string()))?;

        Ok(ResponseHelper::success(Vec::new(), None))
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

        // 注册路由变得更简洁，类型安全
        this.register_resource_routes::<config::Route>()
            .register_resource_routes::<config::Upstream>()
            .register_resource_routes::<config::Service>()
            .register_resource_routes::<config::GlobalRule>()
            .register_resource_routes::<config::SSL>();

        this
    }

    fn register_resource_routes<T: AdminResource>(&mut self) -> &mut Self {
        let path = "/apisix/admin/{resource}/{id}";

        self.route(path, Method::PUT, Box::new(ResourceHandler::<T>::new()))
            .route(path, Method::GET, Box::new(GetHandler::<T>::new()))
            .route(path, Method::DELETE, Box::new(DeleteHandler::<T>::new()));

        self
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

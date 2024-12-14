use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
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

#[async_trait]
trait Hanlder {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        session: &mut ServerSession,
        params: BTreeMap<String, String>,
    ) -> Result<Response<Vec<u8>>, Box<dyn Error>>;
}

pub struct AdminHttpApp {
    etcd: EtcdClientWrapper,
    router: Router<HashMap<Method, Box<dyn Hanlder + Send + Sync>>>,

    config: Admin,
}

impl AdminHttpApp {
    pub fn new(cfg: &Pingsix) -> Self {
        let mut this = Self {
            etcd: EtcdClientWrapper::new(cfg.etcd.clone().unwrap()),
            router: Router::new(),
            config: cfg.admin.clone().unwrap(),
        };

        this.route(
            "/apisix/admin/{resource}/{id}",
            Method::PUT,
            Box::new(ResourcePutHanlder {}),
        )
        .route(
            "/apisix/admin/{resource}/{id}",
            Method::GET,
            Box::new(ResourceGetHanlder {}),
        )
        .route(
            "/apisix/admin/{resource}/{id}",
            Method::DELETE,
            Box::new(ResourceDeleteHanlder {}),
        );

        this
    }

    /// 添加一个路由处理函数
    fn route(
        &mut self,
        path: &str,
        method: Method,
        handler: Box<dyn Hanlder + Send + Sync>,
    ) -> &mut Self {
        if self.router.at(path).is_err() {
            let mut hanlders = HashMap::new();
            hanlders.insert(method, handler);
            self.router.insert(path, hanlders).unwrap();
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
            return Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Vec::new())
                .unwrap();
        }

        let (path, method) = {
            let req_header = http_session.req_header();
            (req_header.uri.path().to_string(), req_header.method.clone())
        };

        match self.router.at(&path) {
            Ok(Match { value, params }) => match value.get(&method) {
                Some(handler) => {
                    let params: BTreeMap<String, String> = params
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    match handler.handle(&self.etcd, http_session, params).await {
                        Ok(resp) => resp,
                        Err(e) => Response::builder()
                            .status(StatusCode::BAD_REQUEST)
                            .body(e.to_string().into_bytes())
                            .unwrap(),
                    }
                }
                None => Response::builder()
                    .status(StatusCode::METHOD_NOT_ALLOWED)
                    .body(Vec::new())
                    .unwrap(),
            },
            Err(_) => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"Not Found".to_vec())
                .unwrap(),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct ValueWrapper<T> {
    value: T,
}

struct ResourcePutHanlder;

#[async_trait]
impl Hanlder for ResourcePutHanlder {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        http_session: &mut ServerSession,
        params: BTreeMap<String, String>,
    ) -> Result<Response<Vec<u8>>, Box<dyn Error>> {
        validate_content_type(http_session)?;

        let body_data = read_request_body(http_session).await?;
        let resource_type = params.get("resource").ok_or("Missing resource type")?;
        let key = format!(
            "{}/{}",
            resource_type,
            params.get("id").ok_or("Missing resource ID")?
        );

        validate_resource(resource_type, &body_data)?;
        match etcd.put(&key, body_data).await {
            Ok(_) => Ok(Response::builder()
                .status(StatusCode::OK)
                .body(Vec::new())
                .unwrap()),
            Err(e) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e.to_string().into_bytes())
                .unwrap()),
        }
    }
}

struct ResourceGetHanlder;

#[async_trait]
impl Hanlder for ResourceGetHanlder {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        params: BTreeMap<String, String>,
    ) -> Result<Response<Vec<u8>>, Box<dyn Error>> {
        let resource_type = params.get("resource").ok_or("Missing resource type")?;
        let key = format!(
            "{}/{}",
            resource_type,
            params.get("id").ok_or("Missing resource ID")?
        );
        match etcd.get(&key).await {
            Err(e) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e.to_string().into_bytes())
                .unwrap()),
            Ok(Some(value)) => {
                let json_value: serde_json::Value = serde_json::from_slice(&value)
                    .map_err(|e| format!("Invalid JSON data: {}", e))?;
                let wrapper = ValueWrapper { value: json_value };
                serde_json::to_vec(&wrapper)
                    .map(|json_vec| {
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(
                                header::CONTENT_TYPE,
                                HeaderValue::from_static("application/json"),
                            )
                            .body(json_vec)
                            .unwrap()
                    })
                    .map_err(|e| e.into())
            }
            Ok(None) => Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(b"Not Found".to_vec())
                .unwrap()),
        }
    }
}

struct ResourceDeleteHanlder;

#[async_trait]
impl Hanlder for ResourceDeleteHanlder {
    async fn handle(
        &self,
        etcd: &EtcdClientWrapper,
        _http_session: &mut ServerSession,
        params: BTreeMap<String, String>,
    ) -> Result<Response<Vec<u8>>, Box<dyn Error>> {
        let key = format!(
            "{}/{}",
            params.get("resource").ok_or("Missing resource type")?,
            params.get("id").ok_or("Missing resource ID")?
        );

        match etcd.delete(&key).await {
            Ok(_) => Ok(Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(Vec::new())
                .unwrap()),
            Err(e) => Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(e.to_string().into_bytes())
                .unwrap()),
        }
    }
}

fn validate_api_key(http_session: &ServerSession, api_key: &str) -> Result<(), Box<dyn Error>> {
    match http_session.get_header("x-api-key") {
        Some(key) if key.to_str()? == api_key => Ok(()),
        _ => Err("Must provide api key".into()),
    }
}

fn validate_content_type(http_session: &ServerSession) -> Result<(), Box<dyn Error>> {
    match http_session.get_header(header::CONTENT_TYPE) {
        Some(content_type) if content_type.to_str()? == "application/json" => Ok(()),
        _ => Err("Content-Type must be application/json".into()),
    }
}

async fn read_request_body(http_session: &mut ServerSession) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut body_data = Vec::new();
    while let Some(bytes) = http_session.read_request_body().await? {
        body_data.extend_from_slice(&bytes);
    }
    Ok(body_data)
}

fn validate_resource(resource_type: &str, body_data: &[u8]) -> Result<(), Box<dyn Error>> {
    match resource_type {
        "routes" => {
            let route = validate_with_plugins::<config::Route>(body_data)?;
            route.validate().map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        "upstreams" => {
            let upstream = json_to_resource::<config::Upstream>(body_data)?;
            upstream
                .validate()
                .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        "services" => {
            let service = validate_with_plugins::<config::Service>(body_data)?;
            service
                .validate()
                .map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        "global_rules" => {
            let rule = validate_with_plugins::<config::GlobalRule>(body_data)?;
            rule.validate().map_err(|e| Box::new(e) as Box<dyn Error>)
        }
        _ => Err("Unsupported resource type".into()),
    }
}

fn validate_with_plugins<T: PluginValidatable + DeserializeOwned>(
    body_data: &[u8],
) -> Result<T, Box<dyn Error>> {
    let resource = json_to_resource::<T>(body_data)?;
    resource.validate_plugins()?;
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

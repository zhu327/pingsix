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
    config::{self, etcd::EtcdClientWrapper, Admin, Identifiable, Pingsix, SecretOp},
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
                    .unwrap_or_else(|_| {
                        CommonErrors::internal_server_error("Internal server error")
                    })
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

    fn validate_resource_value(value: serde_json::Value) -> ApiResult<Self> {
        let resource: Self = serde_json::from_value(value).map_err(|e| {
            ApiError::ProxyError(ProxyError::serialization_error(
                "Failed to deserialize JSON",
                e,
            ))
        })?;

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

        let mut value: serde_json::Value = serde_json::from_slice(&body_data)
            .map_err(|e| ApiError::ValidationError(format!("Invalid JSON: {e}")))?;

        // A GET/LIST response masks secrets with the redaction sentinel ("***").
        // If the client round-trips such a body back (edit-and-resave), restore
        // each still-masked secret from the currently stored resource so we do
        // not persist/validate the sentinel (which e.g. is not a valid SSL key).
        // Secrets the client actually changed carry a real value and are kept.
        if contains_redaction_sentinel(&value) {
            if let Some(raw) = etcd
                .get(&key)
                .await
                .map_err(|e| ApiError::EtcdGetError(e.to_string()))?
            {
                let existing: serde_json::Value = serde_json::from_slice(&raw).map_err(|e| {
                    ApiError::ProxyError(ProxyError::serialization_error(
                        "Failed to parse stored resource",
                        e,
                    ))
                })?;
                let existing = decrypt_for_read(T::RESOURCE_TYPE, existing)?;
                restore_redacted_secrets(T::RESOURCE_TYPE, &mut value, &existing);
            }
        }

        // Use generic resource validation
        T::validate_resource_value(value.clone())?;

        let body_data = encrypt_resource_for_storage(T::RESOURCE_TYPE, value)?;
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
                let logical = decrypt_for_read(T::RESOURCE_TYPE, json_value)?;
                let wrapper = ValueWrapper {
                    value: redact(T::RESOURCE_TYPE, logical),
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
            let logical = decrypt_for_read(T::RESOURCE_TYPE, value)?;

            let item = serde_json::json!({
                "key": key,
                "value": redact(T::RESOURCE_TYPE, logical),
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
    pub fn new(admin: Admin, etcd_cfg: crate::config::Etcd) -> Self {
        let mut this = Self {
            config: admin,
            etcd: EtcdClientWrapper::new(etcd_cfg),
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

    pub fn admin_http_service(cfg: &Pingsix) -> Option<Service<Self>> {
        let admin = cfg.admin.clone()?;
        let etcd_cfg = cfg.etcd.clone()?;
        let app = Self::new(admin, etcd_cfg);
        let addr = &app.config.address.to_string();
        let mut service = Service::new("Admin HTTP".to_string(), app);
        service.add_tcp(addr);
        Some(service)
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

/// Mask secret fields (SSL/TLS private keys, plugin credentials) with `***` for
/// the read API. Applied to the logical (decrypted) resource; see
/// [`decrypt_for_read`].
///
/// Redaction reuses the exact same `#[encrypt]` field walk as encrypt/decrypt
/// (via [`SecretOp::Redact`]), so the masked set is the single source of truth:
/// marking a field `#[encrypt]` masks it here automatically, with no parallel
/// list to maintain. It performs no crypto and never touches the keyring, so it
/// cannot fail.
pub fn redact(resource_type: &str, mut value: serde_json::Value) -> serde_json::Value {
    config::transform_resource_secrets(resource_type, &mut value, SecretOp::Redact)
        .expect("redaction performs no fallible crypto");
    value
}

/// Sentinel [`redact`] writes over secrets; on write it means "keep the stored
/// value" rather than "set the secret to this literal string".
const REDACTED_SENTINEL: &str = "***";

/// Does any string leaf equal the redaction sentinel? Used to skip the extra
/// etcd read/decrypt on the common PUT path where the client sends real values.
fn contains_redaction_sentinel(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(s) => s == REDACTED_SENTINEL,
        serde_json::Value::Array(items) => items.iter().any(contains_redaction_sentinel),
        serde_json::Value::Object(map) => map.values().any(contains_redaction_sentinel),
        _ => false,
    }
}

/// Restore secrets the client left redacted (`"***"`) on a PUT from the stored
/// resource, so a GET/LIST → edit → PUT round-trip preserves untouched secrets.
///
/// Restoration is scoped to true secret leaves: redacting a copy of the stored
/// (decrypted) resource yields exactly the secret paths, and only there is an
/// incoming sentinel swapped for the stored plaintext. A client rotating a
/// secret sends its new value (not the sentinel), which is left untouched.
pub fn restore_redacted_secrets(
    resource_type: &str,
    incoming: &mut serde_json::Value,
    existing_plaintext: &serde_json::Value,
) {
    let secret_map = redact(resource_type, existing_plaintext.clone());
    restore_walk(incoming, existing_plaintext, &secret_map);
}

/// Walk driven by `secret_map` (the redacted stored resource): its sentinel
/// leaves mark secret paths. Where `incoming` still holds the sentinel at such a
/// path, replace it with the stored plaintext at the same path.
fn restore_walk(
    incoming: &mut serde_json::Value,
    plaintext: &serde_json::Value,
    secret_map: &serde_json::Value,
) {
    match secret_map {
        serde_json::Value::String(s)
            if s == REDACTED_SENTINEL && incoming.as_str() == Some(REDACTED_SENTINEL) =>
        {
            *incoming = plaintext.clone();
        }
        serde_json::Value::Object(map) => {
            let (Some(inc), Some(pt)) = (incoming.as_object_mut(), plaintext.as_object()) else {
                return;
            };
            for (key, sub) in map {
                if let (Some(iv), Some(pv)) = (inc.get_mut(key), pt.get(key)) {
                    restore_walk(iv, pv, sub);
                }
            }
        }
        serde_json::Value::Array(items) => {
            let (Some(inc), Some(pt)) = (incoming.as_array_mut(), plaintext.as_array()) else {
                return;
            };
            for (i, sub) in items.iter().enumerate() {
                if let (Some(iv), Some(pv)) = (inc.get_mut(i), pt.get(i)) {
                    restore_walk(iv, pv, sub);
                }
            }
        }
        _ => {}
    }
}

/// Compact a validated resource to storage bytes, encrypting sensitive fields
/// first when data encryption is enabled.
///
/// The JSON is parsed once by the caller. Validation already ran against
/// plaintext. Only resource types with known secret fields are rewritten;
/// others pass through unchanged but are still compacted by `to_vec`.
fn encrypt_resource_for_storage(
    resource_type: &str,
    mut value: serde_json::Value,
) -> ApiResult<Vec<u8>> {
    if crate::utils::encryption::is_enabled() {
        config::transform_resource_secrets(resource_type, &mut value, SecretOp::Encrypt).map_err(
            |e| ApiError::ValidationError(format!("Failed to encrypt resource secrets: {e}")),
        )?;
    }

    serde_json::to_vec(&value).map_err(|e| {
        ApiError::ValidationError(format!("Failed to serialize resource for storage: {e}"))
    })
}

/// Decrypt a resource's secret fields for the read API (GET/LIST) so responses
/// reflect the logical stored resource — mirroring the control-plane load path —
/// before [`redact`] masks those secrets. No-op when encryption is disabled.
///
/// Decryption is fail-closed: an undecryptable value surfaces an error rather
/// than leaking ciphertext into the API response.
fn decrypt_for_read(
    resource_type: &str,
    mut value: serde_json::Value,
) -> ApiResult<serde_json::Value> {
    if crate::utils::encryption::is_enabled() {
        config::transform_resource_secrets(resource_type, &mut value, SecretOp::Decrypt)
            .map_err(ApiError::ProxyError)?;
    }
    Ok(value)
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
    fn encrypt_resource_for_storage_noop_when_disabled() {
        let input = serde_json::json!({
            "id": "1",
            "cert": "c",
            "key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----",
            "snis": ["example.com"],
        });
        let out = encrypt_resource_for_storage("ssls", input.clone()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["key"], input["key"]);
    }

    #[test]
    fn encrypt_resource_leaves_basic_auth_password_when_disabled() {
        let input = serde_json::json!({
            "id": "1",
            "uri": "/",
            "plugins": {
                "basic-auth": {
                    "username": "demo",
                    "password": "s3cret"
                }
            }
        });
        let out = encrypt_resource_for_storage("routes", input).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["plugins"]["basic-auth"]["password"], "s3cret");
        assert_eq!(parsed["plugins"]["basic-auth"]["username"], "demo");
    }

    #[test]
    fn encrypt_resource_leaves_upstream_client_key_when_disabled() {
        let input = serde_json::json!({
            "id": "1",
            "nodes": { "127.0.0.1:443": 1 },
            "tls": {
                "client_cert": "-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----",
                "client_key": "-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----"
            }
        });
        let out = encrypt_resource_for_storage("upstreams", input.clone()).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["tls"]["client_key"], input["tls"]["client_key"]);
        assert_eq!(parsed["tls"]["client_cert"], input["tls"]["client_cert"]);
    }

    #[test]
    fn encrypt_resource_leaves_inline_upstream_client_key_when_disabled() {
        let input = serde_json::json!({
            "id": "1",
            "uri": "/",
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": {
                    "client_cert": "cert",
                    "client_key": "key-material"
                }
            }
        });
        let out = encrypt_resource_for_storage("routes", input).unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(parsed["upstream"]["tls"]["client_key"], "key-material");
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
        // Only routes/services carry an inline upstream in their schema; global
        // rules have no upstream, so schema-driven redaction doesn't touch one.
        for resource_type in ["routes", "services"] {
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
    fn restore_keeps_masked_secret_and_accepts_rotation() {
        // Stored (decrypted) SSL with a real private key.
        let existing = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "-----BEGIN PRIVATE KEY-----\nreal\n-----END PRIVATE KEY-----",
        });

        // Client resaves the redacted GET body verbatim: the sentinel must be
        // swapped back to the stored key, so validation sees the real value.
        let mut resave = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "***",
        });
        restore_redacted_secrets("ssls", &mut resave, &existing);
        assert_eq!(resave["key"], existing["key"]);
        assert_eq!(resave["cert"], "cert-pem");

        // Client rotates the key: a real (non-sentinel) value is left untouched.
        let mut rotate = serde_json::json!({
            "id": "s1",
            "cert": "cert-pem",
            "key": "-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----",
        });
        restore_redacted_secrets("ssls", &mut rotate, &existing);
        assert_eq!(
            rotate["key"],
            "-----BEGIN PRIVATE KEY-----\nnew\n-----END PRIVATE KEY-----"
        );
    }

    #[test]
    fn restore_walks_plugins_nested_upstream_and_arrays() {
        let existing = serde_json::json!({
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "demo", "password": "s3cret" },
                "key-auth": { "key": "k0", "keys": ["k1", "k2"] },
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": {
                    "client_cert": "cert-pem",
                    "client_key": "-----BEGIN PRIVATE KEY-----\nreal\n-----END PRIVATE KEY-----",
                },
            },
        });

        // What a client would resave from a redacted GET, changing only username.
        let mut resave = serde_json::json!({
            "uri": "/",
            "plugins": {
                "basic-auth": { "username": "changed", "password": "***" },
                "key-auth": { "key": "***", "keys": ["***", "***"] },
            },
            "upstream": {
                "nodes": { "127.0.0.1:443": 1 },
                "tls": { "client_cert": "cert-pem", "client_key": "***" },
            },
        });

        restore_redacted_secrets("routes", &mut resave, &existing);

        assert_eq!(resave["plugins"]["basic-auth"]["username"], "changed");
        assert_eq!(resave["plugins"]["basic-auth"]["password"], "s3cret");
        assert_eq!(resave["plugins"]["key-auth"]["key"], "k0");
        assert_eq!(
            resave["plugins"]["key-auth"]["keys"],
            serde_json::json!(["k1", "k2"])
        );
        assert_eq!(
            resave["upstream"]["tls"]["client_key"],
            existing["upstream"]["tls"]["client_key"]
        );
        // No sentinel may survive restoration on a full round-trip.
        assert!(!contains_redaction_sentinel(&resave));
    }

    #[test]
    fn restore_ignores_non_secret_sentinel() {
        // A non-secret field the client literally sets to "***" must be kept as
        // typed (it is not a secret path, so it is not restored).
        let existing = serde_json::json!({ "uri": "/old", "id": "r1" });
        let mut resave = serde_json::json!({ "uri": "***", "id": "r1" });
        restore_redacted_secrets("routes", &mut resave, &existing);
        assert_eq!(resave["uri"], "***");
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
                name: None,
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

    #[test]
    fn encrypt_resource_for_storage_compacts_output() {
        let pretty: serde_json::Value = serde_json::from_str(
            r#"{
            "id": "1",
            "nodes": ["b", "a"]
            }"#,
        )
        .unwrap();
        // Unknown resource type → no encryption, but output must be compacted.
        let compact = encrypt_resource_for_storage("unknown", pretty).unwrap();
        let s = String::from_utf8(compact).unwrap();
        assert!(!s.contains('\n'));
        assert!(!s.contains(' '));
        // array order preserved
        assert!(s.contains(r#"["b","a"]"#));
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["nodes"], serde_json::json!(["b", "a"]));
    }
}

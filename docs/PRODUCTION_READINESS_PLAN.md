# PingSIX 生产就绪改进计划

> 状态：拟实施  
> 范围：P0、P1 为上线前必做；P2 为可选增强  
> 基线：`main` 分支，审查时版本 `0.1.0`  
> 原则：优先修复安全与正确性，再完善可靠性和生产运维；每项改动必须有回归测试和明确验收标准。

## 1. 目标与边界

本计划用于将 PingSIX 从“具备良好工程基础的预发布项目”推进到可灰度上线、可持续运维的生产版本。

### 1.1 本期目标

- 完成全部 P0 安全、数据一致性与协议正确性修复。
- 完成全部 P1 可靠性、安全默认值和多实例语义改进。
- 为每项改动提供代码落点、实现方案、兼容策略、测试和验收标准。
- 建立真实 etcd、动态配置、TLS、DNS、缓存和关闭流程的集成验证。

### 1.2 不在必做范围内

以下能力作为 P2 可选项，不阻塞首个生产版本：

- 分布式限流后端。
- 分布式响应缓存。
- 完整异步化的控制面编译流水线。
- Admin API 的 secret-preserving PATCH。
- 独立诊断服务、OpenTelemetry、完整发布供应链等增强。

### 1.3 关键设计假设

1. 生产环境的动态配置写入应通过 Admin API；直接写 etcd 的外部组件必须遵守同一事务协议，否则无法保证配置图原子性。
2. etcd 短暂中断期间继续使用 last-known-good 快照，但超过阈值后默认退出 Ready，避免无限期承载新流量。
3. P1 阶段允许限流和缓存保持进程本地语义，但必须在配置、响应头、指标和文档中明确表达。
4. 安全默认值的变化可以带来兼容性变更，但必须通过迁移说明和版本发布显式管理，不保留静默不安全行为。

---

## 2. 当前工程基线

项目已有以下良好基础，应在改造中保留：

- 配置使用 `deny_unknown_fields`、`validator` 和跨资源校验。
- 控制面构建完整 candidate 后，通过 `ArcSwap` 原子发布运行时快照：
  - `src/proxy/control_plane.rs`
  - `src/proxy/runtime.rs`
- etcd list/watch 失败后会重新 list，运行时保留最后有效快照：
  - `src/config/etcd.rs`
- Admin 请求体限制为 1 MiB，API key 使用常量时间比较：
  - `src/admin/mod.rs`
- TLS listener 强制 TLS 1.2–1.3：
  - `src/main.rs`
- 默认不缓存带认证信息的请求和包含 `Set-Cookie` 的响应：
  - `src/plugins/cache.rs`
  - `src/service/http.rs`
- CI 已执行 fmt、Clippy、全量测试、cargo-audit 和容器 smoke test：
  - `.github/workflows/rust.yml`
- 审查时已执行 `cargo fmt --all -- --check`、Clippy 和全量测试并通过；实施时应以具体 commit SHA、命令和 CI run 记录结果，不在长期计划中固化易失真的测试数量。

---

## 3. 实施总览

| ID | 优先级 | 改进项 | 主要代码位置 | 建议阶段 |
|---|---|---|---|---|
| P0-1 | P0 | Admin 敏感字段完整脱敏 | `src/admin/mod.rs` | 阶段 A |
| P0-2 | P0 | 正确处理缓存 `Vary: *` | `src/service/http.rs`, `src/plugins/cache.rs` | 阶段 A |
| P0-3 | P0 | 配置图级 etcd 并发原子性 | `src/admin/mod.rs`, `src/config/etcd.rs`, `src/proxy/control_plane.rs` | 阶段 B |
| P0-4 | P0 | 禁止 etcd TLS scheme 静默降级 | `src/config/mod.rs`, `src/config/etcd.rs` | 阶段 A |
| P0-5 | P0 | CORS 仅拦截合法预检请求 | `src/plugins/cors.rs`, `src/proxy/route.rs`, `src/service/http.rs` | 阶段 A |
| P1-1 | P1 | etcd stale readiness 默认失败 | `src/core/status.rs`, `src/config/mod.rs`, `src/main.rs` | 阶段 C |
| P1-2 | P1 | JWT cookie 凭证真正隐藏 | `src/plugins/jwt_auth.rs`, `src/utils/request.rs` | 阶段 A |
| P1-3 | P1 | Key Auth query 默认关闭 | `src/plugins/key_auth.rs` | 阶段 A |
| P1-4 | P1 | 隔离公开探针与详细诊断 | `src/service/status.rs`, `src/core/status.rs`, `src/config/mod.rs` | 阶段 C |
| P1-5 | P1 | DNS 不阻塞控制面 | `src/proxy/upstream/discovery.rs`, `load_balancer.rs`, `control_plane.rs` | 阶段 D |
| P1-6 | P1 | 全局安全 upstream timeout | `src/config/mod.rs`, `src/proxy/route.rs`, `load_balancer.rs` | 阶段 C |
| P1-7 | P1 | 日志安全、轮转与丢弃指标 | `src/logging/mod.rs`, `src/plugins/file_logger.rs` | 阶段 D |
| P1-8 | P1 | 明确多实例限流/缓存语义 | `src/plugins/limit_count.rs`, `cache.rs`, `service/http.rs` | 阶段 D |

---

# 4. P0 必做改进

## P0-1 Admin API 敏感字段完整脱敏

### 现状与风险

Admin GET/LIST 都通过 `redact()` 输出配置，但规则覆盖不完整：

- `key-auth` 支持 `key` 与 `keys`，当前只处理 `keys`：
  - `src/plugins/key_auth.rs`
  - `src/admin/mod.rs::redact_value`
- `tls.client_key` 的识别依赖顶层资源类型为 `upstreams`，route/service 的内联 upstream 可能泄露私钥。
- 新插件增加敏感字段时，当前手工递归规则容易漏加。

### 实现方案

1. 在插件上下文规则中同时脱敏：
   - `jwt-auth.secret`
   - `basic-auth.password`
   - `key-auth.key`
   - `key-auth.keys[]`
   - `csrf.key`
2. 将 upstream TLS 私钥识别改为结构化上下文，而不是仅判断顶层资源类型：
   - 顶层 `upstreams[].tls.client_key`
   - `route.upstream.tls.client_key`
   - `service.upstream.tls.client_key`
   - traffic-split 等支持内联 upstream 的插件配置。
3. 保留 `Upstream.key`，该字段是哈希选择器，不是密钥。
4. 将敏感字段表集中管理，GET 和 LIST 必须复用同一输出函数。
5. 不采用“所有名为 key/password 的字段都脱敏”的泛化规则，避免破坏合法配置。

### 兼容与迁移

- API JSON 结构不变，只有此前泄露的值变为 `"***"`。
- 文档明确：脱敏后的 GET 结果不适合直接 GET-modify-PUT，调用方必须重新提供 secret。
- P2 可增加 PATCH 或 masked-field preservation；本期不让 `"***"` 自动表示保留旧值，避免语义歧义。

### 测试

在 `src/admin/mod.rs` 增加：

- 单个 `key-auth.key` 和多个 `keys`。
- route/service 内联 upstream 私钥。
- 插件内联 upstream 私钥。
- `Upstream.key`、username、证书、普通字段不被误脱敏。
- GET 与 LIST 输出一致。

### 验收标准

- Admin GET/LIST 不返回当前 schema 支持的任何 API key、密码、HMAC secret 或私钥。
- 非敏感选择器字段保持原值。
- 测试清单覆盖所有已支持认证插件和 TLS 私钥位置。

---

## P0-2 正确处理缓存 `Vary: *`

### 现状与风险

`HttpService::cache_vary_filter` 将所有 `Vary` token 当作 header 名。`Vary: *` 实际表示响应不可被一般共享缓存复用；当前行为可能生成一个基于不存在的 `"*"` 请求头的固定 variance key，造成错误复用。

### 实现方案

1. 在 `src/service/http.rs` 增加纯函数：
   - 遍历所有 `Vary` header 行；
   - 按逗号拆分、trim；
   - 检测 token `*`。
2. 在 `response_cache_filter` 中优先检查 `Vary: *`，命中时返回 `RespCacheable::Uncacheable`，不得进入 TTL 补全和缓存写入。
3. `cache_vary_filter` 再做一次防御性检查，但不能将返回 `None` 当成不可缓存的唯一保证。
4. 在 `src/plugins/cache.rs` 校验配置 `vary`：
   - 使用 HTTP `HeaderName` 校验；
   - 拒绝 `"*"`；
   - 统一转为小写并去重。

### 兼容与迁移

- 原先错误缓存的 `Vary: *` 响应将变为 MISS，这是正确的安全变化。
- 显式配置 `vary: ["*"]` 将启动/发布失败；应改为具体 header 或关闭该路由缓存。

### 测试

- 单个 `Vary: *`。
- `Vary: Accept-Encoding, *`。
- 多行 `Vary`，后一行包含 `*`。
- 空格和大小写变体。
- 普通 `Vary: Origin, Accept-Encoding` 行为不变。
- 配置 `vary: ["*"]` 和非法 header 名被拒绝。

### 验收标准

- 包含 `Vary: *` 的响应永不进入共享缓存。
- 普通 Vary variance key 行为不回归。
- 不再对名为 `"*"` 的请求头建立 variance。

---

## P0-3 配置图级 etcd 并发原子性

### 现状与风险

Admin PUT/DELETE 先读取并校验完整配置图，再只对目标 key 做 CAS。两个修改不同 key 的并发请求可能都基于旧图校验成功并同时提交，留下悬空引用。last-known-good 只能保护当前数据面，不能修复 etcd 中的无效持久状态。

### 设计选择

采用**配置图 generation guard key**，而不是为每个资源 key 增加 transaction compare：

- 保留 key：`<prefix>/.pingsix_graph_revision`
- 每次 Admin 修改都比较并更新 guard。
- 事务大小固定，不随配置图规模增长，避免触发 etcd transaction operation 限制。

### 实现方案

1. 修改 `EtcdClientWrapper::read_full_graph`：
   - 返回资源 KV、资源 mod revision、guard 的值/mod revision；
   - guard 不进入 `ResourceConfigSet`。
2. 用以下方法替换目标 key 单独 CAS：
   - `graph_txn_put(...)`
   - `graph_txn_delete(...)`
3. 事务比较条件：
   - guard 已存在：比较 guard mod revision；
   - 首次写：比较 guard `create_revision == 0`；
   - 同时比较目标 key 的预期存在状态/mod revision，便于准确识别冲突。
4. 事务成功操作：
   - PUT/DELETE 资源；
   - 同事务更新 guard generation。
5. 事务失败统一映射为 HTTP 409，调用方重新读取、重新校验后重试。
6. 提供统一的 `is_metadata_key` / metadata filter，并用于所有解析入口：
   - `ResourceConfigSet::from_etcd_list`；
   - `build_config_set_from_kvs`（Admin full-graph candidate）；
   - `apply_events` / `apply_coalesced_events`。
7. guard-only watch event 不重新编译运行时；资源与 guard 同批出现时只对资源变化构建一次 candidate，同时仍推进 observed revision/watch cursor。
8. 文档规定：生产写入只允许 Admin API；外部 writer 必须在同一事务中更新 guard，否则不在一致性保证范围内。

### 兼容与迁移

- 现有 prefix 无需离线数据迁移，第一次 Admin 写入原子创建 guard。
- **版本迁移要求**：启用 guard 后，禁止回滚到不识别 guard、仍执行单 key CAS 的版本。推荐先发布一个兼容过渡版本，使新旧实例都采用 guard transaction，验证混跑后再启用强制策略；CI 增加新旧实例混跑和回滚阻断测试。
- 直接写 etcd 的旧工具仍可改变资源，但不再属于受支持的生产写路径。
- 可增加检测：资源 revision 新于 guard 时将控制面标记 degraded，但这只能检测，不能替代协同事务。

### 测试

单元测试：

- guard key 在 list、Admin full-graph build 和 watch/apply 的所有入口都不进入资源解析。
- 首次创建和已有 guard 的 transaction compare 正确。
- guard-only event 不重建 snapshot；资源与 guard 同 revision 的 batch 只发布一次有效 snapshot。
- 冲突映射为 409，不暴露 etcd endpoint/key。

真实 etcd 集成测试：

- 两个请求基于同一 generation 并发 PUT，恰好一个成功。
- 并发创建引用和删除被引用 upstream，不能同时成功。
- 首次写安全创建 guard。
- 409 后重新读图重试，合法时可以成功。
- 失败事务既不修改资源，也不修改 guard。

### 验收标准

- 两个 Admin mutation 不能从同一配置图 generation 同时提交。
- 受支持的 Admin 写路径不能制造悬空引用。
- 冲突稳定返回 409。
- list/watch 和 snapshot 发布继续保持 last-known-good 语义。

---

## P0-4 禁止 etcd TLS scheme 静默降级

### 现状与风险

`normalize_etcd_endpoints` 根据是否配置 `etcd.tls` 重写 scheme，显式 `https://` 在缺少 TLS block 时会被改为 `http://`，违背用户预期并可能泄露认证信息。

### 实现方案

替换“重写”为“解析并验证”：

| Endpoint | TLS block | 行为 |
|---|---:|---|
| `host:port` | 无 | 推导为 `http://` |
| `host:port` | 有 | 推导为 `https://` |
| `http://...` | 无 | 保留，允许 |
| `https://...` | 有 | 保留，允许 |
| `https://...` | 无 | 配置错误，启动失败 |
| `http://...` | 有 | 配置错误，启动失败 |
| 其他 scheme | 任意 | 配置错误 |

具体修改：

1. 引入可靠 URL parser（新增直接依赖或使用 etcd client 已公开的解析类型），给 `Etcd` 增加 schema validation，启动前检查 endpoint/TLS 一致性。
2. endpoint 只允许 scheme + authority；拒绝 URL userinfo、path、query、fragment、缺失 authority 和非法端口，避免凭证绕过独立 `user/password` 配置并进入错误日志。
3. `create_client` 只消费已验证的 endpoint，不再反向改写 scheme。
4. `build_connect_options` 只负责 timeout、用户认证和 TLS options。
5. 同时校验 etcd `user/password`：必须同时存在或同时不存在，且不能只包含空白。

### 兼容与迁移

- 矛盾配置将从“静默改写”变成“启动失败”。
- 文档给出明文、TLS、mTLS 三组完整示例。
- 错误消息可显示 endpoint，但不得包含密码或 URL userinfo。

### 测试

覆盖上述 endpoint/TLS 矩阵、混合 endpoint 列表、非法 scheme、URL userinfo/path/query/fragment、缺失 authority、非法端口、部分用户名密码、CA-only 和 mTLS。

### 验收标准

- 显式 HTTPS 永不降级为 HTTP。
- 矛盾配置在建立网络连接前失败。
- 不完整 etcd 认证配置不能被静默忽略。

---

## P0-5 CORS 仅拦截合法预检请求

### 现状与风险

当前任何带允许 Origin 的 OPTIONS 都可能直接返回 204，没有要求 `Access-Control-Request-Method`，会截获普通业务 OPTIONS。另一个路由层问题是：只允许 GET 的 route 即使配置 CORS，也可能在插件执行前因 OPTIONS method 不匹配而 404。

### 实现方案

分两层修复：

#### A. 严格识别预检

`PluginCors::handle_options_request` 仅在以下条件都满足时处理：

- Method 为 OPTIONS；
- `Origin` 存在且允许；
- `Access-Control-Request-Method` 存在且可解析；
- requested method 在 `allow_methods` 中；
- requested headers 全部满足 `allow_headers` 策略。

缺少 `Access-Control-Request-Method` 的普通 OPTIONS 不视为预检，继续走正常路由/上游。对于已经匹配 CORS 插件、但 origin/requested method/requested headers 不符合策略的真实预检，本期采用 fail-closed：返回明确 403/4xx，且绝不附加 allow headers、绝不继续交给业务 OPTIONS 伪装成功。

#### B. 支持 route method 不含 OPTIONS 的合法预检

1. 在 runtime snapshot compile 时为 route 计算 `effective_has_cors`，必须同时考虑 route/service executor 与单独存储的 global plugins；不能只检查 `ProxyRoute` 自身 executor。
2. 在 route matcher 增加 preflight fallback：host/path 正常匹配，使用 `Access-Control-Request-Method` 对 route methods 做匹配，并仅返回 `effective_has_cors` 的 route。
3. `HttpService::early_request_filter` 先正常匹配；失败且请求语法上是预检时，再尝试 preflight matcher。
4. 显式 OPTIONS route 始终优先于 fallback。
5. 成功预检不选择 upstream、不执行不相关业务插件。

### 兼容与迁移

- 普通 OPTIONS 将恢复转发，不再被错误截获。
- CORS route 不需要把 OPTIONS 人工加入 methods。
- 非 CORS route 不启用 fallback。

### 测试

- 普通 OPTIONS + Origin 继续转发。
- GET-only + CORS 的合法预检返回 204。
- 缺少 requested method 的普通 OPTIONS 继续转发；method/origin/header 不允许的真实预检返回 403/4xx 且无 allow headers。
- 无 CORS route 不启用 fallback。
- 显式 OPTIONS route 优先。
- route/service/global CORS 继承场景，尤其覆盖仅 global CORS + GET-only route。
- 成功预检不触发 upstream selection。

### 验收标准

- 仅符合 CORS preflight 定义的 OPTIONS 被短路。
- 普通 OPTIONS 业务语义不被破坏。
- 合法预检可匹配目标业务方法对应的 route。

---

# 5. P1 必做改进

## P1-1 etcd stale readiness 默认失败

### 目标语义

- 启动尚未发布有效配置：Not Ready。
- etcd 短暂断开且未超过 `config_stale_after`：继续 Ready，使用 last-known-good。
- 断开超过阈值：默认 Not Ready，停止接收新流量，但进程不退出、不清空快照。
- etcd 恢复且有效配置成功发布：立即 Ready。
- 静态 YAML 模式：成功启动后不因 stale policy 变为 Not Ready。

### 实现方案

1. 将 `fail_readiness_when_stale` 默认值改为 true；建议从 `Option<bool>` 改成带 serde default 的 `bool`。
2. 使用内部 reason enum：`not_initialized`、`config_stale`、`config_invalid` 等，不依赖展示文本计算 readiness。
3. 明确区分 observed revision 与 published revision：progress/guard-only event 只能推进 observed，不得冒充有效配置已发布；恢复 readiness 必须基于成功发布，或确认当前 published snapshot 与最新有效资源图一致。
4. 只有成功解析、编译并发布资源 snapshot 后才记录 publish success；invalid update 后的 progress 不得错误恢复 readiness。
5. 保留 watch progress notification，健康空闲 watch 不应被误判 stale。
6. 示例生产配置显式写出阈值和策略。

### 兼容与迁移

依赖“etcd 永久断开仍持续 Ready”的部署必须显式设置 `fail_readiness_when_stale: false`。发布说明必须标记该默认值变化。

### 测试与验收

- 初始、YAML、短断开、长断开、显式 opt-out、恢复、空闲 watch、无效更新、guard-only update，以及无效更新后再收到有效更新均有测试。
- 默认 etcd 部署超过阈值后 `/status/ready` 返回 503。
- 恢复并发布成功后返回 200。

---

## P1-2 JWT cookie 凭证真正隐藏

### 实现方案

1. 在 `src/utils/request.rs` 增加 `remove_cookie_from_header`：遍历所有 Cookie header 行，删除所有同名 cookie，保留其他 cookie 和顺序，无剩余 cookie 时删除 header。
2. 将 `extract_token` / `extract_from_cookie` 的签名改为 `Result<Option<String>>`，把 header/query/cookie mutation 错误贯穿到 request filter，不能静默忽略。
3. `PluginJWTAuth::extract_from_cookie` 在复制 token 后，如果 `hide_credentials=true`，立即修改上游请求的 Cookie header。
4. 本期响应侧清 cookie 明确定义为 `Path=/` 的 best-effort 清理；请求 Cookie 不包含原始 Path/Secure/SameSite，无法推导原属性。若需要严格删除，新增显式 `cookie_path`、`cookie_domain`、`cookie_secure`、`cookie_same_site` 配置后再作为验收条件。
5. credential 已被移除后仍保持 `ctx.mark_request_has_credentials()`，避免共享缓存误判匿名请求。

### 兼容与迁移

这是对 `hide_credentials` 既有承诺的修复。开启该选项的后端将不再收到 JWT cookie，但其他 cookie 不受影响。

### 测试与验收

覆盖单行/多行 Cookie、多 cookie、重复同名、近似名称、关闭 hide、header 重建失败、缓存 credential flag、多个 `Set-Cookie` 保留。验收要求 JWT cookie 不再转发且其他 cookie 完整。

---

## P1-3 Key Auth query 默认关闭

### 实现方案

1. 将 `PluginConfig::default_query()` 改为空字符串。
2. query 为空时完全跳过 query extraction。
3. header 仍为首选；显式 `query: apikey` 保留旧能力。
4. 文档将 query 认证标记为不推荐的显式 opt-in，并推荐 `hide_credentials: true`。
5. 更新 Admin 脱敏和日志 query redaction 测试。

### 兼容与迁移

未显式配置 `query`、但依赖 `?apikey=` 的客户端会停止认证：

- 推荐迁移到 header；
- 临时兼容可显式配置 `query: apikey`。

### 测试与验收

- 默认不读取 query。
- 显式 query 正常认证并可移除。
- header 行为不变。
- query 认证仍标记为 credential-bearing。

---

## P1-4 隔离公开探针与详细诊断

### 目标接口

| Endpoint | 默认访问 | 内容 |
|---|---|---|
| `/status/live` | 无认证 | `status` |
| `/status/ready` | 无认证 | `status` + 稳定 reason code |
| `/status/config` | 默认仅 loopback；远程需双重显式 opt-in | revision、连接状态、安全错误类别 |

### 实现方案

1. 将 public probe DTO 与 detailed diagnostics DTO 分开。
2. public response 不返回 `last_error` 原文、endpoint、prefix、key 或 revision 细节。
3. 默认仅在 loopback listener 开放 `/status/config`；非 loopback listener 默认禁用该路径。由于当前 Status listener 没有 TLS，明文 API key 不能作为推荐生产保护。
4. 若为兼容需要保留远程明文 diagnostics，必须同时配置 `diagnostics_api_key` 和显式 `allow_insecure_remote: true`，启动时打印高风险告警；长期方案是 P2 的独立 TLS/mTLS diagnostics listener。
5. API key 使用已有常量时间比较函数。
6. `record_sync_error` 同时存储稳定错误类别和仅供日志/受保护诊断使用的详细消息。
7. 增加 `Status::validate_bind_safety`，在 `main::add_optional_services` 启动前执行。

### 兼容与迁移

- loopback 默认可保留详细诊断。
- 非 loopback 部署默认只保留 live/ready；远程明文 diagnostics 必须双重显式 opt-in，生产推荐通过 loopback sidecar/端口转发访问。
- probe consumer 只能依赖 HTTP status、`status` 和稳定 reason code。

### 测试与验收

- public response 永不包含人为注入的 endpoint/password/key 错误文本。
- 非 loopback diagnostics 必须认证。
- live/ready 不需要认证，继续适用于 Kubernetes probe。
- 认证失败返回 403。

---

## P1-5 DNS 不阻塞控制面

### 现状与风险

`eager_discover_backends` 对异步 DNS 创建线程和 Tokio runtime 后立即 `join()`，candidate 构建又发生在控制面 writer lock 内。慢 DNS 会阻塞 list/watch 和后续配置发布。

### 推荐实现方案

采用“两阶段 candidate preparation”。首先将 `EtcdEventHandler::handle_events` / `handle_list_response` 改为 async，或在 `EtcdConfigSync` 与控制面之间增加有界 worker/channel；worker 必须定义 revision fencing、事件合并、队列满策略、取消和 shutdown ownership。随后：

1. 将 DNS 解析从同步 `CandidateSnapshot::build` 中分离。
2. async handler/control-plane worker 在 writer lock 外准备 candidate：DNS 有有限 deadline，支持取消，多个 upstream 受控并发，不按 upstream 创建 OS thread。
3. 准备完成后短暂获取 writer lock：
   - 再比较当前 revision/generation；
   - 过期 candidate 丢弃并重试；
   - 编译、发布、提交 raw state。
4. replacement DNS 解析失败时保留旧 snapshot，不发布零 backend 的替代对象。
5. 新建 DNS-only upstream 在首次解析成功前不发布；Admin 写入仍只返回 committed revision，失败/超时通过结构化错误、日志和控制面指标表达。本期不引入未设计的逐资源 pending API。
6. 增加 `dns_resolution_timeout` 配置，提供有限默认值。

### 可接受的过渡实现

若完整两阶段改造过大，可先：

- 删除 helper-thread + join；
- 静态 IP 继续同步初始化；
- DNS 交给共享 background service；
- replacement 首次成功前继续使用旧 upstream。

但最终不得在控制面锁内等待无界 DNS。

### 测试与验收

- 永不完成的 resolver 不阻塞其他配置事件。
- deadline 后保留旧 snapshot。
- 稍后解析成功可激活新配置。
- shutdown 可取消解析任务。
- 源码控制面路径不存在无界 `thread.join()`。

---

## P1-6 全局安全 upstream timeout

### 实现方案

1. 提供有限 built-in 默认值，初始建议：
   - connect：5 秒；
   - send：30 秒；
   - read：30 秒。
2. 将最终 resolver 改为始终返回非 Optional 的有效 `Timeout`，统一优先级：route > upstream > `pingsix.defaults.upstream_timeout` > built-in。
3. 将 timeout 解析集中为一个函数，named/route inline/service inline/traffic-split 全部复用；`ctx.upstream_override` 当前绕过 route timeout，因此修改路径必须包含 `src/service/http.rs` 和 `src/plugins/traffic_split.rs`。
4. 给 `Timeout.connect/send/read` 增加 `min=1` 和明确上限；0 不表示无限。
5. 如业务确需无 timeout，未来增加显式 `disabled`，不能用魔法数字。
6. health-check timeout、retry timeout 与 peer I/O timeout 保持独立。

### 兼容与迁移

此前无限等待的请求将被终止。长轮询、流式请求必须在 route/upstream 显式提高 read/send timeout。

### 测试与验收

- 四级优先级和所有 upstream 形态有测试，包括 route timeout 覆盖 named/inline traffic-split upstream。
- 0 被拒绝；无任何配置时三个 peer timeout 都断言为 `Some`。
- 每个 selected `HttpPeer` 都有有限 connect/read/write timeout。
- 慢 upstream 集成测试在边界时间返回网关错误而不是挂起。

---

## P1-7 日志安全、轮转与丢弃指标

### 实现方案

#### 文件安全

- 新文件默认权限从 `0644` 改为 `0600`。
- 校验 parent 是目录；Unix 尽量使用 `O_NOFOLLOW` 防止 symlink target。
- URI、query、UA、referer、自定义变量中的 CR/LF/tab/control character 必须转义，保证单请求只能形成一行日志。

#### 轮转

扩展 `config::Log`：

- `max_size_bytes`：有限默认值；
- `max_backups`：有限默认值；
- `rotation: internal|external|disabled`，默认 `internal`，并给出有限 `max_size_bytes/max_backups`；选择 external/disabled 必须显式配置，避免保留无界默认和与 logrotate 双重管理。

单 writer task 内执行：flush → 关闭 → 备份倒序 rename → current 到 `.1` → 安全重开。失败时转 stderr fallback，不静默丢弃。

#### Backpressure 与指标

增加低基数指标：

- `pingsix_log_messages_dropped_total{reason="buffer_full|channel_closed"}`
- `pingsix_log_write_failures_total`
- `pingsix_log_rotations_total`

channel 满时直接递增计数，不通过同一日志 channel 记录；stderr summary 做节流，避免每条丢弃都打印。

#### Query secret

- `$uri` 保持 path-only。
- 将 `redact_query_params` 加入 `file-logger` 插件配置（而不是全局 `Log`，因为该插件可由动态 route/service/global rule 构建），`$query_string` 按该列表脱敏。
- 文档要求加入所有显式 JWT/key-auth query 参数，并覆盖动态配置发布测试。
- 不新增 Authorization/Cookie 原值日志变量。

### 测试与验收

- Unix 文件权限、阈值轮转、备份数、轮转失败、queue saturation、指标、节流、控制字符、query secret、shutdown flush。
- 默认配置下日志有容量上限或明确使用 stdout 平台轮转。
- 丢日志和写失败可由 Prometheus 观测。

---

## P1-8 明确多实例限流和缓存语义

### 本期策略

不在 P1 引入分布式状态，先让本地语义不可误解、可观测、可验证。

### 实现方案

1. `limit-count` 和 `cache` 配置增加 `scope`，本期只支持 `local`。
2. 默认 `local`；配置 `cluster` 明确报错，不能假装全局生效。
3. 限流：
   - 实现 `PluginRateLimit::response_filter`，消费 request phase 已写入 context 的 quota，在正常上游响应上输出 limit/remaining/reset/scope；拒绝短路路径继续直接写 header；
   - 成功和拒绝响应在 quota header 开启时都返回 `X-RateLimit-Scope: local`；
   - 增加 allowed/rejected counter，label 不得包含原始 key。
4. 缓存：
   - 与 `X-Cache-Status` 一起返回 `X-Cache-Scope: local`；
   - `hide_cache_headers=true` 时一起隐藏；
   - 增加能够准确采集的 hit/miss/bypass 指标。Pingora `simple_lru::Manager` 当前没有现成 eviction callback；只有实现可验证的 wrapper/custom manager 后才增加 eviction counter，否则移入 P2。
5. 文档明确：
   - 集群有效限额约为 `count × 接收请求的副本数`，且受负载分布影响；
   - cache entry、lock、eviction、SWR 都是进程本地。
6. 若运行环境能获知 worker/replica 信息，配置加载时只输出一次提醒，不按请求打印。

### 测试与验收

- 两个独立 limiter 各有完整额度。
- 两个 cache instance 不共享 entry/lock。
- local scope header 和指标正确，且没有高基数原始 key。
- `scope: cluster` 在没有后端时配置失败。
- 配置、响应、指标和用户文档对 local 语义描述一致。

---

# 6. P2 可选增强

以下项目不阻塞 P0/P1 灰度发布，但建议按业务需求选择：

## P2-1 分布式限流

- 使用 Redis/专用限流服务实现原子计数或 token bucket。
- 明确 fail-open/fail-closed、超时、重试、热点 key、时钟和区域语义。
- 保留 `scope: local`，只有配置并验证共享后端时才允许 `scope: cluster`。
- 不建议用 etcd 承担高频数据面计数。

## P2-2 分布式响应缓存

- 选择适合数据面吞吐的共享缓存/对象存储。
- 先定义一致性、序列化、分布式锁、失效、SWR 和容量治理，再实现后端。
- 将敏感响应隔离和 cache key 策略作为设计前置条件。

## P2-3 Secret-preserving Admin PATCH

- 增加 PATCH 或显式 masked-field preservation。
- 允许只修改非敏感字段，而不要求客户端重新提交 secret。
- PUT 继续保持完整替换语义，避免 `"***"` 的隐式魔法行为。

## P2-4 完整异步控制面流水线

- candidate preparation 支持 DNS/TLS material 并发准备、deadline、取消和 revision fencing。
- 发布阶段只做短临界区原子交换。

## P2-5 独立诊断服务

- 将 probe 与 operator diagnostics 拆分为不同 listener/service。
- diagnostics 使用 mTLS/RBAC，而不是仅使用 path-level API key。

## P2-6 工程交付增强

- 精确 MSRV CI、覆盖率、mutation testing。
- Tag release、不可变镜像、SBOM、provenance、cosign、debug symbols。
- 仓库内 Helm 或固定外部 chart 版本，并用 kind/k3d 验证。
- etcd snapshot/restore、升级/降级和灾备演练。
- Dashboard、alert rules、SLO、OpenTelemetry。
- 可重复 benchmark 和容量回归门禁。
- 所有插件配置增加 `deny_unknown_fields` 和 JSON Schema。

---

# 7. 分阶段实施顺序

## 阶段 A：安全与协议正确性

可并行实施：

1. P0-1 Admin 脱敏。
2. P0-2 `Vary: *`。
3. P0-4 etcd scheme/TLS 校验。
4. P0-5 CORS 预检。
5. P1-2 JWT cookie 隐藏。
6. P1-3 Key Auth query 默认关闭。

阶段门禁：所有 focused unit tests、全量测试、Clippy 通过；完成兼容性说明。

## 阶段 B：控制面一致性

1. P0-3 graph guard transaction。
2. 真实 etcd 并发测试。
3. guard/list/watch/revision 状态统一。

阶段门禁：并发 mutation 不能制造无效图；故障后 last-known-good 和重试行为验证通过。

## 阶段 C：可靠性默认值

1. P1-6 upstream timeout。
2. P1-1 readiness 默认策略。
3. P1-4 status diagnostics 隔离。

阶段门禁：慢 upstream、etcd 短断/长断/恢复、公开探针信息泄露测试通过。

## 阶段 D：控制面性能与运维

1. P1-5 DNS 非阻塞化。
2. P1-7 日志安全、轮转、指标。
3. P1-8 local scope 语义与指标。

阶段门禁：DNS 卡死不阻塞配置、日志压力可观测、双实例语义测试通过。

## 阶段 E：灰度前系统验证

- TLS listener 和动态证书更新。
- Admin CRUD/CAS 冲突。
- etcd list/watch/断线/恢复/compaction。
- SIGTERM、连接 draining、超时退出。
- CORS live proxy 测试。
- 缓存 `Vary: *` 和认证隔离。
- DNS timeout 和 last-known-good。
- 两进程限流/缓存 local semantics。
- 容器 smoke 和可选 kind/k3d rolling update。

---

# 8. 测试与 CI 方案

## 8.1 每个提交的基础门禁

```bash
cargo fmt --all -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo audit
```

## 8.2 新增集成测试分组

建议新增 `tests/` 与 `ci/` fixture：

- `tests/admin_etcd_concurrency.rs`
- `tests/etcd_tls.rs`
- `tests/cors_preflight.rs`
- `tests/cache_vary.rs`
- `tests/readiness_recovery.rs`
- `tests/upstream_timeout.rs`
- `tests/dns_update.rs`
- `tests/graceful_shutdown.rs`
- `tests/multi_instance_semantics.rs`

CI 使用独立 integration job 和 service container/Docker Compose 启动真实 etcd 与 mock upstream。外部依赖测试通过独立 feature、专用 test target 或 `#[ignore]` 分组执行，默认 `cargo test` 在无 Docker、无 etcd 环境仍可通过。每个 fault test 必须设置 Tokio/进程 timeout，并在成功或失败后断言清理子进程与容器、收集 gateway/etcd/upstream 日志。

## 8.3 非功能验证

- 对日志 queue saturation、DNS 卡死、etcd outage 做 fault injection。
- 对配置热更新做持续请求，验证没有半配置状态。
- 对 cache/auth 组合做数据隔离测试。
- 对动态配置做长时间 soak，监控内存、线程和 health-check task 数量。

---

# 9. 配置与发布迁移清单

P0/P1 会产生以下有意的行为变化，必须进入 release notes：

1. `https://` etcd endpoint 没有 TLS block 时启动失败。
2. etcd user/password 必须成对配置。
3. Key Auth 不再默认读取 `?apikey=`；需改 header 或显式配置 query。
4. `hide_credentials=true` 时 JWT cookie 不再转发 upstream。
5. `Vary: *` 响应不再缓存，`cache.vary: ["*"]` 被拒绝。
6. stale etcd 默认在阈值后使 readiness 失败。
7. 未配置 upstream timeout 时启用有限 built-in 默认值。
8. 非 loopback `/status/config` 默认禁用；兼容场景需 API key 与 `allow_insecure_remote` 双重显式 opt-in。
9. 日志文件权限、轮转和控制字符输出发生变化。
10. 限流和缓存明确声明 `scope: local`。
11. 生产动态配置写入必须通过 Admin API 或遵守 graph guard transaction。

建议至少发布一个预发布版本，在 staging 使用真实配置跑迁移检查器后再进入灰度。

---

# 10. 完成定义（Definition of Done）

P0/P1 只有同时满足以下条件才算完成：

- [ ] 每个 P0/P1 项均有对应代码提交和 focused regression test。
- [ ] 所有 P0 安全与一致性问题通过真实或等价集成测试验证。
- [ ] `cargo fmt`、Clippy、全量测试、依赖审计通过。
- [ ] 配置示例和 `USER_GUIDE.md` 与新默认值一致。
- [ ] 兼容性变化有迁移说明。
- [ ] 真实 etcd 动态更新、恢复和并发测试通过。
- [ ] 慢 DNS、慢 upstream、日志压力和 SIGTERM 测试有明确 deadline。
- [ ] 公开 status endpoint 不泄露内部错误或 secret。
- [ ] 限流和缓存的 local scope 在配置、响应头、指标和文档中一致。
- [ ] staging 持续压测和故障演练没有未解决的 P0/P1 问题。
- [ ] graph guard 有明确升级/混跑/回滚协议；不支持 guard 的旧版本被阻止回滚，或已通过兼容过渡版本和混跑测试证明安全。

完成上述条件后，项目可进入小流量灰度；P2 按容量、合规和多集群需求逐项选择实施。

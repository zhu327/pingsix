# DNS 控制面非阻塞化实施计划

> 对应生产就绪计划：P1-5 DNS 不阻塞控制面  
> 状态：待实施  
> 目标：任何 DNS 解析（慢、超时、永不返回、失败）均不得在控制面 writer lock 内等待，也不得阻塞 etcd list/watch 对后续配置的处理。

## 1. 当前问题与约束

当前调用链为：

```text
EtcdConfigSync list/watch
  -> ProxyEventHandler
  -> ControlPlane::replace_all / apply_events
  -> CandidateSnapshot::build
  -> ProxyUpstream::build
  -> LB::try_from
  -> eager_discover_backends
  -> helper OS thread + Tokio runtime + join()
```

`eager_discover_backends()` 的 `join()` 会同步等待 `LoadBalancer::update()`；DNS lookup 没有明确 deadline。`ControlPlane` 在 build/publish 期间持有 writer lock，因而一个 DNS upstream 能阻塞：

- etcd watch 消费和后续动态配置发布；
- Admin 更新最终生效；
- control-plane shutdown；
- 任何与该 writer lock 串行的完整配置替换。

同时，不能简单删除 eager wait：新 DNS-only upstream 在首次成功解析前若发布，会产生“配置已发布、但没有可选 backend”的瞬时或永久无流量状态。替换已有 upstream 时 DNS 失败也不得以空 backend 覆盖 last-known-good。

## 2. 完成语义

### 2.1 发布规则

1. 静态 IP upstream：同步准备，维持当前首次发布即有 backend 的语义。
2. 新 DNS-only upstream：首次 DNS 解析成功且至少存在一个 backend 后才允许发布。
3. DNS + 静态节点的混合 upstream：静态 backend 可立即成为可发布候选；DNS 结果在 deadline 内成功则一并加入，失败只记录降级，不阻塞发布。
4. 替换已有 DNS upstream：解析失败或 deadline 时保留当前已发布 snapshot；不得发布 backend 为空的 replacement。
5. 路由、service、global rule 等不影响 DNS upstream 的更新：不等待 DNS，保持当前快速 publish 路径。
6. 管理面写入仍只代表 etcd transaction 已提交；DNS preparation 的失败通过结构化日志和指标表达，不能伪装成已成功的数据面激活。

### 2.2 一致性与顺序

- 每个候选都携带来源 `generation`（控制面内部单调递增）和 etcd `revision`。
- preparation 完成时，仅当 generation 仍是最新目标 generation 才可尝试 publish。
- 新事件到达时，旧 preparation 必须取消或在完成时被 fencing 丢弃。
- 相同 revision 的 guard metadata event 不应创建 DNS preparation。
- 失败 preparation 不提交 raw graph，不替换 runtime snapshot，不更新 published revision。

### 2.3 Shutdown

- 所有 DNS preparation task 由单一 worker owner 管理。
- shutdown signal 到达后：停止接收新任务、取消 in-flight task、在有限 deadline 内 await task 停止。
- 不得依赖 OS thread `join()`；不允许 task 泄漏。

## 3. 目标架构

采用**两阶段候选准备 + 有界单 worker/队列**，而不是在 etcd callback 中直接 spawn 无限 task。

```text
etcd list/watch
  -> ControlPlane::submit_update(raw candidate, revision)
  -> bounded preparation queue
  -> ControlPlanePreparationWorker
       - 在锁外计算 DNS 依赖
       - 受 timeout / concurrency / cancellation 控制
       - 返回 PreparedCandidate(generation, revision, raw, prepared upstream material)
  -> ControlPlane::commit_prepared
       - 短 writer lock
       - generation/revision fence
       - compile + atomic runtime publish + raw commit
```

### 3.1 新组件

#### `PreparedUpstream`

在 `src/proxy/upstream/` 新增仅包含已解析 backend 的准备表示，至少包含：

- upstream id / inline identity；
- 原始 `config::Upstream`；
- 已解析 `BTreeSet<Backend>`；
- discovery outcome（static-only、DNS success、DNS timeout、DNS error、partial）；
- 可选的解析耗时。

它不得持有对旧 runtime snapshot 的可变引用。

#### `CandidatePreparation`

在 `src/proxy/control_plane.rs` 或新模块中定义：

```rust
struct CandidatePreparation {
    generation: u64,
    revision: i64,
    raw: ResourceConfigSet,
    changed_upstreams: HashSet<UpstreamKey>,
    cancellation: CancellationToken,
}
```

`UpstreamKey` 要覆盖：

- named upstream；
- route inline upstream；
- service inline upstream；
- traffic-split inline upstream。

先以 named upstream 为核心路径实现；所有 inline 构造点必须复用同一 prepare helper，避免绕过。

#### `ControlPlanePreparationWorker`

- 由 `EtcdConfigSync`/main 在启动时创建，持有 bounded `mpsc` receiver。
- queue 满时采用 **coalesce latest** 策略：保留最新 full raw candidate，取消较旧 pending/in-flight preparation；不得无限堆积 revision。
- 初始容量建议 1 或 2。控制面只需要最新配置，旧候选无业务价值。
- worker 内使用 `tokio::task::JoinSet` + `Semaphore` 控制 upstream DNS 并发，默认 8。
- preparation 仅使用 Tokio task，禁止创建每 upstream OS thread。

## 4. 配置设计

在 `Pingsix` 或 `Defaults` 引入控制面 DNS 配置（建议集中在 `pingsix.defaults`）：

```yaml
pingsix:
  defaults:
    dns_resolution_timeout: 5   # 秒，默认 5，范围 1..=60
    dns_resolution_concurrency: 8 # 默认 8，范围 1..=64
```

若避免首版新增并发配置，可先只公开 `dns_resolution_timeout`，并采用固定安全并发 8；但实现内部仍必须使用 semaphore。

校验：

- timeout 为 0 或超过上限：启动失败；
- 并发为 0 或超过上限：启动失败；
- 配置未给出时使用有限默认值。

## 5. 分阶段实施

### 阶段 1：消除无界等待基础

**文件**

- `src/config/mod.rs`
- `src/main.rs`
- `src/proxy/upstream/discovery.rs`
- `src/proxy/upstream/load_balancer.rs`

**改动**

1. 新增并初始化 DNS timeout defaults。
2. 为 DNS resolver lookup 增加 `tokio::time::timeout`，将超时映射为明确 `DnsResolutionTimeout`/configuration error 类别。
3. 删除 `eager_discover_backends` 的 helper-thread + `join()` 实现。
4. 把 `LoadBalancer` 构造拆成：
   - `from_prepared_backends(...)`：已拥有 backend 的同步构造；
   - `from_discovery(...)`：后续 health-check/background refresh 使用 discovery。
5. 保持静态 `now_or_never()` 快路径，确保纯 IP upstream 行为不回归。

**退出条件**

源码控制面路径不存在 `.join()`；DNS lookup 有有限 deadline。

### 阶段 2：候选 preparation API

**文件**

- 新建 `src/proxy/preparation.rs` 或扩展 `control_plane.rs`
- `src/proxy/upstream/mod.rs`
- `src/proxy/upstream/discovery.rs`
- `src/proxy/runtime.rs`

**改动**

1. 从 `CandidateSnapshot::build` 提取 upstream preparation。
2. `CandidateSnapshot::build` 接收可选 prepared material，构造时不再触发 DNS I/O。
3. 只有配置变更的 upstream 被解析；未变 upstream 复用当前 Arc。
4. 新 DNS-only upstream 若 preparation 无 backend：返回 `PendingDns`，不构建 publishable candidate。
5. replacement DNS failure：返回 preparation failure，调用方保留 last-known-good。

**退出条件**

`CandidateSnapshot::build` 不调用 async DNS、不创建 runtime、不阻塞等待 discovery。

### 阶段 3：异步 control-plane worker 和 fencing

**文件**

- `src/config/etcd.rs`
- `src/proxy/event.rs`
- `src/proxy/control_plane.rs`
- `src/main.rs`

**改动**

1. 将 `EtcdEventHandler` 转为 async，或保留同步 trait 但改为只入队；推荐 async trait 以便 list/watch 等待“已接收/合并”，而不是等待 DNS。
2. `ControlPlane::submit_*`：在短锁内复制/合并 raw candidate、分配 generation、取消旧 preparation、入队，立即返回。
3. worker 在锁外 prepare。
4. `commit_prepared`：短锁内验证：
   - generation 仍等于 latest generation；
   - revision 不低于已发布 revision；
   - raw candidate 仍为 latest；
   - cancellation 未触发。
5. 验证成功后 compile、`ArcSwap` publish、raw commit、published status update。
6. preparation error：记录 status/metric，不提交 raw；下一次 list/watch 可重试。

**重要决定**

由于 etcd 的 raw graph 与 runtime snapshot 必须一致，不能在 DNS failure 时把新 raw graph 作为已提交 raw state。worker 应持有 pending candidate，成功 publish 后才提交。

**退出条件**

一个永不完成的 DNS candidate 不会阻止后续纯静态 candidate 在 deadline 内发布。

### 阶段 4：后续 DNS refresh

初始解析与运行期 refresh 分离：

- 初始解析必须成功才发布新 DNS-only upstream；
- 已发布 upstream 后的 background refresh 仍可失败，但 `LoadBalancer` 保留上次 backend；
- refresh failure 增加指标和节流日志，不能清空已知 backend。

检查 Pingora `LoadBalancer::update()` 的 failure 行为；如其会清空 backend，需在 `DnsDiscovery`/wrapper 中保证失败返回不触发替换，或实现 retaining discovery wrapper。

### 阶段 5：可观测性

新增低基数 Prometheus 指标：

- `pingsix_dns_resolution_total{outcome="success|timeout|error|cancelled"}`
- `pingsix_dns_resolution_duration_seconds`
- `pingsix_control_plane_preparation_total{outcome="published|stale|failed|cancelled"}`
- `pingsix_control_plane_preparation_queue_depth`
- `pingsix_control_plane_pending_dns_upstreams`

日志要求：

- 包含 upstream id、revision、generation、outcome、duration；
- 不记录 URI userinfo、凭据或完整动态请求数据；
- timeout/error 日志节流，防止频繁 etcd 更新造成噪音。

## 6. 错误策略

| 场景 | 动作 | Runtime / readiness |
|---|---|---|
| 新 DNS-only upstream timeout | 不发布候选，保留旧 snapshot | 已有 snapshot 保持；首次启动仍 Not Ready |
| 替换 DNS upstream timeout | 不发布 replacement | old snapshot 保持 Ready；记录 degraded metric/log |
| 混合 static + DNS timeout | 可发布静态 backend 候选 | Ready；记录 partial outcome |
| DNS task cancelled | 丢弃结果 | 不影响 newer candidate |
| queue 满 | coalesce 到最新 generation | 不无限排队 |
| worker panic | 记录 fatal control-plane error并重启 worker/触发 relist | 不发布半配置 |
| etcd watch 断开 | 取消/保留 pending，按最新 list 重建 | 使用既有 stale readiness 策略 |

## 7. 验证计划（实现后执行）

尽管当前优先实现，以下验证是此设计的完成条件：

1. pending resolver + 后续 static event：static event 在小于 DNS timeout 的时间内发布。
2. DNS timeout：候选不发布，runtime 和 raw graph 保持 last-known-good。
3. 新 DNS-only upstream：首个 DNS success 前不 publish；success 后 publish。
4. replacement：旧 backend 在 replacement resolve failure 时仍可选择。
5. revision fencing：慢 revision N 完成于快速 revision N+1 后，N 的结果被丢弃。
6. shutdown：pending task 在 shutdown deadline 内取消；无 OS thread join。
7. 并发：多个 DNS upstream 不超过配置 semaphore 数。
8. static IP 回归：首次 publish 仍有可选 backend。
9. 长时间 churn：task 数、内存、health-check registration 不增长。

## 8. 迁移与发布

- `dns_resolution_timeout` 为新有限默认值，需写入 `config.yaml` 与 `USER_GUIDE.md`。
- 发布说明：DNS-only dynamic update 的 Admin 成功仅表示 etcd 已提交；数据面激活受 DNS preparation 控制。
- staging 灰度先收集 resolution outcome、queue depth、candidate stale/cancelled 指标。
- 回滚前必须确认旧版本不会重新引入 blocking DNS path；若需回滚，应排空/停止动态 DNS 变更并观察 pending queue 为零。

## 9. 非目标

本项不实现：

- 服务发现结果的跨实例共享；
- DNS over HTTPS / 自定义 resolver 管理 API；
- 未设计的 Admin “pending DNS” 状态 API；
- 将 etcd 作为 DNS/endpoint 高频数据面存储。

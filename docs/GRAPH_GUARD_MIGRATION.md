# Graph guard 升级与回滚协议

PingSIX Admin API 使用 `<etcd-prefix>/.pingsix_graph_revision` 串行化配置图修改。当前 guard value 为 `pingsix-graph-v1`。

## 写入约束

- 生产配置写入必须经过当前版本 Admin API。
- 外部 writer 必须在同一 etcd transaction 中比较 guard revision、修改资源并更新 guard。
- 不更新 guard 的单 key writer 不受一致性保证支持。
- 当前代码不再暴露单 key CAS mutation API，避免新代码意外绕过 graph transaction。

## 升级

1. 停止旧 Admin writer，或先部署所有 writer 都支持 `pingsix-graph-v1` 的兼容版本。
2. 确认没有直接写 etcd 的自动化任务。
3. 部署新版本；第一次 Admin mutation 会原子创建 guard。
4. 观察 Admin 409、observed/published revision 和 control-plane preparation 指标。
5. 完成真实 etcd 并发及故障恢复验证后再扩大流量。

## 回滚

创建 guard 后，不得回滚到执行单 key CAS、且不知道 graph guard 的版本。旧二进制无法被新代码远程阻止写入，因此回滚必须由发布系统阻断。

允许回滚的目标版本必须同时满足：

- 识别并过滤 `.pingsix_graph_revision`；
- 所有 Admin mutation 使用相同 graph transaction；
- guard protocol 与 `pingsix-graph-v1` 兼容。

紧急回滚时应先停止所有 Admin 写流量，再回滚到兼容版本；不得删除 guard 来兼容旧 writer。

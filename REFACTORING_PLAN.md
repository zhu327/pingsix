# PingSIX 循环依赖重构计划

## 🎯 目标
消除模块间的循环依赖，建立清晰的分层架构，提升代码的可维护性和可测试性。

## 📊 当前问题分析

### 识别的循环依赖
1. **proxy模块内部循环**：route ↔ service ↔ upstream
2. **service ↔ proxy双向依赖**：service/http.rs ↔ proxy/route.rs
3. **plugin ↔ proxy循环**：plugin/mod.rs ↔ proxy/mod.rs

### 问题根因
- 缺乏清晰的抽象层次
- 模块间直接函数调用过多
- 全局状态管理分散
- 缺乏依赖注入机制

## 🏗️ 新架构设计

### 分层结构
```
Layer 6: Application (main, admin)
Layer 5: Service (HTTP服务实现)
Layer 4: Orchestration (请求编排和协调)
Layer 3: Core Logic (业务逻辑实现)
Layer 2: Plugin System (插件系统)
Layer 1: Foundation (配置、工具、日志)
```

### 核心原则
- **单向依赖**：高层依赖低层，低层不依赖高层
- **接口隔离**：通过trait进行抽象
- **依赖注入**：通过容器管理依赖关系
- **资源集中管理**：统一的注册中心

## 📅 实施计划

### 阶段1：基础设施（第1-2天）
- [ ] 创建 `src/core/` 模块
- [ ] 定义核心trait和接口
- [ ] 实现资源注册中心
- [ ] 创建依赖注入容器

### 阶段2：核心重构（第3-5天）
- [ ] 重构proxy模块结构
- [ ] 消除route/service/upstream循环依赖
- [ ] 实现新的资源解析机制
- [ ] 更新错误处理机制

### 阶段3：插件系统重构（第6-7天）
- [ ] 重构插件接口定义
- [ ] 实现插件管理器
- [ ] 更新所有插件实现
- [ ] 测试插件系统功能

### 阶段4：服务层重构（第8-9天）
- [ ] 重构HTTP服务实现
- [ ] 更新请求处理流程
- [ ] 集成新的依赖注入机制
- [ ] 性能测试和优化

### 阶段5：测试和验证（第10天）
- [ ] 全面回归测试
- [ ] 性能基准测试
- [ ] 功能验证测试
- [ ] 文档更新

## 🔧 技术实施细节

### 1. 核心接口定义
```rust
// src/core/traits.rs
pub trait ResourceProvider<T> {
    fn get(&self, id: &str) -> Option<Arc<T>>;
    fn list(&self) -> Vec<Arc<T>>;
}

pub trait RouteResolver {
    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamProvider>>;
    fn resolve_service(&self) -> Option<Arc<dyn ServiceProvider>>;
}

pub trait RequestHandler {
    async fn handle_request(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<bool>;
}
```

### 2. 资源注册中心
```rust
// src/core/registry.rs
pub struct ResourceRegistry {
    routes: DashMap<String, Arc<ProxyRoute>>,
    upstreams: DashMap<String, Arc<ProxyUpstream>>,
    services: DashMap<String, Arc<ProxyService>>,
}

impl ResourceRegistry {
    pub fn new() -> Self { /* ... */ }
    
    // 统一的资源访问接口
    pub fn get_route(&self, id: &str) -> Option<Arc<ProxyRoute>>;
    pub fn get_upstream(&self, id: &str) -> Option<Arc<ProxyUpstream>>;
    pub fn get_service(&self, id: &str) -> Option<Arc<ProxyService>>;
    
    // 批量操作
    pub fn reload_routes(&self, routes: Vec<Arc<ProxyRoute>>);
    pub fn reload_upstreams(&self, upstreams: Vec<Arc<ProxyUpstream>>);
}
```

### 3. 依赖注入容器
```rust
// src/core/container.rs
pub struct ServiceContainer {
    registry: Arc<ResourceRegistry>,
    plugin_manager: Arc<PluginManager>,
    config_manager: Arc<ConfigManager>,
    health_checker: Arc<HealthCheckService>,
}

impl ServiceContainer {
    pub fn new() -> Self { /* ... */ }
    pub fn registry(&self) -> &ResourceRegistry;
    pub fn plugin_manager(&self) -> &PluginManager;
}
```

## 🔄 迁移策略

### 向后兼容性
- 保持现有API接口不变
- 逐步迁移内部实现
- 使用feature flag控制新旧实现

### 渐进式重构
1. **新增模块**：先创建新的抽象层
2. **双轨运行**：新旧实现并存
3. **逐步迁移**：模块逐个切换到新实现
4. **清理旧代码**：移除废弃的实现

## 📈 预期收益

### 代码质量提升
- 消除循环依赖
- 提高代码可测试性
- 增强模块内聚性
- 降低耦合度

### 开发体验改善
- 更清晰的模块职责
- 更容易的单元测试
- 更好的IDE支持
- 更快的编译时间

### 性能优化
- 减少运行时查找
- 更好的缓存局部性
- 优化的资源管理
- 降低内存占用

## ⚠️ 风险评估

### 潜在风险
- 重构期间的稳定性风险
- 性能回归风险
- API兼容性风险

### 风险缓解
- 全面的测试覆盖
- 性能基准对比
- 渐进式迁移策略
- 回滚机制准备

## 📋 检查清单

### 重构前准备
- [ ] 建立完整的测试套件
- [ ] 创建性能基线
- [ ] 备份当前实现
- [ ] 制定回滚计划

### 重构过程监控
- [ ] 编译时间监控
- [ ] 测试通过率监控
- [ ] 性能指标监控
- [ ] 内存使用监控

### 重构后验证
- [ ] 功能完整性验证
- [ ] 性能对比验证
- [ ] 安全性验证
- [ ] 文档完整性验证
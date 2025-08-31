# 🔄 PingSIX 循环依赖重构指南

## 📊 当前依赖问题诊断

### 🔴 主要循环依赖

1. **proxy模块内部循环**
   ```
   route.rs ──→ service.rs ──→ upstream.rs
      ↑                           │
      └───────────────────────────┘
   ```

2. **service ↔ proxy 双向依赖**
   ```
   service/http.rs ←──→ proxy/route.rs
   ```

3. **plugin ↔ proxy 循环**
   ```
   plugin/mod.rs ←──→ proxy/mod.rs
   ```

### 🔍 根本原因
- **直接函数调用**：`upstream_fetch()`, `service_fetch()` 等全局函数
- **共享状态分散**：各模块都有自己的全局DashMap
- **缺乏抽象层**：具体实现间直接依赖
- **责任混淆**：模块职责边界不清晰

## 🎯 重构目标

### ✅ 期望达成的效果
- 消除所有循环依赖
- 建立清晰的分层架构
- 提高代码可测试性
- 降低模块耦合度
- 提升编译速度

### 📏 成功指标
- 编译时间减少 20%+
- 单元测试覆盖率提升到 80%+
- 模块间依赖关系变为单向
- 代码复杂度降低

## 🏗️ 新架构设计

### 分层架构
```
┌─────────────────┐
│   Application   │ ← main.rs, admin/
├─────────────────┤
│    Service      │ ← service/http.rs
├─────────────────┤
│ Orchestration   │ ← 新增：请求编排层
├─────────────────┤
│   Core Logic    │ ← proxy/route.rs, upstream.rs, service.rs
├─────────────────┤
│ Plugin System   │ ← plugin/
├─────────────────┤
│   Foundation    │ ← config/, utils/, logging/
└─────────────────┘
```

### 核心组件

1. **ResourceRegistry** - 统一资源管理
2. **ServiceContainer** - 依赖注入容器
3. **RequestOrchestrator** - 请求编排器
4. **PluginManager** - 插件管理器

## 🔧 详细重构步骤

### 步骤1：创建核心抽象层

#### 1.1 创建 `src/core/` 模块
```bash
mkdir -p src/core
```

#### 1.2 定义核心trait
```rust
// src/core/traits.rs
pub trait UpstreamProvider: Send + Sync {
    fn select_backend(&self, session: &Session) -> Option<Backend>;
    fn id(&self) -> &str;
}

pub trait RouteResolver: Send + Sync {
    fn resolve_upstream(&self) -> Option<Arc<dyn UpstreamProvider>>;
    fn select_http_peer(&self, session: &mut Session) -> ProxyResult<Box<HttpPeer>>;
}
```

#### 1.3 实现资源注册中心
```rust
// src/core/registry.rs
pub struct ResourceRegistry {
    routes: DashMap<String, Arc<dyn RouteResolver>>,
    upstreams: DashMap<String, Arc<dyn UpstreamProvider>>,
    services: DashMap<String, Arc<dyn ServiceProvider>>,
}
```

### 步骤2：重构proxy模块

#### 2.1 更新proxy/route.rs
```rust
// 移除直接的函数调用
// 旧代码：
// use super::{service::service_fetch, upstream::upstream_fetch};

// 新代码：
use crate::core::{registry::ResourceRegistry, traits::*};

impl ProxyRoute {
    // 通过注册中心解析依赖
    pub fn resolve_upstream(&self, registry: &ResourceRegistry) -> Option<Arc<dyn UpstreamProvider>> {
        if let Some(upstream_id) = &self.inner.upstream_id {
            return registry.get_upstream(upstream_id);
        }
        
        if let Some(service_id) = &self.inner.service_id {
            if let Some(service) = registry.get_service(service_id) {
                return service.get_upstream_provider();
            }
        }
        
        self.upstream.clone()
    }
}
```

#### 2.2 更新proxy/upstream.rs
```rust
// 移除全局状态，改为通过注册中心管理
// 旧代码：
// static UPSTREAM_MAP: Lazy<DashMap<String, Arc<ProxyUpstream>>> = ...

// 新代码：实现UpstreamProvider trait
impl UpstreamProvider for ProxyUpstream {
    fn select_backend(&self, session: &Session) -> Option<Backend> {
        // 现有逻辑保持不变
    }
    
    fn id(&self) -> &str {
        &self.inner.id
    }
}
```

### 步骤3：重构插件系统

#### 3.1 创建插件接口层
```rust
// src/plugin/interface.rs
use crate::core::{ProxyContext, ProxyResult};

#[async_trait]
pub trait PluginInterface: Send + Sync {
    fn name(&self) -> &str;
    fn priority(&self) -> i32;
    
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut ProxyContext,
    ) -> ProxyResult<bool>;
}
```

#### 3.2 实现插件管理器
```rust
// src/plugin/manager.rs
pub struct PluginManager {
    plugins: Vec<Arc<dyn PluginInterface>>,
    registry: Arc<ResourceRegistry>,
}

impl PluginManager {
    pub fn build_executor(&self, plugin_configs: &HashMap<String, JsonValue>) -> Arc<dyn PluginExecutor> {
        // 构建插件执行器，不直接依赖具体插件实现
    }
}
```

### 步骤4：重构服务层

#### 4.1 更新service/http.rs
```rust
// 通过依赖注入获取依赖
pub struct HttpService {
    container: Arc<ServiceContainer>,
}

impl HttpService {
    pub fn new(container: Arc<ServiceContainer>) -> Self {
        Self { container }
    }
}

#[async_trait]
impl ProxyHttp for HttpService {
    async fn early_request_filter(&self, session: &mut Session, ctx: &mut ProxyContext) -> Result<()> {
        // 通过容器获取路由匹配器
        let router = self.container.get_router();
        if let Some(route) = router.match_request(session) {
            ctx.route = Some(route);
        }
        Ok(())
    }
}
```

### 步骤5：创建编排层

#### 5.1 实现请求路由器
```rust
// src/orchestration/router.rs
pub struct RequestRouter {
    registry: Arc<ResourceRegistry>,
    matcher: RouteMatchEngine,
}

impl RequestRouter {
    pub fn match_request(&self, session: &Session) -> Option<Arc<dyn RouteResolver>> {
        // 路由匹配逻辑
    }
}
```

#### 5.2 实现请求执行器
```rust
// src/orchestration/executor.rs
pub struct RequestExecutor {
    registry: Arc<ResourceRegistry>,
    plugin_manager: Arc<PluginManager>,
}

impl RequestExecutor {
    pub async fn execute_request(&self, session: &mut Session) -> ProxyResult<()> {
        // 统一的请求执行流程
    }
}
```

## 📋 迁移检查清单

### 阶段1：准备工作
- [ ] 创建完整的测试套件
- [ ] 建立性能基线
- [ ] 创建 `src/core/` 模块结构
- [ ] 定义所有核心trait

### 阶段2：核心重构
- [ ] 实现ResourceRegistry
- [ ] 实现ServiceContainer
- [ ] 重构proxy/upstream.rs实现UpstreamProvider
- [ ] 重构proxy/service.rs实现ServiceProvider
- [ ] 重构proxy/route.rs实现RouteResolver

### 阶段3：插件系统
- [ ] 创建PluginInterface
- [ ] 实现PluginManager
- [ ] 迁移所有插件实现
- [ ] 更新插件注册机制

### 阶段4：服务层
- [ ] 重构service/http.rs使用依赖注入
- [ ] 创建编排层组件
- [ ] 更新main.rs的初始化流程
- [ ] 更新admin API使用新架构

### 阶段5：验证和清理
- [ ] 运行所有测试
- [ ] 性能基准对比
- [ ] 清理废弃代码
- [ ] 更新文档

## ⚡ 性能优化建议

### 编译时优化
```rust
// 使用泛型而不是trait对象减少动态分发
pub struct TypedRegistry<R, U, S> {
    routes: DashMap<String, Arc<R>>,
    upstreams: DashMap<String, Arc<U>>,
    services: DashMap<String, Arc<S>>,
}
```

### 运行时优化
```rust
// 缓存解析结果
pub struct CachedRouteResolver {
    inner: Arc<dyn RouteResolver>,
    upstream_cache: Arc<RwLock<Option<Arc<dyn UpstreamProvider>>>>,
}
```

## 🛡️ 风险缓解策略

### 1. 渐进式迁移
- 使用feature flag控制新旧实现
- 保持API兼容性
- 模块级别的渐进切换

### 2. 回滚机制
```rust
// 配置开关
#[cfg(feature = "new-architecture")]
use crate::core::registry::ResourceRegistry;

#[cfg(not(feature = "new-architecture"))]
use crate::proxy::route::ROUTE_MAP;
```

### 3. 监控和验证
- 编译时间监控
- 运行时性能对比
- 内存使用分析
- 功能完整性验证

## 📈 预期收益

### 代码质量
- ✅ 消除循环依赖
- ✅ 提高模块内聚性
- ✅ 降低耦合度
- ✅ 增强可测试性

### 开发效率
- ✅ 更快的编译时间
- ✅ 更好的IDE支持
- ✅ 更容易的单元测试
- ✅ 更清晰的错误信息

### 运行时性能
- ✅ 减少动态查找
- ✅ 更好的缓存局部性
- ✅ 优化的资源管理
- ✅ 降低内存碎片

## 🚀 开始实施

推荐按以下顺序开始重构：

1. **立即开始**：创建core模块和基础trait
2. **第一周**：重构proxy模块消除内部循环依赖
3. **第二周**：重构插件系统和服务层
4. **第三周**：性能优化和测试完善

每个阶段都应该保持代码可编译和测试通过，确保渐进式改进。
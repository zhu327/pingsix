//! Request orchestration layer
//!
//! This module provides the orchestration layer that coordinates
//! between different components without creating circular dependencies.

pub mod router;
pub mod executor;
pub mod lifecycle;

pub use router::RequestRouter;
pub use executor::RequestExecutor;
pub use lifecycle::ComponentLifecycle;
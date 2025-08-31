//! Core abstractions and interfaces for PingSIX
//!
//! This module provides the foundational traits, types, and utilities
//! that form the backbone of the PingSIX architecture.

pub mod context;
pub mod error;
pub mod registry;
pub mod traits;
pub mod container;
pub mod loader;

#[cfg(test)]
mod tests;

// Re-export commonly used types
pub use context::ProxyContext;
pub use error::{ProxyError, ProxyResult};
pub use registry::ResourceRegistry;
pub use traits::*;
pub use container::ServiceContainer;
pub use loader::ResourceLoader;
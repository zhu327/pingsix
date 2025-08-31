//! This module contains the core logic of the PingSIX API gateway.
//!
//! It defines the main modules for configuration, proxying, and service management.

pub mod admin;
pub mod config;
pub mod core;
pub mod logging;
pub mod orchestration;
pub mod plugin;
pub mod proxy;
pub mod service;
pub(crate) mod utils;

//! This module contains the core logic of the PingSIX API gateway.
//!
//! It defines the main modules for configuration, proxying, and service management.

pub mod admin;
pub mod config;
pub mod core;
pub mod logging;
pub mod migration;
pub mod orchestration;
pub mod plugin;
pub mod proxy;
pub mod service;
pub(crate) mod utils;

// New main entry point for the refactored architecture
pub mod new_main;

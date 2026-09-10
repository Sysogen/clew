// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The clew domain: what an agent surface is, how a path is classified as one,
//! and the policy governing a scan.
//!
//! This crate depends on nothing but `thiserror`. No filesystem, no network, no
//! async runtime. Every capability it needs from the outside world is a trait
//! in [`ports`], implemented by an adapter.

pub mod catalog;
pub mod hook;
pub mod ports;
pub mod repo_path;
pub mod scan_policy;
pub mod surface;
pub mod tools;

pub use catalog::classify;
pub use hook::Hook;
pub use repo_path::RepoPath;
pub use scan_policy::ScanPolicy;
pub use surface::{Surface, SurfaceKind};

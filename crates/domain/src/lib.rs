// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The clew domain: what an agent surface is, how a path is classified as one,
//! and the policy governing a scan.
//!
//! This crate depends on parsers, matchers and data only: no filesystem, no
//! network, no async runtime, nothing that starts a process. Every capability
//! it needs from the outside world is a trait in [`ports`], implemented by an
//! adapter.
//!
//! The constraint is on what a dependency may do, not how many there are. A
//! format parser, a glob matcher, Unicode's own property data and a shell
//! grammar all belong here; `std::fs` and `std::net` do not, and an outbound
//! adapter is the only place they appear.

pub mod autonomy;
pub mod catalogue;
pub mod credential;
pub mod explain;
pub mod extract;
pub mod finding;
pub mod hook;
pub mod mcp_server;
pub mod pack;
pub mod permission;
pub mod ports;
pub mod repo_path;
pub mod rule;
pub mod rules;
pub mod scan_policy;
pub mod scope;
pub mod secrets;
pub mod shell;
pub mod surface;
pub mod task;

pub use autonomy::Autonomy;
pub use catalogue::{Catalogue, shipped as catalogue};
pub use hook::Hook;
pub use mcp_server::{McpServer, Transport};
pub use permission::Permission;
pub use repo_path::RepoPath;
pub use scan_policy::ScanPolicy;
pub use surface::{Surface, SurfaceKind};
pub use task::Task;

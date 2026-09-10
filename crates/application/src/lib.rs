// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Use cases for clew.
//!
//! This layer coordinates domain operations over the ports. It performs no
//! input or output of its own: everything it touches arrives through a trait
//! defined in `clew_domain::ports`.

pub mod discover_surfaces;

pub use discover_surfaces::{DiscoverSurfaces, DiscoveryReport};

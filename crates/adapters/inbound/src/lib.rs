// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Inbound command-line adapter: argument parsing and rendering.
//!
//! Translates a command line into a request the application understands, and a
//! [`DiscoveryReport`] back into text, JSON or SARIF. Performs no input or
//! output itself; the composition root does the printing.

pub mod args;
pub mod json;
pub mod render;
pub mod sarif;

pub use args::{Command, Format, ParseError, parse};
pub use json::{Scan, document};
pub use render::report;
pub use sarif::sarif;

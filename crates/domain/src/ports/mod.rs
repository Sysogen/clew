// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Outbound ports: every capability the domain needs from the outside world.
//!
//! One trait per module, each with its own error type. A port describes an
//! input or output operation and nothing else. It never carries a serialisation
//! format, and it never maps another crate's errors.

pub mod file_tree;

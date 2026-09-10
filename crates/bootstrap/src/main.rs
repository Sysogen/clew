// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Composition root.
//!
//! The one place a concrete adapter meets a use case, and the only place that
//! reads the environment or writes to a stream.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use clew_adapter_cli::{parse, report, Command};
use clew_adapter_fs::StdFileTree;
use clew_application::DiscoverSurfaces;
use clew_domain::scan_policy::DEFAULT_MAX_DEPTH;
use clew_domain::ScanPolicy;

const USAGE: &str = "\
Discover AI coding agent configuration surfaces in a repository.

USAGE:
    clew path [DIR]     List agent surfaces found under DIR (default: .)
    clew --version
    clew --help

ENVIRONMENT:
    CLEW_MAX_DEPTH      Directory recursion limit

clew never reads a credential value, and never executes a hook, script, or
command it discovers. Symbolic links are reported, never followed.";

fn max_depth() -> usize {
    env::var("CLEW_MAX_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_DEPTH)
}

fn main() -> ExitCode {
    let command = match parse(env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("clew: {error}\nTry 'clew --help'.");
            return ExitCode::FAILURE;
        }
    };

    let root = match command {
        Command::Help => {
            println!("clew {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            println!("clew {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Command::Path { root } => root,
    };

    if !Path::new(&root).is_dir() {
        eprintln!("clew: not a directory: {root}");
        return ExitCode::FAILURE;
    }

    let tree = StdFileTree::new(&root);
    let policy = ScanPolicy::with_default_pruning(max_depth());
    let found = DiscoverSurfaces::new(&tree, &policy).run();

    print!("{}", report(&found, &root));

    if found.is_complete() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

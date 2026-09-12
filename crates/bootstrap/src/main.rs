// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Composition root.

use std::env;
use std::path::Path;
use std::process::ExitCode;

use clew_adapter_cli::{Command, parse, report};
use clew_adapter_fs::{StdFileContents, StdFileTree};
use clew_application::DiscoverSurfaces;
use clew_domain::ScanPolicy;
use clew_domain::scan_policy::{DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES};

const USAGE: &str = "\
Discover AI coding agent configuration surfaces.

USAGE:
    clew path [DIR]     List agent surfaces found under DIR (default: .)
    clew system         List agent surfaces in the home directory
    clew --version
    clew --help

ENVIRONMENT:
    CLEW_MAX_DEPTH      Directory recursion limit
    CLEW_MAX_FILE_BYTES Largest configuration file read

A repository holds what a team shares. The home directory holds what each
engineer set up alone, which no code review covers; `system` reads that.

clew never reads a credential value, and never executes a hook, script, or
command it discovers. Symbolic links are reported, never followed.";

fn max_depth() -> usize {
    env_or("CLEW_MAX_DEPTH", DEFAULT_MAX_DEPTH)
}

fn max_file_bytes() -> u64 {
    env_or("CLEW_MAX_FILE_BYTES", DEFAULT_MAX_FILE_BYTES)
}

fn env_or<T: std::str::FromStr>(name: &str, fallback: T) -> T {
    env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(fallback)
}

fn main() -> ExitCode {
    let command = match parse(env::args().skip(1)) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("clew: {error}\nTry 'clew --help'.");
            return ExitCode::FAILURE;
        }
    };

    let mut home = false;
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
        Command::System => {
            home = true;
            let Some(path) = env::home_dir() else {
                eprintln!("clew: no home directory to scan");
                return ExitCode::FAILURE;
            };
            path.to_string_lossy().into_owned()
        }
    };

    if !Path::new(&root).is_dir() {
        eprintln!("clew: not a directory: {root}");
        return ExitCode::FAILURE;
    }

    let tree = StdFileTree::new(&root);
    let contents = StdFileContents::new(&root);
    let policy =
        ScanPolicy::with_default_pruning(max_depth()).with_max_file_bytes(max_file_bytes());
    let scan = DiscoverSurfaces::new(&tree, &contents, &policy);
    let found = if home {
        scan.in_home().run()
    } else {
        scan.run()
    };

    print!("{}", report(&found, &root));

    if found.is_complete() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

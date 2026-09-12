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
use clew_domain::catalogue;
use clew_domain::scan_policy::{DEFAULT_MAX_DEPTH, DEFAULT_MAX_FILE_BYTES};
use clew_domain::scope::Scope;

const USAGE: &str = "\
Discover AI coding agent configuration surfaces.

USAGE:
    clew path [DIR]     List agent surfaces found under DIR (default: .)
    clew system         List agent surfaces outside any repository
    clew --version
    clew --help

ENVIRONMENT:
    CLEW_MAX_DEPTH      Directory recursion limit
    CLEW_MAX_FILE_BYTES Largest configuration file read

A repository holds what a team shares. `system` reads the rest: what each
engineer set up alone under their home directory, and what an administrator
deployed to the machine. Neither reaches a code review.

clew never reads a credential value, and never executes a hook, script, or
command it discovers. A symbolic link found during a scan is reported, never
followed; a directory clew was told to read is read even if it is one.";

/// Where an administrator deploys policy. Only what a system row names is
/// entered below it.
#[cfg(windows)]
const MACHINE_ROOT: &str = "C:\\";
#[cfg(not(windows))]
const MACHINE_ROOT: &str = "/";

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

    let scans: Vec<(String, Scope)> = match command {
        Command::Help => {
            println!("clew {}\n\n{USAGE}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Command::Version => {
            println!("clew {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Command::Path { root } => {
            if !Path::new(&root).is_dir() {
                eprintln!("clew: not a directory: {root}");
                return ExitCode::FAILURE;
            }
            vec![(root, Scope::Repository)]
        }
        // Two trees, because policy an administrator deployed is not in
        // anybody's home directory.
        Command::System => {
            let Some(home) = env::home_dir() else {
                eprintln!("clew: no home directory to scan");
                return ExitCode::FAILURE;
            };
            vec![
                (home.to_string_lossy().into_owned(), Scope::Home),
                (MACHINE_ROOT.to_owned(), Scope::System),
            ]
        }
    };

    let policy =
        ScanPolicy::with_default_pruning(max_depth()).with_max_file_bytes(max_file_bytes());
    let mut complete = true;

    for (root, scope) in &scans {
        let tree = StdFileTree::new(root).following(&catalogue::shipped().roots_in(*scope));
        let contents = StdFileContents::new(root);
        let found = DiscoverSurfaces::new(&tree, &contents, &policy)
            .in_scope(*scope)
            .run();

        if scans.len() > 1 {
            println!("{root}");
        }
        print!("{}", report(&found, root));
        complete &= found.is_complete();
    }

    if complete {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

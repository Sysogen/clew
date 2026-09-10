// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Discovery of AI coding agent configuration surfaces in a repository.
//!
//! This release covers discovery only: it reports which agent surfaces exist
//! and where. It does not read credentials, resolve identities, or execute
//! anything it finds.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

/// Recognised surfaces, matched on a path suffix so that `.claude/settings.json`
/// does not also match a stray `settings.json` elsewhere in the tree.
const SURFACES: &[(&str, &str)] = &[
    (".mcp.json", "MCP servers"),
    (".claude/settings.json", "Claude Code"),
    (".claude/settings.local.json", "Claude Code"),
    (".codex/config.toml", "Codex"),
    (".cursor/mcp.json", "Cursor"),
    (".cursorrules", "Cursor"),
    (".vscode/mcp.json", "VS Code"),
    (".continue/config.json", "Continue"),
    ("cline_mcp_settings.json", "Cline"),
    (".aider.conf.yml", "Aider"),
    (".github/copilot-instructions.md", "Copilot"),
    (".devcontainer/devcontainer.json", "devcontainer"),
    ("CLAUDE.md", "instruction file"),
    ("AGENTS.md", "instruction file"),
];

const PRUNED: &[&str] = &[".git", "node_modules", "target", "vendor", "dist", ".venv"];

const DEFAULT_MAX_DEPTH: usize = 12;

fn max_depth() -> usize {
    env::var("CLEW_MAX_DEPTH")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_DEPTH)
}

fn classify(relative: &str) -> Option<&'static str> {
    SURFACES.iter().find_map(|(suffix, kind)| {
        (relative == *suffix || relative.ends_with(&format!("/{suffix}"))).then_some(*kind)
    })
}

fn walk(
    dir: &Path,
    root: &Path,
    depth: usize,
    limit: usize,
    found: &mut Vec<(String, &'static str)>,
) {
    if depth > limit {
        return;
    }
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        if path.is_symlink() {
            continue;
        }
        if path.is_dir() {
            if !PRUNED.contains(&name.as_ref()) {
                walk(&path, root, depth + 1, limit, found);
            }
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");
        if let Some(kind) = classify(&relative) {
            found.push((relative, kind));
        }
    }
}

fn usage() {
    println!(
        "clew {}

Discover AI coding agent configuration surfaces in a repository.

USAGE:
    clew path [DIR]     List agent surfaces found under DIR (default: .)
    clew --version
    clew --help

ENVIRONMENT:
    CLEW_MAX_DEPTH      Directory recursion limit (default: {DEFAULT_MAX_DEPTH})

Discovery only in this release. clew never reads credential values and never
executes a hook, script, or command it discovers.",
        env!("CARGO_PKG_VERSION")
    );
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None | Some("--help" | "-h" | "help") => {
            usage();
            return ExitCode::SUCCESS;
        }
        Some("--version" | "-V") => {
            println!("clew {}", env!("CARGO_PKG_VERSION"));
            return ExitCode::SUCCESS;
        }
        Some("path") => {}
        Some(other) => {
            eprintln!("clew: unknown command '{other}'\nTry 'clew --help'.");
            return ExitCode::FAILURE;
        }
    }

    let root = Path::new(args.get(1).map_or(".", String::as_str));
    if !root.is_dir() {
        eprintln!("clew: not a directory: {}", root.display());
        return ExitCode::FAILURE;
    }

    let mut found = Vec::new();
    walk(root, root, 0, max_depth(), &mut found);
    found.sort();

    if found.is_empty() {
        println!("No agent surfaces found under {}.", root.display());
        return ExitCode::SUCCESS;
    }

    let width = found.iter().map(|(p, _)| p.len()).max().unwrap_or(0);
    for (path, kind) in &found {
        println!("{path:<width$}  {kind}");
    }
    println!("\n{} agent surface(s).", found.len());

    ExitCode::SUCCESS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_nested_surfaces_by_full_suffix() {
        assert_eq!(classify(".claude/settings.json"), Some("Claude Code"));
        assert_eq!(
            classify("sub/dir/.claude/settings.json"),
            Some("Claude Code")
        );
    }

    #[test]
    fn a_bare_filename_does_not_match_a_directory_scoped_surface() {
        assert_eq!(classify("settings.json"), None);
        assert_eq!(classify("config/settings.json"), None);
    }

    #[test]
    fn unrelated_files_are_not_surfaces() {
        assert_eq!(classify("src/main.rs"), None);
        assert_eq!(classify("README.md"), None);
    }

    #[test]
    fn root_level_instruction_files_match() {
        assert_eq!(classify("CLAUDE.md"), Some("instruction file"));
        assert_eq!(classify("AGENTS.md"), Some("instruction file"));
    }
}

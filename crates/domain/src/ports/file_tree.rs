// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Reading a directory tree.

use thiserror::Error;

use crate::repo_path::RepoPath;

/// What a directory entry is.
///
/// A symbolic link is reported as a link rather than resolved, so the decision
/// to follow it belongs to the caller's policy rather than to the adapter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link, unresolved.
    Symlink,
}

/// One entry in a directory listing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    /// Path relative to the scan root.
    pub path: RepoPath,
    /// What the entry is.
    pub kind: EntryKind,
}

/// Why a directory could not be listed.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum FileTreeError {
    /// The path does not exist.
    #[error("not found")]
    NotFound,
    /// The process lacks permission to list the path.
    #[error("permission denied")]
    PermissionDenied,
    /// The path exists but is not a directory.
    #[error("not a directory")]
    NotADirectory,
    /// Any other failure, described by the adapter.
    #[error("unreadable: {0}")]
    Unreadable(String),
}

/// Lists directories one level at a time.
///
/// Listing a level at a time rather than walking a whole tree keeps the
/// traversal policy (depth, pruning, symbolic links) in the domain, where it
/// can be tested without touching a real filesystem.
pub trait FileTree {
    /// List the immediate children of `path`.
    ///
    /// # Errors
    ///
    /// Returns an error when the path cannot be listed. A caller scanning a
    /// tree is expected to record the failure and continue, because one
    /// unreadable directory does not invalidate the rest of a scan.
    fn read_dir(&self, path: &RepoPath) -> Result<Vec<DirEntry>, FileTreeError>;
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Outbound filesystem adapter.
//!
//! The only crate in the workspace that touches `std::fs`. It reports what the
//! filesystem says and makes no policy decisions: pruning, depth, and symbolic
//! links belong to `clew_domain::ScanPolicy`.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use clew_domain::ports::file_tree::{DirEntry, EntryKind, FileTree, FileTreeError};
use clew_domain::RepoPath;

/// A [`FileTree`] backed by the real filesystem, rooted at a directory.
pub struct StdFileTree {
    root: PathBuf,
}

impl StdFileTree {
    /// Root the adapter at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn absolute(&self, path: &RepoPath) -> PathBuf {
        if path.as_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(path.as_str())
        }
    }
}

fn map_error(error: &io::Error) -> FileTreeError {
    match error.kind() {
        io::ErrorKind::NotFound => FileTreeError::NotFound,
        io::ErrorKind::PermissionDenied => FileTreeError::PermissionDenied,
        _ => FileTreeError::Unreadable(error.to_string()),
    }
}

fn kind_of(path: &Path) -> Result<EntryKind, FileTreeError> {
    let meta = fs::symlink_metadata(path).map_err(|e| map_error(&e))?;
    let file_type = meta.file_type();
    Ok(if file_type.is_symlink() {
        EntryKind::Symlink
    } else if file_type.is_dir() {
        EntryKind::Directory
    } else {
        EntryKind::File
    })
}

impl FileTree for StdFileTree {
    fn read_dir(&self, path: &RepoPath) -> Result<Vec<DirEntry>, FileTreeError> {
        let absolute = self.absolute(path);
        if !absolute.is_dir() {
            return Err(FileTreeError::NotADirectory);
        }

        let mut entries = Vec::new();
        for entry in fs::read_dir(&absolute).map_err(|e| map_error(&e))? {
            let entry = entry.map_err(|e| map_error(&e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            entries.push(DirEntry {
                path: path.join(name),
                kind: kind_of(&entry.path())?,
            });
        }
        Ok(entries)
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Reading the contents of one file.

use thiserror::Error;

use crate::repo_path::RepoPath;

/// Why a file could not be read.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub enum FileContentsError {
    /// The path does not exist.
    #[error("not found")]
    NotFound,
    /// The process lacks permission to read the path.
    #[error("permission denied")]
    PermissionDenied,
    /// The path is a directory, or a symbolic link that was not followed.
    #[error("not a regular file")]
    NotARegularFile,
    /// The file is larger than the caller allowed.
    #[error("larger than the {limit} byte limit")]
    TooLarge {
        /// The limit the caller supplied.
        limit: u64,
    },
    /// The bytes are not valid UTF-8.
    #[error("not valid UTF-8")]
    NotUtf8,
    /// Any other failure, described by the adapter.
    #[error("unreadable: {0}")]
    Unreadable(String),
}

/// Reads a file as text.
///
/// Separate from [`crate::ports::file_tree::FileTree`] because listing a
/// directory and reading a file are different capabilities with different
/// failure modes, and a caller that only needs to enumerate paths should not
/// be handed the ability to read their contents.
pub trait FileContents {
    /// Read `path` as UTF-8 text, refusing anything larger than `max_bytes`.
    ///
    /// The limit is a parameter rather than a property of the implementation
    /// because it is a scan policy decision, and policy belongs to the caller.
    /// An implementation must be bounded by construction: it may allocate at
    /// most `max_bytes` plus the one byte that proves the limit was exceeded,
    /// so a hostile file cannot exhaust memory. Reading first and measuring
    /// afterwards does not satisfy this.
    ///
    /// A symbolic link is never followed: it reports
    /// [`FileContentsError::NotARegularFile`] rather than reading whatever it
    /// points at, which may be outside the scan root.
    ///
    /// # Errors
    ///
    /// Returns an error when the file is absent, unreadable, not a regular
    /// file, over the limit, or not valid UTF-8. A caller scanning a tree is
    /// expected to record the failure and continue: one unreadable file does
    /// not invalidate the rest of a scan.
    fn read(&self, path: &RepoPath, max_bytes: u64) -> Result<String, FileContentsError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_size_limit_appears_in_the_message() {
        let e = FileContentsError::TooLarge { limit: 1024 };
        assert_eq!(e.to_string(), "larger than the 1024 byte limit");
    }

    #[test]
    fn errors_are_distinguishable() {
        assert_ne!(FileContentsError::NotFound, FileContentsError::NotUtf8);
        assert_ne!(
            FileContentsError::TooLarge { limit: 1 },
            FileContentsError::TooLarge { limit: 2 }
        );
    }
}

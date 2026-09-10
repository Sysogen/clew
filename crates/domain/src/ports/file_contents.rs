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
    /// Larger than the caller allowed.
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

/// Reads a file as text. Separate from
/// [`FileTree`](crate::ports::file_tree::FileTree) so a caller that only
/// enumerates paths cannot also read them.
pub trait FileContents {
    /// Read `path` as UTF-8, refusing anything larger than `max_bytes`.
    ///
    /// Implementations must bound the allocation by construction, at most
    /// `max_bytes` plus one, and must refuse a symlink rather than follow it
    /// out of the scan root.
    ///
    /// # Errors
    ///
    /// Absent, unreadable, not a regular file, over the limit, or not UTF-8.
    /// One failure does not invalidate a scan; callers record and continue.
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

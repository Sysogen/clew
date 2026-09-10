// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Outbound filesystem adapter.
//!
//! The only crate in the workspace that touches `std::fs`. It reports what the
//! filesystem says and makes no policy decisions: pruning, depth, and symbolic
//! links belong to `clew_domain::ScanPolicy`.

use std::fs;
use std::io;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use clew_domain::RepoPath;
use clew_domain::ports::file_contents::{FileContents, FileContentsError};
use clew_domain::ports::file_tree::{DirEntry, EntryKind, FileTree, FileTreeError};

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

/// A [`FileContents`] backed by the real filesystem, rooted at a directory.
pub struct StdFileContents {
    root: PathBuf,
}

impl StdFileContents {
    /// Root the adapter at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
}

fn map_contents_error(error: &io::Error) -> FileContentsError {
    match error.kind() {
        io::ErrorKind::NotFound => FileContentsError::NotFound,
        io::ErrorKind::PermissionDenied => FileContentsError::PermissionDenied,
        _ => FileContentsError::Unreadable(error.to_string()),
    }
}

impl FileContents for StdFileContents {
    fn read(&self, path: &RepoPath, max_bytes: u64) -> Result<String, FileContentsError> {
        let absolute = if path.as_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(path.as_str())
        };

        // symlink_metadata rather than metadata: a link must be refused, not
        // resolved, because it can point outside the scan root.
        let meta = fs::symlink_metadata(&absolute).map_err(|e| map_contents_error(&e))?;
        if !meta.file_type().is_file() {
            return Err(FileContentsError::NotARegularFile);
        }

        // Bounded by construction rather than by a size check. Reading through
        // `take` cannot allocate more than the limit plus the one byte that
        // proves the limit was passed, so there is no window in which a large
        // file is loaded and no gap between checking the size and reading it.
        //
        // No test discriminates this from reading the file and measuring
        // afterwards: both refuse the same inputs, and the difference is
        // memory and time rather than behaviour. It holds by the shape of the
        // code, so do not replace `take` with a read-then-measure.
        let file = fs::File::open(&absolute).map_err(|e| map_contents_error(&e))?;
        let mut bytes = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| map_contents_error(&e))?;

        if bytes.len() as u64 > max_bytes {
            return Err(FileContentsError::TooLarge { limit: max_bytes });
        }

        String::from_utf8(bytes).map_err(|_| FileContentsError::NotUtf8)
    }
}

#[cfg(test)]
mod contents_tests {
    use std::fs;

    use super::*;

    /// A scratch directory keyed by process and line, so concurrent test
    /// binaries and parallel tests inside one binary never share a path.
    fn scratch(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("clew-contents-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        dir
    }

    fn path(name: &str) -> RepoPath {
        RepoPath::root().join(name)
    }

    #[test]
    fn reads_a_small_utf8_file() {
        let dir = scratch("read");
        fs::write(dir.join("a.json"), r#"{"mcpServers":{}}"#).expect("write");

        let read = StdFileContents::new(&dir).read(&path("a.json"), 1024);

        assert_eq!(read.as_deref(), Ok(r#"{"mcpServers":{}}"#));
    }

    #[test]
    fn refuses_a_file_over_the_limit_without_reading_it() {
        let dir = scratch("toolarge");
        fs::write(dir.join("big"), vec![b'x'; 4096]).expect("write");

        let read = StdFileContents::new(&dir).read(&path("big"), 1024);

        assert_eq!(read, Err(FileContentsError::TooLarge { limit: 1024 }));
    }

    #[test]
    fn a_file_exactly_at_the_limit_is_allowed() {
        let dir = scratch("exact");
        fs::write(dir.join("exact"), vec![b'x'; 1024]).expect("write");

        let read = StdFileContents::new(&dir).read(&path("exact"), 1024);

        assert_eq!(read.map(|s| s.len()), Ok(1024));
    }

    #[test]
    fn refuses_bytes_that_are_not_utf8() {
        let dir = scratch("utf8");
        fs::write(dir.join("bin"), [0xff, 0xfe, 0x00]).expect("write");

        let read = StdFileContents::new(&dir).read(&path("bin"), 1024);

        assert_eq!(read, Err(FileContentsError::NotUtf8));
    }

    #[test]
    fn reports_a_missing_file() {
        let dir = scratch("missing");

        let read = StdFileContents::new(&dir).read(&path("nope"), 1024);

        assert_eq!(read, Err(FileContentsError::NotFound));
    }

    #[test]
    fn refuses_a_directory() {
        let dir = scratch("isdir");
        fs::create_dir(dir.join("sub")).expect("mkdir");

        let read = StdFileContents::new(&dir).read(&path("sub"), 1024);

        assert_eq!(read, Err(FileContentsError::NotARegularFile));
    }

    #[cfg(unix)]
    #[test]
    fn never_follows_a_symlink_out_of_the_root() {
        let dir = scratch("symlink");
        let outside = dir.join("outside.txt");
        fs::write(&outside, "secret").expect("write");
        let inside = dir.join("root");
        fs::create_dir(&inside).expect("mkdir");
        std::os::unix::fs::symlink(&outside, inside.join("link")).expect("symlink");

        let read = StdFileContents::new(&inside).read(&path("link"), 1024);

        assert_eq!(
            read,
            Err(FileContentsError::NotARegularFile),
            "a symlink must be refused, not resolved"
        );
    }
}

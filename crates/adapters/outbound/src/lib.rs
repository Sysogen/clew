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
    named: Vec<String>,
}

impl StdFileTree {
    /// Root the adapter at `root`.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
            named: Vec::new(),
        }
    }

    /// Also follow a link at each of these paths.
    ///
    /// They were named rather than discovered: `/etc` is a link on macOS, and
    /// a dotfile manager commonly makes `.claude` one. A link found while
    /// walking is still refused, which is what keeps a hostile tree from
    /// steering the scan.
    #[must_use]
    pub fn following(mut self, paths: &[&str]) -> Self {
        self.named = paths.iter().map(|p| (*p).to_owned()).collect();
        self
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
        let named = path.as_str().is_empty() || self.named.iter().any(|n| n == path.as_str());
        if named {
            // metadata follows, and says absent apart from not-a-directory.
            let found = fs::metadata(&absolute).map_err(|e| map_error(&e))?;
            if !found.is_dir() {
                return Err(FileTreeError::NotADirectory);
            }
        } else {
            // symlink_metadata does not follow, so a link found while walking
            // is refused rather than walked out of the scan root.
            let found = fs::symlink_metadata(&absolute).map_err(|e| map_error(&e))?;
            if !found.is_dir() {
                return Err(FileTreeError::NotADirectory);
            }
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

/// Name a failed open. A no-follow open of a symlink, and any open of a
/// directory on Windows, both fail with errors `ErrorKind` does not separate.
fn classify_open_error(path: &Path, error: &io::Error) -> FileContentsError {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() || meta.is_dir() => {
            FileContentsError::NotARegularFile
        }
        _ => map_contents_error(error),
    }
}

/// Open for reading, refusing a symlink in the open itself. Checking first and
/// opening second can be raced.
fn open_no_follow(path: &Path) -> io::Result<fs::File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW);
    }

    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        // Windows has no O_NOFOLLOW; this opens the reparse point itself.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }

    options.open(path)
}

impl FileContents for StdFileContents {
    fn read(&self, path: &RepoPath, max_bytes: u64) -> Result<String, FileContentsError> {
        let absolute = if path.as_str().is_empty() {
            self.root.clone()
        } else {
            self.root.join(path.as_str())
        };

        let file =
            open_no_follow(&absolute).map_err(|error| classify_open_error(&absolute, &error))?;

        // From the descriptor, so it describes what is actually open.
        let meta = file.metadata().map_err(|e| map_contents_error(&e))?;
        if !meta.file_type().is_file() {
            return Err(FileContentsError::NotARegularFile);
        }

        // take() bounds the allocation. Do not swap for read-then-measure: no
        // test separates them, and that one loads the whole file first.
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

    /// Scratch directory, unique per process and `tag`. Tags must not repeat.
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

    /// A directory reached by a link is outside the tree being scanned, and
    /// walking into one leaves the scan root however it was reached.
    #[cfg(unix)]
    #[test]
    fn never_walks_into_a_linked_directory() {
        let dir = scratch("linkdir");
        let outside = dir.join("outside");
        fs::create_dir(&outside).expect("mkdir");
        fs::write(outside.join("settings.json"), "{}").expect("write");
        let inside = dir.join("root");
        fs::create_dir(&inside).expect("mkdir");
        std::os::unix::fs::symlink(&outside, inside.join(".claude")).expect("symlink");

        let read = StdFileTree::new(&inside).read_dir(&path(".claude"));

        assert_eq!(
            read,
            Err(FileTreeError::NotADirectory),
            "a linked directory must be refused, not walked"
        );
    }

    /// A tool that is not installed leaves no directory. That must read as
    /// absent, not as a directory that could not be inspected, or every scan
    /// reports itself incomplete.
    #[test]
    fn a_named_root_that_is_absent_reads_as_absent() {
        let dir = scratch("absentroot");

        let read = StdFileTree::new(&dir)
            .following(&[".gemini"])
            .read_dir(&path(".gemini"));

        assert_eq!(read, Err(FileTreeError::NotFound));
    }

    /// A named root may be a link: /etc is one on macOS, and a dotfile manager
    /// commonly makes .claude one. Refusing them would report a gap where the
    /// engineer simply keeps their configuration elsewhere.
    #[cfg(unix)]
    #[test]
    fn a_named_root_may_be_a_link() {
        let dir = scratch("namedlink");
        let outside = dir.join("elsewhere");
        fs::create_dir(&outside).expect("mkdir");
        fs::write(outside.join("settings.json"), "{}").expect("write");
        let inside = dir.join("root");
        fs::create_dir(&inside).expect("mkdir");
        std::os::unix::fs::symlink(&outside, inside.join(".claude")).expect("symlink");

        let entries = StdFileTree::new(&inside)
            .following(&[".claude"])
            .read_dir(&path(".claude"))
            .expect("a named root is read");

        assert_eq!(entries.len(), 1);
    }

    /// The operator named the root, so it is followed like any path they type.
    /// On macOS /tmp is itself a link, and refusing it would refuse the scan.
    #[cfg(unix)]
    #[test]
    fn the_root_itself_may_be_a_link() {
        let dir = scratch("linkroot");
        let real = dir.join("real");
        fs::create_dir(&real).expect("mkdir");
        fs::write(real.join("CLAUDE.md"), "x").expect("write");
        let link = dir.join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let entries = StdFileTree::new(&link)
            .read_dir(&RepoPath::root())
            .expect("the named root is read");

        assert_eq!(entries.len(), 1);
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

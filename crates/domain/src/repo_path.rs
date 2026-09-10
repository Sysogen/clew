// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! A path relative to the scan root.

/// A path relative to the scan root, always separated by forward slashes so
/// that classification behaves identically on Windows and Unix.
///
/// The root itself is the empty path.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct RepoPath(String);

impl RepoPath {
    /// The scan root.
    #[must_use]
    pub fn root() -> Self {
        Self(String::new())
    }

    /// Extend this path by one segment.
    ///
    /// Backslashes in `segment` are normalised to forward slashes so a Windows
    /// directory entry cannot produce a path that fails to classify.
    #[must_use]
    pub fn join(&self, segment: &str) -> Self {
        let segment = segment.replace('\\', "/");
        if self.0.is_empty() {
            Self(segment)
        } else {
            Self(format!("{}/{}", self.0, segment))
        }
    }

    /// The path as a forward-slash separated string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The final segment, or the empty string at the root.
    #[must_use]
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or("")
    }

    /// Number of segments from the root. The root itself is depth zero.
    #[must_use]
    pub fn depth(&self) -> usize {
        if self.0.is_empty() {
            0
        } else {
            self.0.matches('/').count() + 1
        }
    }

    /// Whether this path ends with `suffix` on a segment boundary.
    ///
    /// This is the distinction that makes classification correct: a bare
    /// `settings.json` must not satisfy the `.claude/settings.json` suffix.
    #[must_use]
    pub fn ends_with_segments(&self, suffix: &str) -> bool {
        self.0 == suffix || self.0.ends_with(&format!("/{suffix}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_is_empty_and_depth_zero() {
        assert_eq!(RepoPath::root().as_str(), "");
        assert_eq!(RepoPath::root().depth(), 0);
    }

    #[test]
    fn join_builds_forward_slash_paths_from_the_root() {
        let p = RepoPath::root().join("a").join("b");
        assert_eq!(p.as_str(), "a/b");
        assert_eq!(p.depth(), 2);
        assert_eq!(p.file_name(), "b");
    }

    #[test]
    fn join_normalises_windows_separators() {
        let p = RepoPath::root().join("a\\b");
        assert_eq!(p.as_str(), "a/b");
    }

    #[test]
    fn suffix_match_respects_segment_boundaries() {
        let nested = RepoPath::root()
            .join("sub")
            .join(".claude")
            .join("settings.json");
        assert!(nested.ends_with_segments(".claude/settings.json"));

        let bare = RepoPath::root().join("settings.json");
        assert!(!bare.ends_with_segments(".claude/settings.json"));

        let decoy = RepoPath::root().join("notclaude").join("settings.json");
        assert!(!decoy.ends_with_segments("claude/settings.json"));
    }

    #[test]
    fn an_exact_root_level_path_matches_its_own_suffix() {
        assert!(RepoPath::root()
            .join("CLAUDE.md")
            .ends_with_segments("CLAUDE.md"));
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! How much an agent may do before anyone is asked.

/// A mode a configuration file starts an agent in, as the file writes it.
///
/// The value is recorded as found, not judged. A file naming a mode no tool
/// recognises is reported as it stands, and no rule fires on it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Autonomy {
    /// The setting, as its documentation names it, such as
    /// `permissions.defaultMode`.
    pub key: String,
    /// The mode it selects, such as `bypassPermissions`.
    pub value: String,
}

impl Autonomy {
    /// Whether the mode leaves an agent acting with neither a prompt nor a
    /// sandbox around it.
    ///
    /// Only the values that remove both are named. Codex `approval_policy` is
    /// absent on purpose: it stops the asking but leaves the sandbox, which
    /// defaults to `read-only`, so the agent is still bounded.
    #[must_use]
    pub fn is_unchecked(&self) -> bool {
        matches!(
            (self.key.as_str(), self.value.as_str()),
            ("permissions.defaultMode", "bypassPermissions")
                | ("sandbox_mode", "danger-full-access")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mode(key: &str, value: &str) -> Autonomy {
        Autonomy {
            key: key.to_owned(),
            value: value.to_owned(),
        }
    }

    #[test]
    fn bypassing_permissions_is_unchecked() {
        assert!(mode("permissions.defaultMode", "bypassPermissions").is_unchecked());
    }

    #[test]
    fn a_sandbox_with_full_access_is_unchecked() {
        assert!(mode("sandbox_mode", "danger-full-access").is_unchecked());
    }

    /// The accepted set is four values, so it is enumerated rather than
    /// sampled: exactly one of them is unchecked.
    #[test]
    fn every_other_permission_mode_is_silent() {
        for value in ["ask", "plan", "autoMode"] {
            assert!(
                !mode("permissions.defaultMode", value).is_unchecked(),
                "{value} asks before it acts"
            );
        }
    }

    /// As above, over the three modes Codex accepts.
    #[test]
    fn every_other_sandbox_mode_is_silent() {
        for value in ["read-only", "workspace-write"] {
            assert!(
                !mode("sandbox_mode", value).is_unchecked(),
                "{value} keeps a sandbox"
            );
        }
    }

    /// The value decides, and so does the key it sits under: one tool's
    /// dangerous value under another tool's key is neither tool's setting.
    #[test]
    fn a_value_under_the_wrong_key_is_silent() {
        assert!(!mode("sandbox_mode", "bypassPermissions").is_unchecked());
        assert!(!mode("permissions.defaultMode", "danger-full-access").is_unchecked());
    }

    #[test]
    fn an_empty_value_is_not_unchecked() {
        assert!(!mode("permissions.defaultMode", "").is_unchecked());
        assert!(!mode("", "").is_unchecked());
    }

    /// Stopping the asking is not the same as removing the sandbox, and Codex
    /// sandboxes read-only by default.
    #[test]
    fn an_approval_policy_is_not_this_rule() {
        assert!(!mode("approval_policy", "never").is_unchecked());
    }
}

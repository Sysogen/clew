// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! How much an agent may do before anyone is asked.

/// A mode a configuration file starts an agent in, as the file writes it.
///
/// Recorded as found, not judged: a mode no tool recognises is reported as it
/// stands and fires no rule.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Autonomy {
    /// The setting, as its documentation names it, such as
    /// `permissions.defaultMode`.
    pub key: String,
    /// The mode it selects, such as `bypassPermissions`.
    pub value: String,
}

impl Autonomy {
    /// Whether the mode leaves nothing asking first and nothing bounding what
    /// happens.
    ///
    /// Codex `approval_policy` is absent on purpose: it stops the asking but
    /// leaves the sandbox, which defaults to `read-only`. The other three
    /// sandbox nothing, so the prompt was the only control they had.
    #[must_use]
    pub fn is_unchecked(&self) -> bool {
        matches!(
            (self.key.as_str(), self.value.as_str()),
            ("permissions.defaultMode", "bypassPermissions")
                | ("sandbox_mode", "danger-full-access")
                | ("chat.tools.global.autoApprove", "true")
                | ("agent.tool_permissions.default", "allow")
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

    /// Four accepted values, enumerated rather than sampled.
    #[test]
    fn every_other_permission_mode_is_silent() {
        for value in ["ask", "plan", "autoMode"] {
            assert!(
                !mode("permissions.defaultMode", value).is_unchecked(),
                "{value} asks before it acts"
            );
        }
    }

    /// As above, over the three Codex accepts.
    #[test]
    fn every_other_sandbox_mode_is_silent() {
        for value in ["read-only", "workspace-write"] {
            assert!(
                !mode("sandbox_mode", value).is_unchecked(),
                "{value} keeps a sandbox"
            );
        }
    }

    /// One tool's value under another tool's key is neither tool's setting.
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

    /// Stopping the asking is not removing the sandbox.
    #[test]
    fn an_approval_policy_is_not_this_rule() {
        assert!(!mode("approval_policy", "never").is_unchecked());
    }
}

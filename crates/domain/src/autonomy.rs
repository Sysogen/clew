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
    /// The same mode with any credential value in it taken out.
    #[must_use]
    pub fn redacted(&self) -> Self {
        Self {
            key: crate::credential::redacted(&self.key),
            value: crate::credential::redacted(&self.value),
        }
    }

    /// Whether the mode leaves nothing asking first and nothing bounding what
    /// happens.
    ///
    /// Codex `approval_policy` is absent on purpose: it stops the asking but
    /// leaves the sandbox, which defaults to `read-only`. The others sandbox
    /// nothing, so the prompt was the only control they had.
    ///
    /// Codex writes that sandbox two ways. `default_permissions` names a
    /// profile instead of a mode, and `:danger-full-access` is the built-in
    /// that bounds nothing, so it is the same decision as the `sandbox_mode`
    /// value beside it. Reading one spelling and not the other is how a
    /// configuration escapes a rule by being written the newer way.
    #[must_use]
    pub fn is_unchecked(&self) -> bool {
        matches!(
            (self.key.as_str(), self.value.as_str()),
            ("permissions.defaultMode", "bypassPermissions")
                | ("sandbox_mode", "danger-full-access")
                | ("default_permissions", ":danger-full-access")
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
    fn a_credential_in_a_mode_is_not_reported() {
        let secret = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");
        let held = mode(&format!("key={secret}"), &format!("value={secret}"));

        assert!(!format!("{:?}", held.redacted()).contains(secret));
    }

    /// A report reads this off the redacted copy, so redaction must not change
    /// which modes are unchecked.
    #[test]
    fn redacting_leaves_an_unchecked_mode_unchecked() {
        for (key, value) in [
            ("permissions.defaultMode", "bypassPermissions"),
            ("sandbox_mode", "danger-full-access"),
            ("chat.tools.global.autoApprove", "true"),
            ("agent.tool_permissions.default", "allow"),
            ("permissions.defaultMode", "acceptEdits"),
        ] {
            let held = mode(key, value);

            assert_eq!(
                held.redacted().is_unchecked(),
                held.is_unchecked(),
                "{key}={value}"
            );
        }
    }

    #[test]
    fn an_empty_value_is_not_unchecked() {
        assert!(!mode("permissions.defaultMode", "").is_unchecked());
        assert!(!mode("", "").is_unchecked());
    }

    /// Codex takes the same decision in two spellings, and a rule that knows
    /// one of them leaves the other unreported. `default_permissions` is the
    /// profile form; `:danger-full-access` is the built-in that sandboxes
    /// nothing, as `sandbox_mode = "danger-full-access"` does.
    #[test]
    fn a_permission_profile_with_full_access_is_unchecked() {
        assert!(mode("default_permissions", ":danger-full-access").is_unchecked());
    }

    /// The other two built-ins bound what the agent reaches, so the prompt is
    /// not the only control and this is not that rule.
    #[test]
    fn a_bounded_permission_profile_is_not_unchecked() {
        for value in [":read-only", ":workspace", "project-profile"] {
            assert!(
                !mode("default_permissions", value).is_unchecked(),
                "{value} bounds what the agent reaches"
            );
        }
    }

    /// Stopping the asking is not removing the sandbox.
    #[test]
    fn an_approval_policy_is_not_this_rule() {
        assert!(!mode("approval_policy", "never").is_unchecked());
    }
}

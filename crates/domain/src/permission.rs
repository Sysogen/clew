// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Operations an agent may perform without asking.

/// The tool that runs a command of the agent's choosing. Spelt as the
/// settings spell it, which is case-sensitive.
const SHELL: &str = "Bash";

/// A pre-approved operation, as written in the configuration.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Permission {
    /// The tool it applies to, such as `Bash` or an MCP tool name.
    pub tool: String,
    /// The argument restriction. `None` means the grant covers the whole tool.
    pub scope: Option<String>,
}

impl Permission {
    /// Parse one entry, such as `Bash(cargo test:*)` or a bare tool name.
    ///
    /// Returns `None` for an entry that grants nothing: empty, or with
    /// parentheses that do not open before they close. Such an entry is a
    /// configuration defect, not an access grant, so counting it would
    /// overstate what the file actually permits.
    #[must_use]
    pub fn parse(entry: &str) -> Option<Self> {
        let entry = entry.trim();
        if entry.is_empty() {
            return None;
        }

        // Last ')' rather than first, so a scope containing parentheses survives.
        match (entry.find('('), entry.rfind(')')) {
            (Some(open), Some(close)) if open < close => {
                let tool = entry[..open].trim();
                (!tool.is_empty()).then(|| Self {
                    tool: tool.to_owned(),
                    scope: Some(entry[open + 1..close].to_owned()),
                })
            }
            (None, None) => Some(Self {
                tool: entry.to_owned(),
                scope: None,
            }),
            _ => None,
        }
    }

    /// Whether this grants the whole tool rather than one use of it.
    #[must_use]
    pub fn is_unscoped(&self) -> bool {
        self.scope
            .as_deref()
            .is_none_or(|s| s.is_empty() || s == "*")
    }

    /// Whether this grants the shell with nothing restricting what it runs.
    ///
    /// Only the shell. A bare `WebSearch` or `mcp__server__tool` is unscoped
    /// too, but neither takes an argument restriction, so a bare entry is the
    /// only way to write that grant and flagging it would say nothing.
    #[must_use]
    pub fn is_unrestricted_shell(&self) -> bool {
        self.tool == SHELL && self.is_unscoped()
    }

    /// The entry rebuilt as a file writes it, for finding it in one.
    #[must_use]
    pub fn written(&self) -> String {
        match &self.scope {
            Some(scope) => format!("{}({scope})", self.tool),
            None => self.tool.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(entry: &str) -> Permission {
        Permission::parse(entry).expect("valid entry")
    }

    #[test]
    fn splits_a_tool_from_its_scope() {
        let p = parsed("Bash(cargo test:*)");
        assert_eq!(p.tool, "Bash");
        assert_eq!(p.scope.as_deref(), Some("cargo test:*"));
        assert!(!p.is_unscoped());
    }

    #[test]
    fn a_scope_may_contain_parentheses() {
        let p = parsed("Bash(echo (hi))");
        assert_eq!(p.scope.as_deref(), Some("echo (hi)"));
    }

    #[test]
    fn a_bare_tool_name_is_unscoped() {
        let p = parsed("mcp__plugin_figma__generate_diagram");
        assert_eq!(p.tool, "mcp__plugin_figma__generate_diagram");
        assert_eq!(p.scope, None);
        assert!(p.is_unscoped(), "no argument restriction is the whole tool");
    }

    #[test]
    fn a_wildcard_or_empty_scope_is_unscoped() {
        assert!(parsed("Bash(*)").is_unscoped());
        assert!(parsed("Bash()").is_unscoped());
    }

    #[test]
    fn an_unbounded_shell_grant_is_unrestricted() {
        for entry in ["Bash", "Bash()", "Bash(*)"] {
            assert!(
                parsed(entry).is_unrestricted_shell(),
                "{entry} runs anything"
            );
        }
    }

    #[test]
    fn a_shell_grant_with_a_scope_is_not() {
        for entry in [
            "Bash(ls)",
            "Bash(cargo test:*)",
            "Bash(*.sh)",
            "Bash(git:*)",
        ] {
            assert!(
                !parsed(entry).is_unrestricted_shell(),
                "{entry} restricts what runs"
            );
        }
    }

    /// A tool with no argument restriction to give is not an unbounded grant
    /// of one: a bare entry is the only way to write it.
    #[test]
    fn a_tool_that_takes_no_scope_is_not_the_shell() {
        for entry in [
            "WebSearch",
            "TodoWrite",
            "mcp__plugin_figma_figma__use_figma",
            "Read",
        ] {
            assert!(!parsed(entry).is_unrestricted_shell(), "{entry}");
            assert!(parsed(entry).is_unscoped(), "{entry} is still unscoped");
        }
    }

    #[test]
    fn the_tool_name_is_matched_exactly() {
        for entry in ["bash", "BASH", " bash(*)", "Bashful", "Bash2"] {
            assert!(
                !parsed(entry).is_unrestricted_shell(),
                "{entry} is not the tool"
            );
        }
        // Space around an entry is not part of it, so it is still the tool.
        assert!(parsed("  Bash  ").is_unrestricted_shell());
    }

    #[test]
    fn an_entry_is_rebuilt_as_a_file_writes_it() {
        for entry in ["Bash(*)", "Bash()", "Bash(cargo test:*)", "WebSearch"] {
            assert_eq!(parsed(entry).written(), entry, "{entry}");
        }
        // Surrounding space is not part of the entry, so it does not come back.
        assert_eq!(parsed("  Bash(ls)  ").written(), "Bash(ls)");
    }

    #[test]
    fn an_entry_that_grants_nothing_is_rejected() {
        for entry in ["", "   ", "Bash(", "Bash)", ")Bash(", "(ls)", "()"] {
            assert_eq!(
                Permission::parse(entry),
                None,
                "{entry:?} grants nothing and must not be counted"
            );
        }
    }
}

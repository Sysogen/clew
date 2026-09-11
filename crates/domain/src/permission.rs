// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Operations an agent may perform without asking.

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

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
    #[must_use]
    pub fn parse(entry: &str) -> Self {
        // Last ')' rather than first, so a scope containing parentheses survives.
        let bounds = entry
            .find('(')
            .zip(entry.rfind(')'))
            .filter(|(open, close)| open < close);

        match bounds {
            Some((open, close)) => Self {
                tool: entry[..open].trim().to_owned(),
                scope: Some(entry[open + 1..close].to_owned()),
            },
            None => Self {
                tool: entry.trim().to_owned(),
                scope: None,
            },
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

    #[test]
    fn splits_a_tool_from_its_scope() {
        let p = Permission::parse("Bash(cargo test:*)");
        assert_eq!(p.tool, "Bash");
        assert_eq!(p.scope.as_deref(), Some("cargo test:*"));
        assert!(!p.is_unscoped());
    }

    #[test]
    fn a_scope_may_contain_parentheses() {
        let p = Permission::parse("Bash(echo (hi))");
        assert_eq!(p.scope.as_deref(), Some("echo (hi)"));
    }

    #[test]
    fn a_bare_tool_name_is_unscoped() {
        let p = Permission::parse("mcp__plugin_figma__generate_diagram");
        assert_eq!(p.tool, "mcp__plugin_figma__generate_diagram");
        assert_eq!(p.scope, None);
        assert!(p.is_unscoped(), "no argument restriction is the whole tool");
    }

    #[test]
    fn a_wildcard_or_empty_scope_is_unscoped() {
        assert!(Permission::parse("Bash(*)").is_unscoped());
        assert!(Permission::parse("Bash()").is_unscoped());
    }

    #[test]
    fn unbalanced_parentheses_are_not_a_scope() {
        assert_eq!(Permission::parse("Bash)cargo(").scope, None);
        assert_eq!(Permission::parse("Bash(").scope, None);
    }
}

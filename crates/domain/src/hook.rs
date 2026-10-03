// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What an agent does when it reaches an event.

use crate::repo_path::RepoPath;
use crate::shell;

/// What a hook does when it fires.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Action {
    /// A shell command. Never executed.
    Command(String),
    /// Text put into the model's context.
    Prompt(String),
}

impl Action {
    /// The same action with any credential value in it taken out.
    #[must_use]
    pub fn redacted(&self) -> Self {
        match self {
            Self::Command(text) => Self::Command(crate::credential::redacted(text)),
            Self::Prompt(text) => Self::Prompt(crate::credential::redacted(text)),
        }
    }

    /// What it runs or injects, verbatim.
    #[must_use]
    pub fn text(&self) -> &str {
        match self {
            Self::Command(text) | Self::Prompt(text) => text,
        }
    }

    /// Whether it reaches the model rather than a shell.
    #[must_use]
    pub fn injects(&self) -> bool {
        matches!(self, Self::Prompt(_))
    }

    /// The files in the repository this action runs, resolved against
    /// `project`. Only a path that must be inside the checkout is followed.
    #[must_use]
    pub fn scripts(&self, project: &RepoPath) -> Vec<RepoPath> {
        let Self::Command(line) = self else {
            return Vec::new();
        };
        let mut found: Vec<RepoPath> = Vec::new();
        for path in shell::scripts(line)
            .iter()
            .filter_map(|script| resolved(script, project))
        {
            if !found.contains(&path) {
                found.push(path);
            }
        }
        found
    }
}

/// Something registered to happen when an agent reaches an event.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hook {
    /// The event that triggers it, verbatim. Not an enum: tools add events,
    /// and an unknown one still runs code.
    pub event: String,
    /// What it does.
    pub action: Action,
    /// The declared type, when the entry states one. Recorded rather than
    /// filtered on: a type clew does not recognise may still execute.
    pub kind: Option<String>,
    /// Whether it fires as configured. A hook switched off is still reported,
    /// being one edit from running.
    pub enabled: bool,
}

impl Hook {
    /// The same hook with any credential value in it taken out.
    ///
    /// The event as well as the action: a tool's event names are its own, but
    /// the key is read from the file and whatever it says is reported.
    #[must_use]
    pub fn redacted(&self) -> Self {
        Self {
            event: crate::credential::redacted(&self.event),
            action: self.action.redacted(),
            kind: self.kind.as_deref().map(crate::credential::redacted),
            enabled: self.enabled,
        }
    }
}

/// How hook commands name the project root, with and without a fallback.
const PROJECT_ROOTS: &[&str] = &[
    "$CLAUDE_PROJECT_DIR/",
    "${CLAUDE_PROJECT_DIR}/",
    "${CLAUDE_PROJECT_DIR:-.}/",
    "${CLAUDE_PROJECT_DIR:-$PWD}/",
];

/// How hook commands name the root of the checkout.
const CHECKOUT_ROOTS: &[&str] = &[
    "$(git rev-parse --show-toplevel)/",
    "$(git rev-parse --show-toplevel 2>/dev/null)/",
];

/// Where a script path points, when that is certainly inside the checkout.
fn resolved(script: &str, project: &RepoPath) -> Option<RepoPath> {
    let under = |roots: &[&str]| roots.iter().find_map(|root| script.strip_prefix(root));
    let (mut path, relative) = if let Some(rest) = under(PROJECT_ROOTS) {
        (project.clone(), rest)
    } else if let Some(rest) = under(CHECKOUT_ROOTS) {
        (RepoPath::root(), rest)
    } else {
        (project.clone(), script)
    };
    if relative.starts_with(['/', '~'])
        || relative.contains(['$', '`', '*', '?', '[', '{', ':', '\\'])
    {
        return None;
    }
    let base = path.clone();
    for segment in relative.split('/') {
        match segment {
            "" | "." => {}
            ".." => return None,
            segment => path = path.join(segment),
        }
    }
    (path != base).then_some(path)
}

/// The directory a tool's directory, such as `.claude`, sits in.
#[must_use]
pub fn project_of(config: &RepoPath) -> RepoPath {
    let segments: Vec<&str> = config.segments().collect();
    let dirs = &segments[..segments.len().saturating_sub(1)];
    let tool = dirs
        .iter()
        .rposition(|segment| segment.starts_with('.'))
        .unwrap_or(dirs.len());
    dirs[..tool]
        .iter()
        .fold(RepoPath::root(), |path, segment| path.join(segment))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command(line: &str) -> Action {
        Action::Command(line.to_owned())
    }

    fn at(path: &str) -> RepoPath {
        path.split('/')
            .filter(|s| !s.is_empty())
            .fold(RepoPath::root(), |p, s| p.join(s))
    }

    #[test]
    fn a_script_resolves_against_its_project() {
        let pkg = at("pkg");
        for (line, want) in [
            (r#""$CLAUDE_PROJECT_DIR"/tools/x.sh"#, "pkg/tools/x.sh"),
            (
                "${CLAUDE_PROJECT_DIR}/.claude/hooks/a.sh",
                "pkg/.claude/hooks/a.sh",
            ),
            ("./run.sh", "pkg/run.sh"),
            ("python3 lint.py", "pkg/lint.py"),
            ("bash ./scripts/./x.sh", "pkg/scripts/x.sh"),
            (r#""${CLAUDE_PROJECT_DIR:-.}"/a.sh"#, "pkg/a.sh"),
            (r#"bash "${CLAUDE_PROJECT_DIR:-$PWD}/b.sh""#, "pkg/b.sh"),
        ] {
            assert_eq!(command(line).scripts(&pkg), [at(want)], "{line}");
        }
    }

    #[test]
    fn the_top_of_the_checkout_is_the_root_of_the_scan() {
        for (line, want) in [
            (
                r#""$(git rev-parse --show-toplevel)"/.claude/hooks/c.sh"#,
                ".claude/hooks/c.sh",
            ),
            ("$(git rev-parse --show-toplevel 2>/dev/null)/d.sh", "d.sh"),
            (
                r#"HOOK="$(git rev-parse --show-toplevel)/tools/x.py"; python3 "$HOOK""#,
                "tools/x.py",
            ),
        ] {
            assert_eq!(command(line).scripts(&at("pkg")), [at(want)], "{line}");
        }
    }

    #[test]
    fn a_path_that_may_leave_the_checkout_is_never_followed() {
        for line in [
            "/usr/local/bin/x.sh",
            "bash ~/x.sh",
            "bash $HOME/x.sh",
            "bash ../x.sh",
            "bash a/../../x.sh",
            "bash $OTHER/x.sh",
            "bash scripts/*.sh",
            "node ${CLAUDE_PLUGIN_ROOT}/x.js",
            "bash C:/x.sh",
        ] {
            assert!(command(line).scripts(&at("pkg")).is_empty(), "{line}");
        }
    }

    /// A report shows what a file declares, and a hook command is a routine
    /// place for a token. The event too: the key is whatever the file wrote.
    #[test]
    fn a_credential_in_a_hook_is_not_reported() {
        let secret = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");
        let hook = Hook {
            event: format!("On{secret}"),
            action: Action::Command(format!("curl -u {secret} https://x.invalid")),
            kind: Some(format!("type={secret}")),
            enabled: true,
        };

        let held = format!("{:?}", hook.redacted());

        assert!(!held.contains(secret), "{held}");
        assert!(held.contains("curl"), "the command must survive: {held}");
    }

    /// A prompt is injected rather than run, and is reported the same way.
    #[test]
    fn a_credential_in_a_prompt_is_not_reported() {
        let secret = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");
        let action = Action::Prompt(format!("the key is {secret}"));

        assert!(!action.redacted().text().contains(secret));
    }

    /// Redaction is for the report. What a rule reads has to match the file it
    /// came from, so the action it was asked about is left as written.
    #[test]
    fn redacting_does_not_change_the_action_it_was_asked_about() {
        let secret = concat!("ghp_", "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5");
        let action = Action::Command(format!("curl -u {secret}"));

        let _ = action.redacted();

        assert!(action.text().contains(secret), "{action:?}");
    }

    #[test]
    fn a_prompt_runs_nothing() {
        let prompt = Action::Prompt("./x.sh".to_owned());
        assert!(prompt.scripts(&RepoPath::root()).is_empty());
    }

    #[test]
    fn a_tool_runs_hooks_where_its_directory_sits() {
        assert_eq!(project_of(&at("pkg/.claude/settings.json")), at("pkg"));
        assert_eq!(
            project_of(&at("a/b/.claude/settings.local.json")),
            at("a/b")
        );
        assert_eq!(project_of(&at(".claude/settings.json")), RepoPath::root());
        assert_eq!(project_of(&at(".kiro/hooks/lint.json")), RepoPath::root());
        assert_eq!(
            project_of(&at(".work/pkg/.claude/settings.json")),
            at(".work/pkg")
        );
        assert_eq!(project_of(&at("pkg/settings.json")), at("pkg"));
    }
}

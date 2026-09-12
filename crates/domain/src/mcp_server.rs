// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! Model Context Protocol servers an agent can call.

/// How a server is reached.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Transport {
    /// Launched as a local process.
    Local {
        /// The executable.
        command: String,
        /// Its arguments.
        args: Vec<String>,
    },
    /// Reached over the network.
    Remote {
        /// The endpoint.
        url: String,
    },
}

/// A declared MCP server.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct McpServer {
    /// The name it is declared under.
    pub name: String,
    /// How it is reached.
    pub transport: Transport,
    /// Names of environment variables it is given, sorted.
    ///
    /// Names only. A value here may be a credential, and clew never records
    /// one.
    pub env: Vec<String>,
}

/// Shown in place of a value clew will not print.
pub const REDACTED: &str = "<redacted>";

impl Transport {
    /// A local server, with any credential in its arguments taken out.
    ///
    /// Redacted on the way in, not on the way out, so no later formatter or
    /// log can put the value back.
    #[must_use]
    pub fn local(command: String, args: &[String]) -> Self {
        Self::Local {
            command,
            args: redact_args(args),
        }
    }

    /// A remote server, keeping where it points and dropping what it carries.
    #[must_use]
    pub fn remote(url: &str) -> Self {
        Self::Remote {
            url: redact_url(url),
        }
    }
}

impl McpServer {
    /// How the server would be invoked, for display.
    #[must_use]
    pub fn invocation(&self) -> String {
        match &self.transport {
            Transport::Local { command, args } if args.is_empty() => command.clone(),
            Transport::Local { command, args } => format!("{command} {}", args.join(" ")),
            Transport::Remote { url } => url.clone(),
        }
    }
}

/// A url as a reference: where it points, not what it carries.
///
/// The query is marked rather than dropped, so a reader can see the url
/// carries something.
fn redact_url(url: &str) -> String {
    let head = url.split('#').next().unwrap_or(url);
    let (head, has_query) = head
        .split_once('?')
        .map_or((head, false), |(h, _)| (h, true));

    let cleaned = match head.split_once("://") {
        Some((scheme, rest)) => {
            let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
            let host = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
            format!("{scheme}://{host}{path}")
        }
        // Not a url after all. Anything could be in it, so none of it is shown.
        None => REDACTED.to_owned(),
    };

    if has_query {
        format!("{cleaned}?{REDACTED}")
    } else {
        cleaned
    }
}

/// Arguments with credential values taken out.
///
/// A value cannot be told from a package name by looking at it, so what marks
/// one is the flag before it, the `key=value` it sits in, or an issuer prefix.
fn redact_args(args: &[String]) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len());
    let mut redact_next = false;

    for arg in args {
        if redact_next {
            redact_next = false;
            out.push(REDACTED.to_owned());
            continue;
        }
        match arg.split_once('=') {
            Some((flag, _)) if names_a_credential(flag) => out.push(format!("{flag}={REDACTED}")),
            _ if looks_issued(arg) => out.push(REDACTED.to_owned()),
            _ => {
                // Only a flag introduces a value. `-e JIRA_API_TOKEN` passes a
                // name, and redacting what follows would hide the image run.
                redact_next = arg.starts_with('-') && names_a_credential(arg);
                out.push(arg.clone());
            }
        }
    }
    out
}

/// Whether a flag names a credential. Matched by segment, so `--api-key` does
/// and `--author` does not.
fn names_a_credential(flag: &str) -> bool {
    flag.trim_start_matches('-')
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
fn looks_issued(value: &str) -> bool {
    const ISSUED: [&str; 7] = ["sk-", "sk_", "pk_", "ghp_", "gho_", "github_pat_", "xox"];
    ISSUED.iter().any(|p| value.starts_with(p)) && value.len() > 12
}

#[cfg(test)]
mod tests {
    use super::*;

    fn server(transport: Transport) -> McpServer {
        McpServer {
            name: "s".to_owned(),
            transport,
            env: vec![],
        }
    }

    fn local(args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|a| (*a).to_owned()).collect();
        server(Transport::local("npx".to_owned(), &args)).invocation()
    }

    fn remote(url: &str) -> String {
        server(Transport::remote(url)).invocation()
    }

    /// Redaction must remove the value, not hide it. A later formatter, log
    /// line, or serialiser reads the field, not `invocation`.
    #[test]
    fn a_redacted_value_is_not_kept_anywhere_on_the_type() {
        let args = ["--api-key".to_owned(), "sk-live-SECRET".to_owned()];
        let held = format!("{:?}", server(Transport::local("npx".to_owned(), &args)));
        assert!(!held.contains("sk-live-SECRET"), "{held}");

        let held = format!(
            "{:?}",
            server(Transport::remote("https://u:pw@h.invalid/s?token=TOKENV"))
        );
        assert!(!held.contains("TOKENV"), "{held}");
        assert!(!held.contains("pw"), "{held}");
    }

    #[test]
    fn a_value_behind_a_credential_flag_is_not_printed() {
        let said = local(&["-y", "srv", "--api-key", "sk-live-SECRET"]);

        assert!(!said.contains("sk-live-SECRET"), "{said}");
        assert!(
            said.contains("--api-key"),
            "the flag is the finding: {said}"
        );
        assert!(said.contains("srv"), "the package must survive: {said}");
    }

    #[test]
    fn a_credential_written_as_one_word_is_not_printed() {
        for arg in [
            "--token=SECRETVALUE",
            "--password=SECRETVALUE",
            "--auth-token=SECRETVALUE",
            "API_KEY=SECRETVALUE",
        ] {
            let said = local(&[arg]);
            assert!(!said.contains("SECRETVALUE"), "{arg} -> {said}");
        }
    }

    #[test]
    fn a_bare_value_an_issuer_shaped_is_not_printed() {
        for arg in ["sk-live-0123456789abcdef", "ghp_0123456789abcdefghij"] {
            let said = local(&[arg]);
            assert!(!said.contains(arg), "{said}");
        }
    }

    /// A name passed as a value does not introduce a secret. Redacting after
    /// it hid the image being run, which is what a typosquat check reads.
    #[test]
    fn a_variable_name_passed_as_a_value_redacts_nothing() {
        let said = local(&[
            "run",
            "-e",
            "JIRA_API_TOKEN",
            "-e",
            "JIRA_URL",
            "ghcr.io/org/image:1.2",
        ]);

        assert_eq!(
            said,
            "npx run -e JIRA_API_TOKEN -e JIRA_URL ghcr.io/org/image:1.2"
        );
    }

    /// Over-redaction hides findings, so a flag that merely reads like one is
    /// left alone and a package name is never mistaken for a secret.
    #[test]
    fn ordinary_arguments_survive_intact() {
        let said = local(&["-y", "@modelcontextprotocol/server-postgres@latest"]);
        assert_eq!(said, "npx -y @modelcontextprotocol/server-postgres@latest");

        let said = local(&["--author", "someone"]);
        assert_eq!(said, "npx --author someone", "author is not auth");
    }

    #[test]
    fn a_url_keeps_where_it_points_and_drops_what_it_carries() {
        assert_eq!(
            remote("https://mcp.example.invalid/sse"),
            "https://mcp.example.invalid/sse"
        );
        let said = remote("https://user:pw@mcp.example.invalid/sse?token=SECRET#frag");
        assert!(!said.contains("SECRET"), "{said}");
        assert!(!said.contains("pw"), "userinfo is a credential: {said}");
        assert!(said.contains("mcp.example.invalid/sse"), "{said}");
        assert!(
            said.contains(REDACTED),
            "a carried value must be visible as one: {said}"
        );
    }

    /// A transport that is not a url may be anything, including a secret, so
    /// none of it is shown rather than some of it.
    #[test]
    fn a_remote_that_is_not_a_url_is_withheld() {
        assert_eq!(remote("sk-live-not-really-a-url"), REDACTED);
    }

    #[test]
    fn a_local_invocation_joins_its_arguments() {
        let s = McpServer {
            name: "pg".to_owned(),
            transport: Transport::Local {
                command: "npx".to_owned(),
                args: vec!["-y".to_owned(), "server-postgres".to_owned()],
            },
            env: vec![],
        };
        assert_eq!(s.invocation(), "npx -y server-postgres");
    }

    #[test]
    fn a_local_invocation_without_arguments_is_the_command() {
        let s = McpServer {
            name: "x".to_owned(),
            transport: Transport::Local {
                command: "./run.sh".to_owned(),
                args: vec![],
            },
            env: vec![],
        };
        assert_eq!(s.invocation(), "./run.sh");
    }

    #[test]
    fn a_remote_invocation_is_its_url() {
        let s = McpServer {
            name: "atlassian".to_owned(),
            transport: Transport::Remote {
                url: "https://mcp.example.invalid/sse".to_owned(),
            },
            env: vec![],
        };
        assert_eq!(s.invocation(), "https://mcp.example.invalid/sse");
    }
}

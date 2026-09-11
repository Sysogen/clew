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

#[cfg(test)]
mod tests {
    use super::*;

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

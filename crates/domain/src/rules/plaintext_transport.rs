// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Sysogen Lda

//! The `plaintext-transport` rule.

use std::net::IpAddr;

use super::{SERVER_BLOCKS, about_file, after_key, found_at};
use crate::finding::{Finding, RuleId, Severity};
use crate::mcp_server::Transport;
use crate::rule::{Examined, Rule, Subject};

/// See [`Rule::detail`] for what this flags and why.
pub struct PlaintextTransport;

impl Rule for PlaintextTransport {
    fn id(&self) -> RuleId {
        RuleId::PlaintextTransport
    }

    fn name(&self) -> &'static str {
        "plaintext-transport"
    }

    fn severity(&self) -> Severity {
        Severity::Medium
    }

    fn description(&self) -> &'static str {
        "An MCP server reached over plain HTTP"
    }

    fn detail(&self) -> &'static str {
        "A remote MCP server is declared with an http endpoint, so the session crosses \
                the network in cleartext. That session carries the arguments the agent sends, \
                the results it reads back, and whatever header authenticates it. The \
                specification's Streamable HTTP transport requires a server to validate the \
                Origin header and says it should authenticate every connection, naming DNS \
                rebinding as what those prevent; none of it holds when anything on the path \
                can read the exchange and rewrite it, and a tool result the model reads as \
                instructions is worth rewriting. The specification does not require TLS, so \
                this is a weakness in how the server is deployed rather than a breach of the \
                protocol, which is also why an endpoint that stays on the machine is silent."
    }

    fn remediation(&self) -> &'static str {
        "Point the declaration at https, or keep the endpoint on loopback, where the \
                traffic never reaches a network. A server that offers no TLS of its own is \
                usually fronted by a proxy that terminates it, which leaves the plaintext hop \
                inside the host. The specification also asks a local server to bind 127.0.0.1 \
                rather than 0.0.0.0, so that a page in a browser cannot reach it at all."
    }

    fn reads(&self) -> &'static [Subject] {
        &[Subject::Server]
    }

    fn check(&self, at: &Examined<'_>, width: usize) -> Vec<Finding> {
        let Examined::Server {
            path,
            server,
            source,
        } = at
        else {
            return Vec::new();
        };
        let Transport::Remote { url } = &server.transport else {
            return Vec::new();
        };
        if !is_plaintext(url) {
            return Vec::new();
        }
        vec![
            SERVER_BLOCKS
                .iter()
                .find_map(|key| after_key(source, key, &server.name, 0))
                .and_then(|at| found_at(path, self.id(), source, at, width))
                .unwrap_or_else(|| about_file(path, self.id(), &server.name, width)),
        ]
    }
}

/// Whether the endpoint leaves the machine unencrypted.
///
/// A url clew could not read is reported as redacted and has no scheme, so it
/// is not judged: a rule may not guess at what it cannot see.
fn is_plaintext(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    // Schemes are case insensitive, and a file may write any casing.
    if !scheme.eq_ignore_ascii_case("http") {
        return false;
    }
    host_of(rest).is_some_and(|host| !stays_on_the_machine(host))
}

/// The host an endpoint names, without its port or its credentials.
fn host_of(rest: &str) -> Option<&str> {
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    // An address written in brackets keeps the colons that are part of it.
    if let Some(bracketed) = authority.strip_prefix('[') {
        return bracketed.split_once(']').map(|(host, _)| host);
    }
    authority.split(':').next().filter(|host| !host.is_empty())
}

/// Whether traffic to this host never reaches a network.
///
/// Parsed as an address rather than matched as a prefix, so a name that only
/// begins like one, `127.0.0.1.example.invalid`, is still a finding. The
/// unspecified address is included: a client told to reach `0.0.0.0` reaches
/// the local host, and the specification names it as what a server should not
/// bind in the first place.
fn stays_on_the_machine(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback() || address.is_unspecified())
}

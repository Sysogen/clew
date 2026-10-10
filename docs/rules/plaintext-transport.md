# plaintext-transport

Severity **medium**, pack core 3.

An MCP server reached over plain HTTP

## What it means

A remote MCP server is declared with an http endpoint, so the session crosses
the network in cleartext. That session carries the arguments the agent sends,
the results it reads back, and whatever header authenticates it. The
specification's Streamable HTTP transport requires a server to validate the
Origin header and says it should authenticate every connection, naming DNS
rebinding as what those prevent; none of it holds when anything on the path can
read the exchange and rewrite it, and a tool result the model reads as
instructions is worth rewriting. The specification does not require TLS, so
this is a weakness in how the server is deployed rather than a breach of the
protocol, which is also why an endpoint that stays on the machine is silent.

## What to do

Point the declaration at https, or keep the endpoint on loopback, where the
traffic never reaches a network. A server that offers no TLS of its own is
usually fronted by a proxy that terminates it, which leaves the plaintext hop
inside the host. The specification also asks a local server to bind 127.0.0.1
rather than 0.0.0.0, so that a page in a browser cannot reach it at all.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/rules/plaintext_transport.rs`, not this page.

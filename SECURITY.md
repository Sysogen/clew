# Security Policy

## Reporting a vulnerability

Report privately through GitHub's private vulnerability reporting: open the
[Security tab](https://github.com/sysogen/clew/security/advisories) and choose
"Report a vulnerability".

If that page does not offer a reporting option, email **fn@sysogen.com** with
the details instead. A reporting channel that turns out to be closed is the
reason findings go unreported, so please use the fallback rather than assuming
we are uninterested.

Please do not open a public issue for a security problem.

We aim to acknowledge a report within three working days and to agree a
disclosure timeline with you. We will credit you in the advisory unless you ask
us not to.

## Supported versions

Pre-1.0. Only the most recent release receives fixes.

## Scope

`clew` reads files and reports what it finds. Reports of the following are
especially welcome:

- Any path by which `clew` executes content it discovered. It must never run a
  hook, script, or command found during a scan.
- Any path by which a credential value reaches output, logs, or an exit code.
  `clew` reports references and never contents.
- Directory traversal out of the scan root, including through symbolic links.
- Resource exhaustion from a hostile repository: recursion depth, file size,
  file count, or path length.

## Our own disclosure practice

When we find a defect in someone else's repository, we notify the owner
privately with the finding and a remediation, and we do not publish anything
that identifies them. We never validate a discovered credential against its
provider, because confirming it would be unauthorised access to whatever it
opens.

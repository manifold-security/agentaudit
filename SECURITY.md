# Security policy

agentaudit reads configuration from repositories you did not write. If a crafted repository can make it misbehave, report it privately.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: the **Report a vulnerability** button on this repository's **Security** tab.

Do not open a public issue or pull request for a vulnerability.

Include the agentaudit version (`agentaudit --version`) and the smallest repository or configuration that reproduces the problem.

## What happens next

We acknowledge a report within two weeks. Disclosure is coordinated with you: the details stay private until a fixed release is out, and the advisory credits you unless you ask us not to.

## Supported versions

Only the latest release receives security fixes.

## Scope

In scope:

- a crafted repository that makes agentaudit execute anything, write any file other than the reports `-O` asks for, reach any host other than the GitHub repository it was asked to fetch, hang, or crash.

Out of scope: a missed detection. A configuration agentaudit fails to report is a detection gap, not a vulnerability; open a normal issue as described in "Reporting a problem" in [CONTRIBUTING.md](CONTRIBUTING.md).

# Contributing to agentaudit

Thanks for considering a contribution. The most useful contributions are new detection rules and support for new agents — this document covers what a rule has to satisfy before it ships.

## What agentaudit is

It reads an AI coding agent's configuration and reports what that configuration lets the agent do. It never runs or modifies what it reads. Anything that would execute, mutate or network out on the scanned repository's behalf is out of scope.

## The scope boundary: official vendor documentation

A rule must describe behaviour the agent's own vendor documents. If a key is not in the vendor's published docs, we do not model it, however plausible it looks. Cite the page in the rule's `references`, and prefer the `.md` form of the URL where the vendor serves one.

This is deliberately strict. Rules that guess at undocumented behaviour go stale silently and report things no user can act on.

## The two tests every rule must pass

Before proposing a rule, run it through both. A rule that fails either is noise.

**Reachability.** Can a cloned repository cause this to fire, at the scope it is reported from? A setting that only exists in a user's home directory is not something a repository can impose, so it is not something a repository's reader needs warning about.

**Direction.** Does the key OPEN something or CLOSE it? `sandbox: disabled` opens. `readBoundary: workspace` closes. We report what widens what an agent may do, not what narrows it.

## Rules are data

A rule is a JSON object in `rules/<agent>/`. Adding one normally needs no Go at all — if it does, say so in the pull request, because a new operator or target kind is a larger change than a new rule.

Each rule carries `examples` and `negative_examples`, and they are a specification, not documentation: every `examples` entry must match the rule and every `negative_examples` entry must not. The loader checks this at startup, so a rule whose examples disagree with its `match` fails the build rather than shipping.

Give the rule fixture coverage under `testdata/malicious/`. `TestEveryEmbeddedRuleFiresAcrossCapabilitySurface` derives its expectation from the shipped ruleset, so a rule with no fixture fails there.

## Tests and gates

```sh
make check    # gofmt, vet, tests, race, and the js/wasm build and suite
```

Everything must be green before you open a pull request.

Golden files are compared, never refreshed. If a golden fails, the change moved the output: explain why in the pull request rather than regenerating it.

For a guard, name the mutation that makes it fail and run that mutation under the full suite. A test nothing can break is not a guard.

## Commits

Conventional Commits, one logical change per commit. The commit message is where the reasoning goes — it never rots and it is where reviewers look for why a line exists.

## Reporting a problem

Open an issue with the configuration that produced the wrong result, the output you got and the output you expected. A false positive is as much a bug as a missed detection: a tool people learn to ignore protects nobody.

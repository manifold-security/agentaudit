# agentaudit

`agentaudit` reads a repository's AI coding agent configuration and reports what it can do: the hooks, MCP servers, credential helpers, environment variables, permission and sandbox settings an agent picks up when it opens the repository. It only reads configuration; it never runs or modifies it.

It currently supports Claude Code, Codex and Cursor.

## Install

Download the archive for your platform from the
[Releases](https://github.com/manifold-security/agentaudit/releases) page, check it against
`SHA256SUMS`, and put the `agentaudit` binary on your `PATH`:

```sh
shasum -a 256 --ignore-missing -c SHA256SUMS
tar -xzf agentaudit_darwin_arm64.tar.gz
mkdir -p ~/.local/bin && mv agentaudit ~/.local/bin/
```

With Go installed:

```sh
go install github.com/manifold-security/agentaudit/cmd/agentaudit@latest
```

Or build from source:

```sh
make build                          # builds dist/agentaudit
mkdir -p ~/.local/bin && mv dist/agentaudit ~/.local/bin/
```

If `~/.local/bin` is not on your `PATH`, add this line to your shell profile:

```sh
export PATH="$HOME/.local/bin:$PATH"
```

## Quick start

Scan a repository from anywhere by naming it, or `cd` into it and run the command with no argument:

```sh
agentaudit /path/to/repo
cd /path/to/repo && agentaudit
```

Sample output, from `agentaudit testdata/malicious/claude-guardrail` in this repository:

```
agentaudit · testdata/malicious/claude-guardrail

(claude-code)
permissions:
  mcpApproval enableAllProjectMcpServers · true · .claude/settings.json:enableAllProjectMcpServers
  mcpApproval enabledMcpjsonServers · memory · .claude/settings.json:enabledMcpjsonServers[0]
  permissionMode · acceptEdits · .claude/settings.json:permissions.defaultMode

sandbox:
  sandbox · /var/run/docker.sock · .claude/settings.json:sandbox.network.allowUnixSockets[0]
  sandbox · /tmp/app.sock · .claude/settings.json:sandbox.network.allowUnixSockets[1]

5 capabilities · 1 file · 2 categories
```

### What it reports

Findings are grouped by agent (`(claude-code)`, `(codex)`, `(cursor)`), then by category. Each line is one capability: **what** it is, the **value** it carries, and **where** it is declared (file and key). The footer counts the capabilities, the files they came from, and the categories.

| Category | Meaning |
|---|---|
| `code-execution` | runs a command, script or server process: hooks, MCP servers, credential helpers, status lines, bundled scripts, `NODE_OPTIONS`, `PATH` |
| `credential-access` | passes a value from your environment to a server or command |
| `network-access` | reaches the network or redirects where traffic goes: API base URLs, proxies |
| `permissions` | widens what runs without asking you: approval modes, auto-approved MCP servers |
| `sandbox` | turns off or changes the agent's sandbox, or admits a Unix socket |
| `filesystem-access` | grants read or write access to a path |

A repository whose agent configuration yields nothing prints `no capabilities found` followed by the agents it scanned; one with no agent configuration at all prints `no known agent config read`. 

Under `--global-config`, a home directory with no agent configuration prints `no user-level agent config found`, and one that exists but cannot be opened prints `user-level agent config could not be read`.

Exit codes: `0` no findings, `1` at least one finding, `2` usage or runtime error.

## Flags

Usage: `agentaudit [PATH]`. `PATH` defaults to the current directory.

| Flag | Behaviour |
|---|---|
| `-v, --explain` | Adds each finding's rule id, message and reference link. Pretty output only. |
| `-o, --output pretty\|json` | Format printed to stdout. Default `pretty`. |
| `-O, --output-file json\|md\|all` | Also writes `agentaudit-report.json`, `agentaudit-report.md`, or both, to the current directory. Nothing is written without this flag. |
| `-r, --recursive` | Scans every project beneath `PATH`, one report block per project. |
| `--scan-dir <path>` | Adds another target, scanned alongside `PATH`. Repeatable. |
| `--global-config` | Scans only each agent's user-level configuration in your home directory. Cannot be combined with `PATH`, `--scan-dir` or `-r`. |
| `-V, --version` | Prints the version and exits. |

## Examples

Show the rule behind each finding:

```
$ agentaudit -v testdata/malicious/claude-guardrail
...
permissions:
  mcpApproval enableAllProjectMcpServers · true · .claude/settings.json:enableAllProjectMcpServers
    claude.mcp.auto-approve — MCP auto-approve bypasses the per-server approval prompt — https://code.claude.com/docs/en/settings
...
```

Print JSON for another tool to consume:

```sh
agentaudit -o json /path/to/repo
```

Print the report and also save JSON and Markdown copies:

```sh
agentaudit -O all /path/to/repo   # writes ./agentaudit-report.json and ./agentaudit-report.md
```

Scan every project under a directory:

```sh
agentaudit -r /path/to/projects
```

Scan two repositories in one run:

```sh
agentaudit /path/to/repo --scan-dir /path/to/other-repo
```

Scan only your own user-level agent configuration:

```sh
agentaudit --global-config
```

## Library usage

Import `github.com/manifold-security/agentaudit` to scan from Go. A scan reads through an `fs.FS`; for a directory on disk, pass an `os.Root`'s FS, which keeps reads inside the directory. This scans the sample fixture in this repository:

```go
root, err := os.OpenRoot("testdata/malicious/claude-guardrail")
if err != nil {
	log.Fatal(err)
}
defer root.Close()

report, err := agentaudit.New().Scan(root.FS())
if err != nil {
	log.Fatal(err)
}
for _, f := range report.Findings() {
	fmt.Println(f.RuleID, f.Digest())
}
fmt.Println("unreadable:", report.UnreadableSources(), "unparsed:", report.UnparsedSources())
```

The Go API is pre-1.0, so a release may change it.

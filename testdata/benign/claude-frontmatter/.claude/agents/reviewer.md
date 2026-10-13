---
name: reviewer
description: Reviews code changes for the frontmatter binary-e2e fixture.
tools: Read, Grep
permissionMode: acceptEdits
mcpServers:
  fs:
    command: /usr/local/bin/mcp-fs
hooks:
  PreToolUse:
    - matcher: Bash
      hooks:
        - type: command
          command: audit.sh
---

# Reviewer

A subagent used only by the binary-e2e frontmatter fixture.

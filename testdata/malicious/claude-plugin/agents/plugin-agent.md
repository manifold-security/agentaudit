---
name: plugin-agent
permissionMode: suppressed-permission-mode
hooks:
  PreToolUse:
    - hooks:
        - type: command
          command: suppressed-hook.sh
mcpServers:
  db:
    command: suppressed-mcp-server
---

A plugin-shipped agent. Its hooks, mcpServers and permissionMode frontmatter
keys must never be re-emitted as entities (#930's security carve-out); only
its presence must surface.

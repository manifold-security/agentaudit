---
name: reviewer
description: Reviewer agent shipped by the plugin. Every capability key below is one Claude Code refuses for a plugin-shipped agent.
permissionMode: bypassPermissions
hooks:
  SessionStart:
    - hooks:
        - type: command
          command: suppressed-plugin-agent-hook.sh
mcpServers:
  audit:
    command: suppressed-plugin-agent-mcp
---

# Reviewer

Preflight check: !`suppressed-plugin-agent-inline.sh`

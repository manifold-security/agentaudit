---
name: release
description: Cut a release for the current branch
hooks:
  SessionStart:
    - hooks:
        - type: command
          command: command-hook.sh
---

# Release

Cut a release for the current branch.

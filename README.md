# Claude Guard

A PreToolUse security hook for [Claude Code](https://claude.ai/claude-code) that controls Write, Edit, and Bash permissions via allowlists.

## What it does

Claude Guard is a single bash script that acts as a gatekeeper for Claude Code tool calls:

- **Edit/Write** - Only allowed in explicitly configured directories
- **Bash** - Dangerous commands (rm, install, powershell, ...) are blocked, safe read commands (ls, cat, grep, git log, ...) are auto-allowed, everything else requires user confirmation
- **Shell injection protection** - Detects command chaining (`;`, `&&`, `||`), redirects (`>`), command substitution (`` ` ``), and pipes to interpreters

## How it works

```
Claude wants to run a tool
        |
   [PreToolUse Hook]
        |
   Deny rule match? ──Yes──> BLOCKED
        |No
   Allow rule match? ──Yes──> PERMITTED (no prompt)
        |No
   No output ──> Normal permission flow (user is asked)
```

## Installation

```bash
git clone https://github.com/Did-hub/claude-guard.git
cd claude-guard
bash install.sh
```

Then edit `~/.claude/hooks/pretooluse-guard.sh` and adjust `ALLOWED_WRITE_DIRS` to your needs:

```bash
ALLOWED_WRITE_DIRS=(
  "$HOME/projects"
  "$HOME/.claude"
)
```

## Configuration

### Allowed write directories

Edit the `ALLOWED_WRITE_DIRS` array in `pretooluse-guard.sh`:

```bash
ALLOWED_WRITE_DIRS=(
  "$HOME/my-project"
  "$HOME/.claude"
  "/shared/team-folder"
)
```

### Logging

All decisions are logged to `~/.claude/hooks/guard.log`:

```
[2026-03-16 14:16:10] allow | Bash   | Safe read command
[2026-03-16 14:16:16] deny  | Bash   | Destructive command not allowed
[2026-03-16 14:23:01] deny  | Write  | Write not allowed outside allowlist
```

Disable logging by setting `LOG_ENABLED=false` in the script.

### settings.json

The hook is configured in `~/.claude/settings.json`:

```json
{
  "permissions": {
    "allow": ["Read", "Glob", "Grep", "WebSearch", "WebFetch"],
    "deny": []
  },
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash|Edit|Write",
      "hooks": [{
        "type": "command",
        "command": "~/.claude/hooks/pretooluse-guard.sh"
      }]
    }]
  }
}
```

## What is blocked

| Category | Examples | Decision |
|---|---|---|
| Destructive | `rm`, `rmdir`, `del`, `format` | DENY |
| Installations | `pip install`, `npm install`, `winget install` | DENY |
| System commands | `powershell`, `cmd`, `reg`, `net`, `runas` | DENY |
| Code execution | `python -c`, `node -e`, `eval` | DENY |
| File operations | `mv`, `cp`, `mkdir`, `touch`, `chmod` | DENY |
| Process management | `kill`, `systemctl`, `service` | DENY |
| Downloads | `curl`, `wget` | DENY |
| Shell injection | `;`, `&&`, `\|\|`, `>`, `` ` ``, `$()` | DENY |

## What is allowed

| Category | Examples | Decision |
|---|---|---|
| Directory listing | `ls`, `find`, `tree`, `stat`, `du` | ALLOW |
| File reading | `cat`, `head`, `tail`, `wc`, `diff` | ALLOW |
| Text search | `grep`, `rg`, `awk` | ALLOW |
| Git (read-only) | `git log`, `git status`, `git diff`, `git branch` | ALLOW |
| System info | `which`, `whoami`, `uname`, `pwd`, `date` | ALLOW |

Everything not listed above will trigger the normal Claude Code permission prompt (ASK).

## Known limitations

- `echo` commands may bypass the hook due to Claude Code's internal handling
- JSON parsing uses grep/sed (not jq) - may break with multiline command strings
- Shell injection detection is pattern-based, not a full parser

## License

MIT

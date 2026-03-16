#!/bin/bash
# =============================================================================
# PreToolUse Guard: Security hook for Claude Code
# =============================================================================
# Controls all writing/executing tools in a single script.
# Matcher in settings.json: "Bash|Edit|Write"
#
# Logic:
#   Edit/Write -> Path-based allowlist (only specific directories)
#   Bash       -> 1. Detect shell injection -> DENY
#                  2. Detect dangerous commands -> DENY
#                  3. Detect safe read commands -> ALLOW
#                  4. Everything else -> ASK (user decides)
#
# Logging: All decisions are written to ~/.claude/hooks/guard.log
#          Log entries: [timestamp] DECISION | Tool | Detail
# =============================================================================

INPUT=$(cat)

# --- Configuration ---

LOG_FILE="$HOME/.claude/hooks/guard.log"
LOG_ENABLED=true

# Allowed directories for Edit/Write (add your own paths here)
# Use $HOME for home directory, paths will be normalized automatically
ALLOWED_WRITE_DIRS=(
  "$HOME/projects"
  "$HOME/.claude"
)

# --- Helper functions ---

log() {
  if [[ "$LOG_ENABLED" == "true" ]]; then
    printf '[%s] %-5s | %-6s | %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$1" "$TOOL_NAME" "$2" >> "$LOG_FILE"
  fi
}

respond() {
  log "$1" "$2"
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"%s","permissionDecisionReason":"%s"}}' "$1" "$2"
  exit 0
}

# Path normalization for Windows/Git Bash:
#   Backslash -> Slash, C: -> /c, double slashes removed, all lowercase
normalize() {
  printf '%s' "$1" | tr '\\' '/' | sed 's|^[A-Za-z]:|/c|' | sed 's|//*|/|g' | tr '[:upper:]' '[:lower:]'
}

# --- Detect tool name ---

TOOL_NAME=$(echo "$INPUT" | grep -o '"tool_name"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"tool_name"[[:space:]]*:[[:space:]]*"//;s/"$//')

# =============================================================================
# EDIT / WRITE: Path-based allowlist
# =============================================================================

if [[ "$TOOL_NAME" == "Edit" ]] || [[ "$TOOL_NAME" == "Write" ]]; then

  FILE_PATH=$(echo "$INPUT" | grep -o '"file_path"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"file_path"[[:space:]]*:[[:space:]]*"//;s/"$//')

  # No path -> block for safety
  if [[ -z "$FILE_PATH" ]]; then
    respond "deny" "No file path specified"
  fi

  NORMALIZED_FILE=$(normalize "$FILE_PATH")

  # Check against allowed directories
  for RAW_DIR in "${ALLOWED_WRITE_DIRS[@]}"; do
    DIR=$(normalize "$RAW_DIR")
    if [[ "$NORMALIZED_FILE" == "$DIR"* ]]; then
      respond "allow" "Allowed directory: $NORMALIZED_FILE"
    fi
  done

  respond "deny" "Write not allowed outside allowlist. Attempted: $NORMALIZED_FILE"
fi

# =============================================================================
# BASH: Command analysis
# =============================================================================

if [[ "$TOOL_NAME" == "Bash" ]]; then

  COMMAND=$(echo "$INPUT" | grep -o '"command"[[:space:]]*:[[:space:]]*"[^"]*"' | sed 's/.*"command"[[:space:]]*:[[:space:]]*"//;s/"$//')

  if [[ -z "$COMMAND" ]]; then
    respond "ask" "No command detected"
  fi

  # --- STEP 1: Detect shell injection -> DENY ---
  # Protects allowed commands from abuse via chained commands

  # Command chaining: ; && ||
  if echo "$COMMAND" | grep -qE '[;&]{1,2}|\|\|'; then
    respond "deny" "Shell injection: command chaining not allowed (; && ||)"
  fi

  # Pipe to interpreter (bash, sh, python, node, etc.)
  if echo "$COMMAND" | grep -qE '\|\s*(bash|sh|zsh|python|node|ruby|perl|cmd|powershell)'; then
    respond "deny" "Shell injection: pipe to interpreter not allowed"
  fi

  # Command substitution: $(...) or `...`
  if echo "$COMMAND" | grep -qE '\$\(|`'; then
    respond "deny" "Shell injection: command substitution not allowed"
  fi

  # Redirect: > >>
  if echo "$COMMAND" | grep -qE '>>?'; then
    respond "deny" "Shell injection: redirect not allowed (> >>)"
  fi

  # Process substitution: <(...)
  if echo "$COMMAND" | grep -qE '<\('; then
    respond "deny" "Shell injection: process substitution not allowed"
  fi

  # --- STEP 2: Dangerous commands -> DENY ---

  # Destructive: delete, format
  if echo "$COMMAND" | grep -qiE '^\s*(rm|rmdir|del|rd|format|mkfs)\b'; then
    respond "deny" "Destructive command not allowed"
  fi

  # Package managers / installations
  if echo "$COMMAND" | grep -qiE '(pip\s+install|npm\s+install|yarn\s+add|apt\s+install|apt-get\s+install|winget\s+install|choco\s+install|brew\s+install)'; then
    respond "deny" "Installation not allowed"
  fi

  # Windows system commands
  if echo "$COMMAND" | grep -qiE '^\s*(powershell|cmd\s|reg\s|net\s|sc\s|schtasks|wmic|netsh|runas)\b'; then
    respond "deny" "System command not allowed"
  fi

  # Code execution via interpreter
  if echo "$COMMAND" | grep -qiE '(python[23]?\s+-c|node\s+-e|ruby\s+-e|perl\s+-e|eval\s)'; then
    respond "deny" "Code execution not allowed"
  fi

  # File operations (move, copy, create)
  if echo "$COMMAND" | grep -qiE '^\s*(mv|cp|mkdir|touch|chmod|chown|chgrp|ln)\b'; then
    respond "deny" "File operation not allowed"
  fi

  # Process management
  if echo "$COMMAND" | grep -qiE '^\s*(kill|killall|pkill|systemctl|service)\b'; then
    respond "deny" "Process management not allowed"
  fi

  # Network downloads
  if echo "$COMMAND" | grep -qiE '^\s*(curl|wget|fetch)\b'; then
    respond "deny" "Download command not allowed"
  fi

  # --- STEP 3: Safe read commands -> ALLOW ---

  # Filesystem listing
  if echo "$COMMAND" | grep -qE '^\s*(ls|dir|find|file|stat|du|df|tree|realpath|readlink|basename|dirname)(\s|$)'; then
    respond "allow" "Safe read command"
  fi

  # File content reading
  if echo "$COMMAND" | grep -qE '^\s*(cat|head|tail|less|more|wc|sort|uniq|diff|md5sum|sha256sum)(\s|$)'; then
    respond "allow" "Safe read command"
  fi

  # Text search
  if echo "$COMMAND" | grep -qE '^\s*(grep|rg|ag|awk)(\s|$)'; then
    respond "allow" "Safe search command"
  fi

  # Git read commands
  if echo "$COMMAND" | grep -qE '^\s*git\s+(log|status|diff|branch|tag|show|blame|remote|rev-parse|config\s+--list)'; then
    respond "allow" "Safe git command"
  fi

  # System information
  if echo "$COMMAND" | grep -qE '^\s*(which|where|whoami|hostname|uname|env|printenv|date|pwd|id|uptime|php\s+-v|node\s+-v|npm\s+-v|git\s+--version)(\s|$)'; then
    respond "allow" "Safe info command"
  fi

  # --- STEP 4: Everything else -> ASK ---
  respond "ask" "Unknown command - please review"
fi

# Unknown tool -> ASK
respond "ask" "Unknown tool: $TOOL_NAME"

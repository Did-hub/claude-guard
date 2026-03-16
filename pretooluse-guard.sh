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
#                  2. Detect dangerous commands + user BASH_DENY -> DENY
#                  3. Detect safe read commands + user BASH_ALLOW -> ALLOW
#                  4. Everything else -> ASK (user decides)
#
# Configuration: ~/.claude/hooks/guard.conf (see guard.conf.example)
# Logging:       ~/.claude/hooks/guard.log
# =============================================================================

INPUT=$(cat)

# --- Defaults (can be overridden by guard.conf) ---

LOG_FILE="$HOME/.claude/hooks/guard.log"
LOG_ENABLED=true

# --- Load user configuration from guard.conf ---

CONF_FILE="$HOME/.claude/hooks/guard.conf"
ALLOWED_WRITE_DIRS=()
USER_BASH_DENY=()
USER_BASH_ALLOW=()

if [[ -f "$CONF_FILE" ]]; then
  while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue

    key="${line%%=*}"
    value="${line#*=}"

    case "$key" in
      WRITE_ALLOW)
        # Expand $HOME in the value
        eval "value=\"$value\""
        ALLOWED_WRITE_DIRS+=("$value")
        ;;
      BASH_DENY)
        USER_BASH_DENY+=("$value")
        ;;
      BASH_ALLOW)
        USER_BASH_ALLOW+=("$value")
        ;;
      LOG_ENABLED)
        LOG_ENABLED="$value"
        ;;
    esac
  done < "$CONF_FILE"
fi

# Fallback if no WRITE_ALLOW dirs configured
if [[ ${#ALLOWED_WRITE_DIRS[@]} -eq 0 ]]; then
  ALLOWED_WRITE_DIRS=(
    "$HOME/projects"
    "$HOME/.claude"
  )
fi

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

  # Check against allowed directories from guard.conf
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

  # Built-in deny rules
  if echo "$COMMAND" | grep -qiE '^\s*(rm|rmdir|del|rd|format|mkfs)\b'; then
    respond "deny" "Destructive command not allowed"
  fi

  if echo "$COMMAND" | grep -qiE '(pip\s+install|npm\s+install|yarn\s+add|apt\s+install|apt-get\s+install|winget\s+install|choco\s+install|brew\s+install)'; then
    respond "deny" "Installation not allowed"
  fi

  if echo "$COMMAND" | grep -qiE '^\s*(powershell|cmd\s|reg\s|net\s|sc\s|schtasks|wmic|netsh|runas)\b'; then
    respond "deny" "System command not allowed"
  fi

  if echo "$COMMAND" | grep -qiE '(python[23]?\s+-c|node\s+-e|ruby\s+-e|perl\s+-e|eval\s)'; then
    respond "deny" "Code execution not allowed"
  fi

  if echo "$COMMAND" | grep -qiE '^\s*(mv|cp|mkdir|touch|chmod|chown|chgrp|ln)\b'; then
    respond "deny" "File operation not allowed"
  fi

  if echo "$COMMAND" | grep -qiE '^\s*(kill|killall|pkill|systemctl|service)\b'; then
    respond "deny" "Process management not allowed"
  fi

  if echo "$COMMAND" | grep -qiE '^\s*(curl|wget|fetch)\b'; then
    respond "deny" "Download command not allowed"
  fi

  # User-defined deny rules from guard.conf
  for pattern in "${USER_BASH_DENY[@]}"; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
      respond "deny" "Blocked by user rule: $pattern"
    fi
  done

  # --- STEP 3: Safe read commands -> ALLOW ---

  # Built-in allow rules
  if echo "$COMMAND" | grep -qE '^\s*(ls|dir|find|file|stat|du|df|tree|realpath|readlink|basename|dirname)(\s|$)'; then
    respond "allow" "Safe read command"
  fi

  if echo "$COMMAND" | grep -qE '^\s*(cat|head|tail|less|more|wc|sort|uniq|diff|md5sum|sha256sum)(\s|$)'; then
    respond "allow" "Safe read command"
  fi

  if echo "$COMMAND" | grep -qE '^\s*(grep|rg|ag|awk)(\s|$)'; then
    respond "allow" "Safe search command"
  fi

  if echo "$COMMAND" | grep -qE '^\s*git\s+(log|status|diff|branch|tag|show|blame|remote|rev-parse|config\s+--list)'; then
    respond "allow" "Safe git command"
  fi

  if echo "$COMMAND" | grep -qE '^\s*(which|where|whoami|hostname|uname|env|printenv|date|pwd|id|uptime|php\s+-v|node\s+-v|npm\s+-v|git\s+--version)(\s|$)'; then
    respond "allow" "Safe info command"
  fi

  # User-defined allow rules from guard.conf
  for pattern in "${USER_BASH_ALLOW[@]}"; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
      respond "allow" "Allowed by user rule: $pattern"
    fi
  done

  # --- STEP 4: Everything else -> ASK ---
  respond "ask" "Unknown command - please review"
fi

# Unknown tool -> ASK
respond "ask" "Unknown tool: $TOOL_NAME"

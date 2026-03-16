#!/bin/bash
# =============================================================================
# PreToolUse Guard: Security hook for Claude Code
# =============================================================================
# Controls all writing/executing tools in a single script.
# Matcher in settings.json: "Bash|Edit|Write"
#
# Logic:
#   Edit/Write -> Path-based allowlist (WRITE_ALLOW in guard.conf)
#   Bash       -> 1. Detect shell injection -> DENY (always active, not configurable)
#                  2. BASH_DENY rules from guard.conf -> DENY
#                  3. BASH_ALLOW rules from guard.conf -> ALLOW
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
BASH_DENY_RULES=()
BASH_ALLOW_RULES=()

if [[ -f "$CONF_FILE" ]]; then
  while IFS= read -r line; do
    # Skip comments and empty lines
    [[ "$line" =~ ^[[:space:]]*# ]] && continue
    [[ -z "${line// }" ]] && continue

    key="${line%%=*}"
    value="${line#*=}"

    case "$key" in
      WRITE_ALLOW)
        eval "value=\"$value\""
        ALLOWED_WRITE_DIRS+=("$value")
        ;;
      BASH_DENY)
        BASH_DENY_RULES+=("$value")
        ;;
      BASH_ALLOW)
        BASH_ALLOW_RULES+=("$value")
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

  if [[ -z "$FILE_PATH" ]]; then
    respond "deny" "No file path specified"
  fi

  NORMALIZED_FILE=$(normalize "$FILE_PATH")

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

  # --- STEP 1: Shell injection detection (always active, not configurable) ---

  if echo "$COMMAND" | grep -qE '[;&]{1,2}|\|\|'; then
    respond "deny" "Shell injection: command chaining not allowed (; && ||)"
  fi

  if echo "$COMMAND" | grep -qE '\|\s*(bash|sh|zsh|python|node|ruby|perl|cmd|powershell)'; then
    respond "deny" "Shell injection: pipe to interpreter not allowed"
  fi

  if echo "$COMMAND" | grep -qE '\$\(|`'; then
    respond "deny" "Shell injection: command substitution not allowed"
  fi

  if echo "$COMMAND" | grep -qE '>>?'; then
    respond "deny" "Shell injection: redirect not allowed (> >>)"
  fi

  if echo "$COMMAND" | grep -qE '<\('; then
    respond "deny" "Shell injection: process substitution not allowed"
  fi

  # --- STEP 2: BASH_DENY rules from guard.conf ---

  for pattern in "${BASH_DENY_RULES[@]}"; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
      respond "deny" "Blocked: $pattern"
    fi
  done

  # --- STEP 3: BASH_ALLOW rules from guard.conf ---

  for pattern in "${BASH_ALLOW_RULES[@]}"; do
    if echo "$COMMAND" | grep -qiE "$pattern"; then
      respond "allow" "Allowed: $pattern"
    fi
  done

  # --- STEP 4: Everything else -> ASK ---
  respond "ask" "Unknown command - please review"
fi

# Unknown tool -> ASK
respond "ask" "Unknown tool: $TOOL_NAME"

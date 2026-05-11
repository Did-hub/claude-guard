#!/bin/bash
# =============================================================================
# PreToolUse Guard: Security hook for Claude Code
# =============================================================================
# Controls all writing/executing tools in a single script.
# Matcher in settings.json: "Bash|Edit|Write"
#
# Logic:
#   Edit/Write -> 1. WRITE_DENY regex patterns from guard.conf -> DENY
#                  2. WRITE_ALLOW path prefixes from guard.conf -> ALLOW
#                  3. Everything else -> DENY
#   Bash       -> 1. Detect shell injection (redirects, $(), `, pipe-to-interpreter) -> DENY
#                  2. Detect command chaining (; && ||) -> DENY if ALLOW_CHAINING=false
#                  3. BASH_DENY rules from guard.conf -> DENY
#                  4. BASH_ALLOW rules from guard.conf -> ALLOW
#                  5. Everything else -> ASK (user decides)
#
# Configuration: ~/.claude/hooks/guard.conf (see guard.conf.example)
# Logging:       ~/.claude/hooks/guard.log
# =============================================================================

INPUT=$(cat)

# --- Load configuration from guard.conf ---
# Uses grep + paste to build combined regex patterns
# (arrays with for-loops caused deny decisions to be ignored by Claude Code)

CONF_FILE="$HOME/.claude/hooks/guard.conf"
DENY_PATTERN=""
ALLOW_PATTERN=""
LOG_ENABLED="true"
ALLOW_CHAINING="true"

if [[ -f "$CONF_FILE" ]]; then
  DENY_PATTERN=$(grep -E '^BASH_DENY=' "$CONF_FILE" | sed 's/^BASH_DENY=//' | paste -sd'|')
  ALLOW_PATTERN=$(grep -E '^BASH_ALLOW=' "$CONF_FILE" | sed 's/^BASH_ALLOW=//' | paste -sd'|')

  # Read WRITE_ALLOW dirs
  WRITE_ALLOW_DIRS=""
  while IFS= read -r dir; do
    eval "dir=\"$dir\""
    WRITE_ALLOW_DIRS="$WRITE_ALLOW_DIRS|$dir"
  done < <(grep -E '^WRITE_ALLOW=' "$CONF_FILE" | sed 's/^WRITE_ALLOW=//')

  # Read WRITE_DENY regex patterns (checked BEFORE WRITE_ALLOW)
  WRITE_DENY_PATTERN=$(grep -E '^WRITE_DENY=' "$CONF_FILE" | sed 's/^WRITE_DENY=//' | paste -sd'|')

  # Read LOG_ENABLED
  conf_log=$(grep -E '^LOG_ENABLED=' "$CONF_FILE" | tail -1 | sed 's/^LOG_ENABLED=//')
  [[ -n "$conf_log" ]] && LOG_ENABLED="$conf_log"

  # Read ALLOW_CHAINING
  conf_chain=$(grep -E '^ALLOW_CHAINING=' "$CONF_FILE" | tail -1 | sed 's/^ALLOW_CHAINING=//')
  [[ -n "$conf_chain" ]] && ALLOW_CHAINING="$conf_chain"
fi

# --- Helper functions ---

LOG_FILE="$HOME/.claude/hooks/guard.log"

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

  # Check WRITE_DENY patterns first (regex). Checked BEFORE WRITE_ALLOW.
  if [[ -n "$WRITE_DENY_PATTERN" ]]; then
    if echo "$NORMALIZED_FILE" | grep -qE "$WRITE_DENY_PATTERN"; then
      respond "deny" "Edit/Write blocked for this path. Use sed via Bash to preserve encoding. Path: $NORMALIZED_FILE"
    fi
  fi

  # Check each WRITE_ALLOW dir
  IFS='|' read -ra DIRS <<< "${WRITE_ALLOW_DIRS#|}"
  for RAW_DIR in "${DIRS[@]}"; do
    [[ -z "$RAW_DIR" ]] && continue
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

  # --- STEP 1: Shell injection detection ---

  # Command chaining (; && ||) - configurable via ALLOW_CHAINING (default: true)
  if [[ "$ALLOW_CHAINING" != "true" ]]; then
    if echo "$COMMAND" | grep -qE '[;&]{1,2}|\|\|'; then
      respond "deny" "Shell injection: command chaining not allowed (; && ||)"
    fi
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

  if [[ -n "$DENY_PATTERN" ]]; then
    if echo "$COMMAND" | grep -qiE "$DENY_PATTERN"; then
      respond "deny" "Blocked by deny rule"
    fi
  fi

  # --- STEP 3: BASH_ALLOW rules from guard.conf ---

  if [[ -n "$ALLOW_PATTERN" ]]; then
    if echo "$COMMAND" | grep -qiE "$ALLOW_PATTERN"; then
      respond "allow" "Allowed by allow rule"
    fi
  fi

  # --- STEP 4: Everything else -> ASK ---
  respond "ask" "Unknown command - please review"
fi

# Unknown tool -> ASK
respond "ask" "Unknown tool: $TOOL_NAME"

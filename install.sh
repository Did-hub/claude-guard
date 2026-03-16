#!/bin/bash
# =============================================================================
# Claude Guard - Installer
# =============================================================================
# Copies the hook script, config, and example settings to ~/.claude/
# Run: bash install.sh
# =============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CLAUDE_DIR="$HOME/.claude"
HOOKS_DIR="$CLAUDE_DIR/hooks"
SETTINGS_FILE="$CLAUDE_DIR/settings.json"
CONF_FILE="$HOOKS_DIR/guard.conf"

echo "=== Claude Guard Installer ==="
echo ""

# Create directories
mkdir -p "$HOOKS_DIR"
echo "[OK] Directory: $HOOKS_DIR"

# Copy hook script (always overwrite to get latest version)
cp "$SCRIPT_DIR/pretooluse-guard.sh" "$HOOKS_DIR/pretooluse-guard.sh"
chmod +x "$HOOKS_DIR/pretooluse-guard.sh"
echo "[OK] Hook installed: $HOOKS_DIR/pretooluse-guard.sh"

# Handle guard.conf (never overwrite user config)
if [[ -f "$CONF_FILE" ]]; then
  echo "[OK] Config exists: $CONF_FILE (not overwritten)"
else
  cp "$SCRIPT_DIR/guard.conf.example" "$CONF_FILE"
  echo "[OK] Config installed: $CONF_FILE"
  echo "     -> Edit this file to configure allowed directories and commands"
fi

# Handle settings.json
if [[ -f "$SETTINGS_FILE" ]]; then
  echo ""
  echo "[!!] $SETTINGS_FILE already exists."
  echo "     Your existing settings will NOT be overwritten."
  echo "     Please merge manually with: $SCRIPT_DIR/settings.example.json"
  echo ""
  echo "     Required hook config for settings.json:"
  echo '     {'
  echo '       "hooks": {'
  echo '         "PreToolUse": [{'
  echo '           "matcher": "Bash|Edit|Write",'
  echo '           "hooks": [{'
  echo '             "type": "command",'
  echo '             "command": "~/.claude/hooks/pretooluse-guard.sh"'
  echo '           }]'
  echo '         }]'
  echo '       }'
  echo '     }'
else
  cp "$SCRIPT_DIR/settings.example.json" "$SETTINGS_FILE"
  echo "[OK] Settings installed: $SETTINGS_FILE"
fi

echo ""
echo "=== Installation complete ==="
echo ""
echo "Next steps:"
echo "  1. Edit $CONF_FILE"
echo "     -> Add your allowed write directories (WRITE_ALLOW=...)"
echo "     -> Add project-specific commands (BASH_ALLOW=... / BASH_DENY=...)"
echo "  2. Restart Claude Code (or reload window)"
echo "  3. Test: try 'rm /tmp/test' - should be blocked"
echo ""
echo "To update later: git pull && bash install.sh"
echo "  (your guard.conf will be preserved)"
echo ""

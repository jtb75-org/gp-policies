#!/bin/bash
# =============================================================================
# Sync GitHub Secrets directly from Google Valentine (Password Manager)
# =============================================================================

REPO_ROOT="/usr/local/google/home/joebuhr/repo/gp-policies"
ENV_FILE="$REPO_ROOT/.env"

# Check if .env file exists and extract the secret ID
if [ -f "$ENV_FILE" ]; then
    VALENTINE_SECRET_ID=$(grep -E "^VALENTINE_SECRET_ID=" "$ENV_FILE" | cut -d= -f2- | tr -d '"' | tr -d "'")
fi

if [ -z "$VALENTINE_SECRET_ID" ]; then
    echo "Error: VALENTINE_SECRET_ID not found in $ENV_FILE"
    echo "Please configure your .env file with:"
    echo "VALENTINE_SECRET_ID=<your_16_digit_valentine_secret_id>"
    exit 1
fi

# Check if valentine CLI is available
VALENTINE_CLI="/google/bin/releases/valentine-cli/valentine"
if [ ! -x "$VALENTINE_CLI" ] && ! command -v valentine &> /dev/null; then
    echo "Error: Valentine CLI not found."
    echo "Please run: sudo apt update && sudo apt install -y valentine-cli"
    exit 1
fi

# Resolve valentine command
VALENTINE_CMD="valentine"
if [ -x "$VALENTINE_CLI" ]; then
    VALENTINE_CMD="$VALENTINE_CLI"
fi

# Check if gh CLI is installed
if ! command -v gh &> /dev/null; then
    echo "Error: gh CLI (GitHub CLI) is not installed."
    echo "Please install it (https://cli.github.com/) and authenticate with 'gh auth login'."
    exit 1
fi

# Check if gh authenticated
if ! gh auth status &> /dev/null; then
    echo "Error: gh CLI is not authenticated. Please run 'gh auth login'."
    exit 1
fi

# Check if jq is installed (required to parse JSON secret)
if ! command -v jq &> /dev/null; then
    echo "Error: jq is required but not installed."
    exit 1
fi

# Check if user has active gcert
if ! gcertstatus &> /dev/null; then
    echo "gcert credentials expired. Running gcert..."
    gcert || exit 1
fi

echo "🔑 Fetching credentials from Valentine secret ID '$VALENTINE_SECRET_ID'..."
SECRET_JSON=$($VALENTINE_CMD secret get "$VALENTINE_SECRET_ID" --raw 2>/dev/null)

if [ -z "$SECRET_JSON" ]; then
    echo "Error: Failed to retrieve secret from Valentine. Make sure you provided the correct 16-digit secret ID in .env and that your gcert is active."
    exit 1
fi

# Validate JSON structure
if ! echo "$SECRET_JSON" | jq empty 2>/dev/null; then
    echo "Error: Secret content retrieved from Valentine is not valid JSON."
    exit 1
fi

# Extract and validate fields
WIZ_OUTPOST_CLIENT_ID=$(echo "$SECRET_JSON" | jq -r '.WIZ_OUTPOST_CLIENT_ID // empty')
WIZ_OUTPOST_CLIENT_SECRET=$(echo "$SECRET_JSON" | jq -r '.WIZ_OUTPOST_CLIENT_SECRET // empty')
WIZ_OUTPOST_ID=$(echo "$SECRET_JSON" | jq -r '.WIZ_OUTPOST_ID // empty')
CF_TUNNEL_TOKEN=$(echo "$SECRET_JSON" | jq -r '.CF_TUNNEL_TOKEN // empty')

if [ -z "$WIZ_OUTPOST_CLIENT_ID" ] || [ -z "$WIZ_OUTPOST_CLIENT_SECRET" ] || [ -z "$WIZ_OUTPOST_ID" ]; then
    echo "Error: Secret is missing one of the required fields (WIZ_OUTPOST_CLIENT_ID, WIZ_OUTPOST_CLIENT_SECRET, WIZ_OUTPOST_ID)."
    exit 1
fi

echo "🚀 Syncing secrets to GitHub..."

gh secret set WIZ_OUTPOST_CLIENT_ID --body "$WIZ_OUTPOST_CLIENT_ID"
gh secret set WIZ_OUTPOST_CLIENT_SECRET --body "$WIZ_OUTPOST_CLIENT_SECRET"
gh secret set WIZ_OUTPOST_ID --body "$WIZ_OUTPOST_ID"

if [ -n "$CF_TUNNEL_TOKEN" ]; then
    gh secret set CF_TUNNEL_TOKEN --body "$CF_TUNNEL_TOKEN"
    echo "✅ Synced CF_TUNNEL_TOKEN"
fi

echo "🎉 Successfully synced all secrets from Valentine to GitHub!"

#!/bin/bash
set -euo pipefail

REPO="ADORSYS-GIS/wazuh-agent-installer"
VERSION="${1:-latest}"

echo "📥 Downloading Wazuh Agent Installer for macOS..."

if [ "$VERSION" = "latest" ]; then
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" \
    | grep browser_download_url | grep dmg | head -1 | cut -d'"' -f4 || true)
else
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/$VERSION" \
    | grep browser_download_url | grep dmg | head -1 | cut -d'"' -f4 || true)
fi

if [ -z "$DL_URL" ]; then
  echo "❌ Could not find macOS DMG in release"
  echo "   Visit https://github.com/$REPO/releases to check available assets"
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading from: $DL_URL"
curl -fsSL "$DL_URL" -o "$TMP/Installer.dmg"

echo "📦 Installing..."
hdiutil attach "$TMP/Installer.dmg" -mountpoint "$TMP/mount" -quiet
APP_PATH=$(find "$TMP/mount" -maxdepth 1 -name "*.app" -print -quit)
if [ -z "$APP_PATH" ]; then
  echo "❌ Could not find any .app bundle inside the mounted DMG"
  hdiutil detach "$TMP/mount" -quiet
  exit 1
fi

APP_NAME=$(basename "$APP_PATH")
echo "Copying $APP_NAME to /Applications/..."
cp -R "$APP_PATH" /Applications/
hdiutil detach "$TMP/mount" -quiet

echo "🛡️  Removing quarantine attribute to bypass macOS Gatekeeper..."
xattr -dr com.apple.quarantine "/Applications/$APP_NAME"

echo "✅ Wazuh Agent Installer installed successfully! You can find it in your Applications folder."

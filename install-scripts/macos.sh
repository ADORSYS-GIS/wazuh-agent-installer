#!/bin/bash
set -euo pipefail

REPO="ADORSYS-GIS/wazuh-agent-installer"
VERSION="${1:-latest}"

echo "📥 Downloading Wazuh Agent Installer for macOS..."

if [ "$VERSION" = "latest" ]; then
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" \
    | grep browser_download_url | grep dmg | head -1 | cut -d'"' -f4)
else
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/$VERSION" \
    | grep browser_download_url | grep dmg | head -1 | cut -d'"' -f4)
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
cp -R "$TMP/mount/Wazuh Agent Installer.app" /Applications/
hdiutil detach "$TMP/mount" -quiet

echo "🛡️  Removing quarantine attribute to bypass macOS Gatekeeper..."
xattr -dr com.apple.quarantine "/Applications/Wazuh Agent Installer.app"

echo "✅ Wazuh Agent Installer installed successfully! You can find it in your Applications folder."

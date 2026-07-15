#!/bin/bash
set -euo pipefail

REPO="ADORSYS-GIS/wazuh-agent-installer"
VERSION="${1:-latest}"

echo "📥 Downloading Wazuh Agent Installer for Ubuntu..."

if [ "$VERSION" = "latest" ]; then
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" \
    | grep browser_download_url | grep '\.deb"' | head -1 | cut -d'"' -f4)
else
  DL_URL=$(curl -s "https://api.github.com/repos/$REPO/releases/tags/$VERSION" \
    | grep browser_download_url | grep '\.deb"' | head -1 | cut -d'"' -f4)
fi

if [ -z "$DL_URL" ]; then
  echo "❌ Could not find Ubuntu .deb package in release"
  echo "   Visit https://github.com/$REPO/releases to check available assets"
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "Downloading from: $DL_URL"
curl -fsSL "$DL_URL" -o "$TMP/installer.deb"

echo "📦 Installing package..."
sudo dpkg -i "$TMP/installer.deb" || sudo apt-get install -f -y

echo "✅ Wazuh Agent Installer installed successfully!"

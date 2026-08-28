#!/bin/bash
set -euo pipefail

REPO="ADORSYS-GIS/wazuh-agent-installer"
VERSION="${1:-latest}"

echo "📥 Downloading Wazuh Agent Installer for Ubuntu..."

if [ "$VERSION" = "latest" ]; then
  TAG=$(curl -sI "https://github.com/$REPO/releases/latest" | grep -i '^location:' | awk -F'/' '{print $NF}' | tr -d '\r')
else
  TAG="$VERSION"
fi

if [ -z "$TAG" ]; then
  echo "❌ Could not determine version tag."
  exit 1
fi

VER="${TAG#v}"
TAG="v${VER}"

ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
  PKG_ARCH="amd64"
elif [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
  PKG_ARCH="arm64"
else
  echo "❌ Unsupported architecture: $ARCH"
  exit 1
fi

DL_URL="https://github.com/$REPO/releases/download/${TAG}/wazuh-agent-installer-dev_${VER}_${PKG_ARCH}.deb"

# Verify URL exists before downloading
if ! curl -sI -f "$DL_URL" > /dev/null; then
  echo "❌ Could not find Ubuntu .deb package ($DL_URL) in release"
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

#!/bin/bash
set -euo pipefail

REPO="ADORSYS-GIS/wazuh-agent-installer"
VERSION="${1:-latest}"

echo "📥 Downloading Wazuh Agent Installer for macOS..."

if [[ "$VERSION" = "latest" ]]; then
  TAG=$(curl -sI "https://github.com/$REPO/releases/latest" | grep -i '^location:' | awk -F'/' '{print $NF}' | tr -d '\r')
else
  TAG="$VERSION"
fi

if [[ -z "$TAG" ]]; then
  echo "❌ Could not determine version tag."
  exit 1
fi

VER="${TAG#v}"
TAG="v${VER}"

# Tauri builds the artifact using the base version from tauri.conf.json
PKG_VER="${VER%%-rc.*}"

DL_URL="https://github.com/$REPO/releases/download/${TAG}/Wazuh.Agent.Installer_${PKG_VER}_universal.dmg"

# Verify URL exists before downloading
if ! curl -sI -f "$DL_URL" > /dev/null; then
  echo "❌ Could not find macOS DMG ($DL_URL) in release"
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
if [[ -z "$APP_PATH" ]]; then
  echo "❌ Could not find any .app bundle inside the mounted DMG"
  hdiutil detach "$TMP/mount" -quiet
  exit 1
fi

APP_NAME=$(basename "$APP_PATH")
TARGET="/Applications/$APP_NAME"
NEEDS_SUDO=0

if [[ -e "$TARGET" ]] && [[ ! -w "$TARGET" ]]; then
  NEEDS_SUDO=1
elif [[ ! -e "$TARGET" ]] && [[ ! -w "/Applications/" ]]; then
  NEEDS_SUDO=1
fi

if [[ "$NEEDS_SUDO" -eq 1 ]]; then
  echo "Prompting for administrator privileges to copy app..."
  if ! osascript -e "do shell script \"rm -rf \\\"$TARGET\\\" && cp -R \\\"$APP_PATH\\\" /Applications/ && xattr -dr com.apple.quarantine \\\"$TARGET\\\"\" with administrator privileges"; then
    echo "Error: Administrator privileges were denied or installation failed." >&2
    hdiutil detach "$TMP/mount" -quiet
    exit 1
  fi
else
  echo "Copying $APP_NAME to /Applications/..."
  rm -rf "$TARGET"
  cp -R "$APP_PATH" /Applications/
  echo "Removing quarantine attribute to bypass macOS Gatekeeper..."
  xattr -dr com.apple.quarantine "$TARGET"
fi

hdiutil detach "$TMP/mount" -quiet

echo "Success: Wazuh Agent Installer installed successfully! You can find it in your Applications folder."

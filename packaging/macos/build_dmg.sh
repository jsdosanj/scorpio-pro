#!/usr/bin/env bash
# Build a macOS DMG installer for Scorpio Pro using PyInstaller.
#
# Prerequisites:
#   brew install create-dmg
#   pip install pyinstaller
#
# Usage:
#   chmod +x packaging/macos/build_dmg.sh
#   ./packaging/macos/build_dmg.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
APP_NAME="ScorpioPro"
VERSION="1.0.0"
DIST_DIR="${REPO_ROOT}/dist"
BUILD_DIR="${REPO_ROOT}/build"

echo "=================================================="
echo " Scorpio Pro — macOS DMG Build"
echo "=================================================="

cd "${REPO_ROOT}"

# --- Step 1: Ensure PyInstaller is available ---------------------------------
if ! command -v pyinstaller &>/dev/null; then
    echo "[+] Installing PyInstaller..."
    pip install pyinstaller
fi

# --- Step 2: Build standalone binary with PyInstaller -----------------------
echo "[+] Building standalone binary..."
pyinstaller \
    --onefile \
    --name "${APP_NAME}" \
    --add-data "scorpio_pro/reporting/templates:scorpio_pro/reporting/templates" \
    --hidden-import "scorpio_pro.scanners.system_scanner" \
    --hidden-import "scorpio_pro.scanners.network_scanner" \
    --hidden-import "scorpio_pro.scanners.vuln_scanner" \
    --hidden-import "scorpio_pro.scanners.remote_access_scanner" \
    --hidden-import "scorpio_pro.scanners.cloud_scanner" \
    --hidden-import "scorpio_pro.scanners.app_scanner" \
    --hidden-import "scorpio_pro.scanners.shared_drive_scanner" \
    --distpath "${DIST_DIR}" \
    --workpath "${BUILD_DIR}" \
    scorpio_pro/cli.py

echo "[+] Binary built at: ${DIST_DIR}/${APP_NAME}"

# --- Step 3: Create macOS .app bundle wrapper --------------------------------
APP_BUNDLE="${DIST_DIR}/${APP_NAME}.app"
mkdir -p "${APP_BUNDLE}/Contents/MacOS"
mkdir -p "${APP_BUNDLE}/Contents/Resources"

cp "${DIST_DIR}/${APP_NAME}" "${APP_BUNDLE}/Contents/MacOS/${APP_NAME}"

cat > "${APP_BUNDLE}/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>    <string>${APP_NAME}</string>
    <key>CFBundleIdentifier</key>   <string>com.jsdosanj.scorpio-pro</string>
    <key>CFBundleName</key>         <string>${APP_NAME}</string>
    <key>CFBundleVersion</key>      <string>${VERSION}</string>
    <key>CFBundlePackageType</key>  <string>APPL</string>
    <key>LSMinimumSystemVersion</key><string>12.0</string>
    <key>LSUIElement</key>          <true/>
</dict>
</plist>
PLIST

# --- Step 4: Build DMG -------------------------------------------------------
DMG_PATH="${DIST_DIR}/ScorpioPro-${VERSION}.dmg"
echo "[+] Building DMG at: ${DMG_PATH}"

if command -v create-dmg &>/dev/null; then
    create-dmg \
        --volname "Scorpio Pro ${VERSION}" \
        --window-pos 200 120 \
        --window-size 600 300 \
        --icon-size 100 \
        --icon "${APP_NAME}.app" 175 120 \
        --app-drop-link 425 120 \
        "${DMG_PATH}" \
        "${DIST_DIR}/${APP_NAME}.app"
else
    echo "[!] create-dmg not found — creating plain DMG with hdiutil."
    hdiutil create \
        -volname "Scorpio Pro ${VERSION}" \
        -srcfolder "${DIST_DIR}/${APP_NAME}.app" \
        -ov -format UDZO \
        "${DMG_PATH}"
fi

echo ""
echo "=================================================="
echo " ✅ Build complete: ${DMG_PATH}"
echo "=================================================="

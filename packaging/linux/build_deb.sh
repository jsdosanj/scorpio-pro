#!/usr/bin/env bash
# Build a Debian (.deb) package for Scorpio Pro.
#
# Prerequisites:
#   pip install pyinstaller
#   sudo apt-get install dpkg-dev fakeroot
#
# Usage:
#   chmod +x packaging/linux/build_deb.sh
#   ./packaging/linux/build_deb.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
APP_NAME="scorpio-pro"
VERSION="1.0.0"
ARCH="amd64"
MAINTAINER="jsdosanj"
DESCRIPTION="State-of-the-art penetration testing and security auditing tool"
DIST_DIR="${REPO_ROOT}/dist"
PKG_DIR="${DIST_DIR}/${APP_NAME}_${VERSION}_${ARCH}"

echo "=================================================="
echo " Scorpio Pro — Debian Package Build"
echo "=================================================="

cd "${REPO_ROOT}"

# --- Step 1: Build standalone binary ----------------------------------------
if ! command -v pyinstaller &>/dev/null; then
    echo "[+] Installing PyInstaller..."
    pip install pyinstaller
fi

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
    --workpath "${DIST_DIR}/build" \
    scorpio_pro/cli.py

# --- Step 2: Create package directory structure -----------------------------
echo "[+] Creating package structure..."
mkdir -p "${PKG_DIR}/usr/local/bin"
mkdir -p "${PKG_DIR}/usr/share/doc/${APP_NAME}"
mkdir -p "${PKG_DIR}/usr/share/${APP_NAME}"
mkdir -p "${PKG_DIR}/DEBIAN"

# Binary
cp "${DIST_DIR}/${APP_NAME}" "${PKG_DIR}/usr/local/bin/${APP_NAME}"
chmod 0755 "${PKG_DIR}/usr/local/bin/${APP_NAME}"

# Documentation
cp "${REPO_ROOT}/README.md" "${PKG_DIR}/usr/share/doc/${APP_NAME}/" 2>/dev/null || true
cp "${REPO_ROOT}/LICENSE" "${PKG_DIR}/usr/share/doc/${APP_NAME}/"
cp "${REPO_ROOT}/example_scope.yaml" "${PKG_DIR}/usr/share/${APP_NAME}/"

# --- Step 3: Create control file --------------------------------------------
cat > "${PKG_DIR}/DEBIAN/control" <<CONTROL
Package: ${APP_NAME}
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: ${MAINTAINER}
Description: ${DESCRIPTION}
 Scorpio Pro is a comprehensive penetration testing tool that performs
 system, network, vulnerability, cloud, and application security assessments.
 It generates compliance-mapped reports in HTML, JSON, and TXT formats.
Homepage: https://github.com/jsdosanj/scorpio-pro
Depends: libc6
CONTROL

# --- Step 4: Create conffiles (if any) -------------------------------------
cat > "${PKG_DIR}/DEBIAN/conffiles" <<CONFFILES
CONFFILES

# --- Step 5: Build .deb ------------------------------------------------------
echo "[+] Building .deb package..."
fakeroot dpkg-deb --build "${PKG_DIR}"

DEB_PATH="${DIST_DIR}/${APP_NAME}_${VERSION}_${ARCH}.deb"
echo ""
echo "=================================================="
echo " ✅ Package built: ${DEB_PATH}"
echo ""
echo " Install with:"
echo "   sudo dpkg -i ${DEB_PATH}"
echo "=================================================="

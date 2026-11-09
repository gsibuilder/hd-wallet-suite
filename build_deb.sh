#!/bin/bash
set -e

# ── HD Wallet Suite — Debian Package Builder ─────────────────────────
# Version: 2.0-5
# Builds a self-contained .deb with bundled Python deps, icons, and .desktop

PKG_NAME="hd-wallet-suite"
VERSION="2.0-5"
ARCH="amd64"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)/hd-wallet-suite"
BUILD_DIR="/tmp/${PKG_NAME}_${VERSION}_${ARCH}"
DEB_OUT="$(cd "$(dirname "$0")" && pwd)/${PKG_NAME}_${VERSION}_${ARCH}.deb"

echo "══════════════════════════════════════════════════════"
echo "  Building ${PKG_NAME} v${VERSION} (.deb)"
echo "══════════════════════════════════════════════════════"

# ── Clean ─────────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/DEBIAN"
mkdir -p "$BUILD_DIR/usr/bin"
mkdir -p "$BUILD_DIR/usr/share/$PKG_NAME"
mkdir -p "$BUILD_DIR/usr/share/applications"
mkdir -p "$BUILD_DIR/usr/share/pixmaps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/16x16/apps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/24x24/apps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/32x32/apps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/48x48/apps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/64x64/apps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/128x128/apps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/256x256/apps"
mkdir -p "$BUILD_DIR/usr/share/icons/hicolor/512x512/apps"

# ── DEBIAN/control ────────────────────────────────────────────────────
cat > "$BUILD_DIR/DEBIAN/control" <<EOF
Package: ${PKG_NAME}
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${ARCH}
Maintainer: HD Wallet Team <support@hdwallet.io>
Depends: python3, python3-pyqt6, python3-cryptography, python3-requests, python3-bsddb3 | python3-berkeleydb
Description: HD Wallet Cryptographic Engine & Multichain Suite (v2.0)
 Complete HD Wallet suite supporting BIP-32/39/44/49/84/86/380 standards,
 SLIP-0010 Ed25519 multichain address generators, PrivateKeyFinder.io key space navigation,
 forensic carving, wallet recovery, and PSBT tools.
EOF

# ── DEBIAN/postinst — update icon cache ──────────────────────────────
cat > "$BUILD_DIR/DEBIAN/postinst" <<'EOF'
#!/bin/bash
if command -v gtk-update-icon-cache &>/dev/null; then
    gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
fi
if command -v update-desktop-database &>/dev/null; then
    update-desktop-database /usr/share/applications 2>/dev/null || true
fi
EOF
chmod 755 "$BUILD_DIR/DEBIAN/postinst"

# ── .desktop file ─────────────────────────────────────────────────────
cat > "$BUILD_DIR/usr/share/applications/${PKG_NAME}.desktop" <<EOF
[Desktop Entry]
Name=HD Wallet Suite
GenericName=Cryptocurrency Wallet Tool
Comment=HD Wallet Cryptographic Engine & Multichain Suite — BIP-32/39/44/84/86
Exec=/usr/bin/${PKG_NAME}
Icon=${PKG_NAME}
Terminal=false
Type=Application
Categories=Utility;Security;Finance;
Keywords=bitcoin;ethereum;crypto;wallet;hd;bip39;mnemonic;private;key;
StartupNotify=true
StartupWMClass=hd-wallet-suite
EOF

# ── Launcher script ──────────────────────────────────────────────────
cat > "$BUILD_DIR/usr/bin/${PKG_NAME}" <<'EOF'
#!/bin/bash
exec python3 /usr/share/hd-wallet-suite/main.py "$@"
EOF
chmod 755 "$BUILD_DIR/usr/bin/${PKG_NAME}"

# ── Copy application source ──────────────────────────────────────────
echo "Copying application files..."
rsync -a --exclude='__pycache__' \
         --exclude='*.pyc' \
         --exclude='.pytest_cache' \
         --exclude='.idea' \
         "$SRC_DIR/" "$BUILD_DIR/usr/share/$PKG_NAME/"

# ── Install icons ────────────────────────────────────────────────────
echo "Installing icons..."
ICON_DIR="$SRC_DIR/icons"
if [ -d "$ICON_DIR" ]; then
    for SIZE in 16 24 32 48 64 128 256 512; do
        SRC_ICON="$ICON_DIR/${PKG_NAME}-${SIZE}.png"
        if [ -f "$SRC_ICON" ]; then
            cp "$SRC_ICON" "$BUILD_DIR/usr/share/icons/hicolor/${SIZE}x${SIZE}/apps/${PKG_NAME}.png"
        fi
    done
    # Pixmap fallback (48x48)
    if [ -f "$ICON_DIR/${PKG_NAME}-48.png" ]; then
        cp "$ICON_DIR/${PKG_NAME}-48.png" "$BUILD_DIR/usr/share/pixmaps/${PKG_NAME}.png"
    fi
fi

# ── Build .deb ────────────────────────────────────────────────────────
echo "Building .deb package..."
dpkg-deb --build "$BUILD_DIR" "$DEB_OUT"
echo ""
echo "══════════════════════════════════════════════════════"
echo "  ✅ Built: $DEB_OUT"
echo "  📦 Size: $(du -h "$DEB_OUT" | cut -f1)"
echo "══════════════════════════════════════════════════════"

# ── Cleanup ───────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"
echo "Done."

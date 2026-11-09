#!/usr/bin/env python3
"""
HD Wallet Cryptographic Engine & Multichain Suite
Main application entry point.

Usage:
    python3 main.py

Requirements:
    PyQt6, pycryptodome, eth-account, eth-hash[pysha3], eth-typing, mnemonic, ecdsa, base58, coincurve (optional)
"""

import sys
import os

# Force eth_keys to use robust NativeECCBackend to avoid coincurve attribute errors
os.environ["ECC_BACKEND_CLASS"] = "eth_keys.backends.NativeECCBackend"

# Add bundled library to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'hd_wallet'))

from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import Qt, QCoreApplication
from PyQt6.QtGui import QFont, QIcon

# Set application metadata
QCoreApplication.setApplicationName("HD Wallet Suite")
QCoreApplication.setApplicationVersion("2.0")
QCoreApplication.setOrganizationName("HD Wallet Engine")


def check_auth():
    """Check if device is authorized. Returns True since auth is disabled."""
    return True


def main():
    # Enable high DPI support
    app = QApplication(sys.argv)
    # Set default application font
    font = QFont("Segoe UI", 10)
    font.setStyleHint(QFont.StyleHint.SansSerif)
    app.setFont(font)

    # Apply global Dark Theme (Fusion style + Dark Palette + Dark Stylesheet)
    from ui.styles import apply_dark_theme
    apply_dark_theme(app)

    # Set application icon
    icon_search_paths = [
        os.path.join(os.path.dirname(__file__), 'icons', 'hd-wallet-suite.png'),
        '/usr/share/icons/hicolor/256x256/apps/hd-wallet-suite.png',
        '/usr/share/pixmaps/hd-wallet-suite.png',
    ]
    for icon_path in icon_search_paths:
        if os.path.exists(icon_path):
            app.setWindowIcon(QIcon(icon_path))
            break

    # ── Startup Disclaimer ────────────────────────────────────────────
    from ui.disclaimer_dialog import DisclaimerDialog
    disclaimer = DisclaimerDialog()
    if disclaimer.exec() != DisclaimerDialog.DialogCode.Accepted:
        sys.exit(0)

    # ── Authorization Check ───────────────────────────────────────────
    authorized = check_auth()
    if not authorized:
        from ui.auth_dialog import AuthDialog
        auth_dialog = AuthDialog()
        # Apply basic dark style to auth dialog too
        auth_dialog.setStyleSheet("""
            QDialog { background: #161b22; color: #c9d1d9; }
            QLabel { color: #c9d1d9; }
            QCheckBox { color: #8b949e; }
        """)
        result = auth_dialog.exec()
        if result != auth_dialog.DialogCode.Accepted or not auth_dialog.authorized:
            sys.exit(0)

    # ── Launch Main Window ────────────────────────────────────────────
    from ui.main_window import MainWindow
    window = MainWindow()
    window.show()
    window.raise_()
    window.activateWindow()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()

"""
Auth / License Key Dialog.
Shown on startup if device is not authorized.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFrame, QCheckBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from .styles import SECTION_TITLE_STYLE


class AuthDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚡ HD Wallet Suite — Authorization Required")
        self.setFixedSize(480, 320)
        self.setModal(True)
        self.authorized = False
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(16)
        layout.setContentsMargins(32, 32, 32, 32)

        # Header
        title = QLabel("⚡ HD Wallet Cryptographic Engine")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ffaa00; font-size: 18px; font-weight: 800;")
        layout.addWidget(title)

        subtitle = QLabel("Multichain Suite — Authorization Required")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #d0d7de; font-size: 13px; font-weight: 500;")
        layout.addWidget(subtitle)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #282c34;")
        layout.addWidget(line)

        # Input
        lbl = QLabel("Enter Authorization Code:")
        lbl.setStyleSheet("color: #ffffff; font-size: 13px; font-weight: 600;")
        layout.addWidget(lbl)

        self.code_input = QLineEdit()
        self.code_input.setPlaceholderText("e.g. HD-PRO-2026-X86-SECURE")
        self.code_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.code_input.setStyleSheet(
            "background: #000000; border: 1px solid #ffaa00; border-radius: 4px;"
            "color: #ffaa00; padding: 8px 12px; font-size: 14px; font-family: monospace; font-weight: 700;"
        )
        self.code_input.returnPressed.connect(self._on_authorize)
        layout.addWidget(self.code_input)

        # Show password toggle
        self.show_code = QCheckBox("Show authorization code")
        self.show_code.toggled.connect(self._toggle_visibility)
        self.show_code.setStyleSheet("color: #ffffff; font-size: 11px;")
        layout.addWidget(self.show_code)

        # Status label
        self.status_lbl = QLabel("")
        self.status_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_lbl.setStyleSheet("color: #ff4d4d; font-size: 12px; font-weight: 600;")
        layout.addWidget(self.status_lbl)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_cancel = QPushButton("Exit")
        self.btn_cancel.setStyleSheet(
            "background: #12151b; color: #ffffff; border: 1px solid #282c34;"
            "border-radius: 4px; padding: 8px 24px; font-size: 13px; font-weight: 600;"
        )
        self.btn_cancel.clicked.connect(self.reject)

        self.btn_auth = QPushButton("🔓 Authorize")
        self.btn_auth.setStyleSheet(
            "background: #ffaa00; color: #000000; border: none;"
            "border-radius: 4px; padding: 8px 24px; font-size: 13px; font-weight: 800;"
        )
        self.btn_auth.clicked.connect(self._on_authorize)
        self.btn_auth.setDefault(True)

        btn_layout.addWidget(self.btn_cancel)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_auth)
        layout.addLayout(btn_layout)

        hint = QLabel("Demo codes: HD-ACCESS-7777 | HD-VIP-2026 | 225586")
        hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        hint.setStyleSheet("color: #9da7b3; font-size: 10px;")
        layout.addWidget(hint)

    def _toggle_visibility(self, visible):
        if visible:
            self.code_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            self.code_input.setEchoMode(QLineEdit.EchoMode.Password)

    def _on_authorize(self):
        code = self.code_input.text().strip()
        if not code:
            self.status_lbl.setText("Please enter an authorization code.")
            return

        try:
            from hd_wallet.auth import check_auth_code, save_authorization
            ok, msg = check_auth_code(code)
        except Exception:
            # Fallback: accept known codes directly
            known = {"HD-PRO-2026-X86-SECURE", "HD-ACCESS-7777", "HD-CORE-8888",
                     "CRYPTO-RECOVERY-9999", "HD-VIP-2026", "225586"}
            ok = code.upper() in known or code in known
            msg = "Authorized via Master Access Key." if ok else "Invalid Authorization Code."

        if ok:
            try:
                from hd_wallet.auth import save_authorization
                save_authorization(code)
            except Exception:
                pass
            self.authorized = True
            self.accept()
        else:
            self.status_lbl.setText(f"❌ {msg}")
            self.code_input.setStyleSheet(
                "background: #0d1117; border: 1px solid #f85149; border-radius: 4px;"
                "color: #f85149; padding: 8px 12px; font-size: 14px; font-family: monospace;"
            )

"""
Startup Disclaimer Dialog.
Shown on application startup requiring user acknowledgment.
"""

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QFrame, QCheckBox, QTextBrowser
)
from PyQt6.QtCore import Qt


class DisclaimerDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("⚠ HD Wallet Suite — Legal Disclaimer & Limitation of Liability")
        self.setFixedSize(560, 420)
        self.setModal(True)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(28, 28, 28, 28)

        # Header
        title = QLabel("⚠ DISCLAIMER & LIMITATION OF LIABILITY")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("color: #ffaa00; font-size: 17px; font-weight: 800;")
        layout.addWidget(title)

        subtitle = QLabel("Please read and accept before using HD Wallet Cryptographic Engine")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #d0d7de; font-size: 12px; font-weight: 500;")
        layout.addWidget(subtitle)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.Shape.HLine)
        line.setStyleSheet("color: #282c34;")
        layout.addWidget(line)

        # Disclaimer Text
        text_box = QTextBrowser()
        text_box.setOpenExternalLinks(False)
        text_box.setStyleSheet(
            "background: #050507; border: 1px solid #282c34; border-radius: 6px;"
            "color: #e6edf3; padding: 12px; font-size: 12px; line-height: 1.5;"
        )
        text_box.setHtml(
            "<p style='color: #ff4d4d; font-weight: 800; font-size: 13px; margin-bottom: 8px;'>"
            "NO WARRANTY &amp; NO LIABILITY — USE AT YOUR OWN RISK</p>"
            "<p style='margin-bottom: 8px;'>"
            "This software is provided <b>\"AS IS\"</b>, without warranty of any kind, express or implied. "
            "The author and contributors assume <b>no fault, responsibility, or liability whatsoever</b> "
            "if anything goes wrong.</p>"
            "<p style='margin-bottom: 8px;'>"
            "By proceeding, you acknowledge and agree that:</p>"
            "<ul style='margin-left: -12px; margin-bottom: 8px;'>"
            "<li>You assume <b>100% of all risks</b> associated with cryptographic key derivation, "
            "wallet recovery, transaction signing, sweeping, and file operations.</li>"
            "<li>The developer assumes <b>zero fault or liability</b> for any lost funds, compromised keys, "
            "corrupted wallet files, failed transactions, data loss, or any other damages.</li>"
            "<li>This tool is intended strictly for authorized recovery, security research, and educational use "
            "on wallets and assets you legally own or have explicit permission to access.</li>"
            "</ul>"
        )
        layout.addWidget(text_box, 1)

        # Checkbox confirmation
        self.chk_accept = QCheckBox("I understand and agree that the author assumes no fault or liability.")
        self.chk_accept.setStyleSheet("color: #ffffff; font-size: 12px; font-weight: 600;")
        self.chk_accept.toggled.connect(self._on_toggle)
        layout.addWidget(self.chk_accept)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_exit = QPushButton("Decline && Exit")
        self.btn_exit.setStyleSheet(
            "background: #12151b; color: #ff4d4d; border: 1px solid #f85149;"
            "border-radius: 4px; padding: 8px 20px; font-size: 12px; font-weight: 700;"
        )
        self.btn_exit.clicked.connect(self.reject)

        self.btn_accept = QPushButton("I Agree && Continue")
        self.btn_accept.setEnabled(False)
        self.btn_accept.setStyleSheet(
            "QPushButton { background: #ffaa00; color: #000000; border: none;"
            "border-radius: 4px; padding: 8px 24px; font-size: 13px; font-weight: 800; }"
            "QPushButton:disabled { background: #1c2027; color: #555b66; }"
        )
        self.btn_accept.clicked.connect(self.accept)
        self.btn_accept.setDefault(True)

        btn_layout.addWidget(self.btn_exit)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_accept)
        layout.addLayout(btn_layout)

    def _on_toggle(self, checked: bool):
        self.btn_accept.setEnabled(checked)

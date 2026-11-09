"""
MainWindow — HD Wallet Cryptographic Engine & Multichain Suite
Assembles all tabs, top toolbar, status bar, and global wallet state.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QComboBox, QTabWidget, QStatusBar, QFrame,
    QApplication, QLineEdit, QSizePolicy, QInputDialog
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont, QFontDatabase

from .styles import MAIN_STYLESHEET
from .tab_key_inspector import KeyInspectorTab
from .tab_batch_table import BatchAddressTab
from .tab_descriptors import DescriptorWalletsTab
from .tab_multichain import MultichainDirectoryTab
from .tab_wallet_files import WalletFilesTab
from .tab_sweeper import MultichainSweeperTab
from .tab_key_space import KeySpaceExplorerTab
from .tab_btcrecover import BTCRecoverTab
from .tab_psbt import PSBTToolkitTab
from .tab_carving import ForensicCarvingTab
from .tab_all_chains import AllChainsBalanceTab

# Quick test vectors (as shown in the screenshot dropdown)
TEST_VECTORS = [
    ("Quick Test Vector", "more loud knife patch mosquito route rule nurse truth sweet pause cram"),
    ("12-Word Standard (BIP-39)", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"),
    ("24-Word Standard (BIP-39)", "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art"),
    ("All Zeros Seed Hex", "0" * 64),
    ("Electrum Test Seed", "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863"),
]

NETWORKS = [
    ("Bitcoin Mainnet (BTC)", "bitcoin"),
    ("Bitcoin Testnet (TBTC)", "bitcoin_testnet"),
    ("Ethereum (ETH)", "ethereum"),
    ("BNB Chain (BNB)", "bnb"),
    ("Litecoin (LTC)", "litecoin"),
    ("Dogecoin (DOGE)", "dogecoin"),
    ("Tron (TRX)", "tron"),
    ("Solana (SOL)", "solana"),
    ("XRP Ledger (XRP)", "xrp"),
    ("Dash (DASH)", "dash"),
    ("Zcash (ZEC)", "zcash"),
    ("Cosmos (ATOM)", "cosmos"),
]


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("⚡ HD Wallet Cryptographic Engine & Multichain Suite")
        self.setMinimumSize(1280, 800)
        self.resize(1366, 860)

        self.current_wallet = None
        self.current_network = "bitcoin"

        self._setup_ui()
        self._apply_styles()

    def _apply_styles(self):
        self.setStyleSheet(MAIN_STYLESHEET)

    def _setup_ui(self):
        central = QWidget()
        central.setObjectName("central_widget")
        self.setCentralWidget(central)

        main_layout = QVBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ── Top Toolbar Frame ─────────────────────────────────────────
        toolbar_frame = QFrame()
        toolbar_frame.setObjectName("toolbar_frame")
        toolbar_frame.setFixedHeight(48)
        toolbar_frame.setStyleSheet(
            "QFrame#toolbar_frame { background: #090c10; border-bottom: 1px solid #21262d; }"
        )
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(14, 6, 14, 6)
        toolbar_layout.setSpacing(10)

        # Logo / app name (left)
        logo_title = QLabel("⚡ HD Wallet Suite")
        logo_title.setStyleSheet("color: #f0a500; font-weight: 800; font-size: 14px; border: none;")
        toolbar_layout.addWidget(logo_title)

        # Mnemonic status indicator (clean pill badge)
        self.mnemonic_status_btn = QPushButton("● Valid BIP-39 Seed")
        self.mnemonic_status_btn.setStyleSheet(
            "QPushButton { background: #122117; color: #3fb950; border: 1px solid #238636; border-radius: 12px;"
            "padding: 3px 12px; font-size: 11px; font-weight: 700; min-height: 24px; }"
        )
        self.mnemonic_status_btn.setCheckable(False)
        toolbar_layout.addWidget(self.mnemonic_status_btn)

        toolbar_layout.addStretch()

        # Network selector
        net_lbl = QLabel("Network:")
        net_lbl.setStyleSheet("color: #8b949e; font-size: 11px; font-weight: 600;")
        toolbar_layout.addWidget(net_lbl)

        self.network_combo = QComboBox()
        self.network_combo.setFixedWidth(180)
        for name, val in NETWORKS:
            self.network_combo.addItem(name, val)
        self.network_combo.currentIndexChanged.connect(self._on_network_changed)
        toolbar_layout.addWidget(self.network_combo)

        # Test vector dropdown
        self.test_vector_btn = QComboBox()
        self.test_vector_btn.setFixedWidth(160)
        for name, value in TEST_VECTORS:
            self.test_vector_btn.addItem(name, value)
        self.test_vector_btn.activated.connect(self._on_test_vector_selected)
        toolbar_layout.addWidget(self.test_vector_btn)

        # Quick action buttons
        self.btn_12words = QPushButton("New 12-Word")
        self.btn_12words.setObjectName("btn_12words")
        self.btn_12words.clicked.connect(lambda: self._generate_mnemonic(12))
        toolbar_layout.addWidget(self.btn_12words)

        self.btn_24words = QPushButton("New 24-Word")
        self.btn_24words.setObjectName("btn_24words")
        self.btn_24words.clicked.connect(lambda: self._generate_mnemonic(24))
        toolbar_layout.addWidget(self.btn_24words)

        self.btn_load_xprv = QPushButton("Load Key")
        self.btn_load_xprv.setObjectName("btn_load_xprv")
        self.btn_load_xprv.clicked.connect(self._prompt_load_xprv)
        toolbar_layout.addWidget(self.btn_load_xprv)

        self.btn_import = QPushButton("🔒 Import Wallet")
        self.btn_import.setObjectName("btn_import_wallet")
        self.btn_import.clicked.connect(self._import_wallet)
        toolbar_layout.addWidget(self.btn_import)

        main_layout.addWidget(toolbar_frame)

        # ── Tab Widget ────────────────────────────────────────────────
        self.tab_widget = QTabWidget()
        self.tab_widget.setTabPosition(QTabWidget.TabPosition.North)
        self.tab_widget.setDocumentMode(True)

        # Create all tabs
        self.tab_key_inspector = KeyInspectorTab(self)
        self.tab_batch_table = BatchAddressTab(self)
        self.tab_descriptors = DescriptorWalletsTab(self)
        self.tab_multichain = MultichainDirectoryTab(self)
        self.tab_wallet_files = WalletFilesTab(self)
        self.tab_sweeper = MultichainSweeperTab(self)
        self.tab_key_space = KeySpaceExplorerTab(self)
        self.tab_btcrecover = BTCRecoverTab(self)
        self.tab_psbt = PSBTToolkitTab(self)
        self.tab_carving = ForensicCarvingTab(self)
        self.tab_all_chains = AllChainsBalanceTab(self)

        # Add tabs with concise, clean titles
        self.tab_widget.addTab(self.tab_key_inspector, "Key Inspector")
        self.tab_widget.addTab(self.tab_batch_table, "Batch Addresses")
        self.tab_widget.addTab(self.tab_descriptors, "Descriptors")
        self.tab_widget.addTab(self.tab_multichain, "Multichain (50+)")
        self.tab_widget.addTab(self.tab_all_chains, "All Balances")
        self.tab_widget.addTab(self.tab_sweeper, "Sweeper")
        self.tab_widget.addTab(self.tab_wallet_files, "Wallet DBs")
        self.tab_widget.addTab(self.tab_key_space, "Key Space")
        self.tab_widget.addTab(self.tab_btcrecover, "Recovery")
        self.tab_widget.addTab(self.tab_psbt, "PSBT")
        self.tab_widget.addTab(self.tab_carving, "Forensic Carving")

        main_layout.addWidget(self.tab_widget, 1)

        # ── Status Bar ────────────────────────────────────────────────
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)

        # Left: crypto engine info
        self.status_engine = QLabel("Engine: SECP256k1 • BIP-32/39/44/49/84/86/380")
        self.status_engine.setStyleSheet("color: #3fb950; font-size: 11px; font-weight: 600; padding: 2px 8px;")
        self.status_bar.addWidget(self.status_engine)

        # Center: status messages
        self.status_msg = QLabel("")
        self.status_msg.setStyleSheet("color: #e6edf3; font-size: 11px;")
        self.status_bar.addWidget(self.status_msg, 1)

        # Right: author info
        status_right = QLabel("v2.0")
        status_right.setStyleSheet("color: #8b949e; font-size: 11px; padding: 2px 8px;")
        self.status_bar.addPermanentWidget(status_right)

        # Check crypto acceleration
        QTimer.singleShot(500, self._check_crypto_accel)

        # Auto-load test vector on startup
        QTimer.singleShot(100, self._load_default_test_vector)

    def _check_crypto_accel(self):
        try:
            from hd_wallet.crypto_accel import HAS_COINCURVE, get_crypto_engine_info
            info = get_crypto_engine_info()
            engine = info.get('engine', 'Pure Python')
            if HAS_COINCURVE:
                self.status_engine.setText(f"⚡ C-Accelerated Core: libsecp256k1  •  BIP-32/39/44/49/84/86/380")
                self.status_engine.setStyleSheet("color: #f0a500; font-size: 11px; padding: 2px 8px;")
            else:
                self.status_engine.setText(f"⚡ Pure Python Core  •  BIP-32/39/44/49/84/86/380")
        except Exception:
            pass

    def _load_default_test_vector(self):
        """Load the first test vector on startup for immediate demo."""
        default_mnemonic = TEST_VECTORS[0][1]
        self.load_mnemonic(default_mnemonic)

    # ── Public API (called by tabs) ───────────────────────────────────

    def set_wallet(self, wallet):
        """Update the shared wallet and notify all tabs."""
        self.current_wallet = wallet
        self.tab_batch_table.set_wallet(wallet)
        self.tab_descriptors.set_wallet(wallet)
        self.tab_multichain.set_wallet(wallet)
        self.tab_sweeper.set_wallet(wallet)
        self.tab_psbt.set_wallet(wallet)
        self.tab_all_chains.set_wallet(wallet)

    def set_mnemonic_status(self, valid: bool, text: str):
        """Update the mnemonic validity indicator in the toolbar."""
        if valid:
            self.mnemonic_status_btn.setText("● Valid BIP-39 Seed")
            self.mnemonic_status_btn.setStyleSheet(
                "QPushButton { background: #122117; color: #3fb950; border: 1px solid #238636; border-radius: 12px;"
                "padding: 3px 12px; font-size: 11px; font-weight: 700; min-height: 24px; }"
            )
        else:
            clean_t = text.strip()
            if clean_t.startswith("0x"):
                clean_t = clean_t[2:].strip()
            if text.startswith(('xprv', 'xpub', 'yprv', 'ypub', 'zprv', 'zpub')):
                self.mnemonic_status_btn.setText("● Extended Key (xprv/xpub)")
                self.mnemonic_status_btn.setStyleSheet(
                    "QPushButton { background: #101f33; color: #58a6ff; border: 1px solid #1f6feb; border-radius: 12px;"
                    "padding: 3px 12px; font-size: 11px; font-weight: 700; min-height: 24px; }"
                )
            elif len(text) in (51, 52) and text[0] in ('5', 'K', 'L'):
                self.mnemonic_status_btn.setText("● WIF Private Key")
                self.mnemonic_status_btn.setStyleSheet(
                    "QPushButton { background: #101f33; color: #58a6ff; border: 1px solid #1f6feb; border-radius: 12px;"
                    "padding: 3px 12px; font-size: 11px; font-weight: 700; min-height: 24px; }"
                )
            elif (len(clean_t) == 64 or (len(clean_t) > 0 and text.strip().startswith("0x"))) and all(c in "0123456789abcdefABCDEF" for c in clean_t):
                self.mnemonic_status_btn.setText("● Raw Private Key (Hex)")
                self.mnemonic_status_btn.setStyleSheet(
                    "QPushButton { background: #101f33; color: #58a6ff; border: 1px solid #1f6feb; border-radius: 12px;"
                    "padding: 3px 12px; font-size: 11px; font-weight: 700; min-height: 24px; }"
                )
            else:
                self.mnemonic_status_btn.setText("● Custom Input")
                self.mnemonic_status_btn.setStyleSheet(
                    "QPushButton { background: #261f10; color: #f0a500; border: 1px solid #9e6a03; border-radius: 12px;"
                    "padding: 3px 12px; font-size: 11px; font-weight: 700; min-height: 24px; }"
                )

    def status_bar_msg(self, msg: str):
        """Display a status message in the status bar."""
        self.status_msg.setText(msg)

    def load_mnemonic(self, mnemonic: str, passphrase: str = ""):
        """Load a mnemonic phrase or key globally and update all tabs."""
        if hasattr(self.tab_key_inspector, 'passphrase_input'):
            self.tab_key_inspector.passphrase_input.setText(passphrase)
        self.tab_key_inspector.mnemonic_input.setPlainText(mnemonic)
        self.tab_key_inspector._on_derive()
        self.tab_widget.setCurrentIndex(0)

    def load_from_xprv(self, xprv: str):
        """Load from an extended key."""
        if hasattr(self.tab_key_inspector, 'passphrase_input'):
            self.tab_key_inspector.passphrase_input.setText("")
        self.tab_key_inspector.mnemonic_input.setPlainText(xprv)
        self.tab_key_inspector._on_derive()

    # ── Toolbar Handlers ─────────────────────────────────────────────

    def _on_test_vector_selected(self, idx):
        value = self.test_vector_btn.currentData()
        if value:
            self.load_mnemonic(value)

    def _on_network_changed(self, idx):
        self.current_network = self.network_combo.currentData()
        if hasattr(self, 'tab_key_inspector') and self.tab_key_inspector:
            self.tab_key_inspector.set_network(self.current_network)
        if self.current_wallet:
            try:
                from hd_wallet.wallet import HDWallet
                raw = self.current_wallet.raw_input
                wallet = HDWallet(raw, network=self.current_network)
                self.set_wallet(wallet)
            except Exception:
                pass

    def _generate_mnemonic(self, word_count: int):
        try:
            from hd_wallet.wallet import generate_mnemonic
            mnemonic = generate_mnemonic(word_count)
            self.load_mnemonic(mnemonic)
            self.status_bar_msg(f"Generated new {word_count}-word BIP-39 mnemonic.")
        except Exception as e:
            self.status_bar_msg(f"Mnemonic generation error: {e}")

    def _prompt_load_xprv(self):
        self._open_secure_import(initial_tab=1)

    def _import_wallet(self):
        """Open the Hardened Secure Wallet Import Dialog (Seed, Private Hex/WIF/xprv, or Backup File)."""
        self._open_secure_import(initial_tab=0)

    def _open_secure_import(self, initial_tab: int = 0):
        from .import_dialog import SecureImportDialog
        dlg = SecureImportDialog(self)
        dlg.tabs.setCurrentIndex(initial_tab)
        if dlg.exec() == SecureImportDialog.DialogCode.Accepted:
            # Handle DB / encrypted binary file routing if selected
            if dlg.imported_type == "db_file" and dlg.imported_file_path:
                self.tab_btcrecover.wallet_path.setText(dlg.imported_file_path)
                if dlg.imported_secret:
                    self.load_mnemonic(dlg.imported_secret, dlg.imported_passphrase)
                    self.tab_btcrecover._auto_detect()
                    self.status_bar_msg(
                        f"🔒 Verified & imported master key from backup: {os.path.basename(dlg.imported_file_path)}"
                    )
                else:
                    self.tab_widget.setCurrentWidget(self.tab_btcrecover)
                    self.tab_btcrecover._auto_detect()
                    self.status_bar_msg(
                        f"🔒 Loaded database into Recovery Inspector: {os.path.basename(dlg.imported_file_path)}"
                    )
                return

            if dlg.imported_secret:
                if dlg.imported_type == "xprv":
                    self.load_from_xprv(dlg.imported_secret)
                else:
                    self.load_mnemonic(dlg.imported_secret, dlg.imported_passphrase)
                self.status_bar_msg(f"🔒 Securely verified & imported wallet ({dlg.imported_type.upper()}).")


    def _lock_app(self):
        """Auth is disabled."""
        self.status_bar_msg("Authentication is disabled.")

    def closeEvent(self, event):
        """Signal any background worker threads to stop cleanly before exiting."""
        for tab in (
            self.tab_batch_table,
            self.tab_multichain,
            self.tab_all_chains,
            self.tab_key_space,
            self.tab_btcrecover,
        ):
            for attr in ('_balance_worker', '_worker', '_recover_worker'):
                w = getattr(tab, attr, None)
                if w and hasattr(w, 'stop') and w.isRunning():
                    w.stop()
        super().closeEvent(event)

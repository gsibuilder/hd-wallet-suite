"""
Tab 7: Key Space Explorer
PrivateKeyFinder.io style SECP256K1 private key space navigator (1 to 2^256-1)
with All 50+ Chains & Seed Word Count (12/24 Word) Combo Boxes, Custom Path Input Box,
Live Balance Auto-Check, Neon Green Highlighting, and Multi-Chain Inspector.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QApplication, QAbstractItemView, QDialog, QTabWidget
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from .tab_all_chains import AllChainsBalanceTab
from .tab_multichain import CHAINS_50


KEY_SPACE_DERIVATION_STANDARDS = [
    (f"{emoji} {display_name} [{path}]", path, net_key)
    for (net_key, display_name, symbol, emoji, path, addr_key, color) in CHAINS_50
]
KEY_SPACE_DERIVATION_STANDARDS.append(("Custom Path...", "", "bitcoin"))


class KeyDetailDialog(QDialog):
    """Detailed inspector dialog for a single raw private key with embedded All Chains balance overview."""
    def __init__(self, key_data: dict, parent=None):
        super().__init__(parent)
        self.key_data = key_data
        self.wallet = None
        self.derived_info = {}
        self.setWindowTitle(f"Key Detail Inspector — #{key_data.get('index'):,}")
        self.resize(1000, 750)
        self.setStyleSheet("QDialog { background: #000000; color: #ffffff; }")

        try:
            from hd_wallet.wallet import HDWallet
            priv_hex = key_data.get('privateKeyHex', '')
            self.wallet = HDWallet(priv_hex)
            self.derived_info = self.wallet.derive_key("m")
        except Exception:
            pass

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        top_bar = QHBoxLayout()
        title = QLabel(f"🔐 Private Key #{self.key_data.get('index'):,} — Inspector")
        title.setStyleSheet("color: #f0a500; font-size: 16px; font-weight: bold;")
        top_bar.addWidget(title)
        top_bar.addStretch()

        btn_copy_hex = QPushButton("📋 Copy Hex")
        btn_copy_hex.setStyleSheet("background: #21262d; color: #58a6ff; border: 1px solid #30363d; padding: 4px 8px; border-radius: 4px;")
        btn_copy_hex.clicked.connect(lambda: QApplication.clipboard().setText(self.key_data.get('privateKeyHex', '')))
        top_bar.addWidget(btn_copy_hex)

        btn_copy_mnemonic = QPushButton("📋 Copy Mnemonic")
        btn_copy_mnemonic.setStyleSheet("background: #21262d; color: #f0a500; border: 1px solid #30363d; padding: 4px 8px; border-radius: 4px;")
        btn_copy_mnemonic.clicked.connect(lambda: QApplication.clipboard().setText(self.key_data.get('bip39Mnemonic', '')))
        top_bar.addWidget(btn_copy_mnemonic)

        btn_copy_wif = QPushButton("📋 Copy WIF")
        btn_copy_wif.setStyleSheet("background: #21262d; color: #3fb950; border: 1px solid #30363d; padding: 4px 8px; border-radius: 4px;")
        btn_copy_wif.clicked.connect(lambda: QApplication.clipboard().setText(self.key_data.get('privateKeyWif', '')))
        top_bar.addWidget(btn_copy_wif)

        btn_copy_sol_kp = QPushButton("📋 Copy SOL Keypair")
        btn_copy_sol_kp.setStyleSheet("background: #21262d; color: #a371f7; border: 1px solid #30363d; padding: 4px 8px; border-radius: 4px;")
        btn_copy_sol_kp.clicked.connect(lambda: QApplication.clipboard().setText(self.derived_info.get('solanaKeypairBase58') or self.key_data.get('solanaKeypairBase58', '')))
        top_bar.addWidget(btn_copy_sol_kp)

        btn_copy_xrp_sec = QPushButton("📋 Copy XRP Secret")
        btn_copy_xrp_sec.setStyleSheet("background: #21262d; color: #2ea0a0; border: 1px solid #30363d; padding: 4px 8px; border-radius: 4px;")
        btn_copy_xrp_sec.clicked.connect(lambda: QApplication.clipboard().setText(self.derived_info.get('xrpSecretSeed') or self.key_data.get('xrpSecretSeed') or self.derived_info.get('xrpSecretKeySecp') or self.key_data.get('xrpSecretKeySecp') or self.key_data.get('xrpSecretKey', '')))
        top_bar.addWidget(btn_copy_xrp_sec)
        layout.addLayout(top_bar)

        tabs = QTabWidget()
        tabs.setStyleSheet("""
            QTabWidget::pane { border: 1px solid #282c34; background: #000000; border-radius: 6px; }
            QTabBar::tab { background: #0a0a0c; color: #e6edf3; padding: 8px 16px; border-top-left-radius: 4px; border-top-right-radius: 4px; margin-right: 2px; }
            QTabBar::tab:selected { background: #ffaa00; color: #000000; font-weight: bold; }
        """)

        # Tab 1: Addresses Table
        addr_tab = QWidget()
        addr_layout = QVBoxLayout(addr_tab)
        addr_layout.setContentsMargins(10, 10, 10, 10)
        addr_layout.setSpacing(6)

        lbl_hdr = QLabel("📁 Addresses & BIP-39 Mnemonic")
        lbl_hdr.setStyleSheet("color: #c9d1d9; font-size: 14px; font-weight: bold;")
        addr_layout.addWidget(lbl_hdr)

        self.addr_table = QTableWidget()
        self.addr_table.setColumnCount(4)
        self.addr_table.setHorizontalHeaderLabels(["CHAIN", "TYPE", "ADDRESS", "STATUS"])
        self.addr_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.addr_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.addr_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.addr_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.addr_table.setColumnWidth(0, 130)
        self.addr_table.setColumnWidth(1, 110)
        self.addr_table.setColumnWidth(3, 140)
        self.addr_table.setAlternatingRowColors(True)
        self.addr_table.verticalHeader().setVisible(False)
        self.addr_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        addr_layout.addWidget(self.addr_table)

        self._populate_address_table()
        tabs.addTab(addr_tab, "📌 Addresses Overview")

        # Tab 2: All Chains Balances Summary
        mw = self.parent().main_window if self.parent() and hasattr(self.parent(), 'main_window') else None
        self.all_chains_tab = AllChainsBalanceTab(main_window=mw)
        if self.wallet:
            self.all_chains_tab.set_wallet(self.wallet)
        tabs.addTab(self.all_chains_tab, "📊 All Chains Balances")

        layout.addWidget(tabs, 1)

        footer = QLabel("⚠️ Never use keys from this site for real wallets. Educational purposes only.")
        footer.setAlignment(Qt.AlignmentFlag.AlignCenter)
        footer.setStyleSheet("color: #d29922; background: #262118; border: 1px solid #bb8009; border-radius: 4px; padding: 6px; font-weight: bold; font-size: 11px;")
        layout.addWidget(footer)

        close_btn = QPushButton("Close Inspector")
        close_btn.setStyleSheet("background: #238636; color: white; font-weight: bold; padding: 10px; border-radius: 6px;")
        close_btn.clicked.connect(self.accept)

        btn_box = QHBoxLayout()
        btn_sweep = QPushButton("↗ Sweep Wallet (Open in Multichain Sweeper)")
        btn_sweep.setStyleSheet("background: #1f6feb; color: white; font-weight: bold; padding: 10px; border-radius: 6px;")
        btn_sweep.setToolTip("Load this private key / mnemonic into the Multichain Sweeper to sweep assets")
        btn_sweep.clicked.connect(self._open_in_sweeper)
        btn_box.addWidget(btn_sweep)
        btn_box.addWidget(close_btn)
        layout.addLayout(btn_box)

    def _open_in_sweeper(self):
        priv_key = self.key_data.get('bip39Mnemonic') or self.key_data.get('privateKeyHex', '')
        mw = self.parent().main_window if self.parent() and hasattr(self.parent(), 'main_window') else None
        if mw and priv_key:
            mw.load_mnemonic(priv_key)
            mw.tab_widget.setCurrentWidget(mw.tab_sweeper)
            self.accept()

    def _populate_address_table(self):
        d = self.derived_info
        d_raw = self.key_data

        rows_data = [
            ("📝 BIP-39", "MNEMONIC", d_raw.get('bip39Mnemonic', '')),
            ("🔑 WIF(C)", "WIF", d_raw.get('privateKeyWif', '')),
            ("🔑 WIF(U)", "WIF_UNCOMP", d_raw.get('privateKeyWifUncompressed', '')),
            ("🟣 SOL", "KEYPAIR (B58)", d.get('solanaKeypairBase58') or d_raw.get('solanaKeypairBase58', '')),
            ("🟣 SOL", "PRIV (B58)", d.get('solanaPrivateKeyBase58') or d_raw.get('solanaPrivateKeyBase58', '')),
            ("🟣 SOL", "KEYPAIR ARRAY", str(d_raw.get('solanaKeypairArray', '')) if d_raw.get('solanaKeypairArray') else ''),
            ("✗ XRP", "SECRET SEED (s...)", d.get('xrpSecretSeed') or d_raw.get('xrpSecretSeed', '')),
            ("✗ XRP", "SECRET KEY (SECP)", d.get('xrpSecretKeySecp') or d_raw.get('xrpSecretKeySecp', '')),
            ("✗ XRP", "SECRET KEY (WIF)", d.get('xrpSecretKey') or d_raw.get('xrpSecretKey', '')),
            ("🟠 BTC", "LEGACY", d.get('addressP2PKH') or d_raw.get('addressP2PKH', '')),
            ("🟠 BTC", "LEGACY(U)", d.get('addressP2PKHUncompressed') or d_raw.get('addressP2PKHUncompressed', '')),
            ("🟠 BTC", "SEG-WIT", d.get('addressP2WPKH') or d_raw.get('addressP2WPKH', '')),
            ("🟠 BTC", "P2SH", d.get('addressP2SH') or d_raw.get('addressP2SH', '')),
            ("🟠 BTC", "TAPROOT", d.get('addressP2TR') or d_raw.get('addressP2TR', '')),
            ("🔷 EVM", "0X", d.get('addressETH') or d_raw.get('addressETH', '')),
            ("🔴 TRX", "BASE58", d.get('addressTRX') or d_raw.get('addressTRX', '')),
            ("🟣 SOL", "BASE58", d.get('addressSOL') or d_raw.get('addressSOL', '')),
            ("🔵 SUI", "0X", d.get('addressSUI') or d_raw.get('addressSUI', '')),
            ("✗ XRP", "R...", d.get('addressXRP') or d_raw.get('addressXRP', '')),
            ("⚪ LTC", "SEG-WIT", d.get('addressLTC') or d_raw.get('addressLTC', '')),
            ("🐶 DOGE", "LEGACY", d.get('addressDOGE') or d_raw.get('addressDOGE', '')),
            ("🪙 ZEC", "T1 (C)", d.get('addressZEC') or d_raw.get('addressZEC', '')),
            ("⚛️ ATOM", "BECH32", d.get('addressATOM') or d_raw.get('addressATOM', '')),
            ("🔴 DOT", "SS58", d.get('addressDOT') or d_raw.get('addressDOT', '')),
            ("🔵 ADA", "BECH32", d.get('addressADA') or d_raw.get('addressADA', '')),
            ("💧 APT", "0X", d.get('addressAPT') or d_raw.get('addressAPT', '')),
            ("🚀 XLM", "G...", d.get('addressXLM') or d_raw.get('addressXLM', '')),
            ("🟢 NEAR", "BASE58", d.get('addressNEAR') or d_raw.get('addressNEAR', '')),
            ("⛏️ KAS", "BECH32", d.get('addressKAS') or d_raw.get('addressKAS', '')),
            ("🅰️ ALGO", "BASE32", d.get('addressALGO') or d_raw.get('addressALGO', '')),
            ("🔴 XTZ", "KT/TZ", d.get('addressXTZ') or d_raw.get('addressXTZ', '')),
            ("⬢ FIL", "F1/F3", d.get('addressFIL') or d_raw.get('addressFIL', '')),
            ("🥷 INJ", "BECH32", d.get('addressINJ') or d_raw.get('addressINJ', '')),
            ("🧪 OSMO", "BECH32", d.get('addressOSMO') or d_raw.get('addressOSMO', '')),
            ("🎯 SEI", "BECH32", d.get('addressSEI') or d_raw.get('addressSEI', '')),
            ("🌌 TIA", "BECH32", d.get('addressTIA') or d_raw.get('addressTIA', '')),
            ("☕ KAVA", "BECH32", d.get('addressKAVA') or d_raw.get('addressKAVA', '')),
            ("🦅 RVN", "BASE58", d.get('addressRVN') or d_raw.get('addressRVN', '')),
            ("🥇 BTG", "LEGACY", d.get('addressBTG') or d_raw.get('addressBTG', '')),
            ("💎 BSV", "LEGACY", d.get('addressBSV') or d_raw.get('addressBSV', '')),
            ("🟢 BCH", "CASHADDR", d.get('addressBCH') or d_raw.get('addressBCH', '')),
        ]

        self.addr_table.setRowCount(0)
        for chain, dtype, addr in rows_data:
            if not addr:
                continue
            row = self.addr_table.rowCount()
            self.addr_table.insertRow(row)

            c_item = QTableWidgetItem(chain)
            c_item.setFont(QFont("", -1, QFont.Weight.Bold))
            c_item.setFlags(c_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.addr_table.setItem(row, 0, c_item)

            t_item = QTableWidgetItem(dtype)
            t_item.setForeground(QColor("#ffffff"))
            t_item.setFlags(t_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.addr_table.setItem(row, 1, t_item)

            a_item = QTableWidgetItem(addr)
            a_item.setForeground(QColor("#f0a500" if "BIP-39" in chain else "#58a6ff"))
            a_item.setFont(QFont("Courier New", 9, QFont.Weight.Bold if "BIP-39" in chain else QFont.Weight.Normal))
            a_item.setFlags(a_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.addr_table.setItem(row, 2, a_item)

            s_item = QTableWidgetItem("✓")
            s_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            s_item.setForeground(QColor("#3fb950"))
            s_item.setFlags(s_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.addr_table.setItem(row, 3, s_item)

        self.addr_table.resizeRowsToContents()


class KeySpaceExplorerTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.current_page = 1
        self.current_keys = []
        self.highlight_offset = None
        self.current_network = "bitcoin"
        self.current_path = "m/84'/0'/0'/0/0"
        self.current_word_count = 12
        self._page_worker = None
        self._balance_worker = None
        self._search_worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        # Navigation row
        nav_row = QHBoxLayout()
        nav_row.setSpacing(8)

        self.btn_first = QPushButton("⇤ First")
        self.btn_first.setObjectName("btn_first_page")
        self.btn_first.setFixedWidth(75)
        self.btn_first.clicked.connect(lambda: self._load_page(1))
        nav_row.addWidget(self.btn_first)

        self.btn_prev = QPushButton("‹ Prev")
        self.btn_prev.setObjectName("btn_prev_page")
        self.btn_prev.setFixedWidth(75)
        self.btn_prev.clicked.connect(self._prev_page)
        nav_row.addWidget(self.btn_prev)

        nav_row.addWidget(QLabel("Page:"))
        self.page_input = QLineEdit("1")
        self.page_input.setFixedWidth(100)
        self.page_input.returnPressed.connect(self._go_to_page)
        nav_row.addWidget(self.page_input)

        self.btn_next = QPushButton("Next ›")
        self.btn_next.setObjectName("btn_next_page")
        self.btn_next.setFixedWidth(75)
        self.btn_next.clicked.connect(self._next_page)
        nav_row.addWidget(self.btn_next)

        self.btn_random = QPushButton("⚡ Random Page")
        self.btn_random.setObjectName("btn_random_page")
        self.btn_random.clicked.connect(self._random_page)
        nav_row.addWidget(self.btn_random)

        nav_row.addSpacing(10)

        # Search
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search Private Key (Hex / WIF / Int) or Public Address...")
        self.search_input.setMinimumWidth(300)
        self.search_input.returnPressed.connect(self._search)
        nav_row.addWidget(self.search_input, 1)

        self.btn_locate = QPushButton("🔍 Locate")
        self.btn_locate.setObjectName("btn_locate")
        self.btn_locate.clicked.connect(self._search)
        nav_row.addWidget(self.btn_locate)

        layout.addLayout(nav_row)

        # Derivation & All 50+ Chains & Word Count Controls Row
        drv_row = QHBoxLayout()
        drv_row.setSpacing(8)

        drv_row.addWidget(QLabel("Seed Words:"))
        self.word_count_combo = QComboBox()
        self.word_count_combo.setFixedWidth(95)
        for wc in [12, 15, 18, 21, 24]:
            self.word_count_combo.addItem(f"{wc} Words", wc)
        self.word_count_combo.setCurrentIndex(0) # Default to 12 words
        self.word_count_combo.currentIndexChanged.connect(self._on_word_count_changed)
        drv_row.addWidget(self.word_count_combo)

        drv_row.addWidget(QLabel("Chain (50+):"))
        self.coin_combo = QComboBox()
        self.coin_combo.setFixedWidth(200)
        for net_key, display_name, symbol, emoji, path, addr_key, color in CHAINS_50:
            self.coin_combo.addItem(f"{emoji} {display_name}", (net_key, path))
        self.coin_combo.currentIndexChanged.connect(self._on_coin_changed)
        drv_row.addWidget(self.coin_combo)

        drv_row.addWidget(QLabel("Derivation Standard:"))
        self.standard_combo = QComboBox()
        self.standard_combo.setFixedWidth(240)
        for name, path, net in KEY_SPACE_DERIVATION_STANDARDS:
            self.standard_combo.addItem(name, (path, net))
        self.standard_combo.currentIndexChanged.connect(self._on_standard_changed)
        drv_row.addWidget(self.standard_combo)

        drv_row.addWidget(QLabel("Path:"))
        self.custom_path_input = QLineEdit("m/84'/0'/0'/0/0")
        self.custom_path_input.setFixedWidth(140)
        self.custom_path_input.setStyleSheet("background: #000000; border: 1px solid #282c34; color: #ffaa00; font-family: monospace; font-weight: 600;")
        self.custom_path_input.returnPressed.connect(self._load_current_page)
        drv_row.addWidget(self.custom_path_input)

        self.btn_apply_path = QPushButton("⚡ Apply")
        self.btn_apply_path.setFixedWidth(70)
        self.btn_apply_path.clicked.connect(self._load_current_page)
        drv_row.addWidget(self.btn_apply_path)

        drv_row.addStretch()
        layout.addLayout(drv_row)

        # Funded Banner (Lights up neon green when funded wallet detected)
        self.funded_banner = QLabel("Scanning key space page for active balances...")
        self.funded_banner.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.funded_banner.setStyleSheet(
            "background: #161b22; color: #8b949e; border: 1px solid #21262d; "
            "font-weight: 600; font-size: 11px; padding: 4px 8px; border-radius: 4px;"
        )
        layout.addWidget(self.funded_banner)

        # Table - 6 columns: Key # | Private Key (Hex) | Mnemonic | Compressed PubKey | Address | Live Balance
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Key #", "Private Key (Hex)", "BIP-39 Mnemonic", "Public Key (Compressed)", "Address", "Live Balance"
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)

        self.table.setColumnWidth(0, 65)
        self.table.setColumnWidth(1, 240)
        self.table.setColumnWidth(3, 180)
        self.table.setColumnWidth(5, 115)

        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.verticalHeader().setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        self.table.cellClicked.connect(self._on_cell_clicked)
        self.table.itemDoubleClicked.connect(self._on_item_double_clicked)
        layout.addWidget(self.table)

        # Status
        self.status_lbl = QLabel("Key Space Explorer — All 50+ Chains & 12/24 Word Mnemonic Support (1 to 2²⁵⁶-1)")
        self.status_lbl.setStyleSheet("color: #ffffff; font-size: 11px; font-weight: 600;")
        layout.addWidget(self.status_lbl)

    def _on_word_count_changed(self, idx):
        wc = self.word_count_combo.currentData()
        if wc:
            self.current_word_count = wc
            self._load_current_page()

    def _on_coin_changed(self, idx):
        data = self.coin_combo.currentData()
        if data:
            net_key, path = data
            self.current_network = net_key
            if path:
                self.custom_path_input.setText(path)
                self.current_path = path
            self._load_current_page()

    def _on_standard_changed(self, idx):
        data = self.standard_combo.currentData()
        if not data:
            return
        path, net = data
        if path:
            self.custom_path_input.setText(path)
            self.current_path = path
        if net:
            self.current_network = net
            for i in range(self.coin_combo.count()):
                if self.coin_combo.itemData(i)[0] == net:
                    self.coin_combo.blockSignals(True)
                    self.coin_combo.setCurrentIndex(i)
                    self.coin_combo.blockSignals(False)
                    break
        self._load_current_page()

    def _load_current_page(self):
        net_data = self.coin_combo.currentData()
        if net_data:
            self.current_network = net_data[0]
        path = self.custom_path_input.text().strip()
        if path:
            self.current_path = path
        self._load_page(self.current_page)

    def _load_page(self, page: int, highlight_offset: int = None):
        if self._page_worker and self._page_worker.isRunning():
            return
        if self._balance_worker and self._balance_worker.isRunning():
            self._balance_worker.stop()

        self.current_page = page
        self.highlight_offset = highlight_offset
        self.page_input.setText(str(page))
        self.status_lbl.setText(f"Loading page {page} for {self.current_network} ({self.current_word_count}-word, {self.current_path})...")
        self.funded_banner.setText(f"🔍 Scanning page {page} ({self.current_word_count}-word) for active balances across {self.current_network.upper()}...")
        self.funded_banner.setStyleSheet(
            "background: #161b22; color: #8b949e; border: 1px solid #21262d; "
            "font-weight: 600; font-size: 11px; padding: 4px 8px; border-radius: 4px;"
        )
        self.table.setRowCount(0)
        self.current_keys = []

        from .workers import KeySpaceWorker
        worker = KeySpaceWorker(
            page,
            word_count=self.current_word_count,
            network=self.current_network,
            derivation_path=self.current_path
        )
        worker.result.connect(self._on_page_loaded)
        worker.error.connect(lambda e: self.status_lbl.setText(f"Error: {e}"))
        self._page_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_page_loaded(self, data: dict):
        keys = data.get('keys', [])
        self.current_keys = keys
        page = data.get('page', self.current_page)
        max_page = data.get('maxPage', 0)
        start = data.get('startKeyIndex', 0)
        symbol = data.get('symbol', 'BTC')

        self.table.setHorizontalHeaderLabels([
            "Key #", "Private Key (Hex)", f"{self.current_word_count}-Word BIP-39 Mnemonic", "Public Key (Compressed)", f"{symbol} Address", "Live Balance"
        ])

        self.table.setRowCount(0)
        balance_tasks = []
        match_key_data = None

        for i, key_data in enumerate(keys):
            row = self.table.rowCount()
            self.table.insertRow(row)

            # 0: Key #
            num_item = QTableWidgetItem(f"#{start + i}")
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num_item.setForeground(QColor("#f0a500"))
            num_item.setFont(QFont("", -1, QFont.Weight.Bold))
            num_item.setFlags(num_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 0, num_item)

            # 1: Private Key Hex (Clickable)
            priv_hex = key_data.get('privateKeyHex', '')
            hex_item = QTableWidgetItem(priv_hex)
            hex_item.setForeground(QColor("#58a6ff"))
            hex_item.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
            hex_item.setToolTip("Click to open full key details & multi-chain inspector")
            hex_item.setFlags(hex_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 1, hex_item)

            # 2: Mnemonic
            mnem = key_data.get('bip39Mnemonic', '')
            mnem_item = QTableWidgetItem(mnem)
            mnem_item.setForeground(QColor("#c9d1d9"))
            mnem_item.setFont(QFont("Courier New", 9))
            mnem_item.setFlags(mnem_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 2, mnem_item)

            # 3: Compressed PubKey
            comp_pub = key_data.get('compressedPublicKey', '')
            comp_item = QTableWidgetItem(comp_pub)
            comp_item.setForeground(QColor("#8b949e"))
            comp_item.setFont(QFont("Courier New", 9))
            comp_item.setFlags(comp_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 3, comp_item)

            # 4: Address
            addr = key_data.get('address', '')
            addr_item = QTableWidgetItem(addr)
            addr_item.setForeground(QColor("#58a6ff"))
            addr_item.setFont(QFont("Courier New", 9))
            addr_item.setFlags(addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 4, addr_item)

            # 5: Live Balance
            bal_item = QTableWidgetItem("...Checking")
            bal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            bal_item.setForeground(QColor("#8b949e"))
            bal_item.setFlags(bal_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 5, bal_item)

            # Highlight specific search result row if requested
            if self.highlight_offset is not None and i == self.highlight_offset:
                for c_idx in range(self.table.columnCount()):
                    it = self.table.item(row, c_idx)
                    if it:
                        it.setBackground(QColor("#1b3a4b"))
                        it.setForeground(QColor("#39ff14"))
                        it.setFont(QFont("", -1, QFont.Weight.Bold))
                self.table.selectRow(row)
                match_key_data = key_data

            if addr:
                balance_tasks.append((row, addr, self.current_network))

        self.table.resizeRowsToContents()
        self.status_lbl.setText(
            f"Page {page} of {max_page:,} — Keys #{start:,} to #{start + len(keys) - 1:,} "
            f"— Chain: {self.current_network.upper()} ({self.current_word_count}-word, {self.current_path}) (Checking balances...)"
        )
        self.main_window.status_bar_msg(f"Key Space: Page {page} loaded ({len(keys)} keys). Checking balances...")

        # Auto-check balances for this page
        if balance_tasks:
            from .workers import BatchBalanceWorker
            worker = BatchBalanceWorker(balance_tasks, network=self.current_network)
            worker.address_result.connect(self._on_balance_updated)
            worker.finished.connect(self._on_balance_finished)
            self._balance_worker = worker
            self._workers.append(worker)
            worker.start()

        if match_key_data is not None:
            self.highlight_offset = None
            QTimer.singleShot(150, lambda kd=match_key_data: self._show_key_detail(kd))

    def _on_balance_updated(self, row_idx: int, bal_str: str):
        if row_idx < self.table.rowCount():
            item = self.table.item(row_idx, 5)
            if item:
                item.setText(bal_str)
                is_funded = bal_str not in ("0.00000000", "0.000000", "0.0", "0", "---") and not bal_str.startswith("...") and not bal_str.startswith("0.0000")
                if is_funded:
                    # Highlight Live Balance Column
                    item.setForeground(QColor("#39ff14")) # Neon Green
                    item.setBackground(QColor("#113311"))
                    item.setFont(QFont("Courier New", 9, QFont.Weight.Bold))

                    # Highlight Key # Column
                    num_item = self.table.item(row_idx, 0)
                    if num_item:
                        num_item.setForeground(QColor("#39ff14"))
                        num_item.setBackground(QColor("#113311"))

                    # Highlight Private Key (Hex) Column with eye-catching gold/neon green glow
                    hex_item = self.table.item(row_idx, 1)
                    if hex_item:
                        hex_item.setForeground(QColor("#39ff14"))
                        hex_item.setBackground(QColor("#1b3a20"))
                        hex_item.setFont(QFont("Courier New", 9, QFont.Weight.Bold))
                        hex_item.setToolTip("⚡ FUNDED KEY DETECTED! Click to inspect or sweep.")

                    # Also highlight address item
                    addr_item = self.table.item(row_idx, 4)
                    if addr_item:
                        addr_item.setForeground(QColor("#39ff14"))
                        addr_item.setBackground(QColor("#113311"))

                    self.funded_banner.setText(f"🌟 ⚡ FUNDED WALLET DETECTED ON PAGE {self.current_page} (Row #{row_idx + 1}, Balance: {bal_str}) — READY TO SWEEP! ⚡ 🌟")
                    self.funded_banner.setStyleSheet(
                        "background: #113311; color: #39ff14; border: 2px solid #39ff14; "
                        "font-weight: bold; font-size: 14px; padding: 8px; border-radius: 6px;"
                    )
                    self.main_window.status_bar_msg(f"🌟 FUNDED WALLET FOUND ON PAGE {self.current_page} (Row #{row_idx + 1})!")
                else:
                    if not (self.highlight_offset is not None and row_idx == self.highlight_offset):
                        item.setForeground(QColor("#8b949e"))
                        item.setBackground(QColor("#00000000"))
                        hex_item = self.table.item(row_idx, 1)
                        if hex_item:
                            hex_item.setForeground(QColor("#58a6ff"))
                            hex_item.setBackground(QColor("#00000000"))

    def _on_balance_finished(self):
        self.status_lbl.setText(self.status_lbl.text().replace(" (Checking balances...)", " — Balances Checked ✅"))
        self.main_window.status_bar_msg("Key Space page balances checked.")

    def _on_cell_clicked(self, row: int, col: int):
        if col == 1:
            if 0 <= row < len(self.current_keys):
                self._show_key_detail(self.current_keys[row])

    def _on_item_double_clicked(self, item):
        row = item.row()
        if 0 <= row < len(self.current_keys):
            self._show_key_detail(self.current_keys[row])

    def _show_key_detail(self, key_data: dict):
        dlg = KeyDetailDialog(key_data, self)
        dlg.exec()

    def _prev_page(self):
        self.highlight_offset = None
        if self.current_page > 1:
            self._load_page(self.current_page - 1)

    def _next_page(self):
        self.highlight_offset = None
        self._load_page(self.current_page + 1)

    def _go_to_page(self):
        self.highlight_offset = None
        try:
            page = int(self.page_input.text().strip())
            if page < 1:
                page = 1
            self._load_page(page)
        except ValueError:
            pass

    def _random_page(self):
        self.highlight_offset = None
        try:
            from hd_wallet.private_key_finder import get_random_page_number
            page = get_random_page_number()
            self._load_page(page)
        except Exception as e:
            self.status_lbl.setText(f"Error: {e}")

    def _search(self):
        query = self.search_input.text().strip()
        if not query:
            return

        self.status_lbl.setText(f"Searching for key/address: {query[:40]}...")
        from .workers import KeySpaceSearchWorker
        worker = KeySpaceSearchWorker(query)
        worker.result.connect(self._on_search_result)
        worker.error.connect(lambda e: self.status_lbl.setText(f"Search error: {e}"))
        self._search_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_search_result(self, result: dict):
        if 'error' in result:
            self.status_lbl.setText(f"❌ {result['error']}")
            return
        page = result.get('page', 1)
        offset = result.get('offsetInPage', 0)
        priv_hex = result.get('privateKeyHex', '')
        self.status_lbl.setText(
            f"Found matching Private Key at Page {page:,}, Offset {offset} — Key: {priv_hex[:16]}... (Auto-Opening Inspector ✨)"
        )
        self._load_page(page, highlight_offset=offset)

    def _context_menu(self, pos):
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        item = self.table.itemAt(pos)
        if not item:
            return
        copy_cell = menu.addAction("📋 Copy Cell")
        copy_cell.triggered.connect(lambda: QApplication.clipboard().setText(item.text()))
        row = item.row()
        hex_item = self.table.item(row, 1)
        comp_item = self.table.item(row, 3)
        addr_item = self.table.item(row, 4)

        if hex_item:
            copy_hex = menu.addAction("📋 Copy Private Key (Hex)")
            copy_hex.triggered.connect(lambda: QApplication.clipboard().setText(hex_item.text()))
            k_data = self.current_keys[row] if 0 <= row < len(self.current_keys) else {}
            if k_data.get('solanaKeypairBase58'):
                copy_sol_kp = menu.addAction("🟣 Copy Solana Keypair (Base58)")
                copy_sol_kp.triggered.connect(lambda kd=k_data: QApplication.clipboard().setText(kd.get('solanaKeypairBase58', '')))
            xrp_sec = k_data.get('xrpSecretSeed') or k_data.get('xrpSecretKeySecp') or k_data.get('xrpSecretKey', '')
            if xrp_sec:
                copy_xrp_sec = menu.addAction("✗ Copy XRP Secret Key")
                copy_xrp_sec.triggered.connect(lambda sec=xrp_sec: QApplication.clipboard().setText(sec))

            sweep_action = menu.addAction("⚡ Load to Multichain Sweeper")
            sweep_action.triggered.connect(lambda kd=k_data: self._load_key_to_sweeper(kd))

            view_detail = menu.addAction("🔍 Open Key Info & Multi-Chain Inspector")
            view_detail.triggered.connect(lambda: self._show_key_detail(self.current_keys[row]))
        if comp_item:
            copy_comp = menu.addAction("📋 Copy Compressed Public Key")
            copy_comp.triggered.connect(lambda: QApplication.clipboard().setText(comp_item.text()))
        if addr_item:
            copy_addr = menu.addAction("📋 Copy Address")
            copy_addr.triggered.connect(lambda: QApplication.clipboard().setText(addr_item.text()))
        menu.exec(self.table.mapToGlobal(pos))

    def _load_key_to_sweeper(self, key_data: dict):
        priv = key_data.get('bip39Mnemonic') or key_data.get('privateKeyHex', '')
        if priv and hasattr(self, 'main_window') and self.main_window:
            self.main_window.load_mnemonic(priv)
            self.main_window.tab_widget.setCurrentWidget(self.main_window.tab_sweeper)
            self.main_window.status_bar_msg("Loaded funded wallet into Multichain Sweeper.")

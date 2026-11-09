"""
Tab 4: 50 Multichain Directory / Custom Node
Grid of 50+ blockchain addresses with live balance checking,
custom RPC node configuration, and real-time balance polling.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QGroupBox, QScrollArea, QFrame, QApplication
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

# 50 chains configuration: (key, display_name, symbol, emoji, path, addr_key, color)
CHAINS_50 = [
    ("bitcoin",    "Bitcoin (BTC)",        "BTC",    "🟠", "m/84'/0'/0'/0/0",    "addressP2WPKH", "#f0a500"),
    ("ethereum",   "Ethereum (ETH)",        "ETH",    "🔷", "m/44'/60'/0'/0/0",   "addressETH",    "#7c3aed"),
    ("solana",     "Solana (SOL)",          "SOL",    "🟣", "m/44'/501'/0'/0'",   "addressSOL",    "#9945ff"),
    ("xrp",        "XRP Ledger (XRP)",      "XRP",    "✗",  "m/44'/144'/0'/0/0",  "addressXRP",    "#2ea0a0"),
    ("bnb",        "BNB Chain (BNB)",       "BNB",    "🟡", "m/44'/60'/0'/0/0",   "addressETH",    "#f0a500"),
    ("tron",       "Tron (TRX)",            "TRX",    "🔴", "m/44'/195'/0'/0/0",  "addressTRX",    "#ef4444"),
    ("dogecoin",   "Dogecoin (DOGE)",       "DOGE",   "🐕", "m/44'/3'/0'/0/0",    "addressDOGE",   "#c2a633"),
    ("litecoin",   "Litecoin (LTC)",        "LTC",    "⚪", "m/84'/2'/0'/0/0",    "addressLTC",    "#aaaaaa"),
    ("cosmos",     "Cosmos (ATOM)",         "ATOM",   "⚛️",  "m/44'/118'/0'/0/0",  "addressATOM",   "#7c5cfc"),
    ("polkadot",   "Polkadot (DOT)",        "DOT",    "🔴", "m/44'/354'/0'/0/0",  "addressDOT",    "#e6007a"),
    ("cardano",    "Cardano (ADA)",         "ADA",    "🔵", "m/44'/1815'/0'/0/0", "addressADA",    "#0033ad"),
    ("avalanche",  "Avalanche (AVAX)",      "AVAX",   "🔺", "m/44'/60'/0'/0/0",   "addressETH",    "#e84142"),
    ("polygon",    "Polygon (POL)",         "POL",    "🟣", "m/44'/60'/0'/0/0",   "addressETH",    "#8247e5"),
    ("arbitrum",   "Arbitrum (ARB)",        "ARB",    "🔵", "m/44'/60'/0'/0/0",   "addressETH",    "#2d374b"),
    ("optimism",   "Optimism (OP)",         "OP",     "🔴", "m/44'/60'/0'/0/0",   "addressETH",    "#ff0420"),
    ("base",       "Base (BASE)",           "BASE",   "🔵", "m/44'/60'/0'/0/0",   "addressETH",    "#0052ff"),
    ("sui",        "Sui (SUI)",             "SUI",    "🔵", "m/44'/784'/0'/0/0",  "addressSUI",    "#4da2ff"),
    ("near",       "NEAR Protocol (NEAR)", "NEAR",   "🌈", "m/44'/397'/0'/0/0",  "addressNEAR",   "#00c08b"),
    ("algorand",   "Algorand (ALGO)",       "ALGO",   "⬛", "m/44'/283'/0'/0/0",  "addressALGO",   "#00b4d8"),
    ("tezos",      "Tezos (XTZ)",           "XTZ",    "🔵", "m/44'/1729'/0'/0/0", "addressXTZ",    "#2c7df7"),
    ("stellar",    "Stellar (XLM)",         "XLM",    "⭐", "m/44'/148'/0'/0'",   "addressXLM",    "#08b5e5"),
    ("filecoin",   "Filecoin (FIL)",        "FIL",    "🟢", "m/44'/461'/0'/0/0",  "addressFIL",    "#42c1ca"),
    ("aptos",      "Aptos (APT)",           "APT",    "🟤", "m/44'/637'/0'/0/0",  "addressAPT",    "#00bfa5"),
    ("injective",  "Injective (INJ)",       "INJ",    "🔵", "m/44'/60'/0'/0/0",   "addressINJ",    "#00b4d8"),
    ("osmosis",    "Osmosis (OSMO)",        "OSMO",   "🟣", "m/44'/118'/0'/0/0",  "addressOSMO",   "#750ddf"),
    ("dash",       "Dash (DASH)",           "DASH",   "🔵", "m/44'/5'/0'/0/0",    "addressDASH",   "#2d9bf0"),
    ("zcash",      "Zcash (ZEC)",           "ZEC",    "🟡", "m/44'/133'/0'/0/0",  "addressZEC",    "#f4b728"),
    ("kaspa",      "Kaspa (KAS)",           "KAS",    "🟢", "m/44'/111111'/0'/0/0","addressKAS",   "#70c7ba"),
    ("ravencoin",  "Ravencoin (RVN)",       "RVN",    "🐦", "m/44'/175'/0'/0/0",  "addressRVN",    "#384182"),
    ("bitcoingold","Bitcoin Gold (BTG)",    "BTG",    "🟡", "m/44'/156'/0'/0/0",  "addressBTG",    "#e8a900"),
    ("fantom",     "Fantom (FTM)",          "FTM",    "🔵", "m/44'/60'/0'/0/0",   "addressETH",    "#1969ff"),
    ("zksync",     "zkSync Era (ZKSYNC)",   "ZKSYNC", "🔷", "m/44'/60'/0'/0/0",   "addressETH",    "#4e529a"),
    ("linea",      "Linea (ETH)",           "ETH",    "🔵", "m/44'/60'/0'/0/0",   "addressETH",    "#61dfff"),
    ("scroll",     "Scroll (ETH)",          "ETH",    "🔵", "m/44'/60'/0'/0/0",   "addressETH",    "#ebc28e"),
    ("mantle",     "Mantle (MNT)",          "MNT",    "🟢", "m/44'/60'/0'/0/0",   "addressETH",    "#00d395"),
    ("cronos",     "Cronos (CRO)",          "CRO",    "🔵", "m/44'/60'/0'/0/0",   "addressETH",    "#002d74"),
    ("blast",      "Blast (ETH)",           "ETH",    "🟡", "m/44'/60'/0'/0/0",   "addressETH",    "#fcfc03"),
    ("sei",        "Sei (SEI)",             "SEI",    "🔴", "m/44'/118'/0'/0/0",  "addressSEI",    "#fc4a4a"),
    ("celestia",   "Celestia (TIA)",        "TIA",    "🟣", "m/44'/118'/0'/0/0",  "addressTIA",    "#7b2fbe"),
    ("kava",       "Kava (KAVA)",           "KAVA",   "🔴", "m/44'/118'/0'/0/0",  "addressKAVA",   "#ff4b4b"),
    ("bitcoin_taproot","Bitcoin Taproot (BTC)","BTC","🟠","m/86'/0'/0'/0/0",     "addressP2TR",   "#f0a500"),
    ("bitcoin_nested","Bitcoin Nested (BTC)","BTC",  "🟠", "m/49'/0'/0'/0/0",    "addressP2SH",   "#d48c00"),
    ("bitcoin_legacy","Bitcoin Legacy (BTC)","BTC",  "🟠", "m/44'/0'/0'/0/0",    "addressP2PKH",  "#b87800"),
    ("terkehh",    "Terkehh (BSC) (TERK)", "TERK",  "🚀", "m/44'/60'/0'/0/0",   "addressETH",    "#ff6b35"),
    ("bsc_extra",  "BSC Token (BNB)",       "BNB",   "🟡", "m/44'/60'/0'/0/0",   "addressETH",    "#f0a500"),
    ("polygon_zkevm","Polygon zkEVM (POL)", "POL",   "🟣", "m/44'/60'/0'/0/0",   "addressETH",    "#8247e5"),
    ("manta",      "Manta Pacific (ETH)",   "ETH",   "🌊", "m/44'/60'/0'/0/0",   "addressETH",    "#00e5ff"),
    ("mode",       "Mode Network (ETH)",    "ETH",   "🟢", "m/44'/60'/0'/0/0",   "addressETH",    "#dafe0e"),
    ("taiko",      "Taiko (ETH)",           "ETH",   "🔵", "m/44'/60'/0'/0/0",   "addressETH",    "#e81899"),
    ("fraxtal",    "Fraxtal (frxETH)",      "ETH",   "⬛", "m/44'/60'/0'/0/0",   "addressETH",    "#000000"),
]


class CoinCard(QFrame):
    """A compact card widget showing a single coin's address and balance."""

    def __init__(self, chain_key, display_name, symbol, emoji, color, parent=None):
        super().__init__(parent)
        self.chain_key = chain_key
        self._workers = []
        self.setObjectName("coin_card")
        self.setStyleSheet(
            f"QFrame#coin_card {{ background: #161b22; border: 1px solid #21262d; border-left: 3px solid {color}; "
            f"border-radius: 6px; }}"
        )
        self.setFixedHeight(78)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 6, 10, 6)
        layout.setSpacing(4)

        # Header
        header = QHBoxLayout()
        name_lbl = QLabel(f"{emoji} {display_name}")
        name_lbl.setStyleSheet(f"color: #e6edf3; font-weight: 700; font-size: 12px; border: none;")
        header.addWidget(name_lbl)
        header.addStretch()
        self.bal_lbl = QLabel("0.00000000")
        self.bal_lbl.setStyleSheet("color: #8b949e; font-family: 'Courier New', monospace; font-size: 11px; border: none;")
        header.addWidget(self.bal_lbl)
        layout.addLayout(header)

        # Address + inline actions row
        addr_row = QHBoxLayout()
        addr_row.setSpacing(4)
        self.addr_field = QLineEdit()
        self.addr_field.setReadOnly(True)
        self.addr_field.setStyleSheet(
            "background: #090c10; border: 1px solid #21262d; border-radius: 3px;"
            "color: #58a6ff; padding: 3px 6px; font-family: 'Courier New', monospace; font-size: 11px;"
        )
        addr_row.addWidget(self.addr_field, 1)

        copy_btn = QPushButton("Copy")
        copy_btn.setObjectName("btn_copy")
        copy_btn.setFixedWidth(46)
        copy_btn.setFixedHeight(22)
        copy_btn.clicked.connect(lambda: (cb := QApplication.clipboard()) and cb.setText(self.addr_field.text()))
        addr_row.addWidget(copy_btn)

        self.query_btn = QPushButton("Check")
        self.query_btn.setObjectName("btn_check_balance")
        self.query_btn.setFixedWidth(52)
        self.query_btn.setFixedHeight(22)
        self.query_btn.clicked.connect(self._query_balance)
        addr_row.addWidget(self.query_btn)

        layout.addLayout(addr_row)

    def set_address(self, addr: str):
        self.addr_field.setText(addr)

    def set_balance(self, balance_str: str, funded: bool = False):
        self.bal_lbl.setText(balance_str)
        if funded:
            self.bal_lbl.setStyleSheet("color: #00ff66; font-family: 'Courier New', monospace; font-size: 12px; font-weight: 700; border: none;")
        else:
            self.bal_lbl.setStyleSheet("color: #9da7b3; font-family: 'Courier New', monospace; font-size: 12px; border: none;")

    def _query_balance(self):
        addr = self.addr_field.text()
        if not addr:
            return
        self.bal_lbl.setText("⏳")
        from .workers import BalanceCheckWorker
        worker = BalanceCheckWorker(addr, self.chain_key)
        worker.result.connect(lambda a, r: self._on_result(r))
        worker.error.connect(lambda e: self.bal_lbl.setText("ERR"))
        self._workers.append(worker)
        worker.start()

    def _on_result(self, result: dict):
        bal = result.get('balance', 0) or 0
        if isinstance(bal, (int, float)) and bal > 0:
            self.set_balance(f"{bal:.8f}", funded=True)
        else:
            self.set_balance("0.00000000", funded=False)


class MultichainDirectoryTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = None
        self.cards = {}
        self._balance_worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        # ── Action Bar + RPC Toggle ──────────────────────────────────
        action_row = QHBoxLayout()
        self.btn_check_all = QPushButton("Check All 50 Chain Balances")
        self.btn_check_all.setObjectName("btn_check_all")
        self.btn_check_all.clicked.connect(self._check_all)
        action_row.addWidget(self.btn_check_all)

        self.funded_lbl = QLabel("Funded Assets: 0")
        self.funded_lbl.setStyleSheet(
            "background: #122117; color: #3fb950; border: 1px solid #238636; padding: 4px 12px; border-radius: 4px; font-weight: 700;"
        )
        action_row.addWidget(self.funded_lbl)

        action_row.addStretch()

        self.rpc_status = QLabel("RPC: Public Defaults")
        self.rpc_status.setStyleSheet("color: #8b949e; font-size: 11px;")
        action_row.addWidget(self.rpc_status)

        self.btn_toggle_rpc = QPushButton("⚙ Custom RPC Settings")
        self.btn_toggle_rpc.setCheckable(True)
        self.btn_toggle_rpc.toggled.connect(lambda checked: self.rpc_box.setVisible(checked))
        action_row.addWidget(self.btn_toggle_rpc)
        layout.addLayout(action_row)

        # ── Custom RPC Settings (Collapsible, hidden by default) ─────
        self.rpc_box = QGroupBox("Custom Node RPC & Authentication")
        self.rpc_box.setVisible(False)
        rpc_v = QVBoxLayout(self.rpc_box)
        rpc_v.setSpacing(8)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Network:"))
        self.rpc_network = QComboBox()
        self.rpc_network.setMinimumWidth(180)
        for (key, name, *_) in CHAINS_50:
            self.rpc_network.addItem(name, key)
        row1.addWidget(self.rpc_network)
        row1.addSpacing(12)
        row1.addWidget(QLabel("RPC URL:"))
        self.rpc_url = QLineEdit()
        self.rpc_url.setPlaceholderText("http://127.0.0.1:8545 or https://rpc.custom-node.org")
        row1.addWidget(self.rpc_url, 1)

        row1.addSpacing(12)
        row1.addWidget(QLabel("User:"))
        self.rpc_user = QLineEdit()
        self.rpc_user.setPlaceholderText("Optional")
        self.rpc_user.setFixedWidth(110)
        row1.addWidget(self.rpc_user)

        row1.addWidget(QLabel("Pass:"))
        self.rpc_pass = QLineEdit()
        self.rpc_pass.setPlaceholderText("Optional")
        self.rpc_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self.rpc_pass.setFixedWidth(110)
        row1.addWidget(self.rpc_pass)

        self.btn_test_rpc = QPushButton("Test & Apply")
        self.btn_test_rpc.setObjectName("btn_test_connection")
        self.btn_test_rpc.clicked.connect(self._test_rpc)
        row1.addWidget(self.btn_test_rpc)
        rpc_v.addLayout(row1)
        layout.addWidget(self.rpc_box)

        # ── Coin Grid (3-column clean layout) ────────────────────────
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)

        grid_widget = QWidget()
        self.grid = QGridLayout(grid_widget)
        self.grid.setSpacing(8)
        self.grid.setContentsMargins(2, 2, 2, 2)

        col = 0
        row = 0
        for i, (key, name, sym, emoji, path, addr_key, color) in enumerate(CHAINS_50):
            card = CoinCard(key, name, sym, emoji, color)
            self.cards[key + "_" + str(i)] = (card, path, addr_key)
            self.grid.addWidget(card, row, col)
            col += 1
            if col >= 3:
                col = 0
                row += 1

        scroll.setWidget(grid_widget)
        layout.addWidget(scroll, 1)

    def set_wallet(self, wallet):
        self.wallet = wallet
        # Populate addresses immediately
        self._populate_addresses()

    def _populate_addresses(self):
        if not self.wallet:
            return
        for card_key, (card, path, addr_key) in self.cards.items():
            try:
                derived = self.wallet.derive_key(path)
                addr = derived.get(addr_key, '')
                card.set_address(addr)
            except Exception:
                card.set_address('')

    def _test_rpc(self):
        net = self.rpc_network.currentData()
        url = self.rpc_url.text().strip()
        user = self.rpc_user.text().strip()
        passwd = self.rpc_pass.text().strip()

        if not url:
            self.rpc_status.setText("Status: Using Public Default RPCs")
            return

        self.rpc_status.setText("Status: Testing connection...")
        try:
            from hd_wallet.balance import test_custom_rpc_connection, set_custom_rpc_node
            result = test_custom_rpc_connection(net, url, user, passwd)
            if result.get('connected'):
                set_custom_rpc_node(net, url, user, passwd)
                self.rpc_status.setText(f"Status: ✅ Connected — block #{result.get('block_number', '?')}")
                self.rpc_status.setStyleSheet("color: #3fb950; font-size: 12px;")
            else:
                self.rpc_status.setText(f"Status: ❌ {result.get('error', 'Connection failed')}")
                self.rpc_status.setStyleSheet("color: #f85149; font-size: 12px;")
        except Exception as e:
            self.rpc_status.setText(f"Status: ❌ {e}")
            self.rpc_status.setStyleSheet("color: #f85149; font-size: 12px;")

    def _check_all(self):
        if not self.wallet:
            return
        if self._balance_worker and self._balance_worker.isRunning():
            self._balance_worker.stop()
        self.btn_check_all.setText("⏳ Checking...")
        self.btn_check_all.setEnabled(False)
        self.funded_lbl.setText("Funded Assets: ...")

        chains = []
        for card_key, (card, path, addr_key) in self.cards.items():
            net_key = card.chain_key
            chains.append((net_key, card.addr_field.text(), path, addr_key, card))

        funded_count = 0

        def on_result(net_key, address, balance):
            nonlocal funded_count
            # Find matching card
            for ck, (c, p, ak) in self.cards.items():
                if c.chain_key == net_key and c.addr_field.text() == address:
                    funded = float(balance) > 0 if balance.replace('.', '').isdigit() else False
                    c.set_balance(balance, funded)
                    if funded:
                        funded_count += 1
                        self.funded_lbl.setText(f"Funded Assets: {funded_count}")
                    break

        def on_finished():
            self.btn_check_all.setText("Check All 50 Chain Balances")
            self.btn_check_all.setEnabled(True)
            self.funded_lbl.setText(f"Funded Assets: {funded_count}")
            self.main_window.status_bar_msg(f"Balance check complete. {funded_count} funded.")

        all_chain_inputs = [(key, name, path, addr_key)
                            for (key, name, sym, emoji, path, addr_key, color) in CHAINS_50]

        from .workers import MultichainBalanceWorker
        worker = MultichainBalanceWorker(self.wallet, all_chain_inputs)
        worker.coin_result.connect(on_result)
        worker.finished.connect(on_finished)
        self._balance_worker = worker
        self._workers.append(worker)
        worker.start()

"""
Tab 1: Key / Address Inspector
Universal key/seed input, derivation path controls, master seeds display,
and derived key pair / blockchain addresses panel. Dynamically adapts to
selected network/coin from the toolbar combo box.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from typing import List, Tuple, Dict, Any, Optional
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGridLayout, QLabel,
    QLineEdit, QTextEdit, QPushButton, QComboBox, QSpinBox,
    QGroupBox, QFrame, QScrollArea, QApplication, QSizePolicy
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from .styles import (
    SECTION_TITLE_STYLE, MONO_STYLE, MONO_BLUE_STYLE, MONO_GREEN_STYLE,
    MONO_ORANGE_STYLE, STATUS_VALID_STYLE, STATUS_INVALID_STYLE
)

# Network-specific derivation standards
# network_key -> list of (display_name, base_path, key_id)
NETWORK_STANDARDS: Dict[str, List[Tuple[str, str, str]]] = {
    "bitcoin": [
        ("BIP-84 (Native SegWit)", "m/84'/0'/0'", "84"),
        ("BIP-86 (Taproot)", "m/86'/0'/0'", "86"),
        ("BIP-49 (Nested SegWit)", "m/49'/0'/0'", "49"),
        ("BIP-44 (Legacy)", "m/44'/0'/0'", "44"),
        ("Electrum SegWit", "m/0'", "electrum"),
    ],
    "bitcoin_testnet": [
        ("BIP-84 Testnet (Native SegWit)", "m/84'/1'/0'", "84"),
        ("BIP-86 Testnet (Taproot)", "m/86'/1'/0'", "86"),
        ("BIP-49 Testnet (Nested SegWit)", "m/49'/1'/0'", "49"),
        ("BIP-44 Testnet (Legacy)", "m/44'/1'/0'", "44"),
    ],
    "ethereum": [
        ("BIP-44 Ethereum (Standard)", "m/44'/60'/0'", "44_eth"),
        ("Ledger Live Standard", "m/44'/60'/0'", "44_ledger"),
        ("Ledger Legacy Standard", "m/44'/60'/0'/0", "44_ledger_legacy"),
    ],
    "bnb": [
        ("BIP-44 BNB Smart Chain (BEP-20)", "m/44'/60'/0'", "44_bnb"),
        ("BIP-44 Binance Chain (BEP-2 Legacy)", "m/44'/714'/0'", "44_bnb_legacy"),
    ],
    "solana": [
        ("BIP-44 Solana (Phantom/Solflare)", "m/44'/501'/0'", "44_sol"),
        ("BIP-44 Solana Sub-Account", "m/44'/501'/0'/0'", "44_sol_sub"),
    ],
    "tron": [
        ("BIP-44 TRON (TronLink Standard)", "m/44'/195'/0'", "44_trx"),
    ],
    "xrp": [
        ("BIP-44 XRP Ledger (Standard)", "m/44'/144'/0'", "44_xrp"),
    ],
    "litecoin": [
        ("BIP-84 Litecoin (Native SegWit)", "m/84'/2'/0'", "84_ltc"),
        ("BIP-44 Litecoin (Legacy)", "m/44'/2'/0'", "44_ltc"),
        ("BIP-49 Litecoin (Nested SegWit)", "m/49'/2'/0'", "49_ltc"),
    ],
    "dogecoin": [
        ("BIP-44 Dogecoin (Standard)", "m/44'/3'/0'", "44_doge"),
    ],
    "dash": [
        ("BIP-44 Dash (Standard)", "m/44'/5'/0'", "44_dash"),
    ],
    "zcash": [
        ("BIP-44 Zcash (Transparent)", "m/44'/133'/0'", "44_zec"),
    ],
    "cosmos": [
        ("BIP-44 Cosmos Hub (ATOM)", "m/44'/118'/0'", "44_atom"),
    ],
    "polkadot": [
        ("BIP-44 Polkadot (DOT)", "m/44'/354'/0'", "44_dot"),
    ],
    "cardano": [
        ("BIP-44 Cardano (ADA)", "m/1852'/1815'/0'", "44_ada"),
    ],
    "sui": [
        ("BIP-44 Sui (Standard)", "m/44'/784'/0'", "44_sui"),
    ],
    "aptos": [
        ("BIP-44 Aptos (APT)", "m/44'/637'/0'", "44_apt"),
    ],
    "stellar": [
        ("BIP-44 Stellar (XLM)", "m/44'/148'/0'", "44_xlm"),
    ],
    "near": [
        ("BIP-44 NEAR Protocol", "m/44'/397'/0'", "44_near"),
    ],
    "algorand": [
        ("BIP-44 Algorand (ALGO)", "m/44'/283'/0'", "44_algo"),
    ],
    "tezos": [
        ("BIP-44 Tezos (XTZ)", "m/44'/1729'/0'", "44_xtz"),
    ],
    "filecoin": [
        ("BIP-44 Filecoin (FIL)", "m/44'/461'/0'", "44_fil"),
    ],
    "kaspa": [
        ("BIP-44 Kaspa (KAS)", "m/44'/111111'/0'", "44_kas"),
    ],
    "ravencoin": [
        ("BIP-44 Ravencoin (RVN)", "m/44'/175'/0'", "44_rvn"),
    ],
    "bitcoingold": [
        ("BIP-44 Bitcoin Gold (BTG)", "m/44'/156'/0'", "44_btg"),
    ],
    "polygon": [
        ("BIP-44 Polygon (POL)", "m/44'/60'/0'", "44_polygon"),
    ],
    "arbitrum": [
        ("BIP-44 Arbitrum (ARB)", "m/44'/60'/0'", "44_arb"),
    ],
    "optimism": [
        ("BIP-44 Optimism (OP)", "m/44'/60'/0'", "44_op"),
    ],
    "base": [
        ("BIP-44 Base (BASE)", "m/44'/60'/0'", "44_base"),
    ],
    "avalanche": [
        ("BIP-44 Avalanche (AVAX)", "m/44'/60'/0'", "44_avax"),
    ],
}

# Network-specific address configurations
# network_key -> list of (row_label, addr_dict_key, balance_network_key)
NETWORK_ADDR_CONFIGS: Dict[str, List[Tuple[str, str, str]]] = {
    "bitcoin": [
        ("Native SegWit (BIP-84) [bc1q...]", "addressP2WPKH", "bitcoin"),
        ("Taproot (BIP-86) [bc1p...]", "addressP2TR", "bitcoin"),
        ("Nested SegWit (BIP-49) [3...]", "addressP2SH", "bitcoin"),
        ("Legacy (BIP-44) [1...]", "addressP2PKH", "bitcoin"),
    ],
    "bitcoin_testnet": [
        ("Testnet Native SegWit [tb1q...]", "addressP2WPKH", "testnet"),
        ("Testnet Taproot [tb1p...]", "addressP2TR", "testnet"),
        ("Testnet Nested SegWit [2...]", "addressP2SH", "testnet"),
        ("Testnet Legacy [m/n...]", "addressP2PKH", "testnet"),
    ],
    "ethereum": [
        ("Ethereum (ETH) Address [0x...]", "addressETH", "ethereum"),
    ],
    "bnb": [
        ("BNB Smart Chain (BEP-20) [0x...]", "addressETH", "bnb"),
    ],
    "solana": [
        ("Solana (SOL) Base58 Address:", "addressSOL", "solana"),
    ],
    "tron": [
        ("Tron (TRX) Base58Check [T...]:", "addressTRX", "tron"),
        ("Tron Hex / EVM Address [0x...]:", "addressETH", "ethereum"),
    ],
    "xrp": [
        ("XRP Ledger Address [r...]:", "addressXRP", "xrp"),
    ],
    "litecoin": [
        ("Native SegWit (BIP-84) [ltc1...]:", "addressLTC", "litecoin"),
        ("Legacy (BIP-44) [L...]:", "addressP2PKH", "litecoin"),
        ("Nested SegWit (BIP-49) [M...]:", "addressP2SH", "litecoin"),
    ],
    "dogecoin": [
        ("Dogecoin (DOGE) Address [D...]:", "addressDOGE", "dogecoin"),
    ],
    "dash": [
        ("Dash (DASH) Address [X...]:", "addressDASH", "dash"),
    ],
    "zcash": [
        ("Zcash (ZEC) Transparent [t1...]:", "addressZEC", "zcash"),
    ],
    "cosmos": [
        ("Cosmos Hub Address [cosmos1...]:", "addressATOM", "cosmos"),
    ],
    "polkadot": [
        ("Polkadot (DOT) Address [1...]:", "addressDOT", "polkadot"),
    ],
    "cardano": [
        ("Cardano (ADA) Address [addr1...]:", "addressADA", "cardano"),
    ],
    "sui": [
        ("Sui (SUI) Address [0x...]:", "addressSUI", "sui"),
    ],
    "aptos": [
        ("Aptos (APT) Address [0x...]:", "addressAPT", "aptos"),
    ],
    "stellar": [
        ("Stellar (XLM) Address [G...]:", "addressXLM", "stellar"),
    ],
    "near": [
        ("NEAR Protocol Address:", "addressNEAR", "near"),
    ],
    "algorand": [
        ("Algorand (ALGO) Address:", "addressALGO", "algorand"),
    ],
    "tezos": [
        ("Tezos (XTZ) Address [tz1...]:", "addressXTZ", "tezos"),
    ],
    "filecoin": [
        ("Filecoin (FIL) Address [f1...]:", "addressFIL", "filecoin"),
    ],
    "kaspa": [
        ("Kaspa (KAS) Address [kaspa:...]:", "addressKAS", "kaspa"),
    ],
    "ravencoin": [
        ("Ravencoin (RVN) Address [R...]:", "addressRVN", "ravencoin"),
    ],
    "bitcoingold": [
        ("Bitcoin Gold (BTG) Address [G...]:", "addressBTG", "bitcoingold"),
    ],
    "polygon": [
        ("Polygon (POL) Address [0x...]:", "addressETH", "polygon"),
    ],
    "arbitrum": [
        ("Arbitrum (ARB) Address [0x...]:", "addressETH", "arbitrum"),
    ],
    "optimism": [
        ("Optimism (OP) Address [0x...]:", "addressETH", "optimism"),
    ],
    "base": [
        ("Base (BASE) Address [0x...]:", "addressETH", "base"),
    ],
    "avalanche": [
        ("Avalanche (AVAX) Address [0x...]:", "addressETH", "avalanche"),
    ],
}


def make_copy_btn() -> QPushButton:
    btn = QPushButton("Copy")
    btn.setObjectName("btn_copy")
    btn.setFixedWidth(58)
    btn.setFixedHeight(24)
    return btn


def make_field_row(parent_layout: QVBoxLayout, label: str, field_id: str = "") -> Tuple[QLineEdit, QPushButton, QLabel]:
    """Create a labeled read-only field row with Copy button."""
    row = QHBoxLayout()
    lbl = QLabel(label)
    lbl.setFixedWidth(210)
    lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")

    field = QLineEdit()
    field.setReadOnly(True)
    field.setStyleSheet(
        "background: #090c10; border: 1px solid #21262d; border-radius: 4px;"
        "color: #e6edf3; padding: 5px 8px; font-family: 'Courier New', monospace; font-size: 11px;"
    )

    copy_btn = make_copy_btn()
    copy_btn.clicked.connect(lambda _, f=field: (cb := QApplication.clipboard()) and cb.setText(f.text()))

    row.addWidget(lbl)
    row.addWidget(field, 1)
    row.addWidget(copy_btn)
    parent_layout.addLayout(row)
    return field, copy_btn, lbl


class KeyInspectorTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.current_wallet = None
        self.current_derived = None
        self.current_network = "bitcoin"
        self._balance_workers = []
        self._block_signals = False
        self._setup_ui()

    def _setup_ui(self):
        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Scroll area
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        outer_layout.addWidget(scroll)

        container = QWidget()
        scroll.setWidget(container)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(16, 12, 16, 16)
        layout.setSpacing(12)

        # ── Section 1: Universal Key/Seed Input ───────────────────────
        input_box = QGroupBox("Universal Seed / Key Input")
        input_v = QVBoxLayout(input_box)
        input_v.setSpacing(10)

        self.mnemonic_input = QTextEdit()
        self.mnemonic_input.setPlaceholderText(
            "Enter BIP-39 mnemonic phrase, WIF private key, hex seed, xprv/xpub, or raw entropy..."
        )
        self.mnemonic_input.setFixedHeight(64)
        self.mnemonic_input.setObjectName("mnemonic_input")
        self.mnemonic_input.setStyleSheet(
            "QTextEdit { background: #090c10; border: 1px solid #30363d; border-radius: 4px;"
            "color: #58a6ff; padding: 8px; font-family: 'Courier New', monospace; font-size: 13px; font-weight: 600; }"
            "QTextEdit:focus { border-color: #f0a500; }"
        )
        self.mnemonic_input.textChanged.connect(self._on_mnemonic_changed)
        input_v.addWidget(self.mnemonic_input)

        # Controls row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(10)

        # Custom passphrase
        ctrl_row.addWidget(QLabel("Passphrase:"))
        self.passphrase_input = QLineEdit()
        self.passphrase_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.passphrase_input.setPlaceholderText("Optional BIP-39 passphrase (25th word)...")
        self.passphrase_input.setFixedWidth(260)
        ctrl_row.addWidget(self.passphrase_input)

        self.btn_secure_import = QPushButton("🔒 Secure Import...")
        self.btn_secure_import.setObjectName("btn_import_wallet")
        self.btn_secure_import.clicked.connect(lambda: self.main_window._import_wallet())
        ctrl_row.addWidget(self.btn_secure_import)

        ctrl_row.addStretch()

        # Derivation standard
        ctrl_row.addWidget(QLabel("Standard:"))
        self.standard_combo = QComboBox()
        self.standard_combo.setFixedWidth(250)
        self._populate_standards_for_network("bitcoin")
        self.standard_combo.currentIndexChanged.connect(self._on_standard_changed)
        ctrl_row.addWidget(self.standard_combo)
        input_v.addLayout(ctrl_row)

        # Path controls
        path_row = QHBoxLayout()
        path_row.setSpacing(8)

        path_row.addWidget(QLabel("Account:"))
        self.account_spin = QSpinBox()
        self.account_spin.setValue(0)
        self.account_spin.setRange(0, 9999)
        self.account_spin.setFixedWidth(70)
        self.account_spin.valueChanged.connect(self._update_derived_path)
        path_row.addWidget(self.account_spin)

        path_row.addWidget(QLabel("Change:"))
        self.change_spin = QSpinBox()
        self.change_spin.setValue(0)
        self.change_spin.setRange(0, 1)
        self.change_spin.setFixedWidth(55)
        self.change_spin.valueChanged.connect(self._update_derived_path)
        path_row.addWidget(self.change_spin)

        path_row.addWidget(QLabel("Index:"))
        self.index_spin = QSpinBox()
        self.index_spin.setValue(0)
        self.index_spin.setRange(0, 999999)
        self.index_spin.setFixedWidth(75)
        self.index_spin.valueChanged.connect(self._update_derived_path)
        path_row.addWidget(self.index_spin)

        path_row.addSpacing(8)
        path_row.addWidget(QLabel("Derivation Path:"))
        self.derived_path_field = QLineEdit()
        self.derived_path_field.setReadOnly(False)
        self.derived_path_field.setText("m/84'/0'/0'/0/0")
        self.derived_path_field.setStyleSheet(
            "background: #090c10; border: 1px solid #30363d; border-radius: 4px;"
            "color: #f0a500; padding: 4px 8px; font-family: monospace; font-size: 12px; font-weight: 600;"
        )
        path_row.addWidget(self.derived_path_field, 1)

        self.btn_derive = QPushButton("Derive")
        self.btn_derive.setObjectName("btn_derive")
        self.btn_derive.setFixedWidth(90)
        self.btn_derive.clicked.connect(self._on_derive)
        path_row.addWidget(self.btn_derive)
        input_v.addLayout(path_row)

        layout.addWidget(input_box)

        # ── Section 2: Master Cryptographic Seeds / Root Keys ────────
        seeds_box = QGroupBox("Master Seed & Extended Root Keys")
        seeds_v = QVBoxLayout(seeds_box)
        seeds_v.setSpacing(8)

        self.seed_field, _, _ = make_field_row(seeds_v, "BIP-39 Seed (512-bit Hex):")
        self.xprv_field, _, _ = make_field_row(seeds_v, "Master Extended Private (xprv):")
        self.xpub_field, _, _ = make_field_row(seeds_v, "Master Extended Public (xpub):")

        layout.addWidget(seeds_box)

        # ── Section 3: Derived Key Pair / Blockchain Addresses ───────
        derived_box = QGroupBox("Derived Key Pair & Blockchain Addresses")
        self.derived_box_layout = QVBoxLayout(derived_box)
        self.derived_box_layout.setSpacing(8)

        self.wif_field, _, self.wif_label = make_field_row(self.derived_box_layout, "Private Key (WIF):")
        self.privhex_field, _, _ = make_field_row(self.derived_box_layout, "Private Key (Hex):")
        self.pubkey_field, _, _ = make_field_row(self.derived_box_layout, "Public Key (Compressed):")

        # Divider line
        divider = QFrame()
        divider.setFrameShape(QFrame.Shape.HLine)
        divider.setStyleSheet("color: #21262d; margin: 4px 0;")
        self.derived_box_layout.addWidget(divider)

        # Container widget for dynamically recreated address rows
        self.addr_container = QWidget()
        self.addr_container.setStyleSheet("background: transparent;")
        self.addr_layout = QVBoxLayout(self.addr_container)
        self.addr_layout.setContentsMargins(0, 0, 0, 0)
        self.addr_layout.setSpacing(8)
        self.derived_box_layout.addWidget(self.addr_container)

        self.addr_rows = {}
        self._build_address_rows("bitcoin")

        layout.addWidget(derived_box)
        layout.addStretch()

    def _populate_standards_for_network(self, network_key: str):
        self._block_signals = True
        self.standard_combo.clear()
        standards = NETWORK_STANDARDS.get(network_key, NETWORK_STANDARDS["bitcoin"])
        for name, path, key in standards:
            self.standard_combo.addItem(name, (path, key))
        self.standard_combo.setCurrentIndex(0)
        self._block_signals = False

    def _build_address_rows(self, network_key: str):
        """Build or rebuild dynamic address rows based on selected network."""
        # Clear existing rows in addr_layout
        while self.addr_layout.count():
            item = self.addr_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                # Clear sub-layout items
                sub_layout = item.layout()
                while sub_layout.count():
                    sub_item = sub_layout.takeAt(0)
                    if sub_item.widget():
                        sub_item.widget().deleteLater()

        self.addr_rows = {}
        addr_configs = NETWORK_ADDR_CONFIGS.get(network_key, NETWORK_ADDR_CONFIGS["bitcoin"])

        for name, addr_key, net in addr_configs:
            row = QHBoxLayout()
            lbl = QLabel(f"{name}")
            lbl.setFixedWidth(210)
            lbl.setStyleSheet("color: #c9d1d9; font-size: 12px; font-weight: 600;")

            addr_field = QLineEdit()
            addr_field.setReadOnly(True)
            addr_field.setStyleSheet(
                "background: #090c10; border: 1px solid #21262d; border-radius: 4px;"
                "color: #58a6ff; padding: 5px 8px; font-family: 'Courier New', monospace; font-size: 11px; font-weight: 600;"
            )

            copy_btn = make_copy_btn()
            copy_btn.clicked.connect(lambda _, f=addr_field: (cb := QApplication.clipboard()) and cb.setText(f.text()))

            bal_lbl = QLabel("0.00000000")
            bal_lbl.setFixedWidth(95)
            bal_lbl.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            bal_lbl.setStyleSheet("color: #8b949e; font-family: 'Courier New', monospace; font-size: 11px;")

            check_btn = QPushButton("Check")
            check_btn.setObjectName("btn_check_balance")
            check_btn.setFixedWidth(64)
            check_btn.setFixedHeight(24)
            check_btn.clicked.connect(lambda _, ak=addr_key, n=net, bl=bal_lbl: self._check_balance(ak, n, bl))

            row.addWidget(lbl)
            row.addWidget(addr_field, 1)
            row.addWidget(copy_btn)
            row.addWidget(bal_lbl)
            row.addWidget(check_btn)

            self.addr_rows[addr_key] = (addr_field, bal_lbl)
            self.addr_layout.addLayout(row)

    def set_network(self, network_key: str):
        """Called when the user selects a coin/network in the top toolbar combo box."""
        self.current_network = network_key
        self._populate_standards_for_network(network_key)
        self._build_address_rows(network_key)
        self._update_derived_path()
        if self.mnemonic_input.toPlainText().strip():
            self._on_derive()

    def _on_standard_changed(self, idx):
        if self._block_signals:
            return
        self._update_derived_path()
        self._on_derive()

    def _update_derived_path(self):
        data = self.standard_combo.currentData()
        if not data:
            return
        base_path, key = data
        acct = self.account_spin.value()
        change = self.change_spin.value()
        index = self.index_spin.value()

        # Build path based on standard
        if "501'" in base_path:
            full_path = f"m/44'/501'/{acct}'/{index}'"
        elif "784'" in base_path:
            full_path = f"m/44'/784'/{acct}'/{index}'"
        elif "637'" in base_path:
            full_path = f"m/44'/637'/{acct}'/{index}'"
        elif "397'" in base_path:
            full_path = f"m/44'/397'/{acct}'"
        elif "'" in base_path:
            parts = base_path.split("/")
            if len(parts) >= 4:
                # BIP-44/49/84/86: m/purpose'/coin'/account'
                parts[-1] = f"{acct}'"
                base = "/".join(parts)
                full_path = f"{base}/{change}/{index}"
            else:
                full_path = f"{base_path}/{change}/{index}"
        else:
            full_path = f"{base_path}/{index}"

        self.derived_path_field.setText(full_path)
        if self.mnemonic_input.toPlainText().strip() and not self._block_signals:
            self._on_derive()

    def _on_mnemonic_changed(self):
        text = self.mnemonic_input.toPlainText().strip()
        if not text:
            return
        # Validate mnemonic
        QTimer.singleShot(300, self._validate_mnemonic)

    def _validate_mnemonic(self):
        text = self.mnemonic_input.toPlainText().strip()
        if not text:
            return
        try:
            from hd_wallet.bip39 import validate_mnemonic
            valid = validate_mnemonic(text)
            self.main_window.set_mnemonic_status(valid, text)
        except Exception:
            pass

    def _on_derive(self):
        text = self.mnemonic_input.toPlainText().strip()
        if not text:
            return

        path = self.derived_path_field.text().strip()
        if not path:
            path = "m/84'/0'/0'/0/0"

        passphrase = self.passphrase_input.text().strip()

        try:
            from hd_wallet.wallet import HDWallet
            wallet = HDWallet(text, passphrase=passphrase, network=self.current_network)
            self.current_wallet = wallet

            # Update main window's shared wallet
            self.main_window.set_wallet(wallet)

            # Fill master seeds
            self.seed_field.setText(wallet.seed_hex or '')
            self.xprv_field.setText(wallet.master_xprv or '')
            self.xpub_field.setText(wallet.master_xpub or '')

            # Derive the key
            derived = wallet.derive_key(path)
            self.current_derived = derived

            self.wif_field.setText(derived.get('privateKeyWif', ''))
            self.privhex_field.setText(derived.get('privateKeyHex', ''))
            self.pubkey_field.setText(derived.get('publicKeyCompressedHex', ''))

            # Address fields
            for addr_key, (addr_field, bal_lbl) in self.addr_rows.items():
                addr = derived.get(addr_key, '')
                addr_field.setText(addr)
                bal_lbl.setText("0.00000000")
                bal_lbl.setStyleSheet("color: #9da7b3; font-family: 'Courier New', monospace; font-size: 11px;")

        except Exception as e:
            self.main_window.status_bar_msg(f"Derivation error: {e}")

    def _check_balance(self, addr_key: str, network: str, bal_lbl: QLabel):
        if not self.current_derived:
            return
        address = self.current_derived.get(addr_key, '')
        if not address:
            return

        bal_lbl.setText("⏳")
        from .workers import BalanceCheckWorker
        worker = BalanceCheckWorker(address, network)
        worker.result.connect(lambda addr, r, lbl=bal_lbl: self._on_balance_result(r, lbl))
        worker.error.connect(lambda e, lbl=bal_lbl: lbl.setText("ERR"))
        worker.start()
        self._balance_workers.append(worker)

    def _on_balance_result(self, result: dict, bal_lbl: QLabel):
        bal = result.get('balance', 0) or 0
        unit = result.get('unit', '')
        if isinstance(bal, (int, float)) and bal > 0:
            bal_lbl.setText(f"{bal:.8f}")
            bal_lbl.setStyleSheet("color: #00ff66; font-family: 'Courier New', monospace; font-size: 11px; font-weight: 700;")
        else:
            bal_lbl.setText("0.00000000")
            bal_lbl.setStyleSheet("color: #9da7b3; font-family: 'Courier New', monospace; font-size: 11px;")

    def load_wallet(self, wallet):
        """Called when wallet changes from toolbar."""
        self.current_wallet = wallet
        self.mnemonic_input.setText(wallet.raw_input)
        self.seed_field.setText(wallet.seed_hex or '')
        self.xprv_field.setText(wallet.master_xprv or '')
        self.xpub_field.setText(wallet.master_xpub or '')
        self._on_derive()

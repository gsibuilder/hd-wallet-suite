"""
Tab 2: Batch Address Table
Generate and display a table of derived addresses with live balance queries.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QSpinBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QApplication, QFileDialog, QFrame, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont

BATCH_PRESETS = [
    ("Bitcoin Native SegWit (BIP-84) [bc1q...]", "m/84'/0'/0'", "addressP2WPKH", "bitcoin"),
    ("Bitcoin Taproot (BIP-86) [bc1p...]", "m/86'/0'/0'", "addressP2TR", "bitcoin"),
    ("Bitcoin Nested SegWit (BIP-49) [3...]", "m/49'/0'/0'", "addressP2SH", "bitcoin"),
    ("Bitcoin Legacy (BIP-44) [1...]", "m/44'/0'/0'", "addressP2PKH", "bitcoin"),
    ("Ethereum / EVM (BIP-44) [0x...]", "m/44'/60'/0'", "addressETH", "ethereum"),
    ("Solana (BIP-44) [sol...]", "m/44'/501'/0'", "addressSOL", "solana"),
    ("Tron (BIP-44) [T...]", "m/44'/195'/0'", "addressTRX", "tron"),
    ("XRP Ledger (BIP-44) [r...]", "m/44'/144'/0'", "addressXRP", "xrp"),
    ("Litecoin (BIP-84) [ltc1...]", "m/84'/2'/0'", "addressLTC", "litecoin"),
    ("Dogecoin (BIP-44) [D...]", "m/44'/3'/0'", "addressDOGE", "dogecoin"),
    ("BNB Chain (BIP-44) [0x...]", "m/44'/60'/0'", "addressETH", "bnb"),
    ("Cosmos (BIP-44) [cosmos...]", "m/44'/118'/0'", "addressATOM", "cosmos"),
    ("Polkadot (BIP-44) [1...]", "m/44'/354'/0'", "addressDOT", "polkadot"),
    ("Cardano (BIP-44) [addr...]", "m/44'/1815'/0'", "addressADA", "cardano"),
    ("Avalanche (BIP-44) [0x...]", "m/44'/60'/0'", "addressETH", "avalanche"),
    ("Polygon (BIP-44) [0x...]", "m/44'/60'/0'", "addressETH", "polygon"),
]


class BatchAddressTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = None
        self.current_rows = []
        self._balance_worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        # Controls row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(8)

        ctrl_row.addWidget(QLabel("Base Derivation:"))
        self.preset_combo = QComboBox()
        self.preset_combo.setMinimumWidth(320)
        for name, path, addr_key, net in BATCH_PRESETS:
            self.preset_combo.addItem(name, (path, addr_key, net))
        ctrl_row.addWidget(self.preset_combo)

        ctrl_row.addWidget(QLabel("Count:"))
        self.count_spin = QSpinBox()
        self.count_spin.setRange(1, 1000)
        self.count_spin.setValue(50)
        self.count_spin.setFixedWidth(80)
        ctrl_row.addWidget(self.count_spin)

        self.btn_generate = QPushButton("⚡ Generate Batch")
        self.btn_generate.setObjectName("btn_generate_batch")
        self.btn_generate.clicked.connect(self._generate_batch)
        ctrl_row.addWidget(self.btn_generate)

        self.btn_query = QPushButton("🔍 Query Live Balances")
        self.btn_query.setObjectName("btn_query_live")
        self.btn_query.clicked.connect(self._query_balances)
        ctrl_row.addWidget(self.btn_query)

        self.btn_export = QPushButton("📤 Export CSV")
        self.btn_export.setObjectName("btn_export_csv")
        self.btn_export.clicked.connect(self._export_csv)
        ctrl_row.addWidget(self.btn_export)

        ctrl_row.addStretch()
        layout.addLayout(ctrl_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "#", "Index", "Path", "Derived Address", "Live Balance", "Public Key", "Private Key (WIF)"
        ])
        # Actually 7 columns:
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "#", "Index", "Path", "Derived Address", "Live Balance", "Public Key", "Private Key (WIF)"
        ])
        hh = self.table.horizontalHeader()
        if hh:
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(1, 55)
        self.table.setColumnWidth(4, 120)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        vh = self.table.verticalHeader()
        if vh:
            vh.setVisible(False)
        layout.addWidget(self.table)

    def set_wallet(self, wallet):
        self.wallet = wallet

    def _generate_batch(self):
        if not self.wallet:
            self.main_window.status_bar_msg("No wallet loaded. Enter a mnemonic first.")
            return

        data = self.preset_combo.currentData()
        if not data:
            return
        base_path, addr_key, network = data
        count = self.count_spin.value()

        self.btn_generate.setText("⏳ Generating...")
        self.btn_generate.setEnabled(False)
        QApplication.processEvents()

        try:
            results = self.wallet.derive_address_batch(
                base_path=base_path,
                count=count,
                change=0,
                start_index=0
            )
            self.current_rows = [(r, addr_key, network) for r in results]
            self._fill_table(results, addr_key)
            self.main_window.status_bar_msg(f"Generated {len(results)} addresses.")
        except Exception as e:
            self.main_window.status_bar_msg(f"Batch error: {e}")
        finally:
            self.btn_generate.setText("⚡ Generate Batch")
            self.btn_generate.setEnabled(True)

    def _fill_table(self, results: list, addr_key: str):
        self.table.setRowCount(0)
        for i, row_data in enumerate(results):
            row_num = self.table.rowCount()
            self.table.insertRow(row_num)

            # Row number (bold, orange)
            num_item = QTableWidgetItem(str(i + 1))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num_item.setForeground(QColor("#ffaa00"))
            num_item.setFont(QFont("", -1, QFont.Weight.Bold))
            num_item.setFlags(num_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_num, 0, num_item)

            index_item = QTableWidgetItem(str(row_data.get('index', i)))
            index_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            index_item.setForeground(QColor("#ffffff"))
            index_item.setFlags(index_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_num, 1, index_item)

            path_item = QTableWidgetItem(row_data.get('path', ''))
            path_item.setForeground(QColor("#ffffff"))
            path_item.setFlags(path_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_num, 2, path_item)

            # Address
            addr = row_data.get('address', '')
            addr_item = QTableWidgetItem(addr)
            addr_item.setForeground(QColor("#58a6ff"))
            addr_item.setFlags(addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_num, 3, addr_item)

            # Balance (empty for now)
            bal_item = QTableWidgetItem("---")
            bal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            bal_item.setForeground(QColor("#9da7b3"))
            bal_item.setFlags(bal_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row_num, 4, bal_item)

            # Public key
            pub_item = QTableWidgetItem(row_data.get('publicKey', ''))
            pub_item.setFlags(pub_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            pub_item.setForeground(QColor("#ffffff"))
            self.table.setItem(row_num, 5, pub_item)

            # Private key WIF
            wif_item = QTableWidgetItem(row_data.get('privateKeyWif', ''))
            wif_item.setFlags(wif_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            wif_item.setForeground(QColor("#00ff66"))
            self.table.setItem(row_num, 6, wif_item)

        self.table.resizeRowsToContents()

    def _query_balances(self):
        if self.table.rowCount() == 0:
            return
        if self._balance_worker and self._balance_worker.isRunning():
            self._balance_worker.stop()

        addresses = []
        for row in range(self.table.rowCount()):
            addr_item = self.table.item(row, 3)
            if addr_item:
                data = self.preset_combo.currentData()
                net = data[2] if data else 'bitcoin'
                addresses.append((row, addr_item.text(), net))

        from .workers import BatchBalanceWorker
        worker = BatchBalanceWorker(addresses)
        worker.address_result.connect(self._on_balance_result)
        worker.progress.connect(
            lambda done, total: self.main_window.status_bar_msg(f"Checking balances... {done}/{total}")
        )
        worker.finished.connect(
            lambda: self.main_window.status_bar_msg("Balance check complete.")
        )
        self.btn_query.setText("⏳ Querying...")
        self.btn_query.setEnabled(False)
        worker.finished.connect(lambda: (
            self.btn_query.setText("🔍 Query Live Balances"),
            self.btn_query.setEnabled(True)
        ))
        self._balance_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_balance_result(self, row: int, balance_str: str):
        item = self.table.item(row, 4)
        if item:
            item.setText(balance_str)
            if balance_str not in ("---", "0.00000000", "ERR"):
                item.setForeground(QColor("#00ff66"))
            else:
                item.setForeground(QColor("#9da7b3"))

    def _export_csv(self):
        if self.table.rowCount() == 0:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "batch_addresses.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w') as f:
                headers = ["#", "Index", "Path", "Address", "Balance", "PublicKey", "PrivateKeyWIF"]
                f.write(",".join(headers) + "\n")
                for row in range(self.table.rowCount()):
                    cells = []
                    for col in range(7):
                        item = self.table.item(row, col)
                        cells.append(f'"{item.text() if item else ""}"')
                    f.write(",".join(cells) + "\n")
            self.main_window.status_bar_msg(f"Exported to {path}")
        except Exception as e:
            self.main_window.status_bar_msg(f"Export error: {e}")

    def _context_menu(self, pos):
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        item = self.table.itemAt(pos)
        if not item:
            return
        copy_action = menu.addAction("📋 Copy Cell")
        if copy_action:
            copy_action.triggered.connect(lambda: (cb := QApplication.clipboard()) and cb.setText(item.text()))
        copy_row_action = menu.addAction("📋 Copy Row")
        row = item.row()
        if copy_row_action:
            copy_row_action.triggered.connect(lambda: self._copy_row(row))
        menu.exec(self.table.mapToGlobal(pos))

    def _copy_row(self, row: int):
        cells = []
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            cells.append(item.text() if item else "")
        cb = QApplication.clipboard()
        if cb:
            cb.setText("\t".join(cells))

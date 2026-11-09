"""
Tab: All Chains Balance Summary
Table view of all 50+ blockchain networks with derived addresses and live balance checks.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView,
    QApplication, QAbstractItemView, QFileDialog
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont
from .tab_multichain import CHAINS_50


class AllChainsBalanceTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = None
        self._worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        # Control row
        ctrl_row = QHBoxLayout()
        ctrl_row.setSpacing(8)

        self.btn_query = QPushButton("⚡ Query All Chains Balances")
        self.btn_query.setObjectName("btn_query_all_chains")
        self.btn_query.clicked.connect(self._query_all_balances)
        ctrl_row.addWidget(self.btn_query)

        self.btn_export = QPushButton("📤 Export CSV")
        self.btn_export.setObjectName("btn_export_all_chains_csv")
        self.btn_export.clicked.connect(self._export_csv)
        ctrl_row.addWidget(self.btn_export)

        ctrl_row.addStretch()
        self.status_lbl = QLabel("Load a wallet (Mnemonic) to scan all chains.")
        self.status_lbl.setStyleSheet("color: #ffffff; font-size: 11px; font-weight: 600;")
        ctrl_row.addWidget(self.status_lbl)

        layout.addLayout(ctrl_row)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            "Chain / Network", "Symbol", "Derivation Path", "Derived Address", "Live Balance", "Status"
        ])
        hh = self.table.horizontalHeader()
        if hh:
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)

        self.table.setColumnWidth(0, 180)
        self.table.setColumnWidth(1, 70)
        self.table.setColumnWidth(2, 180)
        self.table.setColumnWidth(3, 320)
        self.table.setColumnWidth(4, 130)
        self.table.setColumnWidth(5, 90)

        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        vh = self.table.verticalHeader()
        if vh:
            vh.setVisible(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._context_menu)
        layout.addWidget(self.table)

    def set_wallet(self, wallet):
        # Stop any running background worker before updating wallet
        if self._worker and self._worker.isRunning():
            self._worker.stop()
        self.wallet = wallet
        self._populate_chains()
        if wallet:
            self.status_lbl.setText("Wallet loaded. Click 'Query All Chains Balances' to scan live balances.")

    def _populate_chains(self):
        self.table.setRowCount(0)
        if not self.wallet:
            for (key, display_name, symbol, emoji, path, addr_key, color) in CHAINS_50:
                row = self.table.rowCount()
                self.table.insertRow(row)

                # Name
                name_item = QTableWidgetItem(f"{emoji} {display_name}")
                name_item.setForeground(QColor(color))
                name_item.setFont(QFont("", -1, QFont.Weight.Bold))
                name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, 0, name_item)

                # Symbol
                sym_item = QTableWidgetItem(symbol)
                sym_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                sym_item.setFlags(sym_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, 1, sym_item)

                # Path
                path_item = QTableWidgetItem(path)
                path_item.setFlags(path_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, 2, path_item)

                # Address
                addr_item = QTableWidgetItem("---")
                addr_item.setForeground(QColor("#9da7b3"))
                addr_item.setFont(QFont("Courier New", 9))
                addr_item.setFlags(addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, 3, addr_item)

                # Balance
                bal_item = QTableWidgetItem("0.00000000")
                bal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                bal_item.setForeground(QColor("#9da7b3"))
                bal_item.setFlags(bal_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, 4, bal_item)

                # Status
                stat_item = QTableWidgetItem("No Wallet")
                stat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                stat_item.setForeground(QColor("#9da7b3"))
                stat_item.setFlags(stat_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                self.table.setItem(row, 5, stat_item)
            return

        # Derive addresses for all chains
        for row, (key, display_name, symbol, emoji, path, addr_key, color) in enumerate(CHAINS_50):
            self.table.insertRow(row)

            name_item = QTableWidgetItem(f"{emoji} {display_name}")
            name_item.setForeground(QColor(color))
            name_item.setFont(QFont("", -1, QFont.Weight.Bold))
            name_item.setFlags(name_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 0, name_item)

            sym_item = QTableWidgetItem(symbol)
            sym_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            sym_item.setForeground(QColor("#ffffff"))
            sym_item.setFlags(sym_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 1, sym_item)

            path_item = QTableWidgetItem(path)
            path_item.setForeground(QColor("#ffffff"))
            path_item.setFlags(path_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 2, path_item)

            address = ""
            try:
                derived = self.wallet.derive_key(path)
                address = derived.get(addr_key, '')
            except Exception:
                pass

            addr_item = QTableWidgetItem(address if address else "N/A")
            addr_item.setForeground(QColor("#58a6ff" if address else "#9da7b3"))
            addr_item.setFont(QFont("Courier New", 9))
            addr_item.setFlags(addr_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 3, addr_item)

            bal_item = QTableWidgetItem("---")
            bal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            bal_item.setForeground(QColor("#9da7b3"))
            bal_item.setFlags(bal_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 4, bal_item)

            stat_item = QTableWidgetItem("Ready")
            stat_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            stat_item.setForeground(QColor("#ffffff"))
            stat_item.setFlags(stat_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 5, stat_item)

        self.table.resizeRowsToContents()

    def _query_all_balances(self):
        if not self.wallet:
            if self.main_window:
                self.main_window.status_bar_msg("No wallet loaded. Enter a mnemonic first.")
            return

        if self._worker and self._worker.isRunning():
            self._worker.stop()

        self.btn_query.setEnabled(False)
        self.btn_query.setText("⏳ Scanning All Chains...")
        self.status_lbl.setText("Querying live balances across all chains...")

        from .workers import MultichainBalanceWorker
        all_chains_data = [(key, name, path, addr_key) for (key, name, symbol, emoji, path, addr_key, color) in CHAINS_50]

        worker = MultichainBalanceWorker(self.wallet, all_chains_data)
        worker.coin_result.connect(self._on_coin_result)
        worker.finished.connect(self._on_query_finished)
        self._worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_coin_result(self, net_key: str, address: str, balance_str: str):
        for row in range(self.table.rowCount()):
            name_item = self.table.item(row, 0)
            if name_item:
                match_key = CHAINS_50[row][0]
                if match_key == net_key:
                    bal_item = self.table.item(row, 4)
                    stat_item = self.table.item(row, 5)
                    if bal_item and stat_item:
                        bal_item.setText(balance_str)
                        try:
                            f_val = float(balance_str)
                        except ValueError:
                            f_val = 0.0

                        if f_val > 0:
                            bal_item.setForeground(QColor("#00ff66"))  # Neon Green
                            bal_item.setFont(QFont("", -1, QFont.Weight.Bold))
                            stat_item.setText("FUNDED 🎉")
                            stat_item.setForeground(QColor("#00ff66"))
                        else:
                            bal_item.setForeground(QColor("#9da7b3"))
                            stat_item.setText("Checked")
                            stat_item.setForeground(QColor("#ffffff"))
                    break

    def _on_query_finished(self):
        self.btn_query.setEnabled(True)
        self.btn_query.setText("⚡ Query All Chains Balances")
        self.status_lbl.setText("All chains scanned successfully ✅")
        if self.main_window:
            self.main_window.status_bar_msg("All Chains Balance Scan Completed.")

    def _export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export All Chains Balances", "all_chains_balances.csv", "CSV Files (*.csv)")
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as f:
                f.write("Chain,Symbol,DerivationPath,Address,Balance,Status\n")
                for row in range(self.table.rowCount()):
                    chain = it.text() if (it := self.table.item(row, 0)) else ""
                    sym = it.text() if (it := self.table.item(row, 1)) else ""
                    dpath = it.text() if (it := self.table.item(row, 2)) else ""
                    addr = it.text() if (it := self.table.item(row, 3)) else ""
                    bal = it.text() if (it := self.table.item(row, 4)) else ""
                    stat = it.text() if (it := self.table.item(row, 5)) else ""
                    f.write(f'"{chain}","{sym}","{dpath}","{addr}","{bal}","{stat}"\n')
            self.main_window.status_bar_msg(f"Exported to {path}")
        except Exception as e:
            self.main_window.status_bar_msg(f"Export error: {e}")

    def _context_menu(self, pos):
        from PyQt6.QtWidgets import QMenu
        menu = QMenu(self)
        item = self.table.itemAt(pos)
        if not item:
            return
        copy_cell = menu.addAction("📋 Copy Cell")
        if copy_cell:
            copy_cell.triggered.connect(lambda: (cb := QApplication.clipboard()) and cb.setText(item.text()))
        row = item.row()
        addr_item = self.table.item(row, 3)
        if addr_item:
            copy_addr = menu.addAction("📋 Copy Address")
            if copy_addr:
                copy_addr.triggered.connect(lambda: (cb := QApplication.clipboard()) and cb.setText(addr_item.text()))
        menu.exec(self.table.mapToGlobal(pos))

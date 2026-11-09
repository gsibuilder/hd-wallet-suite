"""
Tab 5: Wallet Files / Databases
Berkeley DB / SQLite wallet scanner, parser, and key extractor.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QApplication, QFileDialog, QAbstractItemView,
    QSplitter
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont


class WalletFilesTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self._db_worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        # ── Action Bar ───────────────────────────────────────────────
        action_row = QHBoxLayout()

        self.btn_rescan = QPushButton("Rescan System Databases")
        self.btn_rescan.setObjectName("btn_rescan_db")
        self.btn_rescan.clicked.connect(self._rescan)
        action_row.addWidget(self.btn_rescan)

        self.btn_browse = QPushButton("Browse Wallet / DB...")
        self.btn_browse.setObjectName("btn_load_wallet_db")
        self.btn_browse.clicked.connect(self._browse)
        action_row.addWidget(self.btn_browse)

        self.scan_status = QLabel("Detected Local Wallets: Ready")
        self.scan_status.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        action_row.addWidget(self.scan_status, 1)

        self.btn_query_all = QPushButton("Query Balances for All Wallets")
        self.btn_query_all.setObjectName("btn_primary")
        self.btn_query_all.clicked.connect(self._query_all_balances)
        action_row.addWidget(self.btn_query_all)

        layout.addLayout(action_row)

        # ── Splitter ─────────────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Vertical)

        # Database Files Table
        db_widget = QGroupBox("Detected Database Files & Wallets")
        db_v = QVBoxLayout(db_widget)
        self.db_table = QTableWidget()
        self.db_table.setColumnCount(6)
        self.db_table.setHorizontalHeaderLabels(["Database Path", "Format", "Size", "Keys / Addrs", "Live Balance", "Actions"])
        dhh = self.db_table.horizontalHeader()
        if dhh:
            dhh.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
            dhh.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
            dhh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            dhh.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
            dhh.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
            dhh.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.db_table.setColumnWidth(1, 100)
        self.db_table.setColumnWidth(2, 80)
        self.db_table.setColumnWidth(3, 100)
        self.db_table.setColumnWidth(4, 120)
        self.db_table.setColumnWidth(5, 120)
        self.db_table.setAlternatingRowColors(True)
        dvh = self.db_table.verticalHeader()
        if dvh:
            dvh.setVisible(False)
        self.db_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.db_table.itemSelectionChanged.connect(self._on_db_selected)
        db_v.addWidget(self.db_table)
        splitter.addWidget(db_widget)

        # Extracted Keys Table
        keys_widget = QGroupBox("Extracted Keys, Master Seeds & Output Records")
        keys_v = QVBoxLayout(keys_widget)

        keys_ctrl = QHBoxLayout()
        self.keys_status = QLabel("No wallet selected. Click 'Inspect' on any file above.")
        self.keys_status.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
        keys_ctrl.addWidget(self.keys_status, 1)

        self.btn_export_csv = QPushButton("Export Records CSV")
        self.btn_export_csv.setObjectName("btn_export_csv")
        self.btn_export_csv.clicked.connect(self._export_csv)
        keys_ctrl.addWidget(self.btn_export_csv)
        keys_v.addLayout(keys_ctrl)

        self.keys_table = QTableWidget()
        self.keys_table.setColumnCount(5)
        self.keys_table.setHorizontalHeaderLabels(["Type & Status", "Address", "Live Balance", "Public Key", "Private Key (WIF)"])
        khh = self.keys_table.horizontalHeader()
        if khh:
            khh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            khh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            khh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            khh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            khh.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.keys_table.setColumnWidth(0, 150)
        self.keys_table.setColumnWidth(2, 120)
        self.keys_table.setAlternatingRowColors(True)
        kvh = self.keys_table.verticalHeader()
        if kvh:
            kvh.setVisible(False)
        keys_v.addWidget(self.keys_table)
        splitter.addWidget(keys_widget)

        splitter.setSizes([300, 300])
        layout.addWidget(splitter)

    def _rescan(self):
        self.scan_status.setText("Scanning...")
        self.btn_rescan.setEnabled(False)
        from .workers import WalletDBWorker
        worker = WalletDBWorker(action='scan')
        worker.result.connect(self._on_scan_result)
        worker.error.connect(lambda e: self.scan_status.setText(f"Scan error: {e}"))
        worker.finished.connect(lambda: self.btn_rescan.setEnabled(True))
        self._db_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_scan_result(self, data: dict):
        dbs = data.get('databases', [])
        self.scan_status.setText(f"Detected Local Wallets: {len(dbs)} found")
        self.db_table.setRowCount(0)
        for db_info in dbs:
            self._add_db_row(db_info)

    def _add_db_row(self, db_info: dict):
        path = db_info.get('path', '')
        fmt = db_info.get('format', 'Unknown')
        size = db_info.get('size_bytes', db_info.get('size', 0))
        key_count = db_info.get('records_count', db_info.get('key_count', 0))
        if not key_count and db_info.get('extracted_addresses'):
            key_count = len(db_info['extracted_addresses'])

        row = self.db_table.rowCount()
        self.db_table.insertRow(row)
        self.db_table.setItem(row, 0, QTableWidgetItem(path))
        self.db_table.setItem(row, 1, QTableWidgetItem(fmt))

        size_str = db_info.get('size_str') or (f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B")
        self.db_table.setItem(row, 2, QTableWidgetItem(size_str))

        count_item = QTableWidgetItem(str(key_count))
        count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        self.db_table.setItem(row, 3, count_item)

        bal_item = QTableWidgetItem("---")
        bal_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
        bal_item.setForeground(QColor("#9da7b3"))
        self.db_table.setItem(row, 4, bal_item)

        # Action button in table
        inspect_btn = QPushButton("🔍 Inspect")
        inspect_btn.setStyleSheet(
            "background: #388bfd; color: white; border: none; border-radius: 3px; padding: 3px 8px; font-size: 11px;"
        )
        inspect_btn.clicked.connect(lambda _, p=path: self._inspect_db(p))
        self.db_table.setCellWidget(row, 5, inspect_btn)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wallet File", os.path.expanduser("~"),
            "Wallet Files (*.dat *.db *.sqlite *.json *.bak);;All Files (*)"
        )
        if path:
            self._inspect_db(path)

    def _inspect_db(self, path: str):
        self.keys_status.setText(f"Parsing: {path}...")
        from .workers import WalletDBWorker
        worker = WalletDBWorker(path=path, action='inspect')
        worker.result.connect(self._on_inspect_result)
        worker.error.connect(lambda e: self.keys_status.setText(f"Parse error: {e}"))
        self._db_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_inspect_result(self, data: dict):
        records = data.get('records', [])
        self.keys_status.setText(f"Extracted {len(records)} records.")
        self.keys_table.setRowCount(0)
        
        auto_populated = False
        for rec in records:
            row = self.keys_table.rowCount()
            self.keys_table.insertRow(row)
            rec_type = rec.get('type', 'Key')
            addr = rec.get('address', '')
            pub = rec.get('public_key', '')
            wif_or_secret = rec.get('private_key_wif', '')
            
            self.keys_table.setItem(row, 0, QTableWidgetItem(rec_type))
            self.keys_table.setItem(row, 1, QTableWidgetItem(addr))
            self.keys_table.setItem(row, 2, QTableWidgetItem("---"))
            self.keys_table.setItem(row, 3, QTableWidgetItem(pub))
            self.keys_table.setItem(row, 4, QTableWidgetItem(wif_or_secret))

            # Auto-populate master wallet across app if valid root secret/mnemonic/xprv found
            if not auto_populated and wif_or_secret:
                clean_sec = wif_or_secret.strip()
                words = clean_sec.split()
                if 12 <= len(words) <= 24 and all(w.isalpha() for w in words):
                    self.main_window.load_mnemonic(clean_sec)
                    auto_populated = True
                elif clean_sec.startswith(('xprv', 'yprv', 'zprv', 'tprv', 'vprv', 'uprv', 'xpub', 'ypub', 'zpub')):
                    self.main_window.load_from_xprv(clean_sec)
                    auto_populated = True
                elif rec_type in ('Master Key', 'Unencrypted Key', 'WIF Key') and len(clean_sec) in (51, 52) and clean_sec[0] in ('5', 'K', 'L', '9', 'c'):
                    self.main_window.load_mnemonic(clean_sec)
                    auto_populated = True

        if auto_populated:
            self.main_window.status_bar_msg("✅ Auto-populated extracted wallet across all application tabs.")

    def _on_db_selected(self):
        pass

    def _query_all_balances(self):
        self.main_window.status_bar_msg("Querying live balances for all detected wallets...")

    def _export_csv(self):
        if self.keys_table.rowCount() == 0:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "wallet_records.csv", "CSV Files (*.csv)")
        if not path:
            return
        with open(path, 'w') as f:
            headers = ["Type", "Address", "Balance", "PublicKey", "PrivateKeyWIF"]
            f.write(",".join(headers) + "\n")
            for row in range(self.keys_table.rowCount()):
                cells = [f'"{it.text() if (it := self.keys_table.item(row, col)) else ""}"'
                         for col in range(5)]
                f.write(",".join(cells) + "\n")
        self.main_window.status_bar_msg(f"Exported to {path}")


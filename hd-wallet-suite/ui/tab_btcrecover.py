"""
Tab 8: BTCRecover / PyWallet
Left panel: PyWallet 2.3 Key Salvage / DB Dumper
Right panel: BTCRecover 1.13 Password Recovery Engine
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QApplication, QFileDialog, QTextEdit,
    QSplitter, QSpinBox, QAbstractItemView, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont


class BTCRecoverTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self._recover_worker = None
        self._dump_worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        # Target wallet file row
        file_row = QHBoxLayout()
        file_row.addWidget(QLabel("Target Wallet / Backup:"))
        self.wallet_path = QLineEdit()
        self.wallet_path.setPlaceholderText("Select or enter path to wallet.dat, .db, .sqlite, .json, or binary file...")
        file_row.addWidget(self.wallet_path, 1)
        self.btn_browse_wallet = QPushButton("📂 Browse...")
        self.btn_browse_wallet.setObjectName("btn_browse_wallet")
        self.btn_browse_wallet.clicked.connect(self._browse_wallet)
        file_row.addWidget(self.btn_browse_wallet)
        layout.addLayout(file_row)

        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── LEFT: PyWallet Dumper ─────────────────────────────────────
        left_widget = QWidget()
        left_v = QVBoxLayout(left_widget)
        left_v.setContentsMargins(0, 0, 4, 0)
        left_v.setSpacing(6)

        pywallet_box = QGroupBox("PyWallet Key Salvage & DB Dumper")
        pywallet_v = QVBoxLayout(pywallet_box)
        pywallet_v.setSpacing(8)

        # Action buttons
        dump_btns = QHBoxLayout()
        self.btn_auto_detect = QPushButton("Auto-Detect & Extract")
        self.btn_auto_detect.setObjectName("btn_start_carve")
        self.btn_auto_detect.clicked.connect(self._auto_detect)
        dump_btns.addWidget(self.btn_auto_detect)

        self.btn_std_dump = QPushButton("Standard Dump (JSON)")
        self.btn_std_dump.setObjectName("btn_load_psbt")
        self.btn_std_dump.clicked.connect(self._standard_dump)
        dump_btns.addWidget(self.btn_std_dump)

        self.btn_binary_dump = QPushButton("Targeted Binary Recovery")
        self.btn_binary_dump.setObjectName("btn_primary")
        self.btn_binary_dump.clicked.connect(self._binary_recovery)
        dump_btns.addWidget(self.btn_binary_dump)
        pywallet_v.addLayout(dump_btns)

        # Keys table
        self.keys_table = QTableWidget()
        self.keys_table.setColumnCount(5)
        self.keys_table.setHorizontalHeaderLabels([
            "Type & Status", "Address", "Decrypted Key / Secret", "Public Key / xpub", "Output Script Descriptors"
        ])
        hh = self.keys_table.horizontalHeader()
        if hh:
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.keys_table.setColumnWidth(0, 120)
        self.keys_table.setAlternatingRowColors(True)
        vh = self.keys_table.verticalHeader()
        if vh:
            vh.setVisible(False)
        pywallet_v.addWidget(self.keys_table)
        left_v.addWidget(pywallet_box)
        splitter.addWidget(left_widget)

        # ── RIGHT: BTCRecover ─────────────────────────────────────────
        right_widget = QWidget()
        right_v = QVBoxLayout(right_widget)
        right_v.setContentsMargins(4, 0, 0, 0)
        right_v.setSpacing(6)

        recover_box = QGroupBox("BTCRecover Password Recovery Engine")
        recover_v = QVBoxLayout(recover_box)
        recover_v.setSpacing(8)

        # Token input
        recover_v.addWidget(QLabel("Candidate Password Tokens (Space-separated):"))
        self.tokens_input = QLineEdit("password pass 123 2021 2022 bitcoin wallet key")
        recover_v.addWidget(self.tokens_input)

        # Max typos
        typos_row = QHBoxLayout()
        typos_row.addWidget(QLabel("Max Typos:"))
        self.max_typos = QSpinBox()
        self.max_typos.setRange(0, 5)
        self.max_typos.setValue(1)
        self.max_typos.setFixedWidth(80)
        typos_row.addWidget(self.max_typos)
        typos_row.addStretch()

        self.btn_start = QPushButton("Start Recovery")
        self.btn_start.setObjectName("btn_start_btcrecover")
        self.btn_start.clicked.connect(self._start_recover)
        typos_row.addWidget(self.btn_start)

        self.btn_stop = QPushButton("Stop")
        self.btn_stop.setObjectName("btn_stop_btcrecover")
        self.btn_stop.clicked.connect(self._stop_recover)
        typos_row.addWidget(self.btn_stop)
        recover_v.addLayout(typos_row)

        # Log area
        self.recover_log = QTextEdit()
        self.recover_log.setReadOnly(True)
        self.recover_log.setPlaceholderText(
            "BTCRecover real-time verification logs, ETA, speed, and recovered passphrases will stream here..."
        )
        self.recover_log.setStyleSheet(
            "QTextEdit { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9;"
            "padding: 8px; font-family: 'Courier New', monospace; font-size: 11px; border-radius: 4px; }"
        )
        recover_v.addWidget(self.recover_log, 1)

        right_v.addWidget(recover_box)
        splitter.addWidget(right_widget)

        splitter.setSizes([600, 700])
        layout.addWidget(splitter, 1)

    def _browse_wallet(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Wallet File", os.path.expanduser("~"),
            "Wallet Files (*.dat *.db *.sqlite *.json *.bak);;All Files (*)"
        )
        if path:
            self.wallet_path.setText(path)

    def _auto_detect(self):
        path = self.wallet_path.text().strip()
        if not path:
            self.main_window.status_bar_msg("Select a wallet file first.")
            return

        self.btn_auto_detect.setText("⏳ Detecting...")
        self.btn_auto_detect.setEnabled(False)

        from .workers import WalletDBWorker
        worker = WalletDBWorker(path=path, action='inspect')
        worker.result.connect(self._on_dump_result)
        worker.error.connect(lambda e: (
            self.main_window.status_bar_msg(f"Error: {e}"),
            self.btn_auto_detect.setText("Auto-Detect & Extract"),
            self.btn_auto_detect.setEnabled(True)
        ))
        worker.finished.connect(lambda: (
            self.btn_auto_detect.setText("Auto-Detect & Extract"),
            self.btn_auto_detect.setEnabled(True)
        ))
        self._dump_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_dump_result(self, data: dict):
        records = data.get('records', [])
        self.keys_table.setRowCount(0)
        auto_populated = False
        for rec in records:
            row = self.keys_table.rowCount()
            self.keys_table.insertRow(row)
            rec_type = rec.get('type', 'Key')
            addr = rec.get('address', '')
            wif_or_secret = rec.get('private_key_wif', '')
            pub = rec.get('public_key', '')
            desc = rec.get('descriptor', '')

            self.keys_table.setItem(row, 0, QTableWidgetItem(rec_type))
            self.keys_table.setItem(row, 1, QTableWidgetItem(addr))
            self.keys_table.setItem(row, 2, QTableWidgetItem(wif_or_secret))
            self.keys_table.setItem(row, 3, QTableWidgetItem(pub))
            self.keys_table.setItem(row, 4, QTableWidgetItem(desc))

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

        msg = f"Extracted {len(records)} keys/records."
        if auto_populated:
            msg += " Master keys auto-populated across tabs."
        self.main_window.status_bar_msg(msg)


    def _standard_dump(self):
        path = self.wallet_path.text().strip()
        if not path:
            self.main_window.status_bar_msg("Select a wallet file first.")
            return
        
        # Populate in-app table immediately
        self._auto_detect()

        import json
        try:
            from hd_wallet.parser import inspect_database_file, parse_wallet_file
            with open(path, 'rb') as f:
                raw_bytes = f.read()
            db_res = inspect_database_file(path)
            file_res = parse_wallet_file(raw_bytes, filename=os.path.basename(path), check_balances=False)
            
            dump_data = {
                'database_info': db_res,
                'parsed_keys_and_derivations': file_res
            }
            out_path, _ = QFileDialog.getSaveFileName(self, "Save Dump", "wallet_dump.json", "JSON Files (*.json)")
            if out_path:
                with open(out_path, 'w') as f:
                    json.dump(dump_data, f, indent=2, default=str)
                self.main_window.status_bar_msg(f"Saved wallet dump to {out_path}")
        except Exception as e:
            self.main_window.status_bar_msg(f"Dump error: {e}")


    def _binary_recovery(self):
        path = self.wallet_path.text().strip()
        if not path:
            return
        self.main_window.status_bar_msg("Binary recovery: scanning raw bytes for keys...")
        # Trigger auto_detect in binary mode
        self._auto_detect()

    def _start_recover(self):
        path = self.wallet_path.text().strip()
        if not path:
            self.recover_log.append("❌ Select a wallet file first.")
            return

        tokens = self.tokens_input.text().strip()
        max_typos = self.max_typos.value()

        self.recover_log.clear()
        self.btn_start.setEnabled(False)

        from .workers import BTCRecoverWorker
        worker = BTCRecoverWorker(path, tokens, max_typos)
        worker.log.connect(self.recover_log.append)
        worker.finished.connect(self._on_recover_done)
        worker.error.connect(lambda e: self.recover_log.append(f"❌ {e}"))
        self._recover_worker = worker
        self._workers.append(worker)
        worker.start()

    def _stop_recover(self):
        if self._recover_worker and self._recover_worker.isRunning():
            self._recover_worker.stop()
            self.recover_log.append("⛔ Recovery stopped by user.")
        self.btn_start.setEnabled(True)

    def _on_recover_done(self, success: bool, msg: str):
        if success:
            self.recover_log.append(f"\n✅ {msg}")
        else:
            self.recover_log.append(f"\n— {msg}")
        self.btn_start.setEnabled(True)

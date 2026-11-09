"""
Tab 9: PSBT Toolkit
PSBT (Partially Signed Bitcoin Transaction) creator, inspector, signer, and broadcaster.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QApplication, QFileDialog, QTextEdit,
    QSplitter, QFrame
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor


class PSBTToolkitTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = None
        self._psbt_worker = None
        self._workers = []
        self.current_psbt_b64 = ''
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(8)

        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── LEFT: PSBT Input / Creator ────────────────────────────────
        left_widget = QWidget()
        left_v = QVBoxLayout(left_widget)
        left_v.setContentsMargins(0, 0, 6, 0)
        left_v.setSpacing(10)

        input_box = QGroupBox("PSBT Input & Creator")
        input_v = QVBoxLayout(input_box)
        input_v.setSpacing(8)

        # File browser
        file_row = QHBoxLayout()
        self.psbt_file_path = QLineEdit()
        self.psbt_file_path.setPlaceholderText("Select .psbt / .txn file or paste below...")
        file_row.addWidget(self.psbt_file_path, 1)
        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.setObjectName("btn_browse_psbt")
        self.btn_browse.clicked.connect(self._browse_psbt)
        file_row.addWidget(self.btn_browse)
        input_v.addLayout(file_row)

        # Raw paste area
        self.raw_psbt_input = QTextEdit()
        self.raw_psbt_input.setPlaceholderText("Or paste raw Base64 / Hex PSBT string directly here...")
        self.raw_psbt_input.setStyleSheet(
            "QTextEdit { background: #090c10; border: 1px solid #30363d; border-radius: 4px;"
            "color: #c9d1d9; padding: 8px; font-family: 'Courier New', monospace; font-size: 11px; }"
        )
        self.raw_psbt_input.setMaximumHeight(110)
        input_v.addWidget(self.raw_psbt_input)

        # Load / Build buttons
        load_row = QHBoxLayout()
        self.btn_load = QPushButton("Load & Inspect")
        self.btn_load.setObjectName("btn_load_psbt")
        self.btn_load.clicked.connect(self._load_psbt)
        load_row.addWidget(self.btn_load)

        self.btn_build = QPushButton("Build New PSBT")
        self.btn_build.setObjectName("btn_build_psbt")
        self.btn_build.clicked.connect(self._build_psbt)
        load_row.addWidget(self.btn_build)
        input_v.addLayout(load_row)

        # Signing operations section
        sign_box = QGroupBox("Signing & Broadcast Operations")
        sign_v = QVBoxLayout(sign_box)
        sign_v.setSpacing(8)

        self.btn_sign = QPushButton("Sign PSBT with Active Keys")
        self.btn_sign.setObjectName("btn_sign_psbt")
        self.btn_sign.clicked.connect(self._sign_psbt)
        sign_v.addWidget(self.btn_sign)

        self.btn_finalize = QPushButton("Finalize & Extract Raw Hex")
        self.btn_finalize.setObjectName("btn_finalize_psbt")
        self.btn_finalize.clicked.connect(self._finalize_psbt)
        sign_v.addWidget(self.btn_finalize)

        self.btn_broadcast = QPushButton("Broadcast Transaction to Mempool")
        self.btn_broadcast.setObjectName("btn_broadcast_psbt")
        self.btn_broadcast.clicked.connect(self._broadcast)
        sign_v.addWidget(self.btn_broadcast)

        input_v.addWidget(sign_box)
        input_v.addStretch()
        left_v.addWidget(input_box)
        splitter.addWidget(left_widget)

        # ── RIGHT: PSBT Inspector ─────────────────────────────────────
        right_widget = QWidget()
        right_v = QVBoxLayout(right_widget)
        right_v.setContentsMargins(4, 0, 0, 0)
        right_v.setSpacing(6)

        # Status bar
        status_row = QHBoxLayout()
        self.status_label = QLabel("Status: Idle")
        self.status_label.setStyleSheet(
            "background: #21262d; color: #c9d1d9; padding: 4px 8px; border-radius: 3px; font-size: 12px;"
        )
        self.status_label.setMinimumWidth(150)
        status_row.addWidget(self.status_label)

        self.inputs_label = QLabel("Inputs: 0 (0 sats)")
        self.inputs_label.setStyleSheet(self.status_label.styleSheet())
        status_row.addWidget(self.inputs_label)

        self.outputs_label = QLabel("Outputs: 0 (0 sats)")
        self.outputs_label.setStyleSheet(self.status_label.styleSheet())
        status_row.addWidget(self.outputs_label)

        self.fee_label = QLabel("Fee: 0 sats")
        self.fee_label.setStyleSheet(self.status_label.styleSheet())
        status_row.addWidget(self.fee_label)
        right_v.addLayout(status_row)

        # Inputs table
        inp_lbl = QLabel("Inputs:")
        inp_lbl.setStyleSheet("color: #ffffff; font-size: 12px; font-weight: 700;")
        right_v.addWidget(inp_lbl)
        self.inputs_table = QTableWidget()
        self.inputs_table.setColumnCount(5)
        self.inputs_table.setHorizontalHeaderLabels(["Index", "TxID : Vout", "Amount (Sats)", "Address / ScriptPubKey", "Signatures"])
        ihh = self.inputs_table.horizontalHeader()
        if ihh:
            ihh.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
            ihh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.inputs_table.setAlternatingRowColors(True)
        ivh = self.inputs_table.verticalHeader()
        if ivh:
            ivh.setVisible(False)
        self.inputs_table.setMaximumHeight(200)
        right_v.addWidget(self.inputs_table)

        # Outputs table
        out_lbl = QLabel("Outputs:")
        out_lbl.setStyleSheet("color: #ffffff; font-size: 12px; font-weight: 700;")
        right_v.addWidget(out_lbl)
        self.outputs_table = QTableWidget()
        self.outputs_table.setColumnCount(3)
        self.outputs_table.setHorizontalHeaderLabels(["Index", "Destination Address", "Amount (Sats)"])
        ohh = self.outputs_table.horizontalHeader()
        if ohh:
            ohh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            ohh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            ohh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        self.outputs_table.setColumnWidth(0, 60)
        self.outputs_table.setColumnWidth(2, 120)
        self.outputs_table.setAlternatingRowColors(True)
        ovh = self.outputs_table.verticalHeader()
        if ovh:
            ovh.setVisible(False)
        self.outputs_table.setMaximumHeight(200)
        right_v.addWidget(self.outputs_table)

        # Result output
        right_v.addWidget(QLabel("Resulting Base64 / Raw Tx Hex:"))
        self.result_output = QTextEdit()
        self.result_output.setReadOnly(True)
        self.result_output.setPlaceholderText(
            "Updated PSBT Base64 or Final Broadcastable Raw Tx Hex will appear here..."
        )
        self.result_output.setStyleSheet(
            "QTextEdit { background: #0d1117; border: 1px solid #30363d; color: #c9d1d9;"
            "padding: 8px; font-family: 'Courier New', monospace; font-size: 11px; border-radius: 4px; }"
        )
        right_v.addWidget(self.result_output, 1)

        splitter.addWidget(right_widget)
        splitter.setSizes([660, 760])
        layout.addWidget(splitter, 1)

    def set_wallet(self, wallet):
        self.wallet = wallet

    def _browse_psbt(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Open PSBT File", os.path.expanduser("~"),
            "PSBT Files (*.psbt *.txn *.txt);;All Files (*)"
        )
        if path:
            self.psbt_file_path.setText(path)
            try:
                with open(path, 'rb') as f:
                    data = f.read()
                if data.startswith(b'psbt\xff'):
                    self.raw_psbt_input.setPlainText(data.hex())
                else:
                    self.raw_psbt_input.setPlainText(data.decode('utf-8', errors='ignore').strip())
            except Exception as e:
                self.main_window.status_bar_msg(f"File read error: {e}")

    def _load_psbt(self):
        psbt_str = self.raw_psbt_input.toPlainText().strip() or self.psbt_file_path.text().strip()
        if not psbt_str:
            return

        self.current_psbt_b64 = psbt_str
        self.status_label.setText("Status: Loading...")

        from .workers import PSBTWorker
        worker = PSBTWorker('load', {'psbt_string': psbt_str})
        worker.result.connect(self._on_psbt_loaded)
        worker.error.connect(lambda e: (
            self.status_label.setText(f"Status: ❌ Error"),
            self.result_output.setPlainText(f"Error parsing PSBT: {e}")
        ))
        self._psbt_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_psbt_loaded(self, data: dict):
        inputs = data.get('inputs', [])
        outputs = data.get('outputs', [])

        # Update status
        in_sats = sum(inp.get('amount', 0) for inp in inputs)
        out_sats = sum(out.get('amount', 0) for out in outputs)
        fee_sats = max(0, in_sats - out_sats)
        self.status_label.setText("Status: Loaded")
        self.inputs_label.setText(f"Inputs: {len(inputs)} ({in_sats:,} sats)")
        self.outputs_label.setText(f"Outputs: {len(outputs)} ({out_sats:,} sats)")
        self.fee_label.setText(f"Fee: {fee_sats:,} sats")

        # Fill inputs table
        self.inputs_table.setRowCount(0)
        for i, inp in enumerate(inputs):
            row = self.inputs_table.rowCount()
            self.inputs_table.insertRow(row)
            self.inputs_table.setItem(row, 0, QTableWidgetItem(str(i)))
            txid_vout = f"{inp.get('txid', '')[:16]}...:{inp.get('vout', 0)}"
            self.inputs_table.setItem(row, 1, QTableWidgetItem(txid_vout))
            self.inputs_table.setItem(row, 2, QTableWidgetItem(str(inp.get('amount', 0))))
            self.inputs_table.setItem(row, 3, QTableWidgetItem(inp.get('address', inp.get('script_pubkey', ''))))
            sigs = inp.get('partial_sigs', {})
            self.inputs_table.setItem(row, 4, QTableWidgetItem(f"{len(sigs)} sig(s)"))

        # Fill outputs table
        self.outputs_table.setRowCount(0)
        for i, out in enumerate(outputs):
            row = self.outputs_table.rowCount()
            self.outputs_table.insertRow(row)
            self.outputs_table.setItem(row, 0, QTableWidgetItem(str(i)))
            self.outputs_table.setItem(row, 1, QTableWidgetItem(out.get('address', '')))
            self.outputs_table.setItem(row, 2, QTableWidgetItem(str(out.get('amount', 0))))

    def _build_psbt(self):
        self.result_output.setPlainText("PSBT builder: use the Batch Address Table to derive addresses, then construct a PSBT manually.")

    def _sign_psbt(self):
        if not self.wallet or not self.current_psbt_b64:
            return
        wif = ''
        try:
            derived = self.wallet.derive_key("m/84'/0'/0'/0/0")
            wif = derived.get('privateKeyWif', '')
        except Exception:
            pass

        from .workers import PSBTWorker
        worker = PSBTWorker('sign', {'psbt_string': self.current_psbt_b64, 'private_key_wif': wif})
        worker.result.connect(lambda d: self.result_output.setPlainText(d.get('signed_psbt', '')))
        worker.error.connect(lambda e: self.result_output.setPlainText(f"Sign error: {e}"))
        self._psbt_worker = worker
        self._workers.append(worker)
        worker.start()

    def _finalize_psbt(self):
        if not self.current_psbt_b64:
            return
        from .workers import PSBTWorker
        worker = PSBTWorker('finalize', {'psbt_string': self.current_psbt_b64})
        worker.result.connect(lambda d: self.result_output.setPlainText(d.get('raw_tx', '')))
        worker.error.connect(lambda e: self.result_output.setPlainText(f"Finalize error: {e}"))
        self._psbt_worker = worker
        self._workers.append(worker)
        worker.start()

    def _broadcast(self):
        raw_tx = self.result_output.toPlainText().strip()
        if not raw_tx:
            return
        self.result_output.append("\n⏳ Broadcasting...")
        try:
            import urllib.request, urllib.parse, json
            url = "https://blockstream.info/api/tx"
            data = raw_tx.encode()
            req = urllib.request.Request(url, data=data, method='POST')
            with urllib.request.urlopen(req, timeout=15) as resp:
                txid = resp.read().decode().strip()
            self.result_output.append(f"\n✅ Broadcast successful! TxID: {txid}")
        except Exception as e:
            self.result_output.append(f"\n❌ Broadcast failed: {e}")

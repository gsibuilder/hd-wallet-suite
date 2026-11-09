"""
Tab 10: Forensic Deep Carving
Memory dumps, binary backups, and corrupted wallet forensic analysis.
Recovers private keys, mnemonics, WIFs, and xprvs from raw binary data.
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
from PyQt6.QtGui import QColor, QFont


class ForensicCarvingTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self._carve_worker = None
        self._workers = []
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 8, 10, 8)
        layout.setSpacing(10)

        # ── Input Section ─────────────────────────────────────────────
        input_box = QGroupBox("Forensic Key & Mnemonic Carving Engine")
        input_v = QVBoxLayout(input_box)
        input_v.setSpacing(8)

        # File browser
        file_row = QHBoxLayout()
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText(
            "Select corrupted wallet.dat, memory dump .dmp, raw partition, or binary backup..."
        )
        file_row.addWidget(self.file_path, 1)
        btn_browse = QPushButton("Browse File...")
        btn_browse.setObjectName("btn_primary")
        btn_browse.clicked.connect(self._browse)
        file_row.addWidget(btn_browse)
        input_v.addLayout(file_row)

        # Raw text paste
        self.raw_input = QTextEdit()
        self.raw_input.setPlaceholderText(
            "Or paste raw corrupted text, hex stream, or partial words here..."
        )
        self.raw_input.setStyleSheet(
            "QTextEdit { background: #090c10; border: 1px solid #30363d; border-radius: 4px;"
            "color: #c9d1d9; padding: 8px; font-family: 'Courier New', monospace; font-size: 11px; }"
        )
        self.raw_input.setMaximumHeight(85)
        input_v.addWidget(self.raw_input)

        # Action buttons
        btn_row = QHBoxLayout()
        self.btn_carve = QPushButton("Start Deep Forensic Carve")
        self.btn_carve.setObjectName("btn_start_carve")
        self.btn_carve.clicked.connect(self._start_carve)
        btn_row.addWidget(self.btn_carve)

        self.btn_missing = QPushButton("1-Word Missing Solver")
        self.btn_missing.setObjectName("btn_missing_solver")
        self.btn_missing.clicked.connect(self._missing_solver)
        btn_row.addWidget(self.btn_missing)

        self.btn_export = QPushButton("Export Markdown Report")
        self.btn_export.setObjectName("btn_export_markdown")
        self.btn_export.clicked.connect(self._export_report)
        btn_row.addWidget(self.btn_export)
        btn_row.addStretch()

        input_v.addLayout(btn_row)
        layout.addWidget(input_box)

        # ── Results Splitter ──────────────────────────────────────────
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left: Carved Artifacts
        left_widget = QGroupBox("Carved Artifacts & Recovered Keys")
        left_v = QVBoxLayout(left_widget)
        left_v.setSpacing(6)

        self.artifacts_status = QLabel("Artifacts: 0 found (0 mnemonics, 0 WIFs, 0 xprvs, 0 descriptors, 0 BDB records)")
        self.artifacts_status.setStyleSheet("color: #3fb950; font-size: 11px;")
        left_v.addWidget(self.artifacts_status)

        self.artifacts_table = QTableWidget()
        self.artifacts_table.setColumnCount(6)
        self.artifacts_table.setHorizontalHeaderLabels([
            "Type", "Recovered Artifact / Key", "Offset", "Derived Address", "Conf", "Action"
        ])
        hh = self.artifacts_table.horizontalHeader()
        if hh is not None:
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        self.artifacts_table.setColumnWidth(0, 100)
        self.artifacts_table.setColumnWidth(2, 90)
        self.artifacts_table.setColumnWidth(4, 50)
        self.artifacts_table.setColumnWidth(5, 80)
        self.artifacts_table.setAlternatingRowColors(True)
        vh = self.artifacts_table.verticalHeader()
        if vh is not None:
            vh.setVisible(False)
        left_v.addWidget(self.artifacts_table)
        splitter.addWidget(left_widget)

        # Right: Forensic Report
        right_widget = QGroupBox("Forensic Report Preview")
        right_v = QVBoxLayout(right_widget)

        self.report_output = QTextEdit()
        self.report_output.setReadOnly(True)
        self.report_output.setPlaceholderText(
            "Detailed forensic carving report with exact byte offsets, entropy scores, "
            "and addresses will display here..."
        )
        self.report_output.setStyleSheet(
            "QTextEdit { background: #0d1117; border: none; color: #c9d1d9;"
            "padding: 8px; font-family: 'Courier New', monospace; font-size: 11px; }"
        )
        right_v.addWidget(self.report_output)
        splitter.addWidget(right_widget)

        splitter.setSizes([700, 580])
        layout.addWidget(splitter, 1)

        # Store report text for export
        self._report_text = ''

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Binary File", os.path.expanduser("~"),
            "Binary Files (*.dat *.db *.dmp *.bin *.raw *.bak *.img);;All Files (*)"
        )
        if path:
            self.file_path.setText(path)

    def _start_carve(self):
        file_path = self.file_path.text().strip()
        raw_text = self.raw_input.toPlainText().strip()

        if not file_path and not raw_text:
            self.main_window.status_bar_msg("Select a file or paste raw data to carve.")
            return

        self.btn_carve.setText("⏳ Carving...")
        self.btn_carve.setEnabled(False)
        self.artifacts_table.setRowCount(0)
        self.report_output.clear()
        self.artifacts_status.setText("Carving in progress...")

        from .workers import CarvingWorker
        worker = CarvingWorker(
            source=file_path if file_path else None,
            raw_text=raw_text if raw_text else None
        )
        worker.result.connect(self._on_carve_result)
        worker.progress.connect(
            lambda msg: self.artifacts_status.setText(msg)
        )
        worker.error.connect(lambda e: (
            self.artifacts_status.setText(f"❌ Error: {e}"),
            self.btn_carve.setText("Start Deep Forensic Carve"),
            self.btn_carve.setEnabled(True)
        ))
        worker.finished.connect(lambda: (
            self.btn_carve.setText("Start Deep Forensic Carve"),
            self.btn_carve.setEnabled(True)
        ))
        self._carve_worker = worker
        self._workers.append(worker)
        worker.start()

    def _on_carve_result(self, data: dict):
        raw_artifacts = data.get('artifacts', [])
        report = data.get('report', '')
        self._report_text = report

        # Normalize artifacts: carve_artifacts returns a dict with category keys
        artifacts = []
        if isinstance(raw_artifacts, dict):
            for m in raw_artifacts.get('mnemonics', []):
                artifacts.append({
                    'type': 'mnemonic',
                    'value': m.get('mnemonic', ''),
                    'offset': m.get('byte_offset_start'),
                    'derived_address': m.get('address_p2wpkh') or m.get('address_legacy') or m.get('address_eth') or '',
                    'confidence': m.get('confidence', 1.0) * 100 if m.get('confidence', 1.0) <= 1.0 else m.get('confidence', 100)
                })
            for w in raw_artifacts.get('wifs', []):
                artifacts.append({
                    'type': 'wif',
                    'value': w.get('wif', ''),
                    'offset': w.get('byte_offset'),
                    'derived_address': w.get('address_p2wpkh') or w.get('address_legacy') or w.get('address_eth') or '',
                    'confidence': w.get('confidence', 1.0) * 100 if w.get('confidence', 1.0) <= 1.0 else w.get('confidence', 100)
                })
            for x in raw_artifacts.get('extended_keys', []):
                artifacts.append({
                    'type': 'xprv' if x.get('is_private') else 'xpub',
                    'value': x.get('extended_key', ''),
                    'offset': x.get('byte_offset'),
                    'derived_address': '',
                    'confidence': x.get('confidence', 1.0) * 100 if x.get('confidence', 1.0) <= 1.0 else x.get('confidence', 100)
                })
            for d in raw_artifacts.get('descriptors', []):
                artifacts.append({
                    'type': 'descriptor',
                    'value': d.get('descriptor', '') if isinstance(d, dict) else str(d),
                    'offset': d.get('byte_offset') if isinstance(d, dict) else None,
                    'derived_address': '',
                    'confidence': 100
                })
            for b in raw_artifacts.get('bdb_records', []):
                artifacts.append({
                    'type': 'bdb',
                    'value': b.get('description', '') if isinstance(b, dict) else str(b),
                    'offset': b.get('byte_offset') if isinstance(b, dict) else None,
                    'derived_address': b.get('address_p2wpkh') or b.get('address_legacy') or '',
                    'confidence': 95
                })
        elif isinstance(raw_artifacts, list):
            for a in raw_artifacts:
                if isinstance(a, dict):
                    artifacts.append(a)
                elif isinstance(a, str):
                    artifacts.append({'type': 'raw', 'value': a, 'offset': None, 'derived_address': '', 'confidence': 100})

        # Count types
        mnems = sum(1 for a in artifacts if a.get('type') == 'mnemonic')
        wifs = sum(1 for a in artifacts if a.get('type') == 'wif')
        xprvs = sum(1 for a in artifacts if a.get('type') in ('xprv', 'xpub'))
        descs = sum(1 for a in artifacts if a.get('type') == 'descriptor')
        bdbs = sum(1 for a in artifacts if a.get('type') == 'bdb')

        self.artifacts_status.setText(
            f"Artifacts: {len(artifacts)} found "
            f"({mnems} mnemonics, {wifs} WIFs, {xprvs} xprvs, {descs} descriptors, {bdbs} BDB records)"
        )

        # Fill table
        self.artifacts_table.setRowCount(0)
        for artifact in artifacts:
            row = self.artifacts_table.rowCount()
            self.artifacts_table.insertRow(row)

            type_item = QTableWidgetItem(artifact.get('type', '').upper())
            type_colors = {'mnemonic': '#f0a500', 'wif': '#3fb950', 'xprv': '#58a6ff', 'descriptor': '#9945ff'}
            color = type_colors.get(artifact.get('type', ''), '#c9d1d9')
            type_item.setForeground(QColor(color))
            self.artifacts_table.setItem(row, 0, type_item)

            value_item = QTableWidgetItem(artifact.get('value', ''))
            value_item.setFont(QFont("Courier New", 10))
            self.artifacts_table.setItem(row, 1, value_item)

            offset_str = f"0x{artifact.get('offset', 0):08x}" if artifact.get('offset') is not None else "N/A"
            offset_item = QTableWidgetItem(offset_str)
            offset_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.artifacts_table.setItem(row, 2, offset_item)

            addr = artifact.get('derived_address', '')
            addr_item = QTableWidgetItem(addr[:20] + '...' if len(addr) > 20 else addr)
            addr_item.setForeground(QColor("#58a6ff"))
            self.artifacts_table.setItem(row, 3, addr_item)

            conf = artifact.get('confidence', 0)
            conf_item = QTableWidgetItem(f"{conf:.0f}%")
            conf_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.artifacts_table.setItem(row, 4, conf_item)

            load_btn = QPushButton("Load")
            load_btn.setStyleSheet(
                "background: #f0a500; color: #0d1117; border: none; border-radius: 3px;"
                "padding: 2px 6px; font-size: 11px; font-weight: 700;"
            )
            val = artifact.get('value', '')
            atype = artifact.get('type', '')
            if atype == 'xprv' or val.startswith(('xprv', 'yprv', 'zprv', 'tprv', 'vprv', 'uprv', 'xpub', 'ypub', 'zpub')):
                load_btn.clicked.connect(lambda _, v=val: self.main_window.load_from_xprv(v))
            else:
                load_btn.clicked.connect(lambda _, v=val: self.main_window.load_mnemonic(v))
            self.artifacts_table.setCellWidget(row, 5, load_btn)


        # Show report
        if report:
            self.report_output.setPlainText(report)
        else:
            self.report_output.setPlainText(f"Deep forensic carving complete.\n\n"
                                             f"Found {len(artifacts)} artifacts.\n\n"
                                             "No additional report data available.")

        self.main_window.status_bar_msg(f"Carving complete: {len(artifacts)} artifacts found.")

    def _missing_solver(self):
        raw_text = self.raw_input.toPlainText().strip()
        if not raw_text:
            self.main_window.status_bar_msg("Paste a partial mnemonic (with blank for missing word) first.")
            return

        self.btn_missing.setText("⏳ Solving...")
        self.btn_missing.setEnabled(False)
        self.artifacts_status.setText("Solving missing word...")

        try:
            from hd_wallet.carving import DeepCarver
            carver = DeepCarver()
            # Try to find missing word in phrase with _ or ? placeholder
            words = raw_text.split()
            placeholder_idx = next((i for i, w in enumerate(words) if w in ('_', '?', '??', 'MISSING')), None)

            if placeholder_idx is None:
                self.artifacts_status.setText("No placeholder found. Use _ or ? for the missing word.")
                self.btn_missing.setText("🔮 1-Word Missing Solver")
                self.btn_missing.setEnabled(True)
                return

            results = carver.solve_missing_word(words, placeholder_idx)
            if results:
                self.report_output.setPlainText(
                    f"Missing Word Solver Results ({len(results)} candidates):\n\n" +
                    "\n".join([f"  {r['word']}: {r['mnemonic']}" for r in results[:20]])
                )
                if results:
                    self.main_window.load_mnemonic(results[0]['mnemonic'])
            else:
                self.report_output.setPlainText("No valid completions found.")
        except Exception as e:
            self.artifacts_status.setText(f"Solver error: {e}")
        finally:
            self.btn_missing.setText("🔮 1-Word Missing Solver")
            self.btn_missing.setEnabled(True)

    def _export_report(self):
        if not self._report_text:
            return
        path, _ = QFileDialog.getSaveFileName(
            self, "Export Forensic Report", "forensic_report.md", "Markdown Files (*.md);;Text Files (*.txt)"
        )
        if path:
            with open(path, 'w') as f:
                f.write(self._report_text)
            self.main_window.status_bar_msg(f"Report exported to {path}")

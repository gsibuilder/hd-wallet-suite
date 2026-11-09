"""
Tab 3: Descriptor Wallets
Bitcoin output descriptors (BIP-380 to BIP-389), interactive inspector,
and address derivation from descriptors.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QGroupBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QApplication, QFileDialog, QAbstractItemView
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont


class DescriptorWalletsTab(QWidget):
    def __init__(self, main_window, parent=None):
        super().__init__(parent)
        self.main_window = main_window
        self.wallet = None
        self.descriptors = {}
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        # ── Descriptor Section ───────────────────────────────────────
        desc_box = QGroupBox("Standard Bitcoin Output Descriptors (BIP-380 to BIP-389)")
        desc_v = QVBoxLayout(desc_box)
        desc_v.setSpacing(8)

        # Fields
        self.fingerprint_field = QLineEdit()
        self.standard_field = QLineEdit()
        self.ext_desc_field = QLineEdit()
        self.int_desc_field = QLineEdit()

        def add_row(label: str, field_attr: str, monospace: bool = True):
            row = QHBoxLayout()
            lbl = QLabel(label)
            lbl.setFixedWidth(210)
            lbl.setStyleSheet("color: #8b949e; font-size: 12px; font-weight: 600;")
            field = getattr(self, field_attr)
            field.setReadOnly(True)
            if monospace:
                field.setStyleSheet(
                    "background: #090c10; border: 1px solid #21262d; color: #e6edf3;"
                    "padding: 4px 8px; font-family: 'Courier New', monospace; font-size: 11px;"
                    "border-radius: 4px;"
                )
            copy_btn = QPushButton("Copy")
            copy_btn.setObjectName("btn_copy")
            copy_btn.setFixedWidth(54)
            copy_btn.setFixedHeight(24)
            copy_btn.clicked.connect(lambda _, f=field: (cb := QApplication.clipboard()) and cb.setText(f.text()))
            row.addWidget(lbl)
            row.addWidget(field, 1)
            row.addWidget(copy_btn)
            desc_v.addLayout(row)

        add_row("Master Key Fingerprint:", "fingerprint_field")
        add_row("Active Standard:", "standard_field")
        add_row("External Receiving Descriptor:", "ext_desc_field")
        add_row("Internal Change Descriptor:", "int_desc_field")

        # Action buttons
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)

        self.btn_derive_all = QPushButton("Derive All 4 Standards")
        self.btn_derive_all.setObjectName("btn_derive_all_desc")
        self.btn_derive_all.clicked.connect(self._derive_all)
        btn_row.addWidget(self.btn_derive_all)

        self.btn_load_xprv = QPushButton("Load Active xprv")
        self.btn_load_xprv.setObjectName("btn_load_active_xprv")
        self.btn_load_xprv.clicked.connect(self._load_active_xprv)
        btn_row.addWidget(self.btn_load_xprv)

        self.btn_copy_json = QPushButton("Copy Core JSON")
        self.btn_copy_json.clicked.connect(self._copy_json)
        btn_row.addWidget(self.btn_copy_json)

        self.btn_copy_cli = QPushButton("Copy CLI Command")
        self.btn_copy_cli.clicked.connect(self._copy_cli)
        btn_row.addWidget(self.btn_copy_cli)

        self.btn_export = QPushButton("Export File")
        self.btn_export.clicked.connect(self._export_file)
        btn_row.addWidget(self.btn_export)

        btn_row.addStretch()
        desc_v.addLayout(btn_row)
        layout.addWidget(desc_box)

        # ── Inspector Section ─────────────────────────────────────────
        insp_box = QGroupBox("Interactive Descriptor Inspector & Address Derivation")
        insp_v = QVBoxLayout(insp_box)
        insp_v.setSpacing(8)

        insp_ctrl = QHBoxLayout()
        self.desc_input = QLineEdit()
        self.desc_input.setPlaceholderText("Paste or enter an output descriptor string here...")
        self.desc_input.setStyleSheet(
            "background: #090c10; border: 1px solid #30363d; color: #e6edf3;"
            "padding: 6px 8px; font-family: 'Courier New', monospace; font-size: 11px;"
            "border-radius: 4px;"
        )
        insp_ctrl.addWidget(self.desc_input, 1)

        self.btn_derive_desc = QPushButton("Derive 50 Addresses")
        self.btn_derive_desc.setObjectName("btn_primary")
        self.btn_derive_desc.clicked.connect(self._derive_from_descriptor)
        insp_ctrl.addWidget(self.btn_derive_desc)
        insp_v.addLayout(insp_ctrl)

        # Table
        self.insp_table = QTableWidget()
        self.insp_table.setColumnCount(6)
        self.insp_table.setHorizontalHeaderLabels([
            "#", "Scheme / Standard", "Branch & Index", "Derived Address", "Public Key", "Private Key (WIF)"
        ])
        hh = self.insp_table.horizontalHeader()
        if hh is not None:
            hh.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
            hh.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
            hh.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
            hh.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        self.insp_table.setColumnWidth(0, 40)
        self.insp_table.setColumnWidth(2, 100)
        self.insp_table.setAlternatingRowColors(True)
        vh = self.insp_table.verticalHeader()
        if vh is not None:
            vh.setVisible(False)
        insp_v.addWidget(self.insp_table)
        layout.addWidget(insp_box)

    def set_wallet(self, wallet):
        self.wallet = wallet
        # Auto-derive descriptors when wallet loads
        self._derive_all()

    def _derive_all(self):
        if not self.wallet:
            return
        try:
            from hd_wallet.descriptors import generate_wallet_descriptors
            xprv = self.wallet.master_xprv
            if not xprv:
                return
            descs = generate_wallet_descriptors(xprv)
            self.descriptors = descs

            # Master fingerprint
            fp = descs.get('master_fingerprint', '')
            self.fingerprint_field.setText(fp)

            # Active standard (BIP-84 by default)
            self.standard_field.setText(descs.get('active_standard', 'Native SegWit (P2WPKH / BIP-84)'))

            # External receiving
            ext = descs.get('bip84_external', descs.get('external', ''))
            self.ext_desc_field.setText(ext)
            self.desc_input.setText(ext)

            # Internal change
            intl = descs.get('bip84_internal', descs.get('internal', ''))
            self.int_desc_field.setText(intl)

            self.main_window.status_bar_msg("Descriptors generated.")
        except Exception as e:
            self.main_window.status_bar_msg(f"Descriptor error: {e}")

    def _load_active_xprv(self):
        xprv = self.wallet.master_xprv if self.wallet else ''
        if xprv:
            self.main_window.load_from_xprv(xprv)

    def _copy_json(self):
        if not self.descriptors:
            return
        import json
        ext = self.descriptors.get('bip84_external', '')
        intl = self.descriptors.get('bip84_internal', '')
        obj = [{"desc": ext, "active": True, "internal": False, "range": [0, 999], "timestamp": "now"},
               {"desc": intl, "active": True, "internal": True, "range": [0, 999], "timestamp": "now"}]
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(json.dumps(obj, indent=2))
        self.main_window.status_bar_msg("Bitcoin Core JSON copied.")

    def _copy_cli(self):
        if not self.descriptors:
            return
        ext = self.descriptors.get('bip84_external', '')
        intl = self.descriptors.get('bip84_internal', '')
        cmd = (f'bitcoin-cli importdescriptors '
               f'\'[{{"desc":"{ext}","active":true,"internal":false,"range":[0,999],"timestamp":"now"}},'
               f'{{"desc":"{intl}","active":true,"internal":true,"range":[0,999],"timestamp":"now"}}]\'')
        cb = QApplication.clipboard()
        if cb is not None:
            cb.setText(cmd)
        self.main_window.status_bar_msg("CLI command copied.")

    def _export_file(self):
        if not self.descriptors:
            return
        path, _ = QFileDialog.getSaveFileName(self, "Export Descriptors", "wallet_descriptors.txt", "Text Files (*.txt)")
        if not path:
            return
        try:
            with open(path, 'w') as f:
                for k, v in self.descriptors.items():
                    f.write(f"{k}: {v}\n")
            self.main_window.status_bar_msg(f"Exported to {path}")
        except Exception as e:
            self.main_window.status_bar_msg(f"Export error: {e}")

    def _derive_from_descriptor(self):
        desc = self.desc_input.text().strip()
        if not desc or not self.wallet:
            return

        self.btn_derive_desc.setText("⏳ Deriving...")
        self.btn_derive_desc.setEnabled(False)

        try:
            from hd_wallet.descriptors import derive_from_descriptor
            res = derive_from_descriptor(desc, count=50)
            addrs = res.get('addresses', []) if isinstance(res, dict) else (res if isinstance(res, list) else [])
            self._fill_inspector_table(addrs)
            self.main_window.status_bar_msg(f"Derived {len(addrs)} addresses from descriptor.")
        except Exception as e:
            self.main_window.status_bar_msg(f"Descriptor derivation error: {e}")
        finally:
            self.btn_derive_desc.setText("⚡ Derive 50 Addresses")
            self.btn_derive_desc.setEnabled(True)

    def _fill_inspector_table(self, results: list):
        self.insp_table.setRowCount(0)
        for i, item in enumerate(results):
            row_num = self.insp_table.rowCount()
            self.insp_table.insertRow(row_num)

            num_item = QTableWidgetItem(str(i + 1))
            num_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            num_item.setForeground(QColor("#f0a500"))
            num_item.setFont(QFont("", -1, QFont.Weight.Bold))
            self.insp_table.setItem(row_num, 0, num_item)

            scheme = item.get('scheme', 'Native SegWit (P2WPKH / BIP-84) (Receiving /0)')
            self.insp_table.setItem(row_num, 1, QTableWidgetItem(scheme))

            branch = f"{item.get('change', 0)}/{item.get('index', i)}"
            bi = QTableWidgetItem(branch)
            bi.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.insp_table.setItem(row_num, 2, bi)

            addr = item.get('address', '')
            addr_item = QTableWidgetItem(addr)
            addr_item.setForeground(QColor("#58a6ff"))
            self.insp_table.setItem(row_num, 3, addr_item)

            pub = item.get('public_key', '')
            self.insp_table.setItem(row_num, 4, QTableWidgetItem(pub[:20] + '...' if len(pub) > 20 else pub))

            wif = item.get('private_key_wif', '')
            wif_item = QTableWidgetItem(wif)
            wif_item.setForeground(QColor("#3fb950"))
            self.insp_table.setItem(row_num, 5, wif_item)

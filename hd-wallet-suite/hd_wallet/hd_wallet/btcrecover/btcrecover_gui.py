#!/usr/bin/env python
"""Simple PyQt5 GUI for BTCRecover.

This script provides a basic graphical interface to run the BTCRecover
command-line tool. Users can select a wallet file and a password list (or
dictionary) and then start the recovery process. The output from the
underlying BTCRecover process is displayed in a scrolling text area.

The GUI is intentionally minimal to avoid pulling in heavy dependencies
beyond PyQt5, which is available on most platforms via pip.
"""

import sys
import subprocess
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QLabel,
    QLineEdit,
    QPushButton,
    QTextEdit,
    QFileDialog,
    QVBoxLayout,
    QHBoxLayout,
    QMessageBox,
    QCheckBox,
    QPlainTextEdit,
    QSpinBox,
    QScrollArea,
)

class BTCRecoverGUI(QWidget):
    """Main window for the BTCRecover GUI."""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("BTCRecover GUI")
        self._setup_ui()

    def _setup_ui(self) -> None:
        # File selectors
        wallet_label = QLabel("Wallet file:")
        self.wallet_edit = QLineEdit()
        wallet_btn = QPushButton("Browse")
        wallet_btn.clicked.connect(self._browse_wallet)
        wallet_layout = QHBoxLayout()
        wallet_layout.addWidget(wallet_label)
        wallet_layout.addWidget(self.wallet_edit)
        wallet_layout.addWidget(wallet_btn)

        pass_label = QLabel("Password list:")
        self.pass_edit = QLineEdit()
        pass_btn = QPushButton("Browse")
        pass_btn.clicked.connect(self._browse_passlist)
        pass_layout = QHBoxLayout()
        pass_layout.addWidget(pass_label)
        pass_layout.addWidget(self.pass_edit)
        pass_layout.addWidget(pass_btn)

        token_label = QLabel("Token list:")
        self.token_edit = QLineEdit()
        token_btn = QPushButton("Browse")
        token_btn.clicked.connect(self._browse_tokenlist)
        token_layout = QHBoxLayout()
        token_layout.addWidget(token_label)
        token_layout.addWidget(self.token_edit)
        token_layout.addWidget(token_btn)

        # Options area (scrollable)
        options_widget = QWidget()
        options_layout = QVBoxLayout()
        options_widget.setLayout(options_layout)
        self._add_option_widgets(options_layout)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setWidget(options_widget)

        # Run button and output
        self.run_btn = QPushButton("Run BTCRecover")
        self.run_btn.clicked.connect(self._run_btcrecover)
        self.output_area = QTextEdit()
        self.output_area.setReadOnly(True)

        # Assemble main layout
        main_layout = QVBoxLayout()
        main_layout.addLayout(wallet_layout)
        main_layout.addLayout(pass_layout)
        main_layout.addLayout(token_layout)
        main_layout.addWidget(scroll)
        main_layout.addWidget(self.run_btn)
        main_layout.addWidget(self.output_area)
        self.setLayout(main_layout)
        
    def _add_option_widgets(self, layout):
        """Create widgets for BTCRecover options and store them as attributes."""
        # Boolean flags
        self.utf8_check = QCheckBox("--utf8")
        layout.addWidget(self.utf8_check)
        self.no_eta_check = QCheckBox("--no-eta")
        layout.addWidget(self.no_eta_check)
        self.no_progress_check = QCheckBox("--no-progress")
        layout.addWidget(self.no_progress_check)
        self.disable_save_possible_check = QCheckBox("--disable-save-possible-passwords")
        layout.addWidget(self.disable_save_possible_check)
        self.listpass_check = QCheckBox("--listpass")
        layout.addWidget(self.listpass_check)
        self.performance_check = QCheckBox("--performance")
        layout.addWidget(self.performance_check)
        self.pause_check = QCheckBox("--pause")
        layout.addWidget(self.pause_check)
        self.android_pin_check = QCheckBox("--android-pin")
        layout.addWidget(self.android_pin_check)
        self.blockchain_secondpass_check = QCheckBox("--blockchain-secondpass")
        layout.addWidget(self.blockchain_secondpass_check)
        self.data_extract_check = QCheckBox("--data-extract")
        layout.addWidget(self.data_extract_check)
        self.no_dupchecks_check = QCheckBox("--no-dupchecks")
        layout.addWidget(self.no_dupchecks_check)

        # Integer flags (QSpinBox)
        self.typos_spin = QSpinBox()
        self.typos_spin.setRange(0, 1000)
        self.typos_spin.setPrefix("--typos: ")
        layout.addWidget(self.typos_spin)
        self.min_typos_spin = QSpinBox()
        self.min_typos_spin.setRange(0, 1000)
        self.min_typos_spin.setPrefix("--min-typos: ")
        layout.addWidget(self.min_typos_spin)
        self.max_typos_spin = QSpinBox()
        self.max_typos_spin.setRange(0, 1000)
        self.max_typos_spin.setPrefix("--max-typos: ")
        layout.addWidget(self.max_typos_spin)
        self.max_password_repeats_spin = QSpinBox()
        self.max_password_repeats_spin.setRange(1, 100)
        self.max_password_repeats_spin.setPrefix("--max-password-repeats: ")
        layout.addWidget(self.max_password_repeats_spin)
        self.length_min_spin = QSpinBox()
        self.length_min_spin.setRange(0, 999999)
        self.length_min_spin.setPrefix("--length-min: ")
        layout.addWidget(self.length_min_spin)
        self.length_max_spin = QSpinBox()
        self.length_max_spin.setRange(0, 999999)
        self.length_max_spin.setPrefix("--length-max: ")
        layout.addWidget(self.length_max_spin)
        self.threads_spin = QSpinBox()
        self.threads_spin.setRange(1, 64)
        self.threads_spin.setPrefix("--threads: ")
        layout.addWidget(self.threads_spin)
        self.max_eta_spin = QSpinBox()
        self.max_eta_spin.setRange(1, 10000)
        self.max_eta_spin.setPrefix("--max-eta (hours): ")
        layout.addWidget(self.max_eta_spin)
        self.performance_duration_spin = QSpinBox()
        self.performance_duration_spin.setRange(0, 86400)
        self.performance_duration_spin.setPrefix("--performance-duration (s): ")
        layout.addWidget(self.performance_duration_spin)

        # String options (QLineEdit)
        self.regex_only_edit = QLineEdit()
        self.regex_only_edit.setPlaceholderText("--regex-only")
        layout.addWidget(self.regex_only_edit)
        self.regex_never_edit = QLineEdit()
        self.regex_never_edit.setPlaceholderText("--regex-never")
        layout.addWidget(self.regex_never_edit)
        self.delimiter_edit = QLineEdit()
        self.delimiter_edit.setPlaceholderText("--delimiter")
        layout.addWidget(self.delimiter_edit)
        self.worker_edit = QLineEdit()
        self.worker_edit.setPlaceholderText("--worker")
        layout.addWidget(self.worker_edit)
        self.possible_passwords_file_edit = QLineEdit()
        self.possible_passwords_file_edit.setPlaceholderText("--possible-passwords-file")
        layout.addWidget(self.possible_passwords_file_edit)
        self.blockchain_correct_mainpass_edit = QLineEdit()
        self.blockchain_correct_mainpass_edit.setPlaceholderText("--blockchain-correct-mainpass")
        layout.addWidget(self.blockchain_correct_mainpass_edit)
        self.msigna_keychain_edit = QLineEdit()
        self.msigna_keychain_edit.setPlaceholderText("--msigna-keychain")
        layout.addWidget(self.msigna_keychain_edit)
        self.data_extract_string_edit = QLineEdit()
        self.data_extract_string_edit.setPlaceholderText("--data-extract-string")
        layout.addWidget(self.data_extract_string_edit)
        self.custom_wild_edit = QLineEdit()
        self.custom_wild_edit.setPlaceholderText("--custom-wild")
        layout.addWidget(self.custom_wild_edit)

    def _browse_wallet(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select wallet file")
        if path:
            self.wallet_edit.setText(path)

    def _browse_passlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select password list")
        if path:
            self.pass_edit.setText(path)

    def _browse_tokenlist(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select token list")
        if path:
            self.token_edit.setText(path)

    def _run_btcrecover(self) -> None:
        wallet_path = self.wallet_edit.text().strip()
        passlist_path = self.pass_edit.text().strip()
        tokenlist_path = self.token_edit.text().strip()

        if not wallet_path or not Path(wallet_path).is_file():
            QMessageBox.warning(self, "Input error", "Please select a valid wallet file.")
            return
        if not passlist_path or not Path(passlist_path).is_file():
            QMessageBox.warning(self, "Input error", "Please select a valid password list file.")
            return

        script_path = Path(__file__).parent / "btcrecover.py"
        cmd = [sys.executable, str(script_path), "--wallet", wallet_path, "--passlist", passlist_path]

        # optional tokenlist
        if tokenlist_path:
            cmd.extend(["--tokenlist", tokenlist_path])

        # Boolean flags
        if self.utf8_check.isChecked():
            cmd.append("--utf8")
        if self.no_eta_check.isChecked():
            cmd.append("--no-eta")
        if self.no_progress_check.isChecked():
            cmd.append("--no-progress")
        if self.disable_save_possible_check.isChecked():
            cmd.append("--disable-save-possible-passwords")
        if self.listpass_check.isChecked():
            cmd.append("--listpass")
        if self.performance_check.isChecked():
            cmd.append("--performance")
        if self.pause_check.isChecked():
            cmd.append("--pause")
        if self.android_pin_check.isChecked():
            cmd.append("--android-pin")
        if self.blockchain_secondpass_check.isChecked():
            cmd.append("--blockchain-secondpass")
        if self.data_extract_check.isChecked():
            cmd.append("--data-extract")
        if self.no_dupchecks_check.isChecked():
            cmd.append("--no-dupchecks")

        # Integer flags (add if non-zero)
        if self.typos_spin.value():
            cmd.extend(["--typos", str(self.typos_spin.value())])
        if self.min_typos_spin.value():
            cmd.extend(["--min-typos", str(self.min_typos_spin.value())])
        if self.max_typos_spin.value():
            cmd.extend(["--max-typos", str(self.max_typos_spin.value())])
        if self.max_password_repeats_spin.value():
            cmd.extend(["--max-password-repeats", str(self.max_password_repeats_spin.value())])
        if self.length_min_spin.value():
            cmd.extend(["--length-min", str(self.length_min_spin.value())])
        if self.length_max_spin.value():
            cmd.extend(["--length-max", str(self.length_max_spin.value())])
        if self.threads_spin.value():
            cmd.extend(["--threads", str(self.threads_spin.value())])
        if self.max_eta_spin.value():
            cmd.extend(["--max-eta", str(self.max_eta_spin.value())])
        if self.performance_duration_spin.value():
            cmd.extend(["--performance-duration", str(self.performance_duration_spin.value())])

        # String options (add if not empty)
        if self.regex_only_edit.text():
            cmd.extend(["--regex-only", self.regex_only_edit.text().strip()])
        if self.regex_never_edit.text():
            cmd.extend(["--regex-never", self.regex_never_edit.text().strip()])
        if self.delimiter_edit.text():
            cmd.extend(["--delimiter", self.delimiter_edit.text().strip()])
        if self.worker_edit.text():
            cmd.extend(["--worker", self.worker_edit.text().strip()])
        if self.possible_passwords_file_edit.text():
            cmd.extend(["--possible-passwords-file", self.possible_passwords_file_edit.text().strip()])
        if self.blockchain_correct_mainpass_edit.text():
            cmd.extend(["--blockchain-correct-mainpass", self.blockchain_correct_mainpass_edit.text().strip()])
        if self.msigna_keychain_edit.text():
            cmd.extend(["--msigna-keychain", self.msigna_keychain_edit.text().strip()])
        if self.data_extract_string_edit.text():
            cmd.extend(["--data-extract-string", self.data_extract_string_edit.text().strip()])
        if self.custom_wild_edit.text():
            cmd.extend(["--custom-wild", self.custom_wild_edit.text().strip()])

        self.output_area.append("Running: " + " ".join(cmd))
        self.run_btn.setEnabled(False)
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in process.stdout:
                self.output_area.append(line.rstrip())
            process.wait()
            if process.returncode == 0:
                self.output_area.append("\n[Finished] BTCRecover completed successfully.")
            else:
                self.output_area.append(f"\n[Error] BTCRecover exited with code {process.returncode}.")
        except Exception as exc:
            QMessageBox.critical(self, "Execution error", str(exc))
        finally:
            self.run_btn.setEnabled(True)


def main() -> None:
    app = QApplication(sys.argv)
    gui = BTCRecoverGUI()
    gui.resize(800, 600)
    gui.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()

"""
Global QSS Modern Dark Stylesheet for HD Wallet Suite.
Clean, refined, consistent dark UI (#0d1117 base, #161b22 surface, #30363d subtle borders).
"""

MAIN_STYLESHEET = """
/* ═══════════════════════════════════════════════════════════
   HD Wallet Suite — Clean Modern Dark QSS
   Base: #0d1117  Surface: #161b22  Elevated: #21262d
   Border: #30363d  Accent: #f0a500  Blue: #58a6ff  Green: #3fb950
   Text: #e6edf3  Muted: #8b949e
   ═══════════════════════════════════════════════════════════ */

QMainWindow, QWidget {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: 'Segoe UI', 'Inter', 'Ubuntu', 'DejaVu Sans', sans-serif;
    font-size: 12px;
}

/* ─── Tab Widget ─────────────────────────────────────────── */
QTabWidget::pane {
    border: 1px solid #21262d;
    background-color: #0d1117;
    border-top: 1px solid #30363d;
}

QTabBar {
    background-color: #090c10;
}

QTabBar::tab {
    background-color: transparent;
    color: #8b949e;
    padding: 8px 14px;
    border: none;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
    font-size: 12px;
    font-weight: 600;
}

QTabBar::tab:selected {
    background-color: #161b22;
    color: #f0a500;
    font-weight: 700;
    border-bottom: 2px solid #f0a500;
}

QTabBar::tab:hover:!selected {
    background-color: #12161c;
    color: #e6edf3;
}

QTabBar::scroller {
    width: 24px;
}

QTabBar QToolButton {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 3px;
    margin: 2px;
    color: #e6edf3;
}

QTabBar QToolButton:hover {
    background-color: #21262d;
    border-color: #f0a500;
}

/* ─── Group Boxes / Cards ────────────────────────────────── */
QGroupBox {
    border: 1px solid #21262d;
    border-radius: 6px;
    margin-top: 12px;
    padding: 12px 10px 10px 10px;
    background-color: #161b22;
    color: #e6edf3;
    font-weight: 600;
    font-size: 12px;
}

QGroupBox::title {
    subcontrol-origin: margin;
    left: 12px;
    padding: 0 6px;
    color: #f0a500;
    font-weight: 700;
    font-size: 12px;
}

/* ─── Input Fields ───────────────────────────────────────── */
QLineEdit, QTextEdit, QPlainTextEdit {
    background-color: #090c10;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #e6edf3;
    padding: 5px 8px;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
    font-size: 12px;
}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus {
    border-color: #58a6ff;
}

QLineEdit[readOnly="true"] {
    background-color: #0d1117;
    border-color: #21262d;
    color: #c9d1d9;
}

/* ─── ComboBox / Dropdowns ───────────────────────────────── */
QComboBox {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #e6edf3;
    padding: 4px 10px;
    min-height: 26px;
    font-weight: 500;
}

QComboBox:hover {
    border-color: #58a6ff;
}

QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 4px solid transparent;
    border-right: 4px solid transparent;
    border-top: 5px solid #8b949e;
    margin-right: 6px;
}

QComboBox QAbstractItemView {
    background-color: #161b22;
    border: 1px solid #30363d;
    color: #e6edf3;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
    padding: 4px;
}

/* ─── Spin Box ───────────────────────────────────────────── */
QSpinBox, QDoubleSpinBox {
    background-color: #090c10;
    border: 1px solid #30363d;
    border-radius: 4px;
    color: #e6edf3;
    padding: 4px 6px;
    min-height: 24px;
}

QSpinBox:focus, QDoubleSpinBox:focus {
    border-color: #58a6ff;
}

QSpinBox::up-button, QSpinBox::down-button,
QDoubleSpinBox::up-button, QDoubleSpinBox::down-button {
    background-color: #161b22;
    border: none;
    width: 16px;
}

QSpinBox::up-button:hover, QSpinBox::down-button:hover {
    background-color: #21262d;
}

QSpinBox::up-arrow, QDoubleSpinBox::up-arrow {
    image: none;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-bottom: 4px solid #8b949e;
    width: 0;
    height: 0;
}

QSpinBox::down-arrow, QDoubleSpinBox::down-arrow {
    image: none;
    border-left: 3px solid transparent;
    border-right: 3px solid transparent;
    border-top: 4px solid #8b949e;
    width: 0;
    height: 0;
}

/* ─── Buttons ────────────────────────────────────────────── */
QPushButton {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    border-radius: 4px;
    padding: 5px 12px;
    font-weight: 600;
    font-size: 12px;
    min-height: 26px;
}

QPushButton:hover {
    background-color: #30363d;
    border-color: #8b949e;
}

QPushButton:pressed {
    background-color: #161b22;
}

QPushButton:disabled {
    background-color: #161b22;
    color: #484f58;
    border-color: #21262d;
}

/* Primary Accent Buttons (Amber/Gold) */
QPushButton#btn_primary, QPushButton#btn_derive, QPushButton#btn_generate_batch,
QPushButton#btn_random_page, QPushButton#btn_query_live, QPushButton#btn_check_all,
QPushButton#btn_derive_all_desc, QPushButton#btn_locate, QPushButton#btn_rescan_db,
QPushButton#btn_query_all_chains {
    background-color: #d99000;
    color: #090c10;
    border: 1px solid #f0a500;
    font-weight: 700;
}

QPushButton#btn_primary:hover, QPushButton#btn_derive:hover,
QPushButton#btn_generate_batch:hover, QPushButton#btn_random_page:hover,
QPushButton#btn_query_live:hover, QPushButton#btn_check_all:hover,
QPushButton#btn_derive_all_desc:hover, QPushButton#btn_locate:hover,
QPushButton#btn_rescan_db:hover, QPushButton#btn_query_all_chains:hover {
    background-color: #f0a500;
}

/* Subtle Green Action Buttons */
QPushButton#btn_import_wallet, QPushButton#btn_test_connection,
QPushButton#btn_start_btcrecover, QPushButton#btn_start_carve,
QPushButton#btn_build_psbt {
    background-color: #238636;
    color: #ffffff;
    border: 1px solid #2ea043;
    font-weight: 600;
}

QPushButton#btn_import_wallet:hover, QPushButton#btn_test_connection:hover,
QPushButton#btn_start_btcrecover:hover, QPushButton#btn_start_carve:hover,
QPushButton#btn_build_psbt:hover {
    background-color: #2ea043;
}

/* Subtle Blue Action Buttons */
QPushButton#btn_load_xprv, QPushButton#btn_load_psbt, QPushButton#btn_load_wallet_db,
QPushButton#btn_load_active_xprv, QPushButton#btn_browse_psbt, QPushButton#btn_browse_wallet {
    background-color: #1f6feb;
    color: #ffffff;
    border: 1px solid #388bfd;
    font-weight: 600;
}

QPushButton#btn_load_xprv:hover, QPushButton#btn_load_psbt:hover,
QPushButton#btn_load_wallet_db:hover, QPushButton#btn_load_active_xprv:hover,
QPushButton#btn_browse_psbt:hover, QPushButton#btn_browse_wallet:hover {
    background-color: #388bfd;
}

/* Danger / Sweep Buttons */
QPushButton#btn_sweep, QPushButton#btn_stop_btcrecover, QPushButton#btn_lock_app {
    background-color: #da3633;
    color: #ffffff;
    border: 1px solid #f85149;
    font-weight: 700;
}

QPushButton#btn_sweep:hover, QPushButton#btn_stop_btcrecover:hover {
    background-color: #f85149;
}

/* Secondary Operation Buttons */
QPushButton#btn_sign_psbt, QPushButton#btn_missing_solver,
QPushButton#btn_finalize_psbt, QPushButton#btn_broadcast_psbt,
QPushButton#btn_export_markdown, QPushButton#btn_export_csv,
QPushButton#btn_export_all_chains_csv, QPushButton#btn_12words, QPushButton#btn_24words,
QPushButton#btn_next_page, QPushButton#btn_prev_page, QPushButton#btn_first_page {
    background-color: #21262d;
    color: #e6edf3;
    border: 1px solid #30363d;
    font-weight: 600;
}

QPushButton#btn_sign_psbt:hover, QPushButton#btn_missing_solver:hover,
QPushButton#btn_finalize_psbt:hover, QPushButton#btn_broadcast_psbt:hover,
QPushButton#btn_export_markdown:hover, QPushButton#btn_export_csv:hover,
QPushButton#btn_export_all_chains_csv:hover, QPushButton#btn_12words:hover,
QPushButton#btn_24words:hover, QPushButton#btn_next_page:hover,
QPushButton#btn_prev_page:hover, QPushButton#btn_first_page:hover {
    background-color: #30363d;
    border-color: #58a6ff;
}

/* Compact Copy & Check Buttons */
QPushButton#btn_copy {
    background-color: #161b22;
    color: #8b949e;
    border: 1px solid #30363d;
    border-radius: 3px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 600;
    min-height: 22px;
    min-width: 48px;
}

QPushButton#btn_copy:hover {
    background-color: #21262d;
    border-color: #58a6ff;
    color: #e6edf3;
}

QPushButton#btn_check_balance {
    background-color: #161b22;
    color: #58a6ff;
    border: 1px solid #30363d;
    border-radius: 3px;
    padding: 2px 8px;
    font-size: 11px;
    font-weight: 600;
    min-height: 22px;
}

QPushButton#btn_check_balance:hover {
    background-color: #1f6feb;
    color: #ffffff;
    border-color: #388bfd;
}

/* ─── Tables ─────────────────────────────────────────────── */
QTableWidget, QTableView {
    background-color: #0d1117;
    alternate-background-color: #12161e;
    gridline-color: #21262d;
    border: 1px solid #21262d;
    border-radius: 4px;
    color: #e6edf3;
    font-size: 12px;
    selection-background-color: #1f6feb;
    selection-color: #ffffff;
}

QTableWidget::item {
    padding: 4px 8px;
    border-bottom: 1px solid #161b22;
    color: #e6edf3;
}

QTableWidget::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
}

QHeaderView {
    background-color: #161b22;
    border: none;
}

QHeaderView::section {
    background-color: #161b22;
    color: #8b949e;
    padding: 6px 8px;
    border: none;
    border-right: 1px solid #21262d;
    border-bottom: 1px solid #30363d;
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
}

QTableWidget QTableCornerButton::section {
    background-color: #161b22;
    border: 1px solid #21262d;
}

/* ─── Scroll Bars ────────────────────────────────────────── */
QScrollBar:vertical {
    background-color: #0d1117;
    width: 8px;
    margin: 0;
}

QScrollBar::handle:vertical {
    background-color: #30363d;
    border-radius: 4px;
    min-height: 24px;
}

QScrollBar::handle:vertical:hover {
    background-color: #484f58;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background-color: #0d1117;
    height: 8px;
    margin: 0;
}

QScrollBar::handle:horizontal {
    background-color: #30363d;
    border-radius: 4px;
    min-width: 24px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #484f58;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* ─── Labels ─────────────────────────────────────────────── */
QLabel {
    color: #c9d1d9;
    font-size: 12px;
    background: transparent;
}

/* ─── Status Bar & Toolbar ───────────────────────────────── */
QStatusBar {
    background-color: #090c10;
    color: #8b949e;
    border-top: 1px solid #21262d;
    font-size: 11px;
    padding: 2px 8px;
}

QStatusBar QLabel {
    color: #8b949e;
    font-size: 11px;
}

QFrame#toolbar_frame {
    background-color: #090c10;
    border-bottom: 1px solid #21262d;
}

/* ─── Splitter ───────────────────────────────────────────── */
QSplitter::handle {
    background-color: #21262d;
    width: 2px;
    height: 2px;
}

QSplitter::handle:hover {
    background-color: #58a6ff;
}

/* ─── Scroll Area ────────────────────────────────────────── */
QScrollArea, QAbstractScrollArea {
    background-color: #0d1117;
    border: none;
}

/* ─── Menus & Dialogs ────────────────────────────────────── */
QMenu {
    background-color: #161b22;
    border: 1px solid #30363d;
    border-radius: 6px;
    padding: 4px;
    color: #e6edf3;
}

QMenu::item {
    padding: 6px 20px 6px 12px;
    border-radius: 4px;
    color: #e6edf3;
    font-size: 12px;
}

QMenu::item:selected {
    background-color: #1f6feb;
    color: #ffffff;
}

QDialog, QInputDialog, QMessageBox, QFileDialog {
    background-color: #0d1117;
    color: #e6edf3;
}

QToolTip {
    background-color: #161b22;
    border: 1px solid #30363d;
    color: #e6edf3;
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 11px;
}
"""

STATUS_VALID_STYLE = "color: #3fb950; font-weight: 700;"
STATUS_INVALID_STYLE = "color: #f85149; font-weight: 700;"
STATUS_PENDING_STYLE = "color: #f0a500; font-weight: 700;"

MONO_STYLE = "font-family: 'Courier New', 'Consolas', monospace; font-size: 11px; color: #e6edf3;"
MONO_BLUE_STYLE = "font-family: 'Courier New', 'Consolas', monospace; font-size: 12px; color: #58a6ff; font-weight: 600;"
MONO_GREEN_STYLE = "font-family: 'Courier New', 'Consolas', monospace; font-size: 11px; color: #3fb950; font-weight: 700;"
MONO_ORANGE_STYLE = "font-family: 'Courier New', 'Consolas', monospace; font-size: 12px; color: #f0a500; font-weight: 700;"

ORANGE_LABEL_STYLE = "color: #f0a500; font-weight: 700; font-size: 12px;"
SECTION_TITLE_STYLE = "color: #f0a500; font-weight: 700; font-size: 12px;"

BALANCE_ZERO_STYLE = "font-family: 'Courier New', monospace; color: #8b949e; font-size: 11px;"
BALANCE_NONZERO_STYLE = "font-family: 'Courier New', monospace; color: #3fb950; font-weight: 700; font-size: 11px;"


def apply_dark_theme(app) -> None:
    """Apply a unified clean dark palette, Fusion style, and stylesheet to QApplication."""
    from PyQt6.QtWidgets import QStyleFactory
    from PyQt6.QtGui import QPalette, QColor

    fusion = QStyleFactory.create("Fusion")
    if fusion:
        app.setStyle(fusion)

    dark_palette = QPalette()
    dark_palette.setColor(QPalette.ColorRole.Window, QColor("#0d1117"))
    dark_palette.setColor(QPalette.ColorRole.WindowText, QColor("#e6edf3"))
    dark_palette.setColor(QPalette.ColorRole.Base, QColor("#090c10"))
    dark_palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#12161e"))
    dark_palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#161b22"))
    dark_palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#e6edf3"))
    dark_palette.setColor(QPalette.ColorRole.Text, QColor("#e6edf3"))
    dark_palette.setColor(QPalette.ColorRole.Button, QColor("#21262d"))
    dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor("#e6edf3"))
    dark_palette.setColor(QPalette.ColorRole.BrightText, QColor("#f0a500"))
    dark_palette.setColor(QPalette.ColorRole.Link, QColor("#58a6ff"))
    dark_palette.setColor(QPalette.ColorRole.Highlight, QColor("#1f6feb"))
    dark_palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    dark_palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#8b949e"))

    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.WindowText, QColor("#484f58"))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, QColor("#484f58"))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, QColor("#484f58"))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Highlight, QColor("#161b22"))
    dark_palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.HighlightedText, QColor("#484f58"))

    app.setPalette(dark_palette)
    app.setStyleSheet(MAIN_STYLESHEET)

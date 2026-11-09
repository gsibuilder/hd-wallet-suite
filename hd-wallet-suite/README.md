# ⚡ HD Wallet Cryptographic Engine & Multichain Suite (v2.0)

[![Version](https://img.shields.io/badge/version-2.0--5-orange.svg)](#)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](#)
[![GUI](https://img.shields.io/badge/GUI-PyQt6-41cd52.svg)](#)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Debian%20%7C%20Kali%20%7C%20Web-blueviolet.svg)](#)
[![Standards](https://img.shields.io/badge/BIP-32%20%7C%2039%20%7C%2044%20%7C%2049%20%7C%2084%20%7C%2086%20%7C%20174%20%7C%20380-success.svg)](#)

> 🌐 **Run Online in Your Browser (GitHub Pages Web Edition)**:
> **[https://gsibuilder.github.io/hd-wallet-suite/](https://gsibuilder.github.io/hd-wallet-suite/)**
> *(100% client-side execution — all cryptographic key derivations, BIP-39 seeds, 50+ multichain addresses, BIP-380 descriptors, $2^{256}$ key space navigation, and forensic carving run locally in your browser with zero external dependencies.)*

**HD Wallet Cryptographic Engine & Multichain Suite** is a comprehensive desktop cryptographic workbench, hierarchical deterministic (HD) wallet derivation engine, multichain portfolio inspector, and digital forensics/recovery toolkit built with Python and PyQt6.

Designed for security researchers, blockchain engineers, and digital asset recovery specialists, it unifies **50+ blockchain networks**, **C-accelerated secp256k1 & Ed25519 derivation**, **Bitcoin output descriptors**, **PSBT workflows**, **Berkeley DB / SQLite wallet parsing**, **PyWallet & BTCRecover engines**, and **binary forensic carving** into a single dark-themed interface.

---

## 📋 Table of Contents

1. [Key Features & Modules](#-key-features--modules)
2. [Supported Cryptographic Standards & Networks](#-supported-cryptographic-standards--networks)
3. [Project Architecture](#-project-architecture)
4. [Well-Documented Instructions](#-well-documented-instructions)
   - [1. System Requirements & Dependencies](#1-system-requirements--dependencies)
   - [2. Running from Source](#2-running-from-source)
   - [3. Building & Installing the Debian (.deb) Package](#3-building--installing-the-debian-deb-package)
   - [4. Complete User Guide (Tab-by-Tab Walkthrough)](#4-complete-user-guide-tab-by-tab-walkthrough)
   - [5. Python SDK / Programmatic API Usage](#5-python-sdk--programmatic-api-usage)
5. [Security & Operational Best Practices](#-security--operational-best-practices)
6. [Sources, Credits & Acknowledgments](#-sources-credits--acknowledgments)
7. [Legal Disclaimer & Limitation of Liability](#-legal-disclaimer--limitation-of-liability)

---

## 🚀 Key Features & Modules

* **🔑 Universal Key & Seed Inspector**: Derive keys from 12/15/18/21/24-word BIP-39 mnemonics (with optional passphrase), raw 64-character hexadecimal seeds/keys, WIF private keys, or extended keys (`xprv`/`xpub`, `yprv`/`ypub`, `zprv`/`zpub`, `tprv`/`tpub`).
* **⚡ C-Accelerated Cryptography**: Automatically leverages `libsecp256k1` (via `coincurve`) and Blockstream `libwally-core` (via `wallycore`) when available, with a seamless pure-Python `ecdsa` fallback.
* **🌐 50+ Multichain Directory & Custom RPC**: Simultaneously derive and query live balances across 50+ L1/L2 blockchains with support for custom JSON-RPC nodes and HTTP Basic Authentication.
* **🔒 Hardened Wallet Import Dialog**: Zero-log memory import with masked input, strict SECP256k1 curve-order validation, checksum verification, SHA-256 file integrity checks, and clipboard sanitization.
* **📜 Bitcoin Output Descriptors (BIP-380–389)**: Generate, verify, and parse `wpkh`, `tr`, `sh(wpkh)`, and `pkh` descriptors with native polymod checksum calculation and SQLite descriptor wallet inspection.
* **🌌 256-Bit Key Space Explorer**: Navigate the entire $2^{256}$ `secp256k1` private key space (`1` to `N-1`) in 128-key pages (inspired by *PrivateKeyFinder.io*), complete with reverse key lookup, 0-indexed BIP-39 mnemonic mapping, and live multichain balance checking.
* **🛠️ Wallet DB Inspector, PyWallet & BTCRecover**: Parse legacy Berkeley DB (`wallet.dat`), modern SQLite descriptor wallets, Ethereum Web3 V3 Keystores (PBKDF2/scrypt + AES-128-CTR), and Electrum JSON wallets. Includes integrated **PyWallet 2.3** key salvage and **BTCRecover** password recovery workers.
* **📝 PSBT Toolkit (BIP-174)**: Create, decode, inspect, sign, and broadcast Partially Signed Bitcoin Transactions with full input/output script analysis.
* **🔍 Forensic Deep Carving Engine**: Scan raw disk images, corrupted `wallet.dat` files, and memory dumps (`.dmp`, `.bin`, `.raw`) to extract BIP-39 mnemonics, WIFs, extended keys, and ASN.1 DER private keys.

---

## 🔗 Supported Cryptographic Standards & Networks

### Cryptographic & Wallet Standards
| Standard | Specification | Implementation |
| :--- | :--- | :--- |
| **BIP-32** | Hierarchical Deterministic Wallets | [`bip32.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/bip32.py) |
| **BIP-39** | Mnemonic Code for Generating Deterministic Keys | [`bip39.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/bip39.py) |
| **BIP-44** | Multi-Account Hierarchy (`m/44'/coin'/account'/change/index`) | [`wallet.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/wallet.py) |
| **BIP-49** | Nested SegWit P2SH-P2WPKH (`m/49'/0'/0'`) | [`addresses.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/addresses.py) |
| **BIP-84** | Native SegWit Bech32 P2WPKH (`m/84'/0'/0'`) | [`addresses.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/addresses.py) |
| **BIP-86** | Taproot Bech32m P2TR (`m/86'/0'/0'`) | [`addresses.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/addresses.py) |
| **BIP-174** | Partially Signed Bitcoin Transaction (PSBT) Format | [`psbt.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/psbt.py) |
| **BIP-380–389**| Output Script Descriptors & Checksums | [`descriptors.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/descriptors.py) |
| **SLIP-0010** | Universal Private Key Derivation from Master Seed (Ed25519) | [`wallet.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/wallet.py) |

### Supported Blockchains (50+ Configurations)
* **Bitcoin & UTXO Chains**: Bitcoin Mainnet (`P2PKH`, `P2SH-P2WPKH`, `P2WPKH`, `P2TR`), Bitcoin Testnet, Litecoin (`LTC`), Dogecoin (`DOGE`), Dash (`DASH`), Zcash (`ZEC`), Bitcoin Cash (`BCH`), Bitcoin Gold (`BTG`), Bitcoin SV (`BSV`), Ravencoin (`RVN`), Kaspa (`KAS`).
* **Ethereum & EVM Ecosystems**: Ethereum (`ETH`), BNB Smart Chain (`BNB`), Polygon (`POL`), Polygon zkEVM, Arbitrum (`ARB`), Optimism (`OP`), Base (`BASE`), Avalanche C-Chain (`AVAX`), zkSync Era (`ZKSYNC`), Fantom (`FTM`), Linea (`LINEA`), Scroll (`SCROLL`), Blast (`BLAST`), Mantle (`MNT`), Cronos (`CRO`), Gnosis (`GNO`), Celo (`CELO`), Manta Pacific, Mode, Taiko, Fraxtal, Core DAO, Berachain, Monad, Sonic.
* **Non-EVM & Ed25519 / Alternative L1s**: Solana (`SOL`), XRP Ledger (`XRP`), Tron (`TRX`), Sui (`SUI`), Aptos (`APT`), TON (`TON`), Cosmos Hub (`ATOM`), Osmosis (`OSMO`), Injective (`INJ`), Sei (`SEI`), Celestia (`TIA`), Kava (`KAVA`), Polkadot (`DOT`), Cardano (`ADA`), Stellar (`XLM`), NEAR Protocol (`NEAR`), Algorand (`ALGO`), Tezos (`XTZ`), Filecoin (`FIL`).

---

## 📂 Project Architecture

```text
/home/kali/hd-wallet-src/
├── build_deb.sh                         # Automated Debian (.deb) package builder script
├── pyrightconfig.json                   # Type-checking configuration
└── hd-wallet-suite/
    ├── main.py                          # Application entry point & startup flow
    ├── icons/                           # Multi-resolution application icons (16px - 512px)
    ├── ui/                              # PyQt6 Graphical User Interface modules
    │   ├── main_window.py               # Main window, global toolbar, and tab orchestration
    │   ├── styles.py                    # Dark theme Fusion palette & custom QSS stylesheets
    │   ├── disclaimer_dialog.py         # Startup legal disclaimer & liability modal
    │   ├── auth_dialog.py               # Device authorization dialog
    │   ├── import_dialog.py             # Hardened wallet & key import modal
    │   ├── workers.py                   # Background QThread workers for non-blocking I/O
    │   ├── tab_key_inspector.py         # Tab 1: Key / Address Inspector
    │   ├── tab_batch_table.py           # Tab 2: Batch Address Generator & Balance Table
    │   ├── tab_descriptors.py           # Tab 3: Bitcoin Output Descriptors (BIP-380+)
    │   ├── tab_multichain.py            # Tab 4: 50+ Multichain Directory & Custom RPC
    │   ├── tab_all_chains.py            # Tab 5: All Chains Balance Summary & CSV Export
    │   ├── tab_sweeper.py               # Tab 6: Multichain Asset Sweeper
    │   ├── tab_wallet_files.py          # Tab 7: Wallet Databases Scanner & Inspector
    │   ├── tab_key_space.py             # Tab 8: 256-Bit Key Space Explorer
    │   ├── tab_btcrecover.py            # Tab 9: PyWallet Salvage & BTCRecover Engine
    │   ├── tab_psbt.py                  # Tab 10: PSBT Creator, Decoder, Signer & Broadcaster
    │   └── tab_carving.py               # Tab 11: Forensic Deep Carving Engine
    └── hd_wallet/                       # Bundled dependencies & core cryptographic library
        └── hd_wallet/                   # Core Python cryptographic engine package
            ├── __init__.py              # Public SDK exports
            ├── wallet.py                # HDWallet class & SLIP-0010 / BIP-32 orchestration
            ├── bip32.py                 # BIP-32 HD node derivation & extended key serialization
            ├── bip39.py                 # BIP-39 wordlist, entropy, PBKDF2-HMAC-SHA512 seed gen
            ├── addresses.py             # Multi-network address encoders (Base58, Bech32/m, Keccak, etc.)
            ├── coins.py                 # Network parameters, prefixes, and BIP-44 coin types
            ├── crypto_accel.py          # C-library acceleration (coincurve / wallycore / ecdsa)
            ├── descriptors.py           # BIP-380 descriptor parser, generator & checksums
            ├── psbt.py                  # BIP-174 PSBT binary serializer, parser & signer
            ├── balance.py               # Multi-chain RPC & REST API balance querying engine
            ├── sweep.py                 # Transaction construction & sweeping across EVM/BTC/SOL/TRX
            ├── private_key_finder.py    # 2^256 key space pagination & reverse index calculator
            ├── carving.py               # DeepCarver binary forensic scanner & report generator
            ├── parser.py                # Unified wallet file inspector & PyWallet engine router
            ├── parse_wallet.py          # Native Berkeley DB wallet.dat parser
            ├── pywallet.py              # Integrated PyWallet 2.3-gsc recovery script (Python 3)
            └── pywallet_27.py           # Legacy PyWallet 2.2 script (Python 2/3 hybrid)
```

---

## 📖 Well-Documented Instructions

### 1. System Requirements & Dependencies

* **Operating System**: Linux (Debian, Ubuntu, Kali Linux recommended)
* **Python**: Python `3.10+`
* **System Packages** (for GUI and Berkeley DB support):
  ```bash
  sudo apt update
  sudo apt install -y python3 python3-pyqt6 python3-cryptography python3-requests python3-bsddb3
  ```
  *(Note: On newer Debian/Kali distributions where `python3-bsddb3` is replaced, install `python3-berkeleydb` instead. The `hd-wallet-suite/hd_wallet/` directory also ships with pre-bundled self-contained wheels and C-extensions for offline portability.)*

---

### 2. Running from Source

1. **Navigate to the application directory**:
   ```bash
   cd /home/kali/hd-wallet-src/hd-wallet-suite
   ```
2. **Launch the GUI application**:
   ```bash
   python3 main.py
   ```
3. **Startup Flow**:
   * On launch, the **Disclaimer & Limitation of Liability** dialog ([`disclaimer_dialog.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/disclaimer_dialog.py)) will appear.
   * Check **"I understand and agree that the author assumes no fault or liability"** and click **"I Agree & Continue"** to enter the main workbench.

---

### 3. Building & Installing the Debian (`.deb`) Package

The repository includes an automated package builder ([`build_deb.sh`](file:///home/kali/hd-wallet-src/build_deb.sh)) that packages the source, bundled dependencies, desktop launcher, and multi-resolution icons into a standalone `.deb` installer.

1. **Build the `.deb` package**:
   ```bash
   cd /home/kali/hd-wallet-src
   ./build_deb.sh
   ```
   This produces [`hd-wallet-suite_2.0-5_amd64.deb`](file:///home/kali/hd-wallet-src/hd-wallet-suite_2.0-5_amd64.deb) in the root directory.

2. **Install the package**:
   ```bash
   sudo dpkg -i hd-wallet-suite_2.0-5_amd64.deb
   sudo apt-get install -f   # Resolves any missing system-level Qt/Python dependencies
   ```

3. **Launch from Terminal or Application Menu**:
   ```bash
   hd-wallet-suite
   ```
   Or open **HD Wallet Suite** directly from your desktop environment's *Applications → Utility / Security* menu.

---

### 4. Complete User Guide (Tab-by-Tab Walkthrough)

#### Top Global Toolbar
Located at the top of [`MainWindow`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/main_window.py):
* **Seed Status Pill**: Displays the active input type (`● Valid BIP-39 Seed`, `● Extended Key`, `● WIF Private Key`, or `● Raw Private Key`).
* **Network Selector**: Switch the active primary context (`Bitcoin Mainnet`, `Bitcoin Testnet`, `Ethereum`, `BNB Chain`, `Litecoin`, `Dogecoin`, `Tron`, `Solana`, `XRP`, `Dash`, `Zcash`, `Cosmos`).
* **Quick Test Vector Dropdown**: Instantly load standard BIP-39 test vectors (12-word, 24-word, all-zeros hex, Electrum seed) for testing and verification.
* **New 12-Word / New 24-Word**: Generate cryptographically secure random BIP-39 mnemonics using `os.urandom` entropy.
* **Load Key / 🔒 Import Wallet**: Opens the [`SecureImportDialog`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/import_dialog.py) for hardened, checksum-verified importing of mnemonics, hex/WIF/xprv keys, or encrypted wallet backup files (`.json`, `wallet.dat`, `.sqlite`).

---

#### Tab 1: Key Inspector ([`tab_key_inspector.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_key_inspector.py))
* **Purpose**: Deep inspection of master seeds, extended keys, and single-path address derivations.
* **Instructions**:
  1. Enter or paste a **BIP-39 Mnemonic**, **Raw Hex Key**, **WIF**, or **Extended Key (`xprv`/`xpub`)** into the top input box (or use **🔒 Import Wallet**).
  2. *(Optional)* Enter a **BIP-39 Passphrase** (25th word).
  3. Select a **Derivation Standard** preset (e.g., `BIP-84 Native SegWit`, `BIP-86 Taproot`, `BIP-49 Nested SegWit`, `BIP-44 Legacy`) or customize the `Account`, `Change (0=External, 1=Internal)`, and `Address Index` spinboxes.
  4. Click **Derive** to inspect the 512-bit BIP-39 Seed Hex, Root Master Private Key (`xprv`), Account Extended Keys (`xprv`/`xpub`/`zprv`/`zpub`), WIF, Public Key (compressed/uncompressed), and all corresponding network addresses.

#### Tab 2: Batch Addresses ([`tab_batch_table.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_batch_table.py))
* **Purpose**: Bulk generation of sequential addresses with live balance checking and CSV export.
* **Instructions**:
  1. Choose a **Preset Chain & Standard** (e.g., Bitcoin BIP-84/86/49/44, Ethereum, Solana, Tron, XRP, Litecoin, Dogecoin, Cosmos, Polkadot, Cardano).
  2. Set the **Start Index** and **Count** (number of addresses to derive).
  3. Click **Generate Batch** to populate the table with Derivation Path, Address, Public Key, and Private Key (WIF/Hex).
  4. Click **Check Balances** to query live on-chain balances in a background thread, or **Export CSV** to save the derived batch.

#### Tab 3: Descriptors ([`tab_descriptors.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_descriptors.py))
* **Purpose**: Generate and parse Bitcoin Core Output Descriptors (`BIP-380` through `BIP-389`).
* **Instructions**:
  1. When a wallet is loaded, the top panel automatically computes the **Master Fingerprint** and standard external (`0/*`) and internal (`1/*`) descriptors with valid `#checksum` suffixes (`wpkh(...)`, `tr(...)`, `sh(wpkh(...))`, `pkh(...)`).
  2. Paste any custom descriptor into the **Descriptor Inspector** input box and click **Parse & Derive** to verify its checksum and derive child addresses across a specified index range.

#### Tab 4: Multichain (50+) ([`tab_multichain.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_multichain.py))
* **Purpose**: Visual 3-column card grid displaying derived addresses and balances across 50+ blockchains simultaneously.
* **Instructions**:
  1. Review the derived address on any chain card and click **Copy** or **Check** for an individual balance lookup.
  2. Click **Check All 50 Chain Balances** to launch a concurrent multi-chain balance scan. Funded chains highlight in neon green and increment the **Funded Assets** badge.
  3. **Custom RPC Node**: Click **⚙ Custom RPC Settings**, select a network, enter your custom `http(s)://` RPC URL (and optional username/password), and click **Test & Apply**.

#### Tab 5: All Balances ([`tab_all_chains.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_all_chains.py))
* **Purpose**: Unified tabular summary of all 50+ chains for rapid sorting, auditing, and reporting.
* **Instructions**:
  1. Click **⚡ Query All Chains Balances** to scan all networks for the active wallet.
  2. Click **📤 Export CSV** to export the full multichain address and balance audit report.

#### Tab 6: Sweeper ([`tab_sweeper.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_sweeper.py))
* **Purpose**: Consolidate and sweep funds from derived addresses to designated destination addresses across EVM chains, Bitcoin, Solana, Tron, XRP, and Litecoin.
* **Instructions**:
  1. Configure your target **Destination Addresses** for each ecosystem (`EVM`, `BTC`, `SOL`, `TRX`, `XRP`, `LTC`).
  2. Click **Sweep All Chains** (or individual chain sweep buttons) to scan for positive balances, construct signed sweep transactions (automatically deducting gas/network fees), broadcast them, and view transaction hashes in the execution log.

#### Tab 7: Wallet DBs ([`tab_wallet_files.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_wallet_files.py))
* **Purpose**: Discover, inspect, and extract keys from local wallet database files.
* **Instructions**:
  1. Click **Rescan System Databases** to automatically locate known wallet files in standard directories, or click **Browse Wallet / DB...** to select a specific `wallet.dat` (Berkeley DB), SQLite descriptor wallet, Electrum JSON, or keystore file.
  2. Select a database entry to inspect its format header, encryption status, master keys (`mkey`/`ckey`), scripts, and extracted private/public keys.

#### Tab 8: Key Space ([`tab_key_space.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_key_space.py))
* **Purpose**: Interactive $2^{256}$ private key space directory and reverse key locator.
* **Instructions**:
  1. Select a target **Blockchain / Derivation Path** and **Mnemonic Word Count** (`12` or `24` words).
  2. Navigate pages (`1` to $9.046 \times 10^{74}$) using **First**, **Prev**, **Next**, **Last**, or **🎲 Random Page**, or type a specific page number and click **Go**.
  3. **Reverse Search**: Paste any Private Key (Hex/WIF) or Mnemonic into the search bar to calculate its exact page number and index offset within the $2^{256}$ key space.
  4. Double-click any row to open the **Key Detail Inspector** modal for a full 50-chain breakdown of that specific key.

#### Tab 9: Recovery ([`tab_btcrecover.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_btcrecover.py))
* **Purpose**: Dual-panel wallet salvage (**PyWallet 2.3**) and password recovery (**BTCRecover**).
* **Instructions**:
  1. Click **📂 Browse...** to select a target `wallet.dat`, `.db`, `.sqlite`, or encrypted backup file.
  2. **Left Panel (PyWallet Key Salvage & DB Dumper)**: Click **Dump Wallet JSON** or **Salvage Keys** to extract raw keys, metadata, and unencrypted records from damaged or legacy Berkeley DB files.
  3. **Right Panel (BTCRecover Password Engine)**: Configure candidate passwords, tokenlist/typos rules, or wordlist files and run multi-threaded passphrase recovery against encrypted wallet master keys.

#### Tab 10: PSBT ([`tab_psbt.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_psbt.py))
* **Purpose**: BIP-174 Partially Signed Bitcoin Transaction lifecycle management.
* **Instructions**:
  1. **Create**: Enter UTXO inputs (`TxID`, `Vout`, `Amount`, `ScriptPubKey`) and recipient outputs (`Address`, `Amount`) to build an unsigned PSBT, or load an existing Base64/Hex/binary `.psbt` file.
  2. **Decode & Inspect**: View decoded global metadata, inputs, outputs, fee calculations, and signature statuses.
  3. **Sign & Finalize**: Sign inputs using the currently loaded wallet's private keys, finalize witness/scriptSig fields, and extract or broadcast the raw hex transaction.

#### Tab 11: Forensic Carving ([`tab_carving.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_carving.py))
* **Purpose**: Low-level binary carving for lost keys in disk images, memory dumps, and corrupted files.
* **Instructions**:
  1. Click **Browse File...** to select a binary dump (`.dmp`, `.raw`, `.img`, `wallet.dat`) or paste raw hex/text payloads.
  2. Click **Start Deep Carve** to scan for valid BIP-39 mnemonic sequences (with checksum validation), Base58Check WIF private keys, BIP-32 extended keys (`xprv`/`zprv`), and ASN.1 DER secp256k1 key structures (`\x04\x20`).
  3. Export recovered artifacts and forensic reports to JSON/TXT or load any discovered key directly into the **Key Inspector**.

---

### 5. Python SDK / Programmatic API Usage

You can also use the underlying [`hd_wallet`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/__init__.py) engine directly in your own Python scripts:

```python
import sys
sys.path.insert(0, "/home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet")

from hd_wallet import (
    HDWallet,
    generate_mnemonic,
    validate_mnemonic,
    generate_wallet_descriptors,
    get_private_key_page,
)

# 1. Generate or validate a BIP-39 mnemonic
mnemonic = generate_mnemonic(12)
assert validate_mnemonic(mnemonic)

# 2. Initialize HDWallet and derive multichain keys
wallet = HDWallet(mnemonic, passphrase="", network="bitcoin")
btc_segwit = wallet.derive_key("m/84'/0'/0'/0/0")
eth_acct   = wallet.derive_key("m/44'/60'/0'/0/0")
sol_acct   = wallet.derive_key("m/44'/501'/0'/0'")

print("BTC (Native SegWit):", btc_segwit["addressP2WPKH"])
print("BTC (Taproot):      ", btc_segwit["addressP2TR"])
print("ETH (EVM):          ", eth_acct["addressETH"])
print("SOL (Ed25519):      ", sol_acct["addressSOL"])

# 3. Generate BIP-380 Output Descriptors
descriptors = generate_wallet_descriptors(mnemonic)
print("BIP-84 Descriptor:  ", descriptors["bip84"]["external"])

# 4. Query a page from the 2^256 Private Key Space
page_data = get_private_key_page(page_number=1, keys_per_page=5, word_count=12)
for entry in page_data["keys"]:
    print(entry["privateKeyHex"], "->", entry["addressP2WPKH"])
```

---

## 🛡️ Security & Operational Best Practices

* **Air-Gapped Operation**: When handling high-value production seeds or performing sensitive forensic recovery on real assets, run **HD Wallet Suite** on an offline, air-gapped machine.
* **Memory & Clipboard Hygiene**: Use the **🔒 Import Wallet** dialog ([`import_dialog.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/import_dialog.py)), which masks sensitive inputs by default, validates checksums before loading, and wipes temporary buffers on close.
* **Custom RPC Endpoints**: For privacy-sensitive balance lookups, configure your own local or private full node in **Tab 4 → ⚙ Custom RPC Settings** rather than relying on public RPC endpoints.

---

## 🏆 Sources, Credits & Acknowledgments

### Primary Author & Architecture
* **Author & Lead Developer**: **Corey K.** (`hdwalletengine@proton.me`)
* **Project**: *HD Wallet Cryptographic Engine & Multichain Suite (v2.0)*
* **Package Maintainer**: HD Wallet Team (`support@hdwallet.io`)

### Integrated Open-Source Engines & Pioneers
This suite integrates, adapts, and builds upon foundational work from the cryptocurrency security and open-source community:

1. **PyWallet (`pywallet.py` v2.3-gsc & `pywallet_27.py` v2.2)**
   * **Credits**: Originally created by **Joric**, expanded by **Jackjack** ([`jackjack-jj/pywallet`](https://github.com/jackjack-jj/pywallet)), and updated for Python 3 recovery by **Great-Software-Company** ([`Great-Software-Company/pywallet`](https://github.com/Great-Software-Company/pywallet)).
   * **Role in Suite**: Powers legacy Berkeley DB (`wallet.dat`) key salvage, raw database record dumping, and corrupted wallet recovery in [`pywallet.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/pywallet.py) and [`pywallet_27.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/pywallet_27.py).

2. **BTCRecover Concepts & Recovery Workflows**
   * **Credits**: Inspired by **Christopher Gurnee (`gurnec`)** and **3rdIteration** ([`3rdIteration/btcrecover`](https://github.com/3rdIteration/btcrecover)).
   * **Role in Suite**: Inspires the password candidate generation, mutation rules, and wallet decryption workflows in [`tab_btcrecover.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_btcrecover.py).

3. **PrivateKeyFinder.io & Key Space Directory Architecture**
   * **Credits**: Inspired by the [PrivateKeyFinder.io](https://privatekeyfinder.io) directory model and visual key space indexing concepts.
   * **Role in Suite**: Implemented in [`private_key_finder.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/hd_wallet/hd_wallet/private_key_finder.py) and [`tab_key_space.py`](file:///home/kali/hd-wallet-src/hd-wallet-suite/ui/tab_key_space.py) for navigating the $2^{256}$ `secp256k1` key space with deterministic 0-indexed BIP-39 mnemonic mapping.

4. **Bitcoin Improvement Proposals (BIPs) & SLIP Standards**
   * **Credits**: **Pieter Wuille** (BIP-32, Bech32/Bech32m, `libsecp256k1`, Output Descriptors), **Marek Palatinus / Pavol Rusnak / Aaron Voisine / Sean Bowe** (BIP-39, BIP-44, SLIP-0010), **Andrew Chow** (BIP-174 PSBT, BIP-380+ Output Descriptors).

5. **Core Cryptographic Libraries & Open-Source Dependencies**
   * **`libsecp256k1` & `coincurve`**: Bitcoin Core developers & Ofek Lev — High-speed C-accelerated ECDSA and Schnorr cryptography.
   * **Blockstream `libwally-core` (`wallycore`)**: Blockstream — Native C primitives for HD wallets, descriptors, and PSBT.
   * **Ethereum Foundation Python Stack**: `eth-account`, `eth-keys`, `eth-keyfile`, `eth-utils`, `eth-abi`, `eth-typing`, `eth-hash`, `rlp`, `py_ecc`, `hexbytes`.
   * **`PyQt6` & Qt6 Framework**: Riverbank Computing & The Qt Company — Cross-platform GUI toolkit.
   * **`cryptography` & `pycryptodome`**: Python Cryptographic Authority (PyCA) — AES, scrypt, PBKDF2, and digest primitives.
   * **`python-ecdsa` & `base58` & `bsddb3`**: Pure-Python elliptic curve cryptography, Base58Check encoding, and Oracle Berkeley DB bindings.

---

## ⚠️ Legal Disclaimer & Limitation of Liability

> **NO WARRANTY & NO LIABILITY — USE AT YOUR OWN RISK**
>
> This software is provided **"AS IS"**, without warranty of any kind, express or implied. The author and contributors assume **no fault, responsibility, or liability whatsoever** if anything goes wrong.
>
> * You assume **100% of all risks** associated with cryptographic key derivation, wallet recovery, transaction signing, sweeping, and file operations.
> * The developer assumes **zero fault or liability** for any lost funds, compromised keys, corrupted wallet files, failed transactions, data loss, or any other damages.
> * This tool is intended strictly for **authorized recovery, security research, and educational use** on wallets and assets you legally own or have explicit permission to access.

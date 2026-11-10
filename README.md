# ⚡ HD Wallet Cryptographic Engine & Multichain Suite

A desktop and browser-based crypto workbench for HD wallet derivation, multichain inspection, wallet recovery, and forensic key analysis.

## Overview

This repository packages the full HD Wallet Suite application and its bundled Python runtime, including:

- BIP-32 / BIP-39 / BIP-44 / BIP-49 / BIP-84 / BIP-86 support
- 50+ multichain address and balance workflows
- wallet database inspection and recovery tooling
- PSBT, descriptor, and key-space analysis
- forensic carving and deep recovery utilities

## Repository layout

- `README.md` — project overview and usage guidance
- `build_deb.sh` — Debian packaging helper
- `configure_dns.sh` — DNS configuration helper
- `docs/` — static web assets for the browser edition
- `hd-wallet-suite/` — application source and bundled Python runtime

## Quick start

From the project root:

```bash
cd hd-wallet-suite
python3 main.py
```

For Debian packaging:

```bash
./build_deb.sh
```

## More information

- Project homepage: https://gsibuilder.github.io/hd-wallet-suite/
- Browser edition: https://gsibuilder.github.io/hd-wallet-suite/
- Full project documentation and architecture notes remain in the application directory README and the source modules in `hd-wallet-suite/`

## Security note

This software is intended for authorized, legal recovery, research, and educational use on wallets/assets you own or are explicitly permitted to access.

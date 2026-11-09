---
description: Environment and coding guidelines for Python, PyQt6, and crypto modules in hd-wallet-suite
globs: "**/*.py"
always_on: true
---

# Python & PyQt Development Rules

## 1. Virtual Environment & Type Checker Configuration
- In Kali/Debian environments where GUI (`PyQt6`) and C-extension libraries (`bsddb3`, `cryptography`) are installed via system packages, ensure `.venv/pyvenv.cfg` includes `include-system-site-packages = true`.
- When configuring `pyrightconfig.json`, include `"/usr/lib/python3/dist-packages"` in `extraPaths`.

## 2. PyQt Threading Invariants
- **NEVER** assign `self.start = ...` on any `QThread` subclass. Use `self.start_index` or `self.start_offset` to avoid clobbering the native `QThread.start()` method.
- When copying to the clipboard, guard with `cb = QApplication.clipboard(); if cb: cb.setText(...)` to satisfy strict null-checks and avoid runtime attribute errors.
- Always null-check `table.horizontalHeader()` and `table.verticalHeader()` when configuring column sizing or visibility.

## 3. Cryptography & Key Derivation Invariants
- For `ecdsa` curve orders, cast explicitly to `int`: `int(ecdsa.SECP256k1.generator.order() or 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)`.
- When accessing public keys from a `SigningKey`, use `vk = sk.get_verifying_key(); assert vk is not None` before accessing `vk.pubkey.point`.
- For extended key serialization, support both `int` and `bytes` for version headers.

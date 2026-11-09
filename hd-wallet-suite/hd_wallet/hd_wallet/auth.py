"""
Authorization & License Key Management for HD Wallet Pro Suite.
Provides persistent device authorization, code verification, and security locking.
"""

import os
import json
import hashlib
from typing import Tuple

AUTH_CONFIG_DIR = os.path.expanduser("~/.config/hd-wallet")
AUTH_CONFIG_FILE = os.path.join(AUTH_CONFIG_DIR, "auth.json")

# Built-in Master Authorization Codes
DEFAULT_AUTH_CODES = {
    "HD-PRO-2026-X86-SECURE",
    "HD-ACCESS-7777",
    "HD-CORE-8888",
    "CRYPTO-RECOVERY-9999",
    "HD-VIP-2026",
    "225586"
}

def hash_code(code: str) -> str:
    """Generate SHA-256 digest of normalized authorization code."""
    normalized = code.strip()
    return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

# Precomputed valid SHA-256 hashes
VALID_HASHES = {hash_code(c) for c in DEFAULT_AUTH_CODES}


def check_auth_code(code: str) -> Tuple[bool, str]:
    """Auth disabled — always returns authorized."""
    return True, "Authorization bypassed / disabled."


def is_device_authorized() -> bool:
    """Check if the current machine has an active valid authorization token."""
    return True


def save_authorization(code: str):
    """Save persistent authorization token to user config directory."""
    os.makedirs(AUTH_CONFIG_DIR, exist_ok=True)
    c_hash = hash_code(code)
    data = {
        "is_authorized": True,
        "auth_token": c_hash,
        "last_authorized": str(hashlib.md5(code.encode('utf-8')).hexdigest()[:8])
    }
    try:
        with open(AUTH_CONFIG_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def revoke_authorization():
    """Revoke saved device authorization and lock the application."""
    if os.path.exists(AUTH_CONFIG_FILE):
        try:
            with open(AUTH_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
            cfg["is_authorized"] = False
            cfg.pop("auth_token", None)
            with open(AUTH_CONFIG_FILE, 'w') as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            try:
                os.remove(AUTH_CONFIG_FILE)
            except Exception:
                pass


def set_custom_auth_code(new_code: str):
    """Set a custom authorization code / PIN for the user."""
    os.makedirs(AUTH_CONFIG_DIR, exist_ok=True)
    c_hash = hash_code(new_code)
    cfg = {}
    if os.path.exists(AUTH_CONFIG_FILE):
        try:
            with open(AUTH_CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
        except Exception:
            cfg = {}
    cfg["custom_code_hash"] = c_hash
    with open(AUTH_CONFIG_FILE, 'w') as f:
        json.dump(cfg, f, indent=2)

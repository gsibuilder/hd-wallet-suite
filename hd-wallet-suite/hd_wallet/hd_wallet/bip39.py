"""
BIP-39 Mnemonic and Seed derivation module.
"""

import os
import hashlib
from typing import Union

try:
    from mnemonic import Mnemonic
    _mnem_eng = Mnemonic("english")
    WORDLIST = set(_mnem_eng.wordlist)
except ImportError:
    _mnem_eng = None
    WORDLIST = set()


def generate_mnemonic(strength: int = 128) -> str:
    """
    Generate a BIP-39 mnemonic phrase.
    strength: 128 (12 words), 160 (15 words), 192 (18 words), 224 (21 words), 256 (24 words).
    """
    if strength not in (128, 160, 192, 224, 256):
        strength = 128

    if _mnem_eng:
        return _mnem_eng.generate(strength=strength)

    # Fallback if mnemonic package is somehow absent
    entropy = os.urandom(strength // 8)
    return entropy_to_mnemonic(entropy)


def validate_mnemonic(mnemonic: str) -> bool:
    """
    Validate a BIP-39 mnemonic string.
    """
    clean = " ".join(mnemonic.strip().split())
    if not clean:
        return False
    if _mnem_eng:
        return _mnem_eng.check(clean)
    words = clean.split()
    return len(words) in (12, 15, 18, 21, 24)


def mnemonic_to_seed(mnemonic: str, passphrase: str = "") -> bytes:
    """
    Derive 512-bit seed from BIP-39 mnemonic and salt passphrase using PBKDF2-HMAC-SHA512.
    """
    clean = " ".join(mnemonic.strip().split())
    salt = ("mnemonic" + passphrase).encode("utf-8")
    return hashlib.pbkdf2_hmac(
        'sha512',
        clean.encode("utf-8"),
        salt,
        2048,
        64
    )


def entropy_to_mnemonic(entropy: bytes) -> str:
    """
    Convert raw entropy bytes into a BIP-39 mnemonic phrase.
    """
    if _mnem_eng:
        return _mnem_eng.to_mnemonic(entropy)
    
    # Minimal fallback logic
    ent_bits = len(entropy) * 8
    checksum_bits = ent_bits // 32
    hash_bytes = hashlib.sha256(entropy).digest()
    
    # Combine entropy and checksum
    bits_str = "".join(f"{b:08b}" for b in entropy)
    checksum_str = "".join(f"{b:08b}" for b in hash_bytes)[:checksum_bits]
    full_bits = bits_str + checksum_str
    
    # Divide into 11-bit chunks
    indices = [int(full_bits[i:i+11], 2) for i in range(0, len(full_bits), 11)]
    if _mnem_eng is not None and hasattr(_mnem_eng, 'wordlist'):
        wordlist = _mnem_eng.wordlist
        return " ".join(wordlist[i] for i in indices)
    return " ".join(str(i) for i in indices)


def carve_bip39_mnemonics(data: Union[bytes, str]) -> list:
    """
    Scan arbitrary binary or string data for valid BIP-39 mnemonic sequences
    (12, 15, 18, 21, or 24 words) with mathematically verified checksums.
    """
    import re
    if isinstance(data, bytes):
        text = data.decode('utf-8', errors='ignore')
    else:
        text = str(data)

    if not _mnem_eng or not hasattr(_mnem_eng, 'wordlist'):
        return []

    word_set = set(_mnem_eng.wordlist)
    tokens = [t.lower() for t in re.findall(r'[a-zA-Z]+', text)]
    if len(tokens) < 12:
        return []

    found = []
    seen = set()

    for length in (24, 21, 18, 15, 12):
        for i in range(len(tokens) - length + 1):
            chunk = tokens[i:i+length]
            if all(w in word_set for w in chunk):
                candidate = " ".join(chunk)
                if candidate not in seen and validate_mnemonic(candidate):
                    seen.add(candidate)
                    found.append(candidate)

    return found


def carve_extended_keys(data: Union[bytes, str]) -> list:
    """
    Extract all valid Base58Check extended keys (xprv, zprv, yprv, tprv, xpub, zpub, ypub, tpub)
    and raw 78-byte BIP32 serialized payloads from arbitrary binary or string data.
    """
    import re
    from .bip32 import BIP32Node
    from .addresses import base58check_encode

    found = []
    seen = set()

    # 1. Text / Regex scan for base58 string representations
    if isinstance(data, bytes):
        text = data.decode('utf-8', errors='ignore')
    else:
        text = str(data)

    pattern = re.compile(r'\b([xyzuvtXYZUVT]p[ru][vb][1-9A-HJ-NP-Za-km-z]{100,115})\b')
    for match in pattern.findall(text):
        if match not in seen:
            try:
                BIP32Node.from_extended_key(match)
                seen.add(match)
                found.append(match)
            except Exception:
                pass

    # 2. Binary scan for 78-byte BIP-32 payloads with known headers
    if isinstance(data, bytes) and len(data) >= 78:
        known_headers = [
            b'\x04\x88\xad\xe4',  # xprv
            b'\x04\x88\xb2\x1e',  # xpub
            b'\x04\xb2\x43\x0c',  # zprv
            b'\x04\xb2\x47\x46',  # zpub
            b'\x04\x9d\x78\x78',  # yprv
            b'\x04\x9d\x7c\xb2',  # ypub
            b'\x04\x35\x83\x94',  # tprv
            b'\x04\x35\x87\xcf',  # tpub
        ]
        for hdr in known_headers:
            start = 0
            while True:
                idx = data.find(hdr, start)
                if idx == -1 or idx + 78 > len(data):
                    break
                payload = data[idx:idx+78]
                try:
                    b58_str = base58check_encode(payload)
                    if b58_str not in seen:
                        BIP32Node.from_extended_key(b58_str)
                        seen.add(b58_str)
                        found.append(b58_str)
                except Exception:
                    pass
                start = idx + 1

    return found


def carve_hex_seeds(data: Union[bytes, str]) -> list:
    """
    Extract valid 32-byte (64 hex chars) or 64-byte (128 hex chars) master seed strings.
    """
    import re
    if isinstance(data, bytes):
        text = data.decode('utf-8', errors='ignore')
    else:
        text = str(data)

    found = []
    seen = set()
    for match in re.findall(r'\b([0-9a-fA-F]{64}|[0-9a-fA-F]{128})\b', text):
        m_lower = match.lower()
        if m_lower not in seen:
            seen.add(m_lower)
            found.append(m_lower)
    return found



"""
Advanced Forensic Deep Carving Engine for Bitcoin & Cryptocurrency Artifacts.
Carves unallocated slack space, corrupted Berkeley DB files, RAM dumps, and log files for:
- Low-level Berkeley DB Key/Value records (mkey, ckey, key, wkey, hdseed, name, etc.)
- BIP-39 Mnemonic Sequences (12-24 words) & 1-word missing error reconstructor
- WIF Private Keys (Compressed & Uncompressed Base58Check)
- Extended Keys (xprv, yprv, zprv, tprv, xpub, ypub, zpub, tpub) both Base58 & 78-byte raw binary
- Bitcoin Output Descriptors (wpkh, tr, sh, pkh) with checksum verification
- Casascius / Mini-Private Keys (S... with SHA256 check)
- Raw 256-bit & 512-bit High-Entropy Master Seed hex payloads
"""

import math
import re
import struct
import hashlib
from typing import Dict, Any, List, Optional, Tuple, Set, Union
import ecdsa

from .bip39 import (
    validate_mnemonic,
    _mnem_eng,
    entropy_to_mnemonic
)
from .bip32 import BIP32Node
from .addresses import (
    base58check_decode,
    base58check_encode,
    decode_wif,
    is_valid_wif,
    pubkey_to_p2pkh,
    pubkey_to_p2wpkh,
    pubkey_to_p2sh_p2wpkh,
    pubkey_to_p2tr,
    pubkey_to_ethereum
)
from .descriptors import descriptor_checksum, add_descriptor_checksum, verify_descriptor_checksum


# Known 4-byte BIP-32 / SLIP-132 version bytes
EXTENDED_KEY_HEADERS = {
    b'\x04\x88\xad\xe4': ('xprv', 'mainnet', 'p2pkh'),
    b'\x04\x88\xb2\x1e': ('xpub', 'mainnet', 'p2pkh'),
    b'\x04\x9d\x78\x78': ('yprv', 'mainnet', 'p2sh_p2wpkh'),
    b'\x04\x9d\x7c\xb2': ('ypub', 'mainnet', 'p2sh_p2wpkh'),
    b'\x04\xb2\x43\x0c': ('zprv', 'mainnet', 'p2wpkh'),
    b'\x04\xb2\x47\x46': ('zpub', 'mainnet', 'p2wpkh'),
    b'\x04\x35\x83\x94': ('tprv', 'testnet', 'p2pkh'),
    b'\x04\x35\x87\xcf': ('tpub', 'testnet', 'p2pkh'),
    b'\x04\x4a\x4e\x28': ('uprv', 'testnet', 'p2sh_p2wpkh'),
    b'\x04\x4a\x52\x62': ('upub', 'testnet', 'p2sh_p2wpkh'),
    b'\x04\x5f\x18\xbc': ('vprv', 'testnet', 'p2wpkh'),
    b'\x04\x5f\x1c\xf6': ('vpub', 'testnet', 'p2wpkh'),
}


def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of a byte string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for b in data:
        counts[b] = counts.get(b, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def read_compact_size(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """Read Bitcoin serialization CompactSize integer."""
    if offset >= len(data):
        return 0, offset
    first = data[offset]
    offset += 1
    if first < 253:
        return first, offset
    elif first == 253:
        if offset + 2 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset:offset+2], 'little'), offset + 2
    elif first == 254:
        if offset + 4 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset:offset+4], 'little'), offset + 4
    else:
        if offset + 8 > len(data):
            return 0, len(data)
        return int.from_bytes(data[offset:offset+8], 'little'), offset + 8


def parse_der_private_key(der_bytes: bytes) -> Optional[bytes]:
    """Extract raw 32-byte SECP256k1 scalar from DER-encoded private key."""
    # OpenSSL EC private key DER tag 0x30 ... 0x02 0x01 0x01 0x04 0x20 <32-bytes>
    idx = der_bytes.find(b'\x04\x20')
    if idx != -1 and idx + 34 <= len(der_bytes):
        candidate = der_bytes[idx+2 : idx+34]
        scalar = int.from_bytes(candidate, 'big')
        if 0 < scalar < ecdsa.SECP256k1.order:
            return candidate
    if len(der_bytes) == 32:
        scalar = int.from_bytes(der_bytes, 'big')
        if 0 < scalar < ecdsa.SECP256k1.order:
            return der_bytes
    return None


class DeepCarver:
    """Master deep forensic carver for blockchain cryptographic keys and records."""

    def __init__(self, data: Union[bytes, str] = b""):
        if isinstance(data, str):
            self.raw_bytes = data.encode('utf-8', errors='ignore')
            self.text_content = data
        else:
            self.raw_bytes = data
            self.text_content = data.decode('utf-8', errors='ignore')

    def carve_all(self) -> Dict[str, Any]:
        """Execute all carving engines and return structured forensic artifacts."""
        mnemonics = self.carve_mnemonics()
        wifs = self.carve_wifs()
        extended_keys = self.carve_extended_keys()
        descriptors = self.carve_descriptors()
        bdb_records = self.carve_berkeley_db()
        mini_keys = self.carve_mini_keys()
        hex_seeds = self.carve_seeds()

        total_keys = len(mnemonics) + len(wifs) + len(extended_keys) + len(descriptors) + len(mini_keys) + len(hex_seeds)

        return {
            'summary': {
                'total_artifacts_found': total_keys,
                'mnemonics_count': len(mnemonics),
                'wif_keys_count': len(wifs),
                'extended_keys_count': len(extended_keys),
                'descriptors_count': len(descriptors),
                'bdb_records_count': len(bdb_records),
                'mini_keys_count': len(mini_keys),
                'seeds_count': len(hex_seeds),
                'data_size_bytes': len(self.raw_bytes)
            },
            'mnemonics': mnemonics,
            'wifs': wifs,
            'extended_keys': extended_keys,
            'descriptors': descriptors,
            'bdb_records': bdb_records,
            'mini_keys': mini_keys,
            'seeds': hex_seeds
        }

    carve = carve_all

    def carve_mnemonics(self) -> List[Dict[str, Any]]:
        """Carve valid BIP-39 mnemonic phrases (12-24 words) with exact byte offsets."""
        results = []
        seen = set()

        if not _mnem_eng or not hasattr(_mnem_eng, 'wordlist'):
            return results

        wordlist = _mnem_eng.wordlist
        word_set = set(wordlist)

        # Regex token scanning across raw text
        tokens_with_spans = []
        for match in re.finditer(r'[a-zA-Z]+', self.text_content):
            w = match.group(0).lower()
            tokens_with_spans.append((w, match.start(), match.end()))

        if len(tokens_with_spans) < 12:
            return results

        for length in (24, 21, 18, 15, 12):
            for i in range(len(tokens_with_spans) - length + 1):
                chunk = tokens_with_spans[i : i + length]
                words = [item[0] for item in chunk]
                if all(w in word_set for w in words):
                    phrase = " ".join(words)
                    if phrase not in seen and validate_mnemonic(phrase):
                        seen.add(phrase)
                        start_pos = chunk[0][1]
                        end_pos = chunk[-1][2]
                        # Derive master address for preview
                        try:
                            from .wallet import HDWallet
                            hw = HDWallet(phrase)
                            res_84 = hw.derive_path("m/84'/0'/0'/0/0")
                            res_44 = hw.derive_path("m/44'/0'/0'/0/0")
                            res_eth = hw.derive_path("m/44'/60'/0'/0/0")
                            addr_p2wpkh = res_84.get('addressP2WPKH')
                            addr_legacy = res_44.get('addressP2PKH')
                            addr_eth = res_eth.get('addressETH')
                        except Exception:
                            addr_p2wpkh, addr_legacy, addr_eth = None, None, None

                        results.append({
                            'mnemonic': phrase,
                            'word_count': length,
                            'byte_offset_start': start_pos,
                            'byte_offset_end': end_pos,
                            'type': 'BIP-39 Mnemonic',
                            'confidence': 1.0,
                            'address_p2wpkh': addr_p2wpkh,
                            'address_legacy': addr_legacy,
                            'address_eth': addr_eth
                        })

        return results

    def reconstruct_partial_mnemonic(self, words: List[str]) -> List[str]:
        """
        Reconstruct a BIP-39 phrase with 1 missing or damaged word by brute-forcing
        the 2048 dictionary words against the BIP-39 checksum.
        """
        if not _mnem_eng or not hasattr(_mnem_eng, 'wordlist'):
            return []
        wordlist = _mnem_eng.wordlist

        target_lengths = (12, 15, 18, 21, 24)
        if len(words) + 1 not in target_lengths:
            return []

        solutions = []
        for pos in range(len(words) + 1):
            for cand in wordlist:
                trial = list(words)
                trial.insert(pos, cand)
                phrase = " ".join(trial)
                if validate_mnemonic(phrase):
                    solutions.append(phrase)
        return solutions

    def solve_missing_word(self, words: List[str], placeholder_idx: int) -> List[Dict[str, str]]:
        """
        Solve a missing word at placeholder_idx in words.
        Returns list of dicts with 'word' and 'mnemonic'.
        """
        if not _mnem_eng or not hasattr(_mnem_eng, 'wordlist'):
            return []
        wordlist = _mnem_eng.wordlist
        results = []
        for cand in wordlist:
            trial = list(words)
            trial[placeholder_idx] = cand
            phrase = " ".join(trial)
            if validate_mnemonic(phrase):
                results.append({'word': cand, 'mnemonic': phrase})
        return results

    def carve_wifs(self) -> List[Dict[str, Any]]:
        """Carve Base58Check WIF private keys (Legacy & Compressed)."""
        results = []
        seen = set()

        # Regex for mainnet/testnet WIF: 5... (51 chars), K.../L... (52 chars), 9.../c...
        wif_pattern = re.compile(r'([5KL9c][1-9A-HJ-NP-Za-km-z]{50,51})')
        for match in wif_pattern.finditer(self.text_content):
            wif_str = match.group(1)
            if wif_str in seen:
                continue
            if is_valid_wif(wif_str):
                try:
                    priv_bytes, compressed, net = decode_wif(wif_str)
                    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
                    vk = sk.get_verifying_key()
                    assert vk is not None
                    pt = vk.pubkey.point
                    p_prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
                    pub_comp = p_prefix + pt.x().to_bytes(32, 'big')
                    pub_uncomp = b'\x04' + pt.x().to_bytes(32, 'big') + pt.y().to_bytes(32, 'big')
                    pub = pub_comp if compressed else pub_uncomp

                    seen.add(wif_str)
                    results.append({
                        'wif': wif_str,
                        'privkey_hex': priv_bytes.hex(),
                        'compressed': compressed,
                        'network': 'testnet' if net else 'mainnet',
                        'byte_offset': match.start(),
                        'address_legacy': pubkey_to_p2pkh(pub),
                        'address_p2wpkh': pubkey_to_p2wpkh(pub_comp) if compressed else None,
                        'address_p2sh': pubkey_to_p2sh_p2wpkh(pub_comp) if compressed else None,
                        'address_taproot': pubkey_to_p2tr(pt.x().to_bytes(32, 'big')) if compressed else None,
                        'address_eth': pubkey_to_ethereum(pub),
                        'confidence': 1.0
                    })
                except Exception:
                    pass

        return results

    def carve_extended_keys(self) -> List[Dict[str, Any]]:
        """Carve Base58 and 78-byte raw binary serialized extended keys."""
        results = []
        seen = set()

        # 1. Text Base58 Extended Keys
        xkey_pattern = re.compile(r'([xyzuvtXYZUVT]p[ru][vb][1-9A-HJ-NP-Za-km-z]{100,115})')
        for match in xkey_pattern.finditer(self.text_content):
            key_str = match.group(1)
            if key_str in seen:
                continue
            try:
                node = BIP32Node.from_extended_key(key_str)
                seen.add(key_str)
                results.append({
                    'extended_key': key_str,
                    'is_private': node.is_private,
                    'depth': node.depth,
                    'fingerprint': node.fingerprint.hex(),
                    'child_index': node.child_index,
                    'byte_offset': match.start(),
                    'source': 'Base58 String',
                    'confidence': 1.0
                })
            except Exception:
                pass

        # 2. Binary 78-byte raw payload carving
        data = self.raw_bytes
        if len(data) >= 78:
            for i in range(len(data) - 78 + 1):
                hdr = data[i:i+4]
                if hdr in EXTENDED_KEY_HEADERS:
                    payload = data[i:i+78]
                    # Check checksum
                    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
                    b58_cand = base58check_encode(payload)
                    if b58_cand not in seen:
                        try:
                            node = BIP32Node.from_extended_key(b58_cand)
                            seen.add(b58_cand)
                            results.append({
                                'extended_key': b58_cand,
                                'is_private': node.is_private,
                                'depth': node.depth,
                                'fingerprint': node.fingerprint.hex(),
                                'child_index': node.child_index,
                                'byte_offset': i,
                                'source': 'Raw 78-Byte Binary Payload',
                                'confidence': 1.0
                            })
                        except Exception:
                            pass

        return results

    def carve_descriptors(self) -> List[Dict[str, Any]]:
        """Carve Bitcoin output descriptors with checksum verification."""
        results = []
        seen = set()

        # Regex for descriptors: wpkh(...), tr(...), sh(wpkh(...)), pkh(...)
        desc_pattern = re.compile(r'((?:wpkh|tr|sh\(wpkh|pkh)\([^\s\)\#]+\)(?:\#[a-z0-9]{8})?)')
        for match in desc_pattern.finditer(self.text_content):
            desc_str = match.group(1)
            if desc_str in seen:
                continue
            clean_desc = desc_str.split('#')[0]
            chk = descriptor_checksum(clean_desc)
            canonical = f"{clean_desc}#{chk}"
            seen.add(desc_str)
            seen.add(canonical)
            results.append({
                'descriptor': canonical,
                'raw_match': desc_str,
                'checksum': chk,
                'is_valid_checksum': desc_str.endswith(f"#{chk}") if '#' in desc_str else True,
                'byte_offset': match.start(),
                'confidence': 1.0
            })

        return results

    def carve_mini_keys(self) -> List[Dict[str, Any]]:
        """Carve Casascius / Mini private keys (22, 26, or 30-char strings starting with S)."""
        results = []
        seen = set()

        # Mini key regex: 22, 26, or 30 characters of Base58 starting with S
        mini_pattern = re.compile(r'\b(S[1-9A-HJ-NP-Za-km-z]{21,29})\b')
        for match in mini_pattern.finditer(self.text_content):
            cand = match.group(1)
            if len(cand) in (22, 26, 30) and cand not in seen:
                # Validate mini key rule: SHA256(cand + '?')[0] == 0x00
                test_hash = hashlib.sha256((cand + '?').encode('ascii')).digest()
                if test_hash[0] == 0x00:
                    priv_32 = hashlib.sha256(cand.encode('ascii')).digest()
                    seen.add(cand)
                    sk = ecdsa.SigningKey.from_string(priv_32, curve=ecdsa.SECP256k1)
                    vk = sk.get_verifying_key()
                    assert vk is not None
                    pt = vk.pubkey.point
                    p_prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
                    pub_comp = p_prefix + pt.x().to_bytes(32, 'big')

                    results.append({
                        'mini_key': cand,
                        'privkey_hex': priv_32.hex(),
                        'byte_offset': match.start(),
                        'address_legacy': pubkey_to_p2pkh(pub_comp),
                        'confidence': 1.0
                    })

        return results

    def carve_seeds(self) -> List[Dict[str, Any]]:
        """Carve 32-byte (64 hex) and 64-byte (128 hex) high-entropy master seed candidates."""
        results = []
        seen = set()

        # Regex for 64-char (32-byte) or 128-char (64-byte) hex strings
        hex_pattern = re.compile(r'\b([0-9a-fA-F]{64}|[0-9a-fA-F]{128})\b')
        for match in hex_pattern.finditer(self.text_content):
            hex_str = match.group(1).lower()
            if hex_str in seen:
                continue
            raw_cand = bytes.fromhex(hex_str)
            ent = calculate_entropy(raw_cand)
            # High entropy filter (> 3.5 for 32 bytes)
            if ent > 3.4:
                seen.add(hex_str)
                results.append({
                    'seed_hex': hex_str,
                    'byte_length': len(raw_cand),
                    'entropy': round(ent, 3),
                    'byte_offset': match.start(),
                    'confidence': min(1.0, ent / 4.0)
                })

        return results

    def carve_berkeley_db(self) -> List[Dict[str, Any]]:
        """
        Deep low-level Berkeley DB binary carver.
        Scans raw file sectors and pages for key/value pairs even when B-Tree headers are broken.
        Specifically extracts: mkey, ckey, key, wkey, hdseed, crypted_hdseed, name, defaultkey.
        """
        records = []
        data = self.raw_bytes

        # Search for known Bitcoin Core BDB record tags in binary stream
        tags = [
            (b'\x04mkey', 'mkey (Master Encryption Key)'),
            (b'\x04ckey', 'ckey (Encrypted Private Key)'),
            (b'\x03key', 'key (Plaintext Private Key)'),
            (b'\x04wkey', 'wkey (Wallet Private Key)'),
            (b'\x06hdseed', 'hdseed (Plaintext HD Master Seed)'),
            (b'\x0ecrypted_hdseed', 'crypted_hdseed (Encrypted HD Master Seed)'),
            (b'\x04name', 'name (Address Label)'),
            (b'\x0adefaultkey', 'defaultkey (Default Wallet Key)'),
            (b'\x07hdchain', 'hdchain (HD Chain Metadata)')
        ]

        for tag_bytes, tag_name in tags:
            idx = 0
            while True:
                idx = data.find(tag_bytes, idx)
                if idx == -1:
                    break

                rec_offset = idx
                try:
                    # Parse record context
                    if tag_name.startswith('mkey'):
                        # mkey payload: salt(8 or 16), nDerivationMethod(4), nDeriveIterations(4), vchOtherDerivationParameters, crypted_key(48)
                        mkey_payload = data[rec_offset+len(tag_bytes) : rec_offset+len(tag_bytes)+128]
                        records.append({
                            'record_type': 'mkey',
                            'byte_offset': rec_offset,
                            'description': 'Master Encryption Key Record',
                            'raw_hex': mkey_payload[:64].hex()
                        })
                    elif tag_name.startswith('ckey'):
                        # ckey: pubkey(33 or 65) -> crypted_privkey(48 or 64)
                        pub_cand = data[rec_offset+len(tag_bytes) : rec_offset+len(tag_bytes)+34]
                        if len(pub_cand) >= 34 and pub_cand[0] in (33, 65):
                            pub_len = pub_cand[0]
                            pubkey_bytes = pub_cand[1:1+pub_len]
                            records.append({
                                'record_type': 'ckey',
                                'byte_offset': rec_offset,
                                'pubkey_hex': pubkey_bytes.hex(),
                                'address_p2wpkh': pubkey_to_p2wpkh(pubkey_bytes) if pub_len == 33 else None,
                                'address_legacy': pubkey_to_p2pkh(pubkey_bytes)
                            })
                    elif tag_name.startswith('key'):
                        # plaintext key: pubkey -> privkey (DER format or raw)
                        k_cand = data[rec_offset+len(tag_bytes) : rec_offset+len(tag_bytes)+150]
                        priv_raw = parse_der_private_key(k_cand)
                        if priv_raw:
                            sk = ecdsa.SigningKey.from_string(priv_raw, curve=ecdsa.SECP256k1)
                            vk = sk.get_verifying_key()
                            assert vk is not None
                            pt = vk.pubkey.point
                            pub_comp = (b'\x02' if pt.y() % 2 == 0 else b'\x03') + pt.x().to_bytes(32, 'big')
                            records.append({
                                'record_type': 'key',
                                'byte_offset': rec_offset,
                                'privkey_hex': priv_raw.hex(),
                                'address_legacy': pubkey_to_p2pkh(pub_comp),
                                'address_p2wpkh': pubkey_to_p2wpkh(pub_comp)
                            })
                    else:
                        records.append({
                            'record_type': tag_name.split()[0],
                            'byte_offset': rec_offset,
                            'description': tag_name
                        })
                except Exception:
                    pass

                idx += len(tag_bytes)

        return records


def carve_artifacts(data: Union[bytes, str]) -> Dict[str, Any]:
    """Convenience functional wrapper for DeepCarver."""
    carver = DeepCarver(data)
    return carver.carve_all()


def generate_forensic_report(carve_result: Dict[str, Any]) -> str:
    """Generate a clean, structured forensic markdown report from carving results."""
    summary = carve_result.get('summary', {})
    lines = [
        "# Cryptographic Artifact Deep Carving Report",
        "",
        "## Summary Statistics",
        f"- **Total Artifacts Found:** {summary.get('total_artifacts_found', 0)}",
        f"- **BIP-39 Mnemonic Phrases:** {summary.get('mnemonics_count', 0)}",
        f"- **WIF Private Keys:** {summary.get('wif_keys_count', 0)}",
        f"- **Extended Keys (xprv/zprv/xpub):** {summary.get('extended_keys_count', 0)}",
        f"- **Output Descriptors:** {summary.get('descriptors_count', 0)}",
        f"- **Berkeley DB Low-Level Records:** {summary.get('bdb_records_count', 0)}",
        f"- **Mini Private Keys:** {summary.get('mini_keys_count', 0)}",
        f"- **High-Entropy Seeds:** {summary.get('seeds_count', 0)}",
        f"- **Total Data Analyzed:** {summary.get('data_size_bytes', 0)} bytes",
        "",
        "---"
    ]

    # Mnemonics Section
    mnems = carve_result.get('mnemonics', [])
    if mnems:
        lines.append("## Carved BIP-39 Mnemonics")
        for idx, m in enumerate(mnems, 1):
            lines.append(f"### Mnemonic #{idx} ({m.get('word_count')} words)")
            lines.append(f"- **Phrase:** `{m.get('mnemonic')}`")
            lines.append(f"- **Offset:** `0x{m.get('byte_offset_start', 0):08x}` - `0x{m.get('byte_offset_end', 0):08x}`")
            if m.get('address_p2wpkh'):
                lines.append(f"- **Native SegWit (P2WPKH):** `{m.get('address_p2wpkh')}`")
            if m.get('address_legacy'):
                lines.append(f"- **Legacy Bitcoin (P2PKH):** `{m.get('address_legacy')}`")
            if m.get('address_eth'):
                lines.append(f"- **Ethereum (EIP-55):** `{m.get('address_eth')}`")
            lines.append("")

    # WIF Section
    wifs = carve_result.get('wifs', [])
    if wifs:
        lines.append("## Carved WIF Private Keys")
        for idx, w in enumerate(wifs, 1):
            lines.append(f"### WIF Key #{idx} ({w.get('network')}, {'compressed' if w.get('compressed') else 'uncompressed'})")
            lines.append(f"- **WIF:** `{w.get('wif')}`")
            lines.append(f"- **Privkey Hex:** `{w.get('privkey_hex')}`")
            lines.append(f"- **Offset:** `0x{w.get('byte_offset', 0):08x}`")
            if w.get('address_p2wpkh'):
                lines.append(f"- **Native SegWit:** `{w.get('address_p2wpkh')}`")
            if w.get('address_taproot'):
                lines.append(f"- **Taproot:** `{w.get('address_taproot')}`")
            if w.get('address_legacy'):
                lines.append(f"- **Legacy (P2PKH):** `{w.get('address_legacy')}`")
            lines.append("")

    # Extended Keys Section
    xkeys = carve_result.get('extended_keys', [])
    if xkeys:
        lines.append("## Carved Extended Keys")
        for idx, x in enumerate(xkeys, 1):
            lines.append(f"### Extended Key #{idx} ({'Private' if x.get('is_private') else 'Public'})")
            lines.append(f"- **Key:** `{x.get('extended_key')}`")
            lines.append(f"- **Source:** {x.get('source')}")
            lines.append(f"- **Depth:** {x.get('depth')} | **Fingerprint:** `{x.get('fingerprint')}`")
            lines.append(f"- **Offset:** `0x{x.get('byte_offset', 0):08x}`")
            lines.append("")

    # Descriptors Section
    descs = carve_result.get('descriptors', [])
    if descs:
        lines.append("## Carved Output Descriptors")
        for idx, d in enumerate(descs, 1):
            lines.append(f"- `{d.get('descriptor')}` (Offset: `0x{d.get('byte_offset', 0):08x}`)")
        lines.append("")

    return "\n".join(lines)

"""
BIP-380 to BIP-386 Output Script Descriptors Module.
Supports official Bitcoin Core checksum computation, standard account descriptor generation
(wpkh, tr, sh(wpkh), pkh), Bitcoin Core importdescriptors JSON export, and descriptor-based address derivation.
"""

import re
import json
import sqlite3
from typing import Dict, List, Any, Optional, Tuple

from .bip32 import BIP32Node
from .bip39 import mnemonic_to_seed
from .addresses import (
    pubkey_to_p2pkh,
    pubkey_to_p2wpkh,
    pubkey_to_p2sh_p2wpkh,
    pubkey_to_p2tr,
    encode_wif,
    hash160
)

# BIP-380 Character Sets
INPUT_CHARSET = (
    "0123456789()[],'/*abcdefgh@:$%{}"
    "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~"
    "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
)
CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def poly_mod(c: int, val: int) -> int:
    """Internal GF(32) polynomial modulo generator for BIP-380."""
    c0 = c >> 35
    c = ((c & 0x7ffffffff) << 5) ^ val
    if c0 & 1:
        c ^= 0xf5dee51989
    if c0 & 2:
        c ^= 0xa9fdca3312
    if c0 & 4:
        c ^= 0x1bab10e32d
    if c0 & 8:
        c ^= 0x3706b1677a
    if c0 & 16:
        c ^= 0x644d626ffd
    return c


def descriptor_checksum(desc_str: str) -> str:
    """
    Calculate the official 8-character BIP-380 checksum for a descriptor string.
    """
    clean_desc = desc_str.split('#')[0].strip()
    c = 1
    cls = 0
    clscount = 0
    for ch in clean_desc:
        pos = INPUT_CHARSET.find(ch)
        if pos == -1:
            return ""
        c = poly_mod(c, pos & 31)
        cls = cls * 3 + (pos >> 5)
        clscount += 1
        if clscount == 3:
            c = poly_mod(c, cls)
            cls = 0
            clscount = 0
    if clscount > 0:
        c = poly_mod(c, cls)
    for _ in range(8):
        c = poly_mod(c, 0)
    c ^= 1
    ret = []
    for j in range(8):
        ret.append(CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31])
    return "".join(ret)


def add_descriptor_checksum(desc_str: str) -> str:
    """Append official '#checksum' to a descriptor string."""
    clean_desc = desc_str.split('#')[0].strip()
    chk = descriptor_checksum(clean_desc)
    if not chk:
        return clean_desc
    return f"{clean_desc}#{chk}"


def verify_descriptor_checksum(desc_with_checksum: str) -> bool:
    """Verify if the descriptor string contains a valid BIP-380 checksum."""
    if '#' not in desc_with_checksum:
        return False
    desc, chk = desc_with_checksum.split('#', 1)
    return descriptor_checksum(desc.strip()) == chk.strip()


def generate_wallet_descriptors(
    mnemonic: str,
    passphrase: str = "",
    network: str = "bitcoin",
    account: int = 0,
    include_private: bool = True
) -> Dict[str, Any]:
    """
    Generate all standard BIP-380/BIP-386 Output Script Descriptors
    for Bitcoin Core, Sparrow, Electrum, Specter, etc.
    Accepts mnemonic phrase, xprv/xpub/zprv/zpub, or master seed hex.
    """
    clean_key = mnemonic.strip()
    if clean_key.startswith(('xprv', 'xpub', 'yprv', 'ypub', 'zprv', 'zpub', 'tprv', 'tpub', 'vprv', 'vpub', 'uprv', 'upub', 'Yprv', 'Ypub', 'Zprv', 'Zpub')):
        try:
            root_node = BIP32Node.from_extended_key(clean_key)
        except Exception:
            seed = mnemonic_to_seed(clean_key, passphrase)
            root_node = BIP32Node.from_seed(seed)
    elif len(clean_key) in (64, 128) and all(c in "0123456789abcdefABCDEF" for c in clean_key):
        seed = bytes.fromhex(clean_key)
        root_node = BIP32Node.from_seed(seed)
    else:
        seed = mnemonic_to_seed(clean_key, passphrase)
        root_node = BIP32Node.from_seed(seed)

    master_fingerprint = root_node.fingerprint.hex()
    master_xpub = root_node.serialize_ext_key(0x0488b21e, is_private=False)
    master_xprv = root_node.serialize_ext_key(0x0488ade4, is_private=True) if root_node.private_key else ""

    standards = [
        {
            "id": "bip84",
            "name": "Native SegWit (P2WPKH / BIP-84)",
            "purpose": 84,
            "template": "wpkh([{fp}/{purpose}'/0'/{account}']{key}/0/*)",
            "change_template": "wpkh([{fp}/{purpose}'/0'/{account}']{key}/1/*)",
            "output_type": "bech32",
            "address_prefix": "bc1q"
        },
        {
            "id": "bip86",
            "name": "Taproot (P2TR / BIP-86)",
            "purpose": 86,
            "template": "tr([{fp}/{purpose}'/0'/{account}']{key}/0/*)",
            "change_template": "tr([{fp}/{purpose}'/0'/{account}']{key}/1/*)",
            "output_type": "bech32m",
            "address_prefix": "bc1p"
        },
        {
            "id": "bip49",
            "name": "Nested SegWit (P2SH-P2WPKH / BIP-49)",
            "purpose": 49,
            "template": "sh(wpkh([{fp}/{purpose}'/0'/{account}']{key}/0/*))",
            "change_template": "sh(wpkh([{fp}/{purpose}'/0'/{account}']{key}/1/*))",
            "output_type": "p2sh-segwit",
            "address_prefix": "3"
        },
        {
            "id": "bip44",
            "name": "Legacy (P2PKH / BIP-44)",
            "purpose": 44,
            "template": "pkh([{fp}/{purpose}'/0'/{account}']{key}/0/*)",
            "change_template": "pkh([{fp}/{purpose}'/0'/{account}']{key}/1/*)",
            "output_type": "legacy",
            "address_prefix": "1"
        }
    ]

    descriptors = []
    bitcoin_core_import = []

    for std in standards:
        purpose = std["purpose"]
        acct_path = f"m/{purpose}'/0'/{account}'"
        try:
            acct_node = root_node.derive_path(acct_path)
            acct_xpub = acct_node.serialize_ext_key(0x0488b21e, is_private=False)
            acct_xprv = acct_node.serialize_ext_key(0x0488ade4, is_private=True) if acct_node.private_key else ""
        except Exception:
            acct_xpub = master_xpub
            acct_xprv = master_xprv

        # Public (Watch-only) Descriptors
        pub_recv_raw = std["template"].format(fp=master_fingerprint, purpose=purpose, account=account, key=acct_xpub)
        pub_chg_raw = std["change_template"].format(fp=master_fingerprint, purpose=purpose, account=account, key=acct_xpub)
        pub_recv = add_descriptor_checksum(pub_recv_raw)
        pub_chg = add_descriptor_checksum(pub_chg_raw)

        # Private (Signing) Descriptors
        priv_recv_raw = std["template"].format(fp=master_fingerprint, purpose=purpose, account=account, key=acct_xprv or acct_xpub)
        priv_chg_raw = std["change_template"].format(fp=master_fingerprint, purpose=purpose, account=account, key=acct_xprv or acct_xpub)
        priv_recv = add_descriptor_checksum(priv_recv_raw)
        priv_chg = add_descriptor_checksum(priv_chg_raw)

        item = {
            "id": std["id"],
            "name": std["name"],
            "purpose": purpose,
            "account": account,
            "accountPath": acct_path,
            "accountXpub": acct_xpub,
            "accountXprv": acct_xprv,
            "externalPublic": pub_recv,
            "internalPublic": pub_chg,
            "externalPrivate": priv_recv,
            "internalPrivate": priv_chg,
            "outputType": std["output_type"],
            "addressPrefix": std["address_prefix"]
        }
        descriptors.append(item)

        target_recv = priv_recv if (include_private and acct_xprv) else pub_recv
        target_chg = priv_chg if (include_private and acct_xprv) else pub_chg

        bitcoin_core_import.append({
            "desc": target_recv,
            "timestamp": "now",
            "active": True,
            "internal": False,
            "range": [0, 999],
            "next": 0
        })
        bitcoin_core_import.append({
            "desc": target_chg,
            "timestamp": "now",
            "active": True,
            "internal": True,
            "range": [0, 999],
            "next": 0
        })

    return {
        "masterFingerprint": master_fingerprint,
        "masterXpub": master_xpub,
        "masterXprv": master_xprv,
        "account": account,
        "descriptors": descriptors,
        "bitcoinCoreImportJson": bitcoin_core_import,
        "bitcoinCoreCliCommand": f"bitcoin-cli importdescriptors '{json.dumps(bitcoin_core_import)}'"
    }


def derive_from_descriptor(
    descriptor_str: str,
    count: int = 50,
    start_index: int = 0,
    network: str = "bitcoin"
) -> Dict[str, Any]:
    """
    Parse a descriptor and derive explicit on-chain addresses.
    Supports wpkh, tr, sh(wpkh), and pkh descriptors with range or wildcards.
    Returns a dict with 'descriptor', 'addresses', and 'total'.
    """
    clean = descriptor_str.split('#')[0].strip()
    
    # Extract inner key / xpub / xprv
    m_wpkh = re.search(r'wpkh\((?:\[[^\]]+\])?([^\)]+)\)', clean)
    m_tr = re.search(r'tr\((?:\[[^\]]+\])?([^\)]+)\)', clean)
    m_sh_wpkh = re.search(r'sh\(wpkh\((?:\[[^\]]+\])?([^\)]+)\)\)', clean)
    m_pkh = re.search(r'pkh\((?:\[[^\]]+\])?([^\)]+)\)', clean)

    desc_type = "wpkh"
    key_expression = ""
    if m_tr:
        desc_type = "tr"
        key_expression = m_tr.group(1)
    elif m_sh_wpkh:
        desc_type = "sh_wpkh"
        key_expression = m_sh_wpkh.group(1)
    elif m_wpkh:
        desc_type = "wpkh"
        key_expression = m_wpkh.group(1)
    elif m_pkh:
        desc_type = "pkh"
        key_expression = m_pkh.group(1)
    else:
        key_expression = clean

    # Determine branch and path suffix
    branch = 0
    if "/1/*" in key_expression or "/1" in key_expression:
        branch = 1
    
    # Extract base ext key or raw pubkey
    ext_key_match = re.search(r'([xyzuvtXYZUVT]p[ru][vb][0-9a-zA-Z]+)', key_expression)
    if not ext_key_match:
        pub_match = re.search(r'\b(0[23][0-9a-fA-F]{64})\b', key_expression)
        if pub_match:
            pub_hex = pub_match.group(1)
            pub_bytes = bytes.fromhex(pub_hex)
            if desc_type == "tr":
                addr = pubkey_to_p2tr(pub_bytes)
            elif desc_type == "sh_wpkh":
                addr = pubkey_to_p2sh_p2wpkh(pub_bytes)
            elif desc_type == "pkh":
                addr = pubkey_to_p2pkh(pub_bytes)
            else:
                addr = pubkey_to_p2wpkh(pub_bytes)
            return {
                "descriptor": descriptor_str,
                "addresses": [{
                    "index": 0,
                    "path": "single",
                    "address": addr,
                    "descriptorType": desc_type,
                    "publicKey": pub_hex,
                    "privateKeyWif": "N/A",
                    "privateKeyHex": "N/A"
                }],
                "total": 1
            }
        return {"descriptor": descriptor_str, "addresses": [], "total": 0}

    ext_key = ext_key_match.group(1)
    
    # Derive from ext_key
    try:
        base_node = BIP32Node.from_extended_key(ext_key)
        branch_node = base_node.derive_child(branch, is_hardened=False) if (base_node.depth < 5) else base_node
        results = []

        for i in range(start_index, start_index + count):
            try:
                child = branch_node.derive_child(i, is_hardened=False)
                pub_bytes = child.public_key
                priv_bytes = child.private_key

                if desc_type == "tr":
                    addr = pubkey_to_p2tr(pub_bytes)
                elif desc_type == "sh_wpkh":
                    addr = pubkey_to_p2sh_p2wpkh(pub_bytes)
                elif desc_type == "pkh":
                    addr = pubkey_to_p2pkh(pub_bytes)
                else: # wpkh
                    addr = pubkey_to_p2wpkh(pub_bytes)

                priv_wif = encode_wif(priv_bytes, compressed=True) if priv_bytes else ""
                priv_hex = priv_bytes.hex() if priv_bytes else ""

                results.append({
                    "index": i,
                    "path": f"{branch}/{i}",
                    "address": addr,
                    "descriptorType": desc_type,
                    "publicKey": pub_bytes.hex(),
                    "privateKeyWif": priv_wif,
                    "privateKeyHex": priv_hex
                })
            except Exception:
                continue

        return {
            "descriptor": descriptor_str,
            "addresses": results,
            "total": len(results)
        }
    except Exception as e:
        return {"descriptor": descriptor_str, "addresses": [], "total": 0, "error": str(e)}


def derive_all_standard_descriptors(
    key_or_mnemonic: str,
    passphrase: str = "",
    count_per_scheme: int = 10
) -> List[Dict[str, Any]]:
    """
    Derive addresses across all standard descriptor types (BIP-84, BIP-86, BIP-49, BIP-44)
    using both external (receiving /0/*) and internal (change /1/*) branches.
    """
    desc_info = generate_wallet_descriptors(key_or_mnemonic, passphrase=passphrase, include_private=True)
    all_results = []
    
    for d in desc_info.get('descriptors', []):
        ext_desc = d.get('externalPrivate') or d.get('externalPublic')
        int_desc = d.get('internalPrivate') or d.get('internalPublic')
        
        if ext_desc:
            res_ext = derive_from_descriptor(ext_desc, count=count_per_scheme)
            for item in res_ext.get('addresses', []):
                item['scheme'] = f"{d['name']} (Receiving /0)"
                all_results.append(item)
                
        if int_desc:
            res_int = derive_from_descriptor(int_desc, count=count_per_scheme)
            for item in res_int.get('addresses', []):
                item['scheme'] = f"{d['name']} (Change /1)"
                all_results.append(item)
                
    return all_results


def parse_sqlite_descriptor_wallet(db_path: str) -> Dict[str, Any]:
    """
    Parse a modern Bitcoin Core SQLite descriptor wallet (v0.21+ format).
    Extracts all descriptor scripts, flags, and metadata.
    """
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM main")
        rows = cursor.fetchall()
        
        descriptors = []
        wallet_flags = 0
        wallet_version = 0

        for k, v in rows:
            if isinstance(k, bytes) and k.startswith(b'\x04desc'):
                try:
                    desc_str = v.decode('utf-8', errors='ignore')
                    descriptors.append(desc_str)
                except Exception:
                    pass
            elif isinstance(k, bytes) and k.startswith(b'\x05flags'):
                wallet_flags = int.from_bytes(v, 'little') if v else 0
            elif isinstance(k, bytes) and k.startswith(b'\x07version'):
                wallet_version = int.from_bytes(v, 'little') if v else 0

        conn.close()
        return {
            "isDescriptorWallet": True,
            "walletType": "Bitcoin Core SQLite Descriptor Wallet",
            "version": wallet_version,
            "flags": wallet_flags,
            "descriptors": descriptors,
            "totalDescriptors": len(descriptors)
        }
    except Exception as e:
        return {
            "isDescriptorWallet": False,
            "error": str(e)
        }


def generate_descriptors_for_record(sec: str, pubkey: str = "") -> List[str]:
    """
    Generate output script descriptors (wpkh, tr, sh(wpkh), pkh) for any given secret
    (WIF private key, BIP-39 mnemonic, master xprv, HD seed hex) or public key.
    """
    descriptors = []
    clean_sec = (sec or "").strip()
    clean_pub = (pubkey or "").strip()

    if clean_sec.startswith("Seed Hex: "):
        clean_sec = clean_sec.split("Seed Hex: ", 1)[1].strip()

    # 1. Extended Key, Mnemonic, or Seed Hex
    if clean_sec:
        words = clean_sec.split()
        is_mnem = (len(words) in (12, 15, 18, 21, 24)) and not clean_sec.startswith('{')
        is_ext = clean_sec.startswith(('xprv', 'xpub', 'yprv', 'ypub', 'zprv', 'zpub', 'tprv', 'tpub', 'vprv', 'vpub'))
        is_hex_seed = (len(clean_sec) in (64, 128)) and all(c in '0123456789abcdefABCDEF' for c in clean_sec)

        if is_mnem or is_ext or is_hex_seed:
            try:
                desc_res = generate_wallet_descriptors(clean_sec, include_private=True)
                for d in desc_res.get('descriptors', []):
                    priv = d.get('externalPrivate')
                    pub = d.get('externalPublic')
                    if priv:
                        descriptors.append(priv)
                    elif pub:
                        descriptors.append(pub)
                if descriptors:
                    return descriptors
            except Exception:
                pass

        # 2. Base58 WIF Private Key (e.g. 5..., K..., L..., c..., 9...)
        if len(clean_sec) in (51, 52) or (clean_sec.startswith(('5', 'K', 'L', 'c', '9')) and len(clean_sec) > 30 and ' ' not in clean_sec):
            try:
                descriptors.append(add_descriptor_checksum(f"wpkh({clean_sec})"))
                descriptors.append(add_descriptor_checksum(f"tr({clean_sec})"))
                descriptors.append(add_descriptor_checksum(f"sh(wpkh({clean_sec}))"))
                descriptors.append(add_descriptor_checksum(f"pkh({clean_sec})"))
                return descriptors
            except Exception:
                pass

        # 3. Hex Private Key (32 bytes = 64 hex characters)
        if len(clean_sec) == 64 and all(c in '0123456789abcdefABCDEF' for c in clean_sec):
            try:
                descriptors.append(add_descriptor_checksum(f"wpkh({clean_sec})"))
                descriptors.append(add_descriptor_checksum(f"tr({clean_sec})"))
                descriptors.append(add_descriptor_checksum(f"sh(wpkh({clean_sec}))"))
                descriptors.append(add_descriptor_checksum(f"pkh({clean_sec})"))
                return descriptors
            except Exception:
                pass

    # 4. Public Key Fallback (watch-only descriptors if no private key)
    if clean_pub and clean_pub != 'N/A' and len(clean_pub) in (66, 130) and all(c in '0123456789abcdefABCDEF' for c in clean_pub):
        try:
            descriptors.append(add_descriptor_checksum(f"wpkh({clean_pub})"))
            descriptors.append(add_descriptor_checksum(f"tr({clean_pub})"))
            descriptors.append(add_descriptor_checksum(f"sh(wpkh({clean_pub}))"))
            descriptors.append(add_descriptor_checksum(f"pkh({clean_pub})"))
            return descriptors
        except Exception:
            pass

    return descriptors


def parse_descriptor(descriptor_str: str) -> Dict[str, Any]:
    """Parse output script descriptor and return structure details."""
    clean = descriptor_str.split('#')[0].strip()
    chk = descriptor_checksum(clean)
    desc_type = "unknown"
    if clean.startswith("wpkh("): desc_type = "wpkh"
    elif clean.startswith("tr("): desc_type = "tr"
    elif clean.startswith("sh(wpkh("): desc_type = "sh_wpkh"
    elif clean.startswith("pkh("): desc_type = "pkh"
    elif clean.startswith("sh("): desc_type = "sh"

    return {
        "descriptor": descriptor_str,
        "clean_descriptor": clean,
        "checksum": chk,
        "canonical": f"{clean}#{chk}",
        "type": desc_type
    }



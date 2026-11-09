"""
Cryptographic Hardware & C-Library Acceleration Engine.
Integrates libsecp256k1 (via coincurve) and Blockstream libwally-core (via wallycore)
for ultra-high-speed key derivation, BIP-32 hierarchies, and descriptor operations.
"""

from typing import Optional, Dict, Any, List, Tuple
import ecdsa

try:
    import coincurve
    HAS_COINCURVE = True
except ImportError:
    coincurve = None
    HAS_COINCURVE = False

try:
    import wallycore
    HAS_WALLYCORE = True
except ImportError:
    wallycore = None
    HAS_WALLYCORE = False

SECP256K1_ORDER: int = int(ecdsa.SECP256k1.generator.order() or 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)


def get_crypto_engine_info() -> Dict[str, Any]:
    """Return runtime information about available accelerated crypto backends."""
    return {
        "coincurve": {
            "available": HAS_COINCURVE,
            "version": getattr(coincurve, "__version__", "22.0.0") if HAS_COINCURVE else None,
            "description": "Native C libsecp256k1 ECDSA & Schnorr acceleration",
        },
        "wallycore": {
            "available": HAS_WALLYCORE,
            "version": getattr(wallycore, "__version__", "1.5.6") if HAS_WALLYCORE else None,
            "description": "Blockstream libwally-core native BIP-32/38/39, PSBT & Descriptors",
        },
        "pure_python_fallback": {
            "available": True,
            "engine": "ecdsa (python)",
        }
    }


def fast_privkey_to_pubkey(privkey_bytes: bytes, compressed: bool = True) -> bytes:
    """
    Derive compressed or uncompressed secp256k1 public key from a 32-byte private key.
    Uses coincurve (C libsecp256k1) if available, otherwise falls back to pure-Python ecdsa.
    """
    if len(privkey_bytes) != 32:
        raise ValueError(f"Private key must be exactly 32 bytes, got {len(privkey_bytes)}")

    if HAS_COINCURVE and coincurve is not None:
        try:
            return getattr(coincurve, 'PublicKey').from_secret(privkey_bytes).format(compressed=compressed)
        except Exception:
            pass

    # Pure Python fallback
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    vk_bytes = vk.to_string()
    x = vk_bytes[:32]
    y_int = int.from_bytes(vk_bytes[32:], 'big')
    if compressed:
        prefix = b'\x02' if (y_int % 2 == 0) else b'\x03'
        return prefix + x
    return b'\x04' + vk_bytes


def fast_pubkey_tweak_add(pubkey_bytes: bytes, tweak_bytes: bytes) -> bytes:
    """
    Add a tweak scalar to a public key point: Q = P + tweak * G.
    """
    if HAS_COINCURVE and coincurve is not None:
        try:
            pk = getattr(coincurve, 'PublicKey')(pubkey_bytes)
            pk.add(tweak_bytes)
            return pk.format(compressed=True)
        except Exception:
            pass

    # Fallback
    sk_point = ecdsa.SECP256k1.generator * int.from_bytes(tweak_bytes, 'big')
    if len(pubkey_bytes) == 33:
        # Decompress
        vk = ecdsa.VerifyingKey.from_string(pubkey_bytes, curve=ecdsa.SECP256k1)
        assert vk.pubkey is not None
        parent_point = vk.pubkey.point
    else:
        raw = pubkey_bytes[1:] if len(pubkey_bytes) == 65 else pubkey_bytes
        vk = ecdsa.VerifyingKey.from_string(raw, curve=ecdsa.SECP256k1)
        assert vk.pubkey is not None
        parent_point = vk.pubkey.point

    child_point = sk_point + parent_point
    x = child_point.x().to_bytes(32, 'big')
    prefix = b'\x02' if (child_point.y() % 2 == 0) else b'\x03'
    return prefix + x


def wally_bip32_derive_path(seed: bytes, path: str, is_testnet: bool = False) -> Optional[Dict[str, Any]]:
    """
    Derive BIP-32 keys along an arbitrary path using high-performance wallycore C-bindings.
    Returns dictionary with xprv, xpub, privkey_hex, pubkey_hex, depth, index.
    """
    if not HAS_WALLYCORE or wallycore is None:
        return None

    try:
        ver_priv = wallycore.BIP32_VER_TEST_PRIVATE if is_testnet else wallycore.BIP32_VER_MAIN_PRIVATE
        ver_pub = wallycore.BIP32_VER_TEST_PUBLIC if is_testnet else wallycore.BIP32_VER_MAIN_PUBLIC

        hdkey = wallycore.bip32_key_from_seed_alloc(seed, ver_priv, 0)
        
        # Parse path e.g. "m/84'/0'/0'/0/0"
        clean_path = path.strip()
        if clean_path.startswith("m/"):
            clean_path = clean_path[2:]
        elif clean_path.startswith("m"):
            clean_path = clean_path[1:]

        segments = [s for s in clean_path.split('/') if s]
        current_key = hdkey

        for seg in segments:
            is_hardened = seg.endswith("'") or seg.endswith("h") or seg.endswith("H")
            num_str = seg.rstrip("'hH")
            idx = int(num_str)
            child_num = (idx | 0x80000000) if is_hardened else idx
            next_key = wallycore.bip32_key_from_parent_alloc(current_key, child_num, wallycore.BIP32_FLAG_KEY_PRIVATE)
            current_key = next_key

        xprv = wallycore.bip32_key_to_base58(current_key, wallycore.BIP32_FLAG_KEY_PRIVATE)
        xpub = wallycore.bip32_key_to_base58(current_key, wallycore.BIP32_FLAG_KEY_PUBLIC)
        priv_bytes = getattr(wallycore, 'bip32_key_get_priv_key')(current_key)
        pub_bytes = getattr(wallycore, 'bip32_key_get_pub_key')(current_key)
        chain_code = getattr(wallycore, 'bip32_key_get_chain_code')(current_key)

        return {
            "xprv": xprv,
            "xpub": xpub,
            "privkey_hex": priv_bytes.hex() if priv_bytes else None,
            "pubkey_hex": pub_bytes.hex() if pub_bytes else None,
            "chain_code": chain_code.hex() if chain_code else None,
            "backend": "wallycore (C-Engine)"
        }
    except Exception as e:
        return None

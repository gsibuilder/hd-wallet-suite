"""
Cryptographic utility functions and address formatters for 18 supported blockchains.
"""

import hashlib
import base58
from typing import Optional

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
except ImportError:
    ed25519 = None

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
RIPPLE_ALPHABET = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash160(data: bytes) -> bytes:
    """RIPEMD160(SHA256(data))"""
    return hashlib.new('ripemd160', sha256(data)).digest()


def base58check_encode(payload: bytes) -> str:
    """Base58Check encoding with double SHA-256 checksum."""
    checksum = sha256(sha256(payload))[:4]
    return base58.b58encode(payload + checksum).decode('ascii')


def base58check_decode(encoded: str) -> bytes:
    """Base58Check decoding with double SHA-256 checksum verification."""
    raw = base58.b58decode(encoded.strip())
    if len(raw) < 4:
        raise ValueError("Invalid Base58Check string: too short")
    payload = raw[:-4]
    checksum = raw[-4:]
    if sha256(sha256(payload))[:4] != checksum:
        raise ValueError("Invalid Base58Check checksum")
    return payload


def b58encode_ripple(data: bytes) -> str:
    """Ripple Base58 encoding with leading zero padding."""
    val = int.from_bytes(data, byteorder='big')
    res = []
    while val > 0:
        val, mod = divmod(val, 58)
        res.append(RIPPLE_ALPHABET[mod])
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    res.extend([RIPPLE_ALPHABET[0]] * pad)
    return ''.join(reversed(res))


def encode_wif(private_key_bytes: bytes, prefix: bytes = b'\x80', compressed: bool = True) -> str:
    """Encode raw private key into Wallet Import Format (WIF)."""
    payload = prefix + private_key_bytes
    if compressed:
        payload += b'\x01'
    return base58check_encode(payload)


def decode_wif(wif_str: str) -> tuple[bytes, bool, int]:
    """
    Decode WIF string into (private_key_bytes, is_compressed, prefix_byte).
    Supports Bitcoin mainnet (0x80), testnet (0xef), and altcoin prefixes.
    """
    raw = base58.b58decode(wif_str.strip())
    if len(raw) < 37:
        raise ValueError("Invalid WIF length")
    payload = raw[:-4]
    checksum = raw[-4:]
    if sha256(sha256(payload))[:4] != checksum:
        raise ValueError("Invalid WIF checksum")
    prefix = payload[0]
    data = payload[1:]
    if len(data) == 33 and data[-1] == 0x01:
        return data[:-1], True, prefix
    elif len(data) == 32:
        return data, False, prefix
    else:
        raise ValueError(f"Invalid private key payload length in WIF: {len(data)}")


def is_valid_wif(wif_str: str) -> bool:
    """Check if string is a valid Base58Check WIF private key."""
    if not isinstance(wif_str, str):
        return False
    w = wif_str.strip()
    if len(w) < 40 or len(w) > 60:
        return False
    try:
        decode_wif(w)
        return True
    except Exception:
        return False


# --- Bech32 & Bech32m Implementation ---

def _bech32_polymod(values: list[int]) -> int:
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk


def _hrp_expand(hrp: str) -> list[int]:
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _create_checksum(hrp: str, data: list[int], spec: str = 'bech32') -> list[int]:
    values = _hrp_expand(hrp) + data
    const = 0x2bc830a3 if spec == 'bech32m' else 1
    polymod = _bech32_polymod(values + [0] * 6) ^ const
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: bytes, frombits: int, tobits: int, pad: bool = True) -> Optional[list[int]]:
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


def encode_bech32(hrp: str, witness_version: int, witness_program: bytes) -> str:
    spec = 'bech32m' if witness_version > 0 else 'bech32'
    converted = _convertbits(witness_program, 8, 5)
    if converted is None:
        raise ValueError("Failed to convert bits for Bech32 encoding")
    data = [witness_version] + converted
    checksum = _create_checksum(hrp, data, spec)
    return hrp + '1' + ''.join([CHARSET[d] for d in data + checksum])


def _bech32_verify_checksum(hrp: str, data: list[int]) -> Optional[str]:
    polymod = _bech32_polymod(_hrp_expand(hrp) + data)
    if polymod == 1:
        return 'bech32'
    if polymod == 0x2bc830a3:
        return 'bech32m'
    return None


def decode_bech32(bech: str) -> tuple[Optional[str], Optional[list[int]], Optional[str]]:
    """Decode a Bech32 or Bech32m string into (hrp, data, spec)."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return None, None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None, None
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None, None
    if not all(x in CHARSET for x in bech[pos + 1:]):
        return None, None, None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos + 1:]]
    spec = _bech32_verify_checksum(hrp, data)
    if spec is None:
        return None, None, None
    return hrp, data[:-6], spec


# --- Multichain Address Generators ---

def pubkey_to_p2pkh(pubkey_bytes: bytes, prefix: bytes = b'\x00') -> str:
    """Generate P2PKH address (Legacy 1... / m... / n... / D... / t1...)."""
    pkh = hash160(pubkey_bytes)
    return base58check_encode(prefix + pkh)


def pubkey_to_p2sh_p2wpkh(pubkey_bytes: bytes, prefix: bytes = b'\x05') -> str:
    """Generate P2SH-P2WPKH address (Nested SegWit 3... / 2... / M...)."""
    pkh = hash160(pubkey_bytes)
    redeem_script = b'\x00\x14' + pkh
    sh = hash160(redeem_script)
    return base58check_encode(prefix + sh)


def pubkey_to_p2wpkh(pubkey_bytes: bytes, hrp: str = 'bc') -> str:
    """Generate P2WPKH address (Native SegWit Bech32 bc1q... / tb1q... / ltc1...)."""
    pkh = hash160(pubkey_bytes)
    return encode_bech32(hrp, 0, pkh)


def pubkey_to_p2tr(pubkey_bytes: bytes, hrp: str = 'bc') -> str:
    """Generate P2TR address (Taproot Bech32m bc1p... / tb1p...)."""
    x_only = pubkey_bytes[1:33] if len(pubkey_bytes) == 33 else pubkey_bytes[:32]
    return encode_bech32(hrp, 1, x_only)


def keccak256_bytes(data: bytes) -> bytes:
    """True Keccak-256 hash (as used by Ethereum / TRON)."""
    try:
        from eth_hash.auto import keccak  # type: ignore
        return keccak(data)
    except Exception:
        try:
            from eth_utils import keccak  # type: ignore
            return keccak(data)
        except Exception:
            try:
                from pysha3 import keccak_256  # type: ignore
                return keccak_256(data).digest()
            except Exception:
                import hashlib
                return hashlib.sha3_256(data).digest()


def pubkey_to_ethereum(uncompressed_pubkey_bytes: bytes) -> str:
    """Ethereum / EVM Address (0x... EIP-55)."""
    if len(uncompressed_pubkey_bytes) == 65 and uncompressed_pubkey_bytes[0] == 4:
        uncompressed_pubkey_bytes = uncompressed_pubkey_bytes[1:]
    
    k = keccak256_bytes(uncompressed_pubkey_bytes).hex()
    raw_addr = k[-40:].lower()
    
    hash_hex = keccak256_bytes(raw_addr.encode('utf-8')).hex()
    
    checksummed = ""
    for i, char in enumerate(raw_addr):
        if char in "0123456789":
            checksummed += char
        elif int(hash_hex[i], 16) >= 8:
            checksummed += char.upper()
        else:
            checksummed += char
            
    return "0x" + checksummed


def privkey_to_solana(privkey_bytes: bytes) -> str:
    """Solana Address (Base58 of Ed25519 pubkey)."""
    if ed25519:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes[:32])
        pub_bytes = pk.public_key().public_bytes_raw()
        return base58.b58encode(pub_bytes).decode('ascii')
    return base58.b58encode(privkey_bytes[:32]).decode('ascii')


def pubkey_to_tron(uncompressed_pubkey_bytes: bytes) -> str:
    """Tron Address (T... Base58Check)."""
    if len(uncompressed_pubkey_bytes) == 65 and uncompressed_pubkey_bytes[0] == 4:
        uncompressed_pubkey_bytes = uncompressed_pubkey_bytes[1:]
    k = keccak256_bytes(uncompressed_pubkey_bytes)
    
    return base58check_encode(b'\x41' + k[-20:])


def privkey_to_sui(privkey_bytes: bytes) -> str:
    """Sui Address (0x... Blake2b-256 hash)."""
    if ed25519:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes[:32])
        pub_bytes = pk.public_key().public_bytes_raw()
    else:
        pub_bytes = privkey_bytes[:32]
    
    return "0x" + hashlib.blake2b(b'\x00' + pub_bytes, digest_size=32).hexdigest()


def pubkey_to_xrp(compressed_pubkey_bytes: bytes) -> str:
    """XRP Address (r... Ripple Base58Check)."""
    pkh = hash160(compressed_pubkey_bytes)
    payload = b'\x00' + pkh
    chk = sha256(sha256(payload))[:4]
    return b58encode_ripple(payload + chk)


def privkey_to_xrp_secret(privkey_bytes: bytes) -> str:
    """XRPL Family Seed (s... 16-byte seed Ripple Base58Check)."""
    payload = b'\x21' + privkey_bytes[:16]
    chk = sha256(sha256(payload))[:4]
    return b58encode_ripple(payload + chk)


def privkey_to_xrp_secret_secp(privkey_bytes: bytes) -> str:
    """XRPL RFC1751 / secp256k1 Secret Key (prefix 0x22 Ripple Base58Check)."""
    payload = b'\x22' + privkey_bytes[:32]
    chk = sha256(sha256(payload))[:4]
    return b58encode_ripple(payload + chk)


def pubkey_to_zcash(compressed_pubkey_bytes: bytes) -> str:
    """Zcash Address (t1... Base58Check)."""
    pkh = hash160(compressed_pubkey_bytes)
    return base58check_encode(b'\x1c\xb8' + pkh)


def pubkey_to_dash(compressed_pubkey_bytes: bytes) -> str:
    """Dash Address (X... Base58Check)."""
    return pubkey_to_p2pkh(compressed_pubkey_bytes, prefix=b'\x4c')


def pubkey_to_dogecoin(compressed_pubkey_bytes: bytes) -> str:
    """Dogecoin Address (D... Base58Check)."""
    return pubkey_to_p2pkh(compressed_pubkey_bytes, prefix=b'\x1e')


def pubkey_to_cosmos(compressed_pubkey_bytes: bytes) -> str:
    """Cosmos Hub Address (cosmos1... Bech32)."""
    pkh = hash160(compressed_pubkey_bytes)
    converted = _convertbits(pkh, 8, 5)
    if converted is None:
        return ""
    checksum = _create_checksum('cosmos', converted, 'bech32')
    return 'cosmos1' + ''.join([CHARSET[d] for d in converted + checksum])


def privkey_to_aptos(privkey_bytes: bytes) -> str:
    """Aptos Address (0x... SHA3-256 of Ed25519 public key + single key scheme 0x00)."""
    if ed25519:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes[:32])
        pub_bytes = pk.public_key().public_bytes_raw()
    else:
        pub_bytes = privkey_bytes[:32]
    try:
        from pysha3 import sha3_256  # type: ignore
        h = sha3_256(pub_bytes + b'\x00').hexdigest()
    except Exception:
        h = hashlib.sha3_256(pub_bytes + b'\x00').hexdigest()
    return "0x" + h


def pubkey_to_polkadot(pubkey_bytes: bytes) -> str:
    """Polkadot SS58 Address (Prefix 0x00 -> starts with 1)."""
    raw = pubkey_bytes[1:33] if len(pubkey_bytes) == 33 else pubkey_bytes[:32]
    prefix = b'\x00'
    payload = prefix + raw
    chk = hashlib.blake2b(b'SS58PRE' + payload, digest_size=64).digest()[:2]
    return base58.b58encode(payload + chk).decode('ascii')


def privkey_to_stellar(privkey_bytes: bytes) -> str:
    """Stellar Public Key Account Address (G... Strkey Base32)."""
    import base64
    if ed25519:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes[:32])
        pub_bytes = pk.public_key().public_bytes_raw()
    else:
        pub_bytes = privkey_bytes[:32]
    version = b'\x30'
    payload = version + pub_bytes
    crc = 0x0000
    for byte in payload:
        crc ^= (byte << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    crc_bytes = crc.to_bytes(2, byteorder='little')
    return base64.b32encode(payload + crc_bytes).decode('ascii').rstrip('=')


def pubkey_to_cardano(pubkey_bytes: bytes) -> str:
    """Cardano Address (addr1... Bech32)."""
    header = b'\x61'
    payload = header + hashlib.blake2b(pubkey_bytes, digest_size=28).digest()
    converted = _convertbits(payload, 8, 5)
    if converted is None:
        return ""
    checksum = _create_checksum('addr', converted, 'bech32')
    return 'addr1' + ''.join([CHARSET[d] for d in converted + checksum])


def privkey_to_near(privkey_bytes: bytes) -> str:
    """NEAR Protocol Implicit Account ID (64 hex characters of Ed25519 public key)."""
    if ed25519:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes[:32])
        pub_bytes = pk.public_key().public_bytes_raw()
    else:
        pub_bytes = privkey_bytes[:32]
    return pub_bytes.hex()


def pubkey_to_kaspa(pubkey_bytes: bytes) -> str:
    """Kaspa Address (kaspa:q... 32-byte Schnorr / Bech32)."""
    x_only = pubkey_bytes[1:33] if len(pubkey_bytes) == 33 else pubkey_bytes[:32]
    converted = _convertbits(b'\x00' + x_only, 8, 5)
    if converted is None:
        return ""
    checksum = _create_checksum('kaspa', converted, 'bech32')
    return 'kaspa:' + ''.join([CHARSET[d] for d in converted + checksum])


def privkey_to_algorand(privkey_bytes: bytes) -> str:
    """Algorand Address (58-character Base32 with 4-byte checksum)."""
    import base64
    if ed25519:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes[:32])
        pub_bytes = pk.public_key().public_bytes_raw()
    else:
        pub_bytes = privkey_bytes[:32]
    try:
        chk = hashlib.new('sha512_256', pub_bytes).digest()[-4:]
    except Exception:
        chk = hashlib.sha512(pub_bytes).digest()[:32][-4:]
    return base64.b32encode(pub_bytes + chk).decode('ascii').rstrip('=')


def pubkey_to_tezos(pubkey_bytes: bytes) -> str:
    """Tezos Address (tz1... Base58Check with prefix \x06\xa1\x9f)."""
    pkh = hash160(pubkey_bytes)
    prefix = b'\x06\xa1\x9f'
    return base58check_encode(prefix + pkh)


def pubkey_to_filecoin(pubkey_bytes: bytes) -> str:
    """Filecoin SECP256k1 Address (f1...)."""
    import base64
    pkh = hashlib.blake2b(pubkey_bytes, digest_size=20).digest()
    payload = b'\x01' + pkh
    chk = hashlib.blake2b(payload, digest_size=4).digest()
    b32 = base64.b32encode(pkh + chk).decode('ascii').lower().rstrip('=')
    return 'f1' + b32


def pubkey_to_cosmos_bech32(pubkey_bytes: bytes, hrp: str = 'cosmos') -> str:
    """Generic Cosmos Ecosystem Address Formatter (inj1, osmo1, sei1, celestia1, kava1, terra1)."""
    pkh = hash160(pubkey_bytes)
    converted = _convertbits(pkh, 8, 5)
    if converted is None:
        return ""
    checksum = _create_checksum(hrp, converted, 'bech32')
    return hrp + '1' + ''.join([CHARSET[d] for d in converted + checksum])


def pubkey_to_ravencoin(pubkey_bytes: bytes) -> str:
    """Ravencoin Address (R... Base58Check prefix 0x3c)."""
    return pubkey_to_p2pkh(pubkey_bytes, prefix=b'\x3c')


def pubkey_to_bitcoingold(pubkey_bytes: bytes) -> str:
    """Bitcoin Gold Address (G... Base58Check prefix 0x26)."""
    return pubkey_to_p2pkh(pubkey_bytes, prefix=b'\x26')


def ed25519_pubkey(privkey_bytes: bytes) -> bytes:
    """Extract 32-byte Ed25519 public key from private key bytes."""
    if ed25519:
        pk = ed25519.Ed25519PrivateKey.from_private_bytes(privkey_bytes[:32])
        return pk.public_key().public_bytes_raw()
    return privkey_bytes[:32]




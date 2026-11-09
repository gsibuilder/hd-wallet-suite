"""
BIP-32 Hierarchical Deterministic Key Derivation engine.
"""

import hmac
import hashlib
import ecdsa
from typing import Tuple, List, Optional
from .addresses import hash160, base58check_encode, encode_wif
from .crypto_accel import fast_privkey_to_pubkey, fast_pubkey_tweak_add

SECP256K1_ORDER: int = int(ecdsa.SECP256k1.generator.order() or 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)


class BIP32Node:
    def __init__(self, private_key: Optional[bytes], public_key: bytes, chain_code: bytes, depth: int, index: int, parent_fingerprint: bytes):
        self.private_key = private_key
        self.public_key = public_key
        self.chain_code = chain_code
        self.depth = depth
        self.index = index
        self.parent_fingerprint = parent_fingerprint

    @classmethod
    def from_seed(cls, seed: bytes, network_key: bytes = b'Bitcoin seed') -> 'BIP32Node':
        I = hmac.new(network_key, seed, hashlib.sha512).digest()
        master_priv = I[:32]
        master_chain = I[32:]
        master_pub = cls._privkey_to_pubkey(master_priv, compressed=True)
        return cls(
            private_key=master_priv,
            public_key=master_pub,
            chain_code=master_chain,
            depth=0,
            index=0,
            parent_fingerprint=b'\x00\x00\x00\x00'
        )

    @staticmethod
    def _privkey_to_pubkey(privkey_bytes: bytes, compressed: bool = True) -> bytes:
        return fast_privkey_to_pubkey(privkey_bytes, compressed=compressed)

    @property
    def fingerprint(self) -> bytes:
        """First 4 bytes of HASH160 of compressed public key."""
        return hash160(self.public_key)[:4]

    @property
    def is_private(self) -> bool:
        """True if node contains private key, False if neutered public key."""
        return self.private_key is not None

    @property
    def child_index(self) -> int:
        return self.index

    def derive_child(self, index: int, is_hardened: bool) -> 'BIP32Node':
        child_index = (index | 0x80000000) if is_hardened else index

        if is_hardened:
            if not self.private_key:
                raise ValueError("Cannot derive hardened child key from public key (neutered node)")
            data = b'\x00' + self.private_key + child_index.to_bytes(4, 'big')
        else:
            data = self.public_key + child_index.to_bytes(4, 'big')

        I = hmac.new(self.chain_code, data, hashlib.sha512).digest()
        I_L, I_R = I[:32], I[32:]

        if self.private_key:
            ki = (int.from_bytes(I_L, 'big') + int.from_bytes(self.private_key, 'big')) % SECP256K1_ORDER
            child_priv = ki.to_bytes(32, 'big')
            child_pub = self._privkey_to_pubkey(child_priv, compressed=True)
        else:
            # Public key derivation: Q_child = Q_parent + I_L * G
            child_pub = fast_pubkey_tweak_add(self.public_key, I_L)
            child_priv = None

        return BIP32Node(
            private_key=child_priv,
            public_key=child_pub,
            chain_code=I_R,
            depth=self.depth + 1,
            index=child_index,
            parent_fingerprint=self.fingerprint
        )

    def derive_path(self, path: str) -> 'BIP32Node':
        """
        Derive node along a path string like "m/84'/0'/0'/0/0".
        Automatically handles relative paths when node is already at depth > 0 (e.g. xpub/xprv).
        """
        import re
        clean_path = path.strip().rstrip(';').rstrip(',')
        if clean_path.startswith('m/'):
            clean_path = clean_path[2:]
        elif clean_path.startswith('m'):
            clean_path = clean_path[1:]

        if not clean_path:
            return self

        segments = [s.strip().rstrip(';').rstrip(',') for s in clean_path.split('/') if s.strip()]

        if self.depth > 0 and len(segments) >= self.depth:
            # If path starts with hardened levels matching root depth, strip the root prefix
            is_absolute_format = any(s.endswith("'") or s.endswith('h') or s.endswith('H') for s in segments[:self.depth])
            if is_absolute_format:
                segments = segments[self.depth:]

        current = self
        for seg in segments:
            if not seg:
                continue
            is_hardened = seg.endswith("'") or seg.endswith('h') or seg.endswith('H')
            raw_index = seg.rstrip("'hH")
            digits_only = re.sub(r'\D', '', raw_index)
            if not digits_only:
                continue
            index = int(digits_only)
            current = current.derive_child(index, is_hardened)

        return current

    def serialize_ext_key(self, version_bytes: int | bytes, is_private: bool = True) -> str:
        """
        Serialize extended key (xprv, xpub, zprv, zpub, yprv, ypub) into Base58Check string.
        """
        ver = version_bytes.to_bytes(4, 'big') if isinstance(version_bytes, int) else version_bytes
        depth = self.depth.to_bytes(1, 'big')
        parent_fp = self.parent_fingerprint
        idx = self.index.to_bytes(4, 'big')
        chain = self.chain_code

        if is_private:
            if not self.private_key:
                raise ValueError("Cannot serialize private key for neutered node")
            key_data = b'\x00' + self.private_key
        else:
            key_data = self.public_key

        payload = ver + depth + parent_fp + idx + chain + key_data
        return base58check_encode(payload)

    @classmethod
    def from_extended_key(cls, ext_key: str) -> 'BIP32Node':
        """
        Deserialize an extended key (xprv, xpub, zprv, zpub, yprv, ypub, etc.) Base58Check string.
        """
        import base58
        from .addresses import sha256
        decoded = base58.b58decode(ext_key.strip())
        if len(decoded) != 82:
            raise ValueError(f"Invalid extended key byte length: {len(decoded)}, expected 82 (78 payload + 4 checksum)")
        payload, checksum = decoded[:-4], decoded[-4:]
        if sha256(sha256(payload))[:4] != checksum:
            raise ValueError("Invalid Base58Check checksum for extended key")

        depth = payload[4]
        parent_fingerprint = payload[5:9]
        index = int.from_bytes(payload[9:13], 'big')
        chain_code = payload[13:45]
        key_data = payload[45:78]

        if key_data[0] == 0:
            private_key = key_data[1:33]
            public_key = cls._privkey_to_pubkey(private_key, compressed=True)
        else:
            private_key = None
            public_key = key_data

        return cls(
            private_key=private_key,
            public_key=public_key,
            chain_code=chain_code,
            depth=depth,
            index=index,
            parent_fingerprint=parent_fingerprint
        )

"""
BIP-174 / BIP-370 Partially Signed Bitcoin Transaction (PSBT) Implementation.
Provides Creator, Updater, Signer, Combiner, Finalizer, and Extractor functionality.
Supports Legacy (P2PKH), Nested SegWit (P2SH-P2WPKH), Native SegWit (P2WPKH), and Taproot (P2TR BIP-341/371).
"""

import base64
import hashlib
import struct
from typing import Dict, Any, List, Optional, Tuple, Union
import ecdsa
import ecdsa.util

from .addresses import (
    pubkey_to_p2pkh,
    pubkey_to_p2wpkh,
    pubkey_to_p2sh_p2wpkh,
    pubkey_to_p2tr,
    decode_wif,
    base58check_decode,
    base58check_encode,
    encode_bech32,
    decode_bech32
)

# Magic bytes for BIP-174 PSBT: 0x70736274ff ("psbt" + 0xff)
PSBT_MAGIC = b'psbt\xff'

# Global Types (BIP 174 & BIP 370)
PSBT_GLOBAL_UNSIGNED_TX = 0x00
PSBT_GLOBAL_XPUB = 0x01
PSBT_GLOBAL_TX_VERSION = 0x02
PSBT_GLOBAL_FALLBACK_LOCKTIME = 0x03
PSBT_GLOBAL_INPUT_COUNT = 0x04
PSBT_GLOBAL_OUTPUT_COUNT = 0x05
PSBT_GLOBAL_TX_MODIFIABLE = 0x06
PSBT_GLOBAL_VERSION = 0xFB
PSBT_GLOBAL_PROPRIETARY = 0xFC

# Input Types
PSBT_IN_NON_WITNESS_UTXO = 0x00
PSBT_IN_WITNESS_UTXO = 0x01
PSBT_IN_PARTIAL_SIG = 0x02
PSBT_IN_SIGHASH_TYPE = 0x03
PSBT_IN_REDEEM_SCRIPT = 0x04
PSBT_IN_WITNESS_SCRIPT = 0x05
PSBT_IN_BIP32_DERIVATION = 0x06
PSBT_IN_FINAL_SCRIPTSIG = 0x07
PSBT_IN_FINAL_SCRIPTWITNESS = 0x08
PSBT_IN_POR_COMMITMENT = 0x09
PSBT_IN_RIPEMD160 = 0x0A
PSBT_IN_SHA256 = 0x0B
PSBT_IN_HASH160 = 0x0C
PSBT_IN_HASH256 = 0x0D
PSBT_IN_PREVIOUS_TXID = 0x0E
PSBT_IN_OUTPUT_INDEX = 0x0F
PSBT_IN_SEQUENCE = 0x10
PSBT_IN_REQUIRED_TIME_LOCKTIME = 0x11
PSBT_IN_REQUIRED_HEIGHT_LOCKTIME = 0x12
PSBT_IN_TAP_KEY_SIG = 0x13
PSBT_IN_TAP_SCRIPT_SIG = 0x14
PSBT_IN_TAP_LEAF_SCRIPT = 0x15
PSBT_IN_TAP_BIP32_DERIVATION = 0x16
PSBT_IN_TAP_INTERNAL_KEY = 0x17
PSBT_IN_TAP_MERKLE_ROOT = 0x18
PSBT_IN_PROPRIETARY = 0xFC

# Output Types
PSBT_OUT_REDEEM_SCRIPT = 0x00
PSBT_OUT_WITNESS_SCRIPT = 0x01
PSBT_OUT_BIP32_DERIVATION = 0x02
PSBT_OUT_AMOUNT = 0x03
PSBT_OUT_SCRIPT = 0x04
PSBT_OUT_TAP_INTERNAL_KEY = 0x05
PSBT_OUT_TAP_TREE = 0x06
PSBT_OUT_TAP_BIP32_DERIVATION = 0x07
PSBT_OUT_PROPRIETARY = 0xFC

# Sighash flags
SIGHASH_DEFAULT = 0x00
SIGHASH_ALL = 0x01
SIGHASH_NONE = 0x02
SIGHASH_SINGLE = 0x03
SIGHASH_ANYONECANPAY = 0x80


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    h = hashlib.new('ripemd160')
    h.update(sha256(data))
    return h.digest()


def encode_varint(n: int) -> bytes:
    if n < 0xfd:
        return bytes([n])
    elif n <= 0xffff:
        return b'\xfd' + struct.pack('<H', n)
    elif n <= 0xffffffff:
        return b'\xfe' + struct.pack('<I', n)
    else:
        return b'\xff' + struct.pack('<Q', n)


def decode_varint(data: bytes, offset: int = 0) -> Tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Buffer underflow reading varint")
    first = data[offset]
    offset += 1
    if first < 0xfd:
        return first, offset
    elif first == 0xfd:
        if offset + 2 > len(data):
            raise ValueError("Buffer underflow reading varint 16")
        val = struct.unpack('<H', data[offset:offset+2])[0]
        return val, offset + 2
    elif first == 0xfe:
        if offset + 4 > len(data):
            raise ValueError("Buffer underflow reading varint 32")
        val = struct.unpack('<I', data[offset:offset+4])[0]
        return val, offset + 4
    else:
        if offset + 8 > len(data):
            raise ValueError("Buffer underflow reading varint 64")
        val = struct.unpack('<Q', data[offset:offset+8])[0]
        return val, offset + 8


def address_to_script_pubkey(address: str) -> bytes:
    """Convert Bitcoin address (Legacy, SegWit v0, Taproot v1, P2SH) to scriptPubKey."""
    address = address.strip()
    # Bech32 / Bech32m
    if address.lower().startswith(('bc1', 'tb1', 'bcrt1')):
        hrp, data, spec = decode_bech32(address)
        if data is None or len(data) == 0:
            raise ValueError(f"Invalid Bech32 address: {address}")
        witver = data[0]
        # convert 5-bit to 8-bit
        # Using custom converter
        acc, bits = 0, 0
        prog = bytearray()
        for val in data[1:]:
            acc = (acc << 5) | val
            bits += 5
            while bits >= 8:
                bits -= 8
                prog.append((acc >> bits) & 0xff)
        prog_bytes = bytes(prog)
        if witver == 0:
            # P2WPKH (20 bytes) or P2WSH (32 bytes)
            return bytes([0x00, len(prog_bytes)]) + prog_bytes
        elif witver == 1:
            # Taproot P2TR (OP_1 + Push32 + 32-byte key)
            return bytes([0x51, len(prog_bytes)]) + prog_bytes
        else:
            return bytes([0x50 + witver, len(prog_bytes)]) + prog_bytes

    # Base58Check (P2PKH or P2SH)
    raw = base58check_decode(address)
    version = raw[0]
    payload = raw[1:]
    if version in (0x00, 0x6f):  # Mainnet / Testnet P2PKH
        # OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
        return b'\x76\xa9\x14' + payload + b'\x88\xac'
    elif version in (0x05, 0xc4):  # Mainnet / Testnet P2SH
        # OP_HASH160 <20 bytes> OP_EQUAL
        return b'\xa9\x14' + payload + b'\x87'
    else:
        raise ValueError(f"Unknown address version byte: {version}")


def script_pubkey_to_address(script_pubkey: bytes, testnet: bool = False) -> str:
    """Convert scriptPubKey back to human-readable address."""
    # P2PKH: OP_DUP OP_HASH160 0x14 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
    if len(script_pubkey) == 25 and script_pubkey.startswith(b'\x76\xa9\x14') and script_pubkey.endswith(b'\x88\xac'):
        h160 = script_pubkey[3:23]
        prefix = b'\x6f' if testnet else b'\x00'
        return base58check_encode(prefix + h160)

    # P2SH: OP_HASH160 0x14 <20 bytes> OP_EQUAL
    if len(script_pubkey) == 23 and script_pubkey.startswith(b'\xa9\x14') and script_pubkey.endswith(b'\x87'):
        h160 = script_pubkey[2:22]
        prefix = b'\xc4' if testnet else b'\x05'
        return base58check_encode(prefix + h160)

    # P2WPKH: OP_0 0x14 <20 bytes>
    if len(script_pubkey) == 22 and script_pubkey.startswith(b'\x00\x14'):
        hrp = 'tb' if testnet else 'bc'
        return encode_bech32(hrp, 0, script_pubkey[2:])

    # P2WSH: OP_0 0x20 <32 bytes>
    if len(script_pubkey) == 34 and script_pubkey.startswith(b'\x00\x20'):
        hrp = 'tb' if testnet else 'bc'
        return encode_bech32(hrp, 0, script_pubkey[2:])

    # P2TR: OP_1 0x20 <32 bytes>
    if len(script_pubkey) == 34 and script_pubkey.startswith(b'\x51\x20'):
        hrp = 'tb' if testnet else 'bc'
        return encode_bech32(hrp, 1, script_pubkey[2:])

    return f"unknown_script({script_pubkey.hex()})"


class PSBTMap:
    """Represents a key-value map inside a PSBT (Global, Input, or Output)."""
    def __init__(self):
        self.entries: List[Tuple[bytes, bytes]] = []

    def set(self, key: bytes, value: bytes):
        for idx, (k, _) in enumerate(self.entries):
            if k == key:
                self.entries[idx] = (key, value)
                return
        self.entries.append((key, value))

    def get(self, key: bytes) -> Optional[bytes]:
        for k, v in self.entries:
            if k == key:
                return v
        return None

    def get_by_type(self, key_type: int) -> List[Tuple[bytes, bytes]]:
        res = []
        for k, v in self.entries:
            if len(k) > 0 and k[0] == key_type:
                res.append((k, v))
        return res

    def delete(self, key: bytes):
        self.entries = [entry for entry in self.entries if entry[0] != key]

    def delete_by_type(self, key_type: int):
        self.entries = [entry for entry in self.entries if len(entry[0]) == 0 or entry[0][0] != key_type]

    def serialize(self) -> bytes:
        out = bytearray()
        for k, v in self.entries:
            out.extend(encode_varint(len(k)))
            out.extend(k)
            out.extend(encode_varint(len(v)))
            out.extend(v)
        out.append(0x00)  # Separator 0x00 denotes end of map
        return bytes(out)

    @classmethod
    def deserialize(cls, data: bytes, offset: int = 0) -> Tuple['PSBTMap', int]:
        m = cls()
        while offset < len(data):
            if data[offset] == 0x00:
                offset += 1
                break
            key_len, offset = decode_varint(data, offset)
            if offset + key_len > len(data):
                raise ValueError("Key length exceeds buffer")
            key = data[offset:offset+key_len]
            offset += key_len

            val_len, offset = decode_varint(data, offset)
            if offset + val_len > len(data):
                raise ValueError("Value length exceeds buffer")
            val = data[offset:offset+val_len]
            offset += val_len

            m.set(key, val)
        return m, offset


class PSBT:
    """Partially Signed Bitcoin Transaction (BIP-174 & BIP-370)."""

    def __init__(self):
        self.global_map: PSBTMap = PSBTMap()
        self.inputs: List[PSBTMap] = []
        self.outputs: List[PSBTMap] = []
        self.tx_version: int = 2
        self.locktime: int = 0

    @classmethod
    def create(
        cls,
        inputs: List[Dict[str, Any]],
        outputs: List[Dict[str, Any]],
        locktime: int = 0,
        tx_version: int = 2
    ) -> 'PSBT':
        """
        Create a new PSBT.
        Inputs: [{'txid': hex_str, 'vout': int, 'amount_sats': int, 'script_pubkey': hex_or_bytes, 'address': str, 'sequence': 0xffffffff}]
        Outputs: [{'address': str, 'amount_sats': int}] or [{'script_pubkey': hex_or_bytes, 'amount_sats': int}]
        """
        psbt = cls()
        psbt.tx_version = tx_version
        psbt.locktime = locktime

        # Construct unsigned transaction for Global Map (BIP-174 format)
        raw_tx = bytearray()
        raw_tx.extend(struct.pack('<I', tx_version))
        raw_tx.extend(encode_varint(len(inputs)))

        for inp in inputs:
            txid_bytes = bytes.fromhex(inp['txid'])[::-1]  # Little-endian in wire format
            vout = int(inp['vout'])
            seq = inp.get('sequence', 0xffffffff)
            raw_tx.extend(txid_bytes)
            raw_tx.extend(struct.pack('<I', vout))
            raw_tx.extend(b'\x00')  # Empty scriptSig for unsigned tx
            raw_tx.extend(struct.pack('<I', seq))

        raw_tx.extend(encode_varint(len(outputs)))
        for out in outputs:
            amt = int(out['amount_sats'])
            if 'script_pubkey' in out:
                spk = bytes.fromhex(out['script_pubkey']) if isinstance(out['script_pubkey'], str) else out['script_pubkey']
            else:
                spk = address_to_script_pubkey(out['address'])
            raw_tx.extend(struct.pack('<Q', amt))
            raw_tx.extend(encode_varint(len(spk)))
            raw_tx.extend(spk)

        raw_tx.extend(struct.pack('<I', locktime))

        # Global Map
        psbt.global_map.set(bytes([PSBT_GLOBAL_UNSIGNED_TX]), bytes(raw_tx))

        # Inputs
        for inp in inputs:
            imap = PSBTMap()
            amt = inp.get('amount_sats')
            spk = None
            if 'script_pubkey' in inp and inp['script_pubkey']:
                spk = bytes.fromhex(inp['script_pubkey']) if isinstance(inp['script_pubkey'], str) else inp['script_pubkey']
            elif 'address' in inp and inp['address']:
                spk = address_to_script_pubkey(inp['address'])

            if amt is not None and spk is not None:
                # Add Witness UTXO (8 bytes amount + scriptPubKey)
                witness_utxo = struct.pack('<Q', amt) + encode_varint(len(spk)) + spk
                imap.set(bytes([PSBT_IN_WITNESS_UTXO]), witness_utxo)

            if 'non_witness_utxo' in inp and inp['non_witness_utxo']:
                raw_parent = bytes.fromhex(inp['non_witness_utxo']) if isinstance(inp['non_witness_utxo'], str) else inp['non_witness_utxo']
                imap.set(bytes([PSBT_IN_NON_WITNESS_UTXO]), raw_parent)

            if 'redeem_script' in inp and inp['redeem_script']:
                rs = bytes.fromhex(inp['redeem_script']) if isinstance(inp['redeem_script'], str) else inp['redeem_script']
                imap.set(bytes([PSBT_IN_REDEEM_SCRIPT]), rs)

            # Default SIGHASH_ALL
            imap.set(bytes([PSBT_IN_SIGHASH_TYPE]), struct.pack('<I', SIGHASH_ALL))
            psbt.inputs.append(imap)

        # Outputs
        for out in outputs:
            omap = PSBTMap()
            if 'redeem_script' in out and out['redeem_script']:
                rs = bytes.fromhex(out['redeem_script']) if isinstance(out['redeem_script'], str) else out['redeem_script']
                omap.set(bytes([PSBT_OUT_REDEEM_SCRIPT]), rs)
            psbt.outputs.append(omap)

        return psbt

    def serialize(self) -> bytes:
        out = bytearray(PSBT_MAGIC)
        out.extend(self.global_map.serialize())
        for imap in self.inputs:
            out.extend(imap.serialize())
        for omap in self.outputs:
            out.extend(omap.serialize())
        return bytes(out)

    def to_base64(self) -> str:
        return base64.b64encode(self.serialize()).decode('ascii')

    def to_hex(self) -> str:
        return self.serialize().hex()

    @classmethod
    def from_bytes(cls, data: bytes) -> 'PSBT':
        if not data.startswith(PSBT_MAGIC):
            raise ValueError(f"Invalid PSBT magic bytes (expected {PSBT_MAGIC.hex()})")

        offset = len(PSBT_MAGIC)
        psbt = cls()
        psbt.global_map, offset = PSBTMap.deserialize(data, offset)

        # Determine number of inputs and outputs from global unsigned tx
        raw_tx = psbt.global_map.get(bytes([PSBT_GLOBAL_UNSIGNED_TX]))
        num_inputs = 0
        num_outputs = 0

        if raw_tx:
            tx_offset = 4  # skip version
            num_inputs, tx_offset = decode_varint(raw_tx, tx_offset)
            for _ in range(num_inputs):
                tx_offset += 36  # 32 txid + 4 vout
                script_len, tx_offset = decode_varint(raw_tx, tx_offset)
                tx_offset += script_len + 4  # sequence
            num_outputs, tx_offset = decode_varint(raw_tx, tx_offset)
        else:
            in_count_bytes = psbt.global_map.get(bytes([PSBT_GLOBAL_INPUT_COUNT]))
            if in_count_bytes:
                num_inputs, _ = decode_varint(in_count_bytes, 0)
            out_count_bytes = psbt.global_map.get(bytes([PSBT_GLOBAL_OUTPUT_COUNT]))
            if out_count_bytes:
                num_outputs, _ = decode_varint(out_count_bytes, 0)

        for _ in range(num_inputs):
            imap, offset = PSBTMap.deserialize(data, offset)
            psbt.inputs.append(imap)

        for _ in range(num_outputs):
            omap, offset = PSBTMap.deserialize(data, offset)
            psbt.outputs.append(omap)

        return psbt

    deserialize = from_bytes

    @classmethod
    def from_base64(cls, b64_str: str) -> 'PSBT':
        clean = b64_str.strip().replace('\n', '').replace('\r', '')
        return cls.from_bytes(base64.b64decode(clean))

    @classmethod
    def from_hex(cls, hex_str: str) -> 'PSBT':
        return cls.from_bytes(bytes.fromhex(hex_str.strip()))

    @classmethod
    def parse_any(cls, psbt_str_or_bytes: Union[str, bytes]) -> 'PSBT':
        if isinstance(psbt_str_or_bytes, bytes):
            return cls.from_bytes(psbt_str_or_bytes)
        s = psbt_str_or_bytes.strip()
        if s.startswith('70736274ff') or len(s) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in s[:10]):
            try:
                return cls.from_hex(s)
            except Exception:
                pass
        return cls.from_base64(s)

    def to_dict(self) -> Dict[str, Any]:
        """Convert PSBT into an inspectable dictionary structure."""
        res: Dict[str, Any] = {
            'format': 'PSBT (BIP-174)',
            'base64': self.to_base64(),
            'hex': self.to_hex(),
            'num_inputs': len(self.inputs),
            'num_outputs': len(self.outputs),
            'inputs': [],
            'outputs': [],
            'total_input_sats': 0,
            'total_output_sats': 0,
            'fee_sats': None,
            'is_finalized': True
        }

        # Parse Global unsigned tx
        raw_tx = self.global_map.get(bytes([PSBT_GLOBAL_UNSIGNED_TX]))
        tx_info: Dict[str, Any] = {}
        if raw_tx:
            tx_version = struct.unpack('<I', raw_tx[:4])[0]
            tx_info['version'] = tx_version
            tx_offset = 4
            nin, tx_offset = decode_varint(raw_tx, tx_offset)
            tx_inputs = []
            for _ in range(nin):
                txid = raw_tx[tx_offset:tx_offset+32][::-1].hex()
                vout = struct.unpack('<I', raw_tx[tx_offset+32:tx_offset+36])[0]
                tx_offset += 36
                slen, tx_offset = decode_varint(raw_tx, tx_offset)
                tx_offset += slen
                seq = struct.unpack('<I', raw_tx[tx_offset:tx_offset+4])[0]
                tx_offset += 4
                tx_inputs.append({'txid': txid, 'vout': vout, 'sequence': seq})

            nout, tx_offset = decode_varint(raw_tx, tx_offset)
            tx_outputs = []
            for _ in range(nout):
                val = struct.unpack('<Q', raw_tx[tx_offset:tx_offset+8])[0]
                tx_offset += 8
                spk_len, tx_offset = decode_varint(raw_tx, tx_offset)
                spk = raw_tx[tx_offset:tx_offset+spk_len]
                tx_offset += spk_len
                tx_outputs.append({
                    'amount_sats': val,
                    'amount_btc': val / 1e8,
                    'script_pubkey': spk.hex(),
                    'address': script_pubkey_to_address(spk)
                })
            locktime = struct.unpack('<I', raw_tx[tx_offset:tx_offset+4])[0]
            tx_info['locktime'] = locktime
            tx_info['inputs'] = tx_inputs
            tx_info['outputs'] = tx_outputs
            res['unsigned_tx'] = tx_info
            res['total_output_sats'] = sum(o['amount_sats'] for o in tx_outputs)

        # Parse Inputs
        all_in_sats = 0
        has_all_input_amounts = True
        for idx, imap in enumerate(self.inputs):
            in_data: Dict[str, Any] = {'index': idx}
            if 'unsigned_tx' in res and idx < len(res['unsigned_tx']['inputs']):
                in_data.update(res['unsigned_tx']['inputs'][idx])

            # Witness UTXO
            w_utxo = imap.get(bytes([PSBT_IN_WITNESS_UTXO]))
            if w_utxo:
                amt = struct.unpack('<Q', w_utxo[:8])[0]
                spk_len, spk_off = decode_varint(w_utxo, 8)
                spk = w_utxo[spk_off:spk_off+spk_len]
                in_data['amount_sats'] = amt
                in_data['amount_btc'] = amt / 1e8
                in_data['script_pubkey'] = spk.hex()
                in_data['address'] = script_pubkey_to_address(spk)
                all_in_sats += amt
            else:
                has_all_input_amounts = False

            # Signatures
            sigs = []
            for k, v in imap.get_by_type(PSBT_IN_PARTIAL_SIG):
                pubkey = k[1:].hex()
                sigs.append({'pubkey': pubkey, 'signature': v.hex()})
            in_data['partial_signatures'] = sigs

            # Taproot Key Sig
            tap_sig = imap.get(bytes([PSBT_IN_TAP_KEY_SIG]))
            if tap_sig:
                in_data['taproot_key_sig'] = tap_sig.hex()

            # Final ScriptSig / Witness
            final_ss = imap.get(bytes([PSBT_IN_FINAL_SCRIPTSIG]))
            final_sw = imap.get(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]))
            in_data['is_finalized'] = bool(final_ss or final_sw)
            if not in_data['is_finalized']:
                res['is_finalized'] = False

            if final_ss:
                in_data['final_script_sig'] = final_ss.hex()
            if final_sw:
                in_data['final_script_witness'] = final_sw.hex()

            res['inputs'].append(in_data)

        res['total_input_sats'] = all_in_sats
        if has_all_input_amounts and res['total_output_sats'] is not None:
            res['fee_sats'] = all_in_sats - res['total_output_sats']
            res['fee_btc'] = res['fee_sats'] / 1e8

        # Parse Outputs
        for idx, omap in enumerate(self.outputs):
            out_data: Dict[str, Any] = {'index': idx}
            if 'unsigned_tx' in res and idx < len(res['unsigned_tx']['outputs']):
                out_data.update(res['unsigned_tx']['outputs'][idx])
            res['outputs'].append(out_data)

        return res

    def sign(self, keys: List[Union[str, bytes]], sighash_type: int = SIGHASH_ALL) -> int:
        """
        Sign matching inputs in the PSBT using provided private keys (WIF strings or 32-byte scalar bytes).
        Returns number of signatures generated.
        """
        raw_tx = self.global_map.get(bytes([PSBT_GLOBAL_UNSIGNED_TX]))
        if not raw_tx:
            raise ValueError("Global unsigned transaction not present in PSBT")

        # Parse private keys into SigningKey and compressed pubkey bytes
        key_pairs = []
        for k in keys:
            if isinstance(k, str):
                wif = k.strip()
                priv_bytes, compressed, _ = decode_wif(wif)
            else:
                priv_bytes = k
                compressed = True
            sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
            vk = sk.get_verifying_key()
            assert vk is not None
            pt = vk.pubkey.point
            p_prefix = b'\x02' if pt.y() % 2 == 0 else b'\x03'
            pub_compressed = p_prefix + pt.x().to_bytes(32, 'big')
            key_pairs.append((priv_bytes, sk, pub_compressed, pt.x().to_bytes(32, 'big')))

        signatures_added = 0

        # Unpack unsigned tx details for hashing
        tx_info = self.to_dict().get('unsigned_tx', {})
        tx_inputs = tx_info.get('inputs', [])
        tx_outputs = tx_info.get('outputs', [])
        tx_version = tx_info.get('version', 2)
        locktime = tx_info.get('locktime', 0)

        for in_idx, imap in enumerate(self.inputs):
            # Check if input already has final witness or signature
            if imap.get(bytes([PSBT_IN_FINAL_SCRIPTWITNESS])) or imap.get(bytes([PSBT_IN_FINAL_SCRIPTSIG])):
                continue

            w_utxo = imap.get(bytes([PSBT_IN_WITNESS_UTXO]))
            redeem_script = imap.get(bytes([PSBT_IN_REDEEM_SCRIPT]))

            if not w_utxo:
                continue

            utxo_amount = struct.unpack('<Q', w_utxo[:8])[0]
            spk_len, spk_off = decode_varint(w_utxo, 8)
            script_pubkey = w_utxo[spk_off:spk_off+spk_len]

            # 1. Native SegWit P2WPKH: OP_0 <20 bytes>
            if len(script_pubkey) == 22 and script_pubkey.startswith(b'\x00\x14'):
                target_pkh = script_pubkey[2:]
                for priv_bytes, sk, pub_comp, _ in key_pairs:
                    if hash160(pub_comp) == target_pkh:
                        # Construct BIP-143 scriptCode: 0x19 0x76 0xa9 0x14 <pkh> 0x88 0xac
                        script_code = b'\x76\xa9\x14' + target_pkh + b'\x88\xac'
                        sig_hash = compute_bip143_sighash(
                            tx_version, tx_inputs, tx_outputs, locktime,
                            in_idx, script_code, utxo_amount, sighash_type
                        )
                        # Sign with ECDSA
                        sig_der = sk.sign_digest_deterministic(sig_hash, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
                        full_sig = sig_der + bytes([sighash_type])
                        # Set Partial Sig: Key = 0x02 + pubkey, Value = signature
                        imap.set(bytes([PSBT_IN_PARTIAL_SIG]) + pub_comp, full_sig)
                        signatures_added += 1

            # 2. Nested SegWit P2SH-P2WPKH: OP_HASH160 <20 bytes> OP_EQUAL
            elif len(script_pubkey) == 23 and script_pubkey.startswith(b'\xa9\x14'):
                for priv_bytes, sk, pub_comp, _ in key_pairs:
                    p2wpkh_redeem = b'\x00\x14' + hash160(pub_comp)
                    if redeem_script == p2wpkh_redeem or hash160(p2wpkh_redeem) == script_pubkey[2:22]:
                        if not redeem_script:
                            imap.set(bytes([PSBT_IN_REDEEM_SCRIPT]), p2wpkh_redeem)
                        script_code = b'\x76\xa9\x14' + hash160(pub_comp) + b'\x88\xac'
                        sig_hash = compute_bip143_sighash(
                            tx_version, tx_inputs, tx_outputs, locktime,
                            in_idx, script_code, utxo_amount, sighash_type
                        )
                        sig_der = sk.sign_digest_deterministic(sig_hash, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
                        full_sig = sig_der + bytes([sighash_type])
                        imap.set(bytes([PSBT_IN_PARTIAL_SIG]) + pub_comp, full_sig)
                        signatures_added += 1

            # 3. Taproot P2TR (BIP-341/371): OP_1 <32 bytes>
            elif len(script_pubkey) == 34 and script_pubkey.startswith(b'\x51\x20'):
                target_output_key = script_pubkey[2:]
                for priv_bytes, sk, pub_comp, x_only in key_pairs:
                    # Tweak private key according to BIP-341
                    tag = hashlib.sha256(b'TapTweak').digest()
                    tweak = hashlib.sha256(tag + tag + x_only).digest()
                    tweak_int = int.from_bytes(tweak, 'big')

                    # Compute tweaked pubkey to verify match
                    sk_int = int.from_bytes(priv_bytes, 'big')
                    # Point negation if Y is odd
                    vk = sk.get_verifying_key()
                    assert vk is not None
                    pt = vk.pubkey.point
                    if pt.y() % 2 != 0:
                        sk_int = ecdsa.SECP256k1.order - sk_int
                    tweaked_priv_int = (sk_int + tweak_int) % ecdsa.SECP256k1.order
                    tweaked_priv_bytes = tweaked_priv_int.to_bytes(32, 'big')

                    # Check against target output key
                    tweaked_sk = ecdsa.SigningKey.from_string(tweaked_priv_bytes, curve=ecdsa.SECP256k1)
                    tweaked_vk = tweaked_sk.get_verifying_key()
                    assert tweaked_vk is not None
                    if tweaked_vk.pubkey.point.x().to_bytes(32, 'big') == target_output_key:
                        # Compute BIP-341 Taproot Sighash
                        all_prevouts = [(u.get('amount_sats', 0), bytes.fromhex(u.get('script_pubkey', ''))) for u in self.to_dict().get('inputs', [])]
                        sighash = compute_bip341_sighash(
                            tx_version, tx_inputs, tx_outputs, all_prevouts, locktime, in_idx, SIGHASH_DEFAULT
                        )
                        # Schnorr Sign (BIP-340)
                        schnorr_sig = schnorr_sign(tweaked_priv_bytes, sighash)
                        imap.set(bytes([PSBT_IN_TAP_KEY_SIG]), schnorr_sig)
                        signatures_added += 1

            # 4. Legacy P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
            elif len(script_pubkey) == 25 and script_pubkey.startswith(b'\x76\xa9\x14'):
                target_pkh = script_pubkey[3:23]
                for priv_bytes, sk, pub_comp, _ in key_pairs:
                    if hash160(pub_comp) == target_pkh:
                        sig_hash = compute_legacy_sighash(
                            tx_version, tx_inputs, tx_outputs, locktime, in_idx, script_pubkey, sighash_type
                        )
                        sig_der = sk.sign_digest_deterministic(sig_hash, hashfunc=hashlib.sha256, sigencode=ecdsa.util.sigencode_der)
                        full_sig = sig_der + bytes([sighash_type])
                        imap.set(bytes([PSBT_IN_PARTIAL_SIG]) + pub_comp, full_sig)
                        signatures_added += 1

        return signatures_added

    def finalize(self) -> int:
        """
        Finalize all inputs in the PSBT by converting partial signatures into
        PSBT_IN_FINAL_SCRIPTSIG and PSBT_IN_FINAL_SCRIPTWITNESS fields.
        Returns the number of finalized inputs.
        """
        finalized_count = 0
        for imap in self.inputs:
            if imap.get(bytes([PSBT_IN_FINAL_SCRIPTWITNESS])) or imap.get(bytes([PSBT_IN_FINAL_SCRIPTSIG])):
                finalized_count += 1
                continue

            w_utxo = imap.get(bytes([PSBT_IN_WITNESS_UTXO]))
            if not w_utxo:
                continue

            spk_len, spk_off = decode_varint(w_utxo, 8)
            script_pubkey = w_utxo[spk_off:spk_off+spk_len]
            partial_sigs = imap.get_by_type(PSBT_IN_PARTIAL_SIG)
            tap_sig = imap.get(bytes([PSBT_IN_TAP_KEY_SIG]))
            redeem_script = imap.get(bytes([PSBT_IN_REDEEM_SCRIPT]))

            # Finalize Taproot Key-Path
            if tap_sig and len(script_pubkey) == 34 and script_pubkey.startswith(b'\x51\x20'):
                witness_bytes = encode_varint(1) + encode_varint(len(tap_sig)) + tap_sig
                imap.set(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), witness_bytes)
                imap.delete_by_type(PSBT_IN_TAP_KEY_SIG)
                finalized_count += 1
                continue

            # Finalize Native SegWit P2WPKH
            if partial_sigs and len(script_pubkey) == 22 and script_pubkey.startswith(b'\x00\x14'):
                k, sig = partial_sigs[0]
                pubkey = k[1:]
                witness_bytes = encode_varint(2) + encode_varint(len(sig)) + sig + encode_varint(len(pubkey)) + pubkey
                imap.set(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), witness_bytes)
                imap.delete_by_type(PSBT_IN_PARTIAL_SIG)
                finalized_count += 1
                continue

            # Finalize Nested SegWit P2SH-P2WPKH
            if partial_sigs and redeem_script and len(script_pubkey) == 23 and script_pubkey.startswith(b'\xa9\x14'):
                k, sig = partial_sigs[0]
                pubkey = k[1:]
                # scriptSig pushes redeemScript
                script_sig = encode_varint(len(redeem_script)) + redeem_script
                witness_bytes = encode_varint(2) + encode_varint(len(sig)) + sig + encode_varint(len(pubkey)) + pubkey
                imap.set(bytes([PSBT_IN_FINAL_SCRIPTSIG]), script_sig)
                imap.set(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]), witness_bytes)
                imap.delete_by_type(PSBT_IN_PARTIAL_SIG)
                imap.delete_by_type(PSBT_IN_REDEEM_SCRIPT)
                finalized_count += 1
                continue

            # Finalize Legacy P2PKH
            if partial_sigs and len(script_pubkey) == 25 and script_pubkey.startswith(b'\x76\xa9\x14'):
                k, sig = partial_sigs[0]
                pubkey = k[1:]
                script_sig = encode_varint(len(sig)) + sig + encode_varint(len(pubkey)) + pubkey
                imap.set(bytes([PSBT_IN_FINAL_SCRIPTSIG]), script_sig)
                imap.delete_by_type(PSBT_IN_PARTIAL_SIG)
                finalized_count += 1
                continue

        return finalized_count

    def extract_transaction(self) -> str:
        """
        Extract the fully signed, network-ready raw transaction hex from the finalized PSBT.
        """
        self.finalize()

        raw_tx = self.global_map.get(bytes([PSBT_GLOBAL_UNSIGNED_TX]))
        if not raw_tx:
            raise ValueError("Global unsigned tx missing")

        tx_info = self.to_dict().get('unsigned_tx', {})
        tx_version = tx_info.get('version', 2)
        locktime = tx_info.get('locktime', 0)
        inputs = tx_info.get('inputs', [])
        outputs = tx_info.get('outputs', [])

        has_witness = any(imap.get(bytes([PSBT_IN_FINAL_SCRIPTWITNESS])) is not None for imap in self.inputs)

        out = bytearray()
        out.extend(struct.pack('<I', tx_version))

        if has_witness:
            out.extend(b'\x00\x01')  # BIP-141 SegWit Marker and Flag

        out.extend(encode_varint(len(inputs)))
        for idx, inp in enumerate(inputs):
            out.extend(bytes.fromhex(inp['txid'])[::-1])
            out.extend(struct.pack('<I', inp['vout']))
            # Final scriptSig
            script_sig = self.inputs[idx].get(bytes([PSBT_IN_FINAL_SCRIPTSIG])) or b''
            out.extend(encode_varint(len(script_sig)))
            out.extend(script_sig)
            out.extend(struct.pack('<I', inp.get('sequence', 0xffffffff)))

        out.extend(encode_varint(len(outputs)))
        for outp in outputs:
            out.extend(struct.pack('<Q', outp['amount_sats']))
            spk = bytes.fromhex(outp['script_pubkey'])
            out.extend(encode_varint(len(spk)))
            out.extend(spk)

        if has_witness:
            for idx in range(len(inputs)):
                wit = self.inputs[idx].get(bytes([PSBT_IN_FINAL_SCRIPTWITNESS]))
                if wit:
                    out.extend(wit)
                else:
                    out.append(0x00)

        out.extend(struct.pack('<I', locktime))
        return bytes(out).hex()

    def combine(self, other_psbt: 'PSBT'):
        """Combine metadata and partial signatures from another PSBT into this one."""
        for idx in range(min(len(self.inputs), len(other_psbt.inputs))):
            for k, v in other_psbt.inputs[idx].entries:
                self.inputs[idx].set(k, v)
        for idx in range(min(len(self.outputs), len(other_psbt.outputs))):
            for k, v in other_psbt.outputs[idx].entries:
                self.outputs[idx].set(k, v)


# ==========================================
# Cryptographic & Sighash Helper Routines
# ==========================================

def compute_bip143_sighash(
    version: int,
    inputs: List[Dict],
    outputs: List[Dict],
    locktime: int,
    input_index: int,
    script_code: bytes,
    amount_sats: int,
    sighash_type: int
) -> bytes:
    """Compute BIP-143 SegWit v0 sighash digest."""
    # 1. hashPrevouts
    prevouts = bytearray()
    for inp in inputs:
        prevouts.extend(bytes.fromhex(inp['txid'])[::-1])
        prevouts.extend(struct.pack('<I', inp['vout']))
    hash_prevouts = hash256(bytes(prevouts))

    # 2. hashSequence
    sequences = bytearray()
    for inp in inputs:
        sequences.extend(struct.pack('<I', inp.get('sequence', 0xffffffff)))
    hash_sequence = hash256(bytes(sequences))

    # 3. hashOutputs
    out_bytes = bytearray()
    for out in outputs:
        out_bytes.extend(struct.pack('<Q', out['amount_sats']))
        spk = bytes.fromhex(out['script_pubkey'])
        out_bytes.extend(encode_varint(len(spk)))
        out_bytes.extend(spk)
    hash_outputs = hash256(bytes(out_bytes))

    # 4. Outpoint of current input
    curr_inp = inputs[input_index]
    curr_outpoint = bytes.fromhex(curr_inp['txid'])[::-1] + struct.pack('<I', curr_inp['vout'])

    # Assemble preimage
    preimage = bytearray()
    preimage.extend(struct.pack('<I', version))
    preimage.extend(hash_prevouts)
    preimage.extend(hash_sequence)
    preimage.extend(curr_outpoint)
    preimage.extend(encode_varint(len(script_code)))
    preimage.extend(script_code)
    preimage.extend(struct.pack('<Q', amount_sats))
    preimage.extend(struct.pack('<I', curr_inp.get('sequence', 0xffffffff)))
    preimage.extend(hash_outputs)
    preimage.extend(struct.pack('<I', locktime))
    preimage.extend(struct.pack('<I', sighash_type))

    return hash256(bytes(preimage))


def compute_legacy_sighash(
    version: int,
    inputs: List[Dict],
    outputs: List[Dict],
    locktime: int,
    input_index: int,
    script_pubkey: bytes,
    sighash_type: int
) -> bytes:
    """Compute standard Bitcoin Legacy sighash digest."""
    out = bytearray()
    out.extend(struct.pack('<I', version))
    out.extend(encode_varint(len(inputs)))
    for idx, inp in enumerate(inputs):
        out.extend(bytes.fromhex(inp['txid'])[::-1])
        out.extend(struct.pack('<I', inp['vout']))
        if idx == input_index:
            out.extend(encode_varint(len(script_pubkey)))
            out.extend(script_pubkey)
        else:
            out.append(0x00)
        out.extend(struct.pack('<I', inp.get('sequence', 0xffffffff)))

    out.extend(encode_varint(len(outputs)))
    for outp in outputs:
        out.extend(struct.pack('<Q', outp['amount_sats']))
        spk = bytes.fromhex(outp['script_pubkey'])
        out.extend(encode_varint(len(spk)))
        out.extend(spk)

    out.extend(struct.pack('<I', locktime))
    out.extend(struct.pack('<I', sighash_type))
    return hash256(bytes(out))


def compute_bip341_sighash(
    version: int,
    inputs: List[Dict],
    outputs: List[Dict],
    all_prevouts: List[Tuple[int, bytes]],
    locktime: int,
    input_index: int,
    sighash_type: int
) -> bytes:
    """Compute BIP-341 Taproot sighash digest using tagged hash TapSighash."""
    tag = hashlib.sha256(b'TapSighash').digest()
    tag_prefix = tag + tag

    buf = bytearray()
    buf.append(0x00)  # epoch 0
    buf.append(sighash_type)
    buf.extend(struct.pack('<I', version))
    buf.extend(struct.pack('<I', locktime))

    # sha_prevouts
    prevouts = bytearray()
    for inp in inputs:
        prevouts.extend(bytes.fromhex(inp['txid'])[::-1])
        prevouts.extend(struct.pack('<I', inp['vout']))
    buf.extend(sha256(bytes(prevouts)))

    # sha_amounts
    amounts = bytearray()
    for amt, _ in all_prevouts:
        amounts.extend(struct.pack('<Q', amt))
    buf.extend(sha256(bytes(amounts)))

    # sha_scriptpubkeys
    spks = bytearray()
    for _, spk in all_prevouts:
        spks.extend(encode_varint(len(spk)))
        spks.extend(spk)
    buf.extend(sha256(bytes(spks)))

    # sha_sequences
    seqs = bytearray()
    for inp in inputs:
        seqs.extend(struct.pack('<I', inp.get('sequence', 0xffffffff)))
    buf.extend(sha256(bytes(seqs)))

    # sha_outputs
    out_b = bytearray()
    for out in outputs:
        out_b.extend(struct.pack('<Q', out['amount_sats']))
        spk = bytes.fromhex(out['script_pubkey'])
        out_b.extend(encode_varint(len(spk)))
        out_b.extend(spk)
    buf.extend(sha256(bytes(out_b)))

    # Spend type: 0 (key path)
    buf.append(0x00)
    buf.extend(struct.pack('<I', input_index))

    return hashlib.sha256(tag_prefix + bytes(buf)).digest()


def schnorr_sign(privkey_32: bytes, msg_32: bytes) -> bytes:
    """Pure Python BIP-340 Schnorr signature generation."""
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
    n = ecdsa.SECP256k1.order
    G = ecdsa.SECP256k1.generator

    d0 = int.from_bytes(privkey_32, 'big')
    if d0 == 0 or d0 >= n:
        raise ValueError("Invalid private key for Schnorr signing")

    P = d0 * G
    d = d0 if P.y() % 2 == 0 else n - d0

    # Deterministic nonce k via BIP-340 tagged hash
    tag_aux = hashlib.sha256(b'BIP0340/aux').digest()
    aux_rand = hashlib.sha256(tag_aux + tag_aux + b'\x00'*32).digest()
    t = d.to_bytes(32, 'big')
    px = P.x().to_bytes(32, 'big')
    tag_nonce = hashlib.sha256(b'BIP0340/nonce').digest()
    rand_nonce = hashlib.sha256(tag_nonce + tag_nonce + aux_rand + px + msg_32).digest()
    k0 = int.from_bytes(rand_nonce, 'big') % n
    if k0 == 0:
        raise ValueError("Nonce generation failed")

    R = k0 * G
    k = k0 if R.y() % 2 == 0 else n - k0
    rx = R.x().to_bytes(32, 'big')

    tag_chal = hashlib.sha256(b'BIP0340/challenge').digest()
    e_hash = hashlib.sha256(tag_chal + tag_chal + rx + px + msg_32).digest()
    e = int.from_bytes(e_hash, 'big') % n

    s = (k + e * d) % n
    return rx + s.to_bytes(32, 'big')

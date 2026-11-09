#!/usr/bin/env python3
import sys
import hashlib

try:
    from bsddb3 import db  # type: ignore
except ImportError:
    try:
        from berkeleydb import db  # type: ignore
    except ImportError:
        db = None  # type: ignore

def sha256(data):
    return hashlib.sha256(data).digest()

def b58encode(v):
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    p, acc = 1, 0
    for c in reversed(v):
        acc += p * c
        p = p << 8
    result = ''
    while acc > 0:
        acc, mod = divmod(acc, 58)
        result += alphabet[mod]
    for c in v:
        if c == 0:
            result = alphabet[0] + result
        else:
            break
    return result

def to_wif(privkey_bytes, compressed=True, testnet=False):
    prefix = b'\xef' if testnet else b'\x80'
    payload = prefix + privkey_bytes
    if compressed:
        payload += b'\x01'
    checksum = sha256(sha256(payload))[:4]
    return b58encode(payload + checksum)

def extract_privkey_from_der(der_bytes):
    idx = der_bytes.find(b'\x04\x20')
    if idx != -1:
        return der_bytes[idx+2 : idx+2+32]
    return None

def read_compact_size(data, offset=0):
    size = data[offset]
    offset += 1
    if size < 253:
        return size, offset
    elif size == 253:
        return int.from_bytes(data[offset:offset+2], 'little'), offset+2
    elif size == 254:
        return int.from_bytes(data[offset:offset+4], 'little'), offset+4
    else:
        return int.from_bytes(data[offset:offset+8], 'little'), offset+8

def parse_wallet(filepath):
    if db is None:
        raise RuntimeError("Neither bsddb3 nor berkeleydb is installed.")
    wallet_db = db.DB()
    try:
        wallet_db.open(filepath, "main", db.DB_BTREE, db.DB_RDONLY)
    except Exception as e:
        raise RuntimeError(f"Error opening wallet.dat: {e}")

    cursor = wallet_db.cursor()
    record = cursor.first()
    
    records_by_type = {}
    unencrypted_keys = []
    
    while record:
        key, value = record
        
        key_len, offset = 0, 0
        try:
            key_len, offset = read_compact_size(key, 0)
            key_type = key[offset:offset+key_len].decode('utf-8', errors='ignore')
        except Exception:
            key_type = "unknown"
            
        if key_type == 'key':
            # Public key follows the type string
            pubkey = key[offset+key_len:]
            # Value is CPrivKey vector (compact size + DER)
            val_len, val_offset = read_compact_size(value, 0)
            der_bytes = value[val_offset:val_offset+val_len]
            privkey_bytes = extract_privkey_from_der(der_bytes)
            if privkey_bytes:
                is_compressed = (len(pubkey) == 33)
                wif = to_wif(privkey_bytes, compressed=is_compressed)
                unencrypted_keys.append({
                    'pubkey': pubkey.hex(),
                    'wif': wif,
                    'compressed': is_compressed
                })
                
        records_by_type.setdefault(key_type, []).append((key, value))
        record = cursor.next()

    print(f"Successfully parsed wallet: {filepath}")
    print("-" * 60)
    for t, records in records_by_type.items():
        if t.isalnum():
            print(f"Type: {t:<15} Count: {len(records)}")
        
    print("-" * 60)
    
    if 'hdchain' in records_by_type:
        print("[INFO] HD Chain data found.")
    if 'mkey' in records_by_type:
        print("[INFO] Master keys (mkey) found. Wallet is encrypted.")
    if 'ckey' in records_by_type:
        print("[INFO] Encrypted private keys (ckey) found.")
        
    if unencrypted_keys:
        print(f"\n[SUCCESS] Extracted {len(unencrypted_keys)} unencrypted private keys:")
        for idx, k in enumerate(unencrypted_keys):
            print(f"  {idx+1}. WIF: {k['wif']} (Compressed: {k['compressed']})")
    elif 'ckey' in records_by_type:
        print("\n[WARNING] Private keys are encrypted. You will need the passphrase and AES decryption logic to view them.")
    else:
        print("\n[INFO] No private keys found in this wallet.")

    wallet_db.close()
    return {
        'filepath': filepath,
        'unencrypted_keys': unencrypted_keys,
        'records_by_type': {k: len(v) for k, v in records_by_type.items()},
        'is_encrypted': 'mkey' in records_by_type or 'ckey' in records_by_type,
        'has_hd_chain': 'hdchain' in records_by_type
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 parse_wallet.py <path_to_wallet.dat>")
        sys.exit(1)
    parse_wallet(sys.argv[1])

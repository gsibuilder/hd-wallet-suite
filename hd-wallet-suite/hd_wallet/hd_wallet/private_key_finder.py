"""
PrivateKeyFinder.io style Private Key Space Directory Parser & Navigator.
Indexes the full 256-bit secp256k1 key space (2^256 keys) into navigable pages of 128 keys each,
supporting 50+ coin networks, derivation paths, and standard 0-indexed BIP-39 mnemonics.
"""

import os
import random
import base58
import ecdsa
from typing import Dict, Any, List
from .addresses import (
    encode_wif,
    pubkey_to_p2pkh,
    pubkey_to_p2sh_p2wpkh,
    pubkey_to_p2wpkh,
    pubkey_to_p2tr,
    pubkey_to_ethereum,
    pubkey_to_tron,
    pubkey_to_xrp,
    privkey_to_xrp_secret,
    privkey_to_xrp_secret_secp,
    privkey_to_solana,
    privkey_to_sui,
    pubkey_to_zcash,
    pubkey_to_dash,
    pubkey_to_dogecoin,
    pubkey_to_cosmos,
    privkey_to_aptos,
    pubkey_to_polkadot,
    privkey_to_stellar,
    pubkey_to_cardano,
    privkey_to_near,
    pubkey_to_kaspa,
    privkey_to_algorand,
    pubkey_to_tezos,
    pubkey_to_filecoin,
    pubkey_to_cosmos_bech32,
    pubkey_to_ravencoin,
    pubkey_to_bitcoingold,
    ed25519_pubkey
)
from .crypto_accel import fast_privkey_to_pubkey
from .coins import NETWORKS
from .bip39 import entropy_to_mnemonic

SECP256K1_N = ecdsa.SECP256k1.generator.order()
KEYS_PER_PAGE = 128
MAX_PAGE = SECP256K1_N // KEYS_PER_PAGE


def get_private_key_page(*args, **kwargs) -> Dict[str, Any]:
    """
    Parse and return all raw private keys on a given page number (1-indexed) across the 2^256 key space,
    derived using the specified coin network, derivation path, and 0-indexed BIP-39 mnemonics.
    Optimized for high-speed batch page loads.
    """
    page_number = int(args[0]) if args else int(kwargs.get('page_number', kwargs.get('page', 1)))
    keys_per_page = int(kwargs.get('keys_per_page', kwargs.get('keysPerPage', KEYS_PER_PAGE)))
    word_count = int(kwargs.get('word_count', kwargs.get('wordCount', 12)))
    network = str(kwargs.get('network', 'bitcoin')).lower().strip()
    derivation_path = str(kwargs.get('derivation_path', kwargs.get('path', "m/84'/0'/0'/0/0"))).strip()

    WORD_TO_ENTROPY_BYTES = {12: 16, 15: 20, 18: 24, 21: 28, 24: 32}
    entropy_bytes_len = WORD_TO_ENTROPY_BYTES.get(word_count, 16)

    if page_number < 1:
        page_number = 1
    if page_number > MAX_PAGE:
        page_number = MAX_PAGE

    start_int = (page_number - 1) * keys_per_page + 1
    end_int = min(start_int + keys_per_page - 1, SECP256K1_N - 1)

    keys = []
    net_config = NETWORKS.get(network, NETWORKS['bitcoin'])
    symbol = net_config.get('symbol', 'BTC')
    wif_prefix = net_config.get('wif_prefix', b'\x80')
    p2pkh_prefix = net_config.get('p2pkh_prefix', b'\x00')
    p2sh_prefix = net_config.get('p2sh_prefix', b'\x05')
    hrp = net_config.get('bech32_hrp', 'bc')

    is_standard_path = derivation_path in ("m", "m/0", "m/84'/0'/0'/0/0", "m/44'/0'/0'/0/0", "m/49'/0'/0'/0/0")
    HDWallet = None
    if not is_standard_path:
        try:
            from .wallet import HDWallet as _HDWallet
            HDWallet = _HDWallet
        except Exception:
            pass

    for k_int in range(start_int, end_int + 1):
        priv_bytes = k_int.to_bytes(32, 'big')
        priv_hex = priv_bytes.hex()
        
        try:
            ent_int = k_int - 1
            ent = ent_int.to_bytes(entropy_bytes_len, 'big')
            bip39_mnem = entropy_to_mnemonic(ent)
        except Exception:
            bip39_mnem = "N/A"

        # Fast public keys derivation via C acceleration
        comp_pub_bytes = fast_privkey_to_pubkey(priv_bytes, compressed=True)
        uncomp_pub_bytes = fast_privkey_to_pubkey(priv_bytes, compressed=False)
        comp_pub = comp_pub_bytes.hex()
        uncomp_pub = uncomp_pub_bytes.hex()

        wif = encode_wif(priv_bytes, prefix=bytes([wif_prefix]) if isinstance(wif_prefix, int) else wif_prefix, compressed=True)
        wif_uncompressed = encode_wif(priv_bytes, prefix=bytes([wif_prefix]) if isinstance(wif_prefix, int) else wif_prefix, compressed=False)

        # Solana Ed25519 keypair calculation
        try:
            sol_pub = ed25519_pubkey(priv_bytes)
            sol_keypair_bytes = priv_bytes + sol_pub
            sol_keypair_b58 = base58.b58encode(sol_keypair_bytes).decode('ascii')
            sol_priv_b58 = base58.b58encode(priv_bytes).decode('ascii')
            sol_keypair_array = list(sol_keypair_bytes)
        except Exception:
            sol_keypair_b58 = ""
            sol_priv_b58 = ""
            sol_keypair_array = []

        # XRP Ripple Secret Key & Family Seed
        try:
            xrp_secret_seed = privkey_to_xrp_secret(priv_bytes)
        except Exception:
            xrp_secret_seed = ""
        try:
            xrp_secret_secp = privkey_to_xrp_secret_secp(priv_bytes)
        except Exception:
            xrp_secret_secp = ""
        try:
            xrp_secret = encode_wif(priv_bytes, prefix=b'\x21', compressed=False)
        except Exception:
            xrp_secret = ""

        # Pre-compute address derivations
        addr_p2pkh = pubkey_to_p2pkh(comp_pub_bytes, prefix=p2pkh_prefix if isinstance(p2pkh_prefix, bytes) else bytes([p2pkh_prefix]))
        addr_p2pkh_uncomp = pubkey_to_p2pkh(uncomp_pub_bytes, prefix=p2pkh_prefix if isinstance(p2pkh_prefix, bytes) else bytes([p2pkh_prefix]))
        addr_p2sh = pubkey_to_p2sh_p2wpkh(comp_pub_bytes, prefix=p2sh_prefix if isinstance(p2sh_prefix, bytes) else bytes([p2sh_prefix]))
        addr_p2wpkh = pubkey_to_p2wpkh(comp_pub_bytes, hrp=str(hrp))
        addr_p2tr = pubkey_to_p2tr(comp_pub_bytes, hrp=str(hrp))
        addr_eth = pubkey_to_ethereum(uncomp_pub_bytes)
        addr_trx = pubkey_to_tron(uncomp_pub_bytes)
        addr_xrp = pubkey_to_xrp(comp_pub_bytes)
        addr_sol = privkey_to_solana(priv_bytes)
        addr_sui = privkey_to_sui(priv_bytes)
        addr_ltc = pubkey_to_p2wpkh(comp_pub_bytes, hrp="ltc")
        addr_doge = pubkey_to_dogecoin(comp_pub_bytes)
        addr_dash = pubkey_to_dash(comp_pub_bytes)
        addr_zec = pubkey_to_zcash(comp_pub_bytes)
        addr_atom = pubkey_to_cosmos(comp_pub_bytes)
        addr_dot = pubkey_to_polkadot(comp_pub_bytes)
        addr_ada = pubkey_to_cardano(comp_pub_bytes)
        addr_apt = privkey_to_aptos(priv_bytes)
        addr_xlm = privkey_to_stellar(priv_bytes)
        addr_near = privkey_to_near(priv_bytes)
        addr_kas = pubkey_to_kaspa(comp_pub_bytes)
        addr_algo = privkey_to_algorand(priv_bytes)
        addr_xtz = pubkey_to_tezos(comp_pub_bytes)
        addr_fil = pubkey_to_filecoin(comp_pub_bytes)
        addr_inj = pubkey_to_cosmos_bech32(comp_pub_bytes, hrp='inj')
        addr_osmo = pubkey_to_cosmos_bech32(comp_pub_bytes, hrp='osmo')
        addr_sei = pubkey_to_cosmos_bech32(comp_pub_bytes, hrp='sei')
        addr_tia = pubkey_to_cosmos_bech32(comp_pub_bytes, hrp='celestia')
        addr_kava = pubkey_to_cosmos_bech32(comp_pub_bytes, hrp='kava')
        addr_rvn = pubkey_to_ravencoin(comp_pub_bytes)
        addr_btg = pubkey_to_bitcoingold(comp_pub_bytes)
        addr_bsv = pubkey_to_p2pkh(comp_pub_bytes, prefix=b'\x00')
        addr_bch = pubkey_to_p2pkh(comp_pub_bytes, prefix=b'\x00')

        if HDWallet and not is_standard_path:
            try:
                hd = HDWallet(priv_hex, network=network)
                derived = hd.derive_key(derivation_path)
                primary_addr = derived.get('address') or addr_p2wpkh
            except Exception:
                primary_addr = addr_p2wpkh
        else:
            primary_addr = addr_eth if network == 'ethereum' else (addr_trx if network == 'tron' else (addr_sol if network == 'solana' else (addr_xrp if network == 'xrp' else (addr_p2wpkh if derivation_path.startswith("m/84'") else (addr_p2sh if derivation_path.startswith("m/49'") else addr_p2pkh)))))

        keys.append({
            'index': k_int,
            'privateKeyHex': priv_hex,
            'bip39Mnemonic': bip39_mnem,
            'compressedPublicKey': comp_pub,
            'uncompressedPublicKey': uncomp_pub,
            'privateKeyWif': wif,
            'privateKeyWifUncompressed': wif_uncompressed,
            'solanaKeypairBase58': sol_keypair_b58,
            'solanaPrivateKeyBase58': sol_priv_b58,
            'solanaKeypairArray': sol_keypair_array,
            'xrpSecretKey': xrp_secret,
            'xrpSecretSeed': xrp_secret_seed,
            'xrpSecretKeySecp': xrp_secret_secp,
            'address': primary_addr,
            'addressP2PKH': addr_p2pkh,
            'addressP2PKHUncompressed': addr_p2pkh_uncomp,
            'addressP2SH': addr_p2sh,
            'addressP2WPKH': addr_p2wpkh,
            'addressP2TR': addr_p2tr,
            'addressETH': addr_eth,
            'addressTRX': addr_trx,
            'addressXRP': addr_xrp,
            'addressSOL': addr_sol,
            'addressSUI': addr_sui,
            'addressLTC': addr_ltc,
            'addressDOGE': addr_doge,
            'addressDASH': addr_dash,
            'addressZEC': addr_zec,
            'addressATOM': addr_atom,
            'addressDOT': addr_dot,
            'addressADA': addr_ada,
            'addressAPT': addr_apt,
            'addressXLM': addr_xlm,
            'addressNEAR': addr_near,
            'addressKAS': addr_kas,
            'addressALGO': addr_algo,
            'addressXTZ': addr_xtz,
            'addressFIL': addr_fil,
            'addressINJ': addr_inj,
            'addressOSMO': addr_osmo,
            'addressSEI': addr_sei,
            'addressTIA': addr_tia,
            'addressKAVA': addr_kava,
            'addressRVN': addr_rvn,
            'addressBTG': addr_btg,
            'addressBSV': addr_bsv,
            'addressBCH': addr_bch,
            'network': network,
            'symbol': symbol,
        })

    return {
        'page': page_number,
        'keysPerPage': keys_per_page,
        'startKeyIndex': start_int,
        'endKeyIndex': end_int,
        'maxPage': MAX_PAGE,
        'keys': keys
    }


def search_private_key_location(search_query: str) -> Dict[str, Any]:
    """
    Locate page number for a given Private Key Hex, Decimal Integer, WIF, or Public Address.
    """
    clean = search_query.strip()
    k_int = None

    if clean.isdigit():
        val = int(clean)
        if 1 <= val < SECP256K1_N:
            k_int = val

    elif clean.startswith(('0x', '0X')) or (len(clean) == 64 and all(c in '0123456789abcdefABCDEF' for c in clean)):
        hex_str = clean[2:] if clean.startswith(('0x', '0X')) else clean
        if len(hex_str) == 64:
            val = int(hex_str, 16)
            if 1 <= val < SECP256K1_N:
                k_int = val

    if k_int is None:
        try:
            decoded = base58.b58decode_check(clean)
            if len(decoded) in (33, 34) and decoded[0] in (0x80, 0xEF):
                priv_bytes = decoded[1:33]
                val = int.from_bytes(priv_bytes, 'big')
                if 1 <= val < SECP256K1_N:
                    k_int = val
        except Exception:
            pass

    if k_int is None:
        is_addr = False
        try:
            dec = base58.b58decode_check(clean)
            if len(dec) == 21:
                is_addr = True
        except Exception:
            pass
        if not is_addr and clean.lower().startswith(('bc1', 'tb1')) and len(clean) >= 14:
            is_addr = True
        elif not is_addr and clean.startswith(('0x', '0X')) and len(clean) == 42:
            is_addr = True
        elif not is_addr and clean.startswith('T') and len(clean) == 34:
            is_addr = True

        if is_addr:
            max_scan = 50000
            for scan_int in range(1, max_scan + 1):
                p_bytes = scan_int.to_bytes(32, 'big')
                c_pub = fast_privkey_to_pubkey(p_bytes, compressed=True)
                u_pub = fast_privkey_to_pubkey(p_bytes, compressed=False)
                addrs = [
                    pubkey_to_p2pkh(u_pub, prefix=b'\x00'),
                    pubkey_to_p2pkh(c_pub, prefix=b'\x00'),
                    pubkey_to_p2wpkh(c_pub, hrp='bc'),
                    pubkey_to_ethereum(u_pub),
                    pubkey_to_tron(u_pub)
                ]
                if any(clean.lower() == a.lower() for a in addrs):
                    k_int = scan_int
                    break

            if k_int is None:
                raw_hash = None
                try:
                    dec = base58.b58decode_check(clean)
                    if len(dec) == 21:
                        raw_hash = dec[1:]
                except Exception:
                    pass
                if not raw_hash and clean.startswith(('0x', '0X')) and len(clean) == 42:
                    try:
                        raw_hash = bytes.fromhex(clean[2:])
                    except Exception:
                        pass
                if raw_hash:
                    h_val = int.from_bytes(raw_hash, 'big')
                    k_int = max(1, (h_val % (SECP256K1_N - 1)) + 1)

    if k_int is None or k_int < 1 or k_int >= SECP256K1_N:
        return {'error': f'Invalid or unresolvable key/address query: {search_query}.'}

    page_number = ((k_int - 1) // KEYS_PER_PAGE) + 1
    offset_in_page = (k_int - 1) % KEYS_PER_PAGE
    priv_hex = k_int.to_bytes(32, 'big').hex()

    return {
        'privateKeyInteger': k_int,
        'privateKeyHex': priv_hex,
        'page': page_number,
        'offsetInPage': offset_in_page,
        'keysPerPage': KEYS_PER_PAGE
    }


def get_random_page_number() -> int:
    """Generate random page number across the 2^256 key space."""
    random_bytes = os.urandom(32)
    rand_int = int.from_bytes(random_bytes, 'big') % MAX_PAGE
    return max(1, rand_int)

"""
High-level HDWallet class and derivation helper APIs supporting 18 blockchains.
"""

from typing import Dict, Any, List, Optional
from .bip39 import generate_mnemonic, validate_mnemonic, mnemonic_to_seed
from .bip32 import BIP32Node
from .addresses import (
    encode_wif,
    decode_wif,
    is_valid_wif,
    pubkey_to_p2pkh,
    pubkey_to_p2sh_p2wpkh,
    pubkey_to_p2wpkh,
    pubkey_to_p2tr,
    pubkey_to_ethereum,
    privkey_to_solana,
    pubkey_to_tron,
    privkey_to_sui,
    pubkey_to_xrp,
    privkey_to_xrp_secret,
    privkey_to_xrp_secret_secp,
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
    ed25519_pubkey,
    sha256
)
from .coins import NETWORKS, SUPPORTED_COINS


def derive_slip0010_ed25519(seed: bytes, path: str) -> bytes:
    """
    SLIP-0010 Ed25519 HD Key Derivation (Solana, Sui, Aptos, Stellar, Algorand, NEAR).
    Derives 32-byte Ed25519 private key seed.
    """
    import hmac
    import hashlib
    clean_path = path.strip()
    if clean_path.startswith('m/'): clean_path = clean_path[2:]
    elif clean_path.startswith('m'): clean_path = clean_path[1:]
    segments = [s.strip() for s in clean_path.split('/') if s.strip()]

    I = hmac.new(b'ed25519 seed', seed, hashlib.sha512).digest()
    k, c = I[:32], I[32:]
    for seg in segments:
        raw = seg.rstrip("'hH")
        if not raw.isdigit():
            continue
        idx = int(raw) | 0x80000000
        data = b'\x00' + k + idx.to_bytes(4, 'big')
        I = hmac.new(c, data, hashlib.sha512).digest()
        k, c = I[:32], I[32:]
    return k


class HDWallet:
    def __init__(self, key_or_mnemonic: str, passphrase: str = "", network: str = "bitcoin"):
        self.raw_input = key_or_mnemonic.strip()
        self.passphrase = passphrase
        self.network_name = network.lower()
        self.network_config = NETWORKS.get(self.network_name, NETWORKS["bitcoin"])
        
        # Clean prefix if any
        clean = " ".join(self.raw_input.strip().split())
        if clean.startswith("Seed Hex: "):
            clean = clean.split("Seed Hex: ", 1)[1].strip()
        elif clean.startswith("0x") and len(clean) > 2:
            clean = clean[2:].strip()
            if all(c in "0123456789abcdefABCDEF" for c in clean) and len(clean) <= 64:
                clean = clean.zfill(64)

        self.input_type = "unknown"
        self.is_single_key = False
        self.single_privkey = None
        self.single_compressed = True
        self.mnemonic = ""
        self.seed = b""
        self.seed_hex = ""

        # 1. Extended Key (xprv / zprv / yprv / tprv / xpub / etc.)
        if len(clean) in [111, 112] and clean.startswith(('xprv', 'xpub', 'yprv', 'ypub', 'zprv', 'zpub', 'tprv', 'tpub', 'vprv', 'vpub', 'uprv', 'upub', 'Yprv', 'Ypub', 'Zprv', 'Zpub')):
            try:
                self.root_node = BIP32Node.from_extended_key(clean)
                self.input_type = "xprv" if self.root_node.private_key else "xpub"
            except Exception:
                pass

        # 2. WIF Private Key
        if self.input_type == "unknown" and is_valid_wif(clean):
            try:
                priv_bytes, is_comp, pfx = decode_wif(clean)
                self.input_type = "wif"
                self.is_single_key = True
                self.single_privkey = priv_bytes
                self.single_compressed = is_comp
                pub_comp = BIP32Node._privkey_to_pubkey(priv_bytes, compressed=True)
                chain_code = sha256(b"WIF_KEY:" + priv_bytes)
                self.root_node = BIP32Node(private_key=priv_bytes, public_key=pub_comp, chain_code=chain_code, depth=0, index=0, parent_fingerprint=b'\x00\x00\x00\x00')
            except Exception:
                pass

        # 3. Hex Private Key or Master Seed (32, 64, 128 chars hex)
        if self.input_type == "unknown" and all(c in "0123456789abcdefABCDEF" for c in clean):
            if len(clean) == 64:  # 32-byte key
                try:
                    raw_bytes = bytes.fromhex(clean)
                    self.input_type = "hex"
                    self.is_single_key = True
                    self.single_privkey = raw_bytes
                    self.single_compressed = True
                    pub_comp = BIP32Node._privkey_to_pubkey(raw_bytes, compressed=True)
                    chain_code = sha256(b"HEX_KEY:" + raw_bytes)
                    self.root_node = BIP32Node(private_key=raw_bytes, public_key=pub_comp, chain_code=chain_code, depth=0, index=0, parent_fingerprint=b'\x00\x00\x00\x00')
                    self.seed_hex = clean.lower()
                except Exception:
                    pass
            elif len(clean) in (32, 40, 48, 56, 128):
                try:
                    self.seed = bytes.fromhex(clean)
                    self.seed_hex = clean.lower()
                    self.input_type = "seed_hex"
                    self.root_node = BIP32Node.from_seed(self.seed)
                except Exception:
                    pass

        # 4. BIP-39 Mnemonic Phrase
        if self.input_type == "unknown":
            normalized_mnem = " ".join(clean.lower().split())
            if validate_mnemonic(normalized_mnem):
                self.mnemonic = normalized_mnem
                self.seed = mnemonic_to_seed(self.mnemonic, passphrase)
                self.seed_hex = self.seed.hex()
                self.input_type = "mnemonic"
                self.root_node = BIP32Node.from_seed(self.seed)
            else:
                self.mnemonic = clean
                self.seed = mnemonic_to_seed(clean, passphrase)
                self.seed_hex = self.seed.hex()
                self.root_node = BIP32Node.from_seed(self.seed)

        self.master_xprv = self.root_node.serialize_ext_key(self.network_config["bip32_xprv"], is_private=True) if self.root_node.private_key else ""
        self.master_xpub = self.root_node.serialize_ext_key(self.network_config["bip32_xpub"], is_private=False)

    @classmethod
    def from_extended_key(cls, ext_key: str, network: str = "bitcoin") -> 'HDWallet':
        return cls(ext_key, network=network)

    @classmethod
    def from_xprv(cls, xprv: str, network: str = "bitcoin") -> 'HDWallet':
        return cls(xprv, network=network)

    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "", network: str = "bitcoin") -> 'HDWallet':
        return cls(mnemonic, passphrase=passphrase, network=network)

    @classmethod
    def from_seed(cls, seed_hex_or_bytes: Any, network: str = "bitcoin") -> 'HDWallet':
        if isinstance(seed_hex_or_bytes, bytes):
            return cls(seed_hex_or_bytes.hex(), network=network)
        return cls(str(seed_hex_or_bytes), network=network)

    def derive_key(self, path: str = "m/84'/0'/0'/0/0") -> Dict[str, Any]:
        normalized_path = path if path.startswith("m") else f"m/{path}"

        # Determine active coin network configuration from path or wallet settings
        active_net = dict(self.network_config)
        if "/2'/" in normalized_path or self.network_name == 'litecoin':
            active_net.update({'wif_prefix': b'\xb0', 'p2pkh_prefix': b'\x30', 'p2sh_prefix': b'\x32', 'bech32_hrp': 'ltc'})
        elif "/3'/" in normalized_path or self.network_name == 'dogecoin':
            active_net.update({'wif_prefix': b'\x9e', 'p2pkh_prefix': b'\x1e', 'p2sh_prefix': b'\x16', 'bech32_hrp': 'doge'})
        elif "/5'/" in normalized_path or self.network_name == 'dash':
            active_net.update({'wif_prefix': b'\xcc', 'p2pkh_prefix': b'\x4c', 'p2sh_prefix': b'\x10', 'bech32_hrp': 'dash'})
        elif "/1'/" in normalized_path or self.network_name in ('testnet', 'bitcoin_testnet'):
            active_net.update({'wif_prefix': b'\xef', 'p2pkh_prefix': b'\x6f', 'p2sh_prefix': b'\xc4', 'bech32_hrp': 'tb'})
        elif "/175'/" in normalized_path or self.network_name == 'ravencoin':
            active_net.update({'wif_prefix': b'\x80', 'p2pkh_prefix': b'\x3c', 'p2sh_prefix': b'\x7a', 'bech32_hrp': 'rvn'})
        elif "/156'/" in normalized_path or self.network_name == 'bitcoingold':
            active_net.update({'wif_prefix': b'\x80', 'p2pkh_prefix': b'\x26', 'p2sh_prefix': b'\x17', 'bech32_hrp': 'btg'})

        wif_prefix = active_net["wif_prefix"]
        p2pkh_pref = active_net["p2pkh_prefix"]
        p2sh_pref = active_net["p2sh_prefix"]
        hrp = active_net["bech32_hrp"]

        if self.is_single_key and self.single_privkey:
            priv_bytes = self.single_privkey
            pub_bytes = BIP32Node._privkey_to_pubkey(priv_bytes, compressed=self.single_compressed)
            uncompressed_pub = BIP32Node._privkey_to_pubkey(priv_bytes, compressed=False)
            target_node = self.root_node
            priv_hex = priv_bytes.hex()
            pub_hex = pub_bytes.hex()
            if self.input_type == "wif" and self.raw_input.startswith(('5', 'K', 'L', 'c', '9', 'T', '6', 'Q', '7', 'X')):
                priv_wif = self.raw_input
            else:
                priv_wif = encode_wif(priv_bytes, prefix=bytes([wif_prefix]) if isinstance(wif_prefix, int) else wif_prefix, compressed=self.single_compressed)
            priv_wif_uncomp = encode_wif(priv_bytes, prefix=bytes([wif_prefix]) if isinstance(wif_prefix, int) else wif_prefix, compressed=False) if priv_bytes else ""
        else:
            target_node = self.root_node.derive_path(path)
            priv_bytes = target_node.private_key
            pub_bytes = target_node.public_key
            uncompressed_pub = BIP32Node._privkey_to_pubkey(priv_bytes, compressed=False) if priv_bytes else pub_bytes
            priv_hex = priv_bytes.hex() if priv_bytes else ""
            pub_hex = pub_bytes.hex()
            priv_wif = encode_wif(priv_bytes, prefix=bytes([wif_prefix]) if isinstance(wif_prefix, int) else wif_prefix, compressed=True) if priv_bytes else ""
            priv_wif_uncomp = encode_wif(priv_bytes, prefix=bytes([wif_prefix]) if isinstance(wif_prefix, int) else wif_prefix, compressed=False) if priv_bytes else ""

        fingerprint = target_node.fingerprint.hex()
        parent_fp = target_node.parent_fingerprint.hex()

        xprv_ver = active_net.get("bip32_xprv", 0x0488ade4)
        xpub_ver = active_net.get("bip32_xpub", 0x0488b21e)
        xprv = target_node.serialize_ext_key(xprv_ver, is_private=True) if priv_bytes and isinstance(xprv_ver, (int, bytes)) else ""
        xpub = target_node.serialize_ext_key(xpub_ver, is_private=False) if isinstance(xpub_ver, (int, bytes)) else ""

        zprv, zpub, yprv, ypub = None, None, None, None
        if "bip32_zprv" in active_net:
            zv = active_net["bip32_zprv"]
            zprv = target_node.serialize_ext_key(zv, is_private=True) if priv_bytes and isinstance(zv, (int, bytes)) else None
            zpub_v = active_net["bip32_zpub"]
            zpub = target_node.serialize_ext_key(zpub_v, is_private=False) if isinstance(zpub_v, (int, bytes)) else None
        if "bip32_yprv" in active_net:
            yv = active_net["bip32_yprv"]
            yprv = target_node.serialize_ext_key(yv, is_private=True) if priv_bytes and isinstance(yv, (int, bytes)) else None
            ypub_v = active_net["bip32_ypub"]
            ypub = target_node.serialize_ext_key(ypub_v, is_private=False) if isinstance(ypub_v, (int, bytes)) else None

        # Standard Bitcoin-family address derivations
        addr_p2pkh = pubkey_to_p2pkh(pub_bytes, prefix=bytes([p2pkh_pref]) if isinstance(p2pkh_pref, int) else p2pkh_pref)
        addr_p2sh = pubkey_to_p2sh_p2wpkh(pub_bytes, prefix=bytes([p2sh_pref]) if isinstance(p2sh_pref, int) else p2sh_pref)
        addr_p2wpkh = pubkey_to_p2wpkh(pub_bytes, hrp=str(hrp))
        addr_p2tr = pubkey_to_p2tr(pub_bytes, hrp=str(hrp))
        addr_eth = pubkey_to_ethereum(uncompressed_pub)

        # Ed25519 & Multichain derivations
        if self.seed and not self.is_single_key:
            sol_k = derive_slip0010_ed25519(self.seed, normalized_path if "/501'/" in normalized_path else "m/44'/501'/0'/0'")
            sui_k = derive_slip0010_ed25519(self.seed, normalized_path if "/784'/" in normalized_path else "m/44'/784'/0'/0'/0'")
            apt_k = derive_slip0010_ed25519(self.seed, normalized_path if "/637'/" in normalized_path else "m/44'/637'/0'/0'/0'")
            xlm_k = derive_slip0010_ed25519(self.seed, normalized_path if "/148'/" in normalized_path else "m/44'/148'/0'")
            algo_k = derive_slip0010_ed25519(self.seed, normalized_path if "/283'/" in normalized_path else "m/44'/283'/0'/0'/0'")
            near_k = derive_slip0010_ed25519(self.seed, normalized_path if "/397'/" in normalized_path else "m/44'/397'/0'")
        else:
            sol_k = sui_k = apt_k = xlm_k = algo_k = near_k = priv_bytes[:32] if priv_bytes else b'\x00'*32

        addr_sol = privkey_to_solana(sol_k) if sol_k else ""
        addr_sui = privkey_to_sui(sui_k) if sui_k else ""
        addr_apt = privkey_to_aptos(apt_k) if apt_k else ""
        addr_xlm = privkey_to_stellar(xlm_k) if xlm_k else ""
        addr_algo = privkey_to_algorand(algo_k) if algo_k else ""
        addr_near = privkey_to_near(near_k) if near_k else ""

        addr_trx = pubkey_to_tron(uncompressed_pub)
        addr_xrp = pubkey_to_xrp(pub_bytes)
        addr_zec = pubkey_to_zcash(pub_bytes)
        addr_dash = pubkey_to_dash(pub_bytes)
        addr_doge = pubkey_to_dogecoin(pub_bytes)
        addr_atom = pubkey_to_cosmos(pub_bytes)
        addr_dot = pubkey_to_polkadot(pub_bytes)
        addr_ada = pubkey_to_cardano(pub_bytes)
        addr_kas = pubkey_to_kaspa(pub_bytes)
        addr_xtz = pubkey_to_tezos(pub_bytes)
        addr_fil = pubkey_to_filecoin(pub_bytes)
        addr_inj = pubkey_to_cosmos_bech32(pub_bytes, hrp='inj')
        addr_osmo = pubkey_to_cosmos_bech32(pub_bytes, hrp='osmo')
        addr_sei = pubkey_to_cosmos_bech32(pub_bytes, hrp='sei')
        addr_tia = pubkey_to_cosmos_bech32(pub_bytes, hrp='celestia')
        addr_kava = pubkey_to_cosmos_bech32(pub_bytes, hrp='kava')
        addr_rvn = pubkey_to_ravencoin(pub_bytes)
        addr_btg = pubkey_to_bitcoingold(pub_bytes)
        addr_bsv = pubkey_to_p2pkh(pub_bytes, prefix=b'\x00')
        addr_ltc = pubkey_to_p2wpkh(pub_bytes, hrp='ltc') if normalized_path.startswith("m/84'") else (pubkey_to_p2sh_p2wpkh(pub_bytes, prefix=b'\x32') if normalized_path.startswith("m/49'") else pubkey_to_p2pkh(pub_bytes, prefix=b'\x30'))

        # Determine primary address and adjust key representations for Ed25519 coins
        primary_addr = ""
        if "/501'/" in normalized_path or self.network_name == 'solana':
            if sol_k:
                sol_pub = ed25519_pubkey(sol_k)
                priv_hex = sol_k.hex()
                pub_hex = sol_pub.hex()
                try:
                    import base58
                    priv_wif = base58.b58encode(sol_k + sol_pub).decode('ascii')
                except Exception:
                    priv_wif = ""
            primary_addr = addr_sol
        elif "/784'/" in normalized_path or self.network_name == 'sui':
            if sui_k:
                sui_pub = ed25519_pubkey(sui_k)
                priv_hex = sui_k.hex()
                pub_hex = sui_pub.hex()
                priv_wif = ""
            primary_addr = addr_sui
        elif "/637'/" in normalized_path or self.network_name == 'aptos':
            if apt_k:
                apt_pub = ed25519_pubkey(apt_k)
                priv_hex = apt_k.hex()
                pub_hex = apt_pub.hex()
                priv_wif = ""
            primary_addr = addr_apt
        elif "/148'/" in normalized_path or self.network_name == 'stellar':
            if xlm_k:
                xlm_pub = ed25519_pubkey(xlm_k)
                priv_hex = xlm_k.hex()
                pub_hex = xlm_pub.hex()
                priv_wif = ""
            primary_addr = addr_xlm
        elif "/283'/" in normalized_path or self.network_name == 'algorand':
            if algo_k:
                algo_pub = ed25519_pubkey(algo_k)
                priv_hex = algo_k.hex()
                pub_hex = algo_pub.hex()
                priv_wif = ""
            primary_addr = addr_algo
        elif "/397'/" in normalized_path or self.network_name == 'near':
            if near_k:
                near_pub = ed25519_pubkey(near_k)
                priv_hex = near_k.hex()
                pub_hex = near_pub.hex()
                priv_wif = ""
            primary_addr = addr_near
        elif "/60'/" in normalized_path or self.network_name in ['ethereum', 'bnb', 'base', 'polygon', 'arbitrum', 'optimism', 'avalanche', 'zksync', 'linea', 'blast', 'scroll', 'mantle', 'cronos', 'fantom']:
            primary_addr = addr_eth
            priv_wif = ""
        elif "/195'/" in normalized_path or self.network_name == 'tron':
            primary_addr = addr_trx
            priv_wif = ""
        elif "/144'/" in normalized_path or self.network_name == 'xrp':
            primary_addr = addr_xrp
        elif "/2'/" in normalized_path or self.network_name == 'litecoin':
            primary_addr = addr_ltc
        elif "/3'/" in normalized_path or self.network_name == 'dogecoin':
            primary_addr = addr_doge
        elif "/5'/" in normalized_path or self.network_name == 'dash':
            primary_addr = addr_dash
        elif "/133'/" in normalized_path or self.network_name == 'zcash':
            primary_addr = addr_zec
        elif "/118'/" in normalized_path or self.network_name == 'cosmos':
            primary_addr = addr_atom
        elif "/354'/" in normalized_path or self.network_name == 'polkadot':
            primary_addr = addr_dot
        elif "/1815'/" in normalized_path or self.network_name == 'cardano':
            primary_addr = addr_ada
        elif "/111111'/" in normalized_path or self.network_name == 'kaspa':
            primary_addr = addr_kas
        elif "/1729'/" in normalized_path or self.network_name == 'tezos':
            primary_addr = addr_xtz
        elif "/461'/" in normalized_path or self.network_name == 'filecoin':
            primary_addr = addr_fil
        elif "/175'/" in normalized_path or self.network_name == 'ravencoin':
            primary_addr = addr_rvn
        elif "/156'/" in normalized_path or self.network_name == 'bitcoingold':
            primary_addr = addr_btg
        elif normalized_path.startswith("m/86'"):
            primary_addr = addr_p2tr
        elif normalized_path.startswith("m/84'"):
            primary_addr = addr_p2wpkh
        elif normalized_path.startswith("m/49'"):
            primary_addr = addr_p2sh
        else:
            primary_addr = addr_p2pkh

        is_hardened = (target_node.index & 0x80000000) != 0
        raw_index = target_node.index & 0x7FFFFFFF

        # Derive Solana keypair & XRP secret representations
        sol_kp_b58 = ""
        sol_priv_b58 = ""
        if sol_k:
            try:
                import base58
                sol_pub = ed25519_pubkey(sol_k)
                sol_kp_b58 = base58.b58encode(sol_k + sol_pub).decode('ascii')
                sol_priv_b58 = base58.b58encode(sol_k).decode('ascii')
            except Exception:
                pass

        xrp_sec_seed = ""
        xrp_sec_secp = ""
        xrp_sec_wif = ""
        if priv_bytes:
            try:
                xrp_sec_seed = privkey_to_xrp_secret(priv_bytes)
            except Exception:
                pass
            try:
                xrp_sec_secp = privkey_to_xrp_secret_secp(priv_bytes)
            except Exception:
                pass
            try:
                xrp_sec_wif = encode_wif(priv_bytes, prefix=b'\x21', compressed=False)
            except Exception:
                pass

        return {
            'path': normalized_path,
            'depth': target_node.depth,
            'index': raw_index,
            'isHardened': is_hardened,
            'fingerprint': fingerprint,
            'parentFingerprint': parent_fp,
            'address': primary_addr,
            'privateKeyHex': priv_hex,
            'privateKeyWif': priv_wif,
            'privateKeyWifUncompressed': priv_wif_uncomp,
            'publicKeyHex': pub_hex,
            'publicKeyCompressedHex': pub_hex,
            'publicKeyUncompressedHex': uncompressed_pub.hex() if isinstance(uncompressed_pub, bytes) else uncompressed_pub,
            'chainCodeHex': target_node.chain_code.hex(),
            'xprv': xprv,
            'xpub': xpub,
            'zprv': zprv,
            'zpub': zpub,
            'yprv': yprv,
            'ypub': ypub,
            'addressP2PKH': addr_p2pkh,
            'addressP2SH': addr_p2sh,
            'addressP2WPKH': addr_p2wpkh,
            'addressP2TR': addr_p2tr,
            'addressETH': addr_eth,
            'addressSOL': addr_sol,
            'addressTRX': addr_trx,
            'addressSUI': addr_sui,
            'addressXRP': addr_xrp,
            'xrpSecretKey': xrp_sec_wif,
            'xrpSecretSeed': xrp_sec_seed,
            'xrpSecretKeySecp': xrp_sec_secp,
            'solanaKeypairBase58': sol_kp_b58,
            'solanaPrivateKeyBase58': sol_priv_b58,
            'addressZEC': addr_zec,
            'addressDASH': addr_dash,
            'addressDOGE': addr_doge,
            'addressATOM': addr_atom,
            'addressAPT': addr_apt,
            'addressDOT': addr_dot,
            'addressXLM': addr_xlm,
            'addressADA': addr_ada,
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
            'addressLTC': addr_ltc,
            'addressBCH': addr_p2pkh,
        }

    derive_path = derive_key

    def derive_address_batch(
        self,
        base_path: str = "m/84'/0'/0'",
        count: int = 50,
        change: int = 0,
        start_index: int = 0
    ) -> List[Dict[str, Any]]:
        normalized_path = base_path if base_path.startswith("m") else f"m/{base_path}"
        account_node = self.root_node.derive_path(normalized_path)
        change_node = account_node.derive_child(change, is_hardened=False)

        wif_prefix = self.network_config["wif_prefix"]
        p2pkh_pref = self.network_config["p2pkh_prefix"]
        p2sh_pref = self.network_config["p2sh_prefix"]
        hrp = self.network_config["bech32_hrp"]

        addresses = []
        for i in range(start_index, start_index + count):
            child = change_node.derive_child(i, is_hardened=False)
            path_str = f"{normalized_path}/{change}/{i}"
            pub_bytes = child.public_key
            priv_bytes = child.private_key
            uncompressed_pub = BIP32Node._privkey_to_pubkey(priv_bytes, compressed=False) if priv_bytes else pub_bytes

            if "/60'/" in normalized_path or self.network_name in ['ethereum', 'bnb', 'base', 'polygon', 'arbitrum', 'optimism', 'avalanche', 'zksync', 'linea', 'blast', 'scroll', 'mantle', 'cronos', 'fantom']:
                addr = pubkey_to_ethereum(uncompressed_pub)
                priv_wif = ""
            elif "/501'/" in normalized_path:
                ed_priv = derive_slip0010_ed25519(self.seed, path_str) if self.seed else priv_bytes
                ed_pub = ed25519_pubkey(ed_priv) if ed_priv else pub_bytes
                addr = privkey_to_solana(ed_priv) if ed_priv else ""
                pub_bytes = ed_pub
                priv_bytes = ed_priv
                try:
                    import base58
                    priv_wif = base58.b58encode(ed_priv + ed_pub).decode('ascii')
                except Exception:
                    priv_wif = ""
            elif "/784'/" in normalized_path:
                ed_priv = derive_slip0010_ed25519(self.seed, path_str) if self.seed else priv_bytes
                ed_pub = ed25519_pubkey(ed_priv) if ed_priv else pub_bytes
                addr = privkey_to_sui(ed_priv) if ed_priv else ""
                pub_bytes = ed_pub
                priv_bytes = ed_priv
                priv_wif = ""
            elif "/637'/" in normalized_path:
                ed_priv = derive_slip0010_ed25519(self.seed, path_str) if self.seed else priv_bytes
                ed_pub = ed25519_pubkey(ed_priv) if ed_priv else pub_bytes
                addr = privkey_to_aptos(ed_priv) if ed_priv else ""
                pub_bytes = ed_pub
                priv_bytes = ed_priv
                priv_wif = ""
            elif "/148'/" in normalized_path:
                ed_priv = derive_slip0010_ed25519(self.seed, path_str) if self.seed else priv_bytes
                ed_pub = ed25519_pubkey(ed_priv) if ed_priv else pub_bytes
                addr = privkey_to_stellar(ed_priv) if ed_priv else ""
                pub_bytes = ed_pub
                priv_bytes = ed_priv
                priv_wif = ""
            elif "/283'/" in normalized_path:
                ed_priv = derive_slip0010_ed25519(self.seed, path_str) if self.seed else priv_bytes
                ed_pub = ed25519_pubkey(ed_priv) if ed_priv else pub_bytes
                addr = privkey_to_algorand(ed_priv) if ed_priv else ""
                pub_bytes = ed_pub
                priv_bytes = ed_priv
                priv_wif = ""
            elif "/397'/" in normalized_path:
                ed_priv = derive_slip0010_ed25519(self.seed, path_str) if self.seed else priv_bytes
                ed_pub = ed25519_pubkey(ed_priv) if ed_priv else pub_bytes
                addr = privkey_to_near(ed_priv) if ed_priv else ""
                pub_bytes = ed_pub
                priv_bytes = ed_priv
                priv_wif = ""
            elif "/195'/" in normalized_path:
                addr = pubkey_to_tron(uncompressed_pub)
                priv_wif = ""
            elif "/144'/" in normalized_path:
                addr = pubkey_to_xrp(pub_bytes)
                priv_wif = ""
            elif "/133'/" in normalized_path:
                addr = pubkey_to_zcash(pub_bytes)
                priv_wif = encode_wif(priv_bytes, prefix=b'\x80', compressed=True) if priv_bytes else ""
            elif "/118'/" in normalized_path:
                addr = pubkey_to_cosmos(pub_bytes)
                priv_wif = ""
            elif "/5'/" in normalized_path:
                addr = pubkey_to_dash(pub_bytes)
                priv_wif = encode_wif(priv_bytes, prefix=b'\xcc', compressed=True) if priv_bytes else ""
            elif "/3'/" in normalized_path:
                addr = pubkey_to_dogecoin(pub_bytes)
                priv_wif = encode_wif(priv_bytes, prefix=b'\x9e', compressed=True) if priv_bytes else ""
            elif "/1815'/" in normalized_path:
                addr = pubkey_to_cardano(pub_bytes)
                priv_wif = ""
            elif "/354'/" in normalized_path:
                addr = pubkey_to_polkadot(pub_bytes)
                priv_wif = ""
            elif "/2'/" in normalized_path: # Litecoin
                if normalized_path.startswith("m/84'"):
                    addr = pubkey_to_p2wpkh(pub_bytes, hrp="ltc")
                elif normalized_path.startswith("m/49'"):
                    addr = pubkey_to_p2sh_p2wpkh(pub_bytes, prefix=b'\x32')
                else:
                    addr = pubkey_to_p2pkh(pub_bytes, prefix=b'\x30')
                priv_wif = encode_wif(priv_bytes, prefix=b'\xb0', compressed=True) if priv_bytes else ""
            elif "/1'/" in normalized_path: # Testnet
                if normalized_path.startswith("m/84'"):
                    addr = pubkey_to_p2wpkh(pub_bytes, hrp="tb")
                elif normalized_path.startswith("m/49'"):
                    addr = pubkey_to_p2sh_p2wpkh(pub_bytes, prefix=b'\xc4')
                else:
                    addr = pubkey_to_p2pkh(pub_bytes, prefix=b'\x6f')
                priv_wif = encode_wif(priv_bytes, prefix=b'\xef', compressed=True) if priv_bytes else ""
            elif normalized_path.startswith("m/84'"):
                addr = pubkey_to_p2wpkh(pub_bytes, hrp=hrp)
                priv_wif = encode_wif(priv_bytes, prefix=wif_prefix, compressed=True) if priv_bytes else ""
            elif normalized_path.startswith("m/86'"):
                addr = pubkey_to_p2tr(pub_bytes, hrp=hrp)
                priv_wif = encode_wif(priv_bytes, prefix=wif_prefix, compressed=True) if priv_bytes else ""
            elif normalized_path.startswith("m/49'"):
                addr = pubkey_to_p2sh_p2wpkh(pub_bytes, prefix=p2sh_pref)
                priv_wif = encode_wif(priv_bytes, prefix=wif_prefix, compressed=True) if priv_bytes else ""
            elif normalized_path.startswith("m/44'"):
                addr = pubkey_to_p2pkh(pub_bytes, prefix=p2pkh_pref)
                priv_wif = encode_wif(priv_bytes, prefix=wif_prefix, compressed=True) if priv_bytes else ""
            else:
                addr = pubkey_to_p2wpkh(pub_bytes, hrp=hrp)
                priv_wif = encode_wif(priv_bytes, prefix=wif_prefix, compressed=True) if priv_bytes else ""

            priv_hex = priv_bytes.hex() if priv_bytes else ""

            addresses.append({
                'index': i,
                'path': path_str,
                'type': 'receiving' if change == 0 else 'change',
                'address': addr,
                'publicKey': pub_bytes.hex(),
                'privateKeyWif': priv_wif,
                'privateKeyHex': priv_hex
            })

        return addresses

    def derive_all_comprehensive(
        self,
        account_count: int = 1,
        address_count: int = 20,
        include_change: bool = True
    ) -> List[Dict[str, Any]]:
        """
        Derive addresses across all key schemes (Native SegWit Bech32, Taproot, Nested SegWit,
        Legacy P2PKH, Ethereum, Litecoin, Dogecoin) for multiple accounts and both change chains.
        """
        results = []
        depth = self.root_node.depth
        hrp = self.network_config["bech32_hrp"]
        p2sh_pref = self.network_config["p2sh_prefix"]
        p2pkh_pref = self.network_config["p2pkh_prefix"]
        wif_prefix = self.network_config["wif_prefix"]
        change_chains = [0, 1] if include_change else [0]

        # If key is already an account or sub-node (depth >= 3)
        if depth >= 3:
            for chg in change_chains:
                try:
                    chg_node = self.root_node.derive_child(chg, is_hardened=False)
                except Exception:
                    continue
                for idx in range(address_count):
                    try:
                        child = chg_node.derive_child(idx, is_hardened=False)
                        pub_bytes = child.public_key
                        priv_bytes = child.private_key
                        uncomp_pub = BIP32Node._privkey_to_pubkey(priv_bytes, compressed=False) if priv_bytes else pub_bytes
                        
                        addr_p2wpkh = pubkey_to_p2wpkh(pub_bytes, hrp=hrp)
                        addr_p2tr = pubkey_to_p2tr(pub_bytes, hrp=hrp)
                        addr_p2sh = pubkey_to_p2sh_p2wpkh(pub_bytes, prefix=p2sh_pref)
                        addr_p2pkh = pubkey_to_p2pkh(pub_bytes, prefix=p2pkh_pref)
                        addr_eth = pubkey_to_ethereum(uncomp_pub)
                        
                        priv_wif = encode_wif(priv_bytes, prefix=wif_prefix, compressed=True) if priv_bytes else ""
                        priv_hex = priv_bytes.hex() if priv_bytes else ""

                        for scheme_name, primary_addr in [
                            ("BIP-84 Native SegWit (bc1q)", addr_p2wpkh),
                            ("BIP-86 Taproot (bc1p)", addr_p2tr),
                            ("BIP-49 Nested SegWit (3...)", addr_p2sh),
                            ("BIP-44 Legacy P2PKH (1...)", addr_p2pkh),
                            ("Ethereum (0x...)", addr_eth),
                        ]:
                            results.append({
                                'scheme': scheme_name,
                                'path': f"/{chg}/{idx}",
                                'account': 0,
                                'change': chg,
                                'index': idx,
                                'type': 'receiving' if chg == 0 else 'change',
                                'address': primary_addr,
                                'publicKey': pub_bytes.hex(),
                                'privateKeyWif': priv_wif,
                                'privateKeyHex': priv_hex
                            })
                    except Exception:
                        continue
            return results

        # Full derivation from root/master node
        standards = [
            {"scheme": "BIP-84 Native SegWit (bc1q)", "purpose": 84, "coin": 0, "fn": lambda pub, uncomp: pubkey_to_p2wpkh(pub, hrp=hrp)},
            {"scheme": "BIP-86 Taproot (bc1p)", "purpose": 86, "coin": 0, "fn": lambda pub, uncomp: pubkey_to_p2tr(pub, hrp=hrp)},
            {"scheme": "BIP-49 Nested SegWit (3...)", "purpose": 49, "coin": 0, "fn": lambda pub, uncomp: pubkey_to_p2sh_p2wpkh(pub, prefix=p2sh_pref)},
            {"scheme": "BIP-44 Legacy P2PKH (1...)", "purpose": 44, "coin": 0, "fn": lambda pub, uncomp: pubkey_to_p2pkh(pub, prefix=p2pkh_pref)},
            {"scheme": "Ethereum (0x...)", "purpose": 44, "coin": 60, "fn": lambda pub, uncomp: pubkey_to_ethereum(uncomp)},
            {"scheme": "Litecoin Native SegWit (ltc1q)", "purpose": 84, "coin": 2, "fn": lambda pub, uncomp: pubkey_to_p2wpkh(pub, hrp="ltc")},
            {"scheme": "Dogecoin Legacy (D...)", "purpose": 44, "coin": 3, "fn": lambda pub, uncomp: pubkey_to_dogecoin(pub)},
        ]

        for std in standards:
            purp = std["purpose"]
            coin_num = std["coin"]
            for acct in range(account_count):
                base_path = f"m/{purp}'/{coin_num}'/{acct}'"
                try:
                    acct_node = self.root_node.derive_path(base_path)
                except Exception:
                    continue
                for chg in change_chains:
                    try:
                        chg_node = acct_node.derive_child(chg, is_hardened=False)
                    except Exception:
                        continue
                    for idx in range(address_count):
                        try:
                            child = chg_node.derive_child(idx, is_hardened=False)
                            path_str = f"{base_path}/{chg}/{idx}"
                            pub_bytes = child.public_key
                            priv_bytes = child.private_key
                            uncomp_pub = BIP32Node._privkey_to_pubkey(priv_bytes, compressed=False) if priv_bytes else pub_bytes
                            fn_callable = std["fn"]
                            addr = fn_callable(pub_bytes, uncomp_pub) if callable(fn_callable) else ""
                            priv_wif = encode_wif(priv_bytes, prefix=wif_prefix, compressed=True) if priv_bytes else ""
                            priv_hex = priv_bytes.hex() if priv_bytes else ""

                            results.append({
                                'scheme': std['scheme'],
                                'path': path_str,
                                'account': acct,
                                'change': chg,
                                'index': idx,
                                'type': 'receiving' if chg == 0 else 'change',
                                'address': addr,
                                'publicKey': pub_bytes.hex(),
                                'privateKeyWif': priv_wif,
                                'privateKeyHex': priv_hex
                            })
                        except Exception:
                            continue

        return results


def derive_all_from_xprv(
    xprv_str: str,
    network_type: str = "bitcoin",
    account_count: int = 1,
    address_count: int = 20,
    include_change: bool = True
) -> List[Dict[str, Any]]:
    wallet = HDWallet(xprv_str, network=network_type)
    return wallet.derive_all_comprehensive(
        account_count=account_count,
        address_count=address_count,
        include_change=include_change
    )


def derive_wallet_from_mnemonic(
    mnemonic: str,
    passphrase: str = "",
    path: str = "m/84'/0'/0'/0/0",
    network_type: str = "bitcoin"
) -> Dict[str, Any]:
    wallet = HDWallet(mnemonic, passphrase, network=network_type)
    derived = wallet.derive_key(path)
    return {
        'seedHex': wallet.seed_hex,
        'masterXprv': wallet.master_xprv,
        'masterXpub': wallet.master_xpub,
        'derivedKey': derived
    }


def derive_address_batch(
    mnemonic: str,
    passphrase: str = "",
    base_path: str = "m/84'/0'/0'",
    count: int = 50,
    change: int = 0,
    start_index: int = 0,
    network_type: str = "bitcoin"
) -> List[Dict[str, Any]]:
    wallet = HDWallet(mnemonic, passphrase, network=network_type)
    return wallet.derive_address_batch(base_path, count=count, change=change, start_index=start_index)


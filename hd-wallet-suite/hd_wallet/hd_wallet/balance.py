"""
Balance Checker Module for querying balances across 18 supported blockchains.
"""

import json
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List

EVM_RPCS = {
    'ethereum': ('https://cloudflare-eth.com', 'https://etherscan.io/address/{address}', 'ETH'),
    'bnb': ('https://bsc-dataseed.binance.org/', 'https://bscscan.com/address/{address}', 'BNB'),
    'arbitrum': ('https://arb1.arbitrum.io/rpc', 'https://arbiscan.io/address/{address}', 'ETH'),
    'optimism': ('https://mainnet.optimism.io', 'https://optimistic.etherscan.io/address/{address}', 'ETH'),
    'base': ('https://mainnet.base.org', 'https://basescan.org/address/{address}', 'ETH'),
    'polygon': ('https://polygon.llamarpc.com', 'https://polygonscan.com/address/{address}', 'POL'),
    'avalanche': ('https://api.avax.network/ext/bc/C/rpc', 'https://snowtrace.io/address/{address}', 'AVAX'),
    'zksync': ('https://mainnet.era.zksync.io', 'https://explorer.zksync.io/address/{address}', 'ETH'),
    'fantom': ('https://rpc.ftm.tools', 'https://ftmscan.com/address/{address}', 'FTM'),
    'linea': ('https://rpc.linea.build', 'https://lineascan.build/address/{address}', 'ETH'),
    'blast': ('https://rpc.blast.io', 'https://blastscan.io/address/{address}', 'ETH'),
    'scroll': ('https://rpc.scroll.io', 'https://scrollscan.com/address/{address}', 'ETH'),
    'mantle': ('https://rpc.mantle.xyz', 'https://mantlescan.xyz/address/{address}', 'MNT'),
    'cronos': ('https://evm.cronos.org', 'https://cronoscan.com/address/{address}', 'CRO'),
}


import threading
import base64

BALANCE_CACHE: Dict[tuple, Dict[str, Any]] = {}
_CACHE_LOCK = threading.Lock()
CUSTOM_RPC_NODES: Dict[str, Dict[str, Any]] = {}


def normalize_rpc_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url:
        return ""
    if not (url.startswith("http://") or url.startswith("https://")):
        url = "http://" + url
    return url


def set_custom_rpc_node(network: str, url: str, username: str = "", password: str = ""):
    """Set custom node RPC endpoint URL and Basic Auth credentials for a network."""
    net = network.lower().strip()
    clean_url = normalize_rpc_url(url)
    if clean_url:
        CUSTOM_RPC_NODES[net] = {
            'url': clean_url,
            'username': username.strip(),
            'password': password.strip()
        }
    elif net in CUSTOM_RPC_NODES:
        del CUSTOM_RPC_NODES[net]


def get_rpc_headers_and_url(network: str) -> tuple[str, Dict[str, str], str]:
    """Returns (rpc_url, headers, symbol) for the network, using custom node if set."""
    net = network.lower().strip()
    default_url, explorer_tmpl, symbol = EVM_RPCS.get(net, EVM_RPCS['ethereum'])
    headers = {'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Python-Engine/1.0'}

    if net in CUSTOM_RPC_NODES:
        c_node = CUSTOM_RPC_NODES[net]
        rpc_url = normalize_rpc_url(c_node['url'])
        if c_node.get('username') and c_node.get('password'):
            cred = f"{c_node['username']}:{c_node['password']}".encode('utf-8')
            headers['Authorization'] = f"Basic {base64.b64encode(cred).decode('ascii')}"
    else:
        rpc_url = default_url

    return rpc_url, headers, symbol


def test_custom_rpc_connection(network: str, url: str, username: str = "", password: str = "") -> Dict[str, Any]:
    """Test RPC connectivity and auth login to a custom node."""
    import time
    start_t = time.time()
    clean_url = normalize_rpc_url(url)
    if not clean_url:
        return {'success': False, 'status': 'Invalid URL', 'error': 'Empty RPC URL'}

    headers = {'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Python-Engine/1.0'}
    if username.strip() and password.strip():
        cred = f"{username.strip()}:{password.strip()}".encode('utf-8')
        headers['Authorization'] = f"Basic {base64.b64encode(cred).decode('ascii')}"

    net = network.lower().strip()
    if net in ('bitcoin', 'btc'):
        payload = {'jsonrpc': '1.0', 'id': 'test', 'method': 'getblockchaininfo', 'params': []}
    elif net in ('solana', 'sol'):
        payload = {'jsonrpc': '2.0', 'id': 1, 'method': 'getHealth', 'params': []}
    else:
        payload = {'jsonrpc': '2.0', 'method': 'eth_blockNumber', 'params': [], 'id': 1}

    req = urllib.request.Request(
        clean_url,
        data=json.dumps(payload).encode('utf-8'),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            latency_ms = int((time.time() - start_t) * 1000)
            res_val = data.get('result')
            block_num = None
            if isinstance(res_val, str) and res_val.startswith('0x'):
                block_num = int(res_val, 16)
            elif isinstance(res_val, dict):
                block_num = res_val.get('blocks')
            return {
                'success': True,
                'status': 'Connected',
                'latency_ms': latency_ms,
                'blockNumber': block_num,
                'response': data
            }
    except Exception as e:
        return {
            'success': False,
            'status': 'Connection Failed',
            'error': str(e)
        }


def get_evm_balance(address: str, chain_key: str = 'ethereum') -> Dict[str, Any]:
    rpc_url, headers, symbol = get_rpc_headers_and_url(chain_key)
    explorer_tmpl = EVM_RPCS.get(chain_key.lower(), EVM_RPCS['ethereum'])[1]
    explorer_url = explorer_tmpl.format(address=address)

    payload = {
        'jsonrpc': '2.0',
        'method': 'eth_getBalance',
        'params': [address, 'latest'],
        'id': 1
    }
    req = urllib.request.Request(
        rpc_url,
        data=json.dumps(payload).encode('utf-8'),
        headers=headers
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            wei = int(data.get('result', '0x0'), 16)
            bal = wei / 1e18
            return {
                'address': address,
                'provider': rpc_url,
                'explorerUrl': explorer_url,
                'totalSatoshis': wei,
                'balanceBtc': f"{bal:.8f} {symbol}",
                'txCount': 0
            }
    except Exception as e:
        return {
            'address': address,
            'explorerUrl': explorer_url,
            'balanceBtc': f"0.00000000 {symbol}",
            'error': str(e)
        }


def get_solana_balance(address: str) -> Dict[str, Any]:
    explorer_url = f"https://solscan.io/account/{address}"
    payload = {
        'jsonrpc': '2.0',
        'id': 1,
        'method': 'getBalance',
        'params': [address]
    }
    req = urllib.request.Request(
        'https://api.mainnet-beta.solana.com',
        data=json.dumps(payload).encode('utf-8'),
        headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Python-Engine/1.0'}
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            lamports = data.get('result', {}).get('value', 0)
            bal = lamports / 1e9
            return {
                'address': address,
                'provider': 'Solana Mainnet RPC',
                'explorerUrl': explorer_url,
                'totalSatoshis': lamports,
                'balanceBtc': f"{bal:.8f} SOL",
                'txCount': 0
            }
    except Exception as e:
        return {
            'address': address,
            'explorerUrl': explorer_url,
            'balanceBtc': "0.00000000 SOL",
            'error': str(e)
        }


def get_ltc_balance(address: str) -> Dict[str, Any]:
    explorer_url = f"https://litecoinspace.org/address/{address}"
    url = f"https://litecoinspace.org/api/address/{address}"
    req = urllib.request.Request(url, headers={'User-Agent': 'HDWallet-Python-Engine/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            data = json.loads(response.read().decode('utf-8'))
            chain_stats = data.get('chain_stats', {})
            mempool_stats = data.get('mempool_stats', {})
            funded = chain_stats.get('funded_txo_sum', 0)
            spent = chain_stats.get('spent_txo_sum', 0)
            confirmed_sats = funded - spent
            mempool_funded = mempool_stats.get('funded_txo_sum', 0)
            mempool_spent = mempool_stats.get('spent_txo_sum', 0)
            unconfirmed_sats = mempool_funded - mempool_spent
            total_sats = confirmed_sats + unconfirmed_sats
            tx_count = chain_stats.get('funded_txo_count', 0) + mempool_stats.get('funded_txo_count', 0)
            return {
                'address': address,
                'provider': 'litecoinspace.org',
                'explorerUrl': explorer_url,
                'confirmedSatoshis': confirmed_sats,
                'unconfirmedSatoshis': unconfirmed_sats,
                'totalSatoshis': total_sats,
                'balanceBtc': f"{(total_sats / 1e8):.8f} LTC",
                'txCount': tx_count,
            }
    except Exception as e:
        # Fallback to BlockCypher
        try:
            url_bc = f"https://api.blockcypher.com/v1/ltc/main/addrs/{address}/balance"
            req_bc = urllib.request.Request(url_bc, headers={'User-Agent': 'HDWallet-Python-Engine/1.0'})
            with urllib.request.urlopen(req_bc, timeout=6) as resp_bc:
                data_bc = json.loads(resp_bc.read().decode('utf-8'))
                final_bal = data_bc.get('final_balance', 0)
                return {
                    'address': address,
                    'provider': 'BlockCypher LTC',
                    'explorerUrl': explorer_url,
                    'totalSatoshis': final_bal,
                    'balanceBtc': f"{(final_bal / 1e8):.8f} LTC",
                    'txCount': data_bc.get('n_tx', 0)
                }
        except Exception as e2:
            return {
                'address': address,
                'explorerUrl': explorer_url,
                'balanceBtc': "0.00000000 LTC",
                'txCount': 0,
                'error': str(e2)
            }


def get_doge_balance(address: str) -> Dict[str, Any]:
    explorer_url = f"https://dogechain.info/address/{address}"
    try:
        url_bc = f"https://api.blockcypher.com/v1/doge/main/addrs/{address}/balance"
        req_bc = urllib.request.Request(url_bc, headers={'User-Agent': 'HDWallet-Python-Engine/1.0'})
        with urllib.request.urlopen(req_bc, timeout=6) as resp_bc:
            data_bc = json.loads(resp_bc.read().decode('utf-8'))
            final_bal = data_bc.get('final_balance', 0)
            return {
                'address': address,
                'provider': 'BlockCypher DOGE',
                'explorerUrl': explorer_url,
                'totalSatoshis': final_bal,
                'balanceBtc': f"{(final_bal / 1e8):.8f} DOGE",
                'txCount': data_bc.get('n_tx', 0)
            }
    except Exception as e:
        return {
            'address': address,
            'explorerUrl': explorer_url,
            'balanceBtc': "0.00000000 DOGE",
            'txCount': 0,
            'error': str(e)
        }


def get_address_balance(address: str, network: str = 'bitcoin', use_cache: bool = True) -> Dict[str, Any]:
    net = network.lower().strip()
    cache_key = (address, net)

    if use_cache:
        with _CACHE_LOCK:
            if cache_key in BALANCE_CACHE:
                return BALANCE_CACHE[cache_key]

    res = _fetch_address_balance_uncached(address, net)
    
    # Ensure normalized 'balance' and 'unit' fields exist
    if 'balance' not in res:
        bal_btc_str = str(res.get('balanceBtc', '')).strip()
        parts = bal_btc_str.split()
        val = 0.0
        unit = parts[1] if len(parts) > 1 else ''
        if parts:
            try:
                val = float(parts[0])
            except Exception:
                val = 0.0
        res['balance'] = val
        if 'unit' not in res:
            res['unit'] = unit

    if use_cache and 'error' not in res:
        with _CACHE_LOCK:
            BALANCE_CACHE[cache_key] = res
    return res



def _fetch_address_balance_uncached(address: str, net: str = 'bitcoin') -> Dict[str, Any]:
    if net in EVM_RPCS:
        return get_evm_balance(address, net)

    if net in ('solana', 'sol'):
        return get_solana_balance(address)

    if net in ('litecoin', 'ltc'):
        return get_ltc_balance(address)

    if net in ('dogecoin', 'doge'):
        return get_doge_balance(address)

    if net in ('tron', 'trx'):
        explorer_url = f"https://tronscan.org/#/address/{address}"
        try:
            url_tx = f"https://apilist.tronscanapi.com/api/account?address={address}"
            req_tx = urllib.request.Request(url_tx, headers={'User-Agent': 'HDWallet-Python-Engine/1.0'})
            with urllib.request.urlopen(req_tx, timeout=4) as resp_tx:
                data_tx = json.loads(resp_tx.read().decode('utf-8'))
                balance_sun = data_tx.get('balance', 0)
                bal_trx = balance_sun / 1e6
                return {
                    'address': address,
                    'provider': 'TronScan',
                    'explorerUrl': explorer_url,
                    'totalSatoshis': balance_sun,
                    'balanceBtc': f"{bal_trx:.6f} TRX",
                    'txCount': data_tx.get('totalTransactionCount', 0)
                }
        except Exception as e:
            return {
                'address': address,
                'explorerUrl': explorer_url,
                'balanceBtc': "0.000000 TRX",
                'txCount': 0,
                'error': str(e)
            }

    if net in ('xrp', 'ripple'):
        explorer_url = f"https://xrpscan.com/account/{address}"
        payload = {
            'method': 'account_info',
            'params': [
                {
                    'account': address,
                    'ledger_index': 'validated',
                    'strict': True
                }
            ]
        }
        req = urllib.request.Request(
            'https://xrplcluster.com/',
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Python-Engine/1.0'}
        )
        try:
            with urllib.request.urlopen(req, timeout=6) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                res = data.get('result', {})

                # Check if account is unfunded (actNotFound)
                if res.get('error') in ('actNotFound', 'Account not found.'):
                    return {
                        'address': address,
                        'provider': 'xrplcluster.com',
                        'explorerUrl': explorer_url,
                        'totalSatoshis': 0,
                        'balanceBtc': "0.000000 XRP",
                        'txCount': 0
                    }

                if res.get('status') == 'success':
                    acc_data = res.get('account_data', {})
                    drops = int(acc_data.get('Balance', 0))
                    xrp_val = drops / 1e6
                    seq = acc_data.get('Sequence', 0)
                    return {
                        'address': address,
                        'provider': 'xrplcluster.com',
                        'explorerUrl': explorer_url,
                        'totalSatoshis': drops,
                        'balanceBtc': f"{xrp_val:.6f} XRP",
                        'txCount': seq
                    }

                err_msg = res.get('error_message', res.get('error', 'Error querying XRPL'))
                return {
                    'address': address,
                    'explorerUrl': explorer_url,
                    'balanceBtc': "0.000000 XRP",
                    'txCount': 0,
                    'error': err_msg
                }
        except Exception as e:
            return {
                'address': address,
                'explorerUrl': explorer_url,
                'balanceBtc': "0.000000 XRP",
                'txCount': 0,
                'error': str(e)
            }

    if net not in ('bitcoin', 'btc', 'testnet', 'tbtc'):
        return {
            'address': address,
            'explorerUrl': '',
            'balanceBtc': f"0.00000000 {net.upper()}",
            'txCount': 0
        }

    if net in ('testnet', 'tbtc'):
        url_tmpl = 'https://mempool.space/testnet/api/address/{address}'
        explorer_url = f"https://mempool.space/testnet/address/{address}"
    else:
        url_tmpl = 'https://mempool.space/api/address/{address}'
        explorer_url = f"https://mempool.space/address/{address}"

    req = urllib.request.Request(url_tmpl.format(address=address), headers={'User-Agent': 'HDWallet-Python-Engine/1.0'})
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            data = json.loads(response.read().decode('utf-8'))
            chain_stats = data.get('chain_stats', {})
            mempool_stats = data.get('mempool_stats', {})

            funded = chain_stats.get('funded_txo_sum', 0)
            spent = chain_stats.get('spent_txo_sum', 0)
            confirmed_sats = funded - spent

            mempool_funded = mempool_stats.get('funded_txo_sum', 0)
            mempool_spent = mempool_stats.get('spent_txo_sum', 0)
            unconfirmed_sats = mempool_funded - mempool_spent

            total_sats = confirmed_sats + unconfirmed_sats
            tx_count = chain_stats.get('funded_txo_count', 0) + mempool_stats.get('funded_txo_count', 0)

            return {
                'address': address,
                'provider': 'mempool.space',
                'explorerUrl': explorer_url,
                'confirmedSatoshis': confirmed_sats,
                'unconfirmedSatoshis': unconfirmed_sats,
                'totalSatoshis': total_sats,
                'balanceBtc': f"{(total_sats / 1e8):.8f} BTC",
                'txCount': tx_count,
                'fundedSatoshis': funded,
                'spentSatoshis': spent
            }
    except Exception as e:
        return {
            'address': address,
            'explorerUrl': explorer_url,
            'balanceBtc': "0.00000000 BTC",
            'txCount': 0,
            'error': str(e)
        }


COMMON_TOKENS = {
    'bnb': [
        {'symbol': 'TERK', 'name': 'Terkehh', 'contract': '0x53035E4e14fb3f82C02357B35d5cC0C5b53928B4', 'decimals': 18},
        {'symbol': 'USDT', 'name': 'Tether USD', 'contract': '0x55d398326f99059fF775485246999027B3197955', 'decimals': 18},
        {'symbol': 'USDC', 'name': 'USD Coin', 'contract': '0x8AC76a51cc950d9822D68b83fE1Ad97B32Cd580d', 'decimals': 18},
        {'symbol': 'WBNB', 'name': 'Wrapped BNB', 'contract': '0xbb4CdB9CBd36B01bD1cBaEBF2De08d9173bc095c', 'decimals': 18},
        {'symbol': 'CAKE', 'name': 'PancakeSwap Token', 'contract': '0x0E09FaBB73Bd3Ade0a17ECC321fD13a19e81cE82', 'decimals': 18},
        {'symbol': 'BUSD', 'name': 'Binance USD', 'contract': '0xe9e7CEA3DedcA5984780Bafc599bD69ADd087D56', 'decimals': 18},
    ],
    'ethereum': [
        {'symbol': 'USDT', 'name': 'Tether USD', 'contract': '0xdAC17F958D2ee523a2206206994597C13D831ec7', 'decimals': 6},
        {'symbol': 'USDC', 'name': 'USD Coin', 'contract': '0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48', 'decimals': 6},
        {'symbol': 'DAI', 'name': 'Dai Stablecoin', 'contract': '0x6B175474E89094C44Da98b954EedeAC495271d0F', 'decimals': 18},
        {'symbol': 'LINK', 'name': 'ChainLink Token', 'contract': '0x514910771AF9Ca656af840dff83E8264EcF986CA', 'decimals': 18},
        {'symbol': 'UNI', 'name': 'Uniswap', 'contract': '0x1f9840a85d5aF5bf1D1762F925BDADdC4201F984', 'decimals': 18},
    ]
}


def get_token_balances(address: str, chain: str = 'bnb') -> List[Dict[str, Any]]:
    """Query balance for all common tokens (including TERK) on BSC or Ethereum."""
    tokens = COMMON_TOKENS.get(chain.lower(), [])
    rpc_url, explorer_tmpl, _ = EVM_RPCS.get(chain.lower(), EVM_RPCS['bnb'])
    results = []
    
    clean_addr = address.lower().replace("0x", "")
    for tok in tokens:
        c_addr = tok['contract']
        dec = tok['decimals']
        sym = tok['symbol']
        call_data = "0x70a08231" + "000000000000000000000000" + clean_addr
        
        payload = {
            'jsonrpc': '2.0',
            'method': 'eth_call',
            'params': [{'to': c_addr, 'data': call_data}, 'latest'],
            'id': 1
        }
        req = urllib.request.Request(
            rpc_url,
            data=json.dumps(payload).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'User-Agent': 'HDWallet-Python-Engine/1.0'}
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode('utf-8'))
                res_hex = data.get('result', '0x')
                if res_hex and res_hex != '0x':
                    raw_val = int(res_hex, 16)
                    val = raw_val / (10 ** dec)
                else:
                    raw_val = 0
                    val = 0.0
                results.append({
                    'symbol': sym,
                    'name': tok['name'],
                    'contract': c_addr,
                    'decimals': dec,
                    'balance': val,
                    'balance_formatted': f"{val:,.4f} {sym}",
                    'raw_balance': raw_val
                })
        except Exception as e:
            results.append({
                'symbol': sym,
                'name': tok['name'],
                'contract': c_addr,
                'decimals': dec,
                'balance': 0.0,
                'balance_formatted': f"0.0000 {sym}",
                'error': str(e)
            })
    return results


def get_batch_balances(addresses: List[str], network: str = 'bitcoin', max_workers: int = 10) -> List[Dict[str, Any]]:
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(lambda addr: get_address_balance(addr, network), addresses))
    return results


"""
Autonomous Fund & Derivation Path Discovery Engine.
Systematically scans all known wallet derivation standards, accounts, change branches,
and index ranges across 20+ blockchains in parallel to discover active derivation paths and on-chain funds.
"""

import time
import json
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional, Callable

from .wallet import HDWallet
from .balance import get_address_balance
from .sweep import EVM_SWEEP_CHAINS

# Comprehensive Derivation Path Templates
DERIVATION_TEMPLATES = [
    # --- BITCOIN (BTC) ---
    {
        'coin': 'Bitcoin',
        'symbol': 'BTC',
        'network': 'bitcoin',
        'standard': 'BIP-84 (Native SegWit Bech32)',
        'addr_key': 'addressP2WPKH',
        'paths': [f"m/84'/0'/0'/0/{i}" for i in range(10)] + [f"m/84'/0'/0'/1/{i}" for i in range(3)] + [f"m/84'/0'/1'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Bitcoin',
        'symbol': 'BTC',
        'network': 'bitcoin',
        'standard': 'BIP-49 (Nested SegWit P2SH)',
        'addr_key': 'addressP2SH',
        'paths': [f"m/49'/0'/0'/0/{i}" for i in range(10)] + [f"m/49'/0'/0'/1/{i}" for i in range(3)]
    },
    {
        'coin': 'Bitcoin',
        'symbol': 'BTC',
        'network': 'bitcoin',
        'standard': 'BIP-44 (Legacy P2PKH)',
        'addr_key': 'addressP2PKH',
        'paths': [f"m/44'/0'/0'/0/{i}" for i in range(10)] + [f"m/44'/0'/0'/1/{i}" for i in range(3)] + [f"m/44'/0'/1'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Bitcoin',
        'symbol': 'BTC',
        'network': 'bitcoin',
        'standard': 'BIP-86 (Taproot P2TR)',
        'addr_key': 'addressP2TR',
        'paths': [f"m/86'/0'/0'/0/{i}" for i in range(5)]
    },
    {
        'coin': 'Bitcoin',
        'symbol': 'BTC',
        'network': 'bitcoin',
        'standard': 'Electrum Native SegWit',
        'addr_key': 'addressP2WPKH',
        'paths': [f"m/0'/{i}" for i in range(5)] + [f"m/0/{i}" for i in range(5)]
    },

    # --- ETHEREUM & EVM NETWORKS ---
    {
        'coin': 'Ethereum',
        'symbol': 'ETH',
        'network': 'ethereum',
        'standard': 'BIP-44 Standard (MetaMask / Trust)',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(5)]
    },
    {
        'coin': 'Ethereum',
        'symbol': 'ETH',
        'network': 'ethereum',
        'standard': 'Ledger Live EVM',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/{i}'/0/0" for i in range(5)]
    },
    {
        'coin': 'Ethereum',
        'symbol': 'ETH',
        'network': 'ethereum',
        'standard': 'Ledger Legacy (MEW)',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/{i}" for i in range(5)]
    },
    {
        'coin': 'BNB Chain',
        'symbol': 'BNB',
        'network': 'bnb',
        'standard': 'BIP-44 BNB Smart Chain',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Polygon',
        'symbol': 'POL',
        'network': 'polygon',
        'standard': 'BIP-44 Polygon',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Arbitrum',
        'symbol': 'ETH',
        'network': 'arbitrum',
        'standard': 'BIP-44 Arbitrum One',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Base',
        'symbol': 'ETH',
        'network': 'base',
        'standard': 'BIP-44 Base L2',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Optimism',
        'symbol': 'ETH',
        'network': 'optimism',
        'standard': 'BIP-44 Optimism',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Avalanche',
        'symbol': 'AVAX',
        'network': 'avalanche',
        'standard': 'BIP-44 Avalanche C-Chain',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'zkSync Era',
        'symbol': 'ETH',
        'network': 'zksync',
        'standard': 'BIP-44 zkSync Era',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Fantom',
        'symbol': 'FTM',
        'network': 'fantom',
        'standard': 'BIP-44 Fantom',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Linea',
        'symbol': 'ETH',
        'network': 'linea',
        'standard': 'BIP-44 Linea',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Blast',
        'symbol': 'ETH',
        'network': 'blast',
        'standard': 'BIP-44 Blast',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Scroll',
        'symbol': 'ETH',
        'network': 'scroll',
        'standard': 'BIP-44 Scroll',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Mantle',
        'symbol': 'MNT',
        'network': 'mantle',
        'standard': 'BIP-44 Mantle',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Cronos',
        'symbol': 'CRO',
        'network': 'cronos',
        'standard': 'BIP-44 Cronos',
        'addr_key': 'addressETH',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },

    # --- NON-EVM ECOSYSTEMS ---
    {
        'coin': 'Solana',
        'symbol': 'SOL',
        'network': 'solana',
        'standard': 'Phantom / Solflare',
        'addr_key': 'addressSOL',
        'paths': ["m/44'/501'/0'/0'", "m/44'/501'/1'/0'", "m/44'/501'/0'", "m/44'/501'/1'"]
    },
    {
        'coin': 'XRP',
        'symbol': 'XRP',
        'network': 'xrp',
        'standard': 'BIP-44 Ripple',
        'addr_key': 'addressXRP',
        'paths': [f"m/44'/144'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'TRON',
        'symbol': 'TRX',
        'network': 'tron',
        'standard': 'BIP-44 TronLink',
        'addr_key': 'addressTRX',
        'paths': [f"m/44'/195'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Dogecoin',
        'symbol': 'DOGE',
        'network': 'dogecoin',
        'standard': 'BIP-44 Dogecoin',
        'addr_key': 'addressDOGE',
        'paths': [f"m/44'/3'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Litecoin',
        'symbol': 'LTC',
        'network': 'litecoin',
        'standard': 'BIP-84 Native SegWit',
        'addr_key': 'addressP2WPKH',
        'paths': [f"m/84'/2'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Litecoin',
        'symbol': 'LTC',
        'network': 'litecoin',
        'standard': 'BIP-44 Legacy',
        'addr_key': 'addressP2PKH',
        'paths': [f"m/44'/2'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Bitcoin Cash',
        'symbol': 'BCH',
        'network': 'bch',
        'standard': 'BIP-44 Bitcoin Cash',
        'addr_key': 'addressP2PKH',
        'paths': [f"m/44'/145'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Zcash',
        'symbol': 'ZEC',
        'network': 'zec',
        'standard': 'BIP-44 Zcash',
        'addr_key': 'addressZEC',
        'paths': [f"m/44'/133'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Dash',
        'symbol': 'DASH',
        'network': 'dash',
        'standard': 'BIP-44 Dash',
        'addr_key': 'addressDASH',
        'paths': [f"m/44'/5'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Cosmos Hub',
        'symbol': 'ATOM',
        'network': 'atom',
        'standard': 'BIP-44 Cosmos',
        'addr_key': 'addressATOM',
        'paths': [f"m/44'/118'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Cardano',
        'symbol': 'ADA',
        'network': 'ada',
        'standard': 'BIP-1852 Cardano',
        'addr_key': 'addressADA',
        'paths': [f"m/1852'/1815'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Polkadot',
        'symbol': 'DOT',
        'network': 'dot',
        'standard': 'BIP-44 Polkadot',
        'addr_key': 'addressDOT',
        'paths': ["m/44'/354'/0'/0'/0'"]
    },
    {
        'coin': 'Stellar',
        'symbol': 'XLM',
        'network': 'xlm',
        'standard': 'BIP-44 Stellar',
        'addr_key': 'addressXLM',
        'paths': [f"m/44'/148'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Aptos',
        'symbol': 'APT',
        'network': 'aptos',
        'standard': 'BIP-44 Aptos',
        'addr_key': 'addressAPT',
        'paths': ["m/44'/637'/0'/0'"]
    },
    {
        'coin': 'Sui',
        'symbol': 'SUI',
        'network': 'sui',
        'standard': 'BIP-44 Sui',
        'addr_key': 'addressSUI',
        'paths': ["m/44'/784'/0'/0'"]
    },
    {
        'coin': 'NEAR Protocol',
        'symbol': 'NEAR',
        'network': 'near',
        'standard': 'BIP-44 NEAR',
        'addr_key': 'addressNEAR',
        'paths': ["m/44'/397'/0'"]
    },
    {
        'coin': 'Kaspa',
        'symbol': 'KAS',
        'network': 'kaspa',
        'standard': 'BIP-44 Kaspa',
        'addr_key': 'addressKAS',
        'paths': ["m/44'/111111'/0'"]
    },
    {
        'coin': 'Injective',
        'symbol': 'INJ',
        'network': 'injective',
        'standard': 'BIP-44 Injective',
        'addr_key': 'addressINJ',
        'paths': [f"m/44'/60'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Ravencoin',
        'symbol': 'RVN',
        'network': 'ravencoin',
        'standard': 'BIP-44 Ravencoin',
        'addr_key': 'addressRVN',
        'paths': [f"m/44'/175'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Bitcoin Gold',
        'symbol': 'BTG',
        'network': 'btg',
        'standard': 'BIP-44 Bitcoin Gold',
        'addr_key': 'addressBTG',
        'paths': [f"m/44'/156'/0'/0/{i}" for i in range(3)]
    },
    {
        'coin': 'Bitcoin SV',
        'symbol': 'BSV',
        'network': 'bsv',
        'standard': 'BIP-44 Bitcoin SV',
        'addr_key': 'addressBSV',
        'paths': [f"m/44'/236'/0'/0/{i}" for i in range(3)]
    },
]


def check_target_balance(target: Dict[str, Any]) -> Dict[str, Any]:
    """Query balance for a single target address item."""
    addr = target['address']
    net = target['network']
    try:
        bal_data = get_address_balance(addr, network=net)
        sat = bal_data.get('totalSatoshis', 0)
        txs = bal_data.get('txCount', 0)
        bal_str = bal_data.get('balanceBtc', f"0.00000000 {target['symbol']}")

        # Determine if address has funds or history
        has_funds = sat > 0
        if not has_funds:
            # Check string balance for non-satoshi balance networks
            try:
                numeric_part = bal_str.split()[0]
                has_funds = float(numeric_part) > 0
            except Exception:
                has_funds = False

        has_activity = txs > 0 or has_funds

        return {
            **target,
            'balance': bal_str,
            'total_satoshis': sat,
            'tx_count': txs,
            'has_funds': has_funds,
            'has_activity': has_activity,
            'balanceData': bal_data,
            'explorerUrl': bal_data.get('explorerUrl', '')
        }
    except Exception as e:
        return {
            **target,
            'balance': f"0.00000000 {target['symbol']}",
            'total_satoshis': 0,
            'tx_count': 0,
            'has_funds': False,
            'has_activity': False,
            'balanceData': {'error': str(e)},
            'error': str(e),
            'explorerUrl': ''
        }


def discover_wallet_funds(
    key_or_mnemonic: str,
    passphrase: str = "",
    progress_callback: Optional[Callable[[Dict[str, Any]], None]] = None,
    max_workers: int = 16
) -> Dict[str, Any]:
    """
    Exhaustively scan all derivation path templates in parallel across all supported chains.
    """
    wallet = HDWallet(key_or_mnemonic.strip(), passphrase=passphrase, network="bitcoin")

    scan_targets = []
    seen = set()

    for tmpl in DERIVATION_TEMPLATES:
        raw_net = tmpl.get('network', 'bitcoin')
        coin_net = raw_net[0] if isinstance(raw_net, list) else raw_net
        try:
            coin_wallet = HDWallet(key_or_mnemonic.strip(), passphrase=passphrase, network=coin_net)
        except Exception:
            coin_wallet = wallet

        for path in tmpl['paths']:
            try:
                k = coin_wallet.derive_key(path)
                addr_k = tmpl['addr_key']
                addr_key_str = addr_k[0] if isinstance(addr_k, list) else addr_k
                addr = k.get(addr_key_str) or k.get('addressP2PKH') or k.get('addressP2WPKH')
                if not addr or addr == 'N/A':
                    continue

                item_key = (tmpl['network'], path, addr)
                if item_key in seen:
                    continue
                seen.add(item_key)

                scan_targets.append({
                    'coin': tmpl['coin'],
                    'symbol': tmpl['symbol'],
                    'network': tmpl['network'],
                    'standard': tmpl['standard'],
                    'path': path,
                    'address': addr,
                    'publicKeyHex': k.get('publicKeyHex', ''),
                    'privateKeyHex': k.get('privateKeyHex', ''),
                    'privateKeyWif': k.get('privateKeyWif', '')
                })
            except Exception:
                continue

    all_results: List[Dict[str, Any]] = []

    def _worker(target):
        res = check_target_balance(target)
        if progress_callback:
            progress_callback(res)
        return res

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        all_results = list(pool.map(_worker, scan_targets))

    funded = [r for r in all_results if r['has_funds']]
    active = [r for r in all_results if r['has_activity']]

    return {
        'input': key_or_mnemonic,
        'mnemonic': wallet.mnemonic or key_or_mnemonic,
        'passphrase': passphrase,
        'total_scanned_addresses': len(all_results),
        'funded_count': len(funded),
        'active_count': len(active),
        'funded_derivations': funded,
        'active_derivations': active,
        'all_derivations': all_results
    }

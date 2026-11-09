"""
Coin specifications and BIP derivation path configurations for 18 supported blockchains.
"""

from typing import Dict, Any, List

SUPPORTED_COINS: List[Dict[str, Any]] = [
    {
        'name': 'Bitcoin',
        'symbol': 'BTC',
        'coinCode': 0,
        'bip44Path': "m/44'/0'/0'",
        'bip84Path': "m/84'/0'/0'",
        'defaultPrefix': {
            'xprv': 0x0488ade4,
            'xpub': 0x0488b21e,
            'zprv': 0x04b2430c,
            'zpub': 0x04b2438c,
            'yprv': 0x049d7878,
            'ypub': 0x049d7cb2,
        }
    },
    {
        'name': 'Bitcoin Testnet',
        'symbol': 'TBTC',
        'coinCode': 1,
        'bip44Path': "m/44'/1'/0'",
        'bip84Path': "m/84'/1'/0'",
        'defaultPrefix': {
            'xprv': 0x04358394,
            'xpub': 0x043587cf,
            'zprv': 0x045f18bc,
            'zpub': 0x045f1cf6,
            'yprv': 0x044a5262,
            'ypub': 0x044a5628,
        }
    },
    {
        'name': 'Ethereum',
        'symbol': 'ETH',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'BNB Chain',
        'symbol': 'BNB',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Arbitrum',
        'symbol': 'ARB',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Optimism',
        'symbol': 'OP',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Base',
        'symbol': 'BASE',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Polygon',
        'symbol': 'POL',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Avalanche',
        'symbol': 'AVAX',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'zkSync Era',
        'symbol': 'ZKSYNC',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Solana',
        'symbol': 'SOL',
        'coinCode': 501,
        'bip44Path': "m/44'/501'/0'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Tron',
        'symbol': 'TRX',
        'coinCode': 195,
        'bip44Path': "m/44'/195'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'TON',
        'symbol': 'TON',
        'coinCode': 607,
        'bip44Path': "m/44'/607'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Sui',
        'symbol': 'SUI',
        'coinCode': 784,
        'bip44Path': "m/44'/784'/0'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'XRP',
        'symbol': 'XRP',
        'coinCode': 144,
        'bip44Path': "m/44'/144'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Litecoin',
        'symbol': 'LTC',
        'coinCode': 2,
        'bip44Path': "m/44'/2'/0'",
        'bip84Path': "m/84'/2'/0'",
        'defaultPrefix': {
            'xprv': 0x019d9cfe,
            'xpub': 0x019da462,
            'zprv': 0x04b2430c,
            'zpub': 0x04b2438c,
        }
    },
    {
        'name': 'Bitcoin Cash',
        'symbol': 'BCH',
        'coinCode': 145,
        'bip44Path': "m/44'/145'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Dogecoin',
        'symbol': 'DOGE',
        'coinCode': 3,
        'bip44Path': "m/44'/3'/0'",
        'defaultPrefix': {'xprv': 0x02fac398, 'xpub': 0x02facafd}
    },
    {
        'name': 'Zcash',
        'symbol': 'ZEC',
        'coinCode': 133,
        'bip44Path': "m/44'/133'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Cosmos Hub',
        'symbol': 'ATOM',
        'coinCode': 118,
        'bip44Path': "m/44'/118'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Dash',
        'symbol': 'DASH',
        'coinCode': 5,
        'bip44Path': "m/44'/5'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Cardano',
        'symbol': 'ADA',
        'coinCode': 1815,
        'bip44Path': "m/1852'/1815'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Polkadot',
        'symbol': 'DOT',
        'coinCode': 354,
        'bip44Path': "m/44'/354'/0'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Stellar',
        'symbol': 'XLM',
        'coinCode': 148,
        'bip44Path': "m/44'/148'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Aptos',
        'symbol': 'APT',
        'coinCode': 637,
        'bip44Path': "m/44'/637'/0'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Fantom',
        'symbol': 'FTM',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Linea',
        'symbol': 'LINEA',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Blast',
        'symbol': 'BLAST',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Scroll',
        'symbol': 'SCROLL',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Mantle',
        'symbol': 'MNT',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Cronos',
        'symbol': 'CRO',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'NEAR Protocol',
        'symbol': 'NEAR',
        'coinCode': 397,
        'bip44Path': "m/44'/397'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Kaspa',
        'symbol': 'KAS',
        'coinCode': 111111,
        'bip44Path': "m/44'/111111'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Injective',
        'symbol': 'INJ',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Algorand',
        'symbol': 'ALGO',
        'coinCode': 283,
        'bip44Path': "m/44'/283'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Tezos',
        'symbol': 'XTZ',
        'coinCode': 1729,
        'bip44Path': "m/44'/1729'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Filecoin',
        'symbol': 'FIL',
        'coinCode': 461,
        'bip44Path': "m/44'/461'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Osmosis',
        'symbol': 'OSMO',
        'coinCode': 118,
        'bip44Path': "m/44'/118'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Sei Network',
        'symbol': 'SEI',
        'coinCode': 118,
        'bip44Path': "m/44'/118'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Celestia',
        'symbol': 'TIA',
        'coinCode': 118,
        'bip44Path': "m/44'/118'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Gnosis Chain',
        'symbol': 'GNO',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Celo',
        'symbol': 'CELO',
        'coinCode': 52752,
        'bip44Path': "m/44'/52752'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Berachain',
        'symbol': 'BERA',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Monad',
        'symbol': 'MON',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Core DAO',
        'symbol': 'CORE',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Sonic / Fantom Sonic',
        'symbol': 'S',
        'coinCode': 60,
        'bip44Path': "m/44'/60'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Kava',
        'symbol': 'KAVA',
        'coinCode': 459,
        'bip44Path': "m/44'/459'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Ravencoin',
        'symbol': 'RVN',
        'coinCode': 175,
        'bip44Path': "m/44'/175'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Bitcoin SV',
        'symbol': 'BSV',
        'coinCode': 236,
        'bip44Path': "m/44'/236'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    },
    {
        'name': 'Bitcoin Gold',
        'symbol': 'BTG',
        'coinCode': 156,
        'bip44Path': "m/44'/156'/0'",
        'defaultPrefix': {'xprv': 0x0488ade4, 'xpub': 0x0488b21e}
    }
]

NETWORKS = {
    'bitcoin': {
        'p2pkh_prefix': b'\x00',
        'p2sh_prefix': b'\x05',
        'bech32_hrp': 'bc',
        'wif_prefix': b'\x80',
        'bip32_xprv': 0x0488ade4,
        'bip32_xpub': 0x0488b21e,
        'bip32_zprv': 0x04b2430c,
        'bip32_zpub': 0x04b2438c,
        'bip32_yprv': 0x049d7878,
        'bip32_ypub': 0x049d7cb2,
    },
    'testnet': {
        'p2pkh_prefix': b'\x6f',
        'p2sh_prefix': b'\xc4',
        'bech32_hrp': 'tb',
        'wif_prefix': b'\xef',
        'bip32_xprv': 0x04358394,
        'bip32_xpub': 0x043587cf,
        'bip32_zprv': 0x045f18bc,
        'bip32_zpub': 0x045f1cf6,
        'bip32_yprv': 0x044a5262,
        'bip32_ypub': 0x044a5628,
    },
    'litecoin': {
        'p2pkh_prefix': b'\x30',
        'p2sh_prefix': b'\x32',
        'bech32_hrp': 'ltc',
        'wif_prefix': b'\xb0',
        'bip32_xprv': 0x019d9cfe,
        'bip32_xpub': 0x019da462,
    },
    'dogecoin': {
        'p2pkh_prefix': b'\x1e',
        'p2sh_prefix': b'\x16',
        'bech32_hrp': 'doge',
        'wif_prefix': b'\x9e',
        'bip32_xprv': 0x02fac398,
        'bip32_xpub': 0x02facafd,
    },
    'dash': {
        'p2pkh_prefix': b'\x4c',
        'p2sh_prefix': b'\x10',
        'bech32_hrp': 'dash',
        'wif_prefix': b'\xcc',
        'bip32_xprv': 0x0488ade4,
        'bip32_xpub': 0x0488b21e,
    },
    'zcash': {
        'p2pkh_prefix': b'\x1c\xb8',
        'p2sh_prefix': b'\x1c\xbd',
        'bech32_hrp': 'zec',
        'wif_prefix': b'\x80',
        'bip32_xprv': 0x0488ade4,
        'bip32_xpub': 0x0488b21e,
    },
    'ravencoin': {
        'p2pkh_prefix': b'\x3c',
        'p2sh_prefix': b'\x7a',
        'bech32_hrp': 'rvn',
        'wif_prefix': b'\x80',
        'bip32_xprv': 0x0488ade4,
        'bip32_xpub': 0x0488b21e,
    },
    'bitcoingold': {
        'p2pkh_prefix': b'\x26',
        'p2sh_prefix': b'\x17',
        'bech32_hrp': 'btg',
        'wif_prefix': b'\x80',
        'bip32_xprv': 0x0488ade4,
        'bip32_xpub': 0x0488b21e,
    }
}


def get_coin(name_or_symbol: str) -> Any:
    """Retrieve coin configuration dictionary by symbol or name."""
    query = name_or_symbol.upper().strip()
    for coin in SUPPORTED_COINS:
        if coin['symbol'].upper() == query or coin['name'].upper() == query:
            return coin
    return None

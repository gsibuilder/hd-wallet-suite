"""
HD Wallet Key Derivation Engine in Python.
Supports BIP-32, BIP-39, BIP-44, BIP-49, BIP-84, Bech32, Bech32m (Taproot), Ethereum, Litecoin, Dogecoin, PSBT, and Deep Carving.
"""

from .wallet import (
    HDWallet,
    derive_wallet_from_mnemonic,
    derive_address_batch,
    generate_mnemonic,
    validate_mnemonic,
    derive_all_from_xprv
)
from .addresses import (
    encode_wif,
    decode_wif,
    is_valid_wif
)
from .auth import (
    check_auth_code,
    is_device_authorized,
    save_authorization,
    revoke_authorization,
    set_custom_auth_code,
    DEFAULT_AUTH_CODES
)
from .parser import (
    parse_wallet_file,
    find_wallet_derivations,
    inspect_database_file,
    discover_present_databases,
    detect_pywallet_engine
)
from .balance import (
    get_address_balance,
    get_batch_balances,
    get_token_balances,
    set_custom_rpc_node,
    test_custom_rpc_connection
)
from .private_key_finder import get_private_key_page, search_private_key_location, get_random_page_number
from .sweep import (
    sweep_evm,
    sweep_all_evm_chains,
    sweep_btc,
    sweep_sol,
    sweep_trx,
    sweep_all_multichain,
    EVM_SWEEP_CHAINS,
    DEFAULT_DESTINATIONS
)

from .descriptors import (
    generate_wallet_descriptors,
    derive_from_descriptor,
    derive_all_standard_descriptors,
    add_descriptor_checksum,
    verify_descriptor_checksum,
    descriptor_checksum,
    parse_sqlite_descriptor_wallet,
    parse_descriptor
)

from .psbt import (
    PSBT,
    PSBTMap,
    PSBT_MAGIC,
    address_to_script_pubkey,
    script_pubkey_to_address
)

from .carving import (
    DeepCarver,
    carve_artifacts,
    generate_forensic_report
)

from .fund_finder import (
    discover_wallet_funds,
    check_target_balance,
    DERIVATION_TEMPLATES
)

from .coins import (
    SUPPORTED_COINS,
    NETWORKS,
    get_coin
)


from .parse_wallet import (
    parse_wallet as parse_wallet_bdb
)

from .crypto_accel import (
    HAS_COINCURVE,
    HAS_WALLYCORE,
    get_crypto_engine_info,
    fast_privkey_to_pubkey,
    fast_pubkey_tweak_add,
    wally_bip32_derive_path
)

__all__ = [
    'HDWallet',
    'derive_wallet_from_mnemonic',
    'derive_address_batch',
    'generate_mnemonic',
    'validate_mnemonic',
    'parse_wallet_file',
    'find_wallet_derivations',
    'inspect_database_file',
    'discover_present_databases',
    'detect_pywallet_engine',
    'get_address_balance',
    'get_batch_balances',
    'get_private_key_page',
    'search_private_key_location',
    'get_random_page_number',
    'sweep_evm',
    'sweep_all_evm_chains',
    'sweep_btc',
    'sweep_sol',
    'sweep_trx',
    'sweep_all_multichain',
    'EVM_SWEEP_CHAINS',
    'DEFAULT_DESTINATIONS',
    'generate_wallet_descriptors',
    'derive_from_descriptor',
    'derive_all_standard_descriptors',
    'add_descriptor_checksum',
    'verify_descriptor_checksum',
    'descriptor_checksum',
    'parse_sqlite_descriptor_wallet',
    'PSBT',
    'PSBTMap',
    'PSBT_MAGIC',
    'address_to_script_pubkey',
    'script_pubkey_to_address',
    'DeepCarver',
    'carve_artifacts',
    'generate_forensic_report',
    'discover_wallet_funds',
    'check_target_balance',
    'DERIVATION_TEMPLATES',
    'SUPPORTED_COINS',
    'NETWORKS',
    'get_coin',
    'parse_descriptor',
    'parse_wallet_bdb',
    'HAS_COINCURVE',
    'HAS_WALLYCORE',
    'get_crypto_engine_info',
    'fast_privkey_to_pubkey',
    'fast_pubkey_tweak_add',
    'wally_bip32_derive_path'
]

__author__ = "Corey K."
__email__ = "hdwalletengine@proton.me"


"""
QThread-based worker classes for all blocking operations.
Ensures UI never freezes during crypto/network operations.
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'hd_wallet'))

from PyQt6.QtCore import QThread, pyqtSignal
from typing import Dict, Any, List, Optional


class DeriveKeyWorker(QThread):
    """Worker for single key derivation."""
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, wallet, path: str):
        super().__init__()
        self.wallet = wallet
        self.path = path

    def run(self):
        try:
            result = self.wallet.derive_key(self.path)
            self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class BatchDeriveWorker(QThread):
    """Worker for batch address derivation."""
    result = pyqtSignal(list)
    progress = pyqtSignal(int)
    error = pyqtSignal(str)

    def __init__(self, wallet, base_path: str, count: int, change: int = 0, start: int = 0):
        super().__init__()
        self.wallet = wallet
        self.base_path = base_path
        self.count = count
        self.change = change
        self.start_index = start

    def run(self):
        try:
            results = self.wallet.derive_address_batch(
                base_path=self.base_path,
                count=self.count,
                change=self.change,
                start_index=self.start_index
            )
            self.result.emit(results)
        except Exception as e:
            self.error.emit(str(e))


class BalanceCheckWorker(QThread):
    """Worker for checking a single address balance."""
    result = pyqtSignal(str, dict)  # address, balance_info
    error = pyqtSignal(str, str)  # address, error

    def __init__(self, address: str, network: str = 'bitcoin'):
        super().__init__()
        self.address = address
        self.network = network

    def run(self):
        try:
            from hd_wallet.balance import get_address_balance
            result = get_address_balance(self.address, self.network)
            self.result.emit(self.address, result)
        except Exception as e:
            self.error.emit(self.address, str(e))


class BatchBalanceWorker(QThread):
    """Worker for checking many balances in a batch."""
    address_result = pyqtSignal(int, str)   # row, balance string
    finished = pyqtSignal()
    progress = pyqtSignal(int, int)  # done, total

    def __init__(self, addresses: list, network: str = 'bitcoin'):
        super().__init__()
        self.addresses = addresses  # list of (row_idx, address, network)
        self.network = network
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        from hd_wallet.balance import get_address_balance
        for i, (row_idx, address, network) in enumerate(self.addresses):
            if self._stopped:
                break
            try:
                result = get_address_balance(address, network)
                bal = result.get('balance', 0) or 0
                unit = result.get('unit', '')
                if isinstance(bal, (int, float)) and bal > 0:
                    bal_str = f"{bal:.8f} {unit}".strip()
                else:
                    bal_str = "0.00000000"
                self.address_result.emit(row_idx, bal_str)
            except Exception:
                self.address_result.emit(row_idx, "---")
            self.progress.emit(i + 1, len(self.addresses))
        self.finished.emit()


class MultichainBalanceWorker(QThread):
    """Worker for checking all 50 chain balances."""
    coin_result = pyqtSignal(str, str, str)  # network_key, address, balance
    finished = pyqtSignal()

    def __init__(self, wallet, all_chains: list):
        super().__init__()
        self.wallet = wallet
        self.all_chains = all_chains  # list of (network_key, display_name, path, addr_key)
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        from hd_wallet.balance import get_address_balance
        for (net_key, display, path, addr_key) in self.all_chains:
            if self._stopped:
                break
            try:
                derived = self.wallet.derive_key(path)
                address = derived.get(addr_key, '')
                if not address:
                    self.coin_result.emit(net_key, '', '0.00000000')
                    continue
                result = get_address_balance(address, net_key)
                bal = result.get('balance', 0) or 0
                if isinstance(bal, (int, float)) and bal > 0:
                    bal_str = f"{bal:.8f}"
                else:
                    bal_str = "0.00000000"
                self.coin_result.emit(net_key, address, bal_str)
            except Exception:
                self.coin_result.emit(net_key, '', '0.00000000')
        self.finished.emit()


class KeySpaceWorker(QThread):
    """Worker for loading a page of raw secp256k1 private keys (privatekeyfinder.io style).

    Each key index (1, 2, 3, …) IS the raw 32-byte private key.  Public keys
    and addresses are derived directly from that raw key — no BIP-39 mnemonic
    derivation, no BIP-32 HD path.  This matches privatekeyfinder.io exactly.
    """
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    # Map network keys to the address dict key returned by get_private_key_page
    _NETWORK_ADDR_KEY = {
        'bitcoin':         'addressP2PKH',
        'bitcoin_legacy':  'addressP2PKH',
        'bitcoin_nested':  'addressP2SH',
        'bitcoin_taproot': 'addressP2TR',
        'ethereum':        'addressETH',
        'bnb':             'addressETH',
        'polygon':         'addressETH',
        'arbitrum':        'addressETH',
        'optimism':        'addressETH',
        'base':            'addressETH',
        'avalanche':       'addressETH',
        'fantom':          'addressETH',
        'zksync':          'addressETH',
        'linea':           'addressETH',
        'scroll':          'addressETH',
        'mantle':          'addressETH',
        'cronos':          'addressETH',
        'blast':           'addressETH',
        'tron':            'addressTRX',
        'xrp':             'addressP2PKH',
        'litecoin':        'addressP2PKH',
        'dogecoin':        'addressP2PKH',
        'dash':            'addressP2PKH',
        'zcash':           'addressP2PKH',
        'solana':          'addressP2PKH',
    }

    _NETWORK_SYMBOL = {
        'bitcoin': 'BTC', 'bitcoin_legacy': 'BTC', 'bitcoin_nested': 'BTC',
        'bitcoin_taproot': 'BTC', 'ethereum': 'ETH', 'bnb': 'BNB',
        'polygon': 'POL', 'arbitrum': 'ARB', 'optimism': 'OP',
        'base': 'BASE', 'avalanche': 'AVAX', 'fantom': 'FTM',
        'zksync': 'ZKSYNC', 'tron': 'TRX', 'xrp': 'XRP',
        'litecoin': 'LTC', 'dogecoin': 'DOGE', 'dash': 'DASH',
        'zcash': 'ZEC', 'solana': 'SOL',
    }

    def __init__(self, page: int, word_count: int = 12, network: str = 'bitcoin', derivation_path: str = "m/84'/0'/0'/0/0"):
        super().__init__()
        self.page = page
        self.word_count = word_count
        self.network = network
        self.derivation_path = derivation_path

    def run(self):
        try:
            from hd_wallet.private_key_finder import get_private_key_page

            data = get_private_key_page(self.page, word_count=self.word_count, network=self.network, derivation_path=self.derivation_path)

            # Pick the right address field for the selected network
            addr_key = self._NETWORK_ADDR_KEY.get(
                self.network.lower(), 'addressP2PKH'
            )
            symbol = self._NETWORK_SYMBOL.get(
                self.network.lower(), 'BTC'
            )

            # Enrich each key dict with a unified 'address' field and symbol
            for key_data in data.get('keys', []):
                key_data['address'] = key_data.get(addr_key, '') or key_data.get('addressP2PKH', '')
                key_data['network'] = self.network
                key_data['symbol'] = symbol

            data['symbol'] = symbol
            self.result.emit(data)
        except Exception as e:
            self.error.emit(str(e))


class KeySpaceSearchWorker(QThread):
    """Worker for searching the key space."""
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, query: str):
        super().__init__()
        self.query = query

    def run(self):
        try:
            from hd_wallet.private_key_finder import search_private_key_location
            result = search_private_key_location(self.query)
            self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class SweepWorker(QThread):
    """Worker for sweeping funds."""
    log = pyqtSignal(str)
    finished = pyqtSignal(bool, str)  # success, summary
    error = pyqtSignal(str)

    def __init__(self, wallet, destinations: dict):
        super().__init__()
        self.wallet = wallet
        self.destinations = destinations

    def run(self):
        try:
            from hd_wallet.sweep import sweep_loaded_wallet
            src = getattr(self.wallet, 'mnemonic', None) or getattr(self.wallet, 'raw_input', None) or self.wallet
            self.log.emit("Starting multichain sweep...")
            results = sweep_loaded_wallet(
                source_data=src,
                destinations=self.destinations
            )
            summary_lines = []
            for item in results:
                chain = item.get('chain', 'Unknown')
                tx = item.get('tx_hash') or item.get('txid')
                if item.get('success') and tx:
                    explorer = item.get('explorer_url', '')
                    msg = f"✅ {chain}: REAL ON-CHAIN BROADCAST! TX: {tx}"
                    if explorer:
                        msg += f"\n   🔗 Explorer: {explorer}"
                    summary_lines.append(msg)
                    self.log.emit(msg)
                elif item.get('success') and not tx:
                    amt = item.get('amount_formatted', '')
                    status_note = item.get('status', 'Not broadcasted')
                    msg = f"ℹ️ {chain}: {amt} found ({status_note}) — No transaction was broadcast."
                    self.log.emit(msg)
                else:
                    msg = item.get('error', item.get('message', 'Skipped'))
                    self.log.emit(f"— {chain}: {msg}")
            self.finished.emit(True, '\n'.join(summary_lines) if summary_lines else 'No on-chain transactions broadcasted.')
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))


class WalletDBWorker(QThread):
    """Worker for scanning/parsing wallet database files with robust fallback carving."""
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, path: Optional[str] = None, action: str = 'scan'):
        super().__init__()
        self.path = path
        self.action = action

    def run(self):
        try:
            if self.action == 'scan':
                from hd_wallet.parser import discover_present_databases
                dbs = discover_present_databases()
                self.result.emit({'databases': dbs})
            elif self.action == 'inspect' and self.path:
                records = []
                try:
                    from hd_wallet.parser import inspect_database_file, parse_wallet_file
                    
                    db_info = inspect_database_file(self.path)
                    records.append({
                        'type': '📁 File Info',
                        'address': db_info.get('format', 'Unknown Format'),
                        'private_key_wif': f"Encrypted: {db_info.get('is_encrypted', False)}",
                        'public_key': os.path.basename(self.path),
                        'descriptor': f"Size: {db_info.get('size_str', '')} | Records: {db_info.get('records_count', 0)}"
                    })

                    if db_info.get('mnemonic'):
                        records.append({
                            'type': '🔑 Master Mnemonic',
                            'address': 'BIP-39 Mnemonic Seed',
                            'private_key_wif': db_info['mnemonic'],
                            'public_key': db_info.get('root_xpub', ''),
                            'descriptor': 'Root Seed Phrase'
                        })
                    if db_info.get('root_xprv'):
                        records.append({
                            'type': '🔑 Extended Key',
                            'address': 'Master xprv',
                            'private_key_wif': db_info['root_xprv'],
                            'public_key': db_info.get('root_xpub', ''),
                            'descriptor': 'Master Root Extended Key'
                        })

                    for k in db_info.get('unencrypted_keys', []):
                        records.append({
                            'type': 'Unencrypted Key',
                            'address': k.get('address', 'N/A'),
                            'private_key_wif': k.get('wif', ''),
                            'public_key': k.get('pubkey', ''),
                            'descriptor': f"Compressed: {k.get('compressed', True)}"
                        })

                    for ea in db_info.get('extracted_addresses', []):
                        records.append({
                            'type': ea.get('type', 'Address'),
                            'address': ea.get('address', ''),
                            'private_key_wif': ea.get('wif', 'N/A'),
                            'public_key': ea.get('pubkey', ''),
                            'descriptor': ea.get('label', '')
                        })

                    # If no structured records extracted, run universal file parser
                    if len(records) <= 1:
                        with open(self.path, 'rb') as f:
                            raw_bytes = f.read()
                        parsed = parse_wallet_file(raw_bytes, filename=os.path.basename(self.path), check_balances=False)
                        if parsed.get('mnemonic'):
                            records.append({
                                'type': '🔑 Carved Mnemonic',
                                'address': 'BIP-39 Mnemonic',
                                'private_key_wif': parsed['mnemonic'],
                                'public_key': parsed.get('root_xpub', ''),
                                'descriptor': parsed.get('note', '')
                            })
                        for d in parsed.get('derivations', [])[:20]:
                            records.append({
                                'type': d.get('name', 'Derived Key'),
                                'address': d.get('address', ''),
                                'private_key_wif': d.get('privateKeyWif', ''),
                                'public_key': d.get('publicKeyHex', ''),
                                'descriptor': f"Path: {d.get('path', '')}"
                            })

                except Exception as bdb_err:
                    records.append({
                        'type': '⚠️ Parse Notice',
                        'address': 'BDB parser fallback triggered',
                        'private_key_wif': str(bdb_err),
                        'public_key': os.path.basename(self.path),
                        'descriptor': 'Scanning raw binary file for artifacts...'
                    })
                    try:
                        with open(self.path, 'rb') as f:
                            raw_data = f.read()

                        from hd_wallet.carving import carve_artifacts
                        import tempfile
                        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as tf:
                            tf.write(raw_data)
                            tmp_name = tf.name
                        carve_res = carve_artifacts(tmp_name)
                        os.unlink(tmp_name)

                        for wif_item in carve_res.get('wif_keys', []):
                            records.append({
                                'type': 'WIF Key',
                                'address': wif_item.get('address_legacy', 'N/A'),
                                'private_key_wif': wif_item.get('wif', ''),
                                'public_key': wif_item.get('pubkey_hex', ''),
                                'descriptor': f"Compressed: {wif_item.get('compressed', True)}"
                            })
                        for m_item in carve_res.get('mnemonics', []):
                            records.append({
                                'type': 'BIP-39 Mnemonic',
                                'address': m_item.get('address_p2wpkh', 'N/A'),
                                'private_key_wif': m_item.get('mnemonic', ''),
                                'public_key': '',
                                'descriptor': f"{m_item.get('word_count')} words"
                            })
                    except Exception as carve_err:
                        records.append({
                            'type': 'Error',
                            'address': 'Failed to parse file',
                            'private_key_wif': str(carve_err),
                            'public_key': '',
                            'descriptor': ''
                        })

                self.result.emit({'records': records})
        except Exception as e:
            self.error.emit(str(e))


class CarvingWorker(QThread):
    """Worker for deep forensic carving."""
    result = pyqtSignal(dict)
    progress = pyqtSignal(str)
    error = pyqtSignal(str)

    def __init__(self, source: Optional[str] = None, raw_text: Optional[str] = None):
        super().__init__()
        self.source = source
        self.raw_text = raw_text

    def run(self):
        try:
            from hd_wallet.carving import carve_artifacts, generate_forensic_report
            if self.source:
                self.progress.emit(f"Carving file: {self.source}")
                artifacts = carve_artifacts(self.source)
            elif self.raw_text:
                import tempfile, os
                with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                    f.write(self.raw_text)
                    tmp = f.name
                self.progress.emit("Carving raw text input...")
                artifacts = carve_artifacts(tmp)
                os.unlink(tmp)
            else:
                self.error.emit("No source provided")
                return
            report = generate_forensic_report(artifacts)
            self.result.emit({'artifacts': artifacts, 'report': report})
        except Exception as e:
            self.error.emit(str(e))


class DescriptorWorker(QThread):
    """Worker for generating wallet descriptors."""
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, wallet):
        super().__init__()
        self.wallet = wallet

    def run(self):
        try:
            from hd_wallet.descriptors import generate_wallet_descriptors
            result = generate_wallet_descriptors(self.wallet.master_xprv)
            self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class DescriptorDeriveWorker(QThread):
    """Worker for deriving addresses from a descriptor."""
    result = pyqtSignal(list)
    error = pyqtSignal(str)

    def __init__(self, descriptor: str, count: int = 50):
        super().__init__()
        self.descriptor = descriptor
        self.count = count

    def run(self):
        try:
            from hd_wallet.descriptors import derive_from_descriptor
            result = derive_from_descriptor(self.descriptor, count=self.count)
            self.result.emit(result)
        except Exception as e:
            self.error.emit(str(e))


class BTCRecoverWorker(QThread):
    """Worker for running BTCRecover password recovery."""
    log = pyqtSignal(str)
    finished = pyqtSignal(bool, str)
    error = pyqtSignal(str)

    def __init__(self, wallet_path: str, tokens: str, max_typos: int = 1):
        super().__init__()
        self.wallet_path = wallet_path
        self.tokens = tokens
        self.max_typos = max_typos
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        try:
            import subprocess
            btcrecover_dir = os.path.join(
                os.path.dirname(__file__), '..', 'hd_wallet', 'hd_wallet', 'btcrecover'
            )
            script = os.path.join(btcrecover_dir, 'btcrecover.py')
            if not os.path.exists(script):
                self.log.emit("BTCRecover script not found. Simulating recovery run...")
                import time
                for i, token in enumerate(self.tokens.split()):
                    if self._stopped:
                        break
                    self.log.emit(f"Trying password: {token}...")
                    time.sleep(0.3)
                self.finished.emit(False, "No password found (demo mode)")
                return

            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as tf:
                tf.write(self.tokens)
                token_file = tf.name

            cmd = [sys.executable, script,
                   '--wallet', self.wallet_path,
                   '--tokenlist', token_file,
                   '--typos', str(self.max_typos)]

            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                    text=True, bufsize=1)
            if proc.stdout is not None:
                for line in proc.stdout:
                    if self._stopped:
                        proc.terminate()
                        break
                    self.log.emit(line.rstrip())

            proc.wait()
            os.unlink(token_file)
            success = proc.returncode == 0
            self.finished.emit(success, "Recovery complete" if success else "No password found")
        except Exception as e:
            self.error.emit(str(e))
            self.finished.emit(False, str(e))


class PSBTWorker(QThread):
    """Worker for PSBT operations."""
    result = pyqtSignal(dict)
    error = pyqtSignal(str)

    def __init__(self, action: str, data: dict):
        super().__init__()
        self.action = action
        self.data = data

    def run(self):
        try:
            from hd_wallet.psbt import PSBT
            if self.action == 'load':
                psbt_str = self.data.get('psbt_string', '')
                if not psbt_str:
                    self.error.emit("No PSBT data provided")
                    return
                psbt = PSBT.from_base64(psbt_str) if not psbt_str.startswith('70736274') else PSBT.from_hex(psbt_str)
                self.result.emit({
                    'inputs': psbt.inputs,
                    'outputs': psbt.outputs,
                    'global_map': psbt.global_map,
                })
            elif self.action == 'sign':
                psbt_str = self.data.get('psbt_string', '')
                wif = self.data.get('private_key_wif', '')
                psbt = PSBT.from_base64(psbt_str) if not psbt_str.startswith('70736274') else PSBT.from_hex(psbt_str)
                count = psbt.sign([wif])
                self.result.emit({'signed_psbt': psbt.to_base64(), 'success': True, 'signatures_added': count})
            elif self.action == 'finalize':
                psbt_str = self.data.get('psbt_string', '')
                psbt = PSBT.from_base64(psbt_str) if not psbt_str.startswith('70736274') else PSBT.from_hex(psbt_str)
                psbt.finalize()
                raw_tx = psbt.extract_transaction()
                self.result.emit({'raw_tx': raw_tx, 'success': True})
        except Exception as e:
            self.error.emit(str(e))


class KeySpaceMultiChainBalanceWorker(QThread):
    """Worker for checking BTC, ETH, and TRX balances across key space table rows."""
    balance_result = pyqtSignal(int, str, str)  # row_idx, chain ('btc', 'eth', 'trx'), balance string
    finished = pyqtSignal()
    progress = pyqtSignal(int, int)

    def __init__(self, tasks: list):
        super().__init__()
        self.tasks = tasks  # list of (row_idx, chain_key, address, network)
        self._stopped = False

    def stop(self):
        self._stopped = True

    def run(self):
        from hd_wallet.balance import get_address_balance
        total = len(self.tasks)
        for i, (row_idx, chain_key, address, network) in enumerate(self.tasks):
            if self._stopped:
                break
            if not address:
                self.balance_result.emit(row_idx, chain_key, "0.00000000")
                continue
            try:
                result = get_address_balance(address, network)
                bal = result.get('balance', 0) or 0
                unit = result.get('unit', '')
                if isinstance(bal, (int, float)) and bal > 0:
                    bal_str = f"{bal:.8f} {unit}".strip()
                else:
                    bal_str = "0.00000000"
                self.balance_result.emit(row_idx, chain_key, bal_str)
            except Exception:
                self.balance_result.emit(row_idx, chain_key, "---")
            self.progress.emit(i + 1, total)
        self.finished.emit()


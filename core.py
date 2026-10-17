# Split of MCX81.py (lines 12533-20236). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import CYAN, GREEN, MLKEM_AVAILABLE, RESET, YELLOW, _DEPS, bcrypt, eth_keccak, logger, mlkem, new_trace_id, set_trace_id, yaml
from node.config import ACTIVE_MINER_WINDOW_BLOCKS, ACTIVE_MINER_WINDOW_SEC, API_PORT, BAN_THRESHOLD, BLOCK_CACHE_MAX, BLOCK_TIME, BURN_ADDRESSES, BURN_ADDRESS_ZERO, CHAIN_ID, CONSENSUS_EXCLUDED_FIELDS, EXTERNAL_IP, GENESIS_SUPPLY, MAX_SUPPLY, MIN_MAZE_SIZE, MIN_WALL_DENSITY_PPM, RPC_BIND_IP, SPATIAL_ACTIVATION_HEIGHT, SPATIAL_BASE_DEPLOY_FEE, SPATIAL_DEPLOY_FEE_MAZE_BPS, SPATIAL_MAX_NAME_LEN, SPATIAL_MAX_SUPPLY, SPATIAL_MAX_SYMBOL_LEN, SUBS, TOKEN_MAX_MINEABLE_SUPPLY, TOKEN_MAX_SUPPLY, VERSION, VM_TIMEOUT, WS_PORT, _block_att_weight, _block_limits_ok, _effective_validators, _fork_tiebreak_winner, _gas_ceiling, _mainnet_guard_failures, _maze_threshold, _maze_ticket, _normalize_validator_key, _valid_maze_size, _validator_boot_mode, apply_consensus_config, check_consensus_params, load_config
from node.genesis import MSG_GET_STATUS, MSG_NEW_MOVE, _effective_consensus_ruleset, _write_genesis_file_atomic, genesis_export_verified, load_genesis_file
from node.crypto import _BadInt, _block_gas_used, _block_timestamp_ok, _cors_origin_allowed, _cumulative_gas_used, _detect_lan_ip, _enrich_eth_log, _eth_sig_fields, _log_matches_filter, _logs_bloom, _rfloat_opt, _rint, _rpc_bearer_token, _rpc_remote_authorized, _tx_lists_consistent, _validate_ws_bind, _ws_app_routes, _ws_page_params, block_signing_payload, calculate_block_hash, canonical_json_bytes, compute_merkle_root, decrypt_private_key, derive_wallet_from_seed, encrypt_private_key, generate_mnemonic, hash_block, hash_tx, mnemonic_to_seed, pubkey_to_address, sign_bytes, sign_message, validate_rpc_security_config, verify_signature
from node.chain import StateTrie, _derive_spatial_coord, _derive_token_address, _moved_value_of, _raw_chain_id_ok, _reorg_base_mint, _spatial_fee_amount_ok, _validated_block_reward, compute_contract_address, decode_raw_eth_transaction, get_dynamic_fee, get_token_creation_fee, tx_data_to_bytes, tx_data_to_hex
from node.database import AutomationRepo, BalanceRepo, BlockRepo, ChallengeRepo, ContractEventRepo, ContractStateRepo, ContractStorageV2Repo, ContractV2Repo, Database, FinalityGadget, FinalityRepo, HTLCRepo, LotteryRepo, MazeAttestationRepo, MinerMazeRepo, MinerRepo, MultisigRepo, NetworkStateRepo, NodeRepo, ReceiptRepo, SlashRepo, SpatialTokenBalanceRepo, SpatialTokenRepo, TokenBalanceRepo, TokenRepo, TransactionRepo, _automation_replay_key, _automation_sig_replay, verify_automation_delete_auth
from node.mempool import MemoryChallengeManager, Mempool
from node.services import HealthChecker, RateLimiter
from node.vm import VMManager, export_vm_sandbox_env
from node.maze import sparse_to_dense
from node.consensus import PoGConsensus
from node.p2p import P2PNode, POW_BASE_DIFFICULTY
from node.bootstrap import Any, Dict, List, Tuple, asyncio, base64, deque, ec, hashlib, ipaddress, json, math, os, secrets, serialization, signal, sys, time, websockets
from node import config as _config
from node import genesis as _genesis


# ─── Main Node Class ────────────────────────────────────────────
class AuxStateError(Exception):
    # R5-append-aux-fail-loud: aux state is consensus-relevant; partial apply diverges followers. Fail the block.
    pass


class MicroCoreNode:
    """The main node class that orchestrates all components."""
    def __init__(self, config: dict = None):
        self.config = config or load_config()
        self.node_id = None
        self.wallet = None
        self.priv = None          # private key hex (never stored in plaintext after startup)
        self.pub = None           # public key hex
        self.password = None
        self.height = 0
        self.last_hash = "0"*64
        self.blocks = []          # list of block dicts (cached)
        self.total_minted = 0
        self.burned_total = 0
        self.miners: Dict[str, Dict] = {}   # miner_id -> miner dict
        self.nodes: Dict[str, Dict] = {}    # node_id -> node dict
        self.balances: Dict[str, int] = {}  # wallet -> balance (in subunits)
        self.tokens: Dict[str, Dict] = {}   # token_address -> token dict
        self.token_balances: Dict[Tuple[str, str], int] = {}  # (token, wallet) -> balance
        self._shutdown_flag = False
        self._proof_field_hint_shown = False
        self._genesis_handled = False

        # ─── Database ──────────────────────────────────────────────
        # R4-mainnet-guard-consistency: pass the EFFECTIVE require_postgres
        # (this config, honoring --config/--db-url) so Database and the
        # start() mainnet guard cannot disagree.
        _db_cfg = self.config.get('database', self.config.get('db', {}))
        self.db = Database(_db_cfg.get('url'),
                           require_postgres=_db_cfg.get('require_postgres', False))
        # R8-sandbox-config (R7-08): publish the EFFECTIVE require_sandbox
        # (this config, honoring --config) for spawned VM workers, same
        # pattern as require_postgres above. Workers read it via
        # _vm_require_sandbox_effective() instead of the import-time global.
        export_vm_sandbox_env(self.config)
        # R9-consensus-config (I-R8-07): same pattern for consensus globals
        # (covers constructions that bypass main(), e.g. embeds/tests).
        apply_consensus_config(self.config)
        validate_rpc_security_config(self.config)   # RPC-LOOPBACK-STRICT-1

        # ─── Repositories ──────────────────────────────────────────
        self.block_repo = BlockRepo(self.db)
        self.tx_repo = TransactionRepo(self.db)
        self.balance_repo = BalanceRepo(self.db)
        self.miner_repo = MinerRepo(self.db)
        self.node_repo = NodeRepo(self.db)
        self.token_repo = TokenRepo(self.db)
        self.token_balance_repo = TokenBalanceRepo(self.db)
        self.contract_state_repo = ContractStateRepo(self.db)
        self.contract_event_repo = ContractEventRepo(self.db)
        self.multisig_repo = MultisigRepo(self.db)
        self.challenge_repo = ChallengeRepo(self.db)
        self.receipt_repo = ReceiptRepo(self.db)
        self.finality_repo = FinalityRepo(self.db)
        self.network_state_repo = NetworkStateRepo(self.db)
        self.contract_v2_repo = ContractV2Repo(self.db)
        self.contract_storage_v2_repo = ContractStorageV2Repo(self.db)
        self.htlc_repo = HTLCRepo(self.db)
        self.maze_repo = MinerMazeRepo(self.db)
        self.maze_attestation_repo = MazeAttestationRepo(self.db)
        self.lottery_repo = LotteryRepo(self.db)
        self.slash_repo = SlashRepo(self.db)
        self.automation_repo = AutomationRepo(self.db)
        # O3-replay-guard: seen automation-create signatures (sig -> time);
        # consulted by api_automations_create, pruned on every use.
        self._seen_automation_sigs: Dict[str, float] = {}
        self.spatial_token_repo = SpatialTokenRepo(self.db)
        self.spatial_token_balance_repo = SpatialTokenBalanceRepo(self.db)
        self.state_trie = StateTrie(self.db)

        # ─── Auxiliary components ──────────────────────────────────
        self.rate_limiter = RateLimiter()
        self.subnet_rate_limiter = RateLimiter(max_requests=300, window_seconds=60)
        self.register_rate_limiter = RateLimiter(max_requests=6, window_seconds=60)
        self.rpc_rate_limiter = RateLimiter(max_requests=30, window_seconds=60)  # per-IP limit for heavy RPC calls
        self.miner_rate_limiters: Dict[str, RateLimiter] = {}  # per-miner rate limit for mining WS path
        self.health_checker = HealthChecker()
        self._start_time = time.time()
        self._sign_timeout_total = 0
        self.mempool = Mempool()
        self.memory_mgr = MemoryChallengeManager()
        self.blockexecutionlock = asyncio.Lock()
        self.ws_sessions = {}

        # ─── High-level components (created later) ────────────────
        self.vm_manager = None
        self.p2p = None
        self.consensus = PoGConsensus(self)  # PoG (Proof of Geography) consensus
        self.finality_gadget = FinalityGadget(self)
        self._producing_enabled = False
        self._next_block_time = 0.0

        # WebSocket connections (miner_id -> websocket)
        self.miner_websockets: Dict[str, Any] = {}
        # Pending block-signing futures (miner_id -> asyncio.Future)
        self._block_sign_futures: Dict[str, asyncio.Future] = {}

        # ─── Wallet and node ID ────────────────────────────────────
        self._setup_wallet()
        self.node_id = self.wallet

        logger.info(f"[Node] Node ID: {self.node_id[:16]}..., wallet: {self.wallet[:16]}...")

    # ─── Wallet Setup ──────────────────────────────────────────────────────
    def _setup_wallet(self):
        """Create or load wallet from environment or config."""
        non_interactive = not sys.stdin.isatty()

        configured_wallet = self.config.get('wallet')
        wallet_address = configured_wallet.get('address') if isinstance(configured_wallet, dict) else configured_wallet
        if wallet_address and self.config.get('private_key_encrypted'):
            raw_password = self.config.get('password') or os.environ.get('MCX_PASSWORD')
            if not raw_password:
                if non_interactive:
                    logger.error("[Wallet] Encrypted wallet found but no password available (not running interactively, and MCX_PASSWORD is not set). Set the MCX_PASSWORD environment variable and restart.")
                    sys.exit(1)
                raw_password = input("Enter password to decrypt private key: ")
            # PASSWORD-STRIP: cmd.exe `set MCX_PASSWORD=test1234 && ...` keeps a
            # trailing space in the value and interactive entry may carry stray
            # whitespace. Normalize first, then fall back to the raw value and
            # the legacy spaced-env artifact for blobs encrypted before this
            # normalization existed.
            password = raw_password.strip() or raw_password
            candidates = []
            for _p in (password, raw_password, password + " "):
                if _p and _p not in candidates:
                    candidates.append(_p)
            encrypted = self.config['private_key_encrypted']
            try:
                last_pw_err = None
                for _pw in candidates:
                    try:
                        self.priv = decrypt_private_key(encrypted, _pw)
                        password = _pw
                        break
                    except Exception as _e:
                        last_pw_err = _e
                else:
                    raise last_pw_err or ValueError("Invalid password")
                self.wallet = wallet_address
                self.pub = self.config.get('public_key')
                if not self.pub:
                    priv_int = int(self.priv, 16)
                    try:
                        priv_key = ec.derive_private_key(priv_int, ec.SECP256K1())
                    except TypeError:
                        priv_key = ec.derive_private_key(priv_int, ec.SECP256K1)
                    pub = priv_key.public_key()
                    pub_raw = pub.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
                    self.pub = pub_raw.hex()
                logger.info("[Wallet] Loaded from config.")
                return
            except Exception as e:
                logger.error(f"[Wallet] Failed to decrypt: {e}")
                sys.exit(1)

        print("\n" + "="*60)
        print(f"{CYAN}WALLET SETUP{RESET}")
        print("="*60)
        if non_interactive:
            logger.warning("[Wallet] Not running interactively (no TTY) — generating a new wallet non-interactively. Set MCX_WALLET_MODE=classic|seed, MCX_WALLET_USERNAME, and MCX_PASSWORD to control this.")
            choice = os.environ.get("MCX_WALLET_MODE", "classic").strip().lower()
            choice = "2" if choice in ("2", "seed", "mnemonic") else "1"
        else:
            choice = input("Generate wallet using:\n  1) Random private key (classic)\n  2) Seed phrase (12 words)\nEnter 1 or 2: ").strip()
        if choice == "2":
            if non_interactive:
                username = os.environ.get("MCX_WALLET_USERNAME", "node").strip() or "node"
            else:
                username = input("Enter a username for this wallet (used in derivation): ").strip() or "node"
            seed = generate_mnemonic()
            print(f"\n{YELLOW}Your 12-word seed phrase (SAVE THIS!):{RESET}\n{seed}\n")
            addr, priv_hex, pub_hex = derive_wallet_from_seed(seed_bytes=mnemonic_to_seed(seed), path=f"m/44'/60'/0'/0/0")
            self.wallet = addr
            self.priv = priv_hex
            self.pub = pub_hex
        else:
            try:
                priv_key = ec.generate_private_key(ec.SECP256K1())
            except TypeError:
                priv_key = ec.generate_private_key(ec.SECP256K1)
            priv_raw = priv_key.private_numbers().private_value.to_bytes(32, 'big')
            self.priv = priv_raw.hex()
            pub = priv_key.public_key()
            pub_raw = pub.public_bytes(encoding=serialization.Encoding.X962, format=serialization.PublicFormat.UncompressedPoint)
            self.pub = pub_raw.hex()
            self.wallet = pubkey_to_address(self.pub)

        self.node_id = self.wallet
        print(f"{GREEN}Wallet address: {self.wallet}{RESET}")
        print(f"Private key (hex): {self.priv[:16]}... (encrypted with password)")

        if not self.password:
            # PASSWORD-STRIP: normalize so encrypt and later decrypt always
            # agree regardless of how the shell delivered the env var.
            pwd = os.environ.get("MCX_PASSWORD", "").strip()
            if not pwd and not non_interactive:
                pwd = input("Enter a password to encrypt your private key: ").strip()
            if not pwd:
                pwd = secrets.token_hex(16)
                print(f"{YELLOW}AUTO-GENERATED PASSWORD (save this!): {pwd}{RESET}")
                if non_interactive:
                    logger.warning("[Wallet] No MCX_PASSWORD set — auto-generated a password and saved the encrypted key to config.yaml. Back up config.yaml's 'password' field or set MCX_PASSWORD before rotating it.")
            self.password = pwd
        encrypted = encrypt_private_key(self.priv, self.password)
        wallet_config = self.config.get('wallet')
        if isinstance(wallet_config, dict):
            wallet_config['address'] = self.wallet
            self.config['wallet'] = wallet_config
        else:
            self.config['wallet'] = self.wallet
        self.config['private_key_encrypted'] = encrypted
        self.config['public_key'] = self.pub
        disk_cfg = {}
        if os.path.exists(_config.CONFIG_PATH):
            try:
                with open(_config.CONFIG_PATH, 'r') as f:
                    disk_cfg = yaml.safe_load(f) or {}
            except Exception:
                disk_cfg = {}
        disk_cfg.update(self.config)
        with open(_config.CONFIG_PATH, 'w') as f:
            yaml.dump(disk_cfg, f)
        logger.info("[Wallet] Generated and saved.")

    # ─── State Loading ──────────────────────────────────────────────────────
    async def _load_state(self):
        latest = await self.block_repo.get_latest()
        if latest:
            self.height = latest['id'] + 1
            self.last_hash = latest['hash']
            latest_ts = latest.get('ts', 0)
            if hasattr(latest_ts, 'timestamp'):
                latest_ts = latest_ts.timestamp()
            self._next_block_time = max(self._next_block_time, float(latest_ts) + BLOCK_TIME)
            load_start = max(0, self.height - BLOCK_CACHE_MAX)
            all_blocks = await self.block_repo.get_range(load_start, self.height - 1, limit=BLOCK_CACHE_MAX)
            self.blocks = all_blocks
            logger.info(f"[State] Loaded {len(self.blocks)} blocks (from #{load_start}), height={self.height}")

        miners = await self.miner_repo.get_active()
        for m in miners:
            self.miners[m['miner_id']] = m

        total_minted = await self.network_state_repo.get("total_minted")
        if total_minted:
            self.total_minted = int(total_minted)
        burned = await self.network_state_repo.get("burned_total")
        if burned:
            self.burned_total = int(burned)

        logger.info(f"[State] Loaded {len(self.miners)} miners, total minted: {self.total_minted//SUBS} MCX")
        await self.finality_gadget.ensure_loaded()
        await self._ensure_genesis_alloc()

    # ─── Transaction Execution ──────────────────────────────────────────────
    # ─── Spatial Tokens V1 helpers ─────────────────────────────────────────
    # V2 note: _live_mazes is currently uncalled (coverage helpers were
    # deleted); kept because the spec says to keep it.
    async def _live_mazes(self) -> list:
        """Interpretation A: 'live' = MinerMazeRepo.get_eligible chain state,
        never WebSocket state (node-local → non-deterministic across peers).
        Returns [(maze_id, minerid, size), ...]; malformed rows skipped."""
        rows = await self.maze_repo.get_eligible(self.height)
        out = []
        for r in rows:
            try:
                out.append((str(r["maze_id"]), str(r["minerid"]), int(r["size"])))
            except Exception:
                continue
        return out

    async def _chain_agreed_maze_sizes(self, at_block: int) -> Dict[str, Tuple[int, int]]:
        """K1-dist (MCX73): maze sizes — and maze ACTIVITY — from sealed chain
        data only (maze_attestations in blocks <= at_block, newest wins),
        never from local minermazes rows (ghost-sim local
        writes + move-gossip timing make those drift per node, which made
        pool splits differ across nodes for the same sealed pool amount).
        R6-maze-update-weight-bind: maze_updates are display/sync data only
        and never confer weight (their size claims are growth-uncapped).
        Returns {maze_id: (size, active_block)}. Single walk for all mazes
        (bounded: stops when every locally-known maze is resolved or after
        500 blocks). Mazes never seen on chain are absent (excluded).
        STRICTLY below at_block (id < at_block): the block being sealed /
        appended is excluded on BOTH sides — the producer's table does not
        contain it yet, so including it would make the follower (whose table
        does, post-create) compute a different set. Both sides therefore
        evaluate parent state, identically."""
        out: Dict[str, Tuple[int, int]] = {}
        try:
            _known = {str(r.get("maze_id", "")) for r in
                      (await self.maze_attestation_repo.get_all() or [])}
            _known.discard("")
        except Exception:
            _known = set()
        if not _known:
            return out
        _remaining = set(_known)
        # Both sides evaluate PARENT state: strictly below at_block (id <
        # at_block). The producer's table does not contain the sealing
        # block yet, while the follower's does (created first in
        # _append_block) — including it would fork the input set.
        _q = ("SELECT id, proof FROM blocks WHERE id < ? AND proof IS NOT NULL ORDER BY id DESC LIMIT 500"
              if self.db.db_type == "sqlite" else
              "SELECT id, proof FROM blocks WHERE id < $1 AND proof IS NOT NULL ORDER BY id DESC LIMIT 500")
        try:
            _rows = await self.db.fetch(_q, int(at_block))
        except Exception:
            return out
        for _r in (_rows or []):
            if not _remaining:
                break
            try:
                _bid = int(_r.get("id", 0))
                _rp = _r.get("proof")
                if isinstance(_rp, str):
                    _rp = json.loads(_rp or "{}")
                if not isinstance(_rp, dict):
                    continue
            except Exception:
                continue
            # R6-maze-update-weight-bind: weight derives from attestation rows only; updates are root-checked at verify but growth-uncapped, so they must never confer weight.
            _ra = _rp.get("maze_attestation")
            if isinstance(_ra, dict):
                _rm = str(_ra.get("maze_id", ""))
                if _rm in _remaining:
                    try:
                        out[_rm] = (int(_ra.get("size", MIN_MAZE_SIZE)), _bid)
                    except Exception:
                        continue
                    _remaining.discard(_rm)
        return out

    async def _proven_update_size(self, maze_id: str, upto_id: int):
        """Newest update-proven size for a maze from sealed chain data.

        WORK-PROOF-1 (mainnet audit): walks block proofs newest-first
        (bounded 500, strictly below upto_id) and returns the first
        maze_updates entry for maze_id with a valid dimension, or None.
        Each sealed update carries a walk-proof (parent replay + root +
        size jump +1), so a returned size represents a proven catch chain,
        not a bare claim. Used to bind attestation growth to proven work
        (see verify_block_proof). Returns None when nothing is proven.
        Residual: on the reorg path the DB walk may include orphaned-tip
        blocks (same imperfection as today's local-row caps); the growth
        cap still binds via _att_base, and the in-block leg is exact."""
        try:
            _mid = str(maze_id or "")
            if not _mid:
                return None
            _upto = int(upto_id)
        except (TypeError, ValueError):
            return None
        try:
            if self.db.db_type == "sqlite":
                _rows = await self.db.fetch(
                    "SELECT id, proof FROM blocks WHERE id < ? AND proof IS NOT NULL ORDER BY id DESC LIMIT 500",
                    _upto)
            else:
                _rows = await self.db.fetch(
                    "SELECT id, proof FROM blocks WHERE id < $1 AND proof IS NOT NULL ORDER BY id DESC LIMIT 500",
                    _upto)
        except Exception:
            return None
        for _r in (_rows or []):
            try:
                _rp = _r.get("proof")
                if isinstance(_rp, str):
                    _rp = json.loads(_rp or "{}")
                if not isinstance(_rp, dict):
                    continue
            except Exception:
                continue
            # Newest block first, and within a block the LAST matching
            # update: _pending_maze_updates appends chronologically, so the
            # tail is the current proven size. Returning the head instead
            # (e.g. 6 when the maze provably reached 13) stranded honest
            # growers: followers rejected growth the chain had proven.
            for _u in reversed(list(_rp.get("maze_updates") or [])):
                if not isinstance(_u, dict):
                    continue
                _um = str(_u.get("maze_id") or _u.get("miner_id") or "")
                if _um != _mid:
                    continue
                _sz = _valid_maze_size(_u.get("new_size"))
                if _sz is not None:
                    return _sz
        return None

    async def _distribute_spatial_fee(self, fee_amount: int, block_id: int) -> Dict[str, int]:
        """Spatial Tokens V2: split SPATIAL_DEPLOY_FEE_MAZE_BPS of fee_amount
        across live mazes, weighted by (size^3 - 125). Returns
        {wallet: amount}. Uses chain-agreed maze sizes so producer and
        followers compute the same split. Dust below 1 subunit is dropped."""
        if int(fee_amount) <= 0:
            return {}
        _maze_cut = int(fee_amount) * SPATIAL_DEPLOY_FEE_MAZE_BPS // 10000
        if _maze_cut <= 0:
            return {}
        _agreed = await self._chain_agreed_maze_sizes(block_id)
        _cutoff = max(0, int(block_id) - ACTIVE_MINER_WINDOW_BLOCKS)
        weights: Dict[str, int] = {}
        for mid, (size, active_block) in _agreed.items():
            if size <= MIN_MAZE_SIZE or active_block < _cutoff:
                continue
            weights[str(mid)] = size ** 3 - MIN_MAZE_SIZE ** 3
        total_w = sum(weights.values())
        if total_w <= 0:
            return {}
        out: Dict[str, int] = {}
        for mid, w in weights.items():
            _mid_hex = str(mid).removeprefix("0x").lower()
            if not (len(_mid_hex) == 130 and _mid_hex.startswith("04")
                    and all(c in "0123456789abcdef" for c in _mid_hex)):
                continue
            try:
                wallet = pubkey_to_address(mid).lower()
            except Exception:
                continue
            amt = _maze_cut * w // total_w
            if amt > 0:
                out[wallet] = out.get(wallet, 0) + amt
        for wallet, amt in out.items():
            await self.balance_repo.add(wallet, amt)
        return out

    async def _record_spatial_fee_payouts(self, block_id: int, payouts: Dict[str, int]) -> None:
        """Spatial Tokens V2: persist per-block fee-payout rows so a reorg
        can deterministically debit what a fork credited. Own transaction —
        all rows for this block land atomically."""
        if not payouts:
            return
        async with await self.db.transaction():
            for wallet, amt in payouts.items():
                if int(amt) <= 0:
                    continue
                if self.db.db_type == "sqlite":
                    await self.db.execute_dml(
                        "INSERT OR REPLACE INTO spatial_fee_payouts (block_id, wallet, amount) VALUES (?,?,?)",
                        block_id, wallet, int(amt))
                else:
                    await self.db.execute_dml(
                        "INSERT INTO spatial_fee_payouts (block_id, wallet, amount) VALUES ($1,$2,$3) ON CONFLICT (block_id, wallet) DO UPDATE SET amount = EXCLUDED.amount",
                        block_id, wallet, int(amt))

    async def _revert_spatial_fee_payouts(self, block_id: int) -> None:
        """Spatial Tokens V2: debit every wallet paid for this block
        (mirror of _distribute_spatial_fee), then drop the rows. Both steps
        run in ONE transaction — a crash mid-debit can never leave a
        half-reverted pool. Idempotent (no rows → no-op)."""
        if self.db.db_type == "sqlite":
            rows = await self.db.fetch("SELECT wallet, amount FROM spatial_fee_payouts WHERE block_id = ?", block_id)
        else:
            rows = await self.db.fetch("SELECT wallet, amount FROM spatial_fee_payouts WHERE block_id = $1", block_id)
        if not rows:
            return
        async with await self.db.transaction():
            for r in rows:
                try:
                    amt = int(r["amount"])
                except (TypeError, ValueError, KeyError):
                    continue
                if amt > 0:
                    await self.balance_repo.add(str(r["wallet"]), -amt)
                if self.db.db_type == "sqlite":
                    await self.db.execute_dml("DELETE FROM spatial_fee_payouts WHERE block_id = ? AND wallet = ?", block_id, r["wallet"])
                else:
                    await self.db.execute_dml("DELETE FROM spatial_fee_payouts WHERE block_id = $1 AND wallet = $2", block_id, r["wallet"])
        logger.info(f"[SPATIAL-POOL-REORG-1] reverted {len(rows)} payout(s) for orphaned block {block_id}")

    async def _rollback_spatial_tx(self, tx: dict, from_w) -> None:
        """SPATIAL-POOL-REORG-1 (§7.12): reverse ONE spatial tx's forward
        effects. Extracted from the _reorg_chain orphan loop so it can be
        unit-tested directly (tests/test_spatial_tokens.py test_e)."""
        tx_type = tx.get('tx_type')
        if tx_type == 'spatial_token_create':
            # Delete the deployed token and refund the deployer. Sealed
            # tx['fee'] = producer_cut and tx['_spatial_fee_maze_cut'] =
            # maze_cut — their sum is exactly the deploy_fee deducted
            # forward. The producer's cut is already reversed by the reorg's
            # reward subtract; the maze cut by _revert_spatial_fee_payouts.
            token_addr = tx.get('to_wallet')
            _ts = str(token_addr) if token_addr else ''
            if _ts.startswith('0x') and len(_ts) == 42:
                try:
                    await self.spatial_token_repo.delete(_ts)
                    if self.db.db_type == "sqlite":
                        await self.db.execute_dml("DELETE FROM spatial_token_balances WHERE token_address = ?", _ts)
                    else:
                        await self.db.execute_dml("DELETE FROM spatial_token_balances WHERE token_address = $1", _ts)
                except Exception as _re:
                    logger.warning(f"[REORG] spatial token delete failed for {_ts[:16]}: {_re}")
            try:
                _cut = tx.get('_spatial_fee_maze_cut')
                if _cut is None:
                    # Real reorg rows come from SELECT * — the maze cut rides
                    # in the data JSON column (mirrored at tx_repo.create).
                    _d = tx.get('data')
                    if isinstance(_d, str):
                        _d = json.loads(_d) if _d else {}
                    _cut = (_d or {}).get('_spatial_fee_maze_cut', 0) \
                        if isinstance(_d, dict) else 0
                _refund = int(tx.get('fee', 0) or 0) + int(_cut or 0)
            except (TypeError, ValueError):
                _refund = 0
            if _refund > 0 and from_w:
                await self.balance_repo.add(from_w, _refund)
        elif tx_type == 'spatial_token_transfer':
            # Reverse the token-balance move — amount is a TOKEN amount,
            # never MCX (REORG-1 lesson).
            token_addr = tx.get('token_address')
            to_w = tx.get('to_wallet')
            try:
                t_amt = int(tx.get('amount', 0))
            except (TypeError, ValueError):
                t_amt = 0
            if token_addr and to_w and t_amt > 0:
                await self.spatial_token_balance_repo.add(str(token_addr), str(to_w).lower(), -t_amt)
                if from_w:
                    await self.spatial_token_balance_repo.add(str(token_addr), str(from_w).lower(), t_amt)
            # Spatial Tokens V2: no rehome — nothing to restore. Refund the
            # full fee (sealed tx['fee'] = producer_cut plus the maze cut,
            # mirroring the create branch above).
            try:
                _tcut = tx.get('_spatial_fee_maze_cut')
                if _tcut is None:
                    _d2 = tx.get('data')
                    if isinstance(_d2, str):
                        _d2 = json.loads(_d2) if _d2 else {}
                    _tcut = (_d2 or {}).get('_spatial_fee_maze_cut', 0) \
                        if isinstance(_d2, dict) else 0
                fee_ref = int(tx.get('fee', 0) or 0) + int(_tcut or 0)
            except (TypeError, ValueError):
                fee_ref = 0
            if fee_ref > 0 and from_w:
                await self.balance_repo.add(from_w, fee_ref)
        elif tx_type == 'spatial_token_burn':
            # Forward path rejects burn — can never appear in a sealed block.
            pass
        elif tx_type in ('spatial_asset_create', 'spatial_asset_transfer',
                         'spatial_challenge_create', 'spatial_challenge_claim',
                         'spatial_challenge_cancel'):
            # Legacy spatial assets/challenges (replaced by Spatial Tokens
            # V1): state tables were dropped by the schema swap and escrow
            # status is unrecoverable — reverting by refund would
            # double-credit claimed challenges. Historical blocks carrying
            # these types must not crash the reorg path (old code called the
            # now-deleted spatial_asset_repo here).
            logger.warning(f"[REORG] legacy spatial tx {tx_type} rolled forward-less (system removed)")

    async def execute_transaction(self, tx_data: Dict, block_id: int, block_ts: float = None) -> Tuple[bool, Dict]:
        if 'timestamp' not in tx_data:
            tx_data['timestamp'] = time.time()
        if 'fee' not in tx_data:
            tx_data['fee'] = 0
        # H-6 (MCX73): record the authorized fee BEFORE any execute-time
        # mutation (spatial paths rewrite tx['fee'] below). Rollback refunds
        # _fee_charged — exactly what was deducted, even if the stored row
        # carries a mutated fee.
        try:
            tx_data['_fee_charged'] = int(tx_data.get('fee', 0))
        except (TypeError, ValueError):
            tx_data['_fee_charged'] = 0
        if not self._verify_tx_signature(tx_data):
            return False, {"error": "Invalid signature"}
        # Duplicate tx detection: reject if tx_hash already confirmed
        tx_hash = tx_data.get('tx_hash')
        existing = await self.tx_repo.get_by_hash(tx_hash) if tx_hash else None
        if existing and existing.get('status') != 'pending':
            # MEMPOOL-RETRY: a previous produce attempt at this exact height
            # already executed this tx (state, receipt and row written), but
            # the miner sign roundtrip failed, so the block was never sealed
            # and the tx stayed in the mempool. Re-including it in the retried
            # block must not re-apply state (that would double-deduct fees and
            # balances), so report success without touching state. Gate on
            # block_id: rows confirmed inside an already-committed block carry
            # a past block id, so true replays of old txs still hit the
            # duplicate error, and followers (which have no local row for a
            # producer-only execution) execute the tx in full on import.
            if existing.get('block_id') == block_id:
                return True, {"result": "already executed in failed attempt at this height"}
            return False, {"error": f"Duplicate transaction {tx_hash[:16]}"}
        from_wallet = tx_data.get('from_wallet')
        if from_wallet:
            confirmed_nonce = await self._get_confirmed_nonce(from_wallet)
            if tx_data.get('nonce', 0) != confirmed_nonce:
                return False, {"error": f"Nonce mismatch: expected {confirmed_nonce}, got {tx_data.get('nonce', 0)}"}

        val = int(tx_data.get('value', 0))
        fee = int(tx_data.get('fee', 0))
        if val < 0 or fee < 0:
            return False, {"error": "Value and fee must be non-negative"}

        tx_type = tx_data.get('tx_type', 'send')

        if tx_type == 'token_create':
            # F2: token creation was a node-local direct DB write at REST
            # submit (create_token() — no block, no gossip, instant state on
            # one node only). It now executes as an ordinary consensus tx.
            # Deterministic by construction: address derives from tx_hash
            # (create_token() used time.time(), which could never agree
            # across nodes) and the fee floor is the dynamic token creation
            # fee at minimum pool size (mempool size differs per node).
            owner = tx_data.get('from_wallet')
            d = tx_data.get('data') or {}
            name = d.get('name')
            symbol = d.get('symbol')
            total_supply = int(d.get('total_supply', 0))
            decimals = int(d.get('decimals', 18))
            burnable = bool(d.get('burnable', True))
            temporal_config = d.get('temporal_config') or {}
            if not name or len(name) < 3 or len(name) > 32:
                return False, {"error": "Invalid name length"}
            if not symbol or len(symbol) < 2 or len(symbol) > 10:
                return False, {"error": "Invalid symbol length"}
            if total_supply <= 0 or total_supply > TOKEN_MAX_SUPPLY:
                return False, {"error": "Invalid supply"}
            fee_floor = get_token_creation_fee(0)
            if fee < fee_floor:
                return False, {"error": f"Insufficient fee: need {fee_floor}"}
            balance = await self.balance_repo.get(owner)
            if balance < fee:
                return False, {"error": f"Insufficient balance: need {fee//SUBS} MCX"}
            token_address = _derive_token_address(tx_hash, owner, name, symbol)
            await self.balance_repo.subtract(owner, fee)
            token = {
                'address': token_address,
                'name': name,
                'symbol': symbol,
                'owner': owner,
                'total_supply': total_supply * SUBS,
                'decimals': decimals,
                'created_at': float(tx_data.get('timestamp', 0)),
                'fee_paid': fee,
                'mintable': True,
                'burnable': burnable,
                'mining_type': '',
                'mining_reward': 0,
                'mining_interval': 1,
                'mining_difficulty': 1,
                'stake_threshold': 0,
                'last_mined_block': 0,
                'total_mined': 0,
                'max_mineable_supply': TOKEN_MAX_MINEABLE_SUPPLY
            }
            await self.token_repo.create(token)
            await self.token_balance_repo.set(token_address, owner, total_supply * SUBS)
            if temporal_config:
                await self.contract_state_repo.set(token_address, "temporal_config", json.dumps(temporal_config))
            self.tokens[token_address] = token
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = 0
            tx_data['token_address'] = token_address
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': 0, 'logs': [], 'contract_address': token_address, 'result': 'success'}
            await self.receipt_repo.create(receipt)
            return True, {"result": "success", "address": token_address}

        if tx_type == 'send':
            from_wallet = tx_data.get('from_wallet')
            to_wallet = tx_data.get('to_wallet')
            amount = int(tx_data.get('value', 0))
            fee = int(tx_data.get('fee', 0))
            total = amount + fee
            balance = await self.balance_repo.get(from_wallet)
            if balance < total:
                return False, {"error": "Insufficient balance"}
            await self.balance_repo.subtract(from_wallet, total)
            if to_wallet and to_wallet.lower() in BURN_ADDRESSES:
                self.burned_total += amount
                await self.network_state_repo.set("burned_total", str(self.burned_total))
                logger.info(f"[BURN] {amount // SUBS} MCX sent to burn address {to_wallet}. Total burned: {self.burned_total // SUBS} MCX")
            else:
                await self.balance_repo.add(to_wallet, amount)
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': 0, 'logs': [], 'contract_address': '', 'result': 'success'}
            await self.receipt_repo.create(receipt)
            return True, {"result": "success"}

        elif tx_type == 'burn':
            from_wallet = tx_data.get('from_wallet')
            to_wallet = tx_data.get('to_wallet', BURN_ADDRESS_ZERO)
            amount = int(tx_data.get('value', 0))
            fee = int(tx_data.get('fee', 0))
            total = amount + fee
            balance = await self.balance_repo.get(from_wallet)
            if balance < total:
                return False, {"error": "Insufficient balance"}
            await self.balance_repo.subtract(from_wallet, total)
            self.burned_total += amount
            await self.network_state_repo.set("burned_total", str(self.burned_total))
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            await self.tx_repo.create(tx_data)
            receipt = {
                'tx_hash': tx_data.get('tx_hash'),
                'block_id': block_id,
                'status': 1,
                'gas_used': 0,
                'logs': [{'event': 'CoinBurned', 'burner': from_wallet, 'amount': amount, 'burned_total': self.burned_total}],
                'contract_address': '',
                'result': 'burned'
            }
            await self.receipt_repo.create(receipt)
            logger.info(f"[BURN] {amount // SUBS} MCX burned by {from_wallet[:16]}. Total burned: {self.burned_total // SUBS} MCX")
            return True, {"result": "burned", "burned_total": self.burned_total}

        elif tx_type == 'token_transfer':
            token_addr = tx_data.get('token_address')
            if not token_addr:
                return False, {"error": "Missing token address"}
            token = await self.token_repo.get(token_addr)
            if not token:
                return False, {"error": "Token not found"}
            from_wallet = tx_data.get('from_wallet')
            to_wallet = tx_data.get('to_wallet')
            amount = int(tx_data.get('value', 0))
            # FEE-1: token_transfer previously skipped the MCX fee entirely
            # (fee-free state mutation + block-level fee accounting gap).
            # Charged on attempt, mirroring contract_call.
            fee = int(tx_data.get('fee', 0))
            mcx_balance = await self.balance_repo.get(from_wallet)
            if mcx_balance < fee:
                return False, {"error": "Insufficient balance for fee"}
            # FEE-ORDER-1 (mainnet audit): NO deduct here. The fee is taken
            # only after every validation below passes; a rejected transfer
            # must not burn the fee (previously deducted at 13009, then
            # trading/cooldown/vesting/balance failures kept it).
            # TIME-CONSENSUS-1 (mainnet audit): temporal predicates evaluate
            # at the sealed block time, not verifier wall-clock. Producer
            # seals block_ts; followers recompute the identical verdict.
            # block_ts None (legacy direct calls) falls back to wall-clock.
            now = block_ts if block_ts is not None else time.time()

            # Temporal L2 verification
            temporal_config = await self.get_token_temporal_config(token_addr)
            if temporal_config:
                # 1. Trading start check
                trading_starts_at = temporal_config.get("trading_starts_at", 0)
                if trading_starts_at > 0 and now < trading_starts_at and from_wallet != token.get("owner"):
                    return False, {"error": f"Trading locked until timestamp {trading_starts_at} ({int(trading_starts_at - now)}s remaining)"}

                # 2. Transfer cooldown check
                cooldown = temporal_config.get("transfer_cooldown_seconds", 0)
                if cooldown > 0 and from_wallet != token.get("owner"):
                    last_tx_time_str = await self.contract_state_repo.get(token_addr, f"last_tx_{from_wallet}")
                    if last_tx_time_str:
                        elapsed = now - float(last_tx_time_str)
                        if elapsed < cooldown:
                            return False, {"error": f"Transfer cooldown active: wait {int(cooldown - elapsed)}s"}

                # 3. Vesting check (continuous linear unlock per second)
                vesting = temporal_config.get("vesting_schedules", {}).get(from_wallet)
                if vesting:
                    v_total = int(vesting.get("total", 0))
                    v_start = float(vesting.get("start", 0))
                    v_dur = float(vesting.get("duration", 1))
                    if now < v_start:
                        locked = v_total
                    elif now >= v_start + v_dur:
                        locked = 0
                    else:
                        unlocked_ratio = (now - v_start) / v_dur
                        locked = int(v_total * (1.0 - unlocked_ratio))
                    from_bal = await self.token_balance_repo.get(token_addr, from_wallet)
                    if from_bal - amount < locked:
                        return False, {"error": f"Insufficient unlocked tokens: {locked} locked in vesting"}

            from_bal = await self.token_balance_repo.get(token_addr, from_wallet)
            if from_bal < amount:
                return False, {"error": "Insufficient token balance"}
            # FEE-ORDER-1: all checks passed — take the fee now.
            if fee > 0:
                await self.balance_repo.subtract(from_wallet, fee)

            # Burn fee tax check
            burn_bps = temporal_config.get("burn_fee_bps", 0) if temporal_config else 0
            burn_tax = (amount * burn_bps) // 10000 if burn_bps > 0 else 0
            net_amount = amount - burn_tax
            # BUG 2 (MCX75): persist burn_tax for the reorg inverse (which
            # must debit net_amount, not amount, and restore supply). The
            # row mirror in TransactionRepo.create carries it; the input
            # dict keeps a transient copy like _fee_charged.
            tx_data['_burn_tax'] = int(burn_tax)

            await self.token_balance_repo.set(token_addr, from_wallet, from_bal - amount)
            to_bal = await self.token_balance_repo.get(token_addr, to_wallet)
            await self.token_balance_repo.set(token_addr, to_wallet, to_bal + net_amount)

            if burn_tax > 0:
                cur_supply = int(token.get("total_supply", 0))
                token["total_supply"] = max(0, cur_supply - burn_tax)
                await self.token_repo.upsert(token)
                cur_burned = int(await self.contract_state_repo.get(token_addr, "burned_total") or 0) + burn_tax
                # BUG 6 (MCX75): journal the temporal write (absolute revert
                # in _revert_exec_journal; BUG 2's orphan branch restores
                # total_supply arithmetically and leaves burned_total here
                # to the journal — no double-revert by construction).
                # old=None preserved exactly when the row is absent (revert
                # DELETEs); int() failure modes unchanged from above.
                _burned_prev_raw = await self.contract_state_repo.get(token_addr, "burned_total")
                await self._journal_state_row(block_id, token_addr, "burned_total", _burned_prev_raw, cur_burned)
                await self.contract_state_repo.set(token_addr, "burned_total", str(cur_burned))

            if temporal_config and temporal_config.get("transfer_cooldown_seconds", 0) > 0:
                _lt_key = f"last_tx_{from_wallet}"
                try:
                    _lt_old = await self.contract_state_repo.get(token_addr, _lt_key)
                except Exception:
                    _lt_old = None
                await self._journal_state_row(block_id, token_addr, _lt_key, _lt_old, str(now))
                await self.contract_state_repo.set(token_addr, _lt_key, str(now))

            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            await self.tx_repo.create(tx_data)
            receipt = {
                'tx_hash': tx_data.get('tx_hash'),
                'block_id': block_id,
                'status': 1,
                'gas_used': 0,
                'logs': [{'event': 'TokenTransfer', 'token': token_addr, 'from': from_wallet, 'to': to_wallet, 'amount': net_amount, 'burn_tax': burn_tax}],
                'contract_address': token_addr,
                'result': 'success'
            }
            await self.receipt_repo.create(receipt)
            return True, {"result": "success", "net_amount": net_amount, "burn_tax": burn_tax}

        elif tx_type == 'token_burn':
            token_addr = tx_data.get('token_address')
            if not token_addr:
                return False, {"error": "Missing token address"}
            token = await self.token_repo.get(token_addr)
            if not token:
                return False, {"error": "Token not found"}
            from_wallet = tx_data.get('from_wallet')
            amount = int(tx_data.get('value', 0))
            # FEE-1: token_burn previously skipped the MCX fee entirely.
            fee = int(tx_data.get('fee', 0))
            mcx_balance = await self.balance_repo.get(from_wallet)
            if mcx_balance < fee:
                return False, {"error": "Insufficient balance for fee"}
            from_bal = await self.token_balance_repo.get(token_addr, from_wallet)
            if from_bal < amount:
                return False, {"error": "Insufficient token balance"}
            # FEE-ORDER-1: deduct only after validation (see token_transfer).
            if fee > 0:
                await self.balance_repo.subtract(from_wallet, fee)
            await self.token_balance_repo.set(token_addr, from_wallet, from_bal - amount)
            new_supply = max(0, int(token.get('total_supply', 0)) - amount)
            token['total_supply'] = new_supply
            await self.token_repo.upsert(token)
            cur_token_burned = int(await self.contract_state_repo.get(token_addr, "burned_total") or 0) + amount
            await self.contract_state_repo.set(token_addr, "burned_total", str(cur_token_burned))
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = amount
            await self.tx_repo.create(tx_data)
            receipt = {
                'tx_hash': tx_data.get('tx_hash'),
                'block_id': block_id,
                'status': 1,
                'gas_used': 0,
                'logs': [{'event': 'TokenBurned', 'token': token_addr, 'burner': from_wallet, 'amount': amount}],
                'contract_address': token_addr,
                'result': 'token_burned'
            }
            await self.receipt_repo.create(receipt)
            return True, {"result": "token_burned", "token": token_addr, "burned": amount, "total_supply": new_supply}

        elif tx_type == 'contract_deploy':
            # fixes1-3A: raw eth txs (MetaMask) carry init code in 'data',
            # native REST txs carry it in 'bytecode'.
            init_code_hex = tx_data_to_hex(tx_data.get('bytecode')) or tx_data_to_hex(tx_data.get('data'))
            if init_code_hex.startswith('0x'):
                init_code_hex = init_code_hex[2:]
            abi = tx_data.get('abi', {})
            if not init_code_hex:
                return False, {"error": "Missing bytecode"}
            if len(init_code_hex) > _config.MAX_BYTECODE * 2:
                return False, {"error": "Bytecode too large"}
            nonce = tx_data.get('nonce', 0)
            contract_address = compute_contract_address(tx_data['from_wallet'], nonce)

            value = tx_data.get('value', 0)
            gas_limit = _gas_ceiling(tx_data.get('gas', _config.GAS_LIMIT_DEFAULT))  # GAS-CEIL-1
            if self.vm_manager is None:
                return False, {"error": "VM manager not initialized"}
            # MCX76-fee-precheck-fee-only: same fee-before-VM rule as
            # contract_call (see above). Fee-only, matching what the
            # forward path charges.
            _b3_fee = int(tx_data.get('fee', 0) or 0)
            if _b3_fee > 0:
                try:
                    _b3_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _b3_bal = 0
                if int(_b3_bal or 0) < _b3_fee:
                    return False, {"error": "Insufficient balance for fee"}
                # FEE-ORDER-1 (mainnet audit): fee is DEDUCTED here, before
                # the VM runs. Gas semantics: attempted execution pays even
                # if the frame reverts; the post-VM deduct is removed so the
                # fee can never be charged twice nor skipped after a flush.
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_fee)
            # R4-top-level-value: move `value` caller->contract at the top
            # level (mirrors _call_contract for sub-calls). Debit before
            # execute so the frame runs post-debit; the gate covers value +
            # fee together so a rejected tx can never leave committed VM
            # state (the MCX76 fee-only invariant, extended to value).
            _b3_value = int(tx_data.get('value', 0) or 0)
            if _b3_value > 0:
                try:
                    _v_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _v_bal = 0
                if int(_v_bal or 0) < _b3_value + _b3_fee:
                    return False, {"error": "Insufficient balance for value"}
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_value)
                tx_data['_value_moved'] = _b3_value  # R5-sign-fail-rollback: marker for the inverse.
            success, return_data, gas_used, logs = await self.vm_manager.execute(
                contract_address,
                caller=tx_data['from_wallet'],
                origin=tx_data['from_wallet'],
                value=value,
                gas_limit=gas_limit,
                input_data=b"",
                static=False,
                init_code_hex=init_code_hex,
                block_id=block_id,
                block_ts=block_ts
            )
            if not success:
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                return False, {"error": "Constructor execution failed", "result": return_data.hex()}
            runtime_bytecode = return_data.hex() if return_data else ''
            if not runtime_bytecode:
                # R5-value-rollback: refund the pre-execute debit.
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                return False, {"error": "Constructor did not return runtime bytecode"}
            if len(runtime_bytecode) > _config.MAX_BYTECODE * 2:
                # R5-value-rollback: refund the pre-execute debit.
                if _b3_value > 0:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
                return False, {"error": f"Runtime bytecode exceeds MAX_BYTECODE ({_config.MAX_BYTECODE} bytes)"}
            # FEE-ORDER-1: fee already deducted at the pre-check; VM failure
            # keeps it (gas semantics), VM success needs no second charge.
            # R4-top-level-value: credit the new contract on success (the
            # debit happened before execute; failure refunded above).
            if _b3_value > 0:
                await self.balance_repo.add(contract_address, _b3_value)
            code_hash = hashlib.sha256(bytes.fromhex(runtime_bytecode)).hexdigest()
            if not isinstance(abi, str):
                abi = json.dumps(abi)
            await self.contract_v2_repo.create({
                'address': contract_address,
                'owner': tx_data['from_wallet'],
                'bytecode': runtime_bytecode,
                'abi': abi,
                'created_at': time.time(),
                'tx_hash': tx_data['tx_hash'],
                'storage_root': '',
                'code_hash': code_hash
            })
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            # R6-contract-tx-at-rest-bind: preserve the signed to_wallet before mutating it.
            if '_signed_to_wallet' not in tx_data:
                tx_data['_signed_to_wallet'] = str(tx_data.get('to_wallet') or '')
            tx_data['to_wallet'] = contract_address
            tx_data['amount'] = value
            await self.tx_repo.create(tx_data)

            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1 if success else 0, 'gas_used': gas_used, 'logs': logs, 'contract_address': contract_address, 'result': 'deployed'}
            await self.receipt_repo.create(receipt)
            return True, {"result": "deployed", "contract_address": contract_address, "gas_used": gas_used}

        elif tx_type == 'contract_call':
            contract_addr = tx_data.get('to_wallet')
            if not contract_addr:
                return False, {"error": "Missing contract address"}
            contract = await self.contract_v2_repo.get(contract_addr)
            if not contract:
                return False, {"error": "Contract not found"}
            # fixes1-3B: raw eth txs put calldata in 'data', not 'input';
            # tx_data_to_bytes also unwraps the {'raw':...} dict that
            # contract_call execution stores back into tx['data'].
            raw_input = tx_data.get('data')
            if raw_input is None:
                raw_input = tx_data.get('input', b'')
            input_data = raw_input if isinstance(raw_input, bytes) else tx_data_to_bytes(raw_input)
            value = tx_data.get('value', 0)
            gas_limit = _gas_ceiling(tx_data.get('gas', _config.GAS_LIMIT_DEFAULT))  # GAS-CEIL-1
            # MCX76-fee-precheck-fee-only: fee admissibility BEFORE any VM
            # state mutation. The pre-check must match the fee the forward
            # path actually charges (fee only, GAS-LEAK FIX); it exists
            # solely to move the post-VM fee check before the VM so a
            # rejected fee cannot leave committed VM state.
            # R4-top-level-value: top-level contract_call now moves `value`
            # caller->contract (previously only sub-calls did). The gate
            # below covers value + fee together, extending the same invariant.
            _b3_fee = int(tx_data.get('fee', 0) or 0)
            if _b3_fee > 0:
                try:
                    _b3_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _b3_bal = 0
                if int(_b3_bal or 0) < _b3_fee:
                    return False, {"error": "Insufficient balance for fee"}
                # FEE-ORDER-1: deduct upfront (gas semantics, see deploy).
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_fee)
            _b3_value = int(tx_data.get('value', 0) or 0)
            if _b3_value > 0:
                try:
                    _v_bal = await self.balance_repo.get(tx_data['from_wallet'])
                except Exception:
                    _v_bal = 0
                if int(_v_bal or 0) < _b3_value + _b3_fee:
                    return False, {"error": "Insufficient balance for value"}
                await self.balance_repo.subtract(tx_data['from_wallet'], _b3_value)
                tx_data['_value_moved'] = _b3_value  # R5-sign-fail-rollback: marker for the inverse.
            success, return_data, gas_used, logs = await self.vm_manager.execute(
                contract_addr,
                caller=tx_data['from_wallet'],
                origin=tx_data['from_wallet'],
                value=value,
                gas_limit=gas_limit,
                input_data=input_data,
                static=False,
                block_id=block_id,
                block_ts=block_ts
            )
            # GAS-LEAK FIX: this path charged BOTH gas_used*GAS_PRICE and the
            # tx fee — eth raw txs already carry fee = gas*gasPrice (RPC
            # eth_sendRawTransaction), so the extra gas_cost left the wallet
            # lighter with nothing credited (the -22,117 call-tx leak; all
            # nodes consistent). Charge the fee only, like contract_deploy /
            # send / token paths. gas_used stays informational in the receipt
            # and the shadow re-exec already models fee-only.
            # FEE-ORDER-1: fee already deducted at the pre-check (same gas
            # semantics as deploy); no second charge after the frame.
            # R4-top-level-value: settle the pre-execute debit — credit the
            # contract on success, refund the caller on VM failure.
            if _b3_value > 0:
                if success:
                    await self.balance_repo.add(contract_addr, _b3_value)
                else:
                    await self.balance_repo.add(tx_data['from_wallet'], _b3_value)
            tx_data['status'] = 'confirmed' if success else 'failed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = value
            # data may be a hex string (raw eth tx) — result recording needs a dict
            raw_data = tx_data.get('data', {})
            # R6-contract-tx-at-rest-bind: preserve the signed data before wrapping it.
            if '_signed_data' not in tx_data:
                _d = tx_data.get('data')
                tx_data['_signed_data'] = json.dumps(_d, sort_keys=True) if isinstance(_d, dict) else str(_d or '')
            if not isinstance(raw_data, dict):
                raw_data = {'raw': raw_data}
            raw_data['result'] = return_data.hex()
            raw_data['gas_used'] = gas_used
            tx_data['data'] = raw_data
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1 if success else 0, 'gas_used': gas_used, 'logs': logs, 'contract_address': contract_addr, 'result': return_data.hex()}
            await self.receipt_repo.create(receipt)
            return success, {"result": return_data.hex(), "logs": logs}

        elif tx_type == 'htlc_create':
            if not _config.HTLC_V1_ENABLED:
                return False, {"error": "htlc_create disabled in V1 (MCX76-htlc-deferred)"}
            htlc_precompile = "0x0000000000000000000000000000000000000006"
            receiver = tx_data.get('receiver')
            hashlock = tx_data.get('hashlock')
            timelock = tx_data.get('timelock')
            amount = tx_data.get('amount', 0)
            token = tx_data.get('token_address', '0x'+'00'*20)
            if not all([receiver, hashlock, timelock]):
                return False, {"error": "Missing HTLC parameters"}
            # FEE-1: htlc_create previously skipped the MCX fee entirely;
            # charged on attempt BEFORE any VM work. FEE-ORDER-1: kept —
            # VM paths charge upfront (gas semantics: reverted frames still
            # consumed resources), unlike validation-only token paths.
            fee = int(tx_data.get('fee', 0))
            mcx_balance = await self.balance_repo.get(tx_data['from_wallet'])
            if mcx_balance < fee:
                return False, {"error": "Insufficient balance for fee"}
            if fee > 0:
                await self.balance_repo.subtract(tx_data['from_wallet'], fee)
            selector = b'\x01\x02\x03\x04'
            receiver_bytes = bytes.fromhex(receiver[2:])
            hashlock_bytes = bytes.fromhex(hashlock[2:]) if hashlock.startswith('0x') else bytes.fromhex(hashlock)
            timelock_bytes = timelock.to_bytes(8, 'big')
            amount_bytes = amount.to_bytes(32, 'big')
            token_bytes = bytes.fromhex(token[2:]) if token.startswith('0x') else bytes.fromhex(token)
            input_data = selector + receiver_bytes + hashlock_bytes + timelock_bytes + amount_bytes + token_bytes
            success, return_data, gas_used, logs = await self.vm_manager.execute(
                htlc_precompile,
                caller=tx_data['from_wallet'],
                origin=tx_data['from_wallet'],
                value=0,
                gas_limit=_config.GAS_LIMIT_DEFAULT,
                input_data=input_data,
                static=False,
                block_id=block_id
            )
            if success:
                htlc_id = return_data.hex()
                tx_data['status'] = 'confirmed'
                tx_data['block_id'] = block_id
                # R6-contract-tx-at-rest-bind: third branch with the same bug — preserve signed to_wallet/data before mutating.
                if '_signed_to_wallet' not in tx_data:
                    tx_data['_signed_to_wallet'] = str(tx_data.get('to_wallet') or '')
                if '_signed_data' not in tx_data:
                    _d = tx_data.get('data')
                    tx_data['_signed_data'] = json.dumps(_d, sort_keys=True) if isinstance(_d, dict) else str(_d or '')
                tx_data['to_wallet'] = htlc_precompile
                tx_data['amount'] = amount
                if not isinstance(tx_data.get('data'), dict):
                    tx_data['data'] = {'raw': tx_data.get('data') or ''}
                tx_data['data']['htlc_id'] = htlc_id
                await self.tx_repo.create(tx_data)
                receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1, 'gas_used': gas_used, 'logs': logs, 'contract_address': htlc_precompile, 'result': htlc_id}
                await self.receipt_repo.create(receipt)
                return True, {"htlc_id": htlc_id}
            else:
                return False, {"error": "HTLC creation failed"}

        elif tx_type == 'spatial_token_create':
            if block_id < SPATIAL_ACTIVATION_HEIGHT:
                return False, {"error": "Spatial tokens not activated yet"}
            from_wallet = tx_data.get('from_wallet')
            if not from_wallet:
                return False, {"error": "from_wallet required"}
            name = str(tx_data.get('name', ''))
            symbol = str(tx_data.get('symbol', ''))
            if not name or len(name) > SPATIAL_MAX_NAME_LEN:
                return False, {"error": f"name must be 1..{SPATIAL_MAX_NAME_LEN} chars"}
            if not symbol or len(symbol) > SPATIAL_MAX_SYMBOL_LEN:
                return False, {"error": f"symbol must be 1..{SPATIAL_MAX_SYMBOL_LEN} chars"}
            try:
                supply = int(tx_data.get('supply', 0))
                decimals = int(tx_data.get('decimals', 18))
                bundle_count = int(tx_data.get('bundle_count', 1))
            except (TypeError, ValueError):
                return False, {"error": "supply/decimals/bundle_count must be ints"}
            if supply <= 0 or supply > SPATIAL_MAX_SUPPLY:
                return False, {"error": f"supply must be 1..{SPATIAL_MAX_SUPPLY}"}
            if not (0 <= decimals <= 255):
                return False, {"error": "decimals out of range"}
            if bundle_count < 1:
                return False, {"error": "bundle_count must be >= 1"}
            # Spatial Tokens V2: coordinate is derived, not client-chosen.
            # Any client-supplied preferred_coord is silently dropped (old
            # clients keep working; the chain ignores it).
            tx_data.pop('preferred_coord', None)
            # Spatial Tokens V2: flat deploy fee. No coverage or deployment
            # multipliers, no sealed-split replay (the fee is a constant, so
            # producer and follower recompute it identically).
            deploy_fee = int(SPATIAL_BASE_DEPLOY_FEE)
            signed_fee = int(tx_data.get('_signed_fee', tx_data.get('fee', 0)) or 0)
            if signed_fee < deploy_fee:
                return False, {"error": f"fee below deploy fee: need >= {deploy_fee}, got {signed_fee}"}
            creator = from_wallet.lower()
            if not creator.startswith("0x") or len(creator) != 42:
                return False, {"error": "from_wallet must be 0x-prefixed 40-hex"}
            nonce = int(tx_data.get('nonce', 0))
            px, py, pz = _derive_spatial_coord(from_wallet, nonce)
            token_address = "0x" + eth_keccak(
                bytes.fromhex(creator[2:]) + nonce.to_bytes(32, 'big'))[-20:].hex()
            if await self.spatial_token_repo.get(token_address):
                return False, {"error": "token already exists"}
            bal = await self.balance_repo.get(from_wallet)
            if bal < deploy_fee:
                return False, {"error": "Insufficient balance for deploy fee"}
            # FLAW-FIX: preserve the signed fee/to_wallet BEFORE mutating them
            # — followers re-verify the stored tx signature (verify_block_proof
            # and execute_transaction entry) against these fields. Raw values
            # are preserved so str() in the signed message is byte-identical.
            if '_signed_fee' not in tx_data:
                tx_data['_signed_fee'] = tx_data.get('fee', 0)
            if '_signed_to_wallet' not in tx_data:
                tx_data['_signed_to_wallet'] = str(tx_data.get('to_wallet') or '')
            await self.balance_repo.subtract(from_wallet, deploy_fee)
            # Spatial Tokens V2: 90/10 split. The producer's cut stays in
            # tx['fee'] (credited via total_fees); the maze cut rides in
            # _spatial_fee_maze_cut for produce_block to distribute.
            maze_cut = deploy_fee * SPATIAL_DEPLOY_FEE_MAZE_BPS // 10000
            producer_cut = deploy_fee - maze_cut
            tx_data['fee'] = producer_cut
            tx_data['_spatial_fee_maze_cut'] = maze_cut
            tx_data['_is_spatial_deploy'] = True
            tx_data['to_wallet'] = token_address
            await self.spatial_token_repo.create({
                "address": token_address, "creator": creator, "name": name,
                "symbol": symbol, "supply": supply, "decimals": decimals,
                "deploy_block": block_id, "preferred_x": px, "preferred_y": py,
                "preferred_z": pz, "bundle_count": bundle_count, "deploy_nonce": nonce,
            })
            await self.spatial_token_balance_repo.add(token_address, creator, supply)
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            tx_data['amount'] = 0
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1,
                       'gas_used': 0, 'logs': [{'event': 'SpatialTokenCreated',
                       'token_address': token_address, 'creator': creator,
                       'supply': supply, 'preferred_coord': [px, py, pz]}],
                       'contract_address': token_address, 'result': 'created'}
            await self.receipt_repo.create(receipt)
            return True, {"token_address": token_address, "deploy_fee": deploy_fee}

        elif tx_type == 'spatial_token_transfer':
            from_wallet = tx_data.get('from_wallet')
            to_wallet = tx_data.get('to_wallet')
            token_address = tx_data.get('token_address')
            if not from_wallet or not to_wallet or not token_address:
                return False, {"error": "from_wallet, to_wallet and token_address required"}
            # R6-spatial-fee-bind: snapshot the submitted cut before any use; verify prefers it over the carried value.
            if '_signed_maze_cut' not in tx_data:
                tx_data['_signed_maze_cut'] = tx_data.get('_spatial_fee_maze_cut')
            tok = await self.spatial_token_repo.get(token_address)
            if not tok:
                return False, {"error": "token not found"}
            # Spatial Tokens V2: no rehome. Coordinate is fixed at deploy.
            if tx_data.get('new_preferred_coord') is not None:
                return False, {"error": "new_preferred_coord disabled in V2 (no rehome)"}
            try:
                amount = int(tx_data.get('amount', 0))
            except (TypeError, ValueError):
                return False, {"error": "amount must be an int"}
            if amount < 0:
                return False, {"error": "amount cannot be negative"}
            # Spatial Tokens V2: sealed replays carry fee=producer_cut with
            # the maze cut in _spatial_fee_maze_cut (top-level transient on
            # block gossip, data-JSON mirror on stored rows). Restore the
            # full fee so followers deduct exactly what the producer did
            # (V1 SPATIAL-EXEC-SEAL-1 pattern). Fresh submits have no mirror
            # anywhere: deduct as-is. The duplicate-tx guard above already
            # covers same-dict retries at the same height.
            _sealed_cut = tx_data.get('_spatial_fee_maze_cut')
            if _sealed_cut is None:
                _d = tx_data.get('data')
                if isinstance(_d, str):
                    try:
                        _d = json.loads(_d) if _d else {}
                    except Exception:
                        _d = {}
                if isinstance(_d, dict):
                    _sealed_cut = _d.get('_spatial_fee_maze_cut', 0)
            try:
                _sealed_cut = int(_sealed_cut or 0)
            except (TypeError, ValueError):
                _sealed_cut = 0
            fee = int(tx_data.get('fee', 0)) + _sealed_cut
            if fee > 0:
                bal = await self.balance_repo.get(from_wallet)
                if bal < fee:
                    return False, {"error": "Insufficient balance for fee"}
            # FEE-ORDER-1: deducted after the token-balance check below.
            # Spatial Tokens V2: 90/10 split on the transfer fee, same as
            # deploy — computed UNCONDITIONALLY so a forged cut on a fee=0
            # transfer is overwritten with 0 instead of surviving into the
            # sealed block (produce sums and the T9 check both filter by
            # tx_type as well). Preserve the signed fee: followers
            # re-verify the stored tx via message_full, which reads
            # _signed_fee (same FLAW-FIX pattern as spatial_token_create).
            if '_signed_fee' not in tx_data:
                tx_data['_signed_fee'] = tx_data.get('fee', 0)
            maze_cut = fee * SPATIAL_DEPLOY_FEE_MAZE_BPS // 10000
            tx_data['fee'] = fee - maze_cut
            tx_data['_spatial_fee_maze_cut'] = maze_cut
            src_bal = await self.spatial_token_balance_repo.get(token_address, from_wallet.lower())
            if src_bal < amount:
                return False, {"error": f"insufficient token balance ({src_bal} < {amount})"}
            # FEE-ORDER-1: all checks passed — take the fee now.
            if fee > 0:
                await self.balance_repo.subtract(from_wallet, fee)
            await self.spatial_token_balance_repo.add(token_address, from_wallet.lower(), -amount)
            await self.spatial_token_balance_repo.add(token_address, to_wallet.lower(), amount)
            tx_data['status'] = 'confirmed'
            tx_data['block_id'] = block_id
            await self.tx_repo.create(tx_data)
            receipt = {'tx_hash': tx_data.get('tx_hash'), 'block_id': block_id, 'status': 1,
                       'gas_used': 0, 'logs': [{'event': 'SpatialTokenTransferred',
                       'token_address': token_address, 'from': from_wallet.lower(),
                       'to': to_wallet.lower(), 'amount': amount}],
                       'contract_address': token_address, 'result': 'transferred'}
            await self.receipt_repo.create(receipt)
            return True, {"token_address": token_address, "amount": amount}

        elif tx_type == 'spatial_token_burn':
            return False, {"error": "spatial_token_burn out of scope for V1"}

        elif tx_type == 'spatial_challenge_create':
            # REMOVED: spatial_challenges system replaced by Spatial Tokens V1.
            return False, {"error": "spatial_challenge_create removed (Spatial Tokens V1)"}

        elif tx_type == 'spatial_challenge_claim':
            return False, {"error": "spatial_challenge_claim removed (Spatial Tokens V1)"}

        elif tx_type == 'spatial_challenge_cancel':
            return False, {"error": "spatial_challenge_cancel removed (Spatial Tokens V1)"}

        else:
            return False, {"error": f"Unsupported tx_type: {tx_type}"}

    async def _get_confirmed_nonce(self, wallet: str) -> int:
        """Return the next expected nonce for a wallet (= max confirmed nonce + 1).
        Uses MAX(nonce) instead of COUNT(*) so it survives row deletions."""
        return await self._get_confirmed_nonce_at(wallet, None)

    async def _get_confirmed_nonce_at(self, wallet: str, height=None) -> int:
        """Ancestor-scoped confirmed nonce: max tx nonce for the wallet at
        block_id <= height (+1). height=None = unbounded (same as
        _get_confirmed_nonce). Fix 3 (R10): the reorg pre-verify seeds the
        branch nonce context from the COMMON ANCESTOR — the branch replays
        from the fork point, so orphan-tip nonces are the wrong base."""
        if self.db.db_type == "sqlite":
            query = "SELECT MAX(nonce) FROM transactions WHERE from_wallet = ? AND block_id >= 0"
            params: list = [wallet]
            if height is not None:
                query += " AND block_id <= ?"
                params.append(int(height))
        else:
            query = "SELECT COALESCE(MAX(nonce), -1) FROM transactions WHERE from_wallet = $1 AND block_id >= 0"
            params = [wallet]
            if height is not None:
                query += " AND block_id <= $2"
                params.append(int(height))
        result = await self.db.fetchval(query, *params)
        # `(result or -1)` was WRONG: MAX(nonce)=0 (a wallet whose first tx is
        # confirmed) is falsy, so the second tx was rejected as nonce-too-high.
        return (result if result is not None else -1) + 1

    def _verify_tx_signature(self, tx: Dict) -> bool:
        signature = tx.get('signature', '')
        # 1. Raw Ethereum transaction check (MetaMask / web3)
        if isinstance(signature, str) and (signature.startswith('0x') or len(signature) > 130):
            try:
                decoded = decode_raw_eth_transaction(signature)
                # R8-chain-id: consensus enforces the chain binding here so
                # every validation route (blocks, gossip, RPC) is covered,
                # not just ingress gates.
                if not _raw_chain_id_ok(decoded):
                    return False
                # R4-raw-tx-bind: the decoded tx is the source of truth; the
                # body must agree field-by-field. Previously only `from` was
                # checked, so a signed tx could be rebound to a different
                # recipient/value/nonce in the body.
                if (str(decoded.get('from') or '').lower() != str(tx.get('from_wallet', '')).lower()
                        or str(decoded.get('to') or '').lower() != str(tx.get('to_wallet') or '').lower()
                        or int(decoded.get('value', 0) or 0) != int(tx.get('value', 0) or 0)
                        or int(decoded.get('nonce', 0) or 0) != int(tx.get('nonce', 0) or 0)
                        or int(decoded.get('gas', 0) or 0) != int(tx.get('gas', 0) or 0)
                        or int(decoded.get('gasPrice', 0) or 0) != int(tx.get('gasPrice', 0) or 0)
                        or str(decoded.get('data') or '').lower() != str(tx.get('data') or '').lower()):
                    return False
                if str(decoded.get('hash', '')).lower() != str(tx.get('tx_hash', '')).lower():
                    return False
                recovered = decoded.get('from', '')
                if recovered and recovered.lower() == tx.get('from_wallet', '').lower():
                    return True
            except Exception:
                pass

        # 2. Native Munex signature verification (support canonical full payload and legacy payload)
        # FLAW-FIX: spatial_token_create mutates tx['fee'] (to producer_cut)
        # and tx['to_wallet'] (to token_address) at execute time; followers
        # re-verify the STORED tx against the original signed values, which
        # ride along in _signed_fee / _signed_to_wallet transient fields.
        fee_use = tx.get('_signed_fee', tx.get('fee', 0))
        to_use = tx.get('_signed_to_wallet', tx.get('to_wallet', ''))
        message_parts_legacy = [
            tx.get('from_wallet', ''),
            to_use,
            str(tx.get('value', 0)),
            str(fee_use),
            str(tx.get('nonce', 0)),
            str(int(tx.get('timestamp', 0)))
        ]
        message_legacy = ':'.join(message_parts_legacy)

        data_val = tx.get('data', '')
        # R6-contract-tx-at-rest-bind: prefer the at-rest capture over the executed wrap.
        _signed_data = tx.get('_signed_data')
        # R6-contract-tx-at-rest-bind: htlc_create included (dormant until V1 re-enables; same failure mode).
        if _signed_data is not None and tx.get('tx_type') in ('contract_deploy', 'contract_call', 'htlc_create'):
            data_str = _signed_data
        else:
            data_str = json.dumps(data_val, sort_keys=True) if isinstance(data_val, dict) else str(data_val)
        target = tx.get('contract_address') or tx.get('token_address') or ''
        spatial_parts = []
        _spatial_fields = ["name","symbol","supply","decimals","preferred_coord",
                           "bundle_count","token_address","new_preferred_coord"]
        if tx.get('tx_type') == 'spatial_token_transfer':
            # FLAW-FIX (vs brief §7.7): spec §14 lists amount as a transfer
            # field but the mandated tuple omitted it — the economic payload
            # would be unsigned (any relayer could alter it). Added for the
            # transfer type ONLY: existing tx types mutate tx['amount'] after
            # signing (lines like tx_data['amount'] = amount), so an
            # unconditional amount field would break their follower re-verify.
            # R6-spatial-fee-bind: _spatial_fee_maze_cut is signature-bound for transfers. Do not reorder fields.
            _spatial_fields = _spatial_fields + ["amount", "_spatial_fee_maze_cut"]
        for _f in _spatial_fields:
            # R6-spatial-fee-bind: prefer the at-rest capture over the carried value.
            if _f == '_spatial_fee_maze_cut' and '_signed_maze_cut' in tx:
                _v = tx.get('_signed_maze_cut')
            else:
                _v = tx.get(_f)
            if _v is None or _v == "":
                continue
            if isinstance(_v, (dict, list)):
                _v = canonical_json_bytes(_v).decode("utf-8")
            spatial_parts.append(f"{_f}={_v}")
        _type_parts = []
        # TXTYPE-BIND-1 (mainnet audit): the transaction type is part of
        # every native signed message. Without it a valid `send` signature
        # verified a `burn` of the same fields (and transfer/send/burn and
        # deploy/call pairs likewise) -- cross-type reinterpretation with a
        # valid signature. Appended here (existing suffix order otherwise
        # untouched); legacy typeless messages still verify ONLY via the
        # send/burn legacy fallback below. Protocol break: old signatures
        # without a bound type no longer verify (see migration note).
        _msg_tx_type = tx.get('tx_type') or 'send'
        _type_parts.append(f"tx_type={_msg_tx_type}")
        if tx.get('tx_type') in ('contract_deploy', 'contract_call'):
            # R6-value-moved-bind: _value_moved is signature-bound for deploys/calls. Do not reorder fields.
            _vm = _moved_value_of(tx)
            if _vm:
                _type_parts.append(f"_value_moved={_vm}")
            # TXTYPE-BIND-1: execution inputs the generic message missed.
            # Deploy reads bytecode/abi/gas (not `data`); calls read
            # input-canonicalized `data` plus gas. A mutated init code or
            # gas limit previously kept a valid signature.
            try:
                _type_parts.append(f"gas={int(tx.get('gas', 0) or 0)}")
            except (TypeError, ValueError):
                _type_parts.append("gas=0")
        if tx.get('tx_type') == 'contract_deploy':
            _bc = tx_data_to_hex(tx.get('bytecode', '')) if isinstance(tx.get('bytecode', ''), str) else ''
            _type_parts.append(f"bytecode={_bc}")
            _abi = tx.get('abi', {})
            try:
                _type_parts.append(f"abi={canonical_json_bytes(_abi).decode('utf-8') if isinstance(_abi, (dict, list)) else str(_abi)}")
            except Exception:
                _type_parts.append(f"abi={str(_abi)}")
        if tx.get('tx_type') == 'htlc_create':
            # TXTYPE-BIND-1: HTLC escrow terms (dormant while HTLC_V1_ENABLED
            # is false, but bound so enabling cannot resurrect unsigned terms).
            for _hf in ("receiver", "hashlock", "timelock", "amount"):
                _type_parts.append(f"htlc_{_hf}={tx.get(_hf, '')}")
        message_parts_full = [
            str(CHAIN_ID),
            tx.get('from_wallet', ''),
            to_use,
            str(tx.get('value', 0)),
            str(fee_use),
            str(tx.get('nonce', 0)),
            str(int(tx.get('timestamp', 0))),
            target,
            data_str,
        ] + spatial_parts + _type_parts
        message_full = ':'.join(message_parts_full)

        pub_key = tx.get('pub_key')
        if pub_key:
            try:
                if pubkey_to_address(pub_key).lower() != tx.get('from_wallet', '').lower():
                    return False
            except Exception:
                return False
            # F2: token_create carries the REST canonical auth signature.
            # R5-sig-bind: nonce and fee are part of the signed message. Do not reorder fields.
            if tx.get('tx_type') == 'token_create':
                d = tx.get('data') or {}
                _fee = tx.get('_signed_fee', tx.get('fee', 0))
                # TXTYPE-BIND-1: temporal/vesting config affects execution
                # (trading locks, cooldowns, vesting) and was unsigned.
                try:
                    _tc = canonical_json_bytes(d.get('temporal_config') or {}).decode('utf-8')
                except Exception:
                    _tc = '{}'
                msg_create = f"{CHAIN_ID}:create_token:{tx.get('from_wallet', '')}:{d.get('name', '')}:{d.get('symbol', '')}:{d.get('total_supply', 0)}:{d.get('decimals', 18)}:{int(bool(d.get('burnable', True)))}:{int(tx.get('nonce', 0))}:{int(_fee or 0)}:{int(tx.get('timestamp', 0))}:{_tc}"
                return verify_signature(pub_key, msg_create, signature)
            if tx.get('tx_type') == 'spatial_token_create':
                # Spatial Tokens V2: REST-created spatial_token_create is
                # signed over the dedicated canonical message WITHOUT a
                # coordinate (V2 derives it). Short-circuit BEFORE the
                # generic payload check so P2P gossip and follower replay
                # accept the tx. The generic full message stays as fallback.
                try:
                    _sup = int(tx.get('supply', 0))
                    _dec = int(tx.get('decimals', 18))
                    _bc = int(tx.get('bundle_count', 1))
                    _ts = int(tx.get('timestamp', 0))
                    _nonce = int(tx.get('nonce', 0))
                    _fee = int(tx.get('_signed_fee', tx.get('fee', 0)) or 0)
                except (TypeError, ValueError):
                    return False
                # R5-sig-bind: nonce and fee are part of the signed message. Do not reorder fields.
                msg_spatial = (f"{CHAIN_ID}:spatial_token_create:{tx.get('from_wallet', '')}:"
                               f"{tx.get('name', '')}:{tx.get('symbol', '')}:{_sup}:"
                               f"{_dec}:{_bc}:{_nonce}:{_fee}:{_ts}")
                return (verify_signature(pub_key, msg_spatial, signature)
                        or verify_signature(pub_key, message_full, signature))
            # N-5: Legacy fallback is ONLY permitted for standard send / burn transactions without contract or spatial payloads
            tx_type = tx.get('tx_type') or 'send'
            allow_legacy = (tx_type in ('send', 'burn')) and not tx.get('data') and not tx.get('contract_address') and not tx.get('token_address')
            if verify_signature(pub_key, message_full, signature) or (allow_legacy and verify_signature(pub_key, message_legacy, signature)):
                return True
        for m in self.miners.values():
            if m.get('wallet') == tx.get('from_wallet'):
                tx_type = tx.get('tx_type') or 'send'
                allow_legacy = (tx_type in ('send', 'burn')) and not tx.get('data') and not tx.get('contract_address') and not tx.get('token_address')
                if verify_signature(m['pub'], message_full, signature) or (allow_legacy and verify_signature(m['pub'], message_legacy, signature)):
                    return True
        return False

    async def _submit_pool_tx(self, tx_data: Dict) -> Tuple[int, Dict]:
        """F2: submit a REST tx through the mempool + gossip (the same path the
        WS handlers and pre-signed automation batch use) instead of executing
        it against local state at submit time. Execute-at-submit wrote
        balances/receipts on ONE node without a block and peers never replayed
        the tx, so every REST mutation diverged the cluster. Returns
        (http_status, body)."""
        if not self._verify_tx_signature(tx_data):
            return 401, {"success": False, "error": "Invalid signature"}
        from_wallet = tx_data.get('from_wallet')
        try:
            _sn, _sf = int(tx_data.get('nonce', 0)), int(tx_data.get('fee', 0))
        except (TypeError, ValueError):
            return 400, {"success": False, "error": "nonce/fee must be ints"}
        if from_wallet:
            expected = max(await self._get_confirmed_nonce(from_wallet), self.mempool.get_nonce(from_wallet))
            if _sn != expected:
                return 400, {"success": False, "error": f"Nonce mismatch: expected {expected}, got {tx_data.get('nonce', 0)}"}
        min_fee = get_dynamic_fee(self.mempool.size())
        if _sf < min_fee:
            return 400, {"success": False, "error": f"Fee too low: need >= {min_fee}"}
        if not await self.mempool.add(tx_data):
            return 503, {"success": False, "error": "Mempool full or invalid"}
        if self.p2p:
            await self.p2p.broadcast_transaction(tx_data)
        return 200, {"success": True, "pending": True, "tx_hash": tx_data.get('tx_hash')}

    async def _replay_transactions(self, tx_list: list, block_id: int = None, block_ts: float = None, _branch_state=None) -> bool:
        """Shadow-reexecute every tx in a block without mutating live state.
        Returns True if all succeed, False otherwise. block_id lets spatial
        branches mirror the checks execute_transaction applies (Spatial
        Tokens V2: flat fees, no coverage/deployments recompute). block_ts
        threads the sealed timestamp (R4-opcodes-add) so shadow TIMESTAMP
        agrees with production.
        R9-branch-replay (I-R8-09): _branch_state is an optional persistent
        shadow context (balances/token/storage maps) shared across the
        blocks of one candidate suffix, so a spend funded by an earlier
        candidate block validates. Without it each call starts fresh
        (single-block behavior, unchanged). Base reads still come from
        live repos — see the residual note at the N-10 call site."""
        if isinstance(_branch_state, dict):
            shadow_balances = _branch_state.setdefault("balances", {})
            shadow_token_balances = _branch_state.setdefault("token", {})
            shadow_storage = _branch_state.setdefault("storage", {})
        else:
            shadow_balances: Dict[str, int] = {}
            shadow_token_balances: Dict[tuple, int] = {}
            # R4-shadow-intra-block: per-address storage cache mirroring the
            # shadow_balances pattern. First access reads the repo; later txs in
            # the same block merge the subprocess's returned _new_storage map
            # (below), so sequential calls to one contract see each other's
            # writes. Previously every tx re-read live state and _new_storage
            # was unpacked but dropped.
            shadow_storage: Dict[str, Dict[str, int]] = {}

        async def _get_bal(wallet: str) -> int:
            return shadow_balances.get(wallet, await self.balance_repo.get(wallet))

        for tx_data in tx_list:
            tx_type = tx_data.get('tx_type', 'send')
            val = int(tx_data.get('value', 0))
            fee = int(tx_data.get('fee', 0))
            from_w = tx_data.get('from_wallet', '')
            to_w = tx_data.get('to_wallet', '')

            # Fork tolerance: this exact tx may already be confirmed in our
            # own fork above the common ancestor — its state effects are
            # already applied locally, so re-executing here would double-count
            # them (and can false-fail on already-spent balance). The reorg
            # path rolls such txs back before re-applying the peer's blocks.
            _txh = tx_data.get('tx_hash')
            if _txh:
                _existing = await self.tx_repo.get_by_hash(_txh)
                if _existing and int(_existing.get('block_id', -1)) >= 0:
                    continue

            if tx_type in ('send', 'burn'):
                total = val + fee
                current = await _get_bal(from_w)
                if current < total:
                    logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} insufficient balance ({current} < {total})")
                    return False
                shadow_balances[from_w] = current - total
                if tx_type == 'send' and to_w:
                    to_current = await _get_bal(to_w)
                    shadow_balances[to_w] = to_current + val

            elif tx_type == 'token_transfer':
                token_addr = tx_data.get('token_address', '')
                amount = val
                # SHADOW-PARITY-1 (mainnet audit): mirror the execute path —
                # MCX fee, temporal policy (at block time), burn-tax net.
                # The shadow previously ignored all three, so blocks the
                # executor rejects passed verification (verify-ok/append-fail
                # stall) and fee/burn-tax accounting diverged.
                if fee > 0:
                    _cb = await _get_bal(from_w)
                    if _cb < fee:
                        logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for token fee")
                        return False
                    shadow_balances[from_w] = _cb - fee
                _tcfg = await self.get_token_temporal_config(token_addr)
                if _tcfg:
                    _now = block_ts if block_ts is not None else time.time()
                    _tstart = _tcfg.get("trading_starts_at", 0)
                    _owner = (await self.token_repo.get(token_addr) or {}).get("owner")
                    if _tstart > 0 and _now < _tstart and from_w != _owner:
                        logger.warning(f"[Verify] Shadow re-exec: trading locked")
                        return False
                    _cd = _tcfg.get("transfer_cooldown_seconds", 0)
                    if _cd > 0 and from_w != _owner:
                        _lt = await self.contract_state_repo.get(token_addr, f"last_tx_{from_w}")
                        if _lt and _now - float(_lt) < _cd:
                            logger.warning(f"[Verify] Shadow re-exec: cooldown active")
                            return False
                    _v = (_tcfg.get("vesting_schedules", {}) or {}).get(from_w)
                    if _v:
                        _vt, _vs, _vd = int(_v.get("total", 0)), float(_v.get("start", 0)), float(_v.get("duration", 1))
                        _locked = _vt if _now < _vs else (0 if _now >= _vs + _vd else int(_vt * (1.0 - (_now - _vs) / _vd)))
                        _fb = await self.token_balance_repo.get(token_addr, from_w)
                        if _fb - amount < _locked:
                            logger.warning(f"[Verify] Shadow re-exec: vesting locked")
                            return False
                try:
                    _bbps = int((_tcfg or {}).get("burn_fee_bps", 0) or 0)
                except (TypeError, ValueError):
                    _bbps = 0
                _btax = (amount * _bbps) // 10000 if _bbps > 0 else 0
                _net = amount - _btax
                key_from = (token_addr, from_w)
                if key_from in shadow_token_balances:
                    current_from = shadow_token_balances[key_from]
                else:
                    current_from = await self.token_balance_repo.get(token_addr, from_w)
                if current_from < amount:
                    logger.warning(f"[Verify] Shadow re-exec: token transfer insufficient balance")
                    return False
                shadow_token_balances[key_from] = current_from - amount
                key_to = (token_addr, to_w)
                if key_to in shadow_token_balances:
                    current_to = shadow_token_balances[key_to]
                else:
                    current_to = await self.token_balance_repo.get(token_addr, to_w)
                shadow_token_balances[key_to] = current_to + _net

            elif tx_type == 'token_burn':
                token_addr = tx_data.get('token_address', '')
                amount = val
                # SHADOW-PARITY-1: mirror the MCX fee the executor charges.
                if fee > 0:
                    _cb = await _get_bal(from_w)
                    if _cb < fee:
                        logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for burn fee")
                        return False
                    shadow_balances[from_w] = _cb - fee
                key_from = (token_addr, from_w)
                if key_from in shadow_token_balances:
                    current_from = shadow_token_balances[key_from]
                else:
                    current_from = await self.token_balance_repo.get(token_addr, from_w)
                if current_from < amount:
                    logger.warning(f"[Verify] Shadow re-exec: token burn insufficient balance")
                    return False
                shadow_token_balances[key_from] = current_from - amount

            elif tx_type in ('contract_deploy', 'contract_call', 'htlc_create'):
                if fee > 0:
                    current = await _get_bal(from_w)
                    if current < fee:
                        logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for contract fee")
                        return False
                    shadow_balances[from_w] = current - fee

                if tx_type == 'htlc_create':
                    # SHADOW-PARITY-1: the executor REJECTS htlc_create while
                    # disabled, so the shadow must reject too. The old
                    # `continue` passed blocks that append-live rejects
                    # (verify-ok/append-fail stall).
                    if not _config.HTLC_V1_ENABLED:
                        logger.warning("[Verify] Shadow re-exec: htlc_create disabled")
                        return False
                    # The HTLC precompile mints a random contract id, so replay is
                    # non-deterministic. Fee/balance was validated above.
                    continue

                vm = self.vm_manager
                if vm is None:
                    logger.warning("[Verify] VM manager unavailable — contract re-execution skipped")
                    continue

                value = int(tx_data.get('value', 0))
                gas_limit = _gas_ceiling(tx_data.get('gas', _config.GAS_LIMIT_DEFAULT))  # GAS-CEIL-1
                # fixes1-3A/3B on the replay path: raw eth txs carry init code
                # in 'data' and calldata in 'data' — 'bytecode'/'input' are the
                # native-REST fields. execute_transaction already reads both;
                # the shadow replay must match or valid blocks fail verification.
                # tx_data_to_bytes also unwraps {'raw':...} dicts written by
                # contract_call execution before block inclusion.
                input_data = tx_data_to_bytes(tx_data.get('data'))
                if not input_data and tx_data.get('input') is not None:
                    input_data = tx_data_to_bytes(tx_data.get('input'))

                try:
                    if tx_type == 'contract_deploy':
                        exec_addr = compute_contract_address(from_w, int(tx_data.get('nonce', 0)))
                        code_hex = tx_data_to_hex(tx_data.get('bytecode')) or tx_data_to_hex(tx_data.get('data'))
                        if not code_hex:
                            logger.warning(f"[Verify] contract_deploy {tx_data.get('tx_hash', '')[:16]} missing bytecode")
                            return False
                        input_hex = ''
                    else:  # contract_call
                        exec_addr = tx_data.get('to_wallet')
                        contract = await vm.contract_v2_repo.get(exec_addr)
                        if not contract:
                            logger.warning(f"[Verify] contract_call to unknown contract {str(exec_addr)[:16]}")
                            return False
                        code_hex = contract['bytecode']
                        input_hex = input_data.hex()

                    # Fresh shadow caches — subprocess returns updated copies and
                    # nothing here is ever written back to the live database.
                    # R4-shadow-intra-block: serve from the per-address cache
                    # when this block already wrote here.
                    if exec_addr in shadow_storage:
                        storage_cache = dict(shadow_storage[exec_addr])
                    else:
                        storage_rows = await vm.contract_storage_v2_repo.get_all(exec_addr)
                        storage_cache = {key: int(val) for key, val in storage_rows.items()}
                        shadow_storage[exec_addr] = dict(storage_cache)
                    if not vm._code_cache_valid:
                        all_contracts = await vm.contract_v2_repo.get_all()
                        vm._code_cache = {c['address']: bytes.fromhex(c['bytecode']) for c in all_contracts}
                        vm._code_cache_valid = True
                    balance_cache = {}
                    for addr in {from_w, exec_addr}:
                        if addr:
                            balance_cache[addr] = await self.balance_repo.get(addr)
                    # R4-top-level-value: mirror the execute path in shadow
                    # (no live writes). Debit from_w up front so the frame
                    # and later txs see post-debit balances; credit exec_addr
                    # on success; restore from_w on failure.
                    _shadow_v = int(value or 0)
                    _shadow_v0 = None
                    if _shadow_v > 0:
                        _shadow_v0 = await _get_bal(from_w)
                        if _shadow_v0 < _shadow_v:
                            logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for value")
                            return False
                        shadow_balances[from_w] = _shadow_v0 - _shadow_v
                        if from_w:
                            balance_cache[from_w] = _shadow_v0 - _shadow_v
                    os.environ['MCX_DB_URL'] = vm.db._pg_target_dsn if vm.db.db_type == 'postgres' else 'sqlite://microcore.db'
                    loop = asyncio.get_event_loop()
                    # R4-pool-rebuild: same rebuild-and-retry helper (this
                    # shadow path broke identically on a poisoned pool).
                    # R4-replay-height: run at the verified block's id, not
                    # the local tip (during reorg/follower replay self.height
                    # is a different chain's tip; height-gated precompiles and
                    # activation checks would evaluate wrong).
                    _replay_height = block_id if block_id is not None else int(self.height)
                    result = await vm._run_vm_subprocess(
                        (code_hex, from_w, from_w, value, gas_limit, exec_addr, input_hex,
                         False, storage_cache, vm._code_cache, balance_cache, None, None,
                         _replay_height, block_ts),
                        timeout=VM_TIMEOUT)
                    success, ret_hex, gas_used, logs, _new_storage, _new_bal, _new_tok = result
                    # R5-shadow-balance-fold: fold intra-block balance deltas so later txs in this block shadow-see them.
                    if success and isinstance(_new_bal, dict):
                        for _b_addr, _b_val in _new_bal.items():
                            try:
                                shadow_balances[_b_addr] = int(_b_val)
                            except (TypeError, ValueError):
                                continue
                    if success and isinstance(_new_tok, dict):
                        for _tk_key, _tk_val in _new_tok.items():
                            if isinstance(_tk_key, (list, tuple)) and len(_tk_key) == 2:
                                try:
                                    shadow_token_balances[tuple(_tk_key)] = int(_tk_val)
                                except (TypeError, ValueError):
                                    continue
                    # R4-shadow-intra-block: fold the subprocess's storage
                    # writes into the block-scoped cache for later txs.
                    if success and isinstance(_new_storage, dict):
                        for _s_addr, _slots in _new_storage.items():
                            if isinstance(_slots, dict):
                                _bucket = shadow_storage.setdefault(_s_addr, {})
                                for _sk, _sv in _slots.items():
                                    try:
                                        _bucket[_sk] = int(_sv)
                                    except (TypeError, ValueError):
                                        continue
                    if _shadow_v > 0:
                        if success:
                            shadow_balances[exec_addr] = await _get_bal(exec_addr) + _shadow_v
                        else:
                            shadow_balances[from_w] = _shadow_v0
                    if not success:
                        logger.warning(f"[Verify] Contract {'call' if tx_type == 'contract_call' else 'deploy'} failed: {tx_data.get('tx_hash', '')[:16]}")
                        return False
                except Exception as e:
                    logger.warning(f"[Verify] Contract {'call' if tx_type == 'contract_call' else 'deploy'} re-execution failed: {e}")
                    return False

            elif tx_type == 'token_create':
                # Mirror execute_transaction's balance effects: the owner pays
                # the creation fee. The token address derives from tx_hash, so
                # a same-block transfer of the fresh supply can shadow-see it.
                d = tx_data.get('data') or {}
                fee_floor = get_token_creation_fee(0)
                if fee < fee_floor:
                    logger.warning(f"[Verify] Shadow re-exec: token_create fee {fee} below floor {fee_floor}")
                    return False
                current = await _get_bal(from_w)
                if current < fee:
                    logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for token_create fee ({current} < {fee})")
                    return False
                shadow_balances[from_w] = current - fee
                try:
                    _tc_addr = _derive_token_address(tx_data.get('tx_hash'), from_w, d.get('name'), d.get('symbol'))
                    _tc_key = (_tc_addr, from_w)
                    shadow_token_balances[_tc_key] = shadow_token_balances.get(_tc_key, 0) + int(d.get('total_supply', 0)) * SUBS
                except Exception:
                    pass

            elif tx_type == 'spatial_token_create':
                # Mirror execute (Spatial Tokens V2): flat deploy fee, no
                # coverage or deployment multipliers. MCX fee only — token
                # supply is not needed for block verification.
                # SHADOW-PARITY-1: mirror the executor's admission gates
                # (signed-fee floor, field shapes); underfunded/malformed
                # creates must fail here exactly as in execute.
                try:
                    _signed = int(tx_data.get('_signed_fee', tx_data.get('fee', 0)) or 0)
                except (TypeError, ValueError):
                    _signed = 0
                if _signed < int(SPATIAL_BASE_DEPLOY_FEE):
                    logger.warning(f"[Verify] Shadow re-exec: spatial deploy fee below floor")
                    return False
                _nm, _sy = str(tx_data.get('name', '')), str(tx_data.get('symbol', ''))
                try:
                    _su, _de, _bc = int(tx_data.get('supply', 0)), int(tx_data.get('decimals', 18)), int(tx_data.get('bundle_count', 1))
                except (TypeError, ValueError):
                    logger.warning(f"[Verify] Shadow re-exec: spatial deploy bad ints")
                    return False
                if (not _nm or len(_nm) > SPATIAL_MAX_NAME_LEN or not _sy
                        or len(_sy) > SPATIAL_MAX_SYMBOL_LEN or _su < 1
                        or _su > SPATIAL_MAX_SUPPLY or not (0 <= _de <= 255) or _bc < 1):
                    logger.warning(f"[Verify] Shadow re-exec: spatial deploy malformed")
                    return False
                deploy_fee = int(SPATIAL_BASE_DEPLOY_FEE)
                current = await _get_bal(from_w)
                if current < deploy_fee:
                    logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} cannot afford spatial deploy fee ({current} < {deploy_fee})")
                    return False
                shadow_balances[from_w] = current - deploy_fee

            elif tx_type == 'spatial_token_transfer':
                token_addr = tx_data.get('token_address', '')
                # SHADOW-PARITY-1: the executor rejects unknown tokens; the
                # shadow must too (else it models transfers of thin air).
                if not await self.spatial_token_repo.get(token_addr):
                    logger.warning(f"[Verify] Shadow re-exec: spatial token not found")
                    return False
                try:
                    amount = int(tx_data.get('amount', 0))
                except (TypeError, ValueError):
                    logger.warning("[Verify] Shadow re-exec: spatial_token_transfer bad amount")
                    return False
                # Separate shadow key space ("S:"+token_address) so spatial
                # balances can never collide with regular token balances.
                skey_from = ("S:" + str(token_addr), from_w.lower())
                if skey_from in shadow_token_balances:
                    s_from = shadow_token_balances[skey_from]
                else:
                    s_from = await self.spatial_token_balance_repo.get(token_addr, from_w.lower())
                if s_from < amount:
                    logger.warning(f"[Verify] Shadow re-exec: spatial transfer insufficient balance ({s_from} < {amount})")
                    return False
                shadow_token_balances[skey_from] = s_from - amount
                skey_to = ("S:" + str(token_addr), to_w.lower())
                if skey_to in shadow_token_balances:
                    s_to = shadow_token_balances[skey_to]
                else:
                    s_to = await self.spatial_token_balance_repo.get(token_addr, to_w.lower())
                shadow_token_balances[skey_to] = s_to + amount
                # Spatial Tokens V2: model the FULL fee the live path
                # deducts (sealed tx['fee'] is producer_cut; restore the
                # maze cut from the data mirror like execute does).
                _sh_cut = tx_data.get('_spatial_fee_maze_cut')
                if _sh_cut is None:
                    _sh_d = tx_data.get('data')
                    if isinstance(_sh_d, str):
                        try:
                            _sh_d = json.loads(_sh_d) if _sh_d else {}
                        except Exception:
                            _sh_d = {}
                    if isinstance(_sh_d, dict):
                        _sh_cut = _sh_d.get('_spatial_fee_maze_cut', 0)
                try:
                    _sh_cut = int(_sh_cut or 0)
                except (TypeError, ValueError):
                    _sh_cut = 0
                if fee + _sh_cut > 0:
                    current = await _get_bal(from_w)
                    if current < fee + _sh_cut:
                        logger.warning(f"[Verify] Shadow re-exec: {from_w[:16]} insufficient balance for spatial transfer fee")
                        return False
                    shadow_balances[from_w] = current - fee - _sh_cut

            elif tx_type == 'spatial_token_burn':
                logger.warning("[Verify] Shadow re-exec: spatial_token_burn out of scope for V1")
                return False

            else:
                logger.warning(f"[Verify] Shadow re-exec: unknown tx_type '{tx_type}'")
                return False

        return True

    async def verify_block_proof(self, block: dict, _att_base: dict = None, _maze_base: dict = None, _branch=None) -> bool:
        """Verify PoG block proof – replay maze_updates, verify lottery, validate signature,
        re-execute transactions, and check timestamp.
        R9-branch-replay (I-R8-09): _branch is an optional shared context
        ({"nonces": {}, "maps": {}}) threading nonce continuity and shadow
        state across one candidate suffix. Without it each call verifies in
        isolation (single-block behavior, unchanged)."""
        if block.get('id') == 0:
            # If we have a known genesis hash, require exact match.
            # Only accept novel genesis during bootstrap when local hash is empty.
            if _genesis._node_genesis_hash:
                return block.get('phash') == '0' * 64 and block.get('hash') == _genesis._node_genesis_hash
            return block.get('phash') == '0' * 64 and bool(block.get('state_root'))

        producer_pub = block.get("producer_pub")
        if not producer_pub:
            logger.warning(f"[Verify] Block {block['id']} missing producer_pub — rejecting")
            return False

        if block.get("transactions") is None or block.get("maze_attestation") is None:
            logger.warning(f"[Verify] Block {block['id']} missing proof fields")
            return False

        # Strict hash + signature
        unsigned_block = {k: v for k, v in block.items() if k not in CONSENSUS_EXCLUDED_FIELDS}
        expected_hash = hash_block(unsigned_block)
        if block.get("hash") != expected_hash:
            logger.warning(f"[Verify] Block {block['id']} hash mismatch (tampered or corrupt)")
            return False
        if not verify_signature(producer_pub, bytes.fromhex(block.get("hash", "")), block.get("signature", "")):
            logger.warning(f"[Verify] Block {block['id']} invalid signature")
            return False

        # ─── Timestamp validation ───
        # R8-timestamp-deterministic (R7-11): consensus validity from chain
        # data only. The old `block_ts > now + 300` rule let skewed nodes
        # disagree on the same signed block. Monotonicity and the future
        # bound both key off the parent row (matched phash only — during a
        # fork the pre-state is ambiguous and both defer to reorg, same
        # rationale as the old monotonicity guard).
        # R9-timestamp-fork (I-R8-06): a timestamp is REQUIRED
        # (non-genesis) — missing/zero/non-numeric can no longer slip past
        # on any path. Reorg candidates face the same rule branch-locally
        # in _reorg_chain's linkage gate.
        block_ts = block.get("ts", 0)
        if block.get('id', 0) > 0 and not block_ts:
            logger.warning(f"[Verify] Block {block['id']} missing timestamp")
            return False
        if block_ts:
            if block.get('id', 0) > 0:
                parent = await self.block_repo.get_by_id(block['id'] - 1)
                if parent and parent.get('hash') == block.get('phash'):
                    if not _block_timestamp_ok(block_ts, parent.get('ts', 0)):
                        logger.warning(f"[Verify] Block {block['id']} timestamp {block_ts} outside parent-relative bounds (parent {parent.get('ts', 0)})")
                        return False

        winner = block.get('winner') or (block.get('miners') or [None])[0]
        # ─── IDEA5-ATTEST: self-attested maze size (replaces lottery_proof) ───
        att = block.get("maze_attestation") or {}
        if not isinstance(att, dict):
            logger.warning(f"[Verify] Block {block['id']} malformed maze_attestation")
            return False
        att_mid = str(att.get("maze_id", "") or "")
        att_pub = str(att.get("pubkey", "") or "")
        try:
            att_size = int(att.get("size", -1))
        except (TypeError, ValueError, OverflowError):
            # R4-overflow-guard: a non-finite size (inf/nan via non-JSON
            # transport or in-process construction) lands at -1 and takes
            # the normal attestation-size rejection below — no crash.
            att_size = -1
        if not att_mid or not att_pub or att_mid.lower() != att_pub.lower():
            logger.warning(f"[Verify] Block {block['id']} maze_attestation pubkey != maze_id (IDEA5-ATTEST)")
            return False
        # MCX79 fixed validator set: only listed keys may produce. Empty
        # set = open mode (any key eligible, pre-MCX79 behavior).
        _validators = _effective_validators()
        if _validators and _normalize_validator_key(att_pub) not in _validators:
            logger.warning(f"[Verify] Block {block['id']} attestation key not in validator set — rejecting")
            return False
        if not producer_pub or producer_pub.lower() != att_pub.lower():
            logger.warning(f"[Verify] Block {block['id']} producer_pub != attestation pubkey (IDEA5-ATTEST)")
            return False
        if not winner:
            logger.warning(f"[Verify] Block {block['id']} has no winner")
            return False
        # IDEA5-MAZE-KEY-BINDING-1: winner must derive from the attestation key:
        #   PC_ + sha256(pubkey_to_address(att_pub) + "_mcx_miner")[:32]
        # (core_suffix on the winner id is tolerated).
        try:
            _derived = "PC_" + hashlib.sha256(f"{pubkey_to_address(att_pub)}_mcx_miner".encode()).hexdigest()[:32].upper()
        except Exception as e:
            logger.warning(f"[Verify] Block {block['id']} winner derivation failed: {e}")
            return False
        if not (winner == _derived or (isinstance(winner, str) and winner.startswith(_derived + "_"))):
            logger.warning(f"[Verify] Block {block['id']} winner not derived from attestation key (IDEA5-MAZE-KEY-BINDING-1)")
            return False
        # Growth cap: +ATTEST_GROWTH_PER_BLOCK per block; first claim capped at
        # MIN_MAZE_SIZE + ATTEST_FRESH_BUFFER (ATTEST-FRESH-BUFFER-1).
        _prior_att = None
        _reorg_mode = isinstance(_att_base, dict)
        if _reorg_mode and att_mid in _att_base:
            # P6 (MCX72): caller-supplied ancestor row (reorg adoption) — the
            # local row may be orphaned-tip state, which is not agreed state.
            _prior_att = _att_base[att_mid]
        elif not _reorg_mode:
            _prior_att = await self.maze_attestation_repo.get(att_mid)
        # P6b (MCX72): reorg mode with no ancestor row means the maze never
        # attested in agreed state — the fresh-maze cap below applies, and
        # the local row (if any: orphaned-tip state) must not participate.
        # Without this, a first-attestation race on both forks of the same
        # maze permanently blocks the reorg (ATTEST-CAP-STRICT vs the local
        # orphaned row). Deterministic: every honest node derives the same
        # verdict from the same ancestor state.
        if _prior_att:
            _pb = int(_prior_att.get("last_block", -1))
            if _pb >= block.get('id', 0):
                # ATTEST-CAP-STRICT: the local row sits at/after this height
                # (written by a competing chain), so along-chain history for
                # the claim cannot be validated here — reject rather than skip.
                # (Reorg adoption supplies ancestor rows via _att_base (P6);
                # this strict path now fires only for genuinely unverifiable
                # claims — watch S5 in soak.)
                logger.warning(f"[Verify] Block {block['id']} growth cap unverifiable (local attestation at {_pb} on competing chain) — rejected (ATTEST-CAP-STRICT)")
                return False
            else:
                _cap = int(_prior_att.get("last_size", MIN_MAZE_SIZE)) + _config.ATTEST_GROWTH_PER_BLOCK * (int(block.get('id', 0)) - _pb)
                if att_size > _cap:
                    logger.warning(f"[Verify] Block {block['id']} attestation growth cap exceeded: {att_size} > {_cap} (IDEA5-ATTEST)")
                    return False
        else:
            _cap = MIN_MAZE_SIZE + _config.ATTEST_FRESH_BUFFER
            if att_size > _cap:
                logger.warning(f"[Verify] Block {block['id']} first attestation exceeds cap: {att_size} > {_cap} (ATTEST-FRESH-BUFFER-1)")
                return False
        if att_size <= MIN_MAZE_SIZE:
            logger.warning(f"[Verify] Block {block['id']} attestation size {att_size} not eligible (must be > {MIN_MAZE_SIZE})")
            return False
        # WORK-PROOF-1 (mainnet audit): growth beyond the fresh-claim cap
        # must be backed by a proven catch — either a maze_updates entry in
        # THIS block with new_size == att_size (its walk-proof is verified
        # below; an invalid update rejects the block there), or a proven
        # size in agreed chain history. Bare self-claims previously
        # compounded weight/lottery advantage at +5/block with no verified
        # work (see F1). No-change claims (== proven/fresh) pass freely.
        # Protocol break: unattested-growth seals no longer verify (see
        # migration note).
        if att_size > MIN_MAZE_SIZE + _config.ATTEST_FRESH_BUFFER:
            _proven = await self._proven_update_size(att_mid, block.get('id', 0))
            # Claiming at most the proven size is always fine (under-claims
            # only weaken the claimant); growth beyond it needs a proven
            # catch in THIS block (its walk-proof is verified below).
            if _proven is None or att_size > _proven:
                _here = False
                for _u in (block.get("maze_updates") or []):
                    if not isinstance(_u, dict):
                        continue
                    _um = str(_u.get("maze_id") or _u.get("miner_id") or "")
                    if _um == att_mid and _valid_maze_size(_u.get("new_size")) == att_size:
                        _here = True
                        break
                if not _here:
                    logger.warning(f"[Verify] Block {block['id']} attestation size {att_size} not backed by a proven catch")
                    return False
        # LOTTERY-SCALE-1: ticket = int(keccak(prev_hash || height || maze_id))
        try:
            _ticket = _maze_ticket(block.get('phash', ''), int(block.get('id', 0)), att_mid)
        except Exception as e:
            logger.warning(f"[Verify] Block {block['id']} ticket computation failed: {e}")
            return False
        if _ticket >= _maze_threshold(att_size):
            logger.warning(f"[Verify] Block {block['id']} LOTTERY FAIL: ticket >= threshold for size {att_size} (IDEA5-ATTEST)")
            return False
        # SHRINK-BOUND-1 (mainnet audit): the sealed shrink factor is
        # adopted verbatim by followers (it derives from local rows, so no
        # recomputation is possible). Bound it: finite within [1.0, 64.0].
        # An unbounded/inf factor previously drove _apply_shrink on every
        # follower. Residual: small lies affect only local-row decay, which
        # is not consensus state (chain-agreed sizes govern lottery/weight).
        try:
            _gsf = float(block.get("global_shrink_factor", 1.0))
        except (TypeError, ValueError):
            logger.warning(f"[Verify] Block {block['id']} bad global_shrink_factor")
            return False
        if not math.isfinite(_gsf) or not (1.0 <= _gsf <= 64.0):
            logger.warning(f"[Verify] Block {block['id']} global_shrink_factor out of bounds")
            return False

        # ─── Equivocation detection: check signed_blocks table ───
        winner_miner = block.get('winner') or (block.get('miners') or [None])[0]
        block_hash = block.get('hash', '')
        if winner_miner and block_hash:
            if self.db.db_type == "sqlite":
                existing = await self.db.fetchrow(
                    "SELECT block_hash FROM signed_blocks WHERE miner_id = ? AND block_id = ?",
                    winner_miner, block.get('id', 0))
            else:
                existing = await self.db.fetchrow(
                    "SELECT block_hash FROM signed_blocks WHERE miner_id = $1 AND block_id = $2",
                    winner_miner, block.get('id', 0))
            if existing and existing.get('block_hash') != block_hash:
                logger.error(f"[Verify] EQUIVOCATION: Miner {winner_miner[:16]} signed two different blocks at height {block.get('id')}: {existing.get('block_hash')[:16]} vs {block_hash[:16]}")
                return False

        # Verify block producer is the winning miner's block_signing_pub
        if winner:
            winner_miner = await self.miner_repo.get(winner)
            if winner_miner and winner_miner.get('pub'):
                verify_key = winner_miner.get('block_signing_pub') or winner_miner.get('pub')
                if producer_pub != verify_key:
                    logger.warning(f"[Verify] Block {block['id']} producer_pub does not match winner's block_signing_pub")
                    return False
            else:
                # LOTTERY-1 REVERTED (design review): strict local validation of
                # declared entries rejected every cross-node block, because
                # non-winning miners' minermazes rows are NOT chain-replicated
                # (only winners' maze_updates ride in blocks; there is no P2P
                # move relay). Restored the lenient path:
                # Foreign miner not yet in local DB: verify producer_pub
                # matches lottery winner or block winner.
                valid_producers = {str(k).lower() for k in [winner, att_pub, att_mid] if k}
                if str(producer_pub).lower() not in valid_producers:
                    logger.warning(f"[Verify] Block {block['id']} producer_pub does not match attestation key or winner")
                    return False

        # ─── INCREMENTAL: only verify the final state per miner from maze_updates ───
        maze_updates = block.get("maze_updates", [])
        # IDEA5-ATTEST: the lottery-proof snapshot (replayed_sizes) is gone —
        # maze size claims are validated by the maze_attestation checks above.

        # Deduplicate: keep only the last update per miner (incremental verification)
        last_update_by_miner: Dict[str, Dict] = {}
        for update in maze_updates:
            mid = update.get("miner_id")
            if mid:
                last_update_by_miner[mid] = update

        # Validate each maze_update's proof (root, parent walk, provenance).
        # MAZE-UPDATES-UX-1: updates no longer feed the lottery (size claims
        # come from maze_attestation); they stay in blocks for ghost/maze
        # display sync and are still provenance-checked here.
        for mid, update in last_update_by_miner.items():
            new_size = update.get("new_size")
            if new_size is None:
                continue

            seed = update.get("seed", "")
            new_density = update.get("new_density", 0)
            new_turbulence = update.get("turbulenceppm", 0)
            # MAZE-MIN-1: reject malformed/undersized dimensions BEFORE
            # generating anything — never clamp-and-continue a sealed claim.
            _new_size = _valid_maze_size(new_size)
            if _new_size is None:
                logger.warning(f"[Verify] Block {block['id']} maze update with invalid size {new_size!r} for {mid[:16]} — rejected")
                return False
            new_size = _new_size
            if seed and new_size > 0:
                try:
                    loop = asyncio.get_event_loop()
                    test_maze = await loop.run_in_executor(
                        self.consensus._move_executor,
                        self.consensus._generate_deterministic_maze,
                        seed, new_size, new_density, new_turbulence, self.height)
                    expected_root = self.consensus._calculate_maze_root(test_maze)
                    claimed_root = update.get("mazeroot", "")
                    if claimed_root and expected_root != claimed_root:
                        logger.warning(f"[Verify] Block {block['id']} maze root mismatch for {mid[:16]}")
                        return False
                except Exception as e:
                    logger.warning(f"[Verify] Block {block['id']} maze replay failed for {mid[:16]}: {e}")
                    return False

            caught_at_nonce = update.get("caught_at_nonce")
            if caught_at_nonce is not None:
                parent_seed = update.get("parent_seed", "")
                parent_size = update.get("parent_size", 0)
                parent_density = update.get("parent_density", 0)
                parent_turbulence = update.get("parent_turbulence", 0)
                parent_mazeroot = update.get("parent_mazeroot", "")
                parent_pos = update.get("parent_pos", [])
                parent_goal = update.get("parent_goal", [])
                caught_by_dir = update.get("caught_by_direction", "")
                parent_pos_attested = update.get("parent_pos_attested")
                parent_movenonce_claimed = update.get("parent_movenonce")

                if not all([parent_seed, parent_size > 0, caught_by_dir, len(parent_pos) == 3, len(parent_goal) == 3]):
                    logger.warning(f"[Verify] Block {block['id']} maze growth missing provenance fields for {mid[:16]}")
                    return False
                # MAZE-MIN-1: the parent dimension obeys the invariant too.
                _parent_size = _valid_maze_size(parent_size)
                if _parent_size is None:
                    logger.warning(f"[Verify] Block {block['id']} maze growth with invalid parent size {parent_size!r} for {mid[:16]} — rejected")
                    return False
                parent_size = _parent_size

                if caught_by_dir not in self.consensus.DIRS:
                    logger.warning(f"[Verify] Block {block['id']} maze growth invalid direction '{caught_by_dir}' for {mid[:16]}")
                    return False

                if new_size != parent_size + 1:
                    logger.warning(f"[Verify] Block {block['id']} maze growth size jump {parent_size} -> {new_size} != +1 for {mid[:16]}")
                    return False

                try:
                    loop = asyncio.get_event_loop()
                    parent_maze = await loop.run_in_executor(
                        self.consensus._move_executor,
                        self.consensus._generate_deterministic_maze,
                        parent_seed, parent_size, parent_density, parent_turbulence, self.height)
                    actual_parent_root = self.consensus._calculate_maze_root(parent_maze)
                    if parent_mazeroot and actual_parent_root != parent_mazeroot:
                        logger.warning(f"[Verify] Block {block['id']} parent maze root mismatch for {mid[:16]}")
                        return False
                    px, py, pz = parent_pos
                    if not (0 <= px < parent_size and 0 <= py < parent_size and 0 <= pz < parent_size):
                        logger.warning(f"[Verify] Block {block['id']} parent_pos out of bounds for {mid[:16]}")
                        return False
                    dx, dy, dz = self.consensus.DIRS[caught_by_dir]
                    dest_x, dest_y, dest_z = px + dx, py + dy, pz + dz
                    gx, gy, gz = parent_goal
                    if (dest_x, dest_y, dest_z) != (gx, gy, gz):
                        logger.warning(f"[Verify] Block {block['id']} goal mismatch for {mid[:16]}: step to ({dest_x},{dest_y},{dest_z}) != goal ({gx},{gy},{gz})")
                        return False
                    # B2 (MCX73): during reorg pre-verify the local row is
                    # orphaned-tip state — judge provenance against the
                    # agreed-ancestor base the caller supplied, falling back
                    # to the local row only for mazes with no agreed history
                    # (same rule as the attestation base above).
                    if isinstance(_maze_base, dict) and mid in _maze_base:
                        db_row = _maze_base[mid]
                    else:
                        db_row = await self.maze_repo.get_by_maze_id(mid)
                    if db_row:
                        db_pos = [int(db_row["posx"]), int(db_row["posy"]), int(db_row["posz"])]
                        if parent_pos_attested is not None and parent_pos_attested != db_pos:
                            logger.warning(f"[Verify] Block {block['id']} parent_pos_attested mismatch for {mid[:16]}: block says {parent_pos_attested}, DB has {db_pos}")
                            return False
                        if parent_movenonce_claimed is not None and parent_movenonce_claimed != int(db_row["movenonce"]):
                            logger.warning(f"[Verify] Block {block['id']} parent_movenonce mismatch for {mid[:16]}: block says {parent_movenonce_claimed}, DB has {db_row['movenonce']}")
                            return False
                    else:
                        logger.info(f"[Verify] Block {block['id']}: no local maze row for {mid[:16]}, walk proof skipped (bootstrap)")
                except Exception as e:
                    logger.warning(f"[Verify] Block {block['id']} maze growth provenance check failed for {mid[:16]}: {e}")
                    return False

        # ─── Verify merkle_root ─── (lottery re-run replaced by the
        # IDEA5-ATTEST threshold check above)
        # R9-txbind (I-R8-08): enforced unconditionally (the sys.maxsize
        # activation gate never fired — a deferred commitment is not
        # enforcement). Producers seal compute_merkle_root(tx_hashes), so
        # honest blocks agree; only forged roots reject. Chain reset:
        # acceptance change; see R9_MIGRATION_NOTES.md.
        block_id_val = block.get("id", 0)
        expected_merkle = compute_merkle_root(block.get("tx_hashes", []))
        if block.get("merkle_root", "") != expected_merkle:
            logger.warning(f"[Verify] Block {block_id_val} merkle_root mismatch")
            return False

        # ─── Validate transactions: verify signatures, nonces, and shadow re-execution ───
        tx_hashes = block.get("tx_hashes", [])
        tx_list = block.get("transactions", [])
        # R5-txhash-transactions-coupling: presence must agree unconditionally.
        if bool(tx_list) != bool(tx_hashes):
            logger.warning(f"[Verify] Block {block['id']} transactions/tx_hashes presence mismatch")
            return False
        if tx_hashes:
            tx_count = block.get("tx_count", 0)
            if tx_count != len(tx_hashes):
                logger.warning(f"[Verify] Block {block['id']} tx_count mismatch: {tx_count} vs {len(tx_hashes)}")
                return False
            # MERKLE-1c: a block must not include the same tx_hash twice
            # (duplicate txids break the tx_hashes <-> transactions pairing
            # and are a classic merkle-malleability vector).
            if len(set(tx_hashes)) != len(tx_hashes):
                logger.warning(f"[Verify] Block {block['id']} has duplicate tx_hash entries")
                return False
            # BLOCK-GAS-1: consensus work ceiling, before any signature
            # verification or VM re-execution is spent on this block.
            _lok, _lreason = _block_limits_ok(tx_list)
            if not _lok:
                logger.warning(f"[Verify] Block {block['id']} exceeds block limits: {_lreason} (BLOCK-GAS-1)")
                return False
            # R9-txbind (I-R8-08): ordered correspondence between the
            # committed list and the executed envelopes.
            _tok, _treason = _tx_lists_consistent(tx_hashes, tx_list)
            if not _tok:
                logger.warning(f"[Verify] Block {block['id']} tx_hashes/envelopes mismatch: {_treason}")
                return False
            seen_nonces: Dict[str, int] = {}
            if isinstance(_branch, dict):
                # R9-branch-replay (I-R8-09): nonce continuity across the
                # suffix (a spend in block N+1 follows block N's nonce).
                seen_nonces = _branch.setdefault("nonces", {})
            for tx_data in tx_list:
                tx_hash = tx_data.get("tx_hash")
                if not tx_hash:
                    logger.warning(f"[Verify] Block {block['id']} transaction missing tx_hash")
                    return False
                val = int(tx_data.get('value', 0))
                fee = int(tx_data.get('fee', 0))
                if val < 0 or fee < 0:
                    logger.warning(f"[Verify] Block {block['id']} tx {tx_hash[:16]} negative value or fee")
                    return False
                if not self._verify_tx_signature(tx_data):
                    logger.warning(f"[Verify] Block {block['id']} tx {tx_hash[:16]} has invalid signature")
                    return False
                # TXHASH-ENFORCE-1 (mainnet audit): recompute the envelope
                # hash instead of trusting it. A producer could otherwise
                # seal mutated fields under a stale-but-listed hash: merkle
                # commits the listed hashes, ordering checks pair them, and
                # the signature (over unsigned fields) still passed. Same
                # acceptance variants as mempool admission (exact, 0x-form,
                # lowercase). Protocol break: envelopes with unbound hashes
                # no longer verify (see migration note).
                _body = {k: v for k, v in tx_data.items() if k != 'tx_hash'}
                _clean = tx_hash.removeprefix("0x").lower()
                if not (hash_tx(_body) == tx_hash or hash_tx(tx_data) == tx_hash
                        or hash_tx(_body) == _clean or hash_tx(tx_data) == _clean):
                    logger.warning(f"[Verify] Block {block['id']} tx {tx_hash[:16]} hash does not match envelope")
                    return False
                from_w = tx_data.get("from_wallet", "")
                if from_w:
                    expected = seen_nonces.get(from_w, await self._get_confirmed_nonce(from_w))
                    if tx_data.get("nonce", -1) != expected:
                        # Fork tolerance: verify runs BEFORE the reorg decision,
                        # so our own same-height fork may already hold this exact
                        # tx (same tx_hash) as confirmed — the nonce then reads
                        # ahead of the block's copy. Reject only if the tx is
                        # unknown or a DIFFERENT tx claims the same nonce.
                        existing_tx = await self.tx_repo.get_by_hash(tx_hash)
                        if existing_tx and int(existing_tx.get('block_id', -1)) >= 0:
                            seen_nonces[from_w] = max(
                                expected, int(tx_data.get("nonce", 0)) + 1)
                        else:
                            logger.warning(f"[Verify] Block {block['id']} tx {tx_hash[:16]} nonce mismatch: "
                                          f"expected {expected}, got {tx_data.get('nonce')}")
                            return False
                    else:
                        seen_nonces[from_w] = expected + 1
            if not await self._replay_transactions(tx_list, block.get("id"), block_ts=block.get("ts"),
                                                       _branch_state=(_branch.setdefault("maps", {}) if isinstance(_branch, dict) else None)):
                logger.warning(f"[Verify] Block {block['id']} transaction re-execution failed")
                return False
            # Spatial Tokens V2 (T9): sealed fee amount must equal the sum
            # of per-tx maze cuts — producer cannot inflate or starve.
            if not _spatial_fee_amount_ok(block):
                logger.warning(f"[Verify] Block {block['id']} spatial_fee_amount mismatch")
                return False

        # ─── Verify reward/subsidy/supply (R9-reward-supply, I-R8-02) ───
        # Recompute the only acceptable reward from the sealed envelopes
        # and canonical minted supply BEFORE any state use. A mismatch
        # (false fees, wrong subsidy, cap overflow) rejects the block here
        # instead of crediting first and skipping the mint later.
        if block.get('id', 0) > 0:
            if _validated_block_reward(block, self.total_minted) is None:
                logger.warning(f"[Verify] Block {block['id']} reward/subsidy/supply mismatch")
                return False

        # ─── Verify state_root (B5: enforced winner-balance commitment) ───
        # (lottery_proof totalweight cross-check removed with IDEA5-ATTEST)
        claimed_root = block.get("state_root", "")
        # R9-reward-supply (I-R8-02): sealed roots are mandatory
        # (non-genesis). An empty root skips both the commitment AND the
        # indirect reward cross-check the probe below performs.
        if block.get('id', 0) > 0 and not claimed_root:
            logger.warning(f"[Verify] Block {block['id']} missing state_root")
            return False
        if claimed_root:
            # State-root check only when our tip is this block's parent —
            # on a fork the pre-state is ambiguous and we defer to reorg.
            parent_hash_ok = (block.get('id', 0) == 0) or (block.get('phash') == self.last_hash)
            if not parent_hash_ok:
                logger.debug(f"[Verify] Block {block['id']} state_root check skipped (fork)")
            else:
                try:
                    probe = StateTrie(self.db)
                    await probe.put("height", block["id"])
                    reward = int(block.get("reward", 0))
                    wallet = block.get("reward_wallet") or ""
                    if wallet and reward > 0:
                        pre_bal = await self.balance_repo.get(wallet)
                        await probe.put(f"balance:{wallet}", (pre_bal or 0) + reward)
                    expected_root = await probe.commit()
                    if claimed_root != expected_root:
                        logger.warning(
                            f"[Verify] Block {block['id']} state_root mismatch: "
                            f"claimed={claimed_root[:16]} expected={expected_root[:16]}")
                        return False
                except Exception as e:
                    logger.warning(f"[Verify] Block {block['id']} state_root check failed: {e}")
                    return False

        return True

    # ─── Wallet Case Normalization ──────────────────────────────────────────
    async def _normalize_wallet_case(self):
        try:
            if self.db.db_type == "sqlite":
                rows = await self.db.fetch("SELECT wallet, bal FROM balances WHERE wallet != LOWER(wallet)")
            else:
                rows = await self.db.fetch("SELECT wallet, bal FROM balances WHERE wallet != LOWER(wallet)")
            if not rows:
                return
            count = 0
            for r in rows:
                low = r['wallet'].lower()
                if self.db.db_type == "sqlite":
                    existing = await self.db.fetchrow("SELECT bal FROM balances WHERE wallet = ?", low)
                    new_bal = (existing['bal'] if existing else 0) + r['bal']
                    await self.db.execute_dml("INSERT OR REPLACE INTO balances (wallet, bal) VALUES (?,?)", low, new_bal)
                    await self.db.execute_dml("DELETE FROM balances WHERE wallet = ?", r['wallet'])
                else:
                    await self.db.execute_dml("INSERT INTO balances (wallet, bal, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (wallet) DO UPDATE SET bal = balances.bal + $2, updated_at = NOW()", low, r['bal'])
                    await self.db.execute_dml("DELETE FROM balances WHERE wallet = $1", r['wallet'])
                count += 1
            if count:
                logger.info(f"[DB] Normalized {count} wallet address entries to lowercase")
        except Exception as e:
            logger.debug(f"[DB] Wallet case normalization skipped: {e}")

    # ─── Balance Queries ──────────────────────────────────────────────────
    async def get_balance(self, wallet: str) -> int:
        return await self.balance_repo.get(wallet)

    async def get_token_balance(self, token: str, wallet: str) -> int:
        return await self.token_balance_repo.get(token, wallet)

    # ─── Miner Registration ────────────────────────────────────────────────
    async def register_miner(self, miner_id: str, wallet: str, pub_key: str,
                             signature: str, timestamp: int, block_signing_pub: str = None,
                             takeover_sig: str = None) -> bool:
        try:
            if abs(int(time.time()) - int(timestamp)) > 120:
                return False
        except (TypeError, ValueError):
            return False
        expected_wallet = pubkey_to_address(pub_key)
        if wallet.lower() != expected_wallet.lower():
            logger.warning(f"[MINER] Wallet mismatch for {miner_id[:16]}: got {wallet}, expected {expected_wallet}")
            return False
        # Validate block_signing_pub is a valid secp256k1 uncompressed public key
        if block_signing_pub:
            try:
                pk_bytes = bytes.fromhex(block_signing_pub)
                if len(pk_bytes) != 65 or pk_bytes[0] != 0x04:
                    logger.warning(f"[MINER] Invalid block_signing_pub format from {miner_id[:16]}: len={len(pk_bytes)} prefix={pk_bytes[0] if pk_bytes else 'empty'}")
                    return False
            except Exception as e:
                logger.warning(f"[MINER] Invalid block_signing_pub from {miner_id[:16]}: {e}")
                return False
        existing = await self.miner_repo.get(miner_id)
        if existing:
            if existing.get('pub') != pub_key:
                if not takeover_sig:
                    logger.warning(f"[MINER] Pub key change rejected for {miner_id[:16]}: missing takeover_sig")
                    return False
                takeover_msg = f"MCXTAKEOVER|{miner_id}|{pub_key}|{timestamp}"
                if not verify_signature(existing['pub'], takeover_msg, takeover_sig):
                    logger.warning(f"[MINER] Pub key change rejected for {miner_id[:16]}: takeover_sig not signed by original key")
                    return False
                message = f"{miner_id}{wallet}{timestamp}"
                if not verify_signature(pub_key, message, signature):
                    logger.warning(f"[MINER] Pub key change rejected for {miner_id[:16]}: new key signature invalid")
                    return False
                logger.info(f"[MINER] Pub key updated for {miner_id[:16]}: authorized by original key")
                existing['pub'] = pub_key
                existing['wallet'] = wallet
                if block_signing_pub:
                    existing['block_signing_pub'] = block_signing_pub
            else:
                message = f"{miner_id}{wallet}{timestamp}"
                if not verify_signature(pub_key, message, signature):
                    logger.warning(f"[MINER] Re-registration signature invalid for {miner_id[:16]}")
                    return False
            now = time.time()
            if existing.get('banned_until', 0) > now:
                logger.info(f"[MINER] Re-registration rejected for {miner_id[:16]}: still banned for {existing['banned_until'] - now:.0f}s")
                return False
            existing['active'] = True
            existing['last_ping'] = now
            await self.miner_repo.update(existing)
            logger.info(f"[MINER] Reactivated existing miner {miner_id[:16]}")
            return True
        message = f"{miner_id}{wallet}{timestamp}"
        if not verify_signature(pub_key, message, signature):
            logger.warning(f"[MINER] First-time registration signature invalid for {miner_id[:16]}")
            return False
        _expected = "PC_" + hashlib.sha256(
            f"{pubkey_to_address(pub_key)}_mcx_miner".encode()
        ).hexdigest()[:32].upper()
        # R5-register-pc-derivation: enforce PC_ derivation at register, not only at verify.
        if not (miner_id == _expected or miner_id.startswith(_expected + "_")):
            logger.warning(f"[MINER] Register rejected: miner_id does not derive from pub_key")
            return False
        miner = {
            'miner_id': miner_id,
            'wallet': wallet,
            'pub': pub_key,
            'block_signing_pub': block_signing_pub or pub_key,
            'rewards': 0,
            'blocks': 0,
            'slashes': 0,
            'uptime': 0,
            'today_uptime': 0,
            'type': 'web',
            'liquidity': 0,
            'fees': 0,
            'last_ping': time.time(),
            'banned_until': 0,
            'created_at': time.time(),
            'last_block': 0,
            'consecutive_misses': 0,
            'total_uptime': 0,
            'ip_address': '',
            'node_id': self.node_id,
            'version': VERSION,
            'active': True,
            'confirmed_balance': 0,
            'password_hash': '',
            'private_key_encrypted': '',
            'gas_collected': 0,
            'maze_wins': 0
        }
        await self.miner_repo.create(miner)
        self.miners[miner_id] = miner
        logger.info(f"[MINER] New miner registered: {miner_id[:16]} (wallet: {wallet[:16]})")
        return True

    # ─── Slashing ──────────────────────────────────────────────────────────
    async def slash_miner(self, miner_id: str, reason: str):
        miner = await self.miner_repo.get(miner_id)
        if not miner:
            return
        miner['slashes'] += 1
        miner['consecutive_misses'] += 1
        rewards = int(miner.get('rewards', 0))
        slash_amount = rewards // 10
        wallet = miner.get('wallet')
        if wallet and slash_amount > 0:
            await self.balance_repo.subtract(wallet, slash_amount)
        if miner['slashes'] >= BAN_THRESHOLD:
            miner['active'] = False
            miner['banned_until'] = time.time() + _config.BAN_DURATION
        await self.miner_repo.update(miner)
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT INTO slashing_events (miner_id, amount, reason, block_id, timestamp) VALUES (?, ?, ?, ?, ?)", miner_id, slash_amount, reason, -1, time.time())
        else:
            await self.db.execute_dml("INSERT INTO slashing_events (miner_id, amount, reason, block_id, timestamp) VALUES ($1, $2, $3, $4, NOW())", miner_id, slash_amount, reason, -1)
        logger.warning(f"[Slash] Miner {miner_id[:16]} slashed: {reason} (amount={slash_amount})")

    async def get_token_temporal_config(self, token_address: str) -> dict:
        raw = await self.contract_state_repo.get(token_address, "temporal_config")
        if raw:
            try: return json.loads(raw)
            except Exception: pass
        return {}

    # ─── Token Creation ────────────────────────────────────────────────────
    # R4-dead-code-remove: create_token deleted (REST-era helper, zero
    # callers; the tx path is execute_transaction's token_create branch).
    # NOTE: this also retires the fifth hashlib.sha3_256 token-address site
    # (it used time.time(), which could never agree across nodes).

    async def get_blocks_range(self, start: int, end: int) -> List[Dict]:
        cached = {b['id']: b for b in self.blocks if start <= b['id'] <= end}
        missing = [i for i in range(start, end + 1) if i not in cached]
        if missing and self.block_repo:
            try:
                db_blocks = await self.block_repo.get_range(start, end, limit=max(10, end - start + 1))
                for b in db_blocks:
                    cached[b['id']] = b
            except Exception as e:
                logger.warning(f"[BlockRepo] get_range error: {e}")
        return [cached[i] for i in sorted(cached.keys())]

    async def import_blocks(self, blocks_data: List[Dict]):
        sorted_blocks = sorted(blocks_data, key=lambda x: x['id'])
        for b in sorted_blocks:
            # Exact-duplicate check BEFORE expensive verification: rewind/
            # catch-up batches re-send blocks we already hold, and verifying
            # the whole known prefix first can outlast the sync progress
            # window, hiding the fork point deeper in the batch.
            existing = await self.block_repo.get_by_id(b['id'])
            if existing and existing.get('hash') == b.get('hash'):
                continue  # already have this exact block; stale duplicate reply

            # If we're stuck below this block's height (tip < b['id'] - 1), we cannot
            # possibly have its parent. Skip silently once, don't log per-block.
            if b['id'] > self.height:
                logger.debug(f"[IMPORT] Block {b['id']} above local tip {self.height} with unknown parent; skipping batch")
                break

            bid = b['id']
            phash = b.get('phash', '')

            if bid == self.height and phash == self.last_hash:
                # Clean-append path ONLY is verified here. Fork-suspect
                # blocks must NOT be verified against local tip state (A3):
                # ATTEST-CAP-STRICT would reject them against orphaned-tip
                # rows and they would die at `continue` without ever reaching
                # _reorg_chain's _att_base-aware pre-verify. The fork branch
                # below routes straight to weights + _reorg_chain (which
                # pre-verifies every adopted block before mutating state).
                if not await self.verify_block_proof(b):
                    logger.warning(f"[IMPORT] Block {b['id']} failed verification")
                    if not self._proof_field_hint_shown:
                        self._proof_field_hint_shown = True
                        logger.warning(
                            "[Verify] One or more blocks rejected for missing proof fields. "
                            "If you are syncing from a node running a different MCX version, "
                            "or your microcore.db predates the current proof schema, delete "
                            "microcore.db and restart. Your wallet (config.yaml) is unaffected."
                        )
                    continue
                await self._append_block(b)
                continue

            if bid > 0 and phash != self.last_hash:
                our_block = await self.block_repo.get_by_id(bid - 1)
                if our_block and our_block.get('hash') == phash:
                    common_height = bid - 1
                else:
                    common_height = -1
                    for ch in range(bid - 1, max(-1, bid - 100), -1):
                        chk = await self.block_repo.get_by_id(ch)
                        if chk and chk.get('hash') == phash:
                            common_height = ch
                            break
                if common_height < 0:
                    logger.debug(f"[IMPORT] Fork at {bid} with unknown parent; skipping")
                    continue

                our_blocks = await self.block_repo.get_range(common_height + 1, self.height, limit=500)
                our_chain_weight = sum(_block_att_weight(ob) for ob in our_blocks)  # IDEA5-CHAINWEIGHT-1
                their_blocks = [blk for blk in sorted_blocks if blk.get('id', 0) > common_height]
                their_chain_weight = sum(_block_att_weight(tb) for tb in their_blocks)  # IDEA5-CHAINWEIGHT-1

                if their_chain_weight > our_chain_weight:
                    logger.warning(f"[REORG] Reorganizing at height {common_height}: their weight {their_chain_weight} > our {our_chain_weight}")
                    await self._reorg_chain(common_height, their_blocks)
                    break
                elif their_chain_weight == our_chain_weight:
                    # R4-fork-tie-hashbreak: larger tip hash wins (Bitcoin
                    # shape) — deterministic across nodes, unlike first-seen.
                    _our_tip = (our_blocks[-1].get("hash", "") if our_blocks else self.last_hash) or ""
                    _their_tip = (their_blocks[-1].get("hash", "") if their_blocks else "") or ""
                    if _fork_tiebreak_winner(_our_tip, _their_tip):
                        logger.warning(f"[REORG] Tie broken by hash at {bid}: adopting their tip {_their_tip[:16]} over {_our_tip[:16]}")
                        await self._reorg_chain(common_height, their_blocks)
                        break
                    logger.debug(f"[IMPORT] Fork at {bid} tied on weight ({our_chain_weight} == {their_chain_weight}); keeping local tip on hash tiebreak")
                    continue
                else:
                    logger.debug(f"[IMPORT] Fork at {bid}: our chain heavier ({our_chain_weight} > {their_chain_weight})")
                    continue

    async def receive_block(self, block_data: Dict) -> str:
        # Returns "ok" (proof-valid — callers may relay), "disconnected"
        # (proof-valid but its parent variant is absent from our tip — the
        # caller should immediately fetch the sender's tail), or "rejected"
        # (never relay). FORK-RELAY-1/FORK-PARENT-1 live in the caller.
        # R5-receive-block-fork-passthrough: gossip fork blocks go to _reorg_chain; strict cap-verify happens there with _att_base.
        _is_clean_append = (isinstance(block_data, dict)
                            and block_data.get('id') == self.height
                            and block_data.get('phash') == self.last_hash)
        if _is_clean_append:
            if not await self.verify_block_proof(block_data):
                logger.warning(f"[Block] Rejected block {block_data.get('id')} – invalid proof")
                return "rejected"
        else:
            # Cheap structural checks only; full verify happens in _reorg_chain.
            if not isinstance(block_data, dict) or "hash" not in block_data or "id" not in block_data:
                return "rejected"
            # Hash + signature still run unconditionally (no attestation state needed).
            try:
                _unsigned = {k: v for k, v in block_data.items() if k not in CONSENSUS_EXCLUDED_FIELDS}
                if block_data.get("hash") != hash_block(_unsigned):
                    return "rejected"
                _pp = block_data.get("producer_pub", "")
                if not _pp or not verify_signature(_pp, bytes.fromhex(block_data.get("hash", "")), block_data.get("signature", "")):
                    return "rejected"
            except Exception:
                return "rejected"

        # Update global shrink factor from blockchain state
        await self.consensus._update_global_shrink_factor()
        bid = block_data['id']
        phash = block_data.get('phash', '')

        # R8-fork-suffix (R7-09): a below-tip singleton has an unknown remote
        # suffix — adopting [block_data] alone strands the node mid-branch
        # (a heavier single block vs our cumulative suffix, then nothing
        # above it). Fetch the sender's tail first (FORK-PARENT-1 in the
        # caller); the complete batch adopts via import_blocks, which
        # compares full suffixes under one rule. Tip ties (bid == height)
        # keep the weight/tiebreak path below — their suffix is complete
        # by construction.
        if bid < self.height:
            logger.debug(f"[Block] Below-tip fork singleton {bid} (tip {self.height}); fetching sender tail")
            return "disconnected"

        if bid == self.height and phash == self.last_hash:
            await self._append_block(block_data)
            logger.info(f"[Block] Received and accepted block {bid}")
            return "ok"

        if bid > 0 and phash != self.last_hash:
            our_block = await self.block_repo.get_by_id(bid - 1)
            if our_block and our_block.get('hash') == phash:
                common_height = bid - 1
                our_blocks = await self.block_repo.get_range(common_height + 1, self.height, limit=500)
                our_chain_weight = sum(_block_att_weight(ob) for ob in our_blocks)  # IDEA5-CHAINWEIGHT-1
                their_chain_weight = _block_att_weight(block_data)  # IDEA5-CHAINWEIGHT-1

                if their_chain_weight > our_chain_weight:
                    logger.warning(f"[REORG] Reorganizing at height {common_height}: their weight {their_chain_weight} > our {our_chain_weight}")
                    # REORG-BOOL-1: adoption failed -> reject, never relay.
                    if not await self._reorg_chain(common_height, [block_data]):
                        return "rejected"
                elif their_chain_weight == our_chain_weight:
                    # R4-fork-tie-hashbreak: larger tip hash wins (see above).
                    _our_tip = (our_blocks[-1].get("hash", "") if our_blocks else self.last_hash) or ""
                    _their_tip = block_data.get("hash", "") or ""
                    if _fork_tiebreak_winner(_our_tip, _their_tip):
                        logger.warning(f"[REORG] Tie broken by hash at {bid}: adopting their tip {_their_tip[:16]} over {_our_tip[:16]}")
                        # REORG-BOOL-1: adoption failed -> reject, never relay.
                        if not await self._reorg_chain(common_height, [block_data]):
                            return "rejected"
                    else:
                        logger.debug(f"[Block] Fork at {bid} tied on weight ({our_chain_weight} == {their_chain_weight}); keeping local tip on hash tiebreak")
                else:
                    logger.debug(f"[Block] Fork at {bid}: our chain heavier ({our_chain_weight} > {their_chain_weight})")
            else:
                logger.debug(f"[Block] Disconnected fork block {bid} (parent {phash[:12]} not at {bid-1}); ignoring")
                return "disconnected"
        return "ok"

    async def _restore_attestations_upto(self, common_height: int, affected: List[str]):
        # IDEA5-ATTEST-REORG-2: re-derive attestation rows that rollback_after
        # deleted. The table is single-row-per-maze (INSERT OR REPLACE), so a
        # maze that attested BOTH before the fork point and again in the
        # orphaned segment had its pre-fork row overwritten — DELETE ... >
        # common_height then dropped its history entirely. Under IDEA5-ELECT
        # that permanently un-elects an honest miner (it can never win again
        # to rewrite its row). Walk the canonical chain newest-first and keep
        # each affected maze's most recent attestation at or below the height.
        remaining = set(affected)
        if not remaining:
            return
        q = ("SELECT id, hash, proof FROM blocks WHERE id <= ? AND proof IS NOT NULL ORDER BY id DESC"
             if self.db.db_type == "sqlite" else
             "SELECT id, hash, proof FROM blocks WHERE id <= $1 AND proof IS NOT NULL ORDER BY id DESC")
        rows = await self.db.fetch(q, common_height)
        for r in rows:
            if not remaining:
                break
            try:
                proof = json.loads(r.get("proof") or "{}")
            except Exception:
                continue
            att = proof.get("maze_attestation")
            if not isinstance(att, dict):
                continue
            mid = str(att.get("maze_id", ""))
            if mid in remaining:
                try:
                    await self.maze_attestation_repo.upsert({
                        "maze_id": mid,
                        "last_size": int(att.get("size", 0)),
                        "last_block": int(r.get("id", 0)),
                        "last_block_hash": str(r.get("hash", "")),
                        "pubkey": str(att.get("pubkey", "")),
                    })
                    remaining.discard(mid)
                except Exception:
                    continue
        if remaining:
            logger.warning(f"[IDEA5-ATTEST-REORG-2] no canonical attestation found for {sorted(remaining)[:4]} at/below {common_height}")

    async def _journal_state_row(self, block_id: int, addr: str, key: str,
                                 old_value, new_value) -> None:
        # BUG 6 (MCX75): journal one contract_state write from a non-VM
        # execute path (token_transfer temporal fields). Same table and
        # absolute semantics as the VM-flush journal (None old = DELETE on
        # revert). block_id < 0 skips (should not happen on mutating paths).
        try:
            if block_id is None or int(block_id) < 0:
                return
        except (TypeError, ValueError):
            return

        def _s(v):
            return None if v is None else str(v)
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES (?,?,?,?,?,?)",
                int(block_id), "contract_state", str(addr), str(key), _s(old_value), _s(new_value))
        else:
            await self.db.execute_dml(
                "INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES ($1,$2,$3,$4,$5,$6)",
                int(block_id), "contract_state", str(addr), str(key), _s(old_value), _s(new_value))

    async def _revert_exec_journal(self, common_height: int, touched_wallets=None,
                                   touched_tokens=None) -> int:
        """B6 (MCX73): undo VM-flush mutations journaled for blocks
        > common_height, newest block first, newest entry first.

        storage       -> absolute restore of the pre-image (None -> DELETE).
        contract_state-> absolute restore, like storage (token_transfer
                          temporal writes: last_tx_* and burned_total).
        balance /
        token_balance -> DELTA revert (add old - new). Absolute restore is
                         wrong here: the journaled pre-image is the value
                         just before the VM ran, which still contains
                         earlier credits that other orphan inverses reverse
                         additively. Deltas commute with those inverses, so
                         the order relative to the per-tx loop no longer
                         matters. Returns the number of entries reverted.
        """
        sqlite = self.db.db_type == "sqlite"
        _bids = await self.db.fetch(
            "SELECT DISTINCT block_id FROM contract_exec_journal WHERE block_id > ? ORDER BY block_id DESC"
            if sqlite else
            "SELECT DISTINCT block_id FROM contract_exec_journal WHERE block_id > $1 ORDER BY block_id DESC",
            int(common_height))
        n = 0
        for _b in (_bids or []):
            _rbid = int(_b["block_id"])
            # Postgres: seq (BIGSERIAL) is true insertion order; ctid is a
            # physical location and is NOT (B6-fix2).
            _jrows = await self.db.fetch(
                "SELECT namespace, addr, key, old_value, new_value FROM contract_exec_journal WHERE block_id = ? ORDER BY rowid DESC"
                if sqlite else
                "SELECT namespace, addr, key, old_value, new_value FROM contract_exec_journal WHERE block_id = $1 ORDER BY seq DESC",
                _rbid)
            for _jr in (_jrows or []):
                _ns, _ad, _ky = _jr["namespace"], _jr["addr"], _jr["key"]
                _ov, _nv = _jr["old_value"], _jr["new_value"]
                if _ns == "storage":
                    if _ov is None:
                        await self.db.execute_dml(
                            "DELETE FROM contract_storage_v2 WHERE contract_address = ? AND key = ?" if sqlite else
                            "DELETE FROM contract_storage_v2 WHERE contract_address = $1 AND key = $2", _ad, _ky)
                    else:
                        await self.contract_storage_v2_repo.set(_ad, _ky, str(_ov))
                elif _ns == "contract_state" and _ky == "burned_total":
                    # B6-fix3 (MCX76 audit): burned_total is ADDITIVE and is
                    # also written by token_burn WITHOUT a journal row, so an
                    # absolute restore overwrote the (arithmetically
                    # reverted) burn with a stale mid-range value. Revert by
                    # delta so it commutes with the token_burn inverse.
                    _cr = await self.contract_state_repo.get(_ad, _ky)
                    try:
                        _cv = int(_cr) if _cr not in (None, "") else 0
                    except (TypeError, ValueError):
                        _cv = 0
                    _res = _cv + (int(_ov) if _ov is not None else 0) - (int(_nv) if _nv is not None else 0)
                    if _res == 0 and _ov is None:
                        await self.db.execute_dml(
                            "DELETE FROM contract_state WHERE contract_address = ? AND key = ?" if sqlite else
                            "DELETE FROM contract_state WHERE contract_address = $1 AND key = $2", _ad, _ky)
                    else:
                        await self.contract_state_repo.set(_ad, _ky, str(max(0, _res)))
                elif _ns == "contract_state":
                    # BUG 6 (MCX75): absolute (last_tx_* timestamps - only
                    # ever written by journaled token_transfers). None old
                    # = key created by the orphaned block -> DELETE.
                    if _ov is None:
                        await self.db.execute_dml(
                            "DELETE FROM contract_state WHERE contract_address = ? AND key = ?" if sqlite else
                            "DELETE FROM contract_state WHERE contract_address = $1 AND key = $2", _ad, _ky)
                    else:
                        await self.contract_state_repo.set(_ad, _ky, str(_ov))
                elif _ns in ("balance", "token_balance"):
                    _delta = (int(_ov) if _ov is not None else 0) - (int(_nv) if _nv is not None else 0)
                    if _delta:
                        if _ns == "balance":
                            await self.balance_repo.add(_ad, _delta)
                            if touched_wallets is not None:
                                touched_wallets.add(str(_ad).lower())
                        else:
                            _cur = await self.token_balance_repo.get(_ad, _ky)
                            await self.token_balance_repo.set(_ad, _ky, int(_cur) + _delta)
                            if touched_tokens is not None:
                                touched_tokens.add((str(_ad), str(_ky)))
                else:
                    raise ValueError(f"unknown journal namespace {_ns}")
                n += 1
            await self.db.execute_dml(
                "DELETE FROM contract_exec_journal WHERE block_id = ?" if sqlite else
                "DELETE FROM contract_exec_journal WHERE block_id = $1", _rbid)
        return n

    async def _reorg_settle_negatives(self, touched_wallets, touched_tokens, shortfalls) -> None:
        """B6-fix3 (MCX76 audit): reorg debits are applied as signed deltas
        (they commute, so order cannot create false shortfalls). Only AFTER
        every inverse and the journal revert has run is a still-negative
        balance a REAL shortfall: record it loudly and clamp to 0."""
        for _w in sorted(touched_wallets or ()):
            _b = int(await self.balance_repo.get(_w) or 0)
            if _b < 0:
                logger.warning(f"[REORG] settle shortfall wallet {str(_w)[:16]} short {-_b}")
                shortfalls.append(("settle:balance", str(_w), -_b, 0))
                await self.balance_repo.set(_w, 0)
        for _t, _w in sorted(touched_tokens or ()):
            _b = int(await self.token_balance_repo.get(_t, _w) or 0)
            if _b < 0:
                logger.warning(f"[REORG] settle token shortfall {str(_t)[:16]}:{str(_w)[:16]} short {-_b}")
                shortfalls.append(("settle:token", "token:" + str(_t)[:16] + ":" + str(_w), -_b, 0))
                await self.token_balance_repo.set(_t, _w, 0)

    async def _invert_block_txs(self, common_height: int, tx_hashes=None, _touched_w=None, _touched_t=None):
        # R5-sign-fail-rollback: invert every tx effect above common_height so a failed produce attempt leaves pre-attempt state.
        if tx_hashes is not None and len(tx_hashes) == 0:
            return []
        if _touched_w is None:
            _touched_w = set()
        if _touched_t is None:
            _touched_t = set()
        _reorg_shortfalls: list = []
        _reorg_deploys: list = []
        _reorg_token_creates: list = []
        _reorg_htlc_ids: list = []
        tx_query = ("SELECT * FROM transactions WHERE block_id > ? ORDER BY block_id DESC, rowid DESC" if self.db.db_type == "sqlite"
                            else "SELECT * FROM transactions WHERE block_id > $1 ORDER BY block_id DESC, timestamp DESC, tx_hash DESC")
        _tx_params: list = [common_height]
        if tx_hashes is not None:
            # R5-sign-fail-rollback: scope to this attempt txs only.
            _hashes = [str(h) for h in tx_hashes]
            if self.db.db_type == "sqlite":
                tx_query += " AND tx_hash IN (%s)" % ",".join("?" * len(_hashes))
                _tx_params += _hashes
            else:
                tx_query += " AND tx_hash IN (%s)" % ",".join("$%d" % n for n in range(2, 2 + len(_hashes)))
                _tx_params += _hashes
        orphaned_txs = await self.db.fetch(tx_query, *_tx_params)
        for tx in orphaned_txs:
            tx_type = tx.get('tx_type', 'send')
            amount = tx.get('amount', 0)
            # H-6 (MCX73): refund what execute actually charged, not
            # the (possibly mutated) stored fee.
            fee = tx.get('_fee_charged', tx.get('fee', 0))
            from_w = tx.get('from_wallet')
            to_w = tx.get('to_wallet')
            if tx_type == 'send' and from_w and to_w:
                total = amount + fee
                await self.balance_repo.add(from_w, total)
                if to_w.lower() in BURN_ADDRESSES:
                    # REORG-1: the forward path destroyed the amount (no credit
                    # to the burn address) — undo the burn, not a transfer.
                    self.burned_total = max(0, self.burned_total - amount)
                    await self.network_state_repo.set("burned_total", str(self.burned_total))
                    logger.info(f"[REORG] Un-burned {amount // SUBS} MCX (send to burn address reverted)")
                else:
                    # B6-fix3 (MCX76 audit): signed delta (see reward debit).
                    await self.balance_repo.add(to_w, -int(amount))
                    _touched_w.add(str(to_w).lower())
            elif tx_type == 'burn' and from_w:
                # REORG-1: native burn inverse — re-credit the destroyed MCX
                # (amount + fee) and reduce burned_total. The old code had no
                # inverse at all for tx_type 'burn'.
                await self.balance_repo.add(from_w, amount + fee)
                self.burned_total = max(0, self.burned_total - amount)
                await self.network_state_repo.set("burned_total", str(self.burned_total))
                logger.info(f"[REORG] Reversed burn of {amount // SUBS} MCX from {from_w[:16]}")
            elif tx_type == 'token_transfer' and from_w and to_w:
                token_addr = tx.get('token_address')
                # BUG 2 (MCX75): forward credits net_amount (amount
                # less burn_tax) and shrinks supply — the old inverse
                # debited the full amount and never restored supply.
                # burn_tax rides in the row's data mirror (preferred);
                # absent (= 0) on pre-mirror rows.
                _btax = 0
                try:
                    _dd = tx.get('data') or {}
                    if isinstance(_dd, str):
                        _dd = json.loads(_dd)
                    if isinstance(_dd, dict):
                        _btax = int(_dd.get('_burn_tax', 0) or 0)
                except Exception:
                    _btax = 0
                if _btax < 0:
                    _btax = 0
                _net = amount - _btax
                if _net < 0:
                    _net = 0
                if token_addr:
                    f_bal = await self.token_balance_repo.get(token_addr, from_w)
                    await self.token_balance_repo.set(token_addr, from_w, f_bal + amount)
                    # B6-fix3 (MCX76 audit): signed delta; clamping here
                    # wrote off balances the later inverses would have
                    # returned. Negatives are settled at the end.
                    t_bal = await self.token_balance_repo.get(token_addr, to_w)
                    await self.token_balance_repo.set(token_addr, to_w, t_bal - _net)
                    _touched_t.add((str(token_addr), str(to_w)))
                    if _btax > 0:
                        tok = await self.token_repo.get(token_addr)
                        if tok:
                            tok['total_supply'] = int(tok.get('total_supply', 0)) + _btax
                            await self.token_repo.upsert(tok)
                        # B6-fix3: burned_total is reverted ONLY by the
                        # journal (delta) - no arithmetic fallback here,
                        # it would double-revert.
                if fee > 0:
                    # FEE-1: refund the MCX fee charged by the forward path
                    await self.balance_repo.add(from_w, fee)
            elif tx_type == 'contract_deploy':
                contract_addr = tx.get('contract_address') or tx.get('to_wallet')
                if fee > 0 and from_w:
                    # B6-fix (MCX73): the forward path charges the fee;
                    # refund it like every other type (the old code
                    # deleted the contract but kept the fee).
                    await self.balance_repo.add(from_w, fee)
                # R5-sign-fail-rollback: reverse the top-level value move (fee-only refund leaked it).
                # R6-value-moved-bind: floor the reversal at the contract balance; never move it negative.
                _vmoved = _moved_value_of(tx)
                if _vmoved > 0 and contract_addr and from_w:
                    _crev = min(_vmoved, max(0, int(await self.balance_repo.get(contract_addr) or 0)))
                    await self.balance_repo.add(contract_addr, -_crev)
                    _touched_w.add(str(contract_addr).lower())
                    await self.balance_repo.add(from_w, _crev)
                    _touched_w.add(str(from_w).lower())
                if contract_addr:
                    # B6-fix3: row deletes are DEFERRED until after the
                    # journal revert, which would otherwise recreate
                    # storage / contract_state rows of a contract that
                    # no longer exists.
                    _reorg_deploys.append(contract_addr)
                    logger.warning(f"[REORG] Reverted contract_deploy for {contract_addr[:16]}")
            elif tx_type == 'contract_call':
                contract_addr = tx.get('to_wallet')
                if fee > 0 and from_w:
                    # Forward path charges the fee only (gas-leak fix) — refund
                    # it on reorg like the token paths do.
                    await self.balance_repo.add(from_w, fee)
                # R5-sign-fail-rollback: reverse the top-level value move (fee-only refund leaked it).
                # R6-value-moved-bind: floor the reversal at the contract balance; never move it negative.
                _vmoved = _moved_value_of(tx)
                if _vmoved > 0 and contract_addr and from_w:
                    _crev = min(_vmoved, max(0, int(await self.balance_repo.get(contract_addr) or 0)))
                    await self.balance_repo.add(contract_addr, -_crev)
                    _touched_w.add(str(contract_addr).lower())
                    await self.balance_repo.add(from_w, _crev)
                    _touched_w.add(str(from_w).lower())
                if contract_addr:
                    logger.info(f"[REORG] contract_call on {contract_addr[:16]} reverted via contract_exec_journal (B6).")
            elif tx_type == 'htlc_create':
                if fee > 0 and from_w:
                    # B6-fix2 (MCX73): forward charges the fee BEFORE the
                    # VM runs (FEE-1); the VM delta is reverted by the
                    # journal, the fee was never refunded.
                    await self.balance_repo.add(from_w, fee)
                tx_id = tx.get('tx_hash')
                if tx_id:
                    if self.db.db_type == "sqlite":
                        await self.db.execute_dml("UPDATE htlc_contracts SET status='reverted' WHERE id = ?", tx_id)
                    else:
                        await self.db.execute_dml("UPDATE htlc_contracts SET status='reverted' WHERE id = $1", tx_id)
                    logger.warning(f"[REORG] Reverted htlc_create {tx_id[:16]}")
                # BUG 7 follow-up (MCX75): collect the htlc_id for
                # post-journal cleanup below. (Deletes here would be
                # wrong: the journal revert hasn't run yet, so the
                # row is still non-zero.)
                try:
                    _hd = tx.get('data') or {}
                    if isinstance(_hd, str):
                        _hd = json.loads(_hd)
                    _hid = (_hd.get('htlc_id') or '') if isinstance(_hd, dict) else ''
                    if _hid:
                        _hid = str(_hid).lower()
                        if _hid not in _reorg_htlc_ids:
                            _reorg_htlc_ids.append(_hid)
                except Exception:
                    pass
            elif tx_type == 'token_burn' and from_w:
                # REORG-1: restore TOKEN state — the old inverse credited the
                # burn amount as MCX (amount is a token amount, not subs!)
                token_addr = tx.get('token_address')
                if token_addr:
                    tb = await self.token_balance_repo.get(token_addr, from_w)
                    await self.token_balance_repo.set(token_addr, from_w, tb + amount)
                    tok = await self.token_repo.get(token_addr)
                    if tok:
                        tok['total_supply'] = int(tok.get('total_supply', 0)) + amount
                        await self.token_repo.upsert(tok)
                    cur_burned = int(await self.contract_state_repo.get(token_addr, "burned_total") or 0)
                    await self.contract_state_repo.set(
                        token_addr, "burned_total", str(max(0, cur_burned - amount)))
                if fee > 0:
                    # MCX fee refund (the forward path charges the fee)
                    await self.balance_repo.add(from_w, fee)
            elif tx_type == 'token_create':
                # BUG 1 (MCX75): forward creates the token row, the
                # initial owner balance, an optional temporal_config
                # row, and deducts the fee — none of which was
                # reverted (no branch existed). Uses _fee_charged
                # (H-6) so the refund matches the deduction.
                _tc_addr = tx.get('token_address') or ''
                if not _tc_addr:
                    try:
                        _rc = await self.receipt_repo.get(tx.get('tx_hash'))
                        _tc_addr = (_rc or {}).get('contract_address') or ''
                    except Exception:
                        _tc_addr = ''
                if not _tc_addr:
                    try:
                        _d = tx.get('data') or {}
                        if isinstance(_d, str):
                            _d = json.loads(_d)
                        _tc_addr = _derive_token_address(tx.get('tx_hash'), from_w, _d.get('name'), _d.get('symbol'))
                    except Exception:
                        _tc_addr = ''
                if fee > 0 and from_w:
                    await self.balance_repo.add(from_w, fee)
                if _tc_addr:
                    _reorg_token_creates.append(_tc_addr)   # B6-fix3: deferred
                    try:
                        self.tokens.pop(_tc_addr, None)
                    except Exception:
                        pass
            elif tx_type in ('spatial_token_create', 'spatial_token_transfer',
                             'spatial_token_burn', 'spatial_asset_create',
                             'spatial_asset_transfer', 'spatial_challenge_create',
                             'spatial_challenge_claim', 'spatial_challenge_cancel'):
                # SPATIAL-POOL-REORG-1 (§7.12): all spatial rollback logic
                # lives in _rollback_spatial_tx — unit-tested directly.
                await self._rollback_spatial_tx(tx, from_w)

        # B6-fix (MCX73): journal revert runs AFTER the per-tx
        # inverses above. B6-fix2 (MCX73): balance / token_balance
        # entries are now reverted by DELTA (old - new), not by an
        # absolute set, so they COMMUTE with the additive per-tx
        # inverses (send/fee/reward). The old absolute restore wrote
        # back a pre-VM value that already included earlier credits
        # (same-block earlier txs, earlier orphaned blocks' rewards)
        # that the additive inverses had just reversed -> inflation.
        # Storage stays absolute (only the VM writes it). Journal
        # block ids come from the journal itself, not from the
        # (limit=1000) orphaned_blocks list. Any failure raises and
        # the P2 rollback aborts as a whole.
        await self._revert_exec_journal(common_height, _touched_w, _touched_t)
        # B6-fix3 (MCX76 audit): deferred deletes - AFTER the journal
        # revert so it cannot resurrect rows of removed contracts/tokens.
        for _ca in _reorg_deploys:
            if self.db.db_type == "sqlite":
                await self.db.execute_dml("DELETE FROM contract_v2 WHERE address = ?", _ca)
                await self.db.execute_dml("DELETE FROM contract_storage_v2 WHERE contract_address = ?", _ca)
                await self.db.execute_dml("DELETE FROM contract_state WHERE contract_address = ?", _ca)
            else:
                await self.db.execute_dml("DELETE FROM contract_v2 WHERE address = $1", _ca)
                await self.db.execute_dml("DELETE FROM contract_storage_v2 WHERE contract_address = $1", _ca)
                await self.db.execute_dml("DELETE FROM contract_state WHERE contract_address = $1", _ca)
        if _reorg_deploys and hasattr(self, 'vm_manager') and self.vm_manager:
            self.vm_manager._code_cache_valid = False
        for _ta in _reorg_token_creates:
            if self.db.db_type == "sqlite":
                await self.db.execute_dml("DELETE FROM tokens WHERE address = ?", _ta)
                await self.db.execute_dml("DELETE FROM token_balances WHERE token_address = ?", _ta)
                await self.db.execute_dml("DELETE FROM contract_state WHERE contract_address = ?", _ta)
            else:
                await self.db.execute_dml("DELETE FROM tokens WHERE address = $1", _ta)
                await self.db.execute_dml("DELETE FROM token_balances WHERE token_address = $1", _ta)
                await self.db.execute_dml("DELETE FROM contract_state WHERE contract_address = $1", _ta)
        _created = set(_reorg_token_creates)
        _touched_t = {(t, w) for (t, w) in _touched_t if t not in _created}
        await self._reorg_settle_negatives(_touched_w, _touched_t, _reorg_shortfalls)
        # BUG 7 follow-up (MCX75): the journal delta revert leaves
        # reverted htlc_id pseudo-balances at exactly 0 (those rows
        # never existed pre-block). Drop zero rows so a reverted
        # chain compares equal with a chain that never had the
        # block. Never touch non-zero rows (conditional DELETE is
        # atomic and exact — no read needed).
        for _hid in _reorg_htlc_ids:
            if self.db.db_type == "sqlite":
                await self.db.execute_dml("DELETE FROM balances WHERE wallet = ? AND bal = 0", _hid)
            else:
                await self.db.execute_dml("DELETE FROM balances WHERE wallet = $1 AND bal = 0", _hid)
        if self.db.db_type == "sqlite":
            if tx_hashes is None:
                # R5-sign-fail-rollback: unscoped mode also drops block rows (reorg).
                await self.db.execute_dml("DELETE FROM transactions WHERE block_id > ?", common_height)
                await self.db.execute_dml("DELETE FROM transaction_receipts WHERE block_id > ?", common_height)
                await self.db.execute_dml("DELETE FROM blocks WHERE id > ?", common_height)
                await self.db.execute_dml("DELETE FROM block_state_roots WHERE block_id > ?", common_height)
            else:
                # R5-sign-fail-rollback: scoped mode deletes only attempt rows; blocks/state_roots are never attempt state.
                _hashes = [str(h) for h in tx_hashes]
                _in = "(%s)" % ",".join("?" * len(_hashes))
                await self.db.execute_dml("DELETE FROM transactions WHERE block_id > ? AND tx_hash IN " + _in, common_height, *_hashes)
                await self.db.execute_dml("DELETE FROM transaction_receipts WHERE block_id > ? AND tx_hash IN " + _in, common_height, *_hashes)
        else:
            if tx_hashes is None:
                await self.db.execute_dml("DELETE FROM transactions WHERE block_id > $1", common_height)
                await self.db.execute_dml("DELETE FROM transaction_receipts WHERE block_id > $1", common_height)
                await self.db.execute_dml("DELETE FROM blocks WHERE id > $1", common_height)
                await self.db.execute_dml("DELETE FROM block_state_roots WHERE block_id > $1", common_height)
            else:
                _hashes = [str(h) for h in tx_hashes]
                _in = "(%s)" % ",".join("$%d" % n for n in range(2, 2 + len(_hashes)))
                await self.db.execute_dml("DELETE FROM transactions WHERE block_id > $1 AND tx_hash IN " + _in, common_height, *_hashes)
                await self.db.execute_dml("DELETE FROM transaction_receipts WHERE block_id > $1 AND tx_hash IN " + _in, common_height, *_hashes)
        return _reorg_shortfalls

    async def _branch_state_root_ok(self, block: dict) -> bool:
        """REORG-STATEROOT-1: protocol state commitment for ONE block,
        recomputed against the CURRENT DB state (which the caller guarantees
        is the block's branch pre-state). Same scope/encoding as the
        producer seal and verify_block_proof's tip probe:
        {height, balance:<reward_wallet> = pre_balance + reward}.
        Pure computation (no trie writes)."""
        try:
            if int(block.get('id', 0)) <= 0:
                return True
            claimed = block.get("state_root", "")
            if not claimed or not isinstance(claimed, str):
                return False
            probe = StateTrie(self.db)
            await probe.put("height", int(block["id"]))
            reward = int(block.get("reward", 0) or 0)
            wallet = block.get("reward_wallet") or ""
            if wallet and reward > 0:
                pre_bal = await self.balance_repo.get(wallet)
                await probe.put(f"balance:{wallet}", int(pre_bal or 0) + reward)
            expected, _ = probe._compute_root()
            return claimed == expected
        except Exception as e:
            logger.warning(f"[REORG-STATEROOT-1] block {block.get('id')} state_root check failed: {e}")
            return False

    async def _assert_reorg_cumulative(self, common_height: int, orphaned: list,
                                         adopted: list, pre_minted: int) -> None:
        """Fix 3 (R10): final cumulative gate over a reorg adoption.

        Runs INSIDE the atomic reorg transaction after the adoption loop:
        rollback + adoption must leave exactly the canonical replay of the
        common prefix plus the adopted suffix — no trust in the branch's
        declared aggregates for anything locally recomputable. Raises
        AuxStateError (full DB rollback + mirror restore by the caller) on:
        (a) linkage: every adopted block present in block_repo, hash-equal,
            parent-linked from the common anchor, tip height/hash mirrored
            in self.height/self.last_hash;
        (b) mint conservation: replaying the rewind (per-block max(0, .)
            floor, orphan order — exactly as the rollback loop applies it)
            then the adoption from the pre-rewind counter must equal live
            total_minted (catches reward-credit/mint-counter skew of the
            IMPORT-MINT class and any future rewind/credit asymmetry; a
            floor-binding rewind logs loudly, never silently);
        (c) tx completeness: each adopted block's persisted transaction set
            equals its sealed tx_hashes exactly (no dropped/duplicated rows;
            orphan rows above common were deleted by the journal revert, so
            the range is adoption-owned).
        Residual (documented, not asserted): full state-root re-derivation
        from the common point and burned_total conservation across mixed
        burn/un-burn sequences — still caught by later sync/verification.
        """
        _tip_id = int(common_height)
        _tip_hash = ""
        if adopted:
            _anchor = await self.block_repo.get_by_id(int(common_height))
            _anchor_hash = (_anchor.get('hash', '') if isinstance(_anchor, dict) else '')
            if not _anchor_hash:
                if int(common_height) == 0:
                    _anchor_hash = '0' * 64
                else:
                    raise AuxStateError(
                        f"reorg cumulative: no common ancestor at {common_height}")
            _prev = str(_anchor_hash)
            for _b in adopted:
                _bid = int(_b.get('id', -1))
                _row = await self.block_repo.get_by_id(_bid)
                if not isinstance(_row, dict):
                    raise AuxStateError(
                        f"reorg cumulative: adopted block {_bid} missing from block_repo")
                if str(_row.get('hash', '')) != str(_b.get('hash', '')):
                    raise AuxStateError(
                        f"reorg cumulative: adopted block {_bid} hash mismatch repo-vs-branch")
                if str(_row.get('phash', '')) != _prev:
                    raise AuxStateError(
                        f"reorg cumulative: adopted block {_bid} not parent-linked")
                _prev = str(_b.get('hash', ''))
                _tip_id, _tip_hash = _bid, _prev
            if int(self.height) != _tip_id + 1:
                raise AuxStateError(
                    f"reorg cumulative: height {self.height} != tip {_tip_id}+1")
            if str(self.last_hash) != str(_tip_hash):
                raise AuxStateError("reorg cumulative: last_hash != adopted tip hash")
            # (b): simulate the rollback rewind exactly (per-block floor in
            # orphan order), then add the adopted base mint.
            _sim = int(pre_minted)
            for _ob in sorted((o for o in (orphaned or []) if isinstance(o, dict)),
                              key=lambda x: int(x.get('id', 0))):
                _om = _reorg_base_mint(_ob)
                if _om > 0:
                    _floored = max(0, _sim - _om)
                    if _floored != _sim - _om:
                        logger.warning(
                            f"[REORG] cumulative: mint rewind floored at 0 "
                            f"(pre={pre_minted} orphan={int(_ob.get('id', -1))})")
                    _sim = _floored
            for _b in adopted:
                _sim += _reorg_base_mint(_b)
            if int(self.total_minted) != _sim:
                raise AuxStateError(
                    f"reorg cumulative: total_minted {self.total_minted} != "
                    f"conserved {_sim} (pre={pre_minted})")
            for _b in adopted:
                _bid = int(_b.get('id', -1))
                _want = set(str(h) for h in (_b.get('tx_hashes') or []))
                if self.db.db_type == "sqlite":
                    _rows = await self.db.fetch(
                        "SELECT tx_hash FROM transactions WHERE block_id = ?", _bid)
                else:
                    _rows = await self.db.fetch(
                        "SELECT tx_hash FROM transactions WHERE block_id = $1", _bid)
                _got = set(str(_r.get('tx_hash', '')) for _r in (_rows or []))
                if _got != _want:
                    raise AuxStateError(
                        f"reorg cumulative: block {_bid} persisted txs "
                        f"{sorted(_got)[:4]} != sealed {sorted(_want)[:4]}")
        else:
            if int(self.height) != int(common_height) + 1:
                raise AuxStateError(
                    f"reorg cumulative: empty adoption left height {self.height} "
                    f"!= common {common_height}+1")

    async def _reorg_chain(self, common_height: int, new_blocks: List[Dict]):
        """Roll back local blocks above common_height and adopt the peer chain.

        Known limitations:
        - Reorgs deeper than PRUNE_BLOCKS are refused before any state is
          touched; per-tx inverses and the journal revert cover the same range.
        - New blocks ARE pre-verified on this path (N-10) against ancestor
          attestation state (P6) before any rollback; a failed pre-verify
          aborts with all state untouched. This method then reverses local
          effects of orphaned blocks and appends the new chain.
        - VM state (storage / balances / token balances / token temporal
          state) is reverted from contract_exec_journal (B6). MCX balance and
          token-balance debits are signed deltas settled at the end
          (B6-fix3), not order-dependent subtract()s.
        - Reorgs whose fork point is below the last checkpoint still heal
          by weight (R8-finality-advisory: checkpoints are advisory, not a
          veto — refusing split partitions permanently).
        - Fix 3 (R10) final cumulative gate (_assert_reorg_cumulative,
          inside the same atomic txn): adopted blocks parent-linked from
          the anchor and present hash-equal in block_repo, tip height/hash
          mirrored, total_minted conserved (pre - rewound orphan mint +
          adopted mint, single-sourced formula), and each adopted block's
          persisted tx set equal to its sealed tx_hashes. Residual: full
          state-root re-derivation from the common point and burned_total
          conservation are still deferred (caught by later sync/
          verification).
        """
        # R8-finality-advisory (R7-03): no local-checkpoint veto here — fork
        # points below checkpoints heal by weight (see FinalityGadget).
        # R9-branch-link (I-R8-03): the candidate suffix must form ONE
        # contiguous parent-linked chain from the common ancestor BEFORE
        # any verification or rollback. Gaps, duplicate heights, reordered
        # input, wrong parent hashes, non-dict entries, or a floating first
        # block previously adopted as canonical history. Timestamps are
        # checked branch-locally here (each block against its actual
        # candidate parent under the deterministic rule — the verify path
        # can only see local-canonical parents). Missing ts or an
        # unanchorable common block also aborts. The whole gate is
        # exception-tight: malformed entries abort the reorg, never escape.
        try:
            _cand_raw = list(new_blocks or [])
            for _ce in _cand_raw:
                if not isinstance(_ce, dict) or int(_ce.get('id', -1)) < 0:
                    logger.error("[Reorg] Candidate suffix contains a malformed entry; aborting reorg")
                    return False
            _cand = sorted((b for b in _cand_raw if int(b.get('id', -1)) > common_height),
                           key=lambda x: int(x.get('id', 0)))
            if _cand:
                _anchor = await self.block_repo.get_by_id(common_height)
                _anchor_hash = (_anchor.get('hash', '') if isinstance(_anchor, dict) else '')
                if not _anchor_hash:
                    if common_height == 0:
                        _anchor_hash = '0' * 64
                    else:
                        logger.error(f"[Reorg] No common ancestor at {common_height}; aborting reorg")
                        return False
                try:
                    _prev_ts = float(_anchor.get('ts', 0) or 0) if isinstance(_anchor, dict) else 0
                except (TypeError, ValueError):
                    _prev_ts = 0
                _prev_id, _prev_hash = common_height, str(_anchor_hash)
                for _cb in _cand:
                    _cid = int(_cb.get('id', -1))
                    if _cid != _prev_id + 1 or str(_cb.get('phash', '')) != str(_prev_hash):
                        logger.error(f"[Reorg] Candidate suffix not contiguous at id {_cid} (prev {_prev_id}); aborting reorg")
                        return False
                    _cts = _cb.get('ts', 0)
                    if not _cts:
                        logger.error(f"[Reorg] Candidate {_cid} missing timestamp; aborting reorg")
                        return False
                    if _prev_ts and not _block_timestamp_ok(_cts, _prev_ts):
                        logger.error(f"[Reorg] Candidate {_cid} timestamp outside parent-relative bounds; aborting reorg")
                        return False
                    try:
                        _prev_ts = float(_cts)
                    except (TypeError, ValueError):
                        _prev_ts = 0
                    _prev_id, _prev_hash = _cid, str(_cb.get('hash', ''))
        except Exception as _link_e:
            logger.error(f"[Reorg] Candidate suffix validation failed ({_link_e}); aborting reorg")
            return False
        # P6 (MCX72): agreed-state attestation base — newest attestation per
        # maze from agreed blocks <= common_height (read-only walk; tolerant
        # of str and dict proof forms). Passed to pre-verification so growth
        # caps evaluate against fork-point state instead of orphaned-tip rows
        # (ATTEST-CAP-STRICT would otherwise reject any same-height competing
        # attestation and strand the node on the lighter fork — observed in
        # soak: fork block 17 vs local row 17, then block 58 vs local 58).
        # The N-10 loop below extends the base with each VERIFIED fork
        # block's attestation, so every block is checked against the same
        # attestation state its honest producer saw (agreed prefix + in-order
        # fork history): producer-passed implies node-passes (a producer's
        # own abandoned rows can only make its check stricter, never looser).
        _att_base = {}
        try:
            _aq = ("SELECT id, hash, proof FROM blocks WHERE id <= ? AND proof IS NOT NULL ORDER BY id DESC"
                   if self.db.db_type == "sqlite" else
                   "SELECT id, hash, proof FROM blocks WHERE id <= $1 AND proof IS NOT NULL ORDER BY id DESC")
            for _r in (await self.db.fetch(_aq, common_height) or []):
                try:
                    _rp = _r.get("proof")
                    if isinstance(_rp, str):
                        _rp = json.loads(_rp or "{}")
                    if not isinstance(_rp, dict):
                        continue
                except Exception:
                    continue
                _ra = _rp.get("maze_attestation")
                if not isinstance(_ra, dict):
                    continue
                _rm = str(_ra.get("maze_id", ""))
                if _rm and _rm not in _att_base:
                    try:
                        _att_base[_rm] = {
                            "maze_id": _rm,
                            "last_size": int(_ra.get("size", 0)),
                            "last_block": int(_r.get("id", 0)),
                            "last_block_hash": str(_r.get("hash", "")),
                            "pubkey": str(_ra.get("pubkey", "")),
                        }
                    except Exception:
                        continue
        except Exception as _aw:
            logger.warning(f"[P6] ancestor attestation walk failed: {_aw} — falling back to local rows")
            _att_base = None
        logger.debug(f"[P6] attestation base: {len(_att_base) if isinstance(_att_base, dict) else 'legacy'} rows at fork {common_height}")
        # B2 (MCX73): agreed-state maze-geometry base for the updates
        # provenance check below (parent_pos_attested / parent_movenonce are
        # judged against local rows, which are orphaned-tip state during a
        # reorg). Shape mirrors what _append_block writes when it applies an
        # update (pos=spawn, movenonce reset, activity=block id). Newest
        # agreed update per maze wins; mazes with no agreed update stay
        # absent and fall back to the local lookup (today's behavior).
        _maze_base = {}
        if _att_base is not None:
            try:
                for _r in (await self.db.fetch(_aq, common_height) or []):
                    try:
                        _rp = _r.get("proof")
                        if isinstance(_rp, str):
                            _rp = json.loads(_rp or "{}")
                        if not isinstance(_rp, dict):
                            continue
                    except Exception:
                        continue
                    for _u in (_rp.get("maze_updates") or []):
                        if not isinstance(_u, dict):
                            continue
                        _mm = str(_u.get("maze_id") or _u.get("miner_id") or "")
                        if not _mm or _mm in _maze_base:
                            continue
                        try:
                            _sp = _u.get("spawn") or [0, 0, 0]
                            _maze_base[_mm] = {
                                "posx": int(_sp[0]), "posy": int(_sp[1]), "posz": int(_sp[2]),
                                "movenonce": 0,
                                "lastactiveheight": int(_r.get("id", 0)),
                            }
                        except Exception:
                            continue
            except Exception as _mw:
                logger.warning(f"[B2] maze-geometry walk failed: {_mw} — falling back to local rows")
                _maze_base = None
        else:
            _maze_base = None
        # N-10: Defensive pre-verification of all adopted fork blocks BEFORE rolling back state
        # R9-branch-replay (I-R8-09): ONE shared branch context across the
        # suffix — nonce continuity plus cumulative shadow state — so a
        # spend funded by an earlier candidate block validates. Base reads
        # still come from live repos (residual: keys touched by the
        # not-yet-rolled-back orphan branch read orphan state; adoption
        # replays authoritatively inside the atomic txn, so a wrongly
        # admitted branch still cannot commit).
        _branch_ctx: dict = {}
        # Fix 3 (R10): seed sender nonces from the COMMON ANCESTOR, not the
        # live (orphan-tip) state. The candidate suffix replays from the
        # fork point — its first block's nonces are ancestor-relative — so
        # seeding from live wrongly rejects any competing suffix that
        # reuses a sender consumed by the orphan branch (standard
        # same-sender replacement), stranding the node on the lighter
        # fork. Later blocks thread cumulatively via seen_nonces. Base
        # reads for balances still come from live repos (R9 residual:
        # adoption replays authoritatively inside the atomic txn, so a
        # wrongly admitted branch still cannot commit).
        try:
            _nest = _branch_ctx.setdefault("nonces", {})
            for _sb in _cand:
                for _stx in (_sb.get("transactions") or []):
                    if not isinstance(_stx, dict):
                        continue
                    _sw = _stx.get("from_wallet", "")
                    if _sw and _sw not in _nest:
                        _nest[_sw] = await self._get_confirmed_nonce_at(
                            _sw, common_height)
        except Exception as _nse:
            logger.warning(f"[Reorg] ancestor nonce seeding failed ({_nse}); pre-verify uses live nonces")
        for b in sorted(new_blocks, key=lambda x: x['id']):
            if b['id'] > common_height:
                if not await self.verify_block_proof(b, _att_base, _maze_base, _branch_ctx):
                    logger.error(f"[Reorg] Block {b.get('id')} failed verification before reorg adoption; aborting reorg")
                    return False
                # B2 (MCX73): extend the geometry base with this VERIFIED
                # block's updates (mirror the _att_base extension below).
                # OVERWRITE (not first-wins): N-10 verifies in ascending id
                # order, so each verified block is the newest sealed state —
                # the next block's parent claims are judged against exactly
                # what its honest producer saw.
                try:
                    if _maze_base is not None:
                        for _u in (b.get('maze_updates') or []):
                            if not isinstance(_u, dict):
                                continue
                            _mm = str(_u.get('maze_id') or _u.get('miner_id') or '')
                            if not _mm:
                                continue
                            _sp = _u.get('spawn') or [0, 0, 0]
                            _maze_base[_mm] = {
                                "posx": int(_sp[0]), "posy": int(_sp[1]), "posz": int(_sp[2]),
                                "movenonce": 0,
                                "lastactiveheight": int(b.get('id', 0)),
                            }
                except Exception:
                    pass
                # P6 (MCX72): extend the base with this VERIFIED block's
                # attestation (top-level key, same source verify reads), so
                # the next fork block sees producer-equivalent state.
                try:
                    _ba = b.get('maze_attestation') or {}
                    if _att_base is not None and isinstance(_ba, dict) and _ba.get('maze_id'):
                        _att_base[str(_ba.get('maze_id'))] = {
                            "maze_id": str(_ba.get('maze_id')),
                            "last_size": int(_ba.get('size', 0)),
                            "last_block": int(b.get('id', 0)),
                            "last_block_hash": str(b.get('hash', '')),
                            "pubkey": str(_ba.get('pubkey', '')),
                        }
                except Exception:
                    pass
        # P2 (MCX72): orphan rollback is ONE atomic transaction (B2) — an
        # exception mid-rollback (missing wallet row, constraint, crash)
        # rolls everything back instead of leaving half-reverted balances.
        # In-memory mirrors cannot roll back: snapshot and restore them.
        # BUG 5 (MCX75): the orphan list was capped at 1000 rows while the
        # journal revert is uncapped — a deeper reorg reverted the journal
        # but left rewards/txs behind. Refuse reorgs deeper than
        # PRUNE_BLOCKS BEFORE the txn opens (not P2PNode.max_reorg_depth,
        # which is a separate networking-layer gate).
        try:
            _reorg_depth = int(self.height) - int(common_height)
        except (TypeError, ValueError):
            _reorg_depth = 0
        if _reorg_depth > _config.PRUNE_BLOCKS:
            logger.error(
                f"[REORG] refused: depth {_reorg_depth} exceeds PRUNE_BLOCKS "
                f"{_config.PRUNE_BLOCKS} (common {common_height}, tip {self.height})")
            return False
        _rz_mem = (self.height, self.last_hash, self.total_minted,
                   self.burned_total, self.blocks)
        # B1 (MCX73): in-memory queues are also rollback state — a requeued
        # slash or maze update that the rolled-back attempt appended would
        # otherwise survive as a phantom and get sealed twice.
        _rz_slashes = list(self.consensus._pending_slashes)
        _rz_maze_updates = list(self.consensus._pending_maze_updates)
        # R8-confirmed-wire (R7-17): orphaned heights un-confirm nonces —
        # drop derived confirmed state so the next admission re-seeds from
        # canonical post-reorg state (lazy healing; always safe).
        if getattr(self, 'mempool', None) is not None:
            self.mempool.forget_confirmed()
        # R8-reorg-atomic (R7-10): the adoption loop below runs inside the
        # same outer transaction (append joins via nesting short-circuit),
        # so these two snapshots cover rollback AND adoption. Mempool
        # evictions inside _append_block are memory-only and would survive
        # a DB rollback — snapshot and restore them too. Same for the
        # finality gadget's in-memory high-water mark.
        _rz_mempool = (dict(self.mempool._transactions)
                       if getattr(self, 'mempool', None) is not None else None)
        _rz_final = self.finality_gadget.get_last_finalized_block()
        # R8-reorg-atomic Audit-E: GLOBAL_SHRINK_FACTOR is a module global
        # rewritten by every appended block (post-commit section) — outside
        # DB rollback reach. Snapshot it with the other mirrors.
        _rz_shrink = _config.GLOBAL_SHRINK_FACTOR
        # G3-RESIDUAL-1 (mainnet audit): mempool nonce admission maps and
        # trie dirt are also adoption-phase memory — cleared/mutated during
        # rollback+adoption yet outside DB rollback reach (previously left
        # diverged after a failed adoption).
        _rz_mmut = getattr(self, 'mempool', None)
        _rz_pend = (dict(_rz_mmut._pending_nonces)
                    if _rz_mmut is not None and hasattr(_rz_mmut, '_pending_nonces') else None)
        _rz_conf = (dict(_rz_mmut._confirmed_nonces)
                    if _rz_mmut is not None and hasattr(_rz_mmut, '_confirmed_nonces') else None)
        try:
            _rz_dirty = dict(self.state_trie._dirty)
        except Exception:
            _rz_dirty = None
        try:
            async with await self.db.transaction():
                # Roll back miner rewards and transaction effects for orphaned blocks
                # BUG 5 (MCX75): page get_range to PRUNE_BLOCKS so the per-tx
                # inverses cover exactly the same depth as the (uncapped)
                # journal revert. Sorted ascending = the historical order.
                orphaned_blocks = []
                _fetch_from = int(common_height) + 1
                for _ in range((_config.PRUNE_BLOCKS // 1000) + 2):
                    if _fetch_from > int(self.height):
                        break
                    _page = await self.block_repo.get_range(_fetch_from, self.height, limit=1000)
                    if not _page:
                        break
                    orphaned_blocks.extend(_page)
                    _fetch_from = max(int(b.get('id', 0)) for b in _page) + 1
                    if len(orphaned_blocks) >= _config.PRUNE_BLOCKS:
                        break
                orphaned_blocks = sorted(orphaned_blocks, key=lambda x: int(x.get('id', 0)))
                # BUG 4 (MCX75): collect debit shortfalls across the whole
                # rollback; reported once at the end (below). An honest
                # spender may already have used the money — loud and
                # auditable, never a silent writeoff, never a clawback.
                _reorg_shortfalls: list = []
                _touched_w: set = set()   # B6-fix3: wallets debited by signed delta
                _touched_t: set = set()   # B6-fix3: (token, wallet) debited by signed delta
                _reorg_deploys: list = []   # B6-fix3: deletes deferred until after journal revert
                _reorg_token_creates: list = []
                # BUG 7 follow-up (MCX75): htlc_ids seen in orphaned
                # htlc_create txs; zero-balance cleanup runs after the
                # journal revert below (which is what zeroes them).
                _reorg_htlc_ids: list = []
                for b in orphaned_blocks:
                    # SPATIAL-POOL-REORG-1 (§7.12): debit pool payouts this fork
                    # credited for this block BEFORE anything else — idempotent
                    # no-op when the block paid nothing.
                    try:
                        await self._revert_spatial_fee_payouts(b.get('id'))
                    except Exception as _rp:
                        logger.warning(f"[SPATIAL-POOL-REORG-1] payout revert failed for orphaned block {b.get('id')}: {_rp}")
                    reward = b.get('reward', 0)
                    winner = b.get('winner') or (b.get('miners') or [None])[0]
                    if winner and reward > 0:
                        # IDEA5-REWARD-WALLET-1: mirror the forward credit resolution so
                        # exactly the wallet that was credited gets debited (the old path
                        # could not resolve foreign winners at all -> stale credit).
                        if isinstance(winner, str) and winner.startswith('0x'):
                            winner_wallet = winner
                        elif b.get('reward_wallet'):
                            winner_wallet = b.get('reward_wallet')
                        else:
                            winner_miner = await self.miner_repo.get(winner)
                            winner_wallet = winner_miner.get('wallet') if winner_miner else None
                            if not winner_wallet:
                                _pub = b.get('producer_pub') or ''
                                if _pub:
                                    try:
                                        winner_wallet = pubkey_to_address(_pub)
                                    except Exception:
                                        winner_wallet = None
                        if winner_wallet:
                            # B6-fix3 (MCX76 audit): signed delta, NOT subtract().
                            # subtract() silently no-ops when the winner already
                            # spent the reward in a later orphaned block (the
                            # tx inverses that return that money run AFTER this
                            # point) -> the reward credit survived the reorg
                            # while total_minted was rewound. Real shortfalls
                            # are detected once at the end (settle).
                            await self.balance_repo.add(winner_wallet, -int(reward))
                            _touched_w.add(str(winner_wallet).lower())
                    # IMPORT-MINT-REORG: mirror the mint rewind so a reorg does not leave
                    # total_minted ahead of the tip's actual mint (forward paths: produce
                    # adds base_reward, import adds reward - total_fees — same value).
                    # Fix 3 (R10): single-sourced formula (see _reorg_base_mint).
                    if reward > 0:
                        _orphan_mint = _reorg_base_mint(b)
                        if _orphan_mint > 0:
                            self.total_minted = max(0, self.total_minted - _orphan_mint)
                            await self.network_state_repo.set("total_minted", str(self.total_minted))
                    # SLASH-REQUEUE-1: slashes sealed into this orphaned block were
                    # cleared from _pending_slashes at seal time, and followers that
                    # never appended the orphan have no slash_repo row (slashes apply
                    # on append) — the event was lost forever (run1: slash@5 existed
                    # only on node1). Requeue so the next produced block re-carries
                    # it; import dedupes by slash_repo row, so nodes that did apply
                    # the original skip the duplicate.
                    for _ev in (b.get('slashes') or []):
                        if _ev not in self.consensus._pending_slashes:
                            self.consensus._pending_slashes.append(dict(_ev))
                # IDEA5-ATTEST-REORG-1: drop attestations written by orphaned blocks
                # (rows with last_block > common_height); the adopted chain re-applies
                # its own as it imports. IDEA5-ATTEST-REORG-2 restores rows whose
                # pre-fork attestation the DELETE clobbered (single-row-per-maze table).
                if orphaned_blocks:
                    try:
                        _affected = [str(r["maze_id"]) for r in
                                     (await self.maze_attestation_repo.get_all() or [])
                                     if int(r.get("last_block", 0)) > common_height]
                        await self.maze_attestation_repo.rollback_after(common_height)
                        if _affected:
                            await self._restore_attestations_upto(common_height, _affected)
                    except Exception as _e:
                        logger.warning(f"[IDEA5-ATTEST-REORG-1] attestation rollback failed: {_e}")

                _reorg_shortfalls = await self._invert_block_txs(common_height, None, _touched_w, _touched_t)

                self.height = common_height + 1
                if common_height > 0:
                    last_block = await self.block_repo.get_by_id(common_height)
                    self.last_hash = last_block.get('hash', '') if last_block else ''
                else:
                    self.last_hash = '0' * 64
                self.blocks = [b for b in self.blocks if b.get('id', 0) <= common_height]
                # BUG 4 (MCX75): single ERROR summary for the whole rollback.
                # Still commits (we are inside the txn and fall through to
                # it) — raising would roll back the rollback, which is worse
                # than an auditable shortfall.
                if _reorg_shortfalls:
                    _sf_wallets = sorted({str(w)[:16] for _, w, _, _ in _reorg_shortfalls})
                    # _rz_mem[0] is the pre-rollback height (tip + 1); the
                    # orphan range is common_height + 1 .. tip.
                    _sf_hi = int(_rz_mem[0]) - 1
                    logger.error(
                        f"[REORG] rollback of blocks {int(common_height) + 1}..{_sf_hi} "
                        f"left {len(_reorg_shortfalls)} debit shortfall(s) "
                        f"wallets={_sf_wallets}")
                # R8-reorg-atomic (R7-10): adopt INSIDE this same outer
                # transaction (_append_block joins it via nesting
                # short-circuit). A failing append raises through the txn
                # exit (full DB rollback of rollback+adoption) into the
                # handler above (in-memory mirrors restored) — no
                # half-reorged chain can commit.
                for b in sorted(new_blocks, key=lambda x: x['id']):
                    if b['id'] > common_height:
                        # REORG-STATEROOT-1: the pre-verification pass skips
                        # the state-commitment check on forks (ambiguous
                        # pre-state). Here the DB holds exactly the branch
                        # pre-state (common ancestor + earlier adopted
                        # blocks), so recompute and enforce it; a mismatch
                        # raises and rolls back the whole adoption.
                        if not await self._branch_state_root_ok(b):
                            raise AuxStateError(f"state_root mismatch in adopted block {b.get('id')}")
                        await self._append_block(b)
                # Fix 3 (R10): final cumulative gate — still inside the outer
                # transaction, so a failure rolls back rollback+adoption
                # together (handler above restores the in-memory mirrors).
                _adopted = sorted(
                    (b for b in (new_blocks or [])
                     if isinstance(b, dict) and int(b.get('id', -1)) > int(common_height)),
                    key=lambda x: int(x.get('id', 0)))
                await self._assert_reorg_cumulative(
                    common_height, orphaned_blocks, _adopted, int(_rz_mem[2]))
        except Exception as _rz_e:
            (self.height, self.last_hash, self.total_minted,
             self.burned_total, self.blocks) = _rz_mem
            self.consensus._pending_slashes = _rz_slashes
            self.consensus._pending_maze_updates = _rz_maze_updates
            # R8-reorg-atomic (R7-10): also unwind adoption-phase memory
            # (mempool evictions + finality high-water) — the DB side is
            # already rolled back by the txn exit above.
            if _rz_mempool is not None and getattr(self, 'mempool', None) is not None:
                self.mempool._transactions = _rz_mempool
            # G3-RESIDUAL-1: restore nonce maps + trie dirt (see snapshot).
            try:
                if _rz_pend is not None and getattr(self, 'mempool', None) is not None:
                    self.mempool._pending_nonces = _rz_pend
                if _rz_conf is not None and getattr(self, 'mempool', None) is not None:
                    self.mempool._confirmed_nonces = _rz_conf
            except Exception:
                pass
            try:
                if _rz_dirty is not None:
                    self.state_trie._dirty = _rz_dirty
            except Exception:
                pass
            try:
                self.finality_gadget._last_finalized_block = _rz_final
            except Exception:
                pass
            _config.GLOBAL_SHRINK_FACTOR = _rz_shrink
            logger.error(f"[REORG] orphan rollback failed, in-memory mirrors restored: {_rz_e}")
            return False

        # NOTE: the adoption loop lives INSIDE the outer transaction above
        # (after the shortfall summary), not here — see R8-reorg-atomic.
        # REORG-BOOL-1 (mainnet audit): success is explicit so callers
        # (receive_block) can refuse to relay a block whose adoption failed.
        return True

    async def _apply_slash_event(self, ev: dict, block_id: int) -> bool:
        """Apply one sealed slash event to miner/maze/slash state.

        R6-slash-state-order: shared by _append_block (followers) and the
        producer seal path (chain reset: state-machine change). Returns
        True when the event bans the miner (caller kicks the socket).
        Dedupes against slashing_events so replays/restarts never
        double-apply. _slash_* only queue + broadcast; every mutation
        below happens here, at seal time, on all nodes alike.
        """
        mid = ev.get('miner_id')
        amt = max(0, int(ev.get('amount', 0)))
        reason = ev.get('reason', '')
        ev_block = int(ev.get('block_id', block_id))
        if not mid:
            return False
        prior = await self.slash_repo.get_by_miner(mid)
        if any(int(r.get('block_id', -1)) == ev_block and r.get('reason') == reason for r in (prior or [])):
            return False
        m = await self.miner_repo.get(mid)
        banned = False
        if m:
            m['rewards'] = max(0, int(m.get('rewards', 0)) - amt)
            if reason == 'equivocation':
                m['active'] = 0
                m['banned_until'] = time.time() + _config.BAN_DURATION
                await self.maze_repo.update_miner_inactive(mid)
                banned = True
            elif reason == 'signing_refusal':
                m['consecutive_misses'] = int(m.get('consecutive_misses', 0)) + 1
                if m['consecutive_misses'] >= _config.MAX_MISSES:
                    m['active'] = 0
                    m['banned_until'] = time.time() + _config.BAN_DURATION
                    await self.maze_repo.update_miner_inactive(mid)
                    banned = True
            await self.miner_repo.update(m)
        else:
            logger.info(f"[IMPORT-SLASH] no local row for miner {mid} in block {block_id}; recording event only")
        await self.slash_repo.create(mid, amt, reason or 'unknown', ev_block)
        return banned

    async def _append_block(self, block: dict):
        # R9-reward-supply (I-R8-02): validate subsidy/fees/cap BEFORE any
        # mutation (same rule as verify_block_proof). A mismatch fails the
        # whole append — the old code credited the supplied reward, then
        # silently skipped the mint when the cap refused it, minting
        # balances beyond MAX_SUPPLY with no counter update.
        _vbase = _validated_block_reward(block, self.total_minted)
        if _vbase is None:
            raise AuxStateError(f"reward/subsidy/supply mismatch in block {block.get('id')}")
        _vbase = _vbase[0]
        # BLOCK-GAS-1: every adoption path (import, sync, reorg) passes here.
        _lok, _lreason = _block_limits_ok(block.get('transactions'))
        if not _lok:
            raise AuxStateError(f"block {block.get('id')} exceeds block limits: {_lreason}")
        # N-3: Wrap all block mutations atomically
        async with await self.db.transaction():
            await self.block_repo.create(block)
            # Credit block winner reward on syncing nodes
            # IMPORT-REWARD: resolve the winner's wallet without depending on a
            # local miners row (followers do not know foreign miners until they
            # register). Fall back to the proof's producer_pub: the producing host
            # is the winner's host, so its pubkey derives the winner's wallet.
            winner = block.get('winner')
            if not winner:
                _miners = block.get('miners')
                if isinstance(_miners, str) and _miners and not _miners.startswith('['):
                    winner = _miners
                elif isinstance(_miners, list) and _miners:
                    winner = _miners[0]
            reward = block.get('reward', 0)
            if winner and reward > 0:
                winner_wallet = None
                if isinstance(winner, str) and winner.startswith('0x'):
                    winner_wallet = winner
                elif block.get('reward_wallet'):
                    # IDEA5-REWARD-WALLET-1: prefer the wallet the producer sealed
                    # (followers have no miners row for foreign winners).
                    winner_wallet = block.get('reward_wallet')
                else:
                    winner_miner = await self.miner_repo.get(winner)
                    if winner_miner and winner_miner.get('wallet'):
                        winner_wallet = winner_miner.get('wallet')
                if not winner_wallet:
                    pub = block.get('producer_pub') or ''
                    if pub:
                        try:
                            winner_wallet = pubkey_to_address(pub)
                        except Exception:
                            winner_wallet = None
                if winner_wallet:
                    await self.balance_repo.add(winner_wallet, reward)
                else:
                    logger.warning(f"[IMPORT-REWARD] Cannot resolve wallet for winner {winner} in block {block['id']}; reward {reward} not credited")
            # IMPORT-MINT: mirror the producer's mint. block['reward'] is
            # base_reward + total_fees, but only base_reward is newly minted —
            # fees are transfers credited to the winner. Adding the full reward
            # over-counted every fee into supply on followers (+700,000 in the
            # fresh-chain forensics). Mint reward minus the block's fees, capped
            # exactly like the produce-side (line ~6312).
            # R9-reward-supply (I-R8-02): _vbase was validated at function
            # top (reward == base + fees, base + minted <= MAX_SUPPLY), so
            # credit and mint fate-share: any cap breach raises (and rolls
            # back the credit) instead of skipping the counter silently.
            if reward > 0:
                _mint = _vbase
                if _mint > 0:
                    if self.total_minted + _mint > MAX_SUPPLY:
                        raise AuxStateError(f"mint of block {block.get('id')} exceeds MAX_SUPPLY")
                    self.total_minted += _mint
                    await self.network_state_repo.set("total_minted", str(self.total_minted))

            # IMPORT-SLASH: apply slash events carried in the block so slashing
            # effects (rewards, misses, bans) replicate instead of staying
            # node-local. Events are queued by the producer at slash time and
            # sealed with its next block (R6-slash-state-order: detectors no
            # longer mutate locally; the dedupe below is replay safety).
            for ev in block.get('slashes') or []:
                try:
                    await self._apply_slash_event(ev, block['id'])
                except AuxStateError:
                    raise
                except Exception as e:
                    # R5-append-aux-fail-loud: aux state is consensus-relevant; partial apply diverges followers. Fail the block.
                    raise AuxStateError(f"slashes of block {block.get('id')}: {e}") from e

            # Replay transactions to reconstruct state on syncing nodes.
            # A2 (MCX73): a failed live replay aborts the import — the error
            # is recorded OUTSIDE the per-tx try (the local except would
            # swallow a raise and commit partial state). No partial commit.
            # R5-txhash-transactions-coupling: mismatch raises; enclosing txn rolls back.
            if bool(block.get("transactions", [])) != bool(block.get("tx_hashes", [])):
                raise RuntimeError(f"transactions/tx_hashes presence mismatch in block {block.get('id')}")
            _replay_error = None
            _sealed_hashes: list = []
            for tx_data in block.get("transactions", []):
                try:
                    # R4-opcodes-add: thread the sealed ts so TIMESTAMP
                    # agrees between producer and import replay.
                    success, result = await self.execute_transaction(tx_data, block['id'], block_ts=block.get('ts'))
                except Exception as e:
                    _replay_error = f"crash on {tx_data.get('tx_hash','?')[:16]}: {e}"
                    break
                if not success:
                    _replay_error = f"replay failed on {tx_data.get('tx_hash','?')[:16]}: {result}"
                    break
                if getattr(self, 'mempool', None) is not None:
                    _sealed_hashes.append(tx_data.get('tx_hash', ''))
            if _replay_error:
                logger.error(f"[Block] {_replay_error} — aborting import of block {block['id']}")
                raise RuntimeError(_replay_error)
            if self.db.db_type == "sqlite":
                await self.db.execute_dml(
                    "INSERT OR REPLACE INTO block_state_roots (block_id, state_root, receipt_root) VALUES (?, ?, ?)",
                    block['id'], block.get('state_root', ''), block.get('receipt_root', '0x' + '00' * 32)
                )
            else:
                await self.db.execute_dml(
                    "INSERT INTO block_state_roots (block_id, state_root, receipt_root) VALUES ($1, $2, $3) ON CONFLICT (block_id) DO UPDATE SET state_root=$2, receipt_root=$3",
                    block['id'], block.get('state_root', ''), block.get('receipt_root', '0x' + '00' * 32)
                )
            # IDEA5-ATTEST: apply the block's self-attested maze size (verify_block_proof
            # already checked pubkey binding, validator membership, growth cap
            # and the lottery threshold).
            _att = block.get("maze_attestation")
            if isinstance(_att, dict) and _att.get("maze_id") and _att.get("size") is not None:
                # MCX79 fixed validator set (defense in depth: verify already
                # rejected non-validator attestations; a block reaching here
                # through any other path must not persist one).
                _av = _effective_validators()
                if _av and _normalize_validator_key(_att.get("pubkey", "")) not in _av:
                    raise AuxStateError(f"attestation key not in validator set in block {block.get('id')}")
                try:
                    await self.maze_attestation_repo.upsert({
                        "maze_id": str(_att["maze_id"]),
                        "last_size": int(_att["size"]),
                        "last_block": int(block['id']),
                        "last_block_hash": str(block.get('hash', '')),
                        "pubkey": str(_att.get("pubkey", "")),
                    })
                except Exception as _e:
                    # R5-append-aux-fail-loud: aux state is consensus-relevant; partial apply diverges followers. Fail the block.
                    raise AuxStateError(f"maze_attestation of block {block.get('id')}: {_e}") from _e
            # Apply maze_updates from block to local maze_repo (MAZE-UPDATES-UX-1)
            for update in block.get("maze_updates", []):
                try:
                    mid = update.get("maze_id") or update.get("miner_id")
                    if not mid:
                        continue
                    existing = await self.maze_repo.get_by_maze_id(mid)
                    if existing:
                        existing = dict(existing)
                        if "new_size" in update:
                            # MAZE-MIN-1: never store an undersized dimension
                            # (verify already rejects such blocks; this is
                            # defense in depth for direct-added blocks).
                            _sz = _valid_maze_size(update["new_size"])
                            if _sz is None:
                                logger.warning(f"[Block] Skipping maze_update with invalid size {update['new_size']!r} for {mid[:16]}")
                                continue
                            existing["size"] = _sz
                        if "seed" in update:
                            existing["seed"] = update["seed"]
                        if "mazeroot" in update:
                            existing["mazeroot"] = update["mazeroot"]
                        if "new_density" in update:
                            existing["walldensityppm"] = update["new_density"]
                        if "goal" in update and len(update["goal"]) == 3:
                            existing["goalx"], existing["goaly"], existing["goalz"] = update["goal"]
                        if "spawn" in update and len(update["spawn"]) == 3:
                            existing["posx"], existing["posy"], existing["posz"] = update["spawn"]
                        if "turbulenceppm" in update:
                            existing["turbulenceppm"] = update["turbulenceppm"]
                        if "new_growthcount" in update:
                            existing["growthcount"] = update["new_growthcount"]
                        existing["movenonce"] = 0
                        existing["lastactiveheight"] = block['id']
                        await self.maze_repo.upsert(existing)
                    else:
                        goal = update.get("goal", [0, 0, 0])
                        spawn = update.get("spawn", [0, 0, 0])
                        new_row = {
                            "maze_id": mid,
                            "minerid": update.get("miner_id", mid),
                            "size": _valid_maze_size(update.get("new_size", MIN_MAZE_SIZE)) or MIN_MAZE_SIZE,
                            "walldensityppm": update.get("new_density", MIN_WALL_DENSITY_PPM),
                            "seed": update.get("seed", ""),
                            "posx": spawn[0], "posy": spawn[1], "posz": spawn[2],
                            "goalx": goal[0], "goaly": goal[1], "goalz": goal[2],
                            "movenonce": 0,
                            "consecutivewallhits": 0,
                            "turbulenceppm": update.get("turbulenceppm", 0),
                            "growthcount": update.get("new_growthcount", 0),
                            "knowledge": update.get("knowledge", 0),
                            "lastgoalheight": block['id'],
                            "lastactiveheight": block['id'],
                            "mazeroot": update.get("mazeroot", ""),
                            "invitedguest": None,
                            "guestlock": False,
                            "createdat": int(time.time()),
                            "updatedat": int(time.time()),
                        }
                        await self.maze_repo.upsert(new_row)
                except Exception as e:
                    logger.warning(f"[Block] Failed to apply maze_update: {e}")
            # Distribute token mining rewards for this block
            await self.distribute_token_mining_rewards(block['id'])
            # Spatial Tokens V2: apply the SEALED fee amount verbatim —
            # never recompute a follower-side figure. Runs after tx replay
            # (tokens live) and after the maze_update loop (sizes live),
            # before the height broadcast — mirrors the producer's Step-7
            # placement.
            try:
                _fee_amt = int(block.get("spatial_fee_amount", 0) or 0)
                if _fee_amt > 0:
                    _payouts = await self._distribute_spatial_fee(_fee_amt, block['id'])
                    if _payouts:
                        await self._record_spatial_fee_payouts(block['id'], _payouts)
            except Exception as _pe:
                # R5-append-aux-fail-loud: aux state is consensus-relevant; partial apply diverges followers. Fail the block.
                raise AuxStateError(f"spatial_fee_amount of block {block.get('id')}: {_pe}") from _pe

        # A1 (MCX73): MEMPOOL-RETRY runs OUTSIDE the DB transaction, at
        # function level — the block AND its state committed above. Drops
        # the copies this node accepted via broadcast so they cannot be
        # re-picked if this node later becomes a producer. Reached only on
        # commit: any exception above (including the A2 replay abort, which
        # rolls the transaction back) skips eviction, so a rollback never
        # loses transactions that are in no block.
        # R4-append-block-commit-boundary: post-commit in-memory state is
        # outside the DB txn; recoverable on restart. Do not move without
        # verifying no await escapes (mempool.remove / on_block / send_json
        # below all await — moving them inside would escape the txn).
        if getattr(self, 'mempool', None) is not None:
            for _h in _sealed_hashes:
                if _h:
                    await self.mempool.remove(_h)
            # R8-confirmed-wire (R7-17): imported seals feed the bound too
            # (followers learn canonical nonces without producing).
            for _stx in block.get("transactions", []):
                try:
                    _w = _stx.get('from_wallet', '') if isinstance(_stx, dict) else ''
                    if _w:
                        self.mempool.note_confirmed_nonce(_w, int(_stx.get('nonce', 0)) + 1)
                except (TypeError, ValueError):
                    continue

        await self.finality_gadget.on_block(block)
        self.blocks.append(block)
        if len(self.blocks) > BLOCK_CACHE_MAX:
            self.blocks = self.blocks[-BLOCK_CACHE_MAX:]
        self.height = block['id'] + 1
        self.last_hash = block.get('hash', '')
        # IMPORT-HEALTH: record_block() only ran on the produce path, so
        # follower nodes went permanently healthy=false after 6.5 BLOCK_TIMEs.
        # Advance last_block_time when a block is imported as well.
        if getattr(self, 'health_checker', None) is not None:
            self.health_checker.last_block_time = time.time()
        # Apply GLOBAL_SHRINK_FACTOR from block (deterministic consensus value)
        if "global_shrink_factor" in block:
            _config.GLOBAL_SHRINK_FACTOR = float(block["global_shrink_factor"])
        # Broadcast new height to all connected miners
        height_msg = {"type": "block_height_update", "height": self.height, "block_id": block['id']}
        for mid, mws in list(self.miner_websockets.items()):
            try:
                await mws.send_json(height_msg)
            except Exception:
                pass

    async def receive_transaction(self, tx_data: Dict) -> bool:
        # R8-seen-cache (R7-20): verdict return — True when admitted or
        # already known, False on any rejection (gossip unmarks on False).
        tx_hash = tx_data.get('tx_hash')
        if not tx_hash:
            return False
        is_valid_hash = False
        sig = tx_data.get('signature', '')
        decoded = None
        if isinstance(sig, str) and (sig.startswith('0x') or len(sig) > 130):
            try:
                decoded = decode_raw_eth_transaction(sig)
                if decoded.get('hash', '').lower() == tx_hash.lower():
                    is_valid_hash = True
            except Exception:
                pass
        if decoded is not None:
            # R8-chain-id: same predicate as consensus (rejects wrong-chain
            # AND legacy-unprotected).
            if not _raw_chain_id_ok(decoded):
                logger.debug(f"[TX] Rejected {tx_hash[:12]}: bad chain_id {decoded.get('chainId')}")
                return False
        if not is_valid_hash:
            tx_body = {k: v for k, v in tx_data.items() if k != 'tx_hash'}
            if hash_tx(tx_body) == tx_hash:
                is_valid_hash = True
        if not is_valid_hash:
            logger.debug("[TX] Rejected: tx_hash does not match tx contents")
            return False
        if not self._verify_tx_signature(tx_data):
            logger.debug(f"[TX] Rejected {tx_hash[:12]}: invalid signature")
            return False
        existing = await self.tx_repo.get_by_hash(tx_hash)
        if existing:
            return True
        if not await self.mempool.add(tx_data):
            return False
        tx_data['status'] = 'pending'
        tx_data['confirmed'] = False
        tx_data['block_id'] = -1
        await self.tx_repo.create(tx_data)
        if self.p2p:
            asyncio.create_task(self.p2p.broadcast_transaction(tx_data))
        return True

    # ─── Token Mining Distribution ──────────────────────────────────────────
    async def distribute_token_mining_rewards(self, block_id: int):
        # DUP-1: disabled - this PoR token-mining payout path could run more
        # than once for the same block (production + re-verification), double
        # crediting miners. Payouts stay disabled until a single canonical,
        # exactly-once distribution point is established.
        # AUDIT-NOTE (MCX77): callers at mine path (~7203) and block-import
        # path (~12856) both reach this stub; the early return keeps the
        # no-op exactly-once by construction. No behavior change in this
        # pass. CHANGELOG F-distribute-doc.
        # R4-dead-code-remove: kept as an intentional no-op; remove only
        # after the token-mining design is settled.
        return
        if self.db.db_type == "sqlite":
            query = "SELECT address, mining_reward, mining_interval, last_mined_block, total_mined, max_mineable_supply FROM tokens WHERE mining_type='por' AND mining_reward > 0"
        else:
            query = "SELECT address, mining_reward, mining_interval, last_mined_block, total_mined, max_mineable_supply FROM tokens WHERE mining_type='por' AND mining_reward > 0"
        rows = await self.db.fetch(query)
        for row in rows:
            token = dict(row)
            if block_id % token['mining_interval'] != 0:
                continue
            if token['last_mined_block'] == block_id:
                continue
            miners = await self.consensus.get_active_miners()
            if not miners:
                continue
            reward_per_miner = token['mining_reward'] // len(miners)
            if reward_per_miner == 0:
                continue
            for miner in miners:
                wallet = miner['wallet']
                if token['total_mined'] + reward_per_miner > token['max_mineable_supply']:
                    continue
                current = await self.token_balance_repo.get(token['address'], wallet)
                await self.token_balance_repo.set(token['address'], wallet, current + reward_per_miner)
                token['total_mined'] += reward_per_miner
                token['last_mined_block'] = block_id
                await self.token_repo.update(token)
                logger.debug(f"[TokenMining] {token['symbol']}: {reward_per_miner//SUBS} to {wallet[:16]}")

    # ─── WebSocket Messaging ──────────────────────────────────────────────
    async def send_to_miner(self, miner_id: str, message: dict) -> bool:
        ws = self.miner_websockets.get(miner_id)
        if not ws:
            logger.warning(f"[WS] No websocket for miner {miner_id}")
            return False
        try:
            await ws.send_str(json.dumps(message))
            logger.debug(f"[WS] Sent to {miner_id}: {message.get('type')}")
            return True
        except Exception as e:
            logger.error(f"[WS] Send to {miner_id} failed: {e}")
            if miner_id in self.miner_websockets:
                del self.miner_websockets[miner_id]
            return False

    # ─── Cleanup / Pruning ─────────────────────────────────────────────────
    async def cleanup_miners(self):
        timeout = ACTIVE_MINER_WINDOW_SEC
        now = time.time()
        active_miners = await self.miner_repo.get_active()
        for miner in active_miners:
            last_ping = miner.get('last_ping', 0)
            if isinstance(last_ping, float):
                age = now - last_ping
            else:
                age = (now - last_ping.timestamp()) if hasattr(last_ping, 'timestamp') else 9999
            if age > timeout:
                miner['active'] = False
                # Only ban for protocol violations, not inactivity
                # Deactivation removes from lottery; reconnection re-activates
                await self.miner_repo.update(miner)
                self.miners.pop(miner['miner_id'], None)
                # Clean up per-miner rate limiter
                self.miner_rate_limiters.pop(miner['miner_id'], None)
                # Disconnect the miner's websocket
                ws = self.miner_websockets.pop(miner['miner_id'], None)
                if ws:
                    try:
                        await ws.close(code=1000, message=b"inactive")
                    except Exception:
                        pass
                logger.info(f"[Cleanup] Deactivated inactive miner: {miner['miner_id'][:16]}... (age: {age:.0f}s)")

    async def cleanup_nodes(self):
        timeout = 600
        now = time.time()
        active_nodes = await self.node_repo.get_active()
        for node in active_nodes:
            if node.get('node_id') == self.node_id:
                continue
            last_seen = node.get('last_seen', 0)
            if isinstance(last_seen, float):
                age = now - last_seen
            else:
                age = (now - last_seen.timestamp()) if hasattr(last_seen, 'timestamp') else 9999
            if age > timeout:
                node['active'] = False
                await self.node_repo.update(node)
                logger.info(f"[Cleanup] Deactivated inactive node: {node['node_id'][:16]}... (age: {age:.0f}s)")

    # ─── Automation Loop ─────────────────────────────────────────────────────
    async def _mempool_restore(self):
        """F4: repopulate the mempool from mempool_persist after a restart."""
        try:
            rows = await self.db.fetch("SELECT tx_json FROM mempool_persist")
        except Exception as e:
            logger.warning(f"[Mempool] restore query failed: {e}")
            return
        restored = 0
        for r in rows or []:
            try:
                tx = json.loads(r['tx_json'])
            except Exception:
                continue
            tx_hash = tx.get('tx_hash')
            if not tx_hash:
                continue
            try:
                existing = await self.tx_repo.get_by_hash(tx_hash)
                if existing and existing.get('status') != 'pending':
                    # Sealed before the crash — the persisted copy is stale.
                    await self.mempool._unpersist(tx_hash)
                    continue
                if await self.mempool.add(tx):
                    restored += 1
            except Exception as e:
                logger.debug(f"[Mempool] restore skipped {str(tx_hash)[:16]}: {e}")
        if restored:
            logger.info(f"[Mempool] Restored {restored} persisted tx(s) after restart")

    async def _automation_loop(self):
        """Autonomous execution engine for smart triggers (block, interval, condition)."""
        while not self._shutdown_flag:
            await asyncio.sleep(1.0)
            try:
                active_autos = await self.automation_repo.list_active()
                now = time.time()
                for auto in active_autos:
                    trigger_type = auto.get("trigger_type")
                    t_conf = auto.get("trigger_config", {})
                    last_run = auto.get("last_run_at") or auto.get("created_at", now)
                    should_run = False

                    if trigger_type == "time_interval":
                        interval = float(t_conf.get("interval_seconds", 60))
                        if now - last_run >= interval:
                            should_run = True
                    elif trigger_type == "block":
                        target_block = int(t_conf.get("target_block", 0))
                        interval_blocks = int(t_conf.get("interval_blocks", 0))
                        if target_block > 0 and self.height >= target_block and auto.get("run_count", 0) == 0:
                            should_run = True
                        elif interval_blocks > 0:
                            # R6-automation-last-block-persist: read the
                            # persisted column. The old code mutated a
                            # transient dict copy that never survived the
                            # iteration, so the trigger fired every second.
                            last_block = int(auto.get("last_block_run", 0) or 0)
                            if self.height - last_block >= interval_blocks:
                                should_run = True
                    elif trigger_type == "condition":
                        cond_type = t_conf.get("condition_type")
                        if cond_type == "balance_below":
                            target_wallet = t_conf.get("wallet")
                            threshold = int(t_conf.get("threshold", 0))
                            bal = await self.balance_repo.get(target_wallet)
                            if bal < threshold:
                                should_run = True

                    if should_run:
                        a_conf = auto.get("action_config", {}) or {}
                        run_count = int(auto.get("run_count", 0))
                        res_msg = "success"
                        try:
                            # REST-3: this loop used to execute burn / contract_call /
                            # token_transfer via direct balance_repo and
                            # token_balance_repo writes — only THIS node's state moved,
                            # peers never saw a transaction and states diverged.
                            # Fix: each automation carries a batch of pre-signed
                            # transactions in action_config["txs"]; submit the batch
                            # entry indexed by run_count through the mempool and gossip
                            # it like any other tx. On missing/exhausted batch, bad
                            # signature or mempool rejection: record and disable.
                            pre_signed = a_conf.get("txs") or []
                            bad = None
                            if not isinstance(pre_signed, list) or run_count >= len(pre_signed):
                                bad = "Pre-signed transaction missing or exhausted"
                            else:
                                tx_data = dict(pre_signed[run_count])
                                if not tx_data.get("tx_hash"):
                                    tx_data["tx_hash"] = hash_tx(tx_data)
                                if not self._verify_tx_signature(tx_data):
                                    bad = "Pre-signed transaction failed signature verification"
                                elif not await self.mempool.add(tx_data):
                                    bad = "Pre-signed transaction rejected by mempool"
                                else:
                                    if self.p2p:
                                        await self.p2p.broadcast_transaction(tx_data)
                                    res_msg = f"Queued pre-signed tx {str(tx_data['tx_hash'])[:16]}"
                            if bad is not None:
                                res_msg = bad
                                # R6-automation-last-block-persist: persist firing height.
                                await self.automation_repo.update_run(auto["id"], now, run_count + 1, res_msg, last_block_run=self.height)
                                await self.automation_repo.set_enabled(auto["id"], False)
                                logger.warning(f"[Automation] Disabled {auto.get('name', auto['id'])}: {res_msg}")
                                continue
                        except Exception as act_err:
                            res_msg = f"Action error: {act_err}"

                        new_count = run_count + 1
                        # R6-automation-last-block-persist: persist firing height.
                        await self.automation_repo.update_run(auto["id"], now, new_count, res_msg, last_block_run=self.height)
                        logger.info(f"[Automation] Ran {auto.get('name', auto['id'])}: {res_msg}")
            except Exception as e:
                logger.debug(f"[Automation] Loop error: {e}")

    # ─── Cleanup Loop ────────────────────────────────────────────────────────
    async def _cleanup_loop(self):
        while not self._shutdown_flag:
            await asyncio.sleep(15)
            try:
                await self.cleanup_miners()
                await self.cleanup_nodes()
                max_blocks = self.config.get('consensus', {}).get('prune_blocks', 10000)
                if self.height > max_blocks:
                    prune_height = self.height - max_blocks
                    await self.db.execute_dml("DELETE FROM blocks WHERE id < ?", prune_height)
                    await self.db.execute_dml("DELETE FROM transactions WHERE block_id < ?", prune_height)
                    logger.info(f"[Cleanup] Pruned blocks and transactions older than {prune_height}")
            except Exception as e:
                logger.error(f"[Cleanup] Error: {e}")

    def get_public_key_hex(self) -> str:
        priv_int = int(self.priv, 16)
        try:
            priv_key = ec.derive_private_key(priv_int, ec.SECP256K1())
        except TypeError:
            priv_key = ec.derive_private_key(priv_int, ec.SECP256K1)
        pub = priv_key.public_key()
        x = pub.public_numbers().x.to_bytes(32, 'big')
        y = pub.public_numbers().y.to_bytes(32, 'big')
        return (b'\x04' + x + y).hex()

    # ─── Genesis ──────────────────────────────────────────────────────────
    async def ensure_genesis(self):
        """Establish chain state. Returns True when the node may produce
        (existing chain, freshly synced chain, or deliberate new genesis);
        False when it restored a verified genesis file but has not synced
        yet (production stays paused; the sync loop re-enables it on
        progress).

        GENESIS-JOIN-1: deliberate initialization and joining are separate
        operations. The old code fell through to _create_genesis() whenever
        discovery timed out — forking a silent new chain on any joining
        node that carried a copied --allow-new-genesis flag or hit a
        transiently empty peer table. Now only an explicit init operation
        creates; join mode either restores a VERIFIED local genesis file or
        refuses to boot. The database is never reset here."""
        await self.db.create_tables()
        if not self.wallet or not self.priv:
            self._setup_wallet()
            self.node_id = self.wallet

        latest = await self.block_repo.get_latest()
        if latest:
            await self._load_state()
            await self._bind_genesis_to_db()
            await self._register_self_miner()
            await self._register_self_node()
            self._genesis_handled = True
            logger.info("Loaded existing blockchain.")
            return True

        logger.info("No local blockchain. Attempting to join network via P2P...")
        default_timeout = 60
        max_discovery_time = (
            self.config.get('p2p', {}).get('discovery_timeout', default_timeout)
            if self.p2p else 0
        )
        logger.info(f"[Genesis] P2P discovery window: {max_discovery_time}s "
                    f"(override with p2p.discovery_timeout in config.yaml)")
        start = time.time()
        discovered = False
        last_peer_count = -1
        last_log_at = 0.0

        while self.p2p and (time.time() - start < max_discovery_time) and not discovered:
            for p in list(self.p2p.peers.values()):
                try:
                    asyncio.create_task(self.p2p._send_message(p, MSG_GET_STATUS, b'{}'))
                except Exception:
                    pass
            await self.p2p.sync_with_peers()
            latest = await self.block_repo.get_latest()
            if latest:
                await self._load_state()
                await self._register_self_miner()
                await self._register_self_node()
                self._genesis_handled = True
                logger.info("Synced blockchain from network.")
                return True
            peer_count = self.p2p.get_peer_count() if self.p2p else 0
            now = time.time()
            if peer_count != last_peer_count or now - last_log_at >= 5.0:
                elapsed = int(now - start)
                if self.p2p and self.p2p.peers:
                    max_remote_h = max(p.height for p in self.p2p.peers.values())
                    remote_h_str = str(max_remote_h)
                else:
                    remote_h_str = "unknown"
                logger.info(f"[Genesis] Discovery progress: {elapsed}s elapsed, "
                            f"peers={peer_count}, remote_height={remote_h_str}")
                last_peer_count = peer_count
                last_log_at = now
            await asyncio.sleep(2)

        peer_count = self.p2p.get_peer_count() if self.p2p else 0
        if getattr(self, '_allow_new_genesis', False):
            # Explicit init operation (seed node only): deliberate new chain.
            if self.p2p and peer_count == 0:
                logger.warning(
                    f"[Genesis] P2P discovery window closed with 0 peers. "
                    f"Check p2p.dns_seeds and p2p.bootstrap_nodes in config.yaml — "
                    f"they must point to a running node reachable on its P2P port. "
                    f"--allow-new-genesis is set: deliberately creating a NEW chain."
                )
            else:
                logger.info("Creating genesis block for a deliberate new chain (--allow-new-genesis).")
            await self._create_genesis()
            await self._register_self_miner()
            await self._register_self_node()
            self._genesis_handled = True
            return True
        # Join mode (no init flag): NEVER create a genesis. Either restore
        # a verified local file (identity checked before trusting anything;
        # _create_genesis re-verifies on the restore path) or refuse to
        # boot. A mismatched file is rejected, never adopted; the database
        # is never reset here.
        _local = load_genesis_file()
        if _local:
            _vok, _vwhy = genesis_export_verified(_local)
            if not _vok:
                logger.error(f"[Genesis] Local genesis.json failed verification ({_vwhy}); "
                             f"refusing to join with an untrusted identity. Copy the file from "
                             f"the network you intend to join.")
                sys.exit(1)
            await self._create_genesis()
            await self._register_self_miner()
            await self._register_self_node()
            self._genesis_handled = True
            logger.info("[Genesis] Restored verified local genesis; syncing the remaining chain "
                        "from peers (production paused until sync establishes state).")
            return False
        logger.error(
            "[Genesis] No local chain, no syncable peers, and no genesis.json. "
            "Joining nodes never create a genesis: copy genesis.json from the "
            "network you intend to join (mismatched identities are rejected), "
            "or restart with --allow-new-genesis for a DELIBERATE new chain. "
            "Refusing to boot."
        )
        sys.exit(1)

    async def _bind_genesis_to_db(self):
        """GENESIS-DBBIND-1: the identity this node ADVERTISES (genesis.json's
        declared hash, set by load_genesis_file) must be the identity of the
        chain it actually HOLDS (the persisted genesis block). Previously only
        the file was consulted: a swapped/copied genesis.json over an existing
        database made the node advertise genesis Y while holding chain X
        (peers on Y accept the handshake, then every block fails linkage), and
        a node with a database but no genesis.json would LEARN a foreign
        genesis from any bootstrap peer. Now:
          * file present  -> its hash must equal the DB genesis hash, else the
            node refuses to start (never silently picks one);
          * file missing  -> the DB genesis hash becomes the local identity, so
            the peer-learn branch (which requires an empty local identity) can
            never replace it; the missing file is reported.
        No DB genesis row (pruned/legacy) -> nothing to bind (reported)."""
        g0 = await self.block_repo.get_by_id(0)
        if not g0:
            logger.warning("[GENESIS] no persisted genesis block (id 0) to bind genesis.json against")
            return
        db_hash = str(g0.get("hash") or "").lower()
        if not db_hash:
            logger.error("[GENESIS] persisted genesis block has no hash; refusing to start")
            sys.exit(1)
        gd = load_genesis_file()
        file_hash = str((gd or {}).get("hash") or "").lower()
        if file_hash:
            if file_hash != db_hash:
                logger.error(
                    f"[GENESIS] genesis.json ({os.path.abspath(_genesis.GENESIS_FILE)}) hash {file_hash[:16]}... does NOT match "
                    f"the genesis block stored in this node's database ({db_hash[:16]}...). Refusing to start: use the "
                    f"genesis.json this database was created from, or a fresh data directory/database for the new chain.")
                sys.exit(1)
            return
        _genesis._node_genesis_hash = db_hash
        try:
            _genesis.FORK_ID = int(db_hash[:8], 16) ^ int(db_hash[8:16], 16)
        except ValueError:
            logger.error("[GENESIS] persisted genesis hash is not hex; refusing to start")
            sys.exit(1)
        logger.warning(
            f"[GENESIS] {os.path.abspath(_genesis.GENESIS_FILE)} is missing but the database holds genesis {db_hash[:16]}...; "
            f"using the database identity. Peers cannot learn genesis from this node until genesis.json is restored.")

    async def _ensure_genesis_alloc(self):
        """GENESIS-ALLOC (followers): credit the deterministic genesis
        distribution exactly once. _create_genesis applies it on the node that
        creates the chain, but nodes that join via P2P sync never run
        _create_genesis — without this hook their balances table misses the
        alloc entirely (verified: creator 211M vs followers 11M on a fresh
        chain). network_state marker 'genesis_alloc_applied' keeps it
        idempotent across restarts."""
        if await self.network_state_repo.get("genesis_alloc_applied"):
            return
        genesis_data = load_genesis_file()
        if not genesis_data:
            return  # no file yet — retry on next _load_state (marker stays unset)
        # Fix 1 (R10): never apply an unverified economic starting state
        # (fail-closed; the atomic txn below still guards crashes, but
        # only fully verified files reach it) — same verifier as every
        # other genesis path.
        _gok, _gwhy = genesis_export_verified(genesis_data)
        if not _gok:
            logger.error(f"{GREEN}[GENESIS]{RESET} refusing unverified genesis file: {_gwhy}")
            raise RuntimeError(f"genesis file failed verification: {_gwhy}")
        # R8-genesis-atomic (R7-05): credits, supply update, and the marker
        # commit in ONE outer transaction (chain reset / startup path).
        # Previously a crash after any credit but before the marker left
        # partial balances that the next startup credited AGAIN (retry adds
        # onto whatever is committed). A failure now rolls everything back;
        # the retry recomputes from committed state and converges exactly
        # once. Trie puts are memory-only and idempotent on replay.
        async with await self.db.transaction():
            alloc = genesis_data.get("alloc")
            if isinstance(alloc, dict) and alloc:
                for _addr, _amt in alloc.items():
                    _amt = int(_amt)
                    cur = await self.balance_repo.get(_addr)
                    new_bal = cur + _amt
                    await self.balance_repo.set(_addr, new_bal)
                    await self.state_trie.put(f"balance:{_addr}", new_bal)
                    self.balances[_addr] = new_bal
                gm = int(genesis_data.get("total_minted", GENESIS_SUPPLY))
                cur_m = await self.network_state_repo.get("total_minted")
                new_m = (int(cur_m) if cur_m else 0) + gm
                await self.network_state_repo.set("total_minted", str(new_m))
                self.total_minted = new_m
                logger.info(f"{GREEN}[GENESIS]{RESET} Applied genesis alloc "
                            f"(+{gm // SUBS} MCX, {len(alloc)} address(es))")
            await self.network_state_repo.set("genesis_alloc_applied", "1")

    async def _create_genesis(self):
        genesis_data = load_genesis_file()
        if not genesis_data:
            if not getattr(self, '_allow_new_genesis', False):
                logger.error(
                    f"{GREEN}[GENESIS]{RESET} No {_genesis.GENESIS_FILE} found. Start the seed node with "
                    f"--allow-new-genesis, or copy genesis.json from a running node."
                )
                raise RuntimeError("No genesis.json found. Cannot create genesis.")
            logger.info(f"{GREEN}[GENESIS]{RESET} Creating genesis block...")
            # GENESIS-ADDR-1: the genesis identity only accepts canonical
            # lowercase alloc addresses; a checksummed/mixed-case wallet used
            # to write a genesis.json that failed its own verification at the
            # next boot (and on every joining peer).
            _gw = str(self.wallet).lower()
            # GENESIS-ATOMIC-1: validate inputs BEFORE touching persistent
            # state — a bad wallet used to fail at self-verification only
            # after balances/markers were already written.
            if (len(_gw) != 42 or not _gw.startswith("0x")
                    or any(c not in "0123456789abcdef" for c in _gw[2:])):
                raise RuntimeError(f"refusing genesis creation: wallet {_gw!r} is not a canonical lowercase 0x address")
            if int(GENESIS_SUPPLY) <= 0:
                raise RuntimeError("refusing genesis creation: GENESIS_SUPPLY must be positive")
            _fresh_ruleset = _effective_consensus_ruleset()
            # Stage trie writes (memory-only puts; commit persists inside
            # the txn below).
            await self.state_trie.put("height", 0)
            await self.state_trie.put(f"balance:{_gw}", GENESIS_SUPPLY)
            genesis_ts = time.time()
            # GENESIS-ATOMIC-1: NOTHING below this point persists until the
            # payload is built and self-verified. state_root comes from the
            # pure _compute_root (no DB writes); the persisting commit() runs
            # inside the atomic txn later.
            state_root, _ = self.state_trie._compute_root()
            # Fix 1 + Fix 2 (R10): ONE canonical identity payload — header
            # fields, economic starting state (GENESIS-ALLOC: deterministic
            # distribution; without this map every restoring node credited
            # ITS OWN wallet the full supply), chain selectors, and the
            # full effective consensus ruleset. A single hash commits all
            # of it (block_dict carries the same fields, so
            # calculate_block_hash — which excludes only
            # hash/signature/pqc_signature/finalized — covers them
            # automatically). The export file IS the payload plus hash and
            # signature; legacy 16-field-hash files fail the identity layer
            # and are refused (chain reset, see R9_MIGRATION_NOTES.md).
            # MCX79: the fixed validator set rides in the identity payload
            # (GENESIS_IDENTITY_FIELDS) and the consensus record, sourced
            # from the live effective ruleset.
            _fresh_ruleset = _effective_consensus_ruleset()
            block_dict = {
                "id": 0,
                "ts": genesis_ts,
                "phash": "0" * 64,
                "miners": [],
                "reward": 0,
                "tx_count": 0,
                "merkle_root": "",
                "nonce": 0,
                "difficulty": 0,
                "version": VERSION,
                "challenge": "",
                "coverage": 0.0,
                "total_tx_value": 0,
                "total_fees": 0,
                "tx_hashes": [],
                "finalized": True,
                "state_root": state_root,
                "producer_pub": "",
                "alloc": {_gw: GENESIS_SUPPLY},
                "total_minted": GENESIS_SUPPLY,
                "chain_id": CHAIN_ID,
                "consensus": _fresh_ruleset,
                "validators": list(_fresh_ruleset["validators"]),
            }
            block_hash = calculate_block_hash(block_dict)
            block_dict["hash"] = block_hash
            block_dict["signature"] = sign_bytes(self.priv, block_signing_payload(block_dict))
            # NOTE: self.genesis_hash / _node_genesis_hash / FORK_ID flip
            # only after the atomic commit below (GENESIS-ATOMIC-1).
            genesis_export = {
                k: v for k, v in block_dict.items()
                if k not in ("finalized", "signature")
            }
            genesis_export["signature"] = block_dict["signature"]
            # GENESIS-SELFCHECK-1: never write (or serve) a genesis file that
            # this same build would refuse to boot from.
            _sok, _swhy = genesis_export_verified(json.loads(json.dumps(genesis_export)))
            if not _sok:
                logger.error(f"{GREEN}[GENESIS]{RESET} freshly built genesis FAILED self-verification: {_swhy}")
                raise RuntimeError(f"fresh genesis failed self-verification: {_swhy}")
            # GENESIS-ATOMIC-1: file FIRST (atomic tmp+replace), database
            # second (single txn). Crash windows resolve cleanly both ways:
            # file-write failure -> nothing persisted anywhere, retry is
            # clean; txn failure -> rollback leaves an empty DB beside a
            # VALID file, so restart takes the restore path and recovers.
            # In-memory mirrors and module globals flip only after commit.
            _write_genesis_file_atomic(genesis_export)
            _genesis._node_genesis_data = genesis_export
            async with await self.db.transaction():
                await self.state_trie.put("height", 0)
                await self.state_trie.put(f"balance:{_gw}", GENESIS_SUPPLY)
                _committed_root = await self.state_trie.commit()
                assert _committed_root == state_root, "genesis trie recomputation diverged"
                await self.balance_repo.set(_gw, GENESIS_SUPPLY)
                await self.network_state_repo.set("total_minted", str(GENESIS_SUPPLY))
                await self.network_state_repo.set("burned_total", "0")
                await self.network_state_repo.set("genesis_alloc_applied", "1")
                await self.block_repo.create(block_dict)
            try:
                self.state_trie.mark_committed()
            except Exception:
                pass
            self.balances[_gw] = GENESIS_SUPPLY
            self.total_minted = GENESIS_SUPPLY
            self.burned_total = 0
            self.genesis_hash = block_hash
            _genesis._node_genesis_hash = block_hash
            _genesis.FORK_ID = int(block_hash[:8], 16) ^ int(block_hash[8:16], 16)
            self.blocks.append(block_dict)
            self.height = 1
            self.last_hash = block_hash
            self._next_block_time = genesis_ts + BLOCK_TIME
        else:
            # Genesis file exists — restore genesis block into empty DB.
            # Fix 1 (R10): verify the FULL identity (hash over header +
            # economics + ruleset, economics policy, ruleset compatibility)
            # before trusting any of it (fail-closed) — the same verifier
            # as the handshake-learn and startup paths. Legacy files fail
            # the identity layer and are refused, never partially applied.
            # The legacy no-alloc self-credit fallback is REMOVED: it
            # credited a node-dependent wallet (non-canonical genesis state
            # — every node diverged). Regenerate genesis.json with the
            # current build if needed.
            _gok, _gwhy = genesis_export_verified(genesis_data)
            if not _gok:
                logger.error(f"{GREEN}[GENESIS]{RESET} refusing unverified genesis file: {_gwhy}")
                raise RuntimeError(f"genesis file failed verification: {_gwhy}")
            # MCX79: the validator set travels with the file (verified
            # above as committed identity + compatible record). Carried on
            # the in-memory genesis block for parity with the fresh path
            # (block_repo.create ignores non-column keys).
            _restored_validators = list(genesis_data["validators"])
            self.genesis_hash = genesis_data.get("hash", "")
            _genesis._node_genesis_hash = self.genesis_hash
            _genesis.FORK_ID = int(self.genesis_hash[:8], 16) ^ int(self.genesis_hash[8:16], 16)
            total_minted = int(genesis_data.get("total_minted", 0))
            self.total_minted = total_minted
            self.burned_total = 0
            alloc = genesis_data.get("alloc")
            # GENESIS-ALLOC: restore the SAME deterministic distribution on
            # every node (verified above: lowercase addrs, exact sum).
            # GENESIS-ATOMIC-2: only memory-side trie puts here; EVERY persistent
            # write (balances, supply counters, the applied-marker and block 0)
            # happens in the single transaction below, so a crash/failure at any
            # step leaves either nothing or the complete genesis — never a marker
            # or balances without block 0.
            for _addr, _amt in alloc.items():
                await self.state_trie.put(f"balance:{_addr}", int(_amt))
            await self.state_trie.put("height", 0)
            state_root = genesis_data.get("state_root")
            if not state_root:
                state_root = await self.state_trie.commit()
            genesis_block = {
                "id": 0,
                "ts": genesis_data.get("ts", time.time()),
                "phash": "0" * 64,
                "miners": [],
                "reward": 0,
                "tx_count": 0,
                "merkle_root": "",
                "nonce": 0,
                "difficulty": 0,
                "version": genesis_data.get("version", VERSION),
                "challenge": "",
                "coverage": 0.0,
                "total_tx_value": 0,
                "total_fees": 0,
                "tx_hashes": [],
                "finalized": True,
                "state_root": state_root,
                "hash": self.genesis_hash,
                "signature": "",
                "producer_pub": "",
                "validators": _restored_validators,
            }
            async with await self.db.transaction():
                for _addr, _amt in alloc.items():
                    await self.balance_repo.set(_addr, int(_amt))
                await self.network_state_repo.set("total_minted", str(total_minted))
                await self.network_state_repo.set("burned_total", "0")
                await self.network_state_repo.set("genesis_alloc_applied", "1")
                await self.block_repo.create(genesis_block)
            for _addr, _amt in alloc.items():
                self.balances[_addr] = int(_amt)
            self.blocks.append(genesis_block)
            self.height = 1
            self.last_hash = self.genesis_hash
            self._next_block_time = genesis_block["ts"] + BLOCK_TIME
            logger.info(f"{GREEN}[GENESIS]{RESET} Restored genesis block from {_genesis.GENESIS_FILE} (hash={self.genesis_hash[:16]}...)")
            assert self.height == 1 and self.last_hash, "genesis restore failed"

    # ─── Self Registration ──────────────────────────────────────────────
    async def _register_self_miner(self):
        miner_id = "PC_" + hashlib.sha256(f"{self.wallet}_mcx_miner".encode()).hexdigest()[:32].upper()
        self.miner_id = miner_id
        existing = await self.miner_repo.get(miner_id)
        if existing:
            existing['last_ping'] = time.time()
            existing['active'] = True
            existing['confirmed_balance'] = await self.balance_repo.get(self.wallet)
            await self.miner_repo.update(existing)
            logger.info(f"{GREEN}[SELF MINER]{RESET} Miner {miner_id[:16]}... already registered, updated.")
            return
        encrypted = self.config.get('private_key_encrypted', '')
        miner = {
            'miner_id': miner_id,
            'wallet': self.wallet,
            'pub': self.pub,
            'uptime': 0,
            'today_uptime': 0,
            'last_ping': time.time(),
            'active': True,
            'rewards': 0,
            'blocks': 0,
            'slashes': 0,
            'type': 'pc',
            'created_at': time.time(),
            'version': VERSION,
            'confirmed_balance': await self.balance_repo.get(self.wallet),
            'password_hash': bcrypt.hashpw(self.password.encode(), bcrypt.gensalt()).decode() if self.password else "",
            'private_key_encrypted': encrypted,
            'maze_wins': 0
        }
        await self.miner_repo.create(miner)
        self.miners[miner_id] = miner
        logger.info(f"{GREEN}[SELF MINER]{RESET} Registered miner {miner_id[:16]}... with wallet {self.wallet[:16]}...")
        self.miner_id = miner_id

    async def _register_self_node(self):
        node_id = self.wallet
        existing = await self.node_repo.get(node_id)
        if existing:
            existing['active'] = True
            existing['mining_enabled'] = self._producing_enabled
            existing['staking_enabled'] = self._producing_enabled
            existing['last_seen'] = time.time()
            await self.node_repo.update(existing)
            await self.node_repo.update_height(node_id, self.height)
            logger.info(f"{GREEN}[SELF NODE]{RESET} Node {node_id[:16]}... already registered.")
            return
        node = {
            'node_id': node_id,
            'wallet': self.wallet,
            'ip': EXTERNAL_IP or '0.0.0.0',
            'port': WS_PORT,
            'last_seen': time.time(),
            'height': self.height,
            'active': True,
            'rewards_earned': 0,
            'version': VERSION,
            'mining_enabled': self._producing_enabled,
            'staking_enabled': self._producing_enabled,
            'last_sync': time.time(),
            'is_multisig_signer': False,
            'public_key': self.get_public_key_hex()
        }
        await self.node_repo.create(node)
        logger.info(f"{GREEN}[SELF NODE]{RESET} Registered node ID: {node_id[:16]}...")

    # ─── Shutdown ──────────────────────────────────────────────────────────
    async def shutdown(self):
        if self._shutdown_flag:
            return
        self._shutdown_flag = True
        logger.info("[Node] Shutting down...")

        # Stop producing first so we don't race the drain
        self._producing_enabled = False

        # Cancel every long-lived task synchronously (before any await) so no
        # background loop can run — and log — between the first two lines of
        # the Section 9.4 shutdown tail: "[Node] Shutting down..." must be
        # immediately followed by the mempool drain line.
        _early: list = [getattr(self, n, None) for n in
                        ('_production_task', '_node_cleanup_task',
                         '_automation_task', '_miner_task')]
        if self.p2p:
            _early += list(getattr(self.p2p, '_bg_tasks', []))
            _early += list(self.p2p._conn_tasks)
            _prune = getattr(self.p2p, '_prune_task', None)
            if _prune is not None:
                _early.append(_prune)
        for _t in _early:
            if _t is not None and not _t.done():
                _t.cancel()
        for _t in _early:
            if _t is None:
                continue
            try:
                await _t
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        # Graceful mempool drain: give in-flight txs a bounded window to land
        try:
            drained = await self.mempool.drain(timeout=30.0)
            if drained:
                logger.info("[Node] Mempool drained cleanly")
        except Exception as e:
            logger.warning(f"[Node] Mempool drain error: {e}")

        if hasattr(self, '_ws_task') and not self._ws_task.done():
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass

        for ws in self.miner_websockets.values():
            try:
                await ws.close()
            except Exception:
                pass
        self.miner_websockets.clear()

        if self.p2p:
            await self.p2p.shutdown()

        # Cancel the mempool's cleanup loop so it does not touch the DB after close
        if self.mempool._cleanup_task and not self.mempool._cleanup_task.done():
            self.mempool._cleanup_task.cancel()
            try:
                await self.mempool._cleanup_task
            except asyncio.CancelledError:
                pass

        # Same for the rate limiters' cleanup loops
        for _rl in (self.rate_limiter, self.subnet_rate_limiter,
                    self.register_rate_limiter, self.rpc_rate_limiter):
            _ct = getattr(_rl, '_cleanup_task', None)
            if _ct is not None and not _ct.done():
                _ct.cancel()
                try:
                    await _ct
                except asyncio.CancelledError:
                    pass
                except Exception:
                    pass

        if self.vm_manager:
            self.vm_manager.close()
        await self.db.close()
        logger.info("[Node] Shutdown complete.")

    # ─── Embedded Miner ──────────────────────────────────────────────────
    async def _start_embedded_miner(self):
        """In-process miner that connects to the local WS and navigates mazes."""
        if not self.config.get('node', {}).get('embedded_miner'):
            return
        miner_id = getattr(self, 'miner_id', None)
        if not miner_id:
            return
        ws_port = self.config.get('node', {}).get('ws_port', WS_PORT)
        url = f"ws://127.0.0.1:{ws_port}/ws"
        logger.info(f"[EMBEDDED MINER] Starting for {miner_id[:16]}... connecting to {url}")
        self._miner_task = asyncio.create_task(self._embedded_miner_loop(url, miner_id))

    async def _embedded_sign_block(self, ws, data, miner_id):
        """Sign an unsigned block from the node's produce_block request."""
        try:
            block = data.get("block") or {
                "id": data.get("height"), "phash": data.get("prev_hash"),
                "winner": miner_id, "miners": data.get("miners", []),
                "tx_hashes": data.get("pending_txs", []),
                "maze_attestation": data.get("maze_attestation", {}),  # IDEA5-ATTEST
                "timestamp": time.time(), "nonce": 0,
            }
            block["producer_pub"] = self.pub
            block["hash"] = hashlib.sha256(canonical_json_bytes(
                {k: v for k, v in block.items() if k not in CONSENSUS_EXCLUDED_FIELDS}
            )).hexdigest()
            block["signature"] = sign_bytes(self.priv, bytes.fromhex(block["hash"]))
            await ws.send(json.dumps({"type": "block_signed", "miner_id": miner_id, "block": block}))
            logger.info(f"[EMBEDDED MINER] Signed block #{block.get('id')} hash={block['hash'][:16]}...")
        except Exception as e:
            logger.error(f"[EMBEDDED MINER] Block signing failed: {e}")

    async def _embedded_recv(self, ws, miner_id, timeout=10):
        """Recv one message, handling produce_block inline wherever we're waiting."""
        deadline = time.time() + timeout
        while True:
            remaining = max(0.1, deadline - time.time())
            raw = await asyncio.wait_for(ws.recv(), timeout=remaining)
            data = json.loads(raw)
            if data.get("type") == "produce_block":
                await self._embedded_sign_block(ws, data, miner_id)
                continue
            if data.get("type") in ("block_height_update", "block_accepted", "wallet_update"):
                continue
            return data

    async def _embedded_miner_loop(self, url, miner_id):
        """Reconnect loop for the embedded miner."""
        while True:
            try:
                async with websockets.connect(url, ping_interval=20, ping_timeout=60,
                                              close_timeout=10, max_size=2**24) as ws:
                    # Register
                    ts = int(time.time())
                    sig_data = f"{miner_id}{self.wallet}{ts}"
                    sig = sign_message(self.priv, sig_data)
                    await ws.send(json.dumps({
                        "type": "register",
                        "miner_id": miner_id,
                        "wallet": self.wallet,
                        "public_key": self.pub,
                        "signature": sig,
                        "timestamp": ts,
                        "miner_type": "pc",
                        "maze_id": self.pub,
                    }))
                    # Wait for registered or memory_challenge
                    while True:
                        resp = await self._embedded_recv(ws, miner_id, timeout=30)
                        if resp.get("type") == "registered":
                            break
                        if resp.get("type") == "memory_challenge_request":
                            seed = base64.b64decode(resp["seed"])
                            mem_size = resp.get("memory_size", 8 * 1024 * 1024)
                            h = hashlib.sha256()
                            counter = 0
                            while h.digest_size * counter < mem_size:
                                h.update(hashlib.sha256(seed + counter.to_bytes(8, "big")).digest())
                                counter += 1
                            await ws.send(json.dumps({
                                "type": "memory_challenge_response",
                                "miner_id": miner_id,
                                "seed": resp["seed"],
                                "commitment": base64.b64encode(h.digest()).decode(),
                            }))
                            continue
                        if resp.get("type") == "registration_failed":
                            logger.error(f"[EMBEDDED MINER] Registration failed: {resp}")
                            break

                    logger.info(f"[EMBEDDED MINER] Registered. Waiting for maze...")
                    # Wait for maze_init
                    maze_data = None
                    while True:
                        data = await self._embedded_recv(ws, miner_id, timeout=120)
                        if data.get("type") == "maze_init":
                            maze_data = data
                            break
                        if data.get("type") == "maze_move_ack":
                            pass  # ignore during wait

                    if not maze_data:
                        await asyncio.sleep(5)
                        continue

                    await self._embedded_mine_round(ws, miner_id, maze_data)

            except Exception as e:
                logger.warning(f"[EMBEDDED MINER] Connection error: {e}")
            await asyncio.sleep(5)

    async def _embedded_mine_round(self, ws, miner_id, maze_data):
        """Navigate a single maze round using BFS."""
        maze = maze_data["maze"]
        size = maze_data["size"]
        start = tuple(maze_data["start"])
        goal = tuple(maze_data["goal"])
        block_id = maze_data.get("block_id", 0)
        movenonce = int(maze_data.get("movenonce", 0))
        mazeversion = int(maze_data.get("growthcount", 0))

        DIRS = [(1,0,0,"east"),(-1,0,0,"west"),(0,1,0,"north"),(0,-1,0,"south"),(0,0,1,"up"),(0,0,-1,"down")]

        async def resync_state():
            """Adopt the server's authoritative maze state after any divergence."""
            nonlocal maze, size, start, goal, cur, movenonce, mazeversion
            await ws.send(json.dumps({"type": "get_maze_state", "miner_id": miner_id, "maze_id": self.pub}))
            deadline = time.time() + 10
            while time.time() < deadline:
                try:
                    data = await self._embedded_recv(ws, miner_id, timeout=max(0.1, deadline - time.time()))
                except asyncio.TimeoutError:
                    return False
                if data.get("type") == "maze_state" and data.get("state"):
                    st = data["state"]
                    maze = st["maze"]
                    size = int(st["size"])
                    start = tuple(st["position"])
                    cur = tuple(st["position"])
                    goal = tuple(st["goal"])
                    movenonce = int(st["movenonce"])
                    mazeversion = int(st["growthcount"])
                    logger.info(f"[EMBEDDED MINER] State resynced: size={size} pos={cur} nonce={movenonce} growth={mazeversion}")
                    return True
            return False

        cur = start
        while True:
            visited = set()
            parent = {}
            queue = deque([cur])
            visited.add(cur)
            found = False
            while queue:
                cx, cy, cz = queue.popleft()
                if (cx, cy, cz) == goal:
                    found = True
                    break
                for dx, dy, dz, _ in DIRS:
                    nx, ny, nz = cx+dx, cy+dy, cz+dz
                    if 0 <= nx < size and 0 <= ny < size and 0 <= nz < size:
                        if maze[nz][ny][nx] == 0 and (nx, ny, nz) not in visited:
                            visited.add((nx, ny, nz))
                            parent[(nx, ny, nz)] = (cx, cy, cz)
                            queue.append((nx, ny, nz))

            if not found:
                logger.warning(f"[EMBEDDED MINER] No path to goal, waiting...")
                await asyncio.sleep(5)
                return

            # Reconstruct path from goal back to the BFS root (current position)
            path = []
            node = goal
            bfs_root = cur
            while node != bfs_root:
                path.append(node)
                node = parent[node]
            path.reverse()

            if not path:
                # cur == goal locally (divergent state): this round cannot advance
                # by moving. Every exit must yield an await — a tight loop here
                # starves the event loop and freezes the whole node.
                if not await resync_state() or cur == goal:
                    await asyncio.sleep(1)
                    return
                continue

            for step_pos in path:
                dx = step_pos[0] - cur[0]
                dy = step_pos[1] - cur[1]
                dz = step_pos[2] - cur[2]
                direction = None
                for sdx, sdy, sdz, sname in DIRS:
                    if sdx == dx and sdy == dy and sdz == dz:
                        direction = sname
                        break
                if not direction:
                    logger.info(f"[EMBEDDED MINER] No direction to {step_pos} from {cur} — replanning")
                    break

                sent_nonce = movenonce + 1
                auth_msg = canonical_json_bytes({
                    "domain": "MCXPOGMOVEV1",
                    "chainid": CHAIN_ID,
                    "minerid": miner_id,
                    "mazeid": self.pub,
                    "mazeversion": mazeversion,
                    "movenonce": sent_nonce,
                    "direction": direction,
                })
                sig = sign_bytes(self.priv, auth_msg)
                await ws.send(json.dumps({
                    "type": "maze_move",
                    "miner_id": miner_id,
                    "maze_id": self.pub,
                    "direction": direction,
                    "signature": sig,
                    "move_nonce": sent_nonce,
                }))
                try:
                    ack = await self._embedded_recv(ws, miner_id, timeout=10)
                except asyncio.TimeoutError:
                    logger.warning(f"[EMBEDDED MINER] Move timeout")
                    return

                # MOVE-ACK-REFRESH: adopt the server's authoritative counters on
                # every ack (success or failure). The signer previously only
                # refreshed mazeversion in resync_state(), so once the server's
                # growthcount moved ahead every subsequent move failed
                # signature verification ([SIG FAIL] storm) until a resync
                # happened to fire.
                if isinstance(ack, dict):
                    if ack.get("movenonce") is not None:
                        movenonce = int(ack["movenonce"])
                    if ack.get("growthcount") is not None:
                        mazeversion = int(ack["growthcount"])

                if ack.get("type") == "wall_hit":
                    logger.info(f"[EMBEDDED MINER] Wall hit received (difficulty={ack.get('difficulty')})")
                    if ack.get("movenonce") is not None:
                        movenonce = int(ack["movenonce"])
                    seed = ack.get("seed")
                    difficulty = ack.get("difficulty", POW_BASE_DIFFICULTY)
                    nonce = await self._embedded_solve_pow(seed, difficulty)
                    await ws.send(json.dumps({
                        "type": "wall_hit_solve",
                        "miner_id": miner_id,
                        "maze_id": self.pub,
                        "nonce": nonce,
                    }))
                    try:
                        sol_ack = await self._embedded_recv(ws, miner_id, timeout=10)
                    except asyncio.TimeoutError:
                        logger.warning(f"[EMBEDDED MINER] wall solve timeout")
                        return
                    if not sol_ack.get("accepted"):
                        break
                    if sol_ack.get("movenonce") is not None:
                        movenonce = int(sol_ack["movenonce"])
                    if sol_ack.get("caught"):
                        await resync_state()
                        logger.info("[EMBEDDED MINER] Caught during wall solve - state resynced")
                        break
                    await resync_state()
                    break

                if ack.get("type") == "maze_move_ack" and ack.get("success"):
                    st = ack.get("state", {})
                    movenonce = int(st.get("movenonce", sent_nonce))
                    cur = tuple(st.get("position", step_pos))
                    if st.get("goal"):
                        goal = tuple(st["goal"])
                    if st.get("goal_moved"):
                        break
                    if st.get("caught"):
                        if ack.get("maze"):
                            maze = ack["maze"]
                            size = int(ack.get("size", size))
                            start = tuple(ack.get("start", cur))
                            cur = start
                            goal = tuple(ack.get("goal", goal))
                            mazeversion = int(st.get("new_growthcount", mazeversion))
                            logger.info(f"[EMBEDDED MINER] Goal caught! Maze grew to {size}³")
                        else:
                            await resync_state()
                            logger.info("[EMBEDDED MINER] Caught (ghost) - state resynced")
                        break
                else:
                    msg = ack.get("message") or ""
                    if msg.startswith("Nonce mismatch"):
                        try:
                            expected = int(msg.split("expected")[1].split(",")[0].strip())
                            movenonce = expected - 1
                            logger.info(f"[EMBEDDED MINER] Nonce resync -> {movenonce}")
                        except Exception:
                            await resync_state()
                    else:
                        st = ack.get("state") or {}
                        logger.info(f"[EMBEDDED MINER] Move rejected: type={ack.get('type')} msg={msg} state={st}")
                        if st.get("position"):
                            cur = tuple(st["position"])
                            break
                        await resync_state()
                    break

    @staticmethod
    async def _embedded_solve_pow(seed, difficulty):
        nonce = 0
        while True:
            data = f"{seed}{nonce}".encode()
            digest = hashlib.sha256(data).digest()
            if int.from_bytes(digest, 'big') >> (256 - difficulty) == 0:
                return nonce
            nonce += 1

    # ─── HTTP/WebSocket Server ─────────────────────────────────────────────
    async def _run_websocket(self):
        from aiohttp import web, WSMsgType
        from aiohttp.web import Application, Request, Response, WebSocketResponse

        @web.middleware
        async def cors_middleware(request, handler):
            if request.method == 'OPTIONS':
                resp = Response(status=204)
            else:
                resp = await handler(request)
            # CORS fix: loopback-only origins (no wildcard)
            origin = request.headers.get('Origin')
            if _cors_origin_allowed(origin):
                resp.headers['Access-Control-Allow-Origin'] = origin
                resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
                resp.headers['Access-Control-Allow-Headers'] = 'Content-Type'
            return resp

        app = Application(middlewares=[cors_middleware])

        async def websocket_handler(request):
            ws = WebSocketResponse(heartbeat=60)
            await ws.prepare(request)
            client_ip = request.remote
            set_trace_id(f"ws-{new_trace_id()}")
            logger.info(f"[WS] New connection from {client_ip}")
            miner_id = None
            try:
                async for msg in ws:
                    if msg.type == WSMsgType.TEXT:
                        try:
                            data = json.loads(msg.data)
                            if not isinstance(data, dict):
                                await ws.send_json({"type": "error", "message": "Invalid message"})
                                continue
                            msg_type = data.get("type")
                            session = self.ws_sessions.get(ws)
                            if msg_type == "enc" and session and "pqe_key" in session:
                                try:
                                    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                                    ct = bytes.fromhex(data.get("ct", ""))
                                    nonce = bytes.fromhex(data.get("nonce", ""))
                                    plain = _AESGCM(session["pqe_key"]).decrypt(nonce, ct, None)
                                    data = json.loads(plain.decode("utf-8"))
                                    msg_type = data.get("type")
                                except Exception as e:
                                    logger.warning(f"[WS] PQE decrypt error: {e}")
                                    continue
                            if msg_type == "ping":
                                await ws.send_json({"type": "pong", "timestamp": time.time()})
                                continue
                            # Rate-limit all WS messages EXCEPT the mining path.
                            # Mining-related types are intentionally unlimited:
                            #   - maze_move: nonce gate in process_move is the real defense
                            #   - wall_hit_solve: gated by _pending_pow; one accepted per wall hit
                            #   - block_signed/memory_challenge_response: single-accept handshake steps
                            # R4-uptime-ping-limit: uptime_ping removed (flood
                            # vector; the embedded miner never sends it).
                            # get_balance/get_maze_state removed too: the
                            # embedded miner sends get_maze_state only on
                            # divergence (resync_state, await-gated) and never
                            # sends get_balance in a loop, so neither needs
                            # exemption. Per-IP rate limiting still applies to
                            # every other message type.
                            _rate_exempt = msg_type in ("enc", "maze_move", "wall_hit_solve", "block_signed", "memory_challenge_response")
                            if not _rate_exempt:
                                allowed = await self.rate_limiter.is_allowed(client_ip)
                                if not allowed:
                                    await ws.send_json({"type": "error", "message": "Rate limit exceeded"})
                                    continue
                            await self._handle_ws_message(ws, data, client_ip)
                            if data.get("miner_id") and not miner_id:
                                miner_id = data["miner_id"]
                        except json.JSONDecodeError:
                            await ws.send_json({"type": "error", "message": "Invalid JSON"})
                        except Exception as e:
                            if not self._shutdown_flag:
                                logger.error(f"[WS] Handler error: {e}", exc_info=True)
                            try:
                                await ws.send_json({"type": "error", "message": str(e)})
                            except Exception:
                                pass
                    elif msg.type == WSMsgType.ERROR:
                        logger.debug(f"[WS] Connection error: {ws.exception()}")
            except Exception as e:
                if not self._shutdown_flag:
                    logger.error(f"[WS] Connection error: {e}")
            finally:
                _sess = self.ws_sessions.pop(ws, None)
                if _sess:
                    for _t in _sess.get("tasks", set()):
                        if not _t.done():
                            _t.cancel()
                if ws.closed and not self._shutdown_flag:
                    logger.info(f"[WS] Connection closed: code={ws.close_code}")
                if miner_id and self.miner_websockets.get(miner_id) is ws:
                    del self.miner_websockets[miner_id]
            return ws

        # R4-ws-rpc-split: the miner WS rides its own public app; every
        # other route registered below stays on `app` (the loopback API
        # app). MCX72 invariant preserved: /rpc never rides 0.0.0.0.
        app_ws = _ws_app_routes(Application(middlewares=[cors_middleware]),
                                websocket_handler)

        async def rpc_handler(request):
            # R6-rpc-error-id: default before the try so the -32603 handler
            # below echoes the request id (None when the body never parsed,
            # which is spec-legal) instead of a hardcoded 1 — and never
            # raises NameError when the failure precedes req_id assignment.
            req_id = None
            try:
                if request.method == 'GET':
                    # R6-eth-blocknumber: latest sealed = height - 1
                    # (self.height is the NEXT block height).
                    return web.json_response({"jsonrpc":"2.0","id":1,"result":hex(self.height - 1 if self.height > 0 else 0)})
                try:
                    body = await request.json()
                except Exception:
                    return web.json_response({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error"},"id":None})
                if not body:
                    return web.json_response({"jsonrpc":"2.0","error":{"code":-32700,"message":"Parse error: empty body"},"id":None})
                method = body.get('method')
                params = body.get('params', [])
                req_id = body.get('id', 1)

                # RPC-AUTH-1: POST /rpc requires the operator bearer token
                # for non-loopback clients (loopback always trusted, so
                # local wallets/tools work with no token). State-changing
                # REST routes keep their per-request signature auth instead.
                if not _rpc_remote_authorized(request, self.config):
                    return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32001, "message": "RPC unauthorized: non-loopback clients must present the configured bearer token (MCX_RPC_TOKEN / node.rpc_token)"}})

                # Rate limit heavy RPC calls per IP
                HEAVY_METHODS = {'eth_call', 'eth_estimateGas', 'eth_getLogs', 'debug_traceTransaction'}
                if method in HEAVY_METHODS:
                    client_ip = request.remote or '127.0.0.1'
                    if not await self.rpc_rate_limiter.is_allowed(client_ip):
                        return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32005, "message": "Rate limit exceeded for heavy RPC calls"}})

                if method == 'eth_chainId':
                    result = hex(CHAIN_ID)
                elif method == 'net_version':
                    result = str(CHAIN_ID)
                elif method == 'web3_clientVersion':
                    result = 'Munex/v0.6.3/python'
                elif method == 'net_listening':
                    result = True
                elif method == 'net_peerCount':
                    result = hex(len(self.p2p.peers)) if self.p2p else '0x0'
                elif method == 'eth_syncing':
                    result = False
                elif method == 'eth_blockNumber':
                    # R6-eth-blocknumber: latest sealed = height - 1
                    # (self.height is the NEXT block height).
                    result = hex(self.height - 1 if self.height > 0 else 0)
                elif method == 'mcx_getBurnedTotal':
                    result = {
                        "burned_total_subunits": hex(self.burned_total),
                        "burned_total_mcx": self.burned_total // SUBS,
                        "total_minted_mcx": self.total_minted // SUBS,
                        "circulating_supply_mcx": (self.total_minted - self.burned_total) // SUBS
                    }
                elif method == 'eth_getBalance':
                    addr = params[0] if params else ''
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    bal = await self.get_balance(addr.lower())
                    result = hex(bal)
                elif method == 'eth_getTransactionCount':
                    addr = params[0] if params else ''
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    addr = addr.lower()
                    confirmed = await self._get_confirmed_nonce(addr)
                    pending = self.mempool.get_nonce(addr)
                    nonce = max(confirmed, pending)
                    result = hex(nonce)
                elif method == 'eth_gasPrice':
                    result = hex(_config.GAS_PRICE)
                elif method == 'eth_maxPriorityFeePerGas':
                    result = hex(_config.GAS_PRICE // 2)
                elif method == 'eth_feeHistory':
                    # R6-eth-fee-history-honest, path (b): no per-block fee
                    # history is retained (no block gas meter, no priority
                    # fees), so report absence instead of the old fabricated
                    # ten-entry response. eth_gasPrice covers wallets.
                    return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "eth_feeHistory is not supported by this node"}})
                elif method == 'eth_getCode':
                    addr = params[0] if params else ''
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    contract = await self.contract_v2_repo.get(addr)
                    result = '0x' + contract['bytecode'] if contract else '0x'
                elif method == 'eth_getStorageAt':
                    addr = params[0] if params else ''
                    # R6-eth-storage-at: accept decimal or 0x keys (the old
                    # int(x, 16) crashed on decimal input) and always return
                    # a full 32-byte word (the old hex() stripped leading
                    # zeros into a short word).
                    _raw = params[1] if len(params) > 1 else "0"
                    try:
                        key = int(_raw, 16) if str(_raw).startswith("0x") else int(_raw)
                    except (TypeError, ValueError):
                        return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid storage key"}})
                    if not addr.startswith('0x'):
                        addr = '0x' + addr
                    val = await self.contract_storage_v2_repo.get(addr, str(key))
                    if val:
                        result = "0x" + int(val, 16).to_bytes(32, "big").hex()
                    else:
                        result = "0x" + "0" * 64
                elif method == 'eth_call':
                    tx_obj = params[0] if params else {}
                    from_addr = tx_obj.get('from', '0x0000000000000000000000000000000000000000')
                    to_addr = tx_obj.get('to', '')
                    data = tx_obj.get('data') or tx_obj.get('input') or '0x'
                    try:
                        value = int(tx_obj.get('value', '0x0'), 16) if isinstance(tx_obj.get('value'), str) else int(tx_obj.get('value', 0))
                        gas_limit = int(tx_obj.get('gas', '0x' + hex(_config.GAS_LIMIT_DEFAULT)[2:]), 16) if isinstance(tx_obj.get('gas'), str) else int(tx_obj.get('gas', _config.GAS_LIMIT_DEFAULT))
                    except (TypeError, ValueError):
                        return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid value/gas"}})
                    if not to_addr:
                        result = '0x'
                    else:
                        try:
                            input_data = bytes.fromhex(data[2:]) if data.startswith('0x') else b''
                        except ValueError:
                            return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid hex input"}})
                        success, ret, gas_used, logs = await self.vm_manager.execute(to_addr, caller=from_addr, origin=from_addr, value=value, gas_limit=gas_limit, input_data=input_data, static=True)
                        result = '0x' + ret.hex() if success else '0x'
                elif method == 'eth_estimateGas':
                    tx_obj = params[0] if params else {}
                    from_addr = tx_obj.get('from', '0x0000000000000000000000000000000000000000')
                    to_addr = tx_obj.get('to', '')
                    data = tx_obj.get('data') or tx_obj.get('input') or '0x'
                    value = int(tx_obj.get('value', '0x0'), 16) if isinstance(tx_obj.get('value'), str) else tx_obj.get('value', 0)
                    gas_limit = _config.GAS_LIMIT_DEFAULT * 10
                    if not to_addr:
                        bytecode = data[2:] if data.startswith('0x') else data
                        input_data = bytes.fromhex(bytecode) if bytecode else b''
                        nonce = await self._get_confirmed_nonce(from_addr)
                        contract_addr = compute_contract_address(from_addr, nonce)
                        success, ret, gas_used, logs = await self.vm_manager.execute(contract_addr, caller=from_addr, origin=from_addr, value=value, gas_limit=gas_limit, input_data=input_data, static=True)
                        # R6-eth-estimate-gas-success: a reverting build has
                        # no valid estimate (was: returned one anyway).
                        if not success:
                            return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "execution reverted"}})
                        result = hex(max(53000, gas_used + 21000))
                    else:
                        try:
                            input_data = bytes.fromhex(data[2:]) if data.startswith('0x') and len(data) > 2 else b''
                        except ValueError:
                            return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32602, "message": "Invalid hex input"}})
                        if not input_data:
                            result = hex(21000)
                        else:
                            success, ret, gas_used, logs = await self.vm_manager.execute(to_addr, caller=from_addr, origin=from_addr, value=value, gas_limit=gas_limit, input_data=input_data, static=True)
                            # R6-eth-estimate-gas-success: same success gate
                            # for the call branch.
                            if not success:
                                return web.json_response({"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "execution reverted"}})
                            result = hex(max(21000, gas_used + 10000))
                elif method == 'eth_sendRawTransaction':
                    raw_tx = params[0] if params else ''
                    if not raw_tx or not raw_tx.startswith('0x'):
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid raw tx"}, "id": req_id})
                    try:
                        decoded = decode_raw_eth_transaction(raw_tx)
                    except Exception as e:
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32602, "message": f"Decode error: {str(e)}"}, "id": req_id})
                    # R8-chain-id: same predicate as consensus (rejects
                    # wrong-chain AND legacy-unprotected).
                    if not _raw_chain_id_ok(decoded):
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid chain ID"}, "id": req_id})
                    from_addr = (decoded.get('from') or '').lower()
                    if not from_addr:
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid sender recovery from raw tx"}, "id": req_id})
                    to = (decoded.get('to') or '').lower()
                    value = int(decoded.get('value', 0))
                    gas = int(decoded.get('gas', 21000))
                    gasPrice = int(decoded.get('gasPrice', 0))
                    if gas < 21000 or gas > _config.GAS_LIMIT_DEFAULT * 10 or gasPrice < 0 or value < 0:
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid gas, gasPrice, or value"}, "id": req_id})
                    maxFee = gas * gasPrice
                    total = value + maxFee
                    bal = await self.get_balance(from_addr)
                    if bal < total:
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32000, "message": "insufficient funds"}, "id": req_id})
                    confirmed_nonce = await self._get_confirmed_nonce(from_addr)
                    if decoded['nonce'] < confirmed_nonce:
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32000, "message": "nonce too low"}, "id": req_id})
                    # Allow nonce gaps up to 10 ahead of confirmed (mempool queuing)
                    pending_nonce = self.mempool.get_nonce(from_addr)
                    max_pending = max(confirmed_nonce, pending_nonce) if pending_nonce else confirmed_nonce
                    if decoded['nonce'] > max_pending + 10:
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32000, "message": "nonce too far ahead (max gap: 10)"}, "id": req_id})
                    tx_hash = decoded['hash']
                    tx_data = {
                        'tx_hash': tx_hash,
                        'from_wallet': from_addr,
                        'to_wallet': to if to else '0x' + '0'*40,
                        'value': value,
                        'fee': maxFee,
                        'nonce': decoded['nonce'],
                        'timestamp': time.time(),
                        'signature': raw_tx,
                        'data': decoded.get('data', ''),
                        'gas': gas,
                        'gasPrice': gasPrice,
                        'tx_type': 'contract_deploy' if not to else 'contract_call' if decoded.get('data') and len(decoded['data']) > 0 else 'send'
                    }
                    # RPC-VERIFY-1 (mainnet audit): run the same signature
                    # + field-binding check as every other ingress path
                    # (chain binding, body agreement, hash equality) instead
                    # of relying on RLP recovery alone.
                    if not self._verify_tx_signature(tx_data):
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32602, "message": "Invalid transaction signature"}, "id": req_id})
                    if await self.mempool.add(tx_data):
                        await self.p2p.broadcast_transaction(tx_data)
                        result = tx_hash
                    else:
                        return web.json_response({"jsonrpc": "2.0", "error": {"code": -32000, "message": "mempool full"}, "id": req_id})
                elif method == 'eth_getTransactionByHash':
                    tx_hash = params[0] if params else ''
                    tx = await self.tx_repo.get_by_hash(tx_hash)
                    if tx:
                        # RPC-RECEIPT-1: blockHash/blockNumber must reference the
                        # tx's OWN block, not the node's current tip. A row whose
                        # block is not sealed yet (execute-before-seal window)
                        # must still report as pending. amount may be absent on
                        # pending rows (set at execute time).
                        _blk = await self.block_repo.get_by_id(tx['block_id']) if tx['block_id'] >= 0 else None
                        _amt = tx.get('amount', tx.get('value', 0))
                        # R8-rpc-meta (R7-23): real v/r/s for raw txs (null
                        # for native — no eth recovery id exists); real
                        # transactionIndex from the sealed block's list.
                        _v, _r, _s = _eth_sig_fields(tx)
                        _txl = []
                        try:
                            _txh = (_blk.get('tx_hashes', '') if _blk else '')
                            _txl = json.loads(_txh) if isinstance(_txh, str) else (_txh or [])
                        except Exception:
                            _txl = []
                        _tidx = _txl.index(tx['tx_hash']) if tx['tx_hash'] in _txl else 0
                        result = {'hash': tx['tx_hash'], 'nonce': hex(tx['nonce']), 'blockHash': ('0x'+_blk['hash']) if _blk else None, 'blockNumber': hex(tx['block_id']) if _blk else None, 'transactionIndex': hex(_tidx) if _blk else None, 'from': tx['from_wallet'], 'to': tx['to_wallet'], 'value': hex(_amt), 'gas': hex(tx.get('gas', _config.GAS_LIMIT_DEFAULT)), 'gasPrice': hex(tx.get('gasPrice', _config.GAS_PRICE)), 'input': tx_data_to_hex(tx.get('data', '0x')), 'v': _v, 'r': _r, 's': _s}
                    else:
                        result = None
                elif method == 'eth_getTransactionReceipt':
                    tx_hash = params[0] if params else ''
                    receipt = await self.receipt_repo.get(tx_hash)
                    result = None
                    if receipt:
                        # RPC-RECEIPT-1: a receipt is only final once its block is
                        # sealed. Return null while the block is missing (the
                        # producer writes receipts at execute time, before the
                        # miner sign roundtrip seals the block), and when the
                        # block exists report THAT block's hash — not the tip.
                        _blk = await self.block_repo.get_by_id(receipt['block_id'])
                        if _blk:
                            tx = await self.tx_repo.get_by_hash(tx_hash)
                            # R8-rpc-meta (R7-23): real transactionIndex (block
                            # order), real cumulative gas, real logs bloom
                            # (was: constant index/bloom, cumulative==gas).
                            _txl2 = []
                            try:
                                _txh2 = _blk.get('tx_hashes', '')
                                _txl2 = json.loads(_txh2) if isinstance(_txh2, str) else (_txh2 or [])
                            except Exception:
                                _txl2 = []
                            _tidx2 = _txl2.index(tx_hash) if tx_hash in _txl2 else 0
                            _ord = []
                            try:
                                _rq = "SELECT tx_hash, gas_used FROM transaction_receipts WHERE block_id = ?" if self.db.db_type == "sqlite" else "SELECT tx_hash, gas_used FROM transaction_receipts WHERE block_id = $1"
                                _rrows = await self.db.fetch(_rq, receipt['block_id'])
                                _bymap = {str(_r.get('tx_hash')): int(_r.get('gas_used', 0) or 0) for _r in (_rrows or [])}
                                _ord = [(_h, _bymap.get(str(_h), 0)) for _h in _txl2]
                            except Exception:
                                _ord = [(tx_hash, receipt['gas_used'])]
                            _logs2 = receipt.get('logs', [])
                            if isinstance(_logs2, str):
                                try:
                                    _logs2 = json.loads(_logs2)
                                except Exception:
                                    _logs2 = []
                            result = {'transactionHash': tx_hash, 'transactionIndex': hex(_tidx2), 'blockHash': '0x' + _blk['hash'], 'blockNumber': hex(receipt['block_id']), 'from': tx['from_wallet'] if tx else '0x0', 'to': tx['to_wallet'] if tx else '0x0', 'cumulativeGasUsed': hex(_cumulative_gas_used(_ord, tx_hash)), 'gasUsed': hex(receipt['gas_used']), 'contractAddress': receipt.get('contract_address', ''), 'logs': _logs2, 'logsBloom': _logs_bloom(_logs2 if isinstance(_logs2, list) else []), 'status': hex(receipt['status'])}
                elif method == 'eth_getLogs':
                    # R8-getlogs (R7-22): full eth filter semantics — address
                    # (str|array) and per-position topics (value|array|null)
                    # match EACH LOG's own fields (was: receipt-level contract
                    # address, no topics, blank blockHash).
                    filter_obj = params[0] if params else {}
                    if not isinstance(filter_obj, dict):
                        filter_obj = {}
                    _tip = self.height - 1 if self.height > 0 else 0

                    def _blk_tag(v, default):
                        # Audit-E: named _blk_tag — the receipt branch below
                        # reuses _blk as a variable in this same scope.
                        try:
                            if isinstance(v, str):
                                if v in ('latest', 'pending'):
                                    return _tip
                                if v == 'earliest':
                                    return 0
                                if v.lower().startswith('0x'):
                                    return int(v, 16)
                                return int(v)
                            if isinstance(v, int):
                                return v
                        except (TypeError, ValueError):
                            pass
                        return default
                    from_block = _blk_tag(filter_obj.get('fromBlock'), 0)
                    to_block = _blk_tag(filter_obj.get('toBlock'), _tip)
                    _bh = filter_obj.get('blockHash')
                    _addr_f = filter_obj.get('address')
                    _addrs = None
                    if isinstance(_addr_f, str):
                        _addrs = [_addr_f]
                    elif isinstance(_addr_f, list):
                        _addrs = [a for a in _addr_f if isinstance(a, str)]
                    _topics_f = filter_obj.get('topics')
                    if not isinstance(_topics_f, list):
                        _topics_f = None
                    if self.db.db_type == "sqlite":
                        q = "SELECT tx_hash,block_id,status,gas_used,logs,contract_address FROM transaction_receipts WHERE block_id >= ? AND block_id <= ?"
                        rows = await self.db.fetch(q, from_block, to_block)
                    else:
                        q = "SELECT tx_hash,block_id,status,gas_used,logs,contract_address FROM transaction_receipts WHERE block_id >= $1 AND block_id <= $2"
                        rows = await self.db.fetch(q, from_block, to_block)
                    if _bh:
                        _bh_norm = str(_bh).lower()
                    else:
                        _bh_norm = None
                    _hash_cache = {}
                    result = []
                    for r in (rows or []):
                        logs = r.get('logs', [])
                        if isinstance(logs, str):
                            try: logs = json.loads(logs)
                            except Exception: logs = []
                        if not isinstance(logs, list):
                            continue
                        _bid = r.get('block_id')
                        if _bid not in _hash_cache:
                            try:
                                _brow = await self.block_repo.get_by_id(_bid)
                            except Exception:
                                _brow = None
                            _bhx = (_brow.get('hash', '') if _brow else '')
                            _hash_cache[_bid] = '0x' + _bhx if _bhx and not str(_bhx).startswith('0x') else (str(_bhx) if _bhx else '')
                            try:
                                _txl = (_brow.get('tx_hashes', '') if _brow else '')
                                _txl = json.loads(_txl) if isinstance(_txl, str) else (_txl or [])
                            except Exception:
                                _txl = []
                            _hash_cache[(_bid, 'txs')] = list(_txl) if isinstance(_txl, list) else []
                            _hash_cache[(_bid, 'n')] = 0
                        if _bh_norm and _hash_cache[_bid].lower() != _bh_norm:
                            continue
                        _txl = _hash_cache.get((_bid, 'txs'), [])
                        try:
                            _tidx = _txl.index(r.get('tx_hash')) if r.get('tx_hash') in _txl else 0
                        except Exception:
                            _tidx = 0
                        for _li, log in enumerate(logs):
                            if not isinstance(log, dict):
                                continue
                            if not _log_matches_filter(log.get('address'), log.get('topics'), _addrs, _topics_f):
                                continue
                            # R8-getlogs: logIndex is block-scoped (running
                            # per block across its receipts).
                            _n = _hash_cache.get((_bid, 'n'), 0)
                            _hash_cache[(_bid, 'n')] = _n + 1
                            result.append(_enrich_eth_log(log, _hash_cache[_bid], hex(_bid), r.get('tx_hash'), hex(_tidx), _n))
                elif method == 'eth_getBlockByNumber':
                    tag = params[0] if params else 'latest'
                    if tag in ('latest', 'pending'):
                        block_id = self.height - 1 if self.height > 0 else 0
                    elif tag == 'earliest':
                        block_id = 0
                    elif isinstance(tag, str) and tag.startswith('0x'):
                        block_id = int(tag, 16)
                    elif isinstance(tag, int):
                        block_id = tag
                    else:
                        block_id = self.height - 1 if self.height > 0 else 0

                    found_block = next((b for b in self.blocks if b.get('id') == block_id), None)
                    if not found_block and self.block_repo:
                        found_block = await self.block_repo.get_by_id(block_id)

                    if found_block:
                        include_full_tx = len(params) > 1 and params[1] is True
                        tx_hashes = found_block.get('tx_hashes', [])
                        if include_full_tx and found_block.get('transactions'):
                            tx_objs = []
                            for _ti, t in enumerate(found_block['transactions']):
                                # R8-rpc-meta (R7-23): real index + real v/r/s
                                # per tx (null for native signatures).
                                _vv, _rr, _ss = _eth_sig_fields(t)
                                tx_objs.append({
                                    'hash': t.get('tx_hash', ''),
                                    'nonce': hex(t.get('nonce', 0)),
                                    'blockHash': '0x' + found_block['hash'],
                                    'blockNumber': hex(found_block['id']),
                                    'transactionIndex': hex(_ti),
                                    'from': t.get('from_wallet', ''),
                                    'to': t.get('to_wallet', ''),
                                    'value': hex(t.get('value', 0)),
                                    'gas': hex(t.get('gas', _config.GAS_LIMIT_DEFAULT)),
                                    'gasPrice': hex(t.get('gasPrice', _config.GAS_PRICE)),
                                    'input': tx_data_to_hex(t.get('data', '0x')),
                                    'v': _vv, 'r': _rr, 's': _ss
                                })
                            tx_result = tx_objs
                        else:
                            tx_result = tx_hashes
                        # R8-rpc-meta (R7-23): real gasUsed = sum of the
                        # block's receipt gas (was: constant 0).
                        _bgas = await _block_gas_used(self.db, found_block['id'])
                        result = {
                            'number': hex(found_block['id']),
                            'hash': '0x' + found_block['hash'] if not found_block['hash'].startswith('0x') else found_block['hash'],
                            'parentHash': '0x' + found_block['phash'] if not found_block['phash'].startswith('0x') else found_block['phash'],
                            'timestamp': hex(int(found_block['ts'])),
                            'transactions': tx_result,
                            'miner': found_block.get('miners', [''])[0] if found_block.get('miners') else '',
                            'gasUsed': hex(_bgas),
                            'gasLimit': hex(_config.GAS_LIMIT_DEFAULT),
                            'stateRoot': found_block.get('state_root', '0x' + '00'*32)
                        }
                    else:
                        result = None
                elif method == 'eth_getBlockByHash':
                    block_hash = params[0] if params else ''
                    clean_hash = block_hash[2:] if block_hash.startswith('0x') else block_hash
                    found_block = next((b for b in self.blocks if b.get('hash') in (block_hash, clean_hash)), None)
                    if not found_block and self.block_repo:
                        q = "SELECT * FROM blocks WHERE hash = ? OR hash = ?" if self.db.db_type == "sqlite" else "SELECT * FROM blocks WHERE hash = $1 OR hash = $2"
                        row = await self.db.fetchrow(q, block_hash, clean_hash)
                        if row:
                            found_block = self.block_repo._unpack_block(row)
                    if found_block:
                        # R8-rpc-meta (R7-23): real gasUsed (was: constant 0).
                        _bgas2 = await _block_gas_used(self.db, found_block['id'])
                        result = {
                            'number': hex(found_block['id']),
                            'hash': '0x' + found_block['hash'] if not found_block['hash'].startswith('0x') else found_block['hash'],
                            'parentHash': '0x' + found_block['phash'] if not found_block['phash'].startswith('0x') else found_block['phash'],
                            'timestamp': hex(int(found_block['ts'])),
                            'transactions': found_block.get('tx_hashes', []),
                            'miner': found_block.get('miners', [''])[0] if found_block.get('miners') else '',
                            'gasUsed': hex(_bgas2),
                            'gasLimit': hex(_config.GAS_LIMIT_DEFAULT)
                        }
                    else:
                        result = None
                elif method == 'eth_getBlockTransactionCountByNumber':
                    block_id = int(params[0], 16) if params and params[0].startswith('0x') else self.height - 1
                    found_block = next((b for b in self.blocks if b.get('id') == block_id), None)
                    if not found_block and self.block_repo:
                        found_block = await self.block_repo.get_by_id(block_id)
                    if found_block:
                        result = hex(len(found_block.get('tx_hashes', [])))
                    else:
                        result = '0x0'
                else:
                    return web.json_response({"jsonrpc": "2.0", "error": {"code": -32601, "message": f"Method {method} not found"}, "id": req_id})

                response = {"jsonrpc": "2.0", "result": result, "id": req_id}
                return web.json_response(response)
            except Exception as e:
                logger.error(f"[RPC] Error: {e}", exc_info=True)
                return web.json_response({"jsonrpc": "2.0", "error": {"code": -32603, "message": str(e)}, "id": req_id})

        app.router.add_post('/rpc', rpc_handler)
        app.router.add_get('/rpc', rpc_handler)

        async def rpc_options(request):
            headers = {
                'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers': 'Content-Type',
            }
            # CORS fix: only loopback origins get an Origin echo (no wildcard)
            origin = request.headers.get('Origin')
            if _cors_origin_allowed(origin):
                headers['Access-Control-Allow-Origin'] = origin
            return web.Response(status=204, headers=headers)
        app.router.add_options('/rpc', rpc_options)

        async def stats_handler(request):
            stats = {
                "height": self.height,
                "peers": self.p2p.get_peer_count() if self.p2p else 0,
                "total_miners": len(self.miners),
                "active_miners": len(self.miner_websockets),
                "uptime": int(time.time() - self.health_checker.start_time),
                "total_minted": self.total_minted // SUBS,
                "burned_total": self.burned_total // SUBS,
                "burned_total_subunits": self.burned_total,
                "circulating_supply": (self.total_minted - self.burned_total) // SUBS,
                "version": VERSION,
                "healthy": self.health_checker.get_status().get("healthy", False),
            }
            return web.json_response(stats)

        app.router.add_get('/stats', stats_handler)

        async def health_handler(request):
            status = self.health_checker.get_status()
            healthy = bool(status.get("healthy", False))
            body = {
                "ok": healthy,
                "version": VERSION,
                "height": self.height,
                "last_hash": self.last_hash,
                "peers": self.p2p.get_peer_count() if self.p2p else 0,
                "miners_active": len(self.miner_websockets),
                "mempool": self.mempool.size(),
                "finality_lag_blocks": self._finality_lag_blocks(),
                "last_block_age": status.get("last_block_age"),
                "errors": status.get("errors", 0),
                "uptime_seconds": int(time.time() - self._start_time),
                "producing": bool(self._producing_enabled),
            }
            return web.json_response(body, status=200 if healthy else 503)

        app.router.add_get('/health', health_handler)

        async def peers_handler(request):
            peers = []
            if self.p2p:
                for nid, (url, last_seen) in getattr(self.p2p, 'tunnel_peers', {}).items():
                    peers.append({"node_id": nid, "url": url, "last_seen": last_seen})
                for nid, info in getattr(self.p2p, 'peers', {}).items():
                    if hasattr(info, 'addr') and info.addr not in [p.get("url","") for p in peers]:
                        peers.append({"node_id": nid, "url": info.addr, "last_seen": getattr(info, 'last_seen', 0)})
            _api_port = self.config.get('node', {}).get('api_port', API_PORT)
            peers.append({"node_id": "self", "url": f"http://127.0.0.1:{_api_port}/rpc", "last_seen": time.time(), "height": self.height})
            return web.json_response({"peers": peers, "total": len(peers)})

        app.router.add_get('/peers', peers_handler)

        async def metrics_handler(request):
            """Prometheus-compatible /metrics endpoint."""
            metrics = []
            metrics.append(f'# HELP mcx_block_height Current block height')
            metrics.append(f'# TYPE mcx_block_height gauge')
            metrics.append(f'mcx_block_height {self.height}')
            metrics.append(f'# HELP mcx_mempool_size Mempool size')
            metrics.append(f'# TYPE mcx_mempool_size gauge')
            metrics.append(f'mcx_mempool_size {self.mempool.size()}')
            metrics.append(f'# HELP mcx_active_miners Number of active miners')
            metrics.append(f'# TYPE mcx_active_miners gauge')
            try:
                active = await self.miner_repo.get_active()
                metrics.append(f'mcx_active_miners {len(active)}')
            except Exception:
                metrics.append(f'mcx_active_miners 0')
            metrics.append(f'# HELP mcx_pending_pow Pending PoW challenges')
            metrics.append(f'# TYPE mcx_pending_pow gauge')
            metrics.append(f'mcx_pending_pow {len(self.consensus._pending_pow)}')
            metrics.append(f'# HELP mcx_uptime_seconds Node uptime in seconds')
            metrics.append(f'# TYPE mcx_uptime_seconds counter')
            metrics.append(f'mcx_uptime_seconds {int(time.time() - self._start_time)}')
            metrics.append(f'# HELP mcx_total_burned Total burned MCX')
            metrics.append(f'# TYPE mcx_total_burned gauge')
            metrics.append(f'mcx_total_burned {self.burned_total // SUBS}')
            metrics.append(f'# HELP mcx_circulating_supply Total circulating MCX')
            metrics.append(f'# TYPE mcx_circulating_supply gauge')
            metrics.append(f'mcx_circulating_supply {(self.total_minted - self.burned_total) // SUBS}')
            metrics.append(f'# HELP mcx_global_shrink_factor Global shrink factor')
            metrics.append(f'# TYPE mcx_global_shrink_factor gauge')
            metrics.append(f'mcx_global_shrink_factor {_config.GLOBAL_SHRINK_FACTOR}')
            metrics.append(f'# HELP mcx_global_avg_size Global average maze size')
            metrics.append(f'# TYPE mcx_global_avg_size gauge')
            metrics.append(f'mcx_global_avg_size {self.consensus._global_avg_size}')
            metrics.append(f'# HELP mcx_finality_lag_blocks Blocks since last finality checkpoint')
            metrics.append(f'# TYPE mcx_finality_lag_blocks gauge')
            metrics.append(f'mcx_finality_lag_blocks {self._finality_lag_blocks()}')
            metrics.append(f'# HELP mcx_sign_timeout_total Total block-signing timeouts since start')
            metrics.append(f'# TYPE mcx_sign_timeout_total counter')
            metrics.append(f'mcx_sign_timeout_total {self._sign_timeout_total}')
            return web.Response(text='\n'.join(metrics), content_type='text/plain')

        app.router.add_get('/metrics', metrics_handler)

        # ─── Munex Developer REST API v1 ───────────────────────────────
        async def api_tokens_list(request):
            tokens = list(self.tokens.values())
            return web.json_response({"success": True, "tokens": tokens, "count": len(tokens)})

        async def api_tokens_create(request):
            try:
                data = await request.json()
            except Exception:
                return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            owner = data.get("owner")
            name = data.get("name")
            symbol = data.get("symbol")
            try:
                total_supply = _rint(data, "total_supply")
                decimals = _rint(data, "decimals", 18)
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            burnable = bool(data.get("burnable", True))
            temporal_config = data.get("temporal_config", {})
            if not owner or not name or not symbol or total_supply <= 0:
                return web.json_response({"success": False, "error": "Missing required token parameters"}, status=400)
            # REST-1: POST /api/v1/tokens previously jumped straight to
            # create_token() — no signature, no nonce: anyone could mint a
            # token from any owner's address and burn their creation fee.
            # Gate: canonical signed message, pub_key must hash to owner,
            # timestamp must be fresh (±300s).
            pub_key = data.get("pub_key")
            signature = data.get("signature")
            ts = data.get("timestamp")
            if not pub_key or not signature:
                return web.json_response({"success": False, "error": "Missing signature"}, status=401)
            if ts is None:
                return web.json_response({"success": False, "error": "Missing timestamp"}, status=401)
            # R5-sig-bind: nonce and fee are part of the signed message. Do not reorder fields.
            try:
                fee = _rint(data, "fee") if data.get("fee") else get_token_creation_fee(self.mempool.size())
                nonce = _rint(data, "nonce") if data.get("nonce") is not None else max(await self._get_confirmed_nonce(owner), self.mempool.get_nonce(owner))
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            message = f"{CHAIN_ID}:create_token:{owner}:{name}:{symbol}:{total_supply}:{decimals}:{int(bool(burnable))}:{nonce}:{fee}:{int(ts)}"
            try:
                if pubkey_to_address(pub_key).lower() != str(owner).lower():
                    return web.json_response({"success": False, "error": "pub_key does not match owner"}, status=401)
            except Exception:
                return web.json_response({"success": False, "error": "Invalid pub_key"}, status=401)
            if not verify_signature(pub_key, message, signature):
                return web.json_response({"success": False, "error": "Invalid signature"}, status=401)
            if abs(time.time() - float(ts)) > 300:
                return web.json_response({"success": False, "error": "Stale timestamp"}, status=401)
            # F2: queue as a consensus token_create tx (mempool + gossip).
            # create_token() mutated THIS node's state instantly — no block,
            # no gossip — so the token existed on one node only. The response
            # is pending until the next sealed block; the token address is
            # deterministic from tx_hash and appears in the receipt's
            # contract_address.
            tx_data = {
                "tx_type": "token_create",
                "from_wallet": owner,
                "to_wallet": owner,
                "value": 0,
                "fee": fee,
                "nonce": nonce,
                "timestamp": int(ts),
                "signature": signature,
                "pub_key": pub_key,
                "data": {"name": name, "symbol": symbol, "total_supply": total_supply, "decimals": decimals, "burnable": bool(burnable), "temporal_config": temporal_config},
            }
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_tokens_get(request):
            addr = request.match_info.get('address')
            token = await self.token_repo.get(addr)
            if not token:
                return web.json_response({"success": False, "error": "Token not found"}, status=404)
            temporal_config = await self.get_token_temporal_config(addr)
            burned_total = int(await self.contract_state_repo.get(addr, "burned_total") or 0)
            return web.json_response({"success": True, "token": token, "temporal_config": temporal_config, "burned_total": burned_total})

        async def api_tokens_balance(request):
            addr = request.match_info.get('address')
            wallet = request.match_info.get('wallet')
            bal = await self.token_balance_repo.get(addr, wallet)
            temporal_config = await self.get_token_temporal_config(addr)
            locked = 0
            vesting = temporal_config.get("vesting_schedules", {}).get(wallet) if temporal_config else None
            now = time.time()
            if vesting:
                v_total = int(vesting.get("total", 0))
                v_start = float(vesting.get("start", 0))
                v_dur = float(vesting.get("duration", 1))
                if now < v_start: locked = v_total
                elif now >= v_start + v_dur: locked = 0
                else: locked = int(v_total * (1.0 - (now - v_start) / v_dur))
            return web.json_response({"success": True, "token": addr, "wallet": wallet, "balance": bal, "unlocked": max(0, bal - locked), "locked_vesting": locked})

        async def api_tokens_transfer(request):
            addr = request.match_info.get('address')
            try: data = await request.json()
            except Exception: return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            # F2: queue via mempool + gossip instead of execute-at-submit.
            try:
                _v, _f, _n = (_rint(data, "amount"), _rint(data, "fee"), _rint(data, "nonce"))
                _ts = _rfloat_opt(data, "timestamp")
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            tx_data = {
                "tx_type": "token_transfer",
                "token_address": addr,
                "from_wallet": data.get("from_wallet"),
                "to_wallet": data.get("to_wallet"),
                "value": _v,
                "fee": _f,
                "nonce": _n,
                "signature": data.get("signature", ""),
                "pub_key": data.get("pub_key"),
            }
            if _ts is not None:
                tx_data["timestamp"] = _ts
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_tokens_burn(request):
            addr = request.match_info.get('address')
            try: data = await request.json()
            except Exception: return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            # F2: queue via mempool + gossip instead of execute-at-submit.
            try:
                _v, _f, _n = (_rint(data, "amount"), _rint(data, "fee"), _rint(data, "nonce"))
                _ts = _rfloat_opt(data, "timestamp")
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            tx_data = {
                "tx_type": "token_burn",
                "token_address": addr,
                "from_wallet": data.get("from_wallet"),
                "value": _v,
                "fee": _f,
                "nonce": _n,
                "signature": data.get("signature", ""),
                "pub_key": data.get("pub_key"),
            }
            if _ts is not None:
                tx_data["timestamp"] = _ts
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_native_burn(request):
            try: data = await request.json()
            except Exception: return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            from_wallet = data.get("from_wallet")
            try:
                amount = _rint(data, "amount")
                _f, _n = _rint(data, "fee"), _rint(data, "nonce")
                _ts = _rfloat_opt(data, "timestamp")
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            if not from_wallet or amount <= 0:
                return web.json_response({"success": False, "error": "Invalid from_wallet or amount"}, status=400)
            # F2: queue via mempool + gossip instead of execute-at-submit.
            tx_data = {
                "tx_type": "burn",
                "from_wallet": from_wallet,
                "to_wallet": BURN_ADDRESS_ZERO,
                "value": amount,
                "fee": _f,
                "nonce": _n,
                "signature": data.get("signature", ""),
                "pub_key": data.get("pub_key"),
            }
            if _ts is not None:
                tx_data["timestamp"] = _ts
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_spatial_token_create(request):
            # Closeout brief Gap A: spatial_token_create had no external
            # submission path (execute/_replay only). Mirrors api_tokens_create
            # auth gating: canonical signed message + fresh timestamp; F2 queue
            # via mempool + gossip (mempool/execute enforce nonce + fee).
            try:
                data = await request.json()
            except Exception:
                return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            from_wallet = data.get("from_wallet")
            name = str(data.get("name") or "")
            symbol = str(data.get("symbol") or "")
            try:
                supply = int(data.get("supply", 0))
            except (TypeError, ValueError):
                return web.json_response({"success": False, "error": "supply must be an int"}, status=400)
            try:
                decimals = int(data.get("decimals", 18))
            except (TypeError, ValueError):
                return web.json_response({"success": False, "error": "decimals must be an int"}, status=400)
            try:
                bundle_count = int(data.get("bundle_count", 1))
            except (TypeError, ValueError):
                return web.json_response({"success": False, "error": "bundle_count must be an int"}, status=400)
            ts = data.get("timestamp")
            nonce = data.get("nonce")
            pub_key = data.get("pub_key")
            signature = data.get("signature")
            if not from_wallet or nonce is None:
                return web.json_response({"success": False, "error": "from_wallet and nonce required"}, status=400)
            if not name or len(name) > SPATIAL_MAX_NAME_LEN:
                return web.json_response({"success": False, "error": f"name must be 1..{SPATIAL_MAX_NAME_LEN} chars"}, status=400)
            if not symbol or len(symbol) > SPATIAL_MAX_SYMBOL_LEN:
                return web.json_response({"success": False, "error": f"symbol must be 1..{SPATIAL_MAX_SYMBOL_LEN} chars"}, status=400)
            if supply < 1 or supply > SPATIAL_MAX_SUPPLY:
                return web.json_response({"success": False, "error": f"supply must be 1..{SPATIAL_MAX_SUPPLY}"}, status=400)
            if not (0 <= decimals <= 255):
                return web.json_response({"success": False, "error": "decimals out of range"}, status=400)
            if bundle_count < 1:
                return web.json_response({"success": False, "error": "bundle_count must be >= 1"}, status=400)
            # Spatial Tokens V2: no client coordinate (derived on-chain; a
            # client-supplied preferred_coord is ignored, not rejected).
            if not pub_key or not signature or ts is None:
                return web.json_response({"success": False, "error": "Missing signature"}, status=401)
            try:
                if pubkey_to_address(pub_key).lower() != str(from_wallet).lower():
                    return web.json_response({"success": False, "error": "pub_key does not match from_wallet"}, status=401)
            except Exception:
                return web.json_response({"success": False, "error": "Invalid pub_key"}, status=401)
            # Spatial Tokens V2 signing format: no coordinate (derived
            # on-chain). Old signatures carrying px,py,pz are rejected.
            # R5-sig-bind: nonce and fee are part of the signed message. Do not reorder fields.
            deploy_fee = int(SPATIAL_BASE_DEPLOY_FEE)
            fee_in = data.get("fee")
            try:
                fee = int(fee_in) if fee_in else deploy_fee
            except (TypeError, ValueError):
                return web.json_response({"success": False, "error": "fee must be an int"}, status=400)
            message = (f"{CHAIN_ID}:spatial_token_create:{from_wallet}:{name}:{symbol}:"
                       f"{supply}:{decimals}:{int(bundle_count)}:{int(nonce)}:{int(fee)}:{int(ts)}")
            if not verify_signature(pub_key, message, signature):
                return web.json_response({"success": False, "error": "Invalid signature"}, status=401)
            if abs(time.time() - float(ts)) > 300:
                return web.json_response({"success": False, "error": "Stale timestamp"}, status=401)
            # Spatial Tokens V2: flat deploy fee. NOT enforced here: the
            # signed tx['fee'] is the authorization ceiling and execute
            # computes the real charge.
            tx_data = {
                "tx_type": "spatial_token_create",
                "from_wallet": str(from_wallet),
                "to_wallet": "",
                "value": 0,
                "fee": fee,
                "nonce": int(nonce),
                "timestamp": int(ts),
                "signature": signature,
                "pub_key": pub_key,
                "name": name,
                "symbol": symbol,
                "supply": supply,
                "decimals": decimals,
                "bundle_count": bundle_count,
            }
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            if status == 200 and isinstance(body, dict):
                body = {**body, "fee": int(fee)}
            return web.json_response(body, status=status)

        async def api_spatial_tokens_list(request):
            # Spatial Tokens V1 (§7.13) — replaces spatial assets list.
            rows = await self.spatial_token_repo.get_all()
            out = [dict(r) for r in (rows or [])]
            return web.json_response({"success": True, "tokens": out, "count": len(out)})

        async def api_spatial_token_get(request):
            addr = request.match_info.get("address")
            r = await self.spatial_token_repo.get(addr)
            if not r:
                return web.json_response({"success": False, "error": "not found"}, status=404)
            out = dict(r)
            wallet = request.query.get("wallet")
            if wallet:
                out["wallet_balance"] = await self.spatial_token_balance_repo.get(addr, wallet.lower())
            return web.json_response({"success": True, "token": out})

        async def api_spatial_token_balance(request):
            # Closeout brief Gap B: canonical path-segment wallet (mirrors
            # /api/v1/tokens/{address}/balance/{wallet}); the old ?wallet=
            # query-param form is removed — one contract, not two.
            addr = request.match_info.get("address")
            wallet = request.match_info.get("wallet")
            if not wallet:
                return web.json_response({"success": False, "error": "wallet path segment required"}, status=400)
            bal = await self.spatial_token_balance_repo.get(addr, wallet.lower())
            return web.json_response({"success": True, "token_address": addr,
                                      "wallet": wallet.lower(), "balance": int(bal or 0)})

        async def api_spatial_token_transfer(request):
            addr = request.match_info.get("address")
            try: data = await request.json()
            except Exception: return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            # F2: queue via mempool + gossip instead of execute-at-submit —
            # identical signing contract to api_tokens_transfer (client signs
            # fee + amount; §7.7 covers them).
            # Spatial Tokens V2: new_preferred_coord is rejected here (the
            # execute path rejects it too; fail fast at the edge).
            if data.get("new_preferred_coord") is not None:
                return web.json_response({"success": False, "error": "new_preferred_coord disabled in V2 (no rehome)"}, status=400)
            try:
                _v = _rint(data, "amount")
                _f, _n = _rint(data, "fee"), _rint(data, "nonce")
                _ts = _rfloat_opt(data, "timestamp")
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            tx_data = {
                "tx_type": "spatial_token_transfer",
                "token_address": addr,
                "from_wallet": data.get("from_wallet"),
                "to_wallet": data.get("to_wallet"),
                "amount": _v,
                "fee": _f,
                "nonce": _n,
                "signature": data.get("signature", ""),
                "pub_key": data.get("pub_key"),
                # R6-spatial-fee-bind: submitted cut is part of the signed message (0 for fresh submits).
                "_spatial_fee_maze_cut": 0,
            }
            if _ts is not None:
                tx_data["timestamp"] = _ts
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_apps_list(request):
            apps = await self.contract_v2_repo.get_all()
            return web.json_response({"success": True, "apps": apps, "count": len(apps)})

        async def api_apps_get(request):
            addr = request.match_info.get('address')
            app_record = await self.contract_v2_repo.get(addr)
            if not app_record: return web.json_response({"success": False, "error": "App not found"}, status=404)
            return web.json_response({"success": True, "app": app_record})

        async def api_apps_deploy(request):
            try: data = await request.json()
            except Exception: return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            # F2: queue via mempool + gossip instead of execute-at-submit.
            try:
                _v = _rint(data, "value")
                _g = _rint(data, "gas", _config.GAS_LIMIT_DEFAULT)
                _f, _n = _rint(data, "fee"), _rint(data, "nonce")
                _ts = _rfloat_opt(data, "timestamp")
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            tx_data = {
                "tx_type": "contract_deploy",
                "from_wallet": data.get("from_wallet"),
                "bytecode": data.get("bytecode"),
                "abi": data.get("abi", {}),
                "value": _v,
                "gas": _g,
                "fee": _f,
                "nonce": _n,
                "signature": data.get("signature", ""),
                "pub_key": data.get("pub_key"),
            }
            if _ts is not None:
                tx_data["timestamp"] = _ts
            # R6-value-moved-bind: submitted marker is part of the signed message (present iff value moves).
            if tx_data.get("value", 0) > 0:
                tx_data["_value_moved"] = int(tx_data["value"])
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_apps_call(request):
            addr = request.match_info.get('address')
            try: data = await request.json()
            except Exception: return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            # F2: queue via mempool + gossip instead of execute-at-submit.
            try:
                _v = _rint(data, "value")
                _g = _rint(data, "gas", _config.GAS_LIMIT_DEFAULT)
                _f, _n = _rint(data, "fee"), _rint(data, "nonce")
                _ts = _rfloat_opt(data, "timestamp")
            except _BadInt as _e:
                return web.json_response({"success": False, "error": f"{_e} must be numeric"}, status=400)
            tx_data = {
                "tx_type": "contract_call",
                "from_wallet": data.get("caller", data.get("from_wallet", "0x0000000000000000000000000000000000000000")),
                "to_wallet": addr,
                "input": data.get("data", data.get("input", "")),
                "value": _v,
                "gas": _g,
                "fee": _f,
                "nonce": _n,
                "signature": data.get("signature", ""),
                "pub_key": data.get("pub_key"),
            }
            if _ts is not None:
                tx_data["timestamp"] = _ts
            # TXTYPE-BIND-1: the verifier and executor read `data`, not
            # `input`. Canonicalize at ingress (before hashing/signing) so
            # the signed bytes are exactly what executes.
            if tx_data.get("input") is not None and not tx_data.get("data"):
                tx_data["data"] = tx_data.pop("input")
            # R6-value-moved-bind: submitted marker is part of the signed message (present iff value moves).
            if tx_data.get("value", 0) > 0:
                tx_data["_value_moved"] = int(tx_data["value"])
            tx_data["tx_hash"] = hash_tx(tx_data)
            status, body = await self._submit_pool_tx(tx_data)
            return web.json_response(body, status=status)

        async def api_apps_state(request):
            addr = request.match_info.get('address')
            state = await self.contract_storage_v2_repo.get_all(addr)
            return web.json_response({"success": True, "address": addr, "state": state})

        async def api_automations_list(request):
            owner = request.query.get('owner')
            if owner: autos = await self.automation_repo.list_by_owner(owner)
            else: autos = await self.automation_repo.list_active()
            return web.json_response({"success": True, "automations": autos, "count": len(autos)})

        async def api_automations_create(request):
            try: data = await request.json()
            except Exception: return web.json_response({"success": False, "error": "Invalid JSON"}, status=400)
            auto_id = "auto_" + secrets.token_hex(16)
            rec = {
                "id": auto_id,
                "name": data.get("name", "MunexAutomation"),
                "owner": data.get("owner"),
                "trigger_type": data.get("trigger_type", "time_interval"),
                "trigger_config": data.get("trigger_config", {}),
                "action_type": data.get("action_type", "contract_call"),
                "action_config": data.get("action_config", {}),
                "enabled": bool(data.get("enabled", True)),
                "created_at": time.time(),
                "last_run_at": None,
                "run_count": 0,
                "last_result": ""
            }
            if not rec["owner"]: return web.json_response({"success": False, "error": "Missing owner"}, status=400)
            # REST-2: automation create previously trusted any caller-supplied
            # owner with no authentication — anyone could arm triggers that
            # spend someone else's tokens. Gate: canonical signed message,
            # pub_key must hash to owner, timestamp fresh (±300s).
            pub_key = data.get("pub_key")
            signature = data.get("signature")
            ts = data.get("timestamp")
            if not pub_key or not signature:
                return web.json_response({"success": False, "error": "Missing signature"}, status=401)
            if ts is None:
                return web.json_response({"success": False, "error": "Missing timestamp"}, status=401)
            # AUTO-ENABLE-BIND-1 (mainnet audit): `enabled` is
            # behavior-affecting (stored and acted on) and is now signed.
            # API break: previously signed requests omitting it no longer
            # verify (they flip a stored field without invalidating the
            # signature otherwise).
            sign_payload = {
                "owner": rec["owner"], "name": rec["name"],
                "trigger_type": rec["trigger_type"], "action_type": rec["action_type"],
                "trigger_config": rec["trigger_config"], "action_config": rec["action_config"],
                "timestamp": int(ts), "enabled": bool(rec["enabled"]),
            }
            message = f"{CHAIN_ID}:create_automation:" + canonical_json_bytes(sign_payload).decode("utf-8")
            try:
                if pubkey_to_address(pub_key).lower() != str(rec["owner"]).lower():
                    return web.json_response({"success": False, "error": "pub_key does not match owner"}, status=401)
            except Exception:
                return web.json_response({"success": False, "error": "Invalid pub_key"}, status=401)
            if not verify_signature(pub_key, message, signature):
                return web.json_response({"success": False, "error": "Invalid signature"}, status=401)
            if abs(time.time() - float(ts)) > 300:
                return web.json_response({"success": False, "error": "Stale timestamp"}, status=401)
            # O3-replay-guard: the same signed bytes must not mint two
            # automations inside their validity window.
            _seen = getattr(self, "_seen_automation_sigs", None)
            if _seen is None:
                _seen = self._seen_automation_sigs = {}
            _rkey = _automation_replay_key(message)
            if _automation_sig_replay(_seen, _rkey, time.time()):
                return web.json_response({"success": False, "error": "Duplicate signature (replay)"}, status=409)
            # AUTO-REPLAY-SEEN-1: durable guard — a restart inside the
            # window must not re-open it. DB failure fails open to the
            # memory guard (same as pre-patch behavior), never closed.
            try:
                if await self.automation_repo.note_replay_seen(_rkey, time.time()):
                    return web.json_response({"success": False, "error": "Duplicate signature (replay)"}, status=409)
            except Exception as _rse:
                logger.debug(f"[Automation] replay-seen DB check skipped: {_rse}")
            await self.automation_repo.create(rec)
            # R4-automations-redact: the create response carries the same
            # redaction as the repo boundary (no signed tx bodies leak).
            return web.json_response({"success": True, "automation": AutomationRepo._redact(rec)})

        async def api_automations_get(request):
            auto_id = request.match_info.get('id')
            rec = await self.automation_repo.get(auto_id)
            if not rec: return web.json_response({"success": False, "error": "Automation not found"}, status=404)
            return web.json_response({"success": True, "automation": rec})

        async def api_automations_delete(request):
            auto_id = request.match_info.get('id')
            # R4-automations-delete-auth: previously no auth — anyone could
            # delete anyone's automation. Mirror api_automations_create.
            try: data = await request.json()
            except Exception: data = {}
            owner = (data or {}).get("owner")
            ok, err = verify_automation_delete_auth(
                auto_id, owner, (data or {}).get("pub_key"),
                (data or {}).get("signature"), (data or {}).get("timestamp"))
            if not ok:
                return web.json_response({"success": False, "error": err}, status=401)
            rec = await self.automation_repo.get(auto_id)
            if not rec:
                return web.json_response({"success": False, "error": "Automation not found"}, status=404)
            if str(rec.get("owner", "")).lower() != str(owner).lower():
                return web.json_response({"success": False, "error": "Not automation owner"}, status=403)
            await self.automation_repo.delete(auto_id)
            return web.json_response({"success": True, "deleted": auto_id})

        app.router.add_get('/api/v1/tokens', api_tokens_list)
        app.router.add_post('/api/v1/tokens', api_tokens_create)
        app.router.add_get('/api/v1/tokens/{address}', api_tokens_get)
        app.router.add_get('/api/v1/tokens/{address}/balance/{wallet}', api_tokens_balance)
        app.router.add_post('/api/v1/tokens/{address}/transfer', api_tokens_transfer)
        app.router.add_post('/api/v1/tokens/{address}/burn', api_tokens_burn)
        app.router.add_post('/api/v1/burn', api_native_burn)
        app.router.add_get('/api/v1/spatial/tokens', api_spatial_tokens_list)
        app.router.add_post('/api/v1/spatial/tokens', api_spatial_token_create)
        app.router.add_get('/api/v1/spatial/tokens/{address}', api_spatial_token_get)
        app.router.add_get('/api/v1/spatial/tokens/{address}/balance/{wallet}', api_spatial_token_balance)
        app.router.add_post('/api/v1/spatial/tokens/{address}/transfer', api_spatial_token_transfer)
        app.router.add_get('/api/v1/apps', api_apps_list)
        app.router.add_post('/api/v1/apps', api_apps_deploy)
        app.router.add_get('/api/v1/apps/{address}', api_apps_get)
        app.router.add_get('/api/v1/apps/{address}/state', api_apps_state)
        app.router.add_post('/api/v1/apps/{address}/call', api_apps_call)
        app.router.add_get('/api/v1/automations', api_automations_list)
        app.router.add_post('/api/v1/automations', api_automations_create)
        app.router.add_get('/api/v1/automations/{id}', api_automations_get)
        app.router.add_delete('/api/v1/automations/{id}', api_automations_delete)

        ws_port = self.config.get('node', {}).get('ws_port', WS_PORT)
        ws_bind_ip = self.config.get('node', {}).get('ws_bind_ip', '0.0.0.0')
        api_port = self.config.get('node', {}).get('api_port', API_PORT)
        # R4-ws-rpc-split: two binds. Public app = miner WS only, on
        # ws_bind_ip:ws_port (0.0.0.0 default: reachable by remote miners).
        # ESP-WS-1: validate + resolve the listener BEFORE binding so a bad
        # address/port fails here with a clear error, not a bind traceback.
        # Logs show configured AND detected-LAN endpoints (curl-able).
        try:
            ws_bind_ip, ws_port, api_port = _validate_ws_bind(ws_bind_ip, ws_port, api_port)
        except ValueError as _be:
            logger.error(f"[WS] Invalid WebSocket listener configuration: {_be}")
            raise
        lan_ip = _detect_lan_ip()
        logger.info(f"[WS] Miner WebSocket listener: ws://{ws_bind_ip}:{ws_port}/ws "
                    f"(route /ws + GET /healthz; LAN check: ws://{lan_ip}:{ws_port}/ws)")
        runner_ws = web.AppRunner(app_ws)
        await runner_ws.setup()
        try:
            await web.TCPSite(runner_ws, ws_bind_ip, ws_port).start()
        except OSError as _oe:
            logger.error(f"[WS] Failed to bind miner WebSocket on {ws_bind_ip}:{ws_port}: {_oe} "
                         f"(port already in use by another process? invalid address for this host?)")
            await runner_ws.cleanup()
            raise RuntimeError(f"miner WebSocket bind failed on {ws_bind_ip}:{ws_port}: {_oe}") from _oe
        runner_api = web.AppRunner(app)
        await runner_api.setup()
        # MCX72: bind the API server to RPC_BIND_IP (default 0.0.0.0 since
        # RPC-AUTH-1: POST /rpc now requires the operator bearer token for
        # non-loopback clients, and loopback stays trusted, so LAN wallets
        # can use it. Read-only GET routes stay open by design.
        _rpc_bind = self.config.get('node', {}).get('rpc_bind_ip', RPC_BIND_IP)
        # R5-bind-split: WS public, RPC/REST private. G1.
        await web.TCPSite(runner_api, _rpc_bind, api_port).start()
        # (lan_ip already detected above for the listener log).
        logger.info(f"[API] Private RPC/REST:       http://{_rpc_bind}:{api_port}/rpc")
        logger.info(f"[API] Private metrics/health: http://{_rpc_bind}:{api_port}/metrics")
        # RPC-AUTH-1: a 0.0.0.0 API bind without a token leaves remote
        # POST /rpc refused-but-noisy; warn once so operators set
        # MCX_RPC_TOKEN / node.rpc_token before serving LAN wallets (and
        # firewall the port). Loopback-only and token-configured binds stay
        # quiet.
        if str(_rpc_bind) == '0.0.0.0' and not _rpc_bearer_token(self.config):
            logger.warning("[API] RPC bound to 0.0.0.0 with no bearer token configured: remote POST /rpc is refused; set MCX_RPC_TOKEN / node.rpc_token to serve LAN wallets, and firewall the port")
        logger.info(f"[WS] MetaMask RPC URL: http://{lan_ip}:{api_port}/rpc  (Chain ID: {CHAIN_ID})")

        try:
            while True:
                await asyncio.sleep(3600)
        except asyncio.CancelledError:
            await runner_ws.cleanup()
            await runner_api.cleanup()
            raise

    def _subnet_key(self, client_ip: str) -> str:
        try:
            ip = ipaddress.ip_address(client_ip)
            if isinstance(ip, ipaddress.IPv6Address):
                net = ipaddress.ip_network(f"{ip}/64", strict=False)
            else:
                net = ipaddress.ip_network(f"{ip}/24", strict=False)
            return str(net)
        except ValueError:
            return client_ip

    async def _miner_path_allowed(self, miner_id: str) -> bool:
        """MINER-RATE-1: bounded per-miner budget for the mining WS path
        (maze_move + wall_hit_solve), which is exempt from the per-IP
        limiter. Local operator policy only (never consensus). The map is
        bounded: callers have already authenticated, and entries are popped
        when a miner is removed."""
        rl = self.miner_rate_limiters.get(miner_id)
        if rl is None:
            if len(self.miner_rate_limiters) >= 10000:
                return False
            rl = RateLimiter(max_requests=1200, window_seconds=60)
            self.miner_rate_limiters[miner_id] = rl
        return await rl.is_allowed(miner_id)

    async def _handle_ws_message(self, ws, data: dict, client_ip: str):
        session = self.ws_sessions.get(ws)
        if session is None:
            session = {"tasks": set()}
            self.ws_sessions[ws] = session
        elif "tasks" not in session:
            session["tasks"] = set()
        msg_type = data.get("type")
        miner_id = data.get("miner_id")
        # --- H-8: Refresh last_ping ONLY from an authenticated session matching miner_id ---
        if miner_id and msg_type != "register" and session.get("miner_id") == miner_id and session.get("authenticated"):
            asyncio.create_task(self.miner_repo.update_last_ping(miner_id))
        # -------------------------------------------------------------

        # ── PQE: ML-KEM-768 Handshake (miner↔node WebSocket) ──────────────
        if msg_type in ("pqe_hello", "pqe_confirm"):
            if not MLKEM_AVAILABLE:
                return
            peer_ip = client_ip or "unknown"
            pqe_timestamps = self.p2p._pqe_rate_limiter.setdefault(peer_ip, [])
            now_ts = time.time()
            pqe_timestamps[:] = [t for t in pqe_timestamps if now_ts - t < 60]
            if len(pqe_timestamps) >= self.p2p._pqe_rate_limit[0]:
                await ws.send_json({"type": "error", "message": "PQE rate limit exceeded"})
                return
            pqe_timestamps.append(now_ts)

        if msg_type == "pqe_hello":
            try:
                if not MLKEM_AVAILABLE:
                    # No PQE support — ignore; miner will fall back to plaintext
                    return
                miner_pqe_pub_hex = data.get("pqe_pub", "")
                if not miner_pqe_pub_hex:
                    await ws.send_json({"type": "error", "message": "pqe_pub missing"})
                    return
                # Generate our own ML-KEM-768 keypair for this WS session
                node_priv = mlkem.MLKEM768PrivateKey.generate()
                node_pub_raw = node_priv.public_key().public_bytes_raw()
                # Encapsulate with miner's public key → shared secret + ciphertext
                miner_pub = mlkem.MLKEM768PublicKey.from_public_bytes(bytes.fromhex(miner_pqe_pub_hex))
                ss_for_miner, ct_for_miner = miner_pub.encapsulate()
                # Store node's private key in session for pqe_confirm step
                session["pqe_node_priv"] = node_priv
                session["pqe_ss_for_miner"] = ss_for_miner
                await ws.send_json({"type": "pqe_hello_ack",
                                    "ct": ct_for_miner.hex(),
                                    "node_pqe_pub": node_pub_raw.hex()})
            except Exception as e:
                logger.warning(f"[WS] PQE hello error: {e}")
            return

        if msg_type == "pqe_confirm":
            try:
                if not MLKEM_AVAILABLE or "pqe_node_priv" not in session:
                    return
                ct_from_miner = bytes.fromhex(data.get("ct", ""))
                node_priv = session.pop("pqe_node_priv")
                ss_remote = node_priv.decapsulate(ct_from_miner)
                ss_local = session.pop("pqe_ss_for_miner", b"")
                combined = ss_local + ss_remote
                from cryptography.hazmat.primitives.kdf.hkdf import HKDF as _HKDF
                from cryptography.hazmat.primitives.hashes import SHA384 as _SHA384
                key = _HKDF(algorithm=_SHA384(), length=32, salt=None,
                            info=b"mcx_miner_ws_mlkem768_aes256gcm").derive(combined)
                session["pqe_key"] = key
                session["pqe_nonce_ctr"] = 0
                # Wrap ws.send_json for outgoing encryption
                orig_send_json = ws.send_json
                async def pqe_send_json(payload_dict, *args, **kwargs):
                    if "pqe_key" in session:
                        from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                        session["pqe_nonce_ctr"] += 1
                        nonce = session["pqe_nonce_ctr"].to_bytes(12, "big")
                        ct = _AESGCM(session["pqe_key"]).encrypt(nonce, json.dumps(payload_dict).encode("utf-8"), None)
                        return await orig_send_json({"type": "enc", "ct": ct.hex(), "nonce": nonce.hex()}, *args, **kwargs)
                    return await orig_send_json(payload_dict, *args, **kwargs)
                ws.send_json = pqe_send_json
                logger.info(f"[WS] PQE ML-KEM-768 session established with {data.get('miner_id', '?'[:16])}")
            except Exception as e:
                logger.warning(f"[WS] PQE confirm error: {e}")
            return

        # Decrypt inbound envelope if PQE session is active for this WebSocket
        if msg_type == "enc" and "pqe_key" in session:
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
                ct = bytes.fromhex(data.get("ct", ""))
                nonce = bytes.fromhex(data.get("nonce", ""))
                plain = _AESGCM(session["pqe_key"]).decrypt(nonce, ct, None)
                data = json.loads(plain.decode("utf-8"))
                msg_type = data.get("type")
            except Exception as e:
                logger.warning(f"[WS] PQE decrypt error: {e}")
                return
        # ────────────────────────────────────────────────────────────────────

        if msg_type == "register":
            try:
                miner_id = data.get("miner_id")
                if not miner_id or not miner_id.startswith("PC_"):
                    await ws.send_json({"type": "registration_failed", "error": "Miner ID must start with PC_ prefix"})
                    return
                wallet = data.get("wallet")
                pub_key = data.get("public_key")
                sig = data.get("signature")
                timestamp = data.get("timestamp", int(time.time()))
                block_signing_pub = data.get("block_signing_pub")
                takeover_sig = data.get("takeover_sig")
                ok = await self.register_miner(miner_id, wallet, pub_key, sig, timestamp, block_signing_pub, takeover_sig)
                if ok:
                    challenge = self.memory_mgr.generate_challenge(miner_id)
                    session["challenge_sent"] = True
                    session["miner_id"] = miner_id
                    session["maze_id"] = data.get("maze_id") or miner_id
                    await ws.send_json(challenge)
                else:
                    await ws.send_json({"type": "registration_failed", "error": "Invalid signature or banned"})
            except Exception as e:
                logger.error(f"[WS] Registration error: {e}", exc_info=True)
                await ws.send_json({"type": "registration_failed", "error": f"Internal error: {str(e)}"})

        elif msg_type == "memory_challenge_response":
            if not session.get("challenge_sent"):
                await ws.send_json({"type": "error", "message": "No challenge pending"})
                return
            miner_id = data.get("miner_id")
            if miner_id != session.get("miner_id"):
                await ws.send_json({"type": "error", "message": "Miner ID mismatch"})
                return
            seed = data.get("seed")
            commitment = data.get("commitment")
            loop = asyncio.get_event_loop()
            ok = await loop.run_in_executor(None, self.memory_mgr.verify_commitment, miner_id, seed, commitment)
            if ok:
                session["authenticated"] = True
                session["challenge_verified"] = True
                self.miner_websockets[miner_id] = ws
                # MINER-REWAKE-1: this host may have just skipped an election
                # because the winner's socket was absent (embedded miners
                # close/reconnect with code=1000 in seconds). Pull the produce
                # schedule forward so the next production-loop poll (0.1s)
                # re-elects with the socket present instead of sleeping out a
                # 30s rank boundary — a 1-2s ws gap otherwise cost a full
                # ladder walk (S9 rate-0 stall).
                self._next_block_time = min(self._next_block_time, time.time() + 0.3)
                await ws.send_json({"type": "registered", "confirmed_balance": 0})
                try:
                    row = await self.consensus._load_or_create_maze(miner_id, session.get("maze_id"))
                    if row is None:
                        await ws.send_json({"type": "error", "message": "Maze already in use by another miner"})
                        return
                    loop = asyncio.get_event_loop()
                    sparse_maze = await loop.run_in_executor(
                        self.consensus._move_executor,
                        self.consensus._generate_deterministic_maze,
                        row["seed"], row["size"], int(row["walldensityppm"]), int(row["turbulenceppm"]), self.height
                    )
                    maze = sparse_to_dense(sparse_maze)
                    # Apply sealed walls (corridor closing behind miner)
                    maze_id_init = row.get("maze_id") or miner_id
                    sealed_init = self.consensus._sealed_walls.get(maze_id_init, set())
                    for sx, sy, sz in sealed_init:
                        if 0 <= sz < row["size"] and 0 <= sy < row["size"] and 0 <= sx < row["size"]:
                            maze[sz][sy][sx] = 1
                    start = (row["posx"], row["posy"], row["posz"])
                    goal = (row["goalx"], row["goaly"], row["goalz"])
                    maze_id = row.get("maze_id") or miner_id
                    ghost = self.consensus._ghost_tuple(row)
                    sealed = self.consensus._sealed_walls.get(maze_id)
                    await ws.send_json({
                        "type": "maze_init",
                        "maze": maze,
                        "size": row["size"],
                        "start": list(start),
                        "goal": list(goal),
                        "maze_root": row["mazeroot"],
                        "block_id": self.height,
                        "difficulty": 1.0,
                        "max_path_length": 10**9,
                        "step_interval": 0.0,
                        "required_knowledge": 10,
                        "ghost": list(ghost) if ghost else None,
                        "sealed_walls": [list(w) for w in sealed] if sealed else [],
                        "growthcount": int(row["growthcount"]),
                        "movenonce": int(row["movenonce"]),
                    })
                except Exception as e:
                    logger.error(f"[WS] MAZE_INIT ERROR for {miner_id}: {e}", exc_info=True)
                    await ws.send_json({"type": "error", "message": f"maze_init: {e}"})
            else:
                await ws.send_json({"type": "registration_failed", "error": "Challenge failed"})

        elif msg_type == "maze_move":
            try:
                miner_id = data.get("miner_id")
                maze_id = data.get("maze_id") or miner_id
                direction = data.get("direction")
                signature = data.get("signature")
                move_nonce = data.get("move_nonce", None)
                if not all([miner_id, direction, signature]):
                    await ws.send_json({"type": "error", "message": "Missing fields"})
                    return
                if not isinstance(miner_id, str) or not isinstance(maze_id, str) \
                        or not isinstance(direction, str) or not isinstance(signature, str) \
                        or len(miner_id) > 128 or len(maze_id) > 192 or len(signature) > 1024:
                    await ws.send_json({"type": "error", "message": "Malformed fields"})
                    return
                # WS-SESSION-BIND-1: only the authenticated session of this
                # miner may drive its maze; the _inflight_moves slot below is
                # keyed by miner_id, so an unauthenticated peer must never be
                # able to occupy another miner's slot.
                if not (session.get("authenticated") and session.get("miner_id") == miner_id):
                    await ws.send_json({"type": "error", "message": "Not authenticated as miner"})
                    return
                _own_row = await self.maze_repo.get_by_maze_id(maze_id)
                if not _own_row or str(_own_row.get("minerid") or "") != miner_id:
                    await ws.send_json({"type": "error", "message": "Maze not owned by miner"})
                    return
                if not await self._miner_path_allowed(miner_id):
                    await ws.send_json({"type": "error", "message": "Rate limit exceeded"})
                    return

                if miner_id in self.consensus._inflight_moves:
                    return
                self.consensus._inflight_moves.add(miner_id)

                async def _process_and_reply():
                    try:
                        if ws.closed:
                            return
                        # Capture pre-move growthcount for P2P broadcast (miner signs with this value)
                        _pre_row = await self.maze_repo.get_by_maze_id(maze_id)
                        _pre_growthcount = int(_pre_row["growthcount"]) if _pre_row else 0
                        success, msg, state = await self.consensus.process_move(miner_id, maze_id, direction, signature, move_nonce)
                        if ws.closed:
                            return
                        if state.get("type") == "wall_hit":
                            await ws.send_json(state)
                        else:
                            ack = {
                                "type": "maze_move_ack",
                                "success": success,
                                "message": msg,
                                "state": state
                            }
                            _ack_row = await self.maze_repo.get_by_maze_id(maze_id)
                            if _ack_row:
                                # MOVE-ACK-REFRESH: always echo the authoritative
                                # nonce/growthcount — even on rejected moves — so
                                # a client that signed with a stale view (the
                                # [SIG FAIL] storm) can recover on the next
                                # attempt instead of wedging permanently.
                                ack["movenonce"] = int(_ack_row["movenonce"])
                                ack["growthcount"] = int(_ack_row["growthcount"])
                            ghost = self.consensus._ghost_tuple(_ack_row)
                            if ghost:
                                ack["ghost"] = list(ghost)
                            sealed = self.consensus._sealed_walls.get(maze_id)
                            if sealed:
                                ack["sealed_walls"] = [list(w) for w in sealed]
                            if success and (state.get("caught") or state.get("shrink")):
                                try:
                                    row = await self.maze_repo.get_by_maze_id(maze_id)
                                    if row:
                                        loop = asyncio.get_event_loop()
                                        sparse_maze = await loop.run_in_executor(
                                            self.consensus._move_executor,
                                            self.consensus._generate_deterministic_maze,
                                            row["seed"], row["size"],
                                            int(row["walldensityppm"]), int(row["turbulenceppm"]), self.height
                                        )
                                        ack["maze"] = sparse_to_dense(sparse_maze)
                                        ack["size"] = row["size"]
                                        ack["start"] = [row["posx"], row["posy"], row["posz"]]
                                        ack["goal"] = [row["goalx"], row["goaly"], row["goalz"]]
                                        ack["growthcount"] = row["growthcount"]
                                        ack["movenonce"] = row["movenonce"]
                                except Exception as e:
                                    logger.error(f"[WS] maze growth send error for {miner_id}: {e}", exc_info=True)
                            await ws.send_json(ack)
                        if (success or state.get("type") == "wall_hit") and getattr(self, 'p2p', None):
                            # NEW-MOVE-GOSSIP: mirror the applied signed move to
                            # peers so follower maze rows (position, nonce,
                            # activity) stay current between seals. Data
                            # propagation only — election rules untouched
                            # (LOTTERY-1 still pending DeepSeek's answer).
                            # ROW-SNAPSHOT: attach the authoritative post-move
                            # row + pos history + oscillation flag; wall hits
                            # (success=False) now gossip too, so follower
                            # consecutivewallhits / ghost / goal state matches
                            # the origin instead of drifting.
                            try:
                                _post_row = await self.maze_repo.get_by_maze_id(maze_id)
                                # ROW-SNAPSHOT pub: followers have no miners
                                # table entry for a foreign miner, so carry the
                                # origin's pub — it is bound to the miner_id by
                                # the PC_ derivation (see MSG_NEW_MOVE handler).
                                _g_pubrow = await self.miner_repo.get(miner_id)
                                _g_pub = ""
                                if _g_pubrow and _g_pubrow.get("pub"):
                                    _g_pub = _g_pubrow["pub"]
                                elif miner_id in self.miners:
                                    _g_pub = (self.miners[miner_id] or {}).get("pub", "")
                                _gossip = {
                                    "miner_id": miner_id, "maze_id": maze_id,
                                    "direction": direction, "signature": signature,
                                    "height": self.height,
                                    "move_nonce": int(_pre_row["movenonce"]) + 1 if _pre_row else (move_nonce if move_nonce is not None else 0),
                                    "growthcount": _pre_growthcount,
                                    "pub": _g_pub,
                                    "row": dict(_post_row) if _post_row else None,
                                    "pos_hist": [[int(v) for v in p] for p in self.consensus._pos_history.get(maze_id, [])],
                                    "oscillating": maze_id in self.consensus._oscillating_mazes,
                                }
                                await self.p2p.broadcast_message(MSG_NEW_MOVE, json.dumps(_gossip).encode())
                            except Exception as _ge:
                                logger.debug(f"[WS] move-gossip broadcast failed: {_ge}")
                    except Exception as e:
                        logger.error(f"[WS] maze_move task error: {e}", exc_info=True)
                        if not ws.closed:
                            try:
                                await ws.send_json({"type": "error", "message": f"Internal error: {str(e)}"})
                            except Exception:
                                pass
                    finally:
                        self.consensus._inflight_moves.discard(miner_id)

                _t = asyncio.create_task(_process_and_reply())
                session.setdefault("tasks", set()).add(_t)
                _t.add_done_callback(lambda _: session.get("tasks", set()).discard(_t))
            except Exception as e:
                logger.error(f"[WS] maze_move error: {e}", exc_info=True)
                await ws.send_json({"type": "error", "message": f"Internal error: {str(e)}"})

        elif msg_type == "wall_hit_solve":
            miner_id = data.get("miner_id")
            maze_id = data.get("maze_id") or miner_id
            # WS-SESSION-BIND-1 / MAZE-OWNER-1: a wall-hit challenge may only
            # be solved by the authenticated owner of that maze. Previously
            # any connection could clear (and advance the ghost of) any maze.
            if (not isinstance(miner_id, str) or not isinstance(maze_id, str)
                    or len(miner_id) > 128 or len(maze_id) > 192
                    or not (session.get("authenticated") and session.get("miner_id") == miner_id)):
                await ws.send_json({"type": "wall_hit_solved", "accepted": False, "error": "Not authenticated as miner"})
                return
            _own_row = await self.maze_repo.get_by_maze_id(maze_id)
            if not _own_row or str(_own_row.get("minerid") or "") != miner_id:
                await ws.send_json({"type": "wall_hit_solved", "accepted": False, "error": "Maze not owned by miner"})
                return
            if not await self._miner_path_allowed(miner_id):
                await ws.send_json({"type": "wall_hit_solved", "accepted": False, "error": "Rate limit exceeded"})
                return
            pending = self.consensus._pending_pow.get(maze_id)
            accepted = False
            caught_by_ghost = False
            if pending:
                seed, difficulty, ts = pending
                if time.time() - ts > 60:
                    self.consensus._pending_pow.pop(maze_id, None)
                else:
                    try:
                        nonce = int(data.get("nonce"))
                        digest = hashlib.sha256(f"{seed}{nonce}".encode()).digest()
                        accepted = int.from_bytes(digest, "big") >> (256 - difficulty) == 0
                    except (TypeError, ValueError, OverflowError):
                        accepted = False
                    if accepted:
                        self.consensus._pending_pow.pop(maze_id, None)

            resp = {"type": "wall_hit_solved", "accepted": accepted}
            if accepted:
                async def _solve_and_reply():
                    try:
                        if ws.closed:
                            return
                        caught = False
                        async with self.consensus._lock_for(maze_id):
                            row = await self.consensus.maze_repo.get_by_maze_id(maze_id)
                            if row:
                                gpos = self.consensus._ghost_tuple(row)
                                gpos_moved = False
                                gsize = int(row["size"])
                                msx, msy, msz = int(row["posx"]), int(row["posy"]), int(row["posz"])
                                loop = asyncio.get_event_loop()
                                msparse = await loop.run_in_executor(
                                    self.consensus._move_executor,
                                    self.consensus._generate_deterministic_maze,
                                    row["seed"], gsize, int(row["walldensityppm"]),
                                    int(row["turbulenceppm"]), self.height)
                                mdense = sparse_to_dense(msparse)
                                if gpos:
                                    if maze_id in self.consensus._oscillating_mazes:
                                        # Oscillation mode: sweep frozen cycle cells
                                        if maze_id not in self.consensus._ghost_cycle:
                                            cycle_cells = []
                                            for p in self.consensus._pos_history.get(maze_id, []):
                                                if p not in cycle_cells:
                                                    cycle_cells.append(p)
                                            if cycle_cells:
                                                def _manh(a, b):
                                                    return abs(a[0]-b[0]) + abs(a[1]-b[1]) + abs(a[2]-b[2])
                                                farthest_idx = max(range(len(cycle_cells)),
                                                                   key=lambda i: _manh(gpos, cycle_cells[i]))
                                                self.consensus._ghost_cycle[maze_id] = cycle_cells
                                                self.consensus._ghost_cycle_idx[maze_id] = farthest_idx
                                                self.consensus._ghost_frozen_target[maze_id] = cycle_cells[farthest_idx]
                                        if maze_id in self.consensus._ghost_cycle:
                                            cycle_cells = self.consensus._ghost_cycle[maze_id]
                                            idx = self.consensus._ghost_cycle_idx[maze_id]
                                            target = cycle_cells[idx]
                                            if gpos == target:
                                                idx = (idx + 1) % len(cycle_cells)
                                                self.consensus._ghost_cycle_idx[maze_id] = idx
                                                target = cycle_cells[idx]
                                            for _ in range(3):
                                                gdx, gdy, gdz = self.consensus._bfs_next_step(mdense, gsize, gpos, target)
                                                if gdx is None:
                                                    break
                                                new_gpos = (gpos[0]+gdx, gpos[1]+gdy, gpos[2]+gdz)
                                                gpos = new_gpos
                                                gpos_moved = True
                                                if new_gpos == (msx, msy, msz):
                                                    caught = True
                                                    restart_ev = await self.consensus._restart_position(dict(row), maze_id, row["minerid"], gsize)
                                                    if restart_ev:
                                                        await self.consensus.maze_repo.upsert({**dict(row), **restart_ev})
                                                    break
                                    else:
                                        for _ in range(3):
                                            gdx, gdy, gdz = self.consensus._bfs_next_step(mdense, gsize, gpos, (msx, msy, msz))
                                            if gdx is None:
                                                break
                                            new_gpos = (gpos[0]+gdx, gpos[1]+gdy, gpos[2]+gdz)
                                            gpos = new_gpos
                                            gpos_moved = True
                                            if new_gpos == (msx, msy, msz):
                                                caught = True
                                                restart_ev = await self.consensus._restart_position(dict(row), maze_id, row["minerid"], gsize)
                                                if restart_ev:
                                                    await self.consensus.maze_repo.upsert({**dict(row), **restart_ev})
                                                break
                                if gpos_moved and not caught:
                                    self.consensus._set_ghost(row, gpos)
                                    await self.consensus.maze_repo.upsert(dict(row))
                        reply = {"type": "wall_hit_solved", "accepted": True, "caught": caught}
                        reply["sealed_walls"] = list(self.consensus._sealed_walls.get(maze_id, set()))
                        reply["ghost"] = None
                        try:
                            row_data = await self.maze_repo.get_by_maze_id(maze_id)
                            if row_data:
                                _gp = self.consensus._ghost_tuple(row_data)
                                reply["ghost"] = list(_gp) if _gp else None
                                reply["position"] = [int(row_data["posx"]), int(row_data["posy"]), int(row_data["posz"])]
                                reply["goal"] = [int(row_data["goalx"]), int(row_data["goaly"]), int(row_data["goalz"])]
                                reply["size"] = int(row_data["size"])
                                reply["movenonce"] = int(row_data["movenonce"])
                                reply["growthcount"] = int(row_data["growthcount"])
                                sz = int(row_data["size"])
                                loop = asyncio.get_event_loop()
                                sp = await loop.run_in_executor(
                                    self.consensus._move_executor,
                                    self.consensus._generate_deterministic_maze,
                                    row_data["seed"], sz, int(row_data["walldensityppm"]),
                                    int(row_data["turbulenceppm"]), self.height)
                                maze_arr = sparse_to_dense(sp)
                                sealed_here = self.consensus._sealed_walls.get(maze_id, set())
                                for wx, wy, wz in sealed_here:
                                    if 0 <= wz < sz and 0 <= wy < sz and 0 <= wx < sz:
                                        maze_arr[wz][wy][wx] = 1
                                reply["maze"] = maze_arr
                        except Exception:
                            pass
                        if not ws.closed:
                            await ws.send_json(reply)
                    except Exception as e:
                        logger.error(f"[WS] wall_hit_solve task error: {e}", exc_info=True)
                        if not ws.closed:
                            try:
                                await ws.send_json({"type": "error", "message": str(e)})
                            except Exception:
                                pass
                _t = asyncio.create_task(_solve_and_reply())
                session.setdefault("tasks", set()).add(_t)
                _t.add_done_callback(lambda _: session.get("tasks", set()).discard(_t))
            else:
                resp["caught"] = False
                await ws.send_json(resp)

        elif msg_type == "knowledge_report":
            # Wall/knowledge reporting – acknowledge for backward compatibility
            await ws.send_json({"type": "knowledge_ack", "accepted": True})

        elif msg_type == "lottery_commit":
            miner_id = data.get("miner_id")
            commit = data.get("commit")
            target_height = data.get("height")
            if not all([miner_id, commit, target_height is not None]):
                await ws.send_json({"type": "error", "message": "Missing fields"})
                return
            # LOTTERY-AUTH-1 (mainnet audit): commits/reveals are bound to
            # the authenticated session (same rule as maze_move) — any
            # unauthenticated peer could otherwise overwrite anyone's
            # commitment and break their reveal.
            if not (session.get("authenticated") and session.get("miner_id") == miner_id):
                await ws.send_json({"type": "error", "message": "Not authenticated as miner"})
                return
            if target_height < self.height + 1 or target_height > self.height + 2:
                await ws.send_json({"type": "error", "message": "Commit window is [height+1, height+2]"})
                return
            commits = self.consensus._lottery_commits.setdefault(target_height, {})
            commits[miner_id] = commit
            await self.consensus.lottery_repo.put_commit(target_height, miner_id, commit)
            await ws.send_json({"type": "lottery_commit_ack", "accepted": True})

        elif msg_type == "lottery_reveal":
            miner_id = data.get("miner_id")
            secret = data.get("secret")
            target_height = data.get("height")
            if not all([miner_id, secret, target_height is not None]):
                await ws.send_json({"type": "error", "message": "Missing fields"})
                return
            # LOTTERY-AUTH-1: same session binding as commits (see above).
            if not (session.get("authenticated") and session.get("miner_id") == miner_id):
                await ws.send_json({"type": "error", "message": "Not authenticated as miner"})
                return
            if target_height <= self.height:
                await ws.send_json({"type": "error", "message": "Reveal too late"})
                return
            commits = self.consensus._lottery_commits.get(target_height, {})
            expected_commit = commits.get(miner_id)
            if not expected_commit:
                await ws.send_json({"type": "error", "message": "No commit found"})
                return
            actual_commit = eth_keccak(bytes.fromhex(secret) + miner_id.encode() + target_height.to_bytes(8, "big")).hex()
            if actual_commit != expected_commit:
                await ws.send_json({"type": "error", "message": "Commit mismatch"})
                return
            reveals = self.consensus._lottery_reveals.setdefault(target_height, {})
            reveals[miner_id] = secret
            await self.consensus.lottery_repo.put_reveal(target_height, miner_id, secret)
            await ws.send_json({"type": "lottery_reveal_ack", "accepted": True})

        elif msg_type == "get_maze_state":
            miner_id = data.get("miner_id")
            maze_id = data.get("maze_id") or miner_id
            if not miner_id:
                await ws.send_json({"type": "error", "message": "Missing miner_id"})
                return
            if ws.closed:
                return
            row = await self.maze_repo.get_by_maze_id(maze_id)
            state = None
            if row:
                size = row["size"]
                loop = asyncio.get_event_loop()
                sparse_maze = await loop.run_in_executor(
                    self.consensus._move_executor,
                    self.consensus._generate_deterministic_maze,
                    row["seed"], size, int(row["walldensityppm"]), int(row["turbulenceppm"]), self.height
                )
                maze_array = sparse_to_dense(sparse_maze)
                sx, sy, sz = row["posx"], row["posy"], row["posz"]
                gx, gy, gz = row["goalx"], row["goaly"], row["goalz"]
                # Apply sealed walls so state sync doesn't clear them
                sealed = self.consensus._sealed_walls.get(maze_id, set())
                for wx, wy, wz in sealed:
                    if 0 <= wz < size and 0 <= wy < size and 0 <= wx < size:
                        maze_array[wz][wy][wx] = 1
                # Validate start is walkable; if walled, find nearest open cell
                if not (0 <= sx < size and 0 <= sy < size and 0 <= sz < size) or maze_array[sz][sy][sx] == 1:
                    sx, sy, sz = self.consensus._find_nearest_open(maze_array, size, sx, sy, sz)
                    await self.maze_repo.upsert({**dict(row), "posx": sx, "posy": sy, "posz": sz, "updatedat": int(time.time())})
                # Validate goal is walkable; if walled, find nearest open cell
                if not (0 <= gx < size and 0 <= gy < size and 0 <= gz < size) or maze_array[gz][gy][gx] == 1:
                    gx, gy, gz = self.consensus._find_nearest_open(maze_array, size, gx, gy, gz)
                    await self.maze_repo.upsert({**dict(row), "goalx": gx, "goaly": gy, "goalz": gz, "updatedat": int(time.time())})
                state = {
                    "miner_id": row["minerid"],
                    "size": size,
                    "position": (sx, sy, sz),
                    "goal": (gx, gy, gz),
                    "movenonce": row["movenonce"],
                    "mazeroot": row["mazeroot"],
                    "growthcount": row["growthcount"],
                    "walldensityppm": row["walldensityppm"],
                    "turbulenceppm": row["turbulenceppm"],
                    "maze": maze_array,
                    "ghost": list(self.consensus._ghost_tuple(row) or (0, 0, 0)),
                }
            if not ws.closed:
                await ws.send_json({"type": "maze_state", "state": state})

        elif msg_type == "get_fee":
            min_fee = get_dynamic_fee(self.mempool.size())
            token_fee = get_token_creation_fee(self.mempool.size())
            await ws.send_json({
                "type": "fee_info",
                "min_fee": min_fee,
                "base_fee": _config.MIN_FEE,
                "mempool_size": self.mempool.size(),
                "token_creation_fee": token_fee
            })

        elif msg_type == "send_tx":
            tx_data = {
                "from_wallet": (data.get("wallet") or "").lower(),
                "to_wallet": (data.get("to") or "").lower(),
                "value": data.get("amount", 0),
                "fee": data.get("fee", 0),
                "nonce": data.get("nonce", 0),
                "timestamp": float(data.get("timestamp")) if data.get("timestamp") else time.time(),
                "tx_type": "send",
                "signature": data.get("signature"),
                "pub_key": data.get("pub_key"),
                "data": data.get("data", {})
            }
            tx_hash = hash_tx(tx_data)
            tx_data["tx_hash"] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({"type": "tx_failed", "error": "Invalid signature"})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({"type": "tx_accepted", "tx_hash": tx_hash})
            else:
                await ws.send_json({"type": "tx_failed", "error": "Mempool full or invalid"})

        elif msg_type == "token_transfer":
            tx_data = {
                "from_wallet": (data.get("wallet") or "").lower(),
                "to_wallet": (data.get("to") or "").lower(),
                "value": data.get("amount", 0),
                "fee": data.get("fee", 0),
                "nonce": data.get("nonce", 0),
                "timestamp": float(data.get("timestamp")) if data.get("timestamp") else time.time(),
                "tx_type": "token_transfer",
                "signature": data.get("signature"),
                "token_address": data.get("token_address"),
                "data": data.get("data", {})
            }
            tx_hash = hash_tx(tx_data)
            tx_data["tx_hash"] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({"type": "tx_failed", "error": "Invalid signature"})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({"type": "tx_accepted", "tx_hash": tx_hash})
            else:
                await ws.send_json({"type": "tx_failed", "error": "Mempool full or invalid"})

        elif msg_type == "deploy_contract":
            tx_data = {
                "from_wallet": (data.get("wallet") or "").lower(),
                "to_wallet": (data.get("wallet") or "").lower(),
                "value": 0,
                "fee": data.get("fee", 0),
                "nonce": data.get("nonce", 0),
                "timestamp": float(data.get("timestamp")) if data.get("timestamp") else time.time(),
                "tx_type": "contract_deploy",
                "signature": data.get("signature"),
                "bytecode": data.get("bytecode", ""),
                "abi": data.get("abi", {})
            }
            # R6-value-moved-bind: submitted marker is part of the signed message (present iff value moves).
            try:
                _wsv = int(tx_data.get("value", 0) or 0)
            except (TypeError, ValueError):
                _wsv = 0
            if _wsv > 0:
                tx_data["_value_moved"] = _wsv
            tx_hash = hash_tx(tx_data)
            tx_data["tx_hash"] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({"type": "tx_failed", "error": "Invalid signature"})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({"type": "tx_accepted", "tx_hash": tx_hash})
            else:
                await ws.send_json({"type": "tx_failed", "error": "Mempool full or invalid"})

        elif msg_type == "call_contract":
            tx_data = {
                "from_wallet": (data.get("wallet") or "").lower(),
                "to_wallet": (data.get("contract_address") or "").lower(),
                "value": data.get("value", 0),
                "fee": data.get("fee", 0),
                "nonce": data.get("nonce", 0),
                "timestamp": float(data.get("timestamp")) if data.get("timestamp") else time.time(),
                "tx_type": "contract_call",
                "signature": data.get("signature"),
                "input": data.get("input", ""),
                "gas": data.get("gas_limit", _config.GAS_LIMIT_DEFAULT)
            }
            # TXTYPE-BIND-1: canonicalize `input` into `data` (see REST).
            if tx_data.get("input") is not None and not tx_data.get("data"):
                tx_data["data"] = tx_data.pop("input")
            # R6-value-moved-bind: submitted marker is part of the signed message (present iff value moves).
            try:
                _wsv = int(tx_data.get("value", 0) or 0)
            except (TypeError, ValueError):
                _wsv = 0
            if _wsv > 0:
                tx_data["_value_moved"] = _wsv
            tx_hash = hash_tx(tx_data)
            tx_data["tx_hash"] = tx_hash
            if not self._verify_tx_signature(tx_data):
                await ws.send_json({"type": "tx_failed", "error": "Invalid signature"})
                return
            if await self.mempool.add(tx_data):
                await self.p2p.broadcast_transaction(tx_data)
                await ws.send_json({"type": "tx_accepted", "tx_hash": tx_hash})
            else:
                await ws.send_json({"type": "tx_failed", "error": "Mempool full or invalid"})

        # R5-ws-dead-tx-handlers: create_token/create_htlc submitted unsupported types; removed. Use /api/v1/tokens instead.
        elif msg_type == "get_balance":
            wallet = data.get("wallet")
            if not wallet:
                await ws.send_json({"type": "balance", "balance": 0, "error": "Missing wallet"})
                return
            bal = await self.get_balance(wallet.lower() if isinstance(wallet, str) else wallet)
            await ws.send_json({"type": "balance", "balance": bal})

        elif msg_type == "get_status":
            status = {"height": self.height, "peers": self.p2p.get_peer_count() if self.p2p else 0, "miners": len(self.miners), "version": VERSION}
            await ws.send_json({"type": "status", "data": status})

        elif msg_type == "get_blocks":
            limit, offset = _ws_page_params(data)
            blocks = []
            total = len(self.blocks)
            start = max(0, total - offset - limit)
            end = total - offset
            for b in self.blocks[start:end]:
                blocks.append({"height": b['id'], "timestamp": b['ts'], "miners": len(b.get('miners', [])), "reward": b.get('reward',0)//SUBS, "hash": b['hash']})
            blocks.reverse()
            has_more = (total - offset - limit) > 0
            await ws.send_json({"type": "blocks", "data": {"blocks": blocks, "has_more": has_more}})

        elif msg_type == "get_transactions":
            limit, offset = _ws_page_params(data)
            if self.db.db_type == "sqlite":
                query = "SELECT tx_hash, from_wallet, to_wallet, amount, timestamp, block_id, status FROM transactions WHERE block_id >= 0 ORDER BY timestamp DESC LIMIT ? OFFSET ?"
            else:
                query = "SELECT tx_hash, from_wallet, to_wallet, amount, timestamp, block_id, status FROM transactions WHERE block_id >= 0 ORDER BY timestamp DESC LIMIT $1 OFFSET $2"
            rows = await self.db.fetch(query, limit, offset)
            txs = [{"hash": r['tx_hash'][:12], "full_hash": r['tx_hash'], "from": r['from_wallet'], "to": r['to_wallet'], "amount": r['amount']//SUBS, "timestamp": r['timestamp'], "block": r['block_id'], "status": r['status']} for r in rows]
            total_row = await self.db.fetchrow("SELECT COUNT(*) FROM transactions WHERE block_id >= 0")
            total = total_row['count'] if total_row else 0
            has_more = (total - offset - limit) > 0
            await ws.send_json({"type": "transactions", "data": {"transactions": txs, "has_more": has_more}})

        elif msg_type == "get_miners":
            wallet = data.get("wallet")
            if wallet:
                miners = await self.miner_repo.get_by_wallet(wallet)
            else:
                miners = await self.miner_repo.get_active()
            miners_list = [{"miner_id": m['miner_id'], "wallet": m['wallet'], "active": m['active'], "blocks": m['blocks'], "rewards": m['rewards']//SUBS, "uptime": m['uptime'], "last_ping": m['last_ping']} for m in miners]
            # J5a: bound the response frame (registration is cheap; the table
            # is unbounded). Truncation is flagged, never silent.
            _trunc_m = len(miners_list) > 1000
            await ws.send_json({"type": "miners", "miners": miners_list[:1000], "truncated": _trunc_m})

        elif msg_type == "get_tokens":
            wallet = data.get("wallet")
            if wallet:
                tokens = await self.db.fetch("SELECT * FROM tokens WHERE owner = ?" if self.db.db_type == "sqlite" else "SELECT * FROM tokens WHERE owner = $1", wallet)
            else:
                tokens = await self.db.fetch("SELECT * FROM tokens")
            # J5a: bound the response frame (see miners above).
            _toks = [dict(t) for t in tokens]
            await ws.send_json({"type": "tokens", "tokens": _toks[:1000], "truncated": len(_toks) > 1000})

        elif msg_type == "get_htlc":
            htlc_id = data.get("htlc_id")
            if not htlc_id:
                await ws.send_json({"type": "error", "message": "Missing htlc_id"})
                return
            htlc = await self.htlc_repo.get(htlc_id)
            if htlc:
                await ws.send_json({"type": "htlc", "data": htlc})
            else:
                await ws.send_json({"type": "htlc", "data": None})

        elif msg_type == "uptime_ping":
            miner_id = data.get("miner_id")
            uptime_seconds = data.get("uptime_seconds", 0)
            if miner_id:
                if self.miner_websockets.get(miner_id) is not ws or session.get("miner_id") != miner_id or not session.get("authenticated"):
                    await ws.send_json({"type": "error", "message": "uptime_ping from unauthenticated connection"})
                    return
                await self.miner_repo.update_last_ping(miner_id)
                # Also refresh maze updatedat so miner stays PoG-eligible
                maze_rows = await self.maze_repo.get(miner_id)
                if maze_rows:
                    for mz in maze_rows:
                        await self.maze_repo.upsert({**dict(mz), "updatedat": int(time.time())})
                logger.debug(f"[WS] Uptime ping from {miner_id}: {uptime_seconds}s")

        elif msg_type == "block_signed":
            miner_id = data.get("miner_id")
            signed_block = data.get("block")
            if miner_id and signed_block:
                if self.miner_websockets.get(miner_id) is not ws:
                    await ws.send_json({"type": "error", "message": "block_signed from unregistered connection"})
                    return
                future = self._block_sign_futures.get(miner_id)
                if future and not future.done():
                    future.set_result(signed_block)
                    logger.debug(f"[WS] Received block_signed from {miner_id[:16]}")
                else:
                    logger.warning(f"[WS] block_signed from {miner_id[:16]} with no pending future")
            else:
                await ws.send_json({"type": "error", "message": "block_signed missing miner_id or block"})

        else:
            await ws.send_json({"type": "error", "message": f"Unknown message type: {msg_type}"})

    # ─── Start the Node ──────────────────────────────────────────────────────
    def _finality_lag_blocks(self) -> int:
        """Blocks between the local tip and the last finality checkpoint."""
        try:
            last_final = self.finality_gadget.get_last_finalized_block()
            if last_final <= 0:
                return max(0, self.height - 1)
            return max(0, (self.height - 1) - last_final)
        except Exception:
            return 0

    async def _verify_chain_integrity(self, depth: int = 100):
        latest = await self.block_repo.get_latest()
        if not latest: return
        end = latest['id']; start = max(0, end - depth)
        blocks = await self.block_repo.get_range(start, end, limit=depth + 1)
        prev_hash = None
        for b in sorted(blocks, key=lambda x: x['id']):
            expected = calculate_block_hash({k: v for k, v in b.items() if k not in CONSENSUS_EXCLUDED_FIELDS})
            if b.get('hash') != expected and b.get('id', 0) > 0:
                logger.error(f"[Integrity] Block {b['id']} hash mismatch"); sys.exit(1)
            if prev_hash is not None and b.get('phash') != prev_hash and b.get('id', 0) > 0:
                logger.error(f"[Integrity] Block {b['id']} parent mismatch"); sys.exit(1)
            prev_hash = b.get('hash', '')
        logger.info(f"[Integrity] Verified last {len(blocks)} blocks")

    async def _restore_from_latest_snapshot(self) -> bool:
        # R8-snapshot-restore (R7-04): snapshot_data maps key -> the EXACT
        # JSON value-encoding stored in _dirty (strings, never re-encoded;
        # StateTrie.put encodes once, the save site stores dict(_dirty)
        # verbatim). Validate-before-apply: the candidate root is computed
        # with zero DB writes; _dirty/height/last_hash change only on
        # success, so a failed restore leaves running state byte-identical.
        # Empty snapshots never rewind the tip (they prove nothing). DB rows
        # above the snapshot are NOT rolled back here — a rewound tip must
        # re-sync/verify forward (see _verify_chain_integrity, which runs
        # right after this in start()).
        row = await self.db.fetchrow("SELECT block_id, state_root, snapshot_data FROM state_snapshots ORDER BY block_id DESC LIMIT 1")
        if not row: return False
        if self.height <= int(row['block_id']) + 500: return False
        try: data = json.loads(row['snapshot_data'])
        except Exception: return False
        if not isinstance(data, dict) or not data: return False
        try:
            candidate = {k: (v if isinstance(v, str)
                             else json.dumps(v, sort_keys=True, separators=(',', ':')))
                         for k, v in data.items()}
        except Exception:
            return False
        _probe = StateTrie(self.db)
        _probe._dirty = dict(candidate)
        try:
            root, _ = _probe._compute_root()
        except Exception:
            return False
        if root != row['state_root']: return False
        blk = await self.block_repo.get_by_id(int(row['block_id']))
        if not blk: return False
        _prior_dirty = dict(self.state_trie._dirty)
        self.state_trie._dirty = dict(candidate)
        _written = await self.state_trie.commit()
        if _written != root:
            # Audit-E: theoretically unreachable (same deterministic
            # computation), but never destroy live dirt — restore aside.
            self.state_trie._dirty = _prior_dirty
            return False
        self.height = int(row['block_id']) + 1
        self.last_hash = blk.get('hash', '')
        logger.info(f"[Snapshot] Restored state from block {row['block_id']}")
        return True

    async def start(self):
        try:
            import importlib.util as _ilu
            _missing_opt = [pip_name for imp, pip_name, req in _DEPS
                            if not req and _ilu.find_spec(imp) is None]
        except Exception:
            _missing_opt = []
        if _missing_opt:
            logger.info(f"[Startup] Optional packages not installed: {_missing_opt}. "
                        f"Some features (Postgres, DHT, uvloop, ML-KEM-768 PQE) are disabled.")
        set_trace_id(f"start-{new_trace_id()}")
        # MAINNET-CONFIG-GUARD: refuse to boot with a mainnet-shaped DB and test
        # settings. The operator opts into mainnet by setting the marker.
        _is_mainnet = bool(self.config.get('node', {}).get('mainnet', False))
        if _is_mainnet:
            failures = _mainnet_guard_failures(self.config)
            if failures:
                for f in failures:
                    logger.error(f"[MAINNET-CONFIG-GUARD] {f}")
                sys.exit(1)
        # MCX79: log the validator mode once at node start (open = any key
        # may produce; restricted = fixed set enforced).
        _validator_boot_mode()
        await self.db.initialize()
        await self.db.create_tables()
        await self._normalize_wallet_case()
        await self._load_state()
        await self._restore_from_latest_snapshot()
        await self._verify_chain_integrity()

        # Load genesis identity on every startup (before P2P)
        genesis_data = load_genesis_file()
        if not genesis_data:
            # genesis.json missing — CANNOT reconstruct from block 0 in DB.
            # Fix 1 (R10): the identity hash commits the alloc map and the
            # full consensus record, neither of which survives in chain
            # state (DB rows carry no alloc column; current balances !=
            # genesis alloc after any reward/fee movement). Any fabricated
            # file would fail the identity layer at the next boot, so
            # writing one only creates a boot loop — fail closed instead
            # with an operator-actionable message. Copy genesis.json from
            # the seed node or a running peer.
            block0 = await self.block_repo.get_by_id(0)
            if block0:
                logger.error("[GENESIS] genesis.json missing but block 0 exists in DB — refusing to fabricate "
                             "an unverifiable replacement (alloc map and consensus record are not recoverable "
                             "from chain state). Copy genesis.json from the seed node or a running peer, then restart.")
                sys.exit(1)
            else:
                logger.warning(f"[GENESIS] No {_genesis.GENESIS_FILE} found. Will attempt P2P discovery or create new genesis.")

        # Fix 1 (R10) startup gate: the local file gets the SAME full
        # identity verification as peer-learned files (hash over header +
        # economics + ruleset, economics policy, ruleset compatibility) —
        # local files are no longer trusted implicitly. Legacy files fail
        # the identity layer here and refuse to boot (chain reset; see
        # R9_MIGRATION_NOTES.md), never grandfathered.
        if genesis_data:
            _vok, _vwhy = genesis_export_verified(genesis_data)
            if not _vok:
                logger.error(f"[GENESIS] Local {_genesis.GENESIS_FILE} failed verification: {_vwhy}; refusing to start. "
                             f"If this names a consensus key, your config.yaml differs from the node that created this genesis: "
                             f"consensus.*, vm.*, fees.*, p2p.ban_duration and consensus.validators must be IDENTICAL on every node.")
                sys.exit(1)

        # R9-consensus-config (I-R8-07): one ruleset per process, bound to
        # genesis, before networking starts. Files without a record
        # (pre-R9 chains) warn and proceed; mismatches refuse to boot
        # instead of validating with mixed rules.
        if genesis_data:
            _cok, _cwhy = check_consensus_params(self.config, genesis_data)
            if not _cok:
                logger.error(f"[CONFIG] Consensus parameters disagree with genesis record: {_cwhy}; refusing to start")
                sys.exit(1)
            if _cwhy != "ok":
                logger.warning(f"[CONFIG] Genesis consensus record absent ({_cwhy}); running on effective config")

        # GENESIS-DBBIND-1: the verified genesis.json must be the genesis of the
        # chain this database actually holds — checked BEFORE networking starts
        # (a mismatch exits; a DB with no block 0 is left to ensure_genesis()).
        await self._bind_genesis_to_db()

        # Recover pending maze updates from DB (crash recovery)
        try:
            rows = await self.db.fetch("SELECT block_id,minerid,update_json FROM pending_maze_updates WHERE block_id > ?", self.height - 1)
            if rows:
                self.consensus._pending_maze_updates = [json.loads(r['update_json']) for r in rows]
                logger.info(f"[Recovery] Loaded {len(rows)} pending maze updates from DB")
        except Exception:
            pass

        self.vm_manager = VMManager(
            self.db, self.contract_v2_repo, self.contract_storage_v2_repo,
            self.token_balance_repo, self.balance_repo, self.htlc_repo
        )
        self.vm_manager.node = self

        # F4: reload the mempool persisted before the last shutdown. A crash
        # between execute-at-produce and seal left the tx in state (its row is
        # confirmed) but gone from memory — without restore the re-produced
        # block sealed empty and followers never replayed the tx. Attach and
        # restore BEFORE p2p/ws come up so no inbound tx races the reload.
        self.mempool.attach_db(self.db)
        await self._mempool_restore()

        self._ws_task = asyncio.create_task(self._run_websocket())
        await asyncio.sleep(0.5)

        self.p2p = P2PNode(self, self.db)
        await self.p2p.start()

        self.consensus = PoGConsensus(self)
        await self.mempool.start_cleanup()
        await self.rate_limiter.start_cleanup()
        await self.subnet_rate_limiter.start_cleanup()
        await self.register_rate_limiter.start_cleanup()
        await self.rpc_rate_limiter.start_cleanup()

        _chain_ready = await self.ensure_genesis()
        # GENESIS-JOIN-1: produce only on established state (existing chain,
        # freshly synced chain, or deliberate new genesis). A restored-but-
        # unsynced join keeps production paused; the sync loop re-enables it
        # on progress (see the stuck-cycle heal). The embedded miner task
        # still starts — it only signs what production_loop asks for, which
        # honors this flag.
        self._producing_enabled = bool(_chain_ready)
        if not _chain_ready:
            logger.warning("[Genesis] Block production paused until chain sync establishes state.")
        self._production_task = asyncio.create_task(self.consensus.production_loop())
        self._node_cleanup_task = asyncio.create_task(self._cleanup_loop())
        self._automation_task = asyncio.create_task(self._automation_loop())
        await self._start_embedded_miner()

        shutdown_event = asyncio.Event()
        def signal_handler():
            asyncio.create_task(self.shutdown())
            shutdown_event.set()
        loop = asyncio.get_running_loop()
        if sys.platform != 'win32':
            loop.add_signal_handler(signal.SIGINT, signal_handler)
            loop.add_signal_handler(signal.SIGTERM, signal_handler)

        await shutdown_event.wait()

        if hasattr(self, '_ws_task'):
            self._ws_task.cancel()
            try:
                await self._ws_task
            except asyncio.CancelledError:
                pass


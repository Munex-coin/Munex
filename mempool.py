# Split of MCX81.py (lines 4577-4918). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import logger
from node.config import MEMPOOL_EXPIRY, MEMPOOL_MAX_NONCE_GAP, MEMPOOL_MAX_SIZE, RBF_INCREMENT, SPATIAL_BASE_DEPLOY_FEE
from node.crypto import hash_tx
from node.chain import decode_raw_eth_transaction, get_dynamic_fee, get_token_creation_fee
from node.bootstrap import Dict, List, Tuple, asyncio, base64, hashlib, hmac, json, secrets, time


# ─── Mempool ──────────────────────────────────────────────────

def _tx_size(tx: Dict) -> int:
    # R6-eviction-serialize-consistency: the single byte-size measure for
    # eviction ranking AND persistence (compact separators — _persist
    # writes this exact encoding, so ranked sizes equal stored sizes).
    return len(json.dumps(tx, separators=(',', ':')).encode("utf-8"))


class Mempool:
    """Unconfirmed-transaction pool (memory + optional DB persistence).

    R6-cpfp-package-fee: CPFP is not implemented — admission judges each
    transaction's own fee only (no package-fee semantics). The old
    parent-hash/floor pseudo-check was removed rather than left
    half-enforcing; a child referencing a pool parent is admitted or
    rejected exactly like any other transaction.
    """
    def __init__(self, max_size: int = MEMPOOL_MAX_SIZE):
        self.max_size = max_size
        self._lock = asyncio.Lock()
        self._transactions: Dict[str, Dict] = {}
        self._expiry = MEMPOOL_EXPIRY
        self._cleanup_task = None
        self._pending_nonces: Dict[str, int] = {}
        # R6-nonce-tracker-bound: highest sealed nonce per wallet, fed by
        # note_confirmed_nonce (block-commit path should call it; default 0
        # when unwired). The add() bound keys off this, not the tracker.
        self._confirmed_nonces: Dict[str, int] = {}
        self._nonce_lock = asyncio.Lock()
        self.db = None  # F4: set via attach_db() to enable persistence

    def attach_db(self, db):
        # F4: optional DB handle — without it the pool is memory-only (the
        # pre-F4 behavior): a restart silently dropped every accepted tx.
        self.db = db

    async def _persist(self, tx: Dict):
        if self.db is None:
            return
        try:
            tx_hash = tx.get('tx_hash')
            if not tx_hash:
                return
            payload = json.dumps(tx, separators=(',', ':'))
            if self.db.db_type == "sqlite":
                await self.db.execute_dml("INSERT OR REPLACE INTO mempool_persist (tx_hash, tx_json, stored_at) VALUES (?,?,?)", tx_hash, payload, time.time())
            else:
                await self.db.execute_dml("INSERT INTO mempool_persist (tx_hash, tx_json, stored_at) VALUES ($1,$2,$3) ON CONFLICT (tx_hash) DO UPDATE SET tx_json=$2, stored_at=$3", tx_hash, payload, time.time())
        except Exception as e:
            logger.debug(f"[Mempool] persist failed for {str(tx.get('tx_hash'))[:16]}: {e}")

    async def _unpersist(self, tx_hash: str):
        if self.db is None or not tx_hash:
            return
        try:
            if self.db.db_type == "sqlite":
                await self.db.execute_dml("DELETE FROM mempool_persist WHERE tx_hash = ?", tx_hash)
            else:
                await self.db.execute_dml("DELETE FROM mempool_persist WHERE tx_hash = $1", tx_hash)
        except Exception as e:
            logger.debug(f"[Mempool] unpersist failed for {str(tx_hash)[:16]}: {e}")

    async def start_cleanup(self):
        async def cleanup_loop():
            while True:
                await asyncio.sleep(60)
                async with self._lock:
                    await self._cleanup()
        self._cleanup_task = asyncio.create_task(cleanup_loop())

    async def add(self, tx: Dict) -> bool:
        async with self._lock:
            tx_hash = tx.get('tx_hash')
            if not tx_hash or not isinstance(tx_hash, str):
                return False
            clean_hash = tx_hash.removeprefix("0x").lower()
            if len(clean_hash) != 64 or not all(c in "0123456789abcdef" for c in clean_hash):
                return False
            # H-9: Verify hash integrity against transaction payload or raw Ethereum transaction
            sig = tx.get('signature', '')
            is_valid_hash = False
            if isinstance(sig, str) and (sig.startswith('0x') or len(sig) > 130):
                try:
                    decoded = decode_raw_eth_transaction(sig)
                    if decoded.get('hash', '').lower() == tx_hash.lower() or decoded.get('hash', '').removeprefix('0x').lower() == clean_hash:
                        is_valid_hash = True
                except Exception:
                    pass
            if not is_valid_hash:
                tx_body = {k: v for k, v in tx.items() if k != 'tx_hash'}
                if (hash_tx(tx_body) == tx_hash or hash_tx(tx) == tx_hash
                        or hash_tx(tx_body) == clean_hash or hash_tx(tx) == clean_hash):
                    is_valid_hash = True
            if not is_valid_hash:
                return False
            if tx_hash in self._transactions:
                return False
            replacement = next((h for h, old in self._transactions.items()
                                if old.get('from_wallet') == tx.get('from_wallet')
                                and old.get('nonce') == tx.get('nonce')), None)
            if replacement:
                # R6-rbf-atomic-replace: validate the bump only here — the
                # old entry is deleted after the replacement fully validates
                # below (deleting first lost the original whenever a later
                # check such as min_fee rejected the replacement).
                old_fee = self._transactions[replacement].get('fee', 0)
                if tx.get('fee', 0) <= old_fee * RBF_INCREMENT:
                    return False
            # R6-cpfp-package-fee, path (b): the parent-hash/floor
            # pseudo-check is deleted (see class docstring) — it enforced
            # no package-fee semantics and was worse than no check.
            # R8-admit-order (R7-18): complete ALL admission validation
            # BEFORE any pool mutation (eviction below, replacement swap
            # after it). A candidate failing here must leave residents
            # untouched. min_fee reads the pre-eviction size (marginally
            # stricter at capacity than the old post-eviction read).
            min_fee = get_dynamic_fee(len(self._transactions))
            if tx.get('fee', 0) < min_fee:
                return False
            # MEMPOOL-FLOOR-1 (mainnet audit): per-type execution floors.
            # The generic dynamic floor admits token_create/spatial_create
            # below what execute demands — never-sealable residents that
            # clog the pool and crowd out valid txs at capacity.
            _tt = tx.get('tx_type', 'send')
            if _tt == 'token_create':
                try:
                    _fl = get_token_creation_fee(0)
                    _fv = int(tx.get('fee', 0) or 0)
                except (TypeError, ValueError):
                    return False
                if _fv < _fl:
                    return False
            elif _tt == 'spatial_token_create':
                try:
                    _fl = int(SPATIAL_BASE_DEPLOY_FEE)
                    _fv = int(tx.get('fee', 0) or 0)
                except (TypeError, ValueError):
                    return False
                if _fv < _fl:
                    return False
            val = int(tx.get('value', 0))
            fee = int(tx.get('fee', 0))
            if val < 0 or fee < 0:
                return False
            wallet = tx.get('from_wallet', '')
            tx_nonce = int(tx.get('nonce', 0)) if wallet else 0
            if wallet:
                # R8-confirmed-wire (R7-17): seed unknown wallets from
                # canonical state so restarts/long-running accounts judge
                # against reality, not default 0.
                await self._seed_confirmed_nonce(wallet)
                # R9-nonce-floor (I-R8-11): below-confirmed nonces can never
                # seal (execution enforces exact nonce), so reject them at
                # admission instead of letting stale spam occupy the pool
                # and compete in eviction. Negative nonces likewise.
                _confirmed = self._confirmed_nonces.get(wallet, 0)
                if tx_nonce < 0 or tx_nonce < _confirmed:
                    return False
                # R6-nonce-tracker-bound: reject absurd future nonces before
                # they can pin the tracker (hostile gossip vector).
                if tx_nonce > _confirmed + MEMPOOL_MAX_NONCE_GAP:
                    return False
            if len(self._transactions) >= self.max_size:
                await self._cleanup()
            if len(self._transactions) >= self.max_size:
                new_fee = int(tx.get('fee', 0))
                new_size = _tx_size(tx)
                new_fpb = new_fee / max(new_size, 1)
                worst_hash = None
                worst_fpb = float('inf')
                for h, old in self._transactions.items():
                    old_fpb = int(old.get('fee', 0)) / max(_tx_size(old), 1)
                    if old_fpb < worst_fpb:
                        worst_fpb = old_fpb
                        worst_hash = h
                if new_fpb <= worst_fpb:
                    return False
                if worst_hash:
                    evicted = self._transactions.pop(worst_hash)
                    await self._unpersist(worst_hash)
                    logger.debug(f"[Mempool] Evicted lowest-fee tx {worst_hash[:16]} (fpb={worst_fpb:.4f}) for higher-fee tx {tx_hash[:16]} (fpb={new_fpb:.4f})")
            if replacement:
                # R6-rbf-atomic-replace: atomic swap — the old entry leaves
                # only now that the replacement passed every check above.
                del self._transactions[replacement]
                await self._unpersist(replacement)
            self._transactions[tx_hash] = tx
            # Track pending nonce for this wallet (next sequential nonce).
            # wallet/tx_nonce validated above; clamp never lowers.
            if wallet:
                current = self._pending_nonces.get(wallet, 0)
                confirmed = self._confirmed_nonces.get(wallet, 0)
                self._pending_nonces[wallet] = max(current, min(tx_nonce + 1, confirmed + MEMPOOL_MAX_NONCE_GAP))
            # F4: mirror the pool to mempool_persist so a restart cannot
            # silently drop accepted txs (the run-2 incident: tx executed
            # at produce, node died before seal, tx vanished on restart).
            await self._persist(tx)
            return True

    async def remove(self, tx_hash: str) -> bool:
        async with self._lock:
            if tx_hash not in self._transactions:
                return False
            removed = self._transactions.pop(tx_hash)
            await self._unpersist(tx_hash)
            # Update pending nonce tracking: recalculate next sequential nonce
            wallet = removed.get('from_wallet', '')
            if wallet:
                wallet_txs = [tx for tx in self._transactions.values() if tx.get('from_wallet') == wallet]
                if wallet_txs:
                    self._pending_nonces[wallet] = max(int(tx.get('nonce', 0)) for tx in wallet_txs) + 1
                else:
                    self._pending_nonces.pop(wallet, None)
            return True

    async def get(self, limit: int = 100) -> List[Dict]:
        async with self._lock:
            await self._cleanup()
            sorted_txs = sorted(self._transactions.values(), key=lambda t: (-t.get('fee', 0), t.get('nonce', 0)))
            return sorted_txs[:limit]

    async def _cleanup(self):
        now = time.time()
        to_remove = [h for h, tx in self._transactions.items() if now - tx.get('timestamp', 0) > self._expiry]
        for h in to_remove:
            removed = self._transactions.pop(h)
            await self._unpersist(h)
            wallet = removed.get('from_wallet', '')
            if wallet:
                wallet_txs = [tx for tx in self._transactions.values() if tx.get('from_wallet') == wallet]
                if wallet_txs:
                    self._pending_nonces[wallet] = max(int(tx.get('nonce', 0)) for tx in wallet_txs) + 1
                else:
                    self._pending_nonces.pop(wallet, None)
        if to_remove:
            logger.debug(f"[Mempool] Removed {len(to_remove)} expired transactions")

    def size(self) -> int:
        return len(self._transactions)

    async def drain(self, timeout: float = 30.0) -> bool:
        """Wait until the mempool is empty or the timeout expires.
        Returns True if fully drained, False on timeout. Called during
        shutdown so in-flight transactions are not orphaned silently."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if not self._transactions:
                return True
            await asyncio.sleep(0.5)
        logger.warning(f"[Mempool] Drain timeout: {len(self._transactions)} txs still pending")
        return False

    def get_nonce(self, wallet: str) -> int:
        return self._pending_nonces.get(wallet, 0)

    def note_confirmed_nonce(self, wallet: str, nonce: int):
        # R6-nonce-tracker-bound: record the NEXT expected nonce for a
        # wallet (MAX(sealed)+1 semantics, like _get_confirmed_nonce).
        # Monotonic: seal paths push it as nonces seal (produce + append);
        # reorgs clear via forget_confirmed; restarts/lazy paths seed from
        # the canonical transactions table (see add()).
        try:
            nonce = int(nonce)
        except (TypeError, ValueError):
            return
        if wallet:
            self._confirmed_nonces[wallet] = max(self._confirmed_nonces.get(wallet, 0), nonce)

    def forget_confirmed(self, wallet: str = None):
        # R8-confirmed-wire (R7-17): drop derived confirmed state (reorg).
        # Absent entries re-seed lazily from canonical state on next add,
        # so forgetting is always safe, never corrupting.
        if wallet is None:
            self._confirmed_nonces.clear()
        else:
            self._confirmed_nonces.pop(wallet, None)

    async def _seed_confirmed_nonce(self, wallet: str):
        # R8-confirmed-wire (R7-17): seed one wallet's confirmed nonce from
        # the canonical transactions table (same query as
        # _get_confirmed_nonce). Covers restarts and wallets the seal
        # pushes have not seen yet. Best-effort: any failure leaves the
        # map untouched (fail-closed to the old default-0 behavior).
        if not wallet or wallet in self._confirmed_nonces:
            return
        if self.db is None:
            return
        try:
            if self.db.db_type == "sqlite":
                _q = "SELECT COALESCE(MAX(nonce),-1)+1 FROM transactions WHERE from_wallet = ? AND block_id >= 0"
            else:
                _q = "SELECT COALESCE(MAX(nonce),-1)+1 FROM transactions WHERE from_wallet = $1 AND block_id >= 0"
            _seed = await self.db.fetchval(_q, wallet)
            if _seed is not None:
                self._confirmed_nonces[wallet] = max(int(_seed), 0)
        except Exception:
            pass


# ─── Memory Challenge Manager ──────────────────────────────
class MemoryChallengeManager:
    def __init__(self):
        self._pending_challenges: Dict[str, Tuple[str, int, float]] = {}

    def generate_challenge(self, miner_id: str, memory_size: int = 8*1024*1024) -> dict:
        seed = secrets.token_bytes(32)
        seed_b64 = base64.b64encode(seed).decode()
        self._pending_challenges[miner_id] = (seed_b64, memory_size, time.time())
        return {"type": "memory_challenge_request", "seed": seed_b64, "memory_size": memory_size, "timestamp": int(time.time())}

    @staticmethod
    def _fill_and_hash(seed: bytes, memory_size: int) -> bytes:
        h = hashlib.sha256()
        counter = 0
        produced = 0
        chunk_size = 32
        while produced < memory_size:
            block = hashlib.sha256(seed + counter.to_bytes(8, "big")).digest()
            h.update(block)
            produced += chunk_size
            counter += 1
        return h.digest()

    def verify_commitment(self, miner_id: str, seed_b64: str, commitment_b64: str) -> bool:
        if miner_id not in self._pending_challenges:
            return False
        stored_seed, mem_size, created = self._pending_challenges[miner_id]
        del self._pending_challenges[miner_id]
        if stored_seed != seed_b64 or time.time() - created > 60:
            return False
        try:
            commitment = base64.b64decode(commitment_b64)
            seed_bytes = base64.b64decode(seed_b64)
        except Exception:
            return False
        if len(commitment) != 32:
            return False
        expected = self._fill_and_hash(seed_bytes, mem_size)
        return hmac.compare_digest(commitment, expected)



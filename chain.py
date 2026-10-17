# Split of MCX81.py (lines 2295-2677). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import Account, eth_keccak, logger, rlp
from node.config import CHAIN_ID, HALVING_INTERVAL, INITIAL_BLOCK_REWARD, MAX_SUPPLY, PEER_CACHE_FILE, SPATIAL_COORD_BOUND, STATE_TREE_EMPTY_HASH
from node.bootstrap import Any, Dict, List, Tuple, json, requests
from node import config as _config


def get_block_reward(height):
    halvings = height // HALVING_INTERVAL
    reward = INITIAL_BLOCK_REWARD
    for _ in range(halvings):
        reward //= 2
        if reward == 0: break
    return reward


def _validated_block_reward(block: dict, canonical_minted: int):
    # R9-reward-supply (I-R8-02): the single consensus rule for block
    # rewards, used by verify_block_proof AND _append_block alike.
    # Field semantics: block['reward'] is subsidy PLUS fee transfers
    # (fees move to the winner; only the subsidy is newly minted).
    # Returns (base, fees, total) or None on ANY mismatch:
    #   fees == sum of sealed tx envelopes (no trusted total_fees),
    #   base == min(subsidy(height), max(0, MAX_SUPPLY - minted)),
    #   reward == base + fees.
    # The produce path computes identically (cap-then-add); see the
    # equivalence test. Blocks at/below genesis height carry no mint
    # (genesis identity is verified separately). Chain reset / acceptance
    # change: see R9_MIGRATION_NOTES.md.
    try:
        bid = int(block.get('id', -1))
        if bid <= 0:
            # REWARD-GENESIS-1: genesis height mints nothing; a block at
            # height <= 0 that CLAIMS a reward must be rejected (the credit
            # path pays block['reward'] before the mint counter is touched).
            if int(block.get('reward', 0) or 0) != 0 or int(block.get('total_fees', 0) or 0) != 0:
                return None
            return (0, 0, 0)
        txs = block.get('transactions', [])
        if txs is None:
            txs = []
        fees = 0
        for _tx in txs:
            if not isinstance(_tx, dict):
                return None
            fees += int(_tx.get('fee', 0) or 0)
        if int(block.get('total_fees', 0) or 0) != fees:
            return None
        subsidy = get_block_reward(bid)
        room = int(canonical_minted if canonical_minted else 0)
        room = MAX_SUPPLY - room
        if room < 0:
            room = 0
        base = subsidy if subsidy < room else room
        if int(block.get('reward', 0) or 0) != base + fees:
            return None
        return base, fees, base + fees
    except (TypeError, ValueError, OverflowError):
        return None

def _reorg_base_mint(block: dict) -> int:
    """Fix 3 (R10): the orphan-mint/adopted-mint arithmetic in ONE place.

    block['reward'] is base_reward + total_fees but only base_reward is
    newly minted (IMPORT-MINT). Both the rollback rewind and the final
    cumulative assertion must use this exact formula or the conservation
    check compares against a different number than the rewind applied."""
    try:
        return max(0, int(block.get('reward', 0) or 0)
                   - int(block.get('total_fees', 0) or 0))
    except (TypeError, ValueError):
        return 0

def get_dynamic_fee(mempool_size):
    """EIP-1559 style: no hard cap. Base fee adjusts with demand."""
    base = _config.MIN_FEE
    if mempool_size <= 50: return base
    multiplier = min(mempool_size / 500, 100)
    return int(base * (1 + multiplier))

def get_token_creation_fee(mempool_size):
    return _config.TOKEN_CREATION_MULTIPLIER * get_dynamic_fee(mempool_size)

def get_public_ip():
    try:
        return requests.get('https://api.ipify.org', timeout=5).json()['ip']
    except Exception:
        try:
            return requests.get('https://icanhazip.com', timeout=5).text.strip()
        except Exception:
            logger.error("Failed to determine public IP — node cannot register on the network.")
            return None

def save_peers_to_cache(peers):
    try:
        with open(PEER_CACHE_FILE, 'w') as f:
            json.dump(list(set(peers)), f, indent=2)
    except Exception as e:
        logger.error(f"[CACHE] Save peers failed: {e}")

def load_peers_from_cache():
    try:
        with open(PEER_CACHE_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return []

# ─── decode_raw_eth_transaction & compute_contract_address ──
def decode_raw_eth_transaction(raw_tx: str) -> dict:
    if raw_tx.startswith('0x'): raw_tx = raw_tx[2:]
    tx_bytes = bytes.fromhex(raw_tx)
    decoded = rlp.decode(tx_bytes)
    if len(decoded) != 9:
        raise ValueError("Only legacy transactions (9 fields) supported")
    nonce = int.from_bytes(decoded[0], 'big')
    gasPrice = int.from_bytes(decoded[1], 'big')
    gas = int.from_bytes(decoded[2], 'big')
    to = decoded[3].hex()
    to = '0x' + to if to else ''
    value = int.from_bytes(decoded[4], 'big')
    data = decoded[5].hex()
    v = int.from_bytes(decoded[6], 'big')
    r = int.from_bytes(decoded[7], 'big')
    s = int.from_bytes(decoded[8], 'big')
    chain_id = None
    if v >= 35:
        chain_id = (v - 35) // 2
    tx_hash = eth_keccak(tx_bytes).hex()
    from_addr = None
    try:
        if Account is not None:
            recovered = Account.recover_transaction(tx_bytes)
            from_addr = recovered.lower() if recovered.startswith('0x') else '0x' + recovered.lower()
    except Exception:
        from_addr = None
    return {'nonce': nonce, 'gasPrice': gasPrice, 'gas': gas, 'to': to, 'value': value, 'data': data, 'v': v, 'r': r, 's': s, 'hash': '0x'+tx_hash, 'from': from_addr, 'chainId': chain_id}

def _raw_chain_id_ok(decoded: dict) -> bool:
    # R8-chain-id: raw Ethereum transactions are valid on this chain only
    # when EIP-155-protected with chainId == CHAIN_ID. Legacy-unprotected
    # (chainId None), missing, or wrong-chain transactions are rejected at
    # every route (consensus verifier + RPC/gossip ingress) — otherwise a
    # foreign-chain signed tx replays against Munex balances. Native Munex
    # signatures need no chain binding (format is chain-specific).
    # Chain reset / acceptance-rule change: see R8_MIGRATION_NOTES.md.
    try:
        return int(decoded.get('chainId')) == CHAIN_ID
    except (TypeError, ValueError):
        return False

def _derive_token_address(tx_hash: str, owner: str, name: str, symbol: str) -> str:
    # R5-sha3-sites: verified already-closed (R4 helper); single keccak derivation pins execute, shadow, reorg-inverse, dex.
    """R4-sha3-sites: legacy token addresses derive via keccak over
    "tx_hash:owner:name:symbol" (last 20 bytes) — not NIST SHA3-256 first-20.
    Single helper used by execute, replay-shadow, and reorg-inverse so all
    three agree by construction. Test chains reset across this change."""
    return "0x" + eth_keccak(f"{tx_hash}:{owner}:{name}:{symbol}".encode()).hex()[-40:]


def _moved_value_of(tx: dict) -> int:
    # R5-sign-fail-rollback: top-level value moved by new execute; re-fetched rows carry it in the data mirror.
    try:
        _v = int(tx.get('_value_moved', 0) or 0)
    except (TypeError, ValueError):
        _v = 0
    if not _v:
        try:
            _dd = tx.get('data') or {}
            if isinstance(_dd, str):
                _dd = json.loads(_dd)
            if isinstance(_dd, dict):
                _v = int(_dd.get('_value_moved', 0) or 0)
        except (TypeError, ValueError):
            _v = 0
    return _v if _v > 0 else 0


def compute_contract_address(sender: str, nonce: int) -> str:
    sender_bytes = bytes.fromhex(sender[2:] if sender.startswith('0x') else sender)
    if rlp is None:
        raise RuntimeError("rlp library is required for compute_contract_address")
    encoded = rlp.encode([sender_bytes, nonce])
    return '0x' + eth_keccak(encoded)[-20:].hex()

def _derive_spatial_coord(creator: str, nonce: int) -> Tuple[int, int, int]:
    """Spatial Tokens V2: coordinate is derived, not client-chosen.
    Deterministic across nodes. Bounded by SPATIAL_COORD_BOUND so it is
    always inside every live maze: coordinates live in [0, 5), which a
    minimum 5x5x5 maze contains exactly (size 5 needs no larger maze).
    Spatial contracts/tokens are separate objects at these coordinates —
    they never change maze side length, volume, growth, attestation size,
    or fork weight (see MAZE-SPATIAL-SEPARATION-1). Collisions between
    tokens are permitted."""
    _c = str(creator).lower().removeprefix("0x")
    h = eth_keccak(
        b"MCXSPATIALV2"
        + int(CHAIN_ID).to_bytes(8, "big")
        + bytes.fromhex(_c)
        + int(nonce).to_bytes(32, "big")
    )
    x = int.from_bytes(h[0:8],  "big") % SPATIAL_COORD_BOUND
    y = int.from_bytes(h[8:16],  "big") % SPATIAL_COORD_BOUND
    z = int.from_bytes(h[16:24], "big") % SPATIAL_COORD_BOUND
    return (x, y, z)

def _spatial_fee_amount_ok(block: dict) -> bool:
    """Spatial Tokens V2 (T9): sealed spatial_fee_amount must equal the sum
    of FULL spatial fees (sealed producer_cut + maze_cut per tx) across the
    block's SPATIAL txs only. Guards against a producer inflating
    distributions (unbacked mint via balance_repo.add) or starving mazes,
    and against forged cuts smuggled in on non-spatial txs (excluded by
    type). Pure function of the block dict; used by verify_block_proof."""
    try:
        sealed = int(block.get("spatial_fee_amount", 0) or 0)
    except (TypeError, ValueError):
        return False
    try:
        txs = block.get("transactions", []) or []
    except Exception:
        return False
    if not isinstance(txs, list):
        return False
    total = 0
    for tx in txs:
        if not isinstance(tx, dict):
            continue
        if tx.get("tx_type") not in ("spatial_token_create",
                                      "spatial_token_transfer"):
            continue
        try:
            total += int(tx.get("fee", 0) or 0) + \
                int(tx.get("_spatial_fee_maze_cut", 0) or 0)
        except (TypeError, ValueError):
            return False
    return total == sealed

def tx_data_to_hex(d) -> str:
    # contract_call execution rewrites tx['data'] to {'raw':..., 'result':...}
    # before the tx enters a block; import-side re-exec must read 'raw'.
    if isinstance(d, dict):
        d = d.get('raw', '')
    if d is None:
        return ''
    return str(d)

def tx_data_to_bytes(d) -> bytes:
    s = tx_data_to_hex(d)
    if not s:
        return b''
    if s.startswith(('0x', '0X')):
        s = s[2:]
    try:
        return bytes.fromhex(s)
    except ValueError:
        return s.encode()

# ─── Merkle Patricia state ───────────────────────────────
def _rlp_encode_int(val: int) -> bytes:
    if val == 0:
        return b'\x00'
    return val.to_bytes((val.bit_length() + 7) // 8, 'big')

def _rlp_encode_bytes(data: bytes) -> bytes:
    if len(data) == 1 and data[0] < 0x80:
        return data
    if len(data) < 56:
        return bytes([0x80 + len(data)]) + data
    length_bytes = _rlp_encode_int(len(data))
    return bytes([0xb7 + len(length_bytes)]) + length_bytes + data

def _rlp_encode_list(items: list) -> bytes:
    payload = b''.join(items)
    if len(payload) < 56:
        return bytes([0xc0 + len(payload)]) + payload
    length_bytes = _rlp_encode_int(len(payload))
    return bytes([0xf7 + len(length_bytes)]) + length_bytes + payload

def _keccak(data: bytes) -> bytes:
    return eth_keccak(data)

class _TrieNode:
    __slots__ = ('node_type', 'encoded', 'hash')
    def __init__(self, node_type, encoded, hash_val):
        self.node_type = node_type
        self.encoded = encoded
        self.hash = hash_val

class StateTrie:
    """Hexary Merkle Patricia Trie backed by state_trie_nodes.
    Stores RLP-encoded trie nodes keyed by keccak hash.
    Falls back to a flat key-value overlay for in-flight mutations."""
    def __init__(self, db):
        self.db = db
        self._dirty: Dict[str, bytes] = {}       # key -> json-encoded value (uncommitted)
        self._node_cache: Dict[bytes, bytes] = {} # node_hash -> rlp_encoded_node

    async def get(self, key: str):
        if key in self._dirty:
            return json.loads(self._dirty[key])
        query = "SELECT node_data FROM state_trie_nodes WHERE node_hash = ?" if self.db.db_type == "sqlite" else "SELECT node_data FROM state_trie_nodes WHERE node_hash = $1"
        row = await self.db.fetchrow(query, key)
        if not row:
            return None
        try:
            return json.loads(row['node_data'])
        except Exception:
            return None

    async def put(self, key: str, value: Any):
        self._dirty[str(key)] = json.dumps(value, sort_keys=True, separators=(',', ':'))

    def _compute_root(self) -> str:
        # Pure root computation over the current _dirty set (no DB writes).
        # R8-snapshot-restore (R7-04): validate-before-apply needs the
        # candidate root WITHOUT persisting nodes; commit() below persists
        # exactly what this computes. MERKLE-1b odd-promote rule shared.
        if not self._dirty:
            return STATE_TREE_EMPTY_HASH
        # Build sorted (leaf_hash, leaf_rlp) pairs, one per dirty key.
        # Leaf preimage is RLP([key_bytes, value_bytes]); leaf hash is keccak of it.
        pairs: List[Tuple[bytes, bytes]] = []
        for key in sorted(self._dirty):
            key_bytes = key.encode()
            value_bytes = self._dirty[key].encode() if isinstance(self._dirty[key], str) else self._dirty[key]
            leaf_rlp = _rlp_encode_list([_rlp_encode_bytes(key_bytes), _rlp_encode_bytes(value_bytes)])
            pairs.append((_keccak(leaf_rlp), leaf_rlp))
        pairs.sort(key=lambda p: p[0])
        # Build a balanced binary Merkle tree over sorted leaf hashes.
        # MERKLE-1b: odd nodes PROMOTE unchanged (no Bitcoin-style
        # self-duplication).
        level: List[bytes] = [lh for lh, _ in pairs]
        records: List[Tuple[str, str]] = []
        for lh, lr in pairs:
            records.append(('0x' + lh.hex(),
                            json.dumps({"kind": "leaf", "rlp": lr.hex()}, sort_keys=True)))
        while len(level) > 1:
            carry = level.pop() if len(level) % 2 == 1 else None
            nxt: List[bytes] = []
            for i in range(0, len(level), 2):
                parent = _keccak(level[i] + level[i + 1])
                nxt.append(parent)
                records.append(('0x' + parent.hex(),
                                json.dumps({"kind": "internal",
                                            "left": '0x' + level[i].hex(),
                                            "right": '0x' + level[i + 1].hex()},
                                           sort_keys=True, separators=(',', ':'))))
            if carry is not None:
                nxt.append(carry)
            level = nxt
        return '0x' + level[0].hex(), records

    async def commit(self) -> str:
        """Write dirty nodes inside their own local transaction and return the root.

        R6-statetrie-dirty-clear: this method NO LONGER clears _dirty
        (chain reset: state-machine change). Clearing inside the local
        transaction lost the dirt when an OUTER transaction rolled back
        afterwards, so a retry rebuilt a wrong root. Callers must invoke
        mark_committed() only after their outer transaction has exited
        successfully; produce_block does so (other single-shot callers
        such as genesis/snapshot-restore rewrite identical keys, which
        is harmless without it).
        Scope (R7-07): the root commits exactly this call's write set
        (STATE_COMMITMENT_SCOPE=two-key: height + winner balance) —
        deterministic across nodes by construction (sorted keys), NOT a
        full-state accumulator. Verifiers recompute from the same writes.
        """
        if not self._dirty:
            return STATE_TREE_EMPTY_HASH

        # R5-statetrie-batch-commit: node writes are atomic with the returned root.
        # R8-snapshot-restore: computation lives in _compute_root (shared
        # with validate-before-apply restore); this method only persists.
        root_hash, records = self._compute_root()
        _leaf_q = ("INSERT OR REPLACE INTO state_trie_nodes (node_hash,node_data,ref_count) VALUES (?,?,1)"
                   if self.db.db_type == "sqlite"
                   else "INSERT INTO state_trie_nodes (node_hash,node_data,ref_count) VALUES ($1,$2,1) "
                        "ON CONFLICT (node_hash) DO UPDATE SET node_data=$2, ref_count=state_trie_nodes.ref_count+1")
        async with await self.db.transaction():
            for _h, _d in records:
                await self.db.execute_dml(_leaf_q, _h, _d)
            return root_hash

    def mark_committed(self):
        # R6-statetrie-dirty-clear: forget dirt only after the outer
        # transaction that wrapped commit() has committed. Never call
        # this before the outer exit is known-good.
        self._dirty.clear()



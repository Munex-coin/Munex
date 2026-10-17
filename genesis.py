# Split of MCX81.py (lines 1097-1636). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import eth_keccak, logger
from node.config import ACTIVE_MINER_WINDOW_BLOCKS, BLOCK_FUTURE_SKEW, CHAIN_ID, DEFAULT_CONFIG, GENESIS_SUPPLY, HALVING_INTERVAL, INITIAL_BLOCK_REWARD, MAX_SUPPLY, MIN_MAZE_SIZE, SPATIAL_COORD_BOUND, SUBS, VERSION, _effective_validators, _normalize_validator_list, _rule_density, _rule_int, _strict_bool, _strict_int, _validate_lottery_value
from node.bootstrap import Dict, Optional, Tuple, hashlib, json, os, tempfile
from node import config as _config


MSG_HANDSHAKE, MSG_PING, MSG_PONG, MSG_GET_BLOCKS, MSG_BLOCKS, MSG_NEW_BLOCK, MSG_NEW_TX, MSG_GET_PEERS, MSG_PEERS, MSG_SLASH, MSG_BAN, MSG_UNBAN, MSG_GET_STATUS, MSG_STATUS, MSG_GET_CHECKPOINT, MSG_CHECKPOINT = range(0x01, 0x11)
MSG_NEW_MOVE = 0x11

GENESIS_FILE = "genesis.json"
_node_genesis_hash = ""
_node_genesis_data = None
FORK_ID = 0

def resolve_genesis_file(config=None, cli_path=None) -> str:
    """GENESIS-PATH-1 (MCX80): deterministic genesis file selection.
    Precedence: --genesis-file CLI > MCX_GENESIS_FILE env > node.genesis_file
    config > 'genesis.json' default. Pure; the default keeps existing users
    working. Every loader/writer below reads the GENESIS_FILE global, which
    main() sets from this resolver once at startup."""
    if cli_path:
        return str(cli_path)
    _env = os.environ.get("MCX_GENESIS_FILE", "")
    if _env.strip():
        return _env.strip()
    try:
        _cfg = ((config or {}).get('node', {}) or {}).get('genesis_file', "")
        if isinstance(_cfg, str) and _cfg.strip():
            return _cfg.strip()
    except (AttributeError, TypeError):
        pass
    return "genesis.json"

def _write_genesis_file_atomic(body: dict) -> None:
    """GENESIS-ATOMIC-1: write the genesis file via temp-file + atomic
    replace so a crash can never leave a half-written genesis.json. The
    temp file lives in the destination directory (same filesystem, so the
    replace is atomic where the platform supports it). Raises on failure
    with nothing persisted at the destination path."""
    _dir = os.path.dirname(os.path.abspath(GENESIS_FILE)) or "."
    _fd, _tmp = tempfile.mkstemp(prefix=".genesis.", suffix=".tmp", dir=_dir)
    try:
        with os.fdopen(_fd, 'w', encoding='utf-8') as f:
            json.dump(body, f, indent=2)
            f.flush()
            try:
                os.fsync(f.fileno())
            except (OSError, AttributeError):
                pass
        os.replace(_tmp, os.path.abspath(GENESIS_FILE))
    except Exception:
        try:
            if os.path.exists(_tmp):
                os.remove(_tmp)
        except OSError:
            pass
        raise

def load_genesis_file():
    """Load the resolved genesis file and set module-level _node_genesis_hash,
    _node_genesis_data, and FORK_ID. Must be called on every startup before
    P2P starts. Logs the fully resolved absolute path plus the full declared
    hash and the recomputed identity hash (read-only diagnostic; acceptance
    is decided by the verification gates, not here)."""
    _abs = os.path.abspath(GENESIS_FILE)
    if not os.path.exists(GENESIS_FILE):
        logger.info(f"[GENESIS] No genesis file at {_abs}")
        _node_genesis_data = None
        return None
    try:
        with open(GENESIS_FILE, 'r') as f:
            data = json.load(f)
        _node_genesis_hash = data.get("hash", "")
        _node_genesis_data = data
        if _node_genesis_hash:
            FORK_ID = int(_node_genesis_hash[:8], 16) ^ int(_node_genesis_hash[8:16], 16)
        try:
            _recomputed = _genesis_identity_hash(_canonical_genesis_payload(data))
            _match = "MATCH" if str(_recomputed).lower() == str(_node_genesis_hash).lower() else "MISMATCH"
        except Exception as _re:
            _recomputed, _match = f"<unrecomputable: {_re}>", "UNRECOMPUTABLE"
        logger.info(f"[GENESIS] Loaded genesis from {_abs} "
                    f"(declared={_node_genesis_hash} recomputed={_recomputed} {_match})")
        return data
    except Exception as e:
        logger.error(f"[GENESIS] Failed to read {_abs}: {e}")
        _node_genesis_data = None
        return None

def _genesis_state_root(alloc: dict) -> str:
    # R9-genesis-auth (I-R8-04): canonical genesis state commitment —
    # height 0 plus one balance:<addr> key per alloc entry, using the exact
    # StateTrie.put encodings and the pure _compute_root (no DB). This is
    # what _create_genesis commits, so recomputation binds the file's alloc
    # to its state_root cryptographically.
    from node.chain import StateTrie  # lazy: forward ref, runtime-only
    _dirty = {"height": json.dumps(0, sort_keys=True, separators=(',', ':'))}
    for _a, _v in alloc.items():
        _dirty[f"balance:{_a}"] = json.dumps(int(_v), sort_keys=True, separators=(',', ':'))
    _t = StateTrie(None)
    _t._dirty = _dirty
    return _t._compute_root()[0]


def _genesis_economics_ok(data: dict):
    # R9-genesis-auth (I-R8-04): every node's initial balances and issuance
    # must be committed to one canonical genesis identity. Returns
    # (True, "ok") or (False, reason). Rules: alloc present and a dict;
    # every address strict lowercase 0x-hex (no case-aliasing — the
    # balance layer lowercases on write, so mixed case would merge or
    # diverge rows); every amount an int with 0 <= amt; total_minted an
    # int with sum(alloc) == total_minted <= MAX_SUPPLY (conservation at
    # height 0); state_root present and equal to the recomputed canonical
    # root. Chain reset: acceptance change; see R9_MIGRATION_NOTES.md.
    if not isinstance(data, dict):
        return False, "genesis body is not a dict"
    alloc = data.get("alloc")
    if not isinstance(alloc, dict):
        return False, "genesis alloc missing or not a map"
    # R9-genesis-auth Audit-E: amounts and totals must BE ints (not
    # merely int-coercible) — the state-root recomputation below commits
    # int encodings, so string forms would verify economics yet mismatch
    # the root. Canonical files always store ints.
    try:
        total = data.get("total_minted", -1)
        if not isinstance(total, int) or isinstance(total, bool):
            return False, "invalid total_minted"
        total = int(total)
    except (TypeError, ValueError):
        return False, "invalid total_minted"
    if total < 0 or total > MAX_SUPPLY:
        return False, "total_minted out of range"
    _sum = 0
    for _a, _v in alloc.items():
        if not isinstance(_a, str) or len(_a) != 42 or not _a.startswith("0x"):
            return False, f"malformed alloc address {_a!r}"
        _hex = _a[2:]
        if not all(c in "0123456789abcdef" for c in _hex):
            return False, f"non-canonical alloc address {_a!r}"
        if not isinstance(_v, int) or isinstance(_v, bool):
            return False, f"invalid alloc amount for {_a!r}"
        _amt = int(_v)
        if _amt < 0 or _amt > MAX_SUPPLY:
            return False, f"alloc amount out of range for {_a!r}"
        _sum += _amt
    if _sum != total:
        return False, "alloc does not sum to total_minted"
    _root = data.get("state_root", "")
    if not _root:
        return False, "missing state_root"
    try:
        if _genesis_state_root(alloc) != _root:
            return False, "state_root does not match alloc"
    except Exception as e:
        return False, f"state_root recomputation failed: {e}"
    return True, "ok"


# ─── Genesis identity (Fix 1 + Fix 2, R10) ───
# One canonical identity hash commits EVERYTHING a node needs to agree on
# before sharing state: block header fields, the economic starting state
# (alloc/total_minted/state_root), the chain selectors (version/chain_id),
# and the full consensus ruleset. Verified identically on all four paths
# (fresh-create self-check, restore, startup gate, handshake-learn).
GENESIS_IDENTITY_VERSION = 1
GENESIS_CONSENSUS_RULESET_VERSION = 5   # v5 (mainnet audit): + tx_type/field binding (TXTYPE-BIND-1), envelope-hash enforcement (TXHASH-ENFORCE-1), block-time temporal semantics (TIME-CONSENSUS-1), attestation work-proof (WORK-PROOF-1), shrink bound (SHRINK-BOUND-1), automation enabled binding (AUTO-ENABLE-BIND-1); chain reset vs v4 (no v4 chain deployed)
# Payload fields covered by the identity hash, in canonical (sorted-key)
# JSON form. The transport-only keys "hash", "signature", and "finalized"
# are tolerated but excluded (same convention as block_signing_payload);
# ANY other top-level key is rejected — every byte of the file is either
# committed identity or explicitly non-identity.
GENESIS_IDENTITY_FIELDS = (
    "id", "ts", "phash", "miners", "reward", "tx_count", "merkle_root",
    "nonce", "difficulty", "version", "challenge", "coverage",
    "total_tx_value", "total_fees", "tx_hashes", "state_root",
    "producer_pub", "alloc", "total_minted", "chain_id", "consensus",
    "validators",
)
GENESIS_TRANSPORT_KEYS = frozenset({"hash", "signature", "finalized"})


def _fixed_consensus_params() -> dict:
    """RULES-BIND-1 (MCX80): consensus-critical protocol literals in ONE
    place, merged into BOTH the config-derived record and the effective
    (live-global) record so genesis creation and verification cannot
    disagree about which rules are in effect. Every value here is consumed
    by a deterministic acceptance/execution path:
    economics.{genesis_supply (genesis alloc), max_supply (mint cap),
    initial_block_reward + halving_interval (subsidy schedule),
    subs (unit conversion)}, protocol.{min_maze_size (eligibility/weight/
    attestation), spatial_coord_bound (coordinate derivation),
    active_miner_window (eligibility window), block_future_skew (timestamp
    validity bound)}. Deliberately NOT bound (fixed but not validity
    predicates): BLOCK_TIME (seal pacing only), FINALITY_EPOCH_LENGTH
    (advisory checkpoints), MIN_STEP_INTERVAL (unused), POG_ACTIVATION_
    HEIGHT/SHRINK_* (local pacing/display). Token/spatial supply caps stay
    separate (TOKEN_MAX_SUPPLY/SPATIAL_MAX_SUPPLY, not native issuance)."""
    return {
        "genesis_supply": int(GENESIS_SUPPLY),
        "max_supply": int(MAX_SUPPLY),
        "initial_block_reward": int(INITIAL_BLOCK_REWARD),
        "halving_interval": int(HALVING_INTERVAL),
        "subs": int(SUBS),
        "min_maze_size": int(MIN_MAZE_SIZE),
        "spatial_coord_bound": int(SPATIAL_COORD_BOUND),
        "active_miner_window": int(ACTIVE_MINER_WINDOW_BLOCKS),
        "block_future_skew": int(BLOCK_FUTURE_SKEW),
    }


def _consensus_record_from_config(config) -> dict:
    """Pure builder: the genesis consensus record for a config mapping.

    Covers every OPERATOR-SETTABLE value consumed by a validity, execution,
    activation, eligibility, fee-charging, or fork-choice path (Fix 2 audit):
    consensus.{max_misses (ban->eligibility 14895/3573/3563), ban_duration
    via p2p (miner ban length 13799/14890 — shared knob, bound once),
    prune_blocks (reorg bound 14680), wall_density_3d (maze contents 6992),
    lottery_scale/attest_fresh_buffer/attest_growth_per_block/slot_timeout
    (R9), htlc_v1_enabled (tx-type/precompile gating),
    validators (MCX79 fixed producer set: sorted canonical pubkeys)},
    fees.{min_fee (fee floor 1707), token_creation_multiplier (1713)},
    vm.{gas_price (BASEFEE/charging), gas_limit_default (execution ceiling +
    admission 16433), max_bytecode (deploy validity)}, plus code anchors
    {version, chain_id} identifying the fixed protocol, plus the
    RULES-BIND-1 fixed literals (native economics, min_maze_size,
    spatial_coord_bound, active_miner_window, block_future_skew — merged
    from the single _fixed_consensus_params() source, so this record and
    the effective record agree by construction). Missing keys fall
    back to DEFAULT_CONFIG. Deliberately NOT bound (operator-local, no
    validity predicate reads them): ports/binds, peer discovery
    (genesis_node/dns/bootstrap/fallback), max_peers/ban_threshold,
    dht/discovery timers, epoch_length (local checkpoint cadence — the
    finalized flag is never validity-read), rbf_increment/max_tx_per_block/
    mempool max_size/expiry/max_nonce_gap (production/policy caps),
    sandbox/require_sandbox/timeout_seconds (local execution env),
    snapshot cadence, database/node/wallet keys. Deliberately NOT bound
    (dead keys, assigned never read): finality_threshold,
    initial/min/max_required_knowledge, knowledge_adjustment_interval,
    target_catch_time, base/min/max_maze_size_3d, maze_growth_rate (sizes
    are chain-agreed, _chain_agreed_maze_sizes), commit_reveal_activation_
    height, max_fee/fee_per_byte (removed R4), max_state_size, cpfp_min_fee,
    block_time/min_step_interval (dead; BLOCK_TIME literal frozen)."""
    _c = (config or {}).get('consensus', {}) or {}
    _f = (config or {}).get('fees', {}) or {}
    _v = (config or {}).get('vm', {}) or {}
    _p = (config or {}).get('p2p', {}) or {}
    _dc = DEFAULT_CONFIG.get('consensus', {})
    _df = DEFAULT_CONFIG.get('fees', {})
    _dv = DEFAULT_CONFIG.get('vm', {})
    _dp = DEFAULT_CONFIG.get('p2p', {})
    try:
        _validators = _normalize_validator_list(
            _c.get('validators', _dc.get('validators', [])))
    except Exception:
        _validators = []
    _gld = _strict_int('gas_limit_default', _v.get('gas_limit_default', _dv.get('gas_limit_default', 100000)), 21000, 10_000_000)
    _rec = {
        "ruleset_version": GENESIS_CONSENSUS_RULESET_VERSION,
        "max_misses": _rule_int('consensus.max_misses', _c.get('max_misses'), _dc.get('max_misses', 3)),
        "ban_duration": _rule_int('p2p.ban_duration', _p.get('ban_duration'), _dp.get('ban_duration', 3600)),
        "prune_blocks": _rule_int('consensus.prune_blocks', _c.get('prune_blocks'), _dc.get('prune_blocks', 10000)),
        # GENESIS-RULESET-1: same floor/validation as the live global
        "wall_density_3d": _rule_density(_c.get('wall_density_3d'), _dc.get('wall_density_3d', 0.55)),
        "min_fee": _rule_int('fees.min_fee', _f.get('min_fee'), _df.get('min_fee', 100)),
        "token_creation_multiplier": _rule_int('fees.token_creation_multiplier', _f.get('token_creation_multiplier'), _df.get('token_creation_multiplier', 5000)),
        "gas_price": _rule_int('vm.gas_price', _v.get('gas_price'), _dv.get('gas_price', 1)),
        "gas_limit_default": _gld,
        "max_bytecode": _rule_int('vm.max_bytecode', _v.get('max_bytecode'), _dv.get('max_bytecode', 65536)),
        "max_block_gas": _strict_int('max_block_gas', _v.get('max_block_gas', _dv.get('max_block_gas', 10000000)), _gld * 10, 1_000_000_000),
        "max_block_txs": _strict_int('max_block_txs', _v.get('max_block_txs', _dv.get('max_block_txs', 1000)), 1, 100_000),
        "htlc_v1_enabled": _strict_bool('consensus.htlc_v1_enabled', _c.get('htlc_v1_enabled', _dc.get('htlc_v1_enabled', False))),
        "lottery_scale": _validate_lottery_value('lottery_scale', _c.get('lottery_scale', _dc.get('lottery_scale', 1 << 249)), 1),
        "attest_fresh_buffer": _validate_lottery_value('attest_fresh_buffer', _c.get('attest_fresh_buffer', _dc.get('attest_fresh_buffer', 5)), 0),
        "attest_growth_per_block": _validate_lottery_value('attest_growth_per_block', _c.get('attest_growth_per_block', _dc.get('attest_growth_per_block', 5)), 0),
        "slot_timeout": _validate_lottery_value('slot_timeout', _c.get('slot_timeout', _dc.get('slot_timeout', 30)), 1),
        "validators": _validators,
        "code": {"version": str(VERSION), "chain_id": int(CHAIN_ID)},
    }
    # RULES-BIND-1: fixed protocol literals merged from the single source —
    # the config-derived record and the effective record below agree by
    # construction (a config cannot override these; code identity covers it).
    _rec.update(_fixed_consensus_params())
    return _rec


def _effective_consensus_ruleset() -> dict:
    """The ruleset this process actually runs: live module globals (which
    apply_consensus_config re-derives from the effective config at node
    init for the lottery keys; the rest are import-time CONFIG-derived and
    are what every validity/execution path reads). Fresh genesis files and
    all verification paths bind against this — never against a stale or
    hypothetical config. Fixed protocol literals merge from the same
    _fixed_consensus_params() source as the config-derived record."""
    _live = {
        "ruleset_version": GENESIS_CONSENSUS_RULESET_VERSION,
        "max_misses": int(MAX_MISSES),
        "ban_duration": int(BAN_DURATION),
        "prune_blocks": int(PRUNE_BLOCKS),
        "wall_density_3d": float(WALL_DENSITY_3D),
        "min_fee": int(MIN_FEE),
        "token_creation_multiplier": int(TOKEN_CREATION_MULTIPLIER),
        "gas_price": int(GAS_PRICE),
        "gas_limit_default": int(GAS_LIMIT_DEFAULT),
        "max_bytecode": int(MAX_BYTECODE),
        "max_block_gas": int(MAX_BLOCK_GAS),
        "max_block_txs": int(MAX_BLOCK_TXS),
        "htlc_v1_enabled": bool(HTLC_V1_ENABLED),
        "lottery_scale": int(LOTTERY_SCALE),
        "attest_fresh_buffer": int(ATTEST_FRESH_BUFFER),
        "attest_growth_per_block": int(ATTEST_GROWTH_PER_BLOCK),
        "slot_timeout": int(SLOT_TIMEOUT),
        "validators": sorted(_effective_validators()),
        "code": {"version": str(VERSION), "chain_id": int(CHAIN_ID)},
    }
    # RULES-BIND-1: same fixed-literal source as the config-derived record.
    _live.update(_fixed_consensus_params())
    return _live


def _canonical_genesis_payload(data: dict) -> dict:
    """Build the exact dict covered by the genesis identity hash. Strict:
    every GENESIS_IDENTITY_FIELDS key must be present with a JSON-native
    shape (alloc/consensus dicts, miners/tx_hashes lists); transport keys
    (hash/signature/finalized) are dropped; anything else raises. Raises
    ValueError on any deviation — callers fail closed."""
    if not isinstance(data, dict):
        raise ValueError("genesis body is not a dict")
    _extra = [k for k in data if k not in GENESIS_IDENTITY_FIELDS
              and k not in GENESIS_TRANSPORT_KEYS]
    if _extra:
        raise ValueError("unknown genesis fields: " + ", ".join(sorted(map(str, _extra))))
    _missing = [k for k in GENESIS_IDENTITY_FIELDS if k not in data]
    if _missing:
        raise ValueError("missing genesis fields: " + ", ".join(_missing))
    try:
        _payload = {
            "id": int(data["id"]),
            "ts": data["ts"],
            "phash": str(data["phash"]),
            "miners": list(data["miners"]),
            "reward": int(data["reward"]),
            "tx_count": int(data["tx_count"]),
            "merkle_root": str(data["merkle_root"]),
            "nonce": int(data["nonce"]),
            "difficulty": int(data["difficulty"]),
            "version": str(data["version"]),
            "challenge": str(data["challenge"]),
            "coverage": data["coverage"],
            "total_tx_value": int(data["total_tx_value"]),
            "total_fees": int(data["total_fees"]),
            "tx_hashes": list(data["tx_hashes"]),
            "state_root": str(data["state_root"]),
            "producer_pub": str(data["producer_pub"]),
            "alloc": dict(data["alloc"]),
            "total_minted": int(data["total_minted"]),
            "chain_id": int(data["chain_id"]),
            "consensus": dict(data["consensus"]),
            "validators": list(data["validators"]),
        }
    except (TypeError, ValueError) as e:
        raise ValueError(f"malformed genesis field: {e}")
    if not isinstance(_payload["ts"], (int, float)) or isinstance(_payload["ts"], bool):
        raise ValueError("malformed genesis field: ts must be a number")
    if not isinstance(_payload["coverage"], (int, float)) or isinstance(_payload["coverage"], bool):
        raise ValueError("malformed genesis field: coverage must be a number")
    if not isinstance(data["alloc"], dict) or not isinstance(data["consensus"], dict):
        raise ValueError("malformed genesis field: alloc/consensus must be maps")
    if not isinstance(data["validators"], list) or any(not isinstance(v, str) for v in data["validators"]):
        raise ValueError("malformed genesis field: validators must be a list of strings")
    return _payload


def _genesis_identity_hash(payload: dict) -> str:
    from node.crypto import canonical_json_bytes  # lazy: forward ref, runtime-only
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def _genesis_export_verified_impl(body):
    """GENESIS-1 (Fix 1 + Fix 2): verify a genesis export — local file or
    peer-learned — against ONE canonical identity before any trust.

    Layer 1 (integrity): the strict canonical payload (header fields +
    alloc + total_minted + chain_id + full consensus record) re-hashed
    must equal the declared hash. ANY committed-field tampering — balances,
    supply, ruleset values, timestamps, roots — fails here, including files
    whose hash was honestly computed over the legacy 16-field shape (their
    recomputed hash differs: refused, see R9_MIGRATION_NOTES.md, no
    grandfathering).
    Layer 2 (policy): R9 economics (exact alloc sum == total_minted <=
    MAX_SUPPLY, canonical addrs/ints, state_root match).
    Layer 3 (compatibility): the file's consensus record must equal this
    process's effective ruleset — mixed-rule nodes refuse each other with
    the differing key named. Key order/whitespace variants verify
    identically (canonical JSON). Returns (ok, reason)."""

    if not isinstance(body, dict):
        return False, "genesis body is not a dict"
    try:
        if int(body.get("id", -1)) != 0:
            return False, "genesis id must be 0"
    except Exception:
        return False, "invalid genesis id"
    if str(body.get("version", "")) != str(VERSION):
        return False, "genesis version mismatch"
    try:
        if int(body.get("chain_id", -1)) != int(CHAIN_ID):
            return False, "chain_id mismatch"
    except Exception:
        return False, "invalid chain_id"
    if str(body.get("phash", "")) != "0" * 64:
        return False, "genesis phash must be all zeros"
    gh = str(body.get("hash", "")).lower()
    if len(gh) != 64 or not all(c in "0123456789abcdef" for c in gh):
        return False, "invalid genesis hash format"
    try:
        _payload = _canonical_genesis_payload(body)
    except ValueError as e:
        return False, str(e)
    try:
        _recomputed = _genesis_identity_hash(_payload)
    except Exception as e:
        return False, f"hash recomputation failed: {e}"
    if _recomputed != gh:
        return False, "recomputed genesis identity hash does not match declared hash"
    # Layer 2: economic policy (cap/conservation/canonical form).
    ok, why = _genesis_economics_ok(body)
    if not ok:
        return False, why
    # MCX79: the top-level validator list and the consensus record must
    # agree — both are committed identity, and only the record is compared
    # against the live ruleset below. A file pairing one set with another
    # (crafted or mixed-version) is refused here, never silently half-bound.
    try:
        _v_top = _normalize_validator_list(body.get("validators"))
        _v_rec_raw = body.get("consensus", {}).get("validators", None)
        _v_rec = _normalize_validator_list(
            _v_rec_raw if isinstance(_v_rec_raw, (list, tuple)) else [])
        if _v_top != _v_rec:
            return False, ("genesis validators list disagrees with consensus "
                           "record")
    except Exception as e:
        return False, f"validators comparison failed: {e}"
    # Layer 3: ruleset compatibility with this process.
    try:
        _want = _effective_consensus_ruleset()
        _got = body.get("consensus")
        if not isinstance(_got, dict) or dict(_got) != _want:
            if not isinstance(_got, dict):
                return False, "genesis consensus record missing or not a map"
            for _k in _want:
                if _k not in _got or _got[_k] != _want[_k]:
                    return False, (f"genesis consensus ruleset differs from local "
                                   f"effective config at '{_k}': genesis={_got.get(_k)!r} local={_want[_k]!r}")
            return False, "genesis consensus ruleset shape differs from local effective config"
    except Exception as e:
        return False, f"consensus record comparison failed: {e}"
    return True, "ok"


def genesis_export_verified(body):
    """GENESIS-TOTAL-1: the single authoritative genesis verifier, as a TOTAL
    function. The inner implementation int()/float()-coerces attacker-
    controlled JSON (Python's parser accepts Infinity/NaN/huge numbers), and
    e.g. {"total_minted": Infinity} raised OverflowError out of
    _canonical_genesis_payload — an uncaught exception on a path fed by peer
    handshakes and local files instead of a clean rejection. Any exception is
    now a fail-closed (False, reason); a genesis is accepted ONLY if the
    implementation returns (True, ...) without raising."""
    try:
        return _genesis_export_verified_impl(body)
    except RecursionError:
        return False, "malformed genesis (nesting too deep)"
    except Exception as _e:
        return False, f"malformed genesis ({type(_e).__name__})"


def strict_replayed_sizes(entries, eligible_rows) -> Tuple[Dict[str, int], Optional[str]]:
    """LOTTERY-1: validate a block's declared lottery entries against this
    node's own eligible set.

    The old verifier trusted declared entries verbatim, so a producer could
    claim arbitrary weight for its own miner (and foreign producers slipped
    through a leniency branch). Rows are keyed by BOTH maze_id and minerid
    (the minermazes table carries both; legacy code keyed maze_id while
    entries use minerid — minerid wins when both are present).

    Returns (sizes, error_reason); error_reason is None on success."""
    local: Dict[str, int] = {}
    for r in eligible_rows or []:
        try:
            size = int(r["size"])
        except Exception:
            continue
        for k in ("maze_id", "minerid"):
            mid = None
            try:
                mid = r[k]
            except Exception:
                mid = r.get(k) if isinstance(r, dict) else None
            if mid:
                local[str(mid)] = size
    sizes: Dict[str, int] = {}
    for e in entries or []:
        mid = e.get("minerid")
        if not mid:
            return {}, "entry missing minerid"
        if str(mid) not in local:
            return {}, f"declared entry for unknown miner {str(mid)[:16]}"
        try:
            claimed = int(e.get("mazesize", 0))
        except (TypeError, ValueError):
            return {}, f"invalid mazesize for {str(mid)[:16]}"
        if claimed != local[str(mid)]:
            return {}, (f"mazesize mismatch for {str(mid)[:16]}: "
                        f"declared {claimed}, local {local[str(mid)]}")
        sizes[str(mid)] = claimed
    return sizes, None

# ─── Consensus RNG (hash-based deterministic random stream) ──
class ConsensusRng:
    """Deterministic hash-based random stream for consensus. Never use Python random."""
    def __init__(self, seed: bytes):
        self.seed = seed
        self.counter = 0

    def bytes(self, length: int) -> bytes:
        output = bytearray()
        while len(output) < length:
            output.extend(eth_keccak(
                b"MCXPOGRNGV1"
                + self.seed
                + self.counter.to_bytes(8, "big")
            ))
            self.counter += 1
        return bytes(output[:length])

    def randbelow(self, upper: int) -> int:
        if upper <= 0:
            raise ValueError("upper must be positive")
        limit = (1 << 256) - ((1 << 256) % upper)
        while True:
            value = int.from_bytes(self.bytes(32), "big")
            if value < limit:
                return value % upper

# ─── Canonical block hashing and signing ─────────────────────

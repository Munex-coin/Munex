# Split of MCX81.py (lines 293-1096). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import eth_keccak, logger, yaml
from node.bootstrap import copy, deque, math, os, re


# ─── Configuration ────────────────────────────────────
CONFIG_PATH = os.environ.get('MCX_CONFIG', 'config.yaml')
DEFAULT_CONFIG = {
    'node': {'ws_port': 8080, 'ws_bind_ip': '0.0.0.0', 'api_port': 8085, 'p2p_port': 8081, 'public_url': None, 'external_ip': '', 'external_port': 8081, 'bind_ip': '0.0.0.0', 'rpc_bind_ip': '0.0.0.0', 'embedded_miner': False, 'rpc_token': '', 'rpc_trust_loopback': True},
    'database': {'url': None, 'require_postgres': False},
    'consensus': {
        'block_time': 50,
        'min_step_interval': 0,  # removed – replaced by R_K_m
        'max_misses': 3,
        'epoch_length': 100,
        'prune_blocks': 10000,
        'base_maze_size_3d': 10,
        'min_maze_size_3d': 8,
        'max_maze_size_3d': 60,
        'maze_growth_rate': 1.018,
        'wall_density_3d': 0.55,
        'initial_required_knowledge': 10,  # R_K_m starts here
        'min_required_knowledge': 5,
        'max_required_knowledge': 100,
        'knowledge_adjustment_interval': 5,
        'target_catch_time': 60.0,  # average seconds to reach goal
        'finality_threshold': 0.66,
        'commit_reveal_activation_height': 0,
        # Idea 5 (IDEA5-ATTEST): self-attested maze sizes
        'lottery_scale': 1 << 249,       # LOTTERY-SCALE-1: retained frozen for record compatibility (MCX79 threshold is asymptotic and no longer consumes it; size6 ~42%)
        'attest_fresh_buffer': 5,        # ATTEST-FRESH-BUFFER-1: first-claim cap above MIN_MAZE_SIZE (5+5=10)
        'attest_growth_per_block': 5,    # growth cap between attestations (+5/block)
        'slot_timeout': 30,              # IDEA5-LIVENESS-1: rank escalation per candidate after the scheduled slot
        'validators': [],                # MCX79 fixed producer set: list of '04'+128-hex pubkeys. MUST be identical on every node of a chain (it is part of genesis identity). [] = open mode (testnet only).
    },
    'fees': {'min_fee': 100, 'max_fee': 100000, 'fee_per_byte': 10, 'token_creation_multiplier': 5000, 'rbf_increment': 1.1, 'cpfp_min_fee': 100},
    'p2p': {'genesis_node': 'munexseed.duckdns.org', 'dns_seeds': ['munexseed.duckdns.org'], 'bootstrap_nodes': ['munexseed.duckdns.org:8081'], 'dht_bootstrap_nodes': ['munexseed.duckdns.org:8083'], 'fallback_nodes': [], 'max_peers': 50, 'ban_threshold': 5, 'ban_duration': 3600, 'dht_enabled': True, 'discovery_interval': 300, 'discovery_timeout': 60, 'allow_private_peers': False},
    'vm': {'gas_price': 1, 'gas_limit_default': 100000, 'max_block_gas': 10000000, 'max_block_txs': 1000, 'max_bytecode': 65536, 'max_state_size': 1024, 'sandbox': True, 'require_sandbox': False, 'timeout_seconds': 5},
    'mempool': {'max_size': 10000, 'expiry': 3600, 'max_tx_per_block': 100}
}
def load_config():
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, 'r') as f:
                loaded = yaml.safe_load(f) or {}
            for k, v in loaded.items():
                if isinstance(v, dict) and k in cfg and isinstance(cfg[k], dict):
                    cfg[k].update(v)
                else:
                    cfg[k] = v
            return cfg
        except Exception as e:
            logger.warning(f"Failed to load {CONFIG_PATH}: {e}, using defaults")
            return cfg
    else:
        with open(CONFIG_PATH, 'w') as f:
            yaml.dump(DEFAULT_CONFIG, f)
        logger.info("Created default config.yaml. Please edit it.")
        return cfg
CONFIG = load_config()

# ─── Constants ────────────────────────────────────────
WS_PORT = CONFIG['node'].get('ws_port', 8080)
API_PORT = CONFIG['node'].get('api_port', 8085)  # R4-ws-rpc-split: private RPC/REST bind port
P2P_PORT = CONFIG['node'].get('p2p_port', 8081)
PUBLIC_URL = CONFIG['node'].get('public_url', None)
DB_URL = CONFIG.get('database', {}).get('url', 'sqlite://microcore.db')
EXTERNAL_IP = CONFIG['node'].get('external_ip', '')
EXTERNAL_PORT = CONFIG['node'].get('external_port', P2P_PORT)
BIND_IP = CONFIG['node'].get('bind_ip', '0.0.0.0')
RPC_BIND_IP = CONFIG['node'].get('rpc_bind_ip', DEFAULT_CONFIG['node']['rpc_bind_ip'])   # RPC-BIND-1: one default (DEFAULT_CONFIG), not a second hard-coded fallback
BLOCK_TIME = 50
# R8-timestamp-deterministic (R7-11): consensus timestamp skew allowance.
# Validity is parent-relative only (see _block_timestamp_ok); this bound
# replaces the old verifier-wall-clock rule. Sized at 12x BLOCK_TIME:
# covers the legacy 300s future bound plus seal pacing for honest
# producers with fast clocks. Wall-clock health stays an operator/relay
# concern, never a validity predicate. (BLOCK_TIME itself is frozen.)
BLOCK_FUTURE_SKEW = 600
COMMIT_REVEAL_ACTIVATION_HEIGHT = CONFIG["consensus"].get("commit_reveal_activation_height", 0)  # 0 = active from genesis
MIN_STEP_INTERVAL = 0.0  # unused
# CONFIG-RANGE-1: strict, bounded, typed parsing for every consensus-effectual
# numeric setting that previously went through a bare int()/float() (silently
# accepting True, 5.9, -3, prune_blocks=0, min_fee<=0, ...). One table is used
# at import time, in apply_consensus_config() and in the genesis-record
# builder, so the three can never resolve the same config differently.
# None means "key absent" -> default (same convention as apply_consensus_config).
RULE_INT_BOUNDS = {
    'consensus.max_misses': (1, 1000),           # slash-ban threshold; 0/negative = instant ban
    'consensus.prune_blocks': (100, 10**9),      # also the max reorg depth: tiny/negative disables reorg protection
    'fees.min_fee': (1, 10**12),                 # 0/negative = free spam
    'fees.token_creation_multiplier': (1, 10**9),
    'vm.gas_price': (1, 10**9),                  # 0 = free VM execution
    'vm.max_bytecode': (1024, 1 << 20),
    'p2p.ban_duration': (1, 31_536_000),         # seconds, <= 1 year
}

def _rule_int(path, v, default=None):
    if v is None:
        v = default
    lo, hi = RULE_INT_BOUNDS[path]
    if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
        raise ValueError(f"config {path} must be an int in [{lo}, {hi}], got {v!r}")
    return v

def _rule_density(v, default=0.55):
    """wall_density_3d: finite real in [0, 1); the effective value is floored at 0.55 (protocol minimum)."""
    if v is None:
        v = default
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v) or not (0 <= v < 1):
        raise ValueError(f"config consensus.wall_density_3d must be a finite number in [0, 1), got {v!r}")
    return max(0.55, float(v))

MAX_MISSES = _rule_int('consensus.max_misses', CONFIG['consensus'].get('max_misses'), 3)
EPOCH_LENGTH = CONFIG['consensus'].get('epoch_length', 100)
PRUNE_BLOCKS = _rule_int('consensus.prune_blocks', CONFIG['consensus'].get('prune_blocks'), 10000)
VALIDATORS = CONFIG['consensus'].get('validators', [])
BASE_MAZE_SIZE_3D = CONFIG['consensus'].get('base_maze_size_3d', 10)
MAZE_GROWTH_RATE = CONFIG['consensus'].get('maze_growth_rate', 1.018)
WALL_DENSITY_3D = _rule_density(CONFIG['consensus'].get('wall_density_3d'))
INITIAL_REQUIRED_KNOWLEDGE = CONFIG['consensus'].get('initial_required_knowledge', 10)
MIN_REQUIRED_KNOWLEDGE = CONFIG['consensus'].get('min_required_knowledge', 5)
KNOWLEDGE_ADJUSTMENT_INTERVAL = CONFIG['consensus'].get('knowledge_adjustment_interval', 5)
TARGET_CATCH_TIME = CONFIG['consensus'].get('target_catch_time', 60.0)
MIN_FEE = _rule_int('fees.min_fee', CONFIG['fees'].get('min_fee'), 100)
# R4-dead-code-remove: MAX_FEE / FEE_PER_BYTE deleted (defined, never read;
# the fee market is documented "no hard cap"). Config keys untouched.
TOKEN_CREATION_MULTIPLIER = _rule_int('fees.token_creation_multiplier', CONFIG['fees'].get('token_creation_multiplier'), 5000)
# ─── Genesis Node Configuration ──────────────────────────────
GENESIS_NODE = "munexseed.duckdns.org"
GENESIS_NODE_HOST = "munexseed.duckdns.org"
GENESIS_NODE_P2P_PORT = 8081
GENESIS_NODE_DHT_PORT = 8083
GENESIS_NODE_WS_PORT = 8080
GENESIS_BOOTSTRAP_ENDPOINT = f"{GENESIS_NODE_HOST}:{GENESIS_NODE_P2P_PORT}"

# ─── Canonical Burn Addresses ──────────────────────────────
BURN_ADDRESS_ZERO = "0x0000000000000000000000000000000000000000"
BURN_ADDRESS_DEAD = "0x000000000000000000000000000000000000dEaD"
BURN_ADDRESSES = {BURN_ADDRESS_ZERO.lower(), BURN_ADDRESS_DEAD.lower()}

DNS_SEEDS = list(dict.fromkeys([GENESIS_NODE_HOST] + CONFIG.get('p2p', {}).get('dns_seeds', [])))
BOOTSTRAP_NODES = list(dict.fromkeys([GENESIS_BOOTSTRAP_ENDPOINT] + CONFIG.get('p2p', {}).get('bootstrap_nodes', [])))
MAX_PEERS = CONFIG['p2p'].get('max_peers', 50)
BAN_THRESHOLD = CONFIG['p2p'].get('ban_threshold', 5)
BAN_DURATION = _rule_int('p2p.ban_duration', CONFIG['p2p'].get('ban_duration'), 3600)
DHT_ENABLED = CONFIG['p2p'].get('dht_enabled', True)
GAS_PRICE = _rule_int('vm.gas_price', CONFIG['vm'].get('gas_price'), 1)
GAS_LIMIT_DEFAULT = CONFIG['vm'].get('gas_limit_default', 100000)
MAX_BYTECODE = _rule_int('vm.max_bytecode', CONFIG['vm'].get('max_bytecode'), 65536)
# BLOCK-GAS-1 (consensus): hard per-block ceilings enforced identically by
# production, import (_append_block), verify_block_proof and reorg replay.
# Bound into the genesis consensus ruleset (version 2).
def _strict_int(name, v, lo, hi):
    if isinstance(v, bool) or not isinstance(v, int) or not (lo <= v <= hi):
        raise ValueError(f"config vm.{name} must be an int in [{lo}, {hi}], got {v!r}")
    return v
GAS_LIMIT_DEFAULT = _strict_int('gas_limit_default', GAS_LIMIT_DEFAULT, 21000, 10_000_000)
MAX_BLOCK_GAS = _strict_int('max_block_gas', CONFIG['vm'].get('max_block_gas', 10_000_000),
                            GAS_LIMIT_DEFAULT * 10, 1_000_000_000)   # >= per-tx ceiling, so any valid tx fits alone
MAX_BLOCK_TXS = _strict_int('max_block_txs', CONFIG['vm'].get('max_block_txs', 1000), 1, 100_000)
MAX_STATE_SIZE = CONFIG['vm'].get('max_state_size', 1024)
VM_SANDBOX = CONFIG['vm'].get('sandbox', True)
VM_REQUIRE_SANDBOX = CONFIG['vm'].get('require_sandbox', False)
VM_TIMEOUT = CONFIG['vm'].get('timeout_seconds', 5)
MAX_VM_MEMORY = 64 * 1024 * 1024        # 64 MB hard cap on VM linear memory
SSTORE_REFUND = 4800                    # EIP-3529 SSTORE clear refund
# R4-sstore-redesign: EIP-2200 cost schedule (cold/warm access stays
# 2100/100 as before; these are the dynamic parts).
SSTORE_SET = 20000                      # 0 -> non-zero on a clean slot
SSTORE_RESET = 2900                     # 5000 - COLD_SLOAD_COST(2100)
MINIMUM_LIQUIDITY = 1000                # R4-dex-fix: first-mint lock (Uniswap V2 shape)
VM_RLIMIT_AS_BYTES = 256 * 1024 * 1024  # 256 MB per-VM-subprocess address space limit
MEMPOOL_MAX_SIZE = CONFIG['mempool'].get('max_size', 10000)
MEMPOOL_EXPIRY = CONFIG['mempool'].get('expiry', 3600)
# R6-nonce-tracker-bound: mempool policy (not consensus) — how far ahead of
# the confirmed nonce an incoming tx may queue (mirrors the RPC send-path
# "max gap: 10" rule so direct-add paths such as gossip cannot pin the
# tracker with an absurd future nonce).
MEMPOOL_MAX_NONCE_GAP = CONFIG['mempool'].get('max_nonce_gap', 10)
MAX_TX_PER_BLOCK = CONFIG['mempool'].get('max_tx_per_block', 100)


# Fixed constants
NODE_HOST = "0.0.0.0"
WS_PATH = "/ws"
RPC_PATH = "/rpc"
SYMBOL = "MCX"
NAME = "MicroCore"
VERSION = "64.2-PoG"
SUBS = 1_000_000
SCHEMA_VERSION = 1

# ─── PoG Consensus Constants ─────────────────────────────
CHAIN_ID = 6620
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
PROTOCOL_VERSION = 64
POG_ACTIVATION_HEIGHT = 100000
MIN_MAZE_SIZE = 5
WEIGHT_START_SIZE = 6
SHRINK_THRESHOLD = 1000
SHRINK_INTERVAL = 100
SHRINK_INTERVAL_SEC = 3600     # offline decay tick: evaluated every hour
ACTIVE_MINER_WINDOW_BLOCKS = 5  # consensus constant: eligible if active in last K blocks

# ─── Idea 5: self-attested maze sizes (IDEA5-ATTEST) ──────────────────────────
LOTTERY_SCALE = int(CONFIG['consensus'].get('lottery_scale', 1 << 249))          # LOTTERY-SCALE-1 (soak-tuned default)
ATTEST_FRESH_BUFFER = int(CONFIG['consensus'].get('attest_fresh_buffer', 5))      # ATTEST-FRESH-BUFFER-1
ATTEST_GROWTH_PER_BLOCK = int(CONFIG['consensus'].get('attest_growth_per_block', 5))
SLOT_TIMEOUT = int(CONFIG['consensus'].get('slot_timeout', 30))                  # IDEA5-LIVENESS-1

# R9-consensus-config (I-R8-07): the consensus parameters that must never
# diverge between import-time globals and the effective (CLI-selected)
# config in one process. apply_consensus_config() re-derives the globals
# from the effective config; check_consensus_params() binds them to the
# genesis record. Both are no-ops for keys the config does not set.
CONSENSUS_PARAM_KEYS = ("lottery_scale", "attest_fresh_buffer",
                        "attest_growth_per_block", "slot_timeout")


def _consensus_defaults():
    _c = DEFAULT_CONFIG.get('consensus', {})
    return {"lottery_scale": int(_c.get('lottery_scale', 1 << 249)),
            "attest_fresh_buffer": int(_c.get('attest_fresh_buffer', 5)),
            "attest_growth_per_block": int(_c.get('attest_growth_per_block', 5)),
            "slot_timeout": int(_c.get('slot_timeout', 30))}


def _validate_lottery_value(name, v, minimum: int) -> int:
    """CONFIG-VALID-1 (MCX80): strict lottery-parameter validation. Only
    genuine ints at or above the protocol minimum are accepted; bools,
    strings, floats, None and out-of-range values raise ValueError with the
    offending value named. Bounds from protocol use: lottery_scale is a
    positive scale (>= 1); attest buffers are additive caps (>= 0);
    slot_timeout divides elapsed time in the producer rank ladder
    (0 would ZeroDivision-crash it), so slot_timeout >= 1."""
    if isinstance(v, bool) or not isinstance(v, int):
        raise ValueError(f"config consensus.{name} must be an int >= {minimum}, got {v!r}")
    if v < minimum:
        raise ValueError(f"config consensus.{name} must be an int >= {minimum}, got {v!r}")
    return v


def _strict_bool(name, v, default=False) -> bool:
    """CONFIG-BOOL-1 (MCX80): centralized strict Boolean parsing. Actual
    bools pass through; only the documented strings "true"/"false"
    (case-insensitive, surrounding whitespace tolerated) are accepted.
    None means absent -> default. Anything else (numbers, unknown strings,
    lists, ...) raises ValueError. In particular the text "false" NEVER
    enables the flag (plain bool("false") is True — the bug this replaces)."""
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        s = v.strip().lower()
        if s == "true":
            return True
        if s == "false":
            return False
    raise ValueError(f"config {name} must be a boolean (true/false), got {v!r}")


def apply_consensus_config(config) -> dict:
    from node.genesis import _consensus_record_from_config  # lazy: forward ref, runtime-only
    """Re-derive EVERY consensus-effectual global from the effective config.

    CONFIG-APPLY-1 (MCX80 audit): the globals are now assigned FROM the same
    validated record the genesis uses (_consensus_record_from_config), so the
    two can never resolve a config differently. Previously absent keys kept
    whatever the globals held (a stale import-time/previous value) while the
    genesis record resolved them to defaults, and a late invalid value left
    earlier keys half-applied. Now: (1) every present value is validated and
    every absent/None value resolves to its default BEFORE any global changes
    (all-or-nothing), (2) globals == record by construction.

    GENESIS-VAL-3: the validator set is validated strictly first
    (validate_validators_config raises on a non-list/malformed key — never
    silent open mode) and applied with the rest. Present-but-invalid values
    raise ValueError (main() exits with a clear message); returns the applied
    mapping (recorded into fresh genesis files for genesis binding)."""
    _c = (config or {}).get('consensus', {}) or {}
    _vals = validate_validators_config(_c.get('validators'))      # strict, may raise
    rec = _consensus_record_from_config(config)                  # validates + resolves defaults, may raise
    # ---- all validation passed: assign (no failure points below) ----
    LOTTERY_SCALE = rec["lottery_scale"]
    ATTEST_FRESH_BUFFER = rec["attest_fresh_buffer"]
    ATTEST_GROWTH_PER_BLOCK = rec["attest_growth_per_block"]
    SLOT_TIMEOUT = rec["slot_timeout"]
    VALIDATORS = _vals
    MAX_MISSES = rec["max_misses"]
    BAN_DURATION = rec["ban_duration"]
    PRUNE_BLOCKS = rec["prune_blocks"]
    WALL_DENSITY_3D = rec["wall_density_3d"]
    MIN_FEE = rec["min_fee"]
    TOKEN_CREATION_MULTIPLIER = rec["token_creation_multiplier"]
    GAS_PRICE = rec["gas_price"]
    GAS_LIMIT_DEFAULT = rec["gas_limit_default"]
    MAX_BYTECODE = rec["max_bytecode"]
    MAX_BLOCK_GAS = rec["max_block_gas"]
    MAX_BLOCK_TXS = rec["max_block_txs"]
    HTLC_V1_ENABLED = rec["htlc_v1_enabled"]
    return {"lottery_scale": LOTTERY_SCALE,
            "attest_fresh_buffer": ATTEST_FRESH_BUFFER,
            "attest_growth_per_block": ATTEST_GROWTH_PER_BLOCK,
            "slot_timeout": SLOT_TIMEOUT,
            "validators": sorted(_effective_validators()),
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
            "htlc_v1_enabled": bool(HTLC_V1_ENABLED)}


def check_consensus_params(config, genesis_data):
    """Bind the effective config to the genesis consensus record (Fix 2).

    Compares the FULL ruleset (_consensus_record_from_config: every
    operator-settable validity/execution/eligibility/fork-choice value plus
    code anchors — see its docstring for the bound/excluded audit) against
    the file's record. Returns (True, reason); reason is "ok" or
    "grandfathered-no-record" (files predating any record warn but boot —
    unreachable via the genesis_export_verified startup gate, which refuses
    record-less files at the identity layer first; kept as defense in
    depth). A mismatch refuses to run mixed rules for one chain:
    (False, "<dotted.key> mismatch: ...") naming the exact key.
    """
    try:
        _want = _consensus_record_from_config(config)
    except (TypeError, ValueError):
        return False, "unparseable consensus config"
    _rec = (genesis_data or {}).get('consensus') if isinstance(genesis_data, dict) else None
    if not isinstance(_rec, dict):
        return True, "grandfathered-no-record"

    def _diff(path, want, got):
        if isinstance(want, dict):
            if not isinstance(got, dict):
                return f"{path or 'consensus'} missing/unparseable in genesis record"
            for _k in want:
                _r = _diff(f"{path}.{_k}" if path else str(_k), want[_k], got.get(_k))
                if _r:
                    return _r
            return ""
        if got != want:
            return f"{path} mismatch: config={want!r} genesis={got!r}"
        return ""
    _reason = _diff("", _want, _rec)
    if _reason:
        return False, _reason
    return True, "ok"


def _normalize_validator_key(v) -> str:
    """Canonical validator key form: string, lowercased, 0x prefix stripped."""
    s = str(v).strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    return s


def _normalize_validator_list(vals) -> list:
    """Sorted canonical validator list from a config value. Non-list
    values and falsy entries yield []. Duplicates are NOT deduplicated
    here (they collapse in the frozenset); sorting keeps the genesis
    record deterministic."""
    try:
        if not isinstance(vals, (list, tuple)):
            return []
        # GENESIS-VAL-1: dedupe so _consensus_record_from_config (config) and
        # _effective_consensus_ruleset (frozenset) always agree. Previously a
        # duplicate entry made check_consensus_params refuse to boot the
        # node that had just created the genesis.
        return sorted({_normalize_validator_key(v) for v in vals if v})
    except Exception:
        return []

_VALIDATOR_KEY_RE = re.compile(r"^04[0-9a-f]{128}$")


def validate_validators_config(raw) -> list:
    """GENESIS-VAL-2: strict, fail-closed validation of consensus.validators.

    The tolerant normalizer above silently maps a non-list (e.g. a single
    YAML string, the natural way to write ONE validator) to [] = open mode
    where ANY key may produce blocks, and silently accepts malformed keys
    that can never match. Both are consensus-affecting misconfigurations,
    so startup refuses them. None / [] is the explicit open mode (warned
    elsewhere; refused on mainnet). Returns the canonical sorted list."""
    if raw is None:
        return []
    if not isinstance(raw, (list, tuple)):
        raise ValueError(
            "consensus.validators must be a YAML LIST of public keys "
            f"(got {type(raw).__name__}); a single key still needs list syntax: '- 04ab...'")
    out = set()
    for i, v in enumerate(raw):
        if not isinstance(v, str):
            raise ValueError(f"consensus.validators[{i}] must be a string public key")
        k = _normalize_validator_key(v)
        if not _VALIDATOR_KEY_RE.fullmatch(k):
            raise ValueError(
                f"consensus.validators[{i}] is not an uncompressed secp256k1 public key "
                f"(expected '04' + 128 hex chars, got {len(k)} chars)")
        out.add(k)
    return sorted(out)


def _effective_validators() -> frozenset:
    """The fixed producer set this process enforces. Empty = open mode
    (any maze key may produce, pre-MCX79 behavior). Frozenset so the
    verify/append/weight hot paths check in O(1)."""
    try:
        return frozenset(_normalize_validator_list(VALIDATORS or []))
    except Exception:
        return frozenset()


_VALIDATOR_MODE_WARNED = False


def _validator_boot_mode() -> str:
    """'restricted' when a validator set is configured, else 'open' with
    a one-time WARNING. Called at node start; unit-testable without
    booting."""
    global _VALIDATOR_MODE_WARNED
    if _effective_validators():
        return "restricted"
    if not _VALIDATOR_MODE_WARNED:
        _VALIDATOR_MODE_WARNED = True
        logger.warning("[VALIDATORS] validator set is empty — any maze key may produce blocks. Do not run this on mainnet.")
    return "open"


def _mainnet_guard_failures(config) -> list:
    """Pure mainnet boot-gate: every refusal reason for this config.
    Empty list = clear to boot. Reads process env for the password/auto-
    install variables (same as the inline guard it replaces). Unit-
    testable without constructing or starting a node."""
    _cfg = config or {}
    if not bool(_cfg.get('node', {}).get('mainnet', False)):
        return []
    failures = []
    if not _cfg.get('database', {}).get('require_postgres', False):
        failures.append("database.require_postgres must be true")
    if not _cfg.get('vm', {}).get('require_sandbox', False):
        failures.append("vm.require_sandbox must be true")
    if os.environ.get("MCX_ALLOW_AUTO_INSTALL"):
        failures.append("MCX_ALLOW_AUTO_INSTALL must be unset on mainnet")
    if os.environ.get("MCX_PG_PASSWORD") in (None, "", "postgres"):
        # R4-mainnet-guard-consistency: name both password variables.
        # MCX_PG_PASSWORD feeds Database._auto_detect_and_connect; the
        # VM subprocess sync connection separately reads MCX_DB_PASS
        # (default 'postgres') — set both on mainnet.
        failures.append("MCX_PG_PASSWORD must be set to a non-default value (node auto-detect)")
    # R5-mainnet-guard-db-pass: both password env vars must be non-default.
    if os.environ.get("MCX_DB_PASS") in (None, "", "postgres"):
        failures.append("MCX_DB_PASS must be set to a non-default value")
    # MCX79 fixed validator set: mainnet must name its producers.
    if not _effective_validators():
        failures.append("consensus.validators must be non-empty on mainnet")
    return failures

def _maze_att_weight(size) -> int:
    """IDEA5-ATTEST lottery weight for an attested maze size (size^3 - 5^3)."""
    # R4-overflow-guard: int(float('inf')) raises OverflowError, not
    # (TypeError, ValueError); non-finite floats carry no weight.
    if isinstance(size, float) and not math.isfinite(size):
        return 0
    try:
        size = int(size)
    except (TypeError, ValueError, OverflowError):
        return 0
    return 0 if size <= MIN_MAZE_SIZE else size ** 3 - MIN_MAZE_SIZE ** 3

TICKET_DOMAIN_MAX = (1 << 256) - 1  # R9-lottery-cap: max keccak ticket.


def _maze_threshold(size) -> int:
    """LOTTERY-SCALE-1: ticket < threshold wins the lottery for this size.

    MCX79 asymptotic gate (chain reset, ruleset v3): pass probability
    p(size) = 1 - MIN_MAZE_SIZE^3 / size^3, evaluated as an integer
    threshold over the 256-bit ticket domain. Strictly increasing in
    size, strictly below TICKET_DOMAIN_MAX for every finite integer
    size — no size ever reaches 100% ("larger maze, higher chance, no
    max, never 100%"). Integer arithmetic only: no floats anywhere on
    this path. Fork weight (_maze_att_weight, cubic, unbounded by
    design) is a separate mechanism and is NOT capped. LOTTERY_SCALE
    itself is frozen (no longer consumed here; retained for record
    compatibility).
    """
    try:
        size = int(size)
    except (TypeError, ValueError, OverflowError):
        return 0
    if size <= MIN_MAZE_SIZE:
        return 0
    denom = size ** 3
    return TICKET_DOMAIN_MAX - (MIN_MAZE_SIZE ** 3 * TICKET_DOMAIN_MAX) // denom

def _maze_ticket(prev_hash: str, height: int, maze_id: str) -> int:
    """Deterministic ticket: int(keccak(prev_hash || height.to_bytes(8) || maze_id))."""
    return int.from_bytes(
        eth_keccak(bytes.fromhex(prev_hash) + int(height).to_bytes(8, "big") + str(maze_id).encode()),
        "big")

def _block_att_weight(block: dict) -> int:
    """IDEA5-CHAINWEIGHT-1: per-block fork-choice weight = its attestation weight.

    MCX79: blocks attested by keys outside the configured validator set
    contribute zero fork weight (defense in depth alongside the
    verify/append rejections). Empty set = open mode, unchanged."""
    att = block.get("maze_attestation")
    if not isinstance(att, dict):
        return 0
    _validators = _effective_validators()
    if _validators and _normalize_validator_key(att.get("pubkey", "")) not in _validators:
        return 0
    return _maze_att_weight(att.get("size", 0))


def _filter_validator_candidates(rows):
    """VALIDATOR-CAND-1: restrict the producer's lottery pool to the fixed
    validator set (maze_id IS the maze public key, the same identity
    verify_block_proof checks). Without this, a non-validator maze could win
    the local ticket race, get a block that EVERY validator rejects, and
    stall the slot. Empty set = open mode: pool unchanged."""
    _v = _effective_validators()
    if not _v:
        return list(rows)
    return [r for r in rows if _normalize_validator_key(r.get("maze_id", "")) in _v]


def _fork_tiebreak_winner(our_tip: str, their_tip: str) -> bool:
    """R4-fork-tie-hashbreak: equal-weight fork rule — the LARGER hex tip
    hash wins (Bitcoin shape). Deterministic across nodes, unlike
    first-seen. Equal hashes mean the same tip: keep ours (False)."""
    return str(their_tip or "") > str(our_tip or "")

def _gas_ceiling(gas_in) -> int:
    """GAS-CEIL-1: clamp client-supplied gas to 10x the configured default."""
    try:
        g = GAS_LIMIT_DEFAULT if gas_in is None else gas_in
        if isinstance(g, str):
            g = int(g, 16) if g.lower().startswith('0x') else int(g)
        g = int(g)
    except (TypeError, ValueError):
        g = GAS_LIMIT_DEFAULT
    return max(0, min(g, GAS_LIMIT_DEFAULT * 10))

# BLOCK-GAS-1: protocol-defined block work budget. A transaction's declared
# gas is the SAME clamped value execution uses (_gas_ceiling); only
# VM-reaching tx types consume it. Independent of host speed or execution
# results, so every node derives the identical verdict from the block alone.
VM_GAS_TX_TYPES = ('contract_deploy', 'contract_call', 'htlc_create')

def _tx_declared_gas(tx) -> int:
    if not isinstance(tx, dict):
        raise ValueError("transaction is not an object")
    if tx.get('tx_type') in VM_GAS_TX_TYPES:
        return _gas_ceiling(tx.get('gas', GAS_LIMIT_DEFAULT))
    return 0

def _block_limits_ok(tx_list):
    """(ok, reason): len(txs) <= MAX_BLOCK_TXS and sum(declared gas) <= MAX_BLOCK_GAS."""
    try:
        txs = tx_list or []
        if len(txs) > MAX_BLOCK_TXS:
            return False, f"{len(txs)} txs > MAX_BLOCK_TXS {MAX_BLOCK_TXS}"
        total = 0
        for t in txs:
            total += _tx_declared_gas(t)
            if total > MAX_BLOCK_GAS:
                return False, f"declared gas {total} > MAX_BLOCK_GAS {MAX_BLOCK_GAS}"
        return True, ""
    except (TypeError, ValueError, OverflowError) as e:
        return False, f"malformed transactions: {e}"

# ─── Spatial assets (tokens + buildings) ────────────────── REMOVED: replaced by Spatial Tokens V1 (see below, after TOKEN_MAX_SUPPLY)
BLOCK_CACHE_MAX = 10000  # max blocks kept in memory
OFFLINE_DECAY_RATE = 0.25      # cubes lost per tick scaled by (size - MIN_MAZE_SIZE)
GROWTH_DIFFICULTY_EXP = 0.1    # wall-hit PoW difficulty increase per unit of avg maze size above 5
MIN_WALL_DENSITY_PPM = 350000
DENSITY_INCREMENT_PPM = 35000
TURBULENCE_INCREMENT_PPM = 150000
ACTIVE_MINER_WINDOW_SEC = 60   # miner deactivates after 60s of inactivity
STORAGE_PER_CELL_KB = 10        # Future: 10 KB per cell for storage proofs (not active yet)
GLOBAL_SHRINK_FACTOR = 1.0      # Updated every block: max(1.0, avg_size / 10)
BASE_DENSITY_PPM = 500000       # 50% walls base density (hard from start)
BASE_TURBULENCE_PPM = 100000    # Base turbulence for maze generation
SNAPSHOT_INTERVAL = 10000       # Save state snapshot every N blocks
CONSENSUS_EXCLUDED_FIELDS = {"hash", "signature", "pqc_signature", "finalized"}
_BLOCK_PROOF_KEYS = {"winner","producer_pub","signature","state_root","transactions","maze_attestation","reward_wallet","maze_updates","global_shrink_factor","slashes","spatial_fee_amount"}  # IDEA5-ATTEST, Spatial Tokens V2
# ROW-SNAPSHOT (MSG_NEW_MOVE): only these minermazes columns may be adopted
# from a peer's authoritative row payload.
MAZE_ROW_COLS = frozenset({
    "maze_id", "minerid", "size", "walldensityppm", "seed", "posx", "posy",
    "posz", "goalx", "goaly", "goalz", "movenonce", "consecutivewallhits",
    "turbulenceppm", "growthcount", "knowledge", "lastgoalheight",
    "lastactiveheight", "mazeroot", "invitedguest", "guestlock",
    "lastknowledgeheight", "createdat", "updatedat", "ghostx", "ghosty",
    "ghostz",
})
MIN_MAZE_SIZE_3D = MIN_MAZE_SIZE

def _valid_maze_size(v):
    """MAZE-MIN-1 (MCX80): single maze-dimension invariant — an int never
    below MIN_MAZE_SIZE (5 = 5x5x5 = 125 cells). Returns the int, or None
    for anything else (non-ints, bools, non-integral floats, undersized).
    Callers reject (verify) or skip/quarantine (apply/load); nobody
    clamps-and-continues a consensus input."""
    try:
        if isinstance(v, bool):
            return None
        n = int(v)
        if isinstance(v, float) and float(n) != float(v):
            return None
    except (TypeError, ValueError, OverflowError):
        return None
    if n < MIN_MAZE_SIZE:
        return None
    return n
# R8-moverow-trust (R7-21): snapshot columns safe to adopt from an
# author-signed but row-unsigned gossip move. The move signature covers
# identity/nonce/direction — NOT the row. Identity (maze_id, minerid)
# and consensus-adjacent columns (size, growth, seed, density,
# knowledge, roots, timestamps, permissions) NEVER merge; they follow
# sealed attestations and local execution only. Position, activity,
# counters, and display columns preserve one-message catch-up parity.
_MOVE_ROW_SAFE_COLS = frozenset({
    "posx", "posy", "posz", "goalx", "goaly", "goalz",
    "movenonce", "consecutivewallhits",
    "lastactiveheight", "ghostx", "ghosty", "ghostz",
})
STATE_TREE_EMPTY_HASH = '0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421'

def mutate_maze_walls(dense_maze, movenonce: int, size: int, protect=None):
    """Deterministic wall mutation based on movenonce. ~25% of walls toggle per call.
    Both miner and node call this with the same movenonce to get the same mutated maze.
    protect: set of (x,y,z) positions that must stay open (start/goal).
    After toggling, verifies solvability (BFS from start to goal). If unsolvable,
    reverts all toggles for this movenonce.
    R6-maze-mutation-idempotent: documentation only (no code change) — this
    function is deterministic for a nonce but NOT idempotent: applying the
    same nonce twice toggles the same cells back (round-trip). No current
    caller applies it twice; any future caller must treat it as
    apply-exactly-once per nonce."""
    protect = set(protect) if protect else set()
    protect.add((0, 0, 0))
    protect.add((size - 1, size - 1, size - 1))
    bounded_nonce = movenonce & 0xFFFFFFFFFFFFFFFF
    mn_bytes = bounded_nonce.to_bytes(8, "big")
    toggled = []
    for z in range(size):
        for y in range(size):
            for x in range(size):
                if (x, y, z) in protect:
                    continue
                h = eth_keccak(b"MCXPOGMUTATEV1" + mn_bytes + x.to_bytes(2, "big") + y.to_bytes(2, "big") + z.to_bytes(2, "big"))
                if h[0] < 64:  # ~25% toggle rate
                    dense_maze[z][y][x] = not dense_maze[z][y][x]
                    toggled.append((x, y, z))
    # Verify solvability: BFS from start to goal
    if toggled:
        start = (0, 0, 0)
        goal = (size - 1, size - 1, size - 1)
        q = deque([start])
        visited = {start}
        while q:
            cx, cy, cz = q.popleft()
            if (cx, cy, cz) == goal:
                break
            for ddx, ddy, ddz in ((1,0,0),(-1,0,0),(0,1,0),(0,-1,0),(0,0,1),(0,0,-1)):
                nx, ny, nz = cx+ddx, cy+ddy, cz+ddz
                if 0 <= nx < size and 0 <= ny < size and 0 <= nz < size and (nx,ny,nz) not in visited and not dense_maze[nz][ny][nx]:
                    visited.add((nx,ny,nz))
                    q.append((nx,ny,nz))
        else:
            # Goal unreachable — revert all toggles
            for (tx, ty, tz) in toggled:
                dense_maze[tz][ty][tx] = not dense_maze[tz][ty][tx]
    return dense_maze
FINALITY_THRESHOLD = CONFIG['consensus'].get('finality_threshold', 0.66)
FINALITY_EPOCH_LENGTH = 100
RBF_INCREMENT = CONFIG['fees'].get('rbf_increment', 1.1)
CPFP_MIN_FEE = CONFIG['fees'].get('cpfp_min_fee', 100)
INITIAL_BLOCK_REWARD = 1_000_000
HALVING_INTERVAL = 2_522_880
# NATIVE-SUPPLY-1 (MCX80, corrected): the genesis allocation is 200 MCX,
# and the native cap is derived from ACTUAL issuance — NOT the nominal
# figure. Boundary convention (see get_block_reward): height 0 is the
# genesis block and carries NO mint (_validated_block_reward returns zeros
# for bid <= 0; _create_genesis sets total_minted = GENESIS_SUPPLY
# directly). Minting heights start at 1. Era k spans heights [k*H, (k+1)*H)
# with reward INITIAL_BLOCK_REWARD // 2**k, so the first halving takes
# effect AT height HALVING_INTERVAL (full reward on heights 0..H-1, half
# on H..2H-1, ...). Hence:
#   nominal 4-year figure = HALVING_INTERVAL * INITIAL_BLOCK_REWARD
#     = 2,522,880 * 1,000,000 = 2,522,880 MCX (includes height 0, which
#     never mints — NOT the issued amount), while
#   actual 4-year mined = (HALVING_INTERVAL - 1) * INITIAL_BLOCK_REWARD
#     = heights 1..H-1 at full reward = 2,522,879 MCX, and
#   maximum supply = 2 * actual-4-year + genesis
#     = 2 * 2,522,879 * 1,000,000 + 200 * 1,000,000 = 5,045,958 MCX.
# Schedule audit (from block 1): integer halving reaches 0 after height
# 50,457,599 (20 nonzero halvings, last reward 1 base unit); exact lifetime
# block issuance = 5,045,741.33984 MCX, so lifetime total (blocks + 200 MCX
# genesis) = 5,045,941.33984 MCX, leaving ~16.66 MCX of unreachable
# rounding headroom under the cap. No native reward path can exceed it:
# produce caps base at MAX_SUPPLY - minted, _validated_block_reward
# enforces the same rule on verify/append, and the economics gate caps
# genesis total_minted. (Pre-correction v4 records carried the nominal
# values 5,045,760/100,000 MCX; no v4 chain was ever deployed, so the
# version stays 4 — such records are refused on sight.) Chain reset:
# acceptance change.
GENESIS_SUPPLY = 200 * SUBS
# Minting heights of the first era exclude genesis: heights 1..H-1.
FIRST_ERA_MINT_HEIGHTS = HALVING_INTERVAL - 1
MAX_SUPPLY = 2 * FIRST_ERA_MINT_HEIGHTS * INITIAL_BLOCK_REWARD + GENESIS_SUPPLY
# Native MCX supply stays distinct from user-created token and
# spatial-token limits below; those caps are intentionally NOT relinked.
TOKEN_MAX_SUPPLY = 5_045_760 * SUBS
TOKEN_MAX_MINEABLE_SUPPLY = TOKEN_MAX_SUPPLY

# ─── Spatial tokens V1 (SPATIAL TOKENS — COMPLETE SPECIFICATION) ─────
# (inserted here rather than at the old Spatial-assets block location
#  because SPATIAL_MAX_SUPPLY references TOKEN_MAX_SUPPLY, defined above)
SPATIAL_ACTIVATION_HEIGHT        = 0
# MCX76-htlc-deferred: HTLC V1 is out of scope (top-level precompile
# dispatch, deterministic htlc_id, and timelock alignment are unmet).
# htlc_create is rejected unless an operator explicitly opts in.
HTLC_V1_ENABLED = _strict_bool('consensus.htlc_v1_enabled', CONFIG['consensus'].get('htlc_v1_enabled', False))
SPATIAL_MIN_DEPLOYABLE_MAX       = 5
SPATIAL_BASE_DEPLOY_FEE          = 1000 * SUBS
SPATIAL_DEPLOY_FEE_MAZE_BPS = 9000   # 90% of spatial fees -> live mazes
SPATIAL_COORD_BOUND         = 5      # (x,y,z) each in [0, 5); inside every maze
SPATIAL_MAX_NAME_LEN             = 32
SPATIAL_MAX_SYMBOL_LEN           = 10
SPATIAL_MAX_SUPPLY               = TOKEN_MAX_SUPPLY
TOKEN_DEFAULT_DECIMALS = 18
DISCOVERY_INTERVAL = 300
HEARTBEAT_INTERVAL = 30
SYNC_INTERVAL = 10
CHECKPOINT_SYNC_THRESHOLD = 500
SYNC_STUCK_TRIP_COOLDOWN = 300
DHT_PORT = int(CONFIG.get('p2p', {}).get('dht_port', 8083))
DHT_BOOTSTRAP_NODES = [(GENESIS_NODE_HOST, GENESIS_NODE_DHT_PORT)]
DHT_SHARD_COUNT = 16
DHT_PEERS_KEY_PREFIX = "mcx_peers_shard_"
DHT_ENTRY_TTL = 600
DHT_MAX_ENTRIES_PER_SHARD = 64
PEER_CACHE_FILE = "microcore_peers.json"
P2P_MAGIC = b"MCX1"
P2P_VERSION = 1
# Offline ASN approximation. Keyed by well-known cloud/hosting CIDR blocks.
# For mainnet, replace with a MaxMind/Team-Cymru offline DB — this map only
# needs to break up the dominant cloud providers enough for eclipse resistance.
ASN_STATIC_MAP = (
    ("3.0.0.0/8",      "AS16509-AWS"),
    ("13.32.0.0/15",   "AS16509-AWS"),
    ("13.64.0.0/11",   "AS8075-AZURE"),
    ("18.0.0.0/8",     "AS16509-AWS"),
    ("20.0.0.0/8",     "AS8075-AZURE"),
    ("34.64.0.0/10",   "AS396982-GCP"),
    ("34.192.0.0/10",  "AS14618-AWS"),
    ("35.152.0.0/13",  "AS14618-AWS"),
    ("35.184.0.0/13",  "AS396982-GCP"),
    ("35.192.0.0/12",  "AS396982-GCP"),
    ("40.64.0.0/10",   "AS8075-AZURE"),
    ("46.101.0.0/16",  "AS14061-DIGITALOCEAN"),
    ("51.104.0.0/13",  "AS8075-AZURE"),
    ("52.0.0.0/8",     "AS16509-AWS"),
    ("54.0.0.0/8",     "AS14618-AWS"),
    ("64.225.0.0/16",  "AS14061-DIGITALOCEAN"),
    ("68.183.0.0/16",  "AS14061-DIGITALOCEAN"),
    ("95.216.0.0/16",  "AS24940-HETZNER"),
    ("104.16.0.0/13",  "AS13335-CLOUDFLARE"),
    ("104.24.0.0/14",  "AS13335-CLOUDFLARE"),
    ("104.131.0.0/16", "AS14061-DIGITALOCEAN"),
    ("104.196.0.0/14", "AS396982-GCP"),
    ("116.202.0.0/15", "AS24940-HETZNER"),
    ("116.203.0.0/16", "AS24940-HETZNER"),
    ("128.140.0.0/17", "AS24940-HETZNER"),
    ("138.68.0.0/16",  "AS14061-DIGITALOCEAN"),
    ("142.132.128.0/17","AS24940-HETZNER"),
    ("159.65.0.0/16",  "AS14061-DIGITALOCEAN"),
    ("159.69.0.0/16",  "AS24940-HETZNER"),
    ("165.227.0.0/16", "AS14061-DIGITALOCEAN"),
    ("167.99.0.0/16",  "AS14061-DIGITALOCEAN"),
    ("168.119.0.0/16", "AS24940-HETZNER"),
    ("172.64.0.0/13",  "AS13335-CLOUDFLARE"),
    ("176.9.0.0/16",   "AS24940-HETZNER"),
    ("178.62.0.0/16",  "AS14061-DIGITALOCEAN"),
    ("188.166.0.0/16", "AS14061-DIGITALOCEAN"),
    ("195.201.0.0/16", "AS24940-HETZNER"),
    ("206.189.0.0/16", "AS14061-DIGITALOCEAN"),
)

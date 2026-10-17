# Split of MCX81.py (lines 4999-7735). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import HAVE_RESOURCE, eth_keccak, logger
from node.config import CHAIN_ID, MAX_VM_MEMORY, MINIMUM_LIQUIDITY, SSTORE_REFUND, SSTORE_RESET, SSTORE_SET, VM_REQUIRE_SANDBOX, VM_RLIMIT_AS_BYTES, VM_TIMEOUT
from node.crypto import _s256
from node.chain import compute_contract_address
from node.database import Database
from node.bootstrap import BrokenProcessPool, Callable, Dict, IntEnum, List, ProcessPoolExecutor, Set, Tuple, asyncio, hashlib, json, math, mp, os, secrets, sqlite3, sys, time
from node import config as _config


# ─── Opcode Definitions ──────────────────────────────────────
class Opcode(IntEnum):
    STOP = 0x00; ADD = 0x01; SUB = 0x02; MUL = 0x03; DIV = 0x04; SDIV = 0x05; MOD = 0x06; SMOD = 0x07; EXP = 0x08; NEG = 0x09
    LT = 0x10; GT = 0x11; SLT = 0x12; SGT = 0x13; EQ = 0x14; ISZERO = 0x15; AND = 0x16; OR = 0x17; XOR = 0x18; NOT = 0x19; BYTE = 0x1a; SHL = 0x1b; SHR = 0x1c; SAR = 0x1d
    SHA3 = 0x20
    POP = 0x50; MLOAD = 0x51; MSTORE = 0x52; MSTORE8 = 0x53; SLOAD = 0x54; SSTORE = 0x55; JUMP = 0x56; JUMPI = 0x57; PC = 0x58; MSIZE = 0x59; GAS = 0x5a; JUMPDEST = 0x5b
    PUSH1 = 0x60; PUSH2 = 0x61; PUSH3 = 0x62; PUSH4 = 0x63; PUSH5 = 0x64; PUSH6 = 0x65; PUSH7 = 0x66; PUSH8 = 0x67; PUSH9 = 0x68; PUSH10 = 0x69; PUSH11 = 0x6a; PUSH12 = 0x6b; PUSH13 = 0x6c; PUSH14 = 0x6d; PUSH15 = 0x6e; PUSH16 = 0x6f; PUSH17 = 0x70; PUSH18 = 0x71; PUSH19 = 0x72; PUSH20 = 0x73; PUSH21 = 0x74; PUSH22 = 0x75; PUSH23 = 0x76; PUSH24 = 0x77; PUSH25 = 0x78; PUSH26 = 0x79; PUSH27 = 0x7a; PUSH28 = 0x7b; PUSH29 = 0x7c; PUSH30 = 0x7d; PUSH31 = 0x7e; PUSH32 = 0x7f
    DUP1 = 0x80; DUP2 = 0x81; DUP3 = 0x82; DUP4 = 0x83; DUP5 = 0x84; DUP6 = 0x85; DUP7 = 0x86; DUP8 = 0x87; DUP9 = 0x88; DUP10 = 0x89; DUP11 = 0x8a; DUP12 = 0x8b; DUP13 = 0x8c; DUP14 = 0x8d; DUP15 = 0x8e; DUP16 = 0x8f
    SWAP1 = 0x90; SWAP2 = 0x91; SWAP3 = 0x92; SWAP4 = 0x93; SWAP5 = 0x94; SWAP6 = 0x95; SWAP7 = 0x96; SWAP8 = 0x97; SWAP9 = 0x98; SWAP10 = 0x99; SWAP11 = 0x9a; SWAP12 = 0x9b; SWAP13 = 0x9c; SWAP14 = 0x9d; SWAP15 = 0x9e; SWAP16 = 0x9f
    LOG0 = 0xa0; LOG1 = 0xa1; LOG2 = 0xa2; LOG3 = 0xa3; LOG4 = 0xa4
    CREATE = 0xf0; CALL = 0xf1; CALLCODE = 0xf2; RETURN = 0xf3; DELEGATECALL = 0xf4; CREATE2 = 0xf5; STATICCALL = 0xfa; REVERT = 0xfd; INVALID = 0xfe; SELFDESTRUCT = 0xff
    CHAINID = 0x46; EXTCODEHASH = 0x3f; SELFBALANCE = 0x47; BASEFEE = 0x48
    # F-opcodes (follow-up): previously-missing yellow-paper values,
    # implemented additively. Absent-before frames reverted on these bytes;
    # no existing contract could depend on the revert, so addition cannot
    # change the outcome of any previously-successful execution.
    # CHANGELOG F-opcodes.
    SIGNEXTEND = 0x0b; ORIGIN = 0x32; CALLER = 0x33
    GASPRICE = 0x3a; RETURNDATASIZE = 0x3d; RETURNDATACOPY = 0x3e
    # R4-opcodes-add: block-context reads (additive; absent-before frames
    # reverted on these bytes). CHANGELOG R4-opcodes-add.
    BLOCKHASH = 0x40; TIMESTAMP = 0x42; NUMBER = 0x43
    # R5-opcodes-add: verified already-closed (R4 threading + tests); no further opcodes added this pass.
    ADDRESS = 0x30; BALANCE = 0x31; CALLVALUE = 0x34; CALLDATALOAD = 0x35; CALLDATASIZE = 0x36; CALLDATACOPY = 0x37; CODESIZE = 0x38; CODECOPY = 0x39; EXTCODESIZE = 0x3b; EXTCODECOPY = 0x3c


# ─── Gas Costs ──────────────────────────────────────────────
class GasCost:
    ZERO = 0; BASE = 2; VERYLOW = 3; LOW = 5; MID = 8; HIGH = 10
    EXTCODE = 700; BALANCE = 700; SLOAD = 800; SSTORE = 20000; SSTORE_COLD = 20000
    CALL = 700; NEWACCOUNT = 25000; MEMORY = 3; LOG = 375; LOGDATA = 8; LOGTOPIC = 375
    SHA3 = 30; SHA3_WORD = 6; CREATE = 32000; CREATE2 = 32000; EXP_BYTE = 50
    EXTCODEHASH_COST = 700; SELFBALANCE_COST = 5; BASEFEE_COST = 2; CHAINID_COST = 2
    COPY = 3; RETURN_COST = 0; REVERT_COST = 0; SELFDESTRUCT_COST = 5000; CALLVALUE_COST = 2; CALLDATA = 3


# ─── Precompiled Contracts ──────────────────────────────────
PRECOMPILED = {
    "0x0000000000000000000000000000000000000001": "ecrecover",
    "0x0000000000000000000000000000000000000002": "sha256",
    "0x0000000000000000000000000000000000000003": "keccak256",
    "0x0000000000000000000000000000000000000004": "token",
    "0x0000000000000000000000000000000000000005": "mcx",
    "0x0000000000000000000000000000000000000006": "htlc",
    "0x0000000000000000000000000000000000000007": "ripemd160",
    "0x0000000000000000000000000000000000000008": "identity",
    "0x0000000000000000000000000000000000000009": "dex",
    "0x000000000000000000000000000000000000000a": "blake2",
    "0x000000000000000000000000000000000000000b": "modexp",
    "0x000000000000000000000000000000000000000c": "ecAdd",
    "0x000000000000000000000000000000000000000d": "ecMul",
    "0x000000000000000000000000000000000000000e": "ecPairing",
}

# Precompile activation heights. A precompile is only callable at block heights
# >= its activation record. All current precompiles are genesis-active (0).
# Future precompiles (e.g. a new curve, a new hash) get added here with the
# hard-fork height they activate at; the VM refuses calls below that height
# so old nodes and new nodes agree on state at every block.
PRECOMPILED_VERSIONS = {
    "0x0000000000000000000000000000000000000001": 0,  # ecrecover
    "0x0000000000000000000000000000000000000002": 0,  # sha256
    "0x0000000000000000000000000000000000000003": 0,  # keccak256
    "0x0000000000000000000000000000000000000004": 0,  # token
    "0x0000000000000000000000000000000000000005": 0,  # mcx
    "0x0000000000000000000000000000000000000006": 0,  # htlc
    "0x0000000000000000000000000000000000000007": 0,  # ripemd160
    "0x0000000000000000000000000000000000000008": 0,  # identity
    "0x0000000000000000000000000000000000000009": 0,  # dex
    "0x000000000000000000000000000000000000000a": 0,  # blake2
    "0x000000000000000000000000000000000000000b": 0,  # modexp
    "0x000000000000000000000000000000000000000c": 0,  # ecAdd
    "0x000000000000000000000000000000000000000d": 0,  # ecMul
    "0x000000000000000000000000000000000000000e": 0,  # ecPairing
}


# ─── Keccak Permutation (used by both SHA3 and Keccak) ───
def sha3_keccak_f(state):
    """
    The Keccak-f[1600] permutation, applied to a list of 25 64-bit words.
    Used by keccak_256 and other hashing.
    """
    round_constants = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000080008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000000000000a, 0x8000000080008081,
        0x8000000080008080, 0x0000000000000001, 0x8000000000008008,
    ]
    for round in range(24):
        # θ step (DISCLOSED FIX: the rho-rotation below needs an explicit
        # 64-bit mask — Python's `<<` is unbounded, so unmasked lanes escaped
        # 64 bits, corrupting the hash and eventually raising OverflowError
        # in keccak_256's final to_bytes. Caught by Section 7's tests.)
        C = [state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20] for x in range(5)]
        D = [C[(x+4)%5] ^ (((C[(x+1)%5] << 1) | (C[(x+1)%5] >> 63)) & 0xFFFFFFFFFFFFFFFF) for x in range(5)]
        for x in range(5):
            for y in range(5):
                state[x + 5*y] ^= D[x]
        # ρ and π steps 
        (x, y) = (1, 0)
        current = state[x + 5*y]
        for t in range(24):
            (x, y) = (y, (2*x + 3*y) % 5)
            shift = ((t+1) * (t+2) // 2) % 64
            next_val = state[x + 5*y]
            state[x + 5*y] = ((current << shift) | (current >> (64 - shift))) & ((1<<64)-1)
            current = next_val
        # χ step
        for y in range(5):
            row = [state[x + 5*y] for x in range(5)]
            for x in range(5):
                state[x + 5*y] = row[x] ^ ((~row[(x+1)%5]) & row[(x+2)%5])
        # ι step
        state[0] ^= round_constants[round]


# ─── keccak_256 ─────────────────────────────────────────────
def keccak_256(data: bytes) -> bytes:
    # EVM-CONFORMANCE: Keccak-256 (pre-NIST padding) per the yellow paper
    # appendix and EIP-1014/EIP-1052. The prior pure-python permutation
    # diverged from Keccak-256 on every input (verified against
    # eth_utils.keccak across 0..1000-byte messages), which corrupted the
    # SHA3 opcode, the keccak256 precompile, VRF hashing and every
    # selector derived through this helper. Delegating to eth_keccak
    # (eth_utils, Crypto fallback) keeps one canonical implementation.
    # sha3_keccak_f below is retained for reference only.
    # CHANGELOG F-keccak.
    return eth_keccak(data)


# ─── VRF (ECVRF over secp256k1) ────────────────────────────────
# Implements ECVRF per RFC 9381 (draft) style hash-to-curve for secp256k1.
# proof = (Gamma, c, s) where Gamma = sk * H(alpha), c = H(Gamma), s = k + c*sk mod n
# output = keccak(Gamma)
# All operations over secp256k1 curve (n = SECP256K1_N)

try:
    from py_ecc.secp256k1 import (
        SECP256K1_N,  # curve order
        G,            # generator point (G1 point tuple)
        add,          # point addition
        mul,          # scalar multiplication
        inv,          # modular inverse
    )
    from py_ecc.secp256k1 import curve
except ImportError:
    from py_ecc.secp256k1.secp256k1 import (
        N as SECP256K1_N,
        G,
        add,
        multiply as mul,
        inv,
        P as _SECP256K1_FIELD_PRIME,
    )
    from types import SimpleNamespace
    curve = SimpleNamespace(field_prime=_SECP256K1_FIELD_PRIME)

# R4-dead-code-remove: vrf_verify + _hash_to_curve_secp256k1 deleted (zero
# callers in this module; test_vrf.py covers MCX69 and is untouched).

# ─── BN256 Precompile Helpers ──────────────────────────────────

# ─── BN256 Precompile Helpers ──────────────────────────────────
def _parse_bn256_point(data: bytes):
    """Parse 64-byte (x, y) into a bn256 G1 affine point.

    Returns () for the point at infinity (encoded (0, 0) per EIP-197) and
    None for off-curve/invalid input. py_ecc 8.x uses affine (FQ, FQ)
    tuples with None as infinity; callers map () -> None for library calls
    and reject None outright, so invalid input can never alias infinity.
    EVM-CONFORMANCE: EIP-196/EIP-197 point validation.
    CHANGELOG F-bn256-parse.
    """
    x = int.from_bytes(data[:32], 'big')
    y = int.from_bytes(data[32:64], 'big')
    if x == 0 and y == 0:
        return ()
    try:
        try:
            from py_ecc.bn128 import curve
            p = curve.field_prime
        except ImportError:
            from py_ecc.bn128 import field_modulus as p
        # R6-bn256-range-check: coordinates must be canonical field
        # elements (x, y < p); the old code reduced mod p, accepting
        # non-canonical encodings of on-curve points.
        if x >= p or y >= p:
            return None
        if (x ** 3 + 3) % p == (y ** 2) % p:
            from py_ecc.bn128 import FQ
            return (FQ(x), FQ(y))
    except Exception:
        pass
    return None

def _bn256_field_prime():
    try:
        from py_ecc.bn128 import curve
        return curve.field_prime
    except ImportError:
        from py_ecc.bn128 import field_modulus as p
        return p


def _bn256_g2_canonical(x0: int, x1: int, y0: int, y1: int) -> bool:
    # R8-bn256-g2 (R7-15): all four G2 FQ2 coordinates must be canonical
    # field elements (< p). Verified empirically against py_ecc 8.0.0:
    # FQ2 silently normalizes out-of-range ints (FQ2([p+5, 7]) == (5, 7)),
    # so without this check non-canonical encodings alias valid points.
    # (0,0,0,0) — the point at infinity — passes (all < p).
    # NOTE (py_ecc limitation, documented): FQ12.__pow__ recurses ~3000
    # deep for the pairing final exponentiation, exceeding the default
    # recursion limit — non-empty pairings fail closed (caught) in this
    # environment until the dependency is upgraded. Subgroup membership
    # beyond is_on_curve relies on the library; revisit on upgrade.
    try:
        p = _bn256_field_prime()
    except Exception:
        return False
    try:
        return (0 <= int(x0) < p and 0 <= int(x1) < p
                and 0 <= int(y0) < p and 0 <= int(y1) < p)
    except (TypeError, ValueError):
        return False


def _encode_bn256_point(point) -> bytes:
    """Encode a bn256 G1 point as 64 bytes (x, y)."""
    if point is None or point == (0, 0, 0):
        return b'\x00' * 64
    # F-bn256-parse: int() normalizes both plain ints and py_ecc FQ
    # elements (py_ecc 8.x affine points are (FQ, FQ)).
    x, y = point[0], point[1]
    return int(x).to_bytes(32, 'big') + int(y).to_bytes(32, 'big')


def _normalize_call_address(to):
    """EVM-CONFORMANCE: opcode address operands are 256-bit stack words;
    only the low 160 bits name an account. Normalize int words to the
    '0x'-hex form used for code_cache / balance_cache / repo keys so
    CALL/CALLCODE/DELEGATECALL/STATICCALL with an int target resolve the
    same account as the string form. Strings pass through unchanged.
    CHANGELOG F-calltarget."""
    if isinstance(to, str):
        return to
    try:
        return '0x' + (int(to) & ((1 << 160) - 1)).to_bytes(20, 'big').hex()
    except Exception:
        return to

# ─── VM Execution Engine ────────────────────────────────────
class VMExecutionEngine:
    def __init__(self, repo_provider: Callable):
        self.repo_provider = repo_provider
        self.stack = []
        self.memory = bytearray()
        self.pc = 0
        self.gas = 0
        self.stopped = False
        self.return_data = b''
        # F-opcodes: EIP-211 returndata buffer (last subcall/create output).
        # CHANGELOG F-opcodes.
        self.last_return_data = b''
        self.reverted = False
        self.current_contract = None
        self.storage_address = None
        self.caller = None
        self.origin = None
        self.value = 0
        self.depth = 0
        self.storage_cache = {}
        # VM-3: writes to OTHER addresses during subcalls, keyed by address
        # (only keys the subcall actually wrote). Plus the dirty-key set for
        # this engine's own storage context.
        self.sub_storage: Dict[str, Dict[str, int]] = {}
        self.storage_dirty: Set[str] = set()
        self.logs = []
        self.code = b''
        self.static_call = False
        self.reentrancy_lock = set()
        self.code_cache = {}
        self.balance_cache = {}
        self.token_balance_cache = {}
        self.htlc_repo = None
        self.selfdestruct_beneficiary = None
        self.created_contracts = []
        self.access_list = {}
        self._dex_pools = {}
        self.gas_refund = 0
        self.original_storage = {}
        self.block_height = 0
        self.block_ts = None  # R4-opcodes-add: set via set_block_timestamp

    def _charge_memory_expansion(self, new_size):
        if new_size <= len(self.memory):
            return
        if new_size > MAX_VM_MEMORY:
            # Hard cap: refuse to grow beyond 64 MB regardless of gas
            self.reverted = True
            return
        old_words = (len(self.memory) + 31) // 32
        new_words = (new_size + 31) // 32
        old_cost = old_words * 3 + old_words * old_words // 512
        new_cost = new_words * 3 + new_words * new_words // 512
        expansion_cost = new_cost - old_cost
        if self.gas < expansion_cost:
            self.reverted = True
            return
        self.gas -= expansion_cost
        self.memory.extend(b'\x00' * (new_size - len(self.memory)))

    def execute(self, bytecode: bytes, caller: str, origin: str, value: int,
                gas_limit: int, contract_address: str, input_data: bytes,
                static: bool = False, storage_address: str = None,
                initial_storage: dict = None, shared_context: bool = False,
                call_depth: int = 0) -> Tuple[bool, bytes, int, List[Dict]]:
        self.gas = gas_limit
        self.caller = caller
        self.origin = origin
        self.value = value
        self.current_contract = contract_address
        self.storage_address = storage_address if storage_address is not None else contract_address
        self.stack = []
        self.memory = bytearray()
        self.pc = 0
        self.stopped = False
        self.reverted = False
        self.logs = []
        self.return_data = b''
        # F-opcodes: reset the EIP-211 returndata buffer per frame.
        # CHANGELOG F-opcodes.
        self.last_return_data = b''
        # VM-3: subcalls preload the target's storage via initial_storage;
        # fresh top-level executions start empty.
        self.storage_cache = dict(initial_storage) if initial_storage is not None else {}
        self.sub_storage = {}
        self.storage_dirty = set()
        self.code = bytecode
        self.input_data = input_data or b''
        self.static_call = static
        # R8-depth (R7-12): frame depth arrives as an explicit input, never
        # reset here (was: self.depth = 0, which defeated the 1024 cap the
        # moment a child frame started). Helpers pass call_depth one above
        # their own and refuse entry at 1024 before calling.
        self.depth = call_depth
        self.selfdestruct_beneficiary = None
        self.created_contracts = []
        self.access_list = {}
        self._dex_pools = {}
        self.gas_refund = 0
        # R6-nested-original-storage: original_storage is caller-provided
        # state (like code_cache/balance_cache) and is NOT reset here, so a
        # shared dict survives into child frames for cross-frame EIP-2200.
        # Fresh engines start empty via __init__; engines are single-use.

        # R6-call-context-lock: CALLCODE/DELEGATECALL children run in the
        # CALLER's context (R6-callcode-address/R6-delegatecall-value), so
        # the entry guard must not mistake the shared address for
        # reentry. shared_context frames skip the trip but never release
        # an entry they did not take (else the parent loses its guard on
        # child exit, and nested CALLs to the parent would open mid-frame).
        if self.current_contract in self.reentrancy_lock and not shared_context:
            self.reverted = True
            return False, b'', 0, []
        _lock_owned = self.current_contract not in self.reentrancy_lock
        self.reentrancy_lock.add(self.current_contract)

        try:
            code_len = len(self.code)
            while not self.stopped and self.gas > 0 and self.pc < code_len:
                op = self.code[self.pc]
                self.pc += 1
                # R6-opcode-base-surcharge: no per-iteration base charge; every branch charges its own complete cost.

                # Push (0x60-0x7f)
                if 0x60 <= op <= 0x7f:
                    size = op - 0x5f
                    if self.pc + size > code_len:
                        self.pc = code_len
                        break
                    data = self.code[self.pc:self.pc+size]
                    self.pc += size
                    val = int.from_bytes(data, 'big')
                    self.stack.append(val)
                    self.gas -= GasCost.VERYLOW
                    continue

                # Dup (0x80-0x8f)
                if 0x80 <= op <= 0x8f:
                    n = op - 0x7f
                    if len(self.stack) >= n:
                        self.stack.append(self.stack[-n])
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                    continue

                # Swap (0x90-0x9f)
                if 0x90 <= op <= 0x9f:
                    n = op - 0x8f
                    if len(self.stack) >= n+1:
                        idx = -n-1
                        self.stack[idx], self.stack[-1] = self.stack[-1], self.stack[idx]
                        self.gas -= GasCost.VERYLOW
                    else:
                        self.reverted = True
                        break
                    continue

                # Arithmetic / comparison / bitwise
                if op == Opcode.STOP:
                    self.stopped = True
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.ADD:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        self.stack.append((a + b) & ((1<<256)-1))
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SUB:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: mu_s[0] - mu_s[1] (a is the stack top)
                        self.stack.append((a - b) & ((1<<256)-1))
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.MUL:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        self.stack.append((a * b) & ((1<<256)-1))
                        self.gas -= GasCost.LOW
                    else: self.reverted = True; break
                elif op == Opcode.DIV:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: unsigned mu_s[0] / mu_s[1]
                        self.stack.append(a // b if b != 0 else 0)
                        self.gas -= GasCost.LOW
                    else: self.reverted = True; break
                elif op == Opcode.SDIV:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: signed division truncated toward zero;
                        # quotient is negative iff the signs differ.
                        if b == 0:
                            self.stack.append(0)
                        else:
                            sa, sb = _s256(a), _s256(b)
                            q = abs(sa) // abs(sb)
                            if (sa < 0) != (sb < 0):
                                q = -q
                            self.stack.append(q & ((1<<256)-1))
                        self.gas -= GasCost.LOW
                    else: self.reverted = True; break
                elif op == Opcode.MOD:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: unsigned mu_s[0] % mu_s[1]
                        self.stack.append(a % b if b != 0 else 0)
                        self.gas -= GasCost.LOW
                    else: self.reverted = True; break
                elif op == Opcode.SMOD:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: signed modulo, sign follows the DIVIDEND
                        if b == 0:
                            self.stack.append(0)
                        else:
                            sa, sb = _s256(a), _s256(b)
                            r = abs(sa) % abs(sb)
                            if sa < 0:
                                r = -r
                            self.stack.append(r & ((1<<256)-1))
                        self.gas -= GasCost.LOW
                    else: self.reverted = True; break
                elif op == Opcode.EXP:
                    if len(self.stack) >= 2:
                        base = self.stack.pop(); exponent = self.stack.pop()
                        self.stack.append(pow(base, exponent, 1<<256))
                        # R6-exp-gas-bytes: per BYTE of the exponent (0 -> 0 bytes), not per bit.
                        exp_bytes = (exponent.bit_length() + 7) // 8
                        self.gas -= GasCost.EXP_BYTE * exp_bytes
                    else: self.reverted = True; break
                elif op == Opcode.NEG:
                    if len(self.stack) >= 1:
                        a = self.stack.pop()
                        self.stack.append((-a) & ((1<<256)-1))
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.LT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: unsigned mu_s[0] < mu_s[1]
                        self.stack.append(1 if a < b else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.GT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: unsigned mu_s[0] > mu_s[1]
                        self.stack.append(1 if a > b else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SLT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: signed mu_s[0] < mu_s[1]
                        self.stack.append(1 if _s256(a) < _s256(b) else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SGT:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        # EVM-OPS: signed mu_s[0] > mu_s[1]
                        self.stack.append(1 if _s256(a) > _s256(b) else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.EQ:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        self.stack.append(1 if b == a else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.ISZERO:
                    if len(self.stack) >= 1:
                        a = self.stack.pop()
                        self.stack.append(1 if a == 0 else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.AND:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        self.stack.append(a & b)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.OR:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        self.stack.append(a | b)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.XOR:
                    if len(self.stack) >= 2:
                        a = self.stack.pop(); b = self.stack.pop()
                        self.stack.append(a ^ b)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.NOT:
                    if len(self.stack) >= 1:
                        a = self.stack.pop()
                        self.stack.append((~a) & ((1<<256)-1))
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.BYTE:
                    if len(self.stack) >= 2:
                        idx = self.stack.pop(); val = self.stack.pop()
                        self.stack.append((val >> (8 * (31 - idx))) & 0xff if idx < 32 else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SHL:
                    if len(self.stack) >= 2:
                        shift = self.stack.pop(); val = self.stack.pop()
                        self.stack.append((val << shift) & ((1<<256)-1) if shift < 256 else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SHR:
                    if len(self.stack) >= 2:
                        shift = self.stack.pop(); val = self.stack.pop()
                        self.stack.append(val >> shift if shift < 256 else 0)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SAR:
                    if len(self.stack) >= 2:
                        shift = self.stack.pop(); val = self.stack.pop()
                        # EVM-CONFORMANCE: EIP-145 arithmetic shift.
                        # Sign-extends from bit 255; stack words are unsigned
                        # so the operand must be re-interpreted via _s256.
                        # CHANGELOG F-sar.
                        signed = _s256(val)
                        if shift >= 256:
                            self.stack.append(0 if signed >= 0 else ((1 << 256) - 1))
                        else:
                            self.stack.append((signed >> shift) & ((1 << 256) - 1))
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SIGNEXTEND:
                    if len(self.stack) >= 2:
                        # EVM-CONFORMANCE: yellow-paper SIGNEXTEND. Width byte
                        # b on top, value second: sign-extend bit (8b+7).
                        # b >= 32 leaves the word unchanged.
                        # CHANGELOG F-opcodes.
                        b = self.stack.pop(); x = self.stack.pop()
                        if b < 32:
                            bit = 8 * b + 7
                            if x & (1 << bit):
                                x = x | ((((1 << 256) - 1) ^ ((1 << (bit + 1)) - 1)))
                            else:
                                x = x & ((1 << (bit + 1)) - 1)
                        self.stack.append(x & ((1 << 256) - 1))
                        self.gas -= GasCost.LOW
                    else: self.reverted = True; break
                elif op == Opcode.SHA3:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop(); size = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert; new bytes read as zero.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        data = self.memory[offset:offset+size]
                        hash_val = keccak_256(data)
                        self.stack.append(int.from_bytes(hash_val, 'big'))
                        self.gas -= GasCost.SHA3 + GasCost.SHA3_WORD * ((size + 31) // 32)
                    else: self.reverted = True; break
                elif op == Opcode.POP:
                    if self.stack:
                        self.stack.pop()
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.MLOAD:
                    if len(self.stack) >= 1:
                        offset = self.stack.pop()
                        self._charge_memory_expansion(offset + 32)
                        if self.reverted: break
                        val = int.from_bytes(self.memory[offset:offset+32], 'big')
                        self.stack.append(val)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.MSTORE:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop(); val = self.stack.pop()
                        self._charge_memory_expansion(offset + 32)
                        if self.reverted: break
                        self.memory[offset:offset+32] = val.to_bytes(32, 'big')
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.MSTORE8:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop(); val = self.stack.pop() & 0xff
                        self._charge_memory_expansion(offset + 1)
                        if self.reverted: break
                        self.memory[offset] = val
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.MSIZE:
                    self.stack.append(len(self.memory))
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.SLOAD:
                    if len(self.stack) >= 1:
                        key = self.stack.pop()
                        slot_key = (self.storage_address, key)
                        warm = slot_key in self.access_list
                        if not warm:
                            self.gas -= 2100
                            self.access_list[slot_key] = True
                        else:
                            self.gas -= 100
                        val = self.storage_cache.get(str(key), 0)
                        self.stack.append(val)
                    else: self.reverted = True; break
                elif op == Opcode.SSTORE:
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 2:
                        key = self.stack.pop(); val = self.stack.pop() & ((1<<256)-1)
                        slot_key = (self.storage_address, key)
                        warm = slot_key in self.access_list
                        if not warm:
                            self.gas -= 2100
                            self.access_list[slot_key] = True
                        else:
                            self.gas -= 100
                        current = self.storage_cache.get(str(key), 0)
                        original_key = (self.storage_address, key)
                        original = self.original_storage.get(original_key, current)
                        self.original_storage[original_key] = original
                        # R5-sstore-gas: access cost (2100/100) is charged once. The dynamic branch charges only the write-relevant delta.
                        if val != current:
                            if original == current:
                                if original == 0:
                                    self.gas -= SSTORE_SET
                                else:
                                    self.gas -= SSTORE_RESET
                                    if val == 0:
                                        self.gas_refund += SSTORE_REFUND
                            else:
                                self.gas -= 100
                                if original != 0:
                                    if current == 0:
                                        self.gas_refund = max(0, self.gas_refund - SSTORE_REFUND)
                                    if val == 0:
                                        self.gas_refund += SSTORE_REFUND
                                if val == original:
                                    if original == 0:
                                        self.gas_refund += SSTORE_SET - 2100
                                    else:
                                        self.gas_refund += SSTORE_RESET - 2100
                        self.storage_cache[str(key)] = val
                        self.storage_dirty.add(str(key))
                    else: self.reverted = True; break
                elif op == Opcode.JUMP:
                    if len(self.stack) >= 1:
                        dest = self.stack.pop()
                        if dest < 0 or dest >= code_len or self.code[dest] != 0x5b:
                            self.reverted = True; break
                        self.pc = dest
                        self.gas -= GasCost.MID
                    else: self.reverted = True; break
                elif op == Opcode.JUMPI:
                    if len(self.stack) >= 2:
                        dest = self.stack.pop(); cond = self.stack.pop()
                        if cond != 0:
                            if dest < 0 or dest >= code_len or self.code[dest] != 0x5b:
                                self.reverted = True; break
                            self.pc = dest
                        self.gas -= GasCost.HIGH
                    else: self.reverted = True; break
                elif op == Opcode.JUMPDEST:
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.PC:
                    self.stack.append(self.pc)
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.GAS:
                    self.stack.append(self.gas)
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.GASPRICE:
                    # EVM-CONFORMANCE: yellow paper. Chain gas price is the
                    # configured GAS_PRICE (also served via BASEFEE).
                    # CHANGELOG F-opcodes.
                    self.stack.append(_config.GAS_PRICE)
                    self.gas -= GasCost.BASE
                elif op == Opcode.CHAINID:
                    self.stack.append(CHAIN_ID)
                    self.gas -= GasCost.CHAINID_COST
                elif op == Opcode.ADDRESS:
                    self.stack.append(int(self.current_contract[2:], 16) if isinstance(self.current_contract, str) and self.current_contract.startswith('0x') else 0)
                    self.gas -= GasCost.BASE
                elif op == Opcode.ORIGIN:
                    # EVM-CONFORMANCE: yellow paper (origin of the tx).
                    # CHANGELOG F-opcodes.
                    self.stack.append(int(self.origin[2:], 16) if isinstance(self.origin, str) and self.origin.startswith('0x') else 0)
                    self.gas -= GasCost.BASE
                elif op == Opcode.CALLER:
                    # EVM-CONFORMANCE: yellow paper (immediate caller).
                    # CHANGELOG F-opcodes.
                    self.stack.append(int(self.caller[2:], 16) if isinstance(self.caller, str) and self.caller.startswith('0x') else 0)
                    self.gas -= GasCost.BASE
                elif op == Opcode.BALANCE:
                    if len(self.stack) < 1:
                        self.reverted = True; break
                    # F-balance: low 160 bits name the account (large words
                    # must mask, not OverflowError); fall back to committed
                    # state when the address was never preloaded.
                    # CHANGELOG F-balance.
                    address = _normalize_call_address(self.stack.pop())
                    bal = self.balance_cache.get(address)
                    if bal is None:
                        loaded = self._load_balance_for(address)
                        bal = loaded if loaded is not None else 0
                        self.balance_cache[address] = bal
                    self.stack.append(bal)
                    self.gas -= GasCost.BALANCE
                elif op == Opcode.CALLVALUE:
                    self.stack.append(self.value)
                    self.gas -= GasCost.CALLVALUE_COST
                elif op == Opcode.CALLDATASIZE:
                    self.stack.append(len(self.input_data))
                    self.gas -= GasCost.CALLDATA
                elif op == Opcode.CALLDATALOAD:
                    if len(self.stack) < 1:
                        self.reverted = True; break
                    offset = self.stack.pop()
                    data = self.input_data[offset:offset + 32].ljust(32, b'\x00')
                    self.stack.append(int.from_bytes(data, 'big'))
                    self.gas -= GasCost.CALLDATA
                elif op in (Opcode.CALLDATACOPY, Opcode.CODECOPY, Opcode.EXTCODECOPY):
                    needed = 3 if op != Opcode.EXTCODECOPY else 4
                    if len(self.stack) < needed:
                        self.reverted = True; break
                    # EVM-OPS: yellow-paper pop order — top first:
                    # CALLDATACOPY/CODECOPY: destOffset, offset, size
                    # EXTCODECOPY:           address, destOffset, offset, size
                    if op == Opcode.EXTCODECOPY:
                        address_value = self.stack.pop()
                        memory_offset = self.stack.pop()
                        code_offset = self.stack.pop()
                        copy_size = self.stack.pop()
                        # F-extcode-fallback: same committed-state fallback.
                        # CHANGELOG F-extcode-fallback.
                        source = self._load_code_for(
                            _normalize_call_address(address_value)) or b''
                    else:
                        memory_offset = self.stack.pop()
                        code_offset = self.stack.pop()
                        copy_size = self.stack.pop()
                        source = self.input_data if op == Opcode.CALLDATACOPY else self.code
                    if memory_offset + copy_size > len(self.memory):
                        self._charge_memory_expansion(memory_offset + copy_size)
                        if self.reverted: break
                    self.memory[memory_offset:memory_offset + copy_size] = source[code_offset:code_offset + copy_size].ljust(copy_size, b'\x00')
                    self.gas -= GasCost.COPY * ((copy_size + 31) // 32)
                elif op == Opcode.RETURNDATASIZE:
                    # EVM-CONFORMANCE: EIP-211. Length of the last subcall's
                    # return data (buffer updated by every CALL-family and
                    # CREATE-family handler). CHANGELOG F-opcodes.
                    self.stack.append(len(self.last_return_data))
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.RETURNDATACOPY:
                    if len(self.stack) >= 3:
                        # EVM-CONFORMANCE: EIP-211. Out-of-bounds reads
                        # revert; zero-padded only within bounds.
                        # CHANGELOG F-opcodes.
                        memory_offset = self.stack.pop()
                        data_offset = self.stack.pop()
                        copy_size = self.stack.pop()
                        if data_offset + copy_size > len(self.last_return_data):
                            self.reverted = True; break
                        if memory_offset + copy_size > len(self.memory):
                            self._charge_memory_expansion(memory_offset + copy_size)
                            if self.reverted: break
                        self.memory[memory_offset:memory_offset + copy_size] = self.last_return_data[data_offset:data_offset + copy_size]
                        self.gas -= GasCost.VERYLOW + GasCost.COPY * ((copy_size + 31) // 32)
                    else: self.reverted = True; break
                elif op == Opcode.CODESIZE:
                    self.stack.append(len(self.code))
                    self.gas -= GasCost.BASE
                elif op == Opcode.EXTCODESIZE:
                    if len(self.stack) < 1:
                        self.reverted = True; break
                    # F-extcode-fallback: committed-state fallback via
                    # _load_code_for (was frame-cache-only, so deployed
                    # contracts read as size 0). CHANGELOG F-extcode-fallback.
                    address = _normalize_call_address(self.stack.pop())
                    code = self._load_code_for(address)
                    self.stack.append(len(code) if code is not None else 0)
                    self.gas -= GasCost.EXTCODE
                elif op == Opcode.SELFBALANCE:
                    # EVM-CONFORMANCE: SELFBALANCE (EIP-1884) is read-only;
                    # allowed in static context (EIP-214 bans only state
                    # mutators). CHANGELOG F-selfbalance.
                    # SELFBALANCE-FALLBACK-1: mirror BALANCE — fall back to
                    # committed state when the contract was never preloaded
                    # into balance_cache (previously read as 0).
                    bal = self.balance_cache.get(self.current_contract)
                    if bal is None:
                        loaded = self._load_balance_for(self.current_contract)
                        bal = loaded if loaded is not None else 0
                        self.balance_cache[self.current_contract] = bal
                    self.stack.append(bal)
                    self.gas -= GasCost.SELFBALANCE_COST
                elif op == Opcode.BASEFEE:
                    self.stack.append(_config.GAS_PRICE)
                    self.gas -= GasCost.BASEFEE_COST
                elif op == Opcode.TIMESTAMP:
                    # R4-opcodes-add: execution-context timestamp, threaded
                    # from the sealed block (produce + replay agree); 0 when
                    # unset (deterministic, never wall-clock here).
                    self.stack.append(int(self.block_ts) if self.block_ts is not None else 0)
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.NUMBER:
                    # R4-opcodes-add: current block height.
                    self.stack.append(int(self.block_height or 0))
                    self.gas -= GasCost.VERYLOW
                elif op == Opcode.BLOCKHASH:
                    if len(self.stack) >= 1:
                        # R4-opcodes-add: sealed ancestor hash in
                        # [height-256, height-1]; 0 otherwise (future,
                        # current, too-old, or unavailable).
                        _bn = self.stack.pop()
                        _bh = 0
                        try:
                            _bn_i = int(_bn)
                        except (TypeError, ValueError):
                            _bn_i = -1
                        if 0 <= _bn_i <= int(self.block_height or 0) - 1 and _bn_i >= int(self.block_height or 0) - 256:
                            _bh = self._load_block_hash_for(_bn_i)
                        self.stack.append(_bh)
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.EXTCODEHASH:
                    if len(self.stack) >= 1:
                        # EVM-CONFORMANCE: EIP-1052. keccak256 of the
                        # account's code, or keccak256(b"") for EOAs / empty
                        # accounts. Code loads via _load_code_for (committed
                        # contract_v2), not just the frame cache.
                        # CHANGELOG F-extcodehash.
                        addr = _normalize_call_address(self.stack.pop())
                        code = self._load_code_for(addr) or b''
                        self.stack.append(int.from_bytes(eth_keccak(code), 'big'))
                        self.gas -= GasCost.EXTCODEHASH_COST
                    else: self.reverted = True; break
                elif op == Opcode.LOG0:
                    # EVM-CONFORMANCE: EIP-214 — LOG* emits state (receipts);
                    # forbidden in static context. CHANGELOG F-log-static.
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 2:
                        offset = self.stack.pop(); size = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        data = self.memory[offset:offset+size]
                        self.logs.append({"address": self.current_contract, "topics": [], "data": data.hex()})
                        self.gas -= GasCost.LOG + GasCost.LOGDATA * size
                    else: self.reverted = True; break
                elif op == Opcode.LOG1:
                    # EVM-CONFORMANCE: EIP-214. CHANGELOG F-log-static.
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 3:
                        offset = self.stack.pop(); size = self.stack.pop(); topic = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        data = self.memory[offset:offset+size]
                        self.logs.append({"address": self.current_contract, "topics": [topic], "data": data.hex()})
                        self.gas -= GasCost.LOG + GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else: self.reverted = True; break
                elif op == Opcode.LOG2:
                    # EVM-CONFORMANCE: EIP-214. CHANGELOG F-log-static.
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 4:
                        offset = self.stack.pop(); size = self.stack.pop()
                        t1 = self.stack.pop(); t2 = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        data = self.memory[offset:offset+size]
                        self.logs.append({"address": self.current_contract, "topics": [t1, t2], "data": data.hex()})
                        self.gas -= GasCost.LOG + 2*GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else: self.reverted = True; break
                elif op == Opcode.LOG3:
                    # EVM-CONFORMANCE: EIP-214. CHANGELOG F-log-static.
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 5:
                        offset = self.stack.pop(); size = self.stack.pop()
                        t1 = self.stack.pop(); t2 = self.stack.pop(); t3 = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        data = self.memory[offset:offset+size]
                        self.logs.append({"address": self.current_contract, "topics": [t1, t2, t3], "data": data.hex()})
                        self.gas -= GasCost.LOG + 3*GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else: self.reverted = True; break
                elif op == Opcode.LOG4:
                    # EVM-CONFORMANCE: EIP-214. CHANGELOG F-log-static.
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 6:
                        offset = self.stack.pop(); size = self.stack.pop()
                        t1 = self.stack.pop(); t2 = self.stack.pop(); t3 = self.stack.pop(); t4 = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        data = self.memory[offset:offset+size]
                        self.logs.append({"address": self.current_contract, "topics": [t1, t2, t3, t4], "data": data.hex()})
                        self.gas -= GasCost.LOG + 4*GasCost.LOGTOPIC + GasCost.LOGDATA * size
                    else: self.reverted = True; break
                elif op == Opcode.CALL:
                    if len(self.stack) >= 7:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        val = self.stack.pop()
                        in_off = self.stack.pop(); in_sz = self.stack.pop()
                        out_off = self.stack.pop(); out_sz = self.stack.pop()
                        if self.static_call and val != 0:
                            self.reverted = True; break
                        # R6-call-gas-dynamic: value-transfer (9000) and new-account (25000) surcharges.
                        # New-account approximation: no code and no balance (revived-account nuances out of scope).
                        if val != 0:
                            self.gas -= 9000  # CALLVALUE
                            _to_norm = _normalize_call_address(to)
                            if not self._has_deployed_code(_to_norm, _to_norm.lower()) and not self._has_balance_for(_to_norm):
                                self.gas -= GasCost.NEWACCOUNT
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted: break
                        input_data = self.memory[in_off:in_off+in_sz]
                        if to in self.reentrancy_lock:
                            self.stack.append(0)
                            self.gas -= GasCost.CALL
                            continue
                        success, ret = self._call_contract(to, val, input_data, gas, self.current_contract)
                        # F-opcodes: EIP-211 returndata buffer (set on
                        # success AND failure). CHANGELOG F-opcodes.
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted: break
                                self.memory[out_off:out_off+out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else: self.reverted = True; break
                elif op == Opcode.CALLCODE:
                    if len(self.stack) >= 7:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        val = self.stack.pop()
                        in_off = self.stack.pop(); in_sz = self.stack.pop()
                        out_off = self.stack.pop(); out_sz = self.stack.pop()
                        if self.static_call and val != 0:
                            self.reverted = True; break
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted: break
                        input_data = self.memory[in_off:in_off+in_sz]
                        success, ret = self._callcode_contract(to, val, input_data, gas, self.caller)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted: break
                                self.memory[out_off:out_off+out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else: self.reverted = True; break
                elif op == Opcode.DELEGATECALL:
                    if len(self.stack) >= 6:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        in_off = self.stack.pop(); in_sz = self.stack.pop()
                        out_off = self.stack.pop(); out_sz = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted: break
                        input_data = self.memory[in_off:in_off+in_sz]
                        success, ret = self._delegate_call(to, input_data, gas)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted: break
                                self.memory[out_off:out_off+out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else: self.reverted = True; break
                elif op == Opcode.STATICCALL:
                    if len(self.stack) >= 6:
                        gas = self.stack.pop()
                        to = self.stack.pop()
                        in_off = self.stack.pop(); in_sz = self.stack.pop()
                        out_off = self.stack.pop(); out_sz = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't revert.
                        self._charge_memory_expansion(in_off + in_sz)
                        if self.reverted: break
                        input_data = self.memory[in_off:in_off+in_sz]
                        success, ret = self._static_call(to, input_data, gas)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            if out_sz > 0:
                                self._charge_memory_expansion(out_off + out_sz)
                                if self.reverted: break
                                self.memory[out_off:out_off+out_sz] = ret[:out_sz]
                            self.stack.append(1)
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CALL
                    else: self.reverted = True; break
                elif op == Opcode.CREATE:
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 3:
                        value = self.stack.pop()
                        offset = self.stack.pop(); size = self.stack.pop()
                        # R8-create-expand (R7-16): init-code reads expand
                        # like every other memory op (was: revert when the
                        # range exceeded touched memory).
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        init_code = self.memory[offset:offset+size]
                        nonce = self.storage_cache.get(f"nonce_{self.current_contract}", 0)
                        new_addr = self._compute_create_address(self.current_contract, nonce)
                        # CREATE-NONCE: advance the creator nonce per attempt
                        # (EVM semantics) — without this the next CREATE from
                        # the same contract recomputes the same address and
                        # fails the code_cache collision check. Committed only
                        # when this frame succeeds (storage commit on success).
                        self._increment_nonce(self.current_contract)
                        success, addr, ret = self._create_contract(new_addr, init_code, value)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            self.stack.append(int(addr, 16))
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CREATE
                    else: self.reverted = True; break
                elif op == Opcode.CREATE2:
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 4:
                        value = self.stack.pop()
                        offset = self.stack.pop(); size = self.stack.pop()
                        salt = self.stack.pop()
                        # R8-create-expand (R7-16): same expansion rule as CREATE.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        init_code = self.memory[offset:offset+size]
                        new_addr = self._compute_create2_address(self.current_contract, salt, init_code)
                        # CREATE-NONCE: CREATE2 addresses are salt-based but
                        # EVM still bumps the creator nonce on each attempt.
                        self._increment_nonce(self.current_contract)
                        success, addr, ret = self._create_contract(new_addr, init_code, value)
                        self.last_return_data = bytes(ret or b'')
                        if success:
                            self.stack.append(int(addr, 16))
                        else:
                            self.stack.append(0)
                        self.gas -= GasCost.CREATE2
                    else: self.reverted = True; break
                elif op == Opcode.RETURN:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop(); size = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't truncate.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        self.return_data = self.memory[offset:offset+size]
                        self.stopped = True
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.REVERT:
                    if len(self.stack) >= 2:
                        offset = self.stack.pop(); size = self.stack.pop()
                        # R6-memory-expand-reads: grow (charging expansion), don't truncate.
                        self._charge_memory_expansion(offset + size)
                        if self.reverted: break
                        self.return_data = self.memory[offset:offset+size]
                        self.reverted = True
                        self.stopped = True
                        self.gas -= GasCost.VERYLOW
                    else: self.reverted = True; break
                elif op == Opcode.SELFDESTRUCT:
                    if self.static_call:
                        self.reverted = True; break
                    if len(self.stack) >= 1:
                        # F-selfdestruct-key: the stack word must be
                        # normalized to an address string. The raw int was
                        # used as a balance_cache key, so the flushed wallet
                        # row carried a non-address key (funds unreachable via
                        # BalanceRepo.get). CHANGELOG F-selfdestruct-key.
                        beneficiary = _normalize_call_address(self.stack.pop())
                        balance = self.balance_cache.get(self.current_contract, 0)
                        if beneficiary != self.current_contract:
                            self.balance_cache[beneficiary] = self.balance_cache.get(beneficiary, 0) + balance
                            self.balance_cache[self.current_contract] = 0
                        self.selfdestruct_beneficiary = beneficiary
                        self.stopped = True
                        self.gas -= GasCost.SELFDESTRUCT_COST
                    else:
                        self.reverted = True; break
                else:
                    self.reverted = True; break

            # R8-gas-halt (R7-02/R7-13): exit-path gas discipline.
            # R8-halt-gas (R7-13): exceptional halts — reverted WITHOUT
            # stopped (invalid opcode, stack errors, ...) — and any exit
            # with a negative balance burn the FULL budget. Only explicit
            # REVERT (reverted WITH stopped) is charged for gas spent.
            # (Supersedes R4-oog-detect's spent-only accounting: R4 pinned
            # ok=False, which still holds; the gas number now burns all.)
            if self.gas < 0 or (self.reverted and not self.stopped):
                self.reverted = True
                return False, self.return_data, gas_limit, self.logs
            if self.reverted:
                return False, self.return_data, gas_limit - self.gas, self.logs
            # R8-gas-zero-halt (R7-02): falling off the loop with bytecode
            # left and no halt is out-of-gas, never success (was: gas == 0
            # reported success with the tail skipped). Ran-off-the-end
            # (pc >= code_len) stays an implicit halt = success.
            if not self.stopped and self.pc < code_len:
                self.reverted = True
                return False, self.return_data, gas_limit, self.logs
            gas_used = gas_limit - self.gas
            # R4-sstore-redesign: EIP-3529 caps total refunds at a fifth
            # of gas used (was a half).
            refund = min(self.gas_refund, gas_used // 5)
            gas_used -= refund
            return True, self.return_data, gas_used, self.logs

        except Exception as e:
            logger.error(f"[VM] Execution error: {e}", exc_info=True)
            # R9-except-gas (I-R8-10): a host-interpreter crash is an
            # exceptional halt — burn the FULL budget like any other
            # non-REVERT failure (was: refund of remaining gas). Callers
            # discard child effects on False, so no state commits either.
            return False, b'', gas_limit, []
        finally:
            if _lock_owned:
                self.reentrancy_lock.discard(self.current_contract)

    def _load_storage_for(self, address: str) -> dict:
        """VM-3: synchronously load an address's committed contract storage.

        Used to preload a subcall target's storage (the caller's flat cache
        only holds the parent's own storage context). Returns {} on any
        failure so execution degrades to empty storage rather than crashing."""
        if not address:
            return {}
        try:
            db = self.repo_provider() if self.repo_provider else None
            if db is None:
                return {}
            ph = "?" if str(getattr(db, "db_url", "sqlite://")).startswith("sqlite") else "%s"
            cur = db.execute(
                f"SELECT key, value FROM contract_storage_v2 WHERE contract_address = {ph}",
                address)
            rows = cur.fetchall()
            out = {}
            for row in rows or []:
                if isinstance(row, dict):
                    k, v = row.get("key"), row.get("value")
                else:
                    k, v = row[0], row[1]
                try:
                    out[str(k)] = int(v)
                except (TypeError, ValueError):
                    continue
            return out
        except Exception:
            return {}

    def _load_balance_for(self, address: str):
        """F-balance: synchronously load an address's committed MCX balance.

        Mirrors BalanceRepo.get over the frame's repo_provider so BALANCE of
        an address outside the preloaded {caller, origin, contract} triple
        returns the committed value instead of 0. Returns None when no
        provider/row is available (caller keeps the 0 default).
        CHANGELOG F-balance."""
        if not address:
            return None
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return None
            cur = sync_db.execute("SELECT bal FROM balances WHERE wallet = ?", address)
            row = cur.fetchone()
            if row is None:
                return 0
            try:
                return row["bal"]
            except (TypeError, KeyError, IndexError):
                return row[0]
        except Exception:
            return None

    def _load_code_for(self, address: str):
        """F-extcodehash: synchronously load an address's committed runtime
        bytecode (contract_v2), filling the frame's code_cache exactly like
        _call_contract. Returns None when absent/unavailable.
        CHANGELOG F-extcodehash."""
        if not address:
            return None
        if address in self.code_cache:
            return self.code_cache[address]
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return None
            cur = sync_db.execute("SELECT bytecode FROM contract_v2 WHERE address = ?", address)
            row = cur.fetchone()
            if row:
                bytecode = bytes.fromhex(row[0])
                self.code_cache[address] = bytecode
                return bytecode
            return None
        except Exception:
            return None

    def _load_block_hash_for(self, block_id: int) -> int:
        """R4-opcodes-add: sealed block hash as int for BLOCKHASH; 0 when
        the row is absent/unavailable (total function, deterministic)."""
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return 0
            cur = sync_db.execute("SELECT hash FROM blocks WHERE id = ?", int(block_id))
            row = cur.fetchone()
            if not row:
                return 0
            try:
                _h = row["hash"]
            except (TypeError, KeyError, IndexError):
                _h = row[0]
            return int(str(_h).removeprefix("0x"), 16)
        except Exception:
            return 0

    def _absorb_child_storage(self, child) -> None:
        """VM-3 / REVERT-1: route a SUCCESSFUL child's storage effects.

        Same storage context -> merge into this engine's cache; other
        address -> keep a per-address bucket in sub_storage (dirty keys
        only). Grandchild buckets propagate up. Callers must only invoke
        this after a successful (non-reverted) child."""
        if child.storage_address == self.storage_address:
            self.storage_cache.update(child.storage_cache)
            self.storage_dirty |= child.storage_dirty
        else:
            bucket = self.sub_storage.setdefault(child.storage_address, {})
            for k in child.storage_dirty:
                bucket[k] = child.storage_cache.get(k, 0)
        for addr, slots in getattr(child, "sub_storage", {}).items():
            if addr == self.storage_address:
                self.storage_cache.update(slots)
                self.storage_dirty |= set(slots)
            else:
                self.sub_storage.setdefault(addr, {}).update(slots)

    def _storage_load(self, key: int) -> int:
        return self.storage_cache.get(str(key), 0)

    def _storage_store(self, key: int, value: int):
        self.storage_cache[str(key)] = value & ((1<<256)-1)
        self.storage_dirty.add(str(key))

    def set_block_height(self, h: int) -> None:
        self.block_height = int(h)

    def set_block_timestamp(self, ts) -> None:
        """R4-opcodes-add: execution-context timestamp for TIMESTAMP."""
        try:
            self.block_ts = float(ts) if ts is not None else None
        except (TypeError, ValueError):
            self.block_ts = None

    def _get_nonce(self, address: str) -> int:
        return self.storage_cache.get(f"nonce_{address}", 0)

    def _increment_nonce(self, address: str) -> int:
        nonce = self._get_nonce(address) + 1
        self.storage_cache[f"nonce_{address}"] = nonce
        self.storage_dirty.add(f"nonce_{address}")
        return nonce

    def _compute_create_address(self, sender: str, nonce: int) -> str:
        return compute_contract_address(sender, nonce)

    def _compute_create2_address(self, sender: str, salt: int, init_code: bytes) -> str:
        # EVM-CONFORMANCE: EIP-1014.
        #   address = keccak256(0xff ++ deployer ++ salt ++ keccak256(init_code))[12:]
        # Two prior bugs fixed here: (1) NIST SHA3-256 was used instead of
        # keccak; (2) the FIRST 20 bytes of the digest were taken instead of
        # the LAST 20 ([-20:], i.e. hash[12:]). Consistent with
        # compute_contract_address (CREATE), which uses eth_keccak(...)[-20:].
        # CHANGELOG F-create2.
        prefix = b'\xff'
        sender_bytes = bytes.fromhex(sender[2:])
        salt_bytes = salt.to_bytes(32, 'big')
        init_hash = eth_keccak(init_code)
        data = prefix + sender_bytes + salt_bytes + init_hash
        return '0x' + eth_keccak(data)[-20:].hex()

    def _create_contract(self, address: str, init_code: bytes, value: int) -> Tuple[bool, str, bytes]:
        # R8-depth (R7-12): CREATE frames count toward EIP-1024 like any
        # message call (was: no guard at all).
        if self.depth + 1 >= 1024:
            return False, address, b''
        if address in self.code_cache:
            return False, address, b''
        # VALUE-1: parent-side value transfer before the constructor runs.
        # R4-value-origin: debit the EXECUTING contract (current_contract),
        # not the EOA caller — CREATE value comes from the creator. Failure
        # paths below restore current_contract accordingly.
        saved_creator = self.balance_cache.get(self.current_contract, 0)
        saved_new = self.balance_cache.get(address, 0)
        if value > 0:
            if saved_creator < value:
                return False, address, b''
            self.balance_cache[self.current_contract] = saved_creator - value
            self.balance_cache[address] = saved_new + value
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.block_height = self.block_height
        child.block_ts = self.block_ts  # R5-nested-block-ts: TIMESTAMP must be consistent across frames.
        child.original_storage = self.original_storage  # R6-nested-original-storage: share for cross-frame EIP-2200.
        # R6-create-caller: the constructor's CALLER is the creating
        # contract, not the EOA (value/address were already correct).
        success, ret, gas_used, logs = child.execute(init_code, caller=self.current_contract, origin=self.origin,
                                                     value=value, gas_limit=self.gas, contract_address=address,
                                                     input_data=b'', static=False, storage_address=address,
                                                     call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and not child.reverted:
            deployed_code = ret if ret else init_code
            if len(deployed_code) > _config.MAX_BYTECODE:
                # EIP-170 style: reject oversized runtime code, refund value
                if value > 0:
                    self.balance_cache[self.current_contract] = saved_creator
                    self.balance_cache[address] = saved_new
                logger.debug(f"[VM] CREATE rejected: runtime size {len(deployed_code)} > MAX_BYTECODE {_config.MAX_BYTECODE}")
                return False, address, b''
            # REVERT-1 / VM-3: commit constructor effects only on success
            # (storage, balances, logs) — the constructor's SSTOREs land in
            # sub_storage under the NEW contract address.
            self.balance_cache.update(child.balance_cache)
            self.logs.extend(child.logs)
            self._absorb_child_storage(child)
            self.code_cache[address] = deployed_code
            self.created_contracts.append((address, deployed_code))
            return True, address, ret
        else:
            if value > 0:
                self.balance_cache[address] = saved_new
                self.balance_cache[self.current_contract] = saved_creator
            return False, address, ret

    def _has_balance_for(self, to: str) -> bool:
        # R6-call-gas-dynamic: balance probe mirroring _has_deployed_code (cache then DB). Read-only.
        try:
            if isinstance(to, str) and self.balance_cache.get(to, 0) > 0:
                return True
            sync_db = self.repo_provider()
            if sync_db is None:
                return False
            cur = sync_db.execute("SELECT bal FROM balances WHERE wallet = ?", to)
            row = cur.fetchone()
            if row is None:
                return False
            try:
                return int(row["bal"]) > 0
            except (TypeError, KeyError, IndexError):
                return int(row[0]) > 0
        except Exception:
            return False

    def _has_deployed_code(self, to: str, to_lower: str) -> bool:
        # C-1 (MCX73) helper: normalized deployed-code probe (cache, either
        # case, then DB, either case). Read-only.
        if to in self.code_cache or to_lower in self.code_cache:
            return True
        try:
            sync_db = self.repo_provider()
            if sync_db is None:
                return False
            for _addr in (to, to_lower):
                try:
                    cur = sync_db.execute("SELECT 1 FROM contract_v2 WHERE address = ?", _addr)
                    if cur.fetchone() is not None:
                        return True
                except Exception:
                    continue
        except Exception:
            pass
        return False

    def _call_contract(self, to: str, value: int, input_data: bytes, gas: int, caller: str) -> Tuple[bool, bytes]:
        # R4-call-gas-clamp: EIP-150 63/64 + EIP-1024 depth cap, before any
        # child runs so a runaway callee cannot spend the parent negative.
        if self.depth + 1 >= 1024:
            return False, b''
        gas = min(gas, max(0, self.gas - self.gas // 64))
        # F-calltarget: normalize int stack-word targets (see helper).
        to = _normalize_call_address(to)
        to_lower = to.lower()
        # C-1 (MCX73): deployed contracts take precedence over precompiles.
        # A contract deployed at a precompile address (adversarial or not)
        # must execute its own code — the old order shadowed it. Precompile
        # addresses are reserved by convention; this ordering is defensive.
        # Behavior is otherwise unchanged: with nothing deployed, precompiles
        # resolve exactly as before.
        if to_lower in PRECOMPILED and not self._has_deployed_code(to, to_lower):
            # R6-precompile-gas: precompiles report their cost via the
            # cell; success deducts the cost, any failure (bad input or
            # over budget) burns the whole forwarded budget (was: free).
            cell: List[int] = []
            ok, ret = self._execute_precompiled(to, input_data, value, gas, caller, cell)
            if ok and cell:
                self.gas -= cell[0]
            else:
                self.gas -= gas
            return ok, ret
        if to in self.reentrancy_lock:
            return False, b''
        if to in self.code_cache:
            bytecode = self.code_cache[to]
        else:
            sync_db = self.repo_provider()
            if sync_db is None:
                return False, b''
            try:
                cur = sync_db.execute("SELECT bytecode FROM contract_v2 WHERE address = ?", to)
                row = cur.fetchone()
                if row:
                    bytecode = row[0]
                    self.code_cache[to] = bytes.fromhex(bytecode)
                else:
                    return False, b''
            except Exception:
                return False, b''
        # VALUE-1: parent-side value transfer BEFORE the child runs, so the
        # child sees funded balances; rolled back if the child fails.
        saved_caller = self.balance_cache.get(caller, 0)
        saved_to = self.balance_cache.get(to, 0)
        if value > 0:
            if saved_caller < value:
                return False, b''
            self.balance_cache[caller] = saved_caller - value
            self.balance_cache[to] = saved_to + value
        # VM-3: the child runs against the TARGET's committed storage
        # (isolated copy); same-context calls keep this frame's cache.
        if self.storage_address is not None and to.lower() == str(self.storage_address).lower():
            initial_storage = dict(self.storage_cache)
        else:
            initial_storage = self._load_storage_for(to)
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.access_list = self.access_list
        child._dex_pools = self._dex_pools
        child.block_height = self.block_height
        child.block_ts = self.block_ts  # R5-nested-block-ts: TIMESTAMP must be consistent across frames.
        child.original_storage = self.original_storage  # R6-nested-original-storage: share for cross-frame EIP-2200.
        success, ret, gas_used, logs = child.execute(bytecode, caller=caller, origin=self.origin,
                                                     value=value, gas_limit=gas, contract_address=to,
                                                     input_data=input_data, static=self.static_call,
                                                     initial_storage=initial_storage,
                                                     call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and not child.reverted:
            # REVERT-1 / VM-3: commit child effects only on success
            self.logs.extend(child.logs)
            self.balance_cache.update(child.balance_cache)
            self._absorb_child_storage(child)
            return True, ret
        # failure: roll back the value transfer, discard child state
        if value > 0:
            self.balance_cache[caller] = saved_caller
            self.balance_cache[to] = saved_to
        return False, ret

    def _callcode_contract(self, to: str, value: int, input_data: bytes, gas: int, caller: str) -> Tuple[bool, bytes]:
        # EVM-CONFORMANCE: mirror _call_contract — fall back to the committed
        # contract_v2 row when the target is not in the frame's code cache.
        # Previously CALLCODE to any not-yet-cached contract unconditionally
        # failed. CHANGELOG F-callcode.
        to = _normalize_call_address(to)
        # R4-call-gas-clamp: EIP-150 63/64 + EIP-1024 depth cap.
        if self.depth + 1 >= 1024:
            return False, b''
        gas = min(gas, max(0, self.gas - self.gas // 64))
        if to in self.code_cache:
            bytecode = self.code_cache[to]
        else:
            sync_db = self.repo_provider()
            if sync_db is None:
                return False, b''
            try:
                cur = sync_db.execute("SELECT bytecode FROM contract_v2 WHERE address = ?", to)
                row = cur.fetchone()
                if row:
                    bytecode = bytes.fromhex(row[0])
                    self.code_cache[to] = bytecode
                else:
                    return False, b''
            except Exception:
                return False, b''
        # R4-value-origin: CALLCODE moves NO balance. Real CALLCODE runs the
        # callee's code in the caller's storage context with the caller's
        # CALLVALUE (passed to the child below); the old parent-side transfer
        # is deleted, not rolled back.
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.access_list = self.access_list
        child._dex_pools = self._dex_pools
        child.block_height = self.block_height
        child.block_ts = self.block_ts  # R5-nested-block-ts: TIMESTAMP must be consistent across frames.
        child.original_storage = self.original_storage  # R6-nested-original-storage: share for cross-frame EIP-2200.
        # VM-3: CALLCODE runs foreign code in THIS frame's storage context;
        # nested frames inherit the parent's storage_address (was
        # current_contract, which broke nested delegate/callcode chains).
        # R6-callcode-address: run the code at the CALLER's address
        # (ADDRESS must report this frame's contract, not the code owner;
        # caller/value were already correct).
        # R6-call-context-lock: shared-context frame (see execute()).
        success, ret, gas_used, logs = child.execute(bytecode, caller=self.caller, origin=self.origin,
                                                     value=value, gas_limit=gas, contract_address=self.current_contract,
                                                     input_data=input_data, static=self.static_call,
                                                     storage_address=self.storage_address,
                                                     initial_storage=dict(self.storage_cache),
                                                     shared_context=True,
                                                     call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and not child.reverted:
            self.logs.extend(child.logs)
            self.balance_cache.update(child.balance_cache)
            self._absorb_child_storage(child)
            return True, ret
        return False, ret

    def _delegate_call(self, to: str, input_data: bytes, gas: int) -> Tuple[bool, bytes]:
        # EVM-CONFORMANCE: same contract_v2 fallback as _call_contract /
        # _callcode_contract (F-callcode extension: DELEGATECALL had the
        # identical cache-only failure mode). CHANGELOG F-callcode.
        to = _normalize_call_address(to)
        # R4-call-gas-clamp: EIP-150 63/64 + EIP-1024 depth cap.
        if self.depth + 1 >= 1024:
            return False, b''
        gas = min(gas, max(0, self.gas - self.gas // 64))
        if to in self.code_cache:
            bytecode = self.code_cache[to]
        else:
            sync_db = self.repo_provider()
            if sync_db is None:
                return False, b''
            try:
                cur = sync_db.execute("SELECT bytecode FROM contract_v2 WHERE address = ?", to)
                row = cur.fetchone()
                if row:
                    bytecode = bytes.fromhex(row[0])
                    self.code_cache[to] = bytecode
                else:
                    return False, b''
            except Exception:
                return False, b''
        child = VMExecutionEngine(self.repo_provider)
        child.code_cache = self.code_cache
        child.reentrancy_lock = self.reentrancy_lock
        child.balance_cache = dict(self.balance_cache)
        child.token_balance_cache = self.token_balance_cache
        child.htlc_repo = self.htlc_repo
        child.access_list = self.access_list
        child._dex_pools = self._dex_pools
        child.block_height = self.block_height
        child.block_ts = self.block_ts  # R5-nested-block-ts: TIMESTAMP must be consistent across frames.
        child.original_storage = self.original_storage  # R6-nested-original-storage: share for cross-frame EIP-2200.
        # VM-3: DELEGATECALL inherits this frame's storage context and value;
        # nested frames must inherit storage_address (not current_contract).
        # R6-delegatecall-value: inherit value AND executing address
        # (ADDRESS/CALLVALUE must report the caller's context, not the
        # callee's; caller/storage_address were already correct).
        # R6-call-context-lock: shared-context frame (see execute()).
        success, ret, gas_used, logs = child.execute(bytecode, caller=self.caller, origin=self.origin,
                                                     value=self.value, gas_limit=gas, contract_address=self.current_contract,
                                                     input_data=input_data, static=self.static_call,
                                                     storage_address=self.storage_address,
                                                     initial_storage=dict(self.storage_cache),
                                                     shared_context=True,
                                                     call_depth=self.depth + 1)
        self.gas -= gas_used
        if success and not child.reverted:
            self.logs.extend(child.logs)
            self.balance_cache.update(child.balance_cache)
            self._absorb_child_storage(child)
            return True, ret
        return False, ret

    def _static_call(self, to: str, input_data: bytes, gas: int) -> Tuple[bool, bytes]:
        # R4-call-gas-clamp: EIP-150 63/64 + EIP-1024 depth cap (the
        # delegated _call_contract clamps again idempotently).
        if self.depth + 1 >= 1024:
            return False, b''
        gas = min(gas, max(0, self.gas - self.gas // 64))
        # EVM-CONFORMANCE: EIP-214. The callee must run with static=True, or
        # every SSTORE/CREATE/LOG guard in the child frame reads False and
        # STATICCALL silently permits state mutation. The flag is restored
        # afterwards so the caller's own context is unchanged.
        # CHANGELOG F-static-propagate.
        prev = self.static_call
        self.static_call = True
        try:
            return self._call_contract(to, 0, input_data, gas, self.caller)
        finally:
            self.static_call = prev

    def _execute_precompiled(self, address: str, input_data: bytes, value: int, gas: int, caller: str, gas_cost_out=None) -> Tuple[bool, bytes]:
        addr_lower = address.lower()
        activation = PRECOMPILED_VERSIONS.get(addr_lower)
        if activation is None:
            return False, b''
        if activation > self.block_height:
            # Precompile not yet activated at this height — treat as empty code
            return False, b''
        name = PRECOMPILED.get(addr_lower)
        if name is None:
            return False, b''

        def _charge(cost):
            # R6-precompile-gas: report the cost to the caller frame via
            # gas_cost_out and enforce the forwarded budget BEFORE
            # executing. Rule: cost is reported as soon as computable
            # (constants/word-math at branch entry; modexp/pairing after
            # their length prefix parses). Unknown/disabled/gated paths
            # above return without touching the cell. True = covered.
            if gas_cost_out is not None:
                gas_cost_out.append(cost)
            return cost <= gas

        if name == "ecrecover":
            # EVM-CONFORMANCE: 3000 gas (Yellow Paper).
            if not _charge(3000):
                return False, b'\x00' * 32
            if len(input_data) < 128:
                return False, b'\x00'*32
            try:
                from eth_keys import keys
                hash_val = input_data[0:32]
                v = int.from_bytes(input_data[32:64], 'big')
                r = int.from_bytes(input_data[64:96], 'big')
                s = int.from_bytes(input_data[96:128], 'big')
                if r == 0 or s == 0:
                    return False, b'\x00'*32
                # Convert v (27/28 or 0/1) to recovery id (0 or 1)
                if v in (27, 28):
                    recid = v - 27
                else:
                    recid = v
                sig = keys.Signature(vrs=(recid, r, s))
                pub = sig.recover_public_key_from_msg_hash(hash_val)
                addr = pub.to_checksum_address()
                # EVM-CONFORMANCE: precompile 0x01 returns a 32-byte
                # right-aligned word (go-ethereum core/vm/contracts.go
                # ecrecover.Run: LeftPadBytes(addr, 32)). The prior 20-byte
                # return shrank the caller's memory on slice assignment.
                # CHANGELOG F-ecrecover.
                return True, b'\x00' * 12 + bytes.fromhex(addr[2:])
            except Exception:
                return False, b'\x00'*32
        elif name == "sha256":
            # EVM-CONFORMANCE: 60 + 12/word (words = ceil(len/32)).
            if not _charge(60 + 12 * ((len(input_data) + 31) // 32)):
                return False, b''
            return True, hashlib.sha256(input_data).digest()
        elif name == "keccak256":
            # MCX custom precompile priced like EIP-Letter: 30 + 6/word.
            if not _charge(30 + 6 * ((len(input_data) + 31) // 32)):
                return False, b''
            return True, keccak_256(input_data)
        elif name == "ripemd160":
            # EVM-CONFORMANCE: 600 + 120/word.
            if not _charge(600 + 120 * ((len(input_data) + 31) // 32)):
                return False, b''
            if len(input_data) == 0:
                return True, b'\x00'*20
            h = hashlib.new('ripemd160', input_data).digest()
            return True, h + b'\x00'*12
        elif name == "identity":
            # EVM-CONFORMANCE: 15 + 3/word.
            if not _charge(15 + 3 * ((len(input_data) + 31) // 32)):
                return False, b''
            return True, input_data
        elif name == "token":
            # R6-precompile-gas: MCX custom precompiles cost flat 1000.
            if not _charge(1000):
                return False, b''
            if len(input_data) < 4:
                return False, b''
            selector = input_data[:4]
            if selector == b'\x70\xa0\x82\x31':  # balanceOf
                if len(input_data) < 36:
                    return False, b''
                addr = input_data[4:36].hex()
                token_addr = self.current_contract
                bal = self.token_balance_cache.get((token_addr, addr), 0)
                return True, bal.to_bytes(32, 'big')
            else:
                return False, b''
        elif name == "mcx":
            # R6-precompile-gas: MCX custom precompiles cost flat 1000.
            if not _charge(1000):
                return False, b''
            if len(input_data) < 4:
                return False, b''
            selector = input_data[:4]
            if selector == b'\x70\xa0\x82\x31':  # balanceOf
                if len(input_data) < 36:
                    return False, b''
                addr = input_data[4:36].hex()
                bal = self.balance_cache.get(addr, 0)
                return True, bal.to_bytes(32, 'big')
            elif selector == b'\xa9\x05\x9c\xbb':  # transfer
                if len(input_data) < 68:
                    return False, b''
                # EVM-CONFORMANCE: EIP-214 — balanceOf stays callable under
                # static; transfer must revert. CHANGELOG F-static-guards.
                if self.static_call:
                    return False, b''
                to = input_data[4:36].hex()
                amount = int.from_bytes(input_data[36:68], 'big')
                caller_bal = self.balance_cache.get(caller, 0)
                if caller_bal < amount:
                    return False, b'\x00'
                self.balance_cache[caller] = caller_bal - amount
                self.balance_cache[to] = self.balance_cache.get(to, 0) + amount
                return True, b'\x01'
            else:
                return False, b''
        elif name == "htlc":
            # CONSENSUS-DETERMINISM: _execute_htlc mints contract IDs with
            # secrets.token_hex(32), which cannot be reproduced across nodes.
            # Gate the precompile identically to the htlc_create tx type so a
            # contract call can never open a nondeterministic path during
            # block replay. CHANGELOG F-htlc-gate.
            if not _config.HTLC_V1_ENABLED:
                return False, b''
            # R6-precompile-gas: flat 1000 (charged only when enabled).
            if not _charge(1000):
                return False, b''
            return self._execute_htlc(input_data, caller)
        elif name == "dex":
            # R6-precompile-gas: flat 1000.
            if not _charge(1000):
                return False, b''
            return self._execute_dex(input_data, caller)
        elif name == "blake2":
            # R6-blake2-eip152: FAIL-CLOSED gate (was a naive
            # hashlib.blake2b digest of the raw input, which is NOT
            # EIP-152 F and consensus-incompatible with every correct
            # client). A from-memory F implementation was attempted and
            # its frame (213B layout, LE words, f-flag, 0-round output,
            # gas=rounds) verified, but multi-round outputs did not
            # reproduce ba80a53f...; shipping an unverified compression
            # function into consensus risks a chain split, so 0x0a
            # reverts until a vendored reference implementation lands.
            return False, b''
        elif name == "modexp":
            if len(input_data) < 96:
                return False, b''
            # EVM-CONFORMANCE: EIP-198 argument order.
            #   input = base_len(32) || exp_len(32) || mod_len(32)
            #           || base || exp || mod
            # The lengths were previously read reversed (mod first).
            # CHANGELOG F-modexp.
            base_len = int.from_bytes(input_data[0:32], 'big')
            exp_len = int.from_bytes(input_data[32:64], 'big')
            mod_len = int.from_bytes(input_data[64:96], 'big')
            # R6-precompile-gas: EIP-2565 ModExp schedule (verified
            # against eips.ethereum.org/EIPS/eip-2565: complexity uses
            # max(base_len, mod_len), divisor 3, floor 200).
            # R8-modexp-eip198 (R7-14): EIP-198 input semantics — calldata
            # is infinitely right-padded with zeros (a short slice is the
            # present prefix plus zero bytes, NOT the whole integer), and
            # the adjusted exponent length uses the FIRST 32 bytes of the
            # exponent (was: low 256 bits of the full integer, which
            # underpriced large leading bytes to near zero).
            max_len = base_len if base_len >= mod_len else mod_len
            words = (max_len + 7) // 8
            mult = words * words
            _exp_off = 96 + base_len
            _exp_head_raw = input_data[_exp_off:_exp_off + 32]
            _exp_head_raw = _exp_head_raw + b'\x00' * (32 - len(_exp_head_raw))
            if exp_len <= 32:
                _exp_full_raw = input_data[_exp_off:_exp_off + exp_len]
                _exp_full_raw = _exp_full_raw + b'\x00' * (exp_len - len(_exp_full_raw))
                _exp_full = int.from_bytes(_exp_full_raw, 'big')
                adj = 0 if _exp_full == 0 else _exp_full.bit_length() - 1
            else:
                _head = int.from_bytes(_exp_head_raw, 'big')
                adj = 8 * (exp_len - 32) + (_head.bit_length() - 1)
            if adj < 1:
                adj = 1
            mx_cost = mult * adj // 3
            if mx_cost < 200:
                mx_cost = 200
            if not _charge(mx_cost):
                return False, b''
            # Cost is affordable, so the declared lengths are bounded by it
            # (any huge length prices itself out above); pad and evaluate.
            _need = 96 + base_len + exp_len + mod_len
            if _need - len(input_data) > 16 * 1024 * 1024:
                return False, b''
            _padded = input_data + b'\x00' * (_need - len(input_data)) if _need > len(input_data) else input_data
            offset = 96
            base = int.from_bytes(_padded[offset:offset+base_len], 'big')
            offset += base_len
            exp = int.from_bytes(_padded[offset:offset+exp_len], 'big')
            offset += exp_len
            mod = int.from_bytes(_padded[offset:offset+mod_len], 'big')
            result = pow(base, exp, mod) if mod != 0 else 0
            return True, result.to_bytes(mod_len, 'big') if mod_len > 0 else b''
        elif name in ("ecAdd","ecMul","ecPairing"):
            try:
                try:
                    from py_ecc.bn128 import add, mul, pairing, G1, Z1, neg
                except ImportError:
                    from py_ecc.bn128 import add, pairing, G1, Z1, neg
                    from py_ecc.bn128 import multiply as mul
                if name == "ecAdd":
                    # R6-bn256-input-length: exact 128B (two points);
                    # short slices used to zero-pad into success.
                    if len(input_data) != 128:
                        return False, b''
                    # R6-precompile-gas: EIP-196 ecAdd costs 150.
                    if not _charge(150):
                        return False, b''
                    p1_bytes = input_data[:64]
                    p2_bytes = input_data[64:128]
                    p1 = _parse_bn256_point(p1_bytes)
                    p2 = _parse_bn256_point(p2_bytes)
                    if p1 is None or p2 is None:
                        return False, b''
                    # EVM-CONFORMANCE: EIP-196 — () is the point at
                    # infinity (identity element); py_ecc 8.x takes None
                    # for it. CHANGELOG F-bn256-parse.
                    result = add(p1 or None, p2 or None)
                    return True, _encode_bn256_point(result)
                elif name == "ecMul":
                    # R6-bn256-input-length: exact 96B (point + scalar).
                    if len(input_data) != 96:
                        return False, b''
                    # R6-precompile-gas: EIP-196 ecMul costs 6000.
                    if not _charge(6000):
                        return False, b''
                    p_bytes = input_data[:64]
                    scalar_bytes = input_data[64:96]
                    p = _parse_bn256_point(p_bytes)
                    if p is None:
                        return False, b''
                    scalar = int.from_bytes(scalar_bytes, 'big')
                    result = mul(p or None, scalar)
                    return True, _encode_bn256_point(result)
                elif name == "ecPairing":
                    # EVM-CONFORMANCE: EIP-197. Input length must be a
                    # multiple of 192 bytes; the empty input is the empty
                    # product of pairings and returns 1 without touching
                    # the curve library. Non-empty inputs are really
                    # verified and any evaluation failure reverts
                    # (fail-closed — the prior code returned True
                    # unconditionally). CHANGELOG F-ecpairing.
                    if len(input_data) % 192 != 0:
                        return False, b''
                    n_pairs = len(input_data) // 192
                    # R6-precompile-gas: EIP-197 pairing costs
                    # 45000 + 34000/pair (empty input still costs 45000).
                    if not _charge(45000 + 34000 * n_pairs):
                        return False, b''
                    if n_pairs == 0:
                        return True, b'\x01' + b'\x00' * 31
                    try:
                        from py_ecc.bn128 import FQ2, FQ12, is_on_curve, b2
                    except ImportError:
                        return False, b''
                    try:
                        acc = FQ12.one()
                        for i in range(n_pairs):
                            g1_bytes = input_data[i*192:i*192+64]
                            p1 = _parse_bn256_point(g1_bytes)
                            if p1 is None:
                                return False, b''
                            x0 = int.from_bytes(input_data[i*192+64:i*192+96], 'big')
                            x1 = int.from_bytes(input_data[i*192+96:i*192+128], 'big')
                            y0 = int.from_bytes(input_data[i*192+128:i*192+160], 'big')
                            y1 = int.from_bytes(input_data[i*192+160:i*192+192], 'big')
                            # R8-bn256-g2 (R7-15): canonical G2 coordinates
                            # (py_ecc normalizes out-of-range ints — without
                            # this, non-canonical encodings alias valid
                            # points; infinity (0,0,0,0) passes).
                            if not _bn256_g2_canonical(x0, x1, y0, y1):
                                return False, b''
                            if x0 == 0 and x1 == 0 and y0 == 0 and y1 == 0:
                                g2 = None
                            else:
                                g2 = (FQ2([x0, x1]), FQ2([y0, y1]))
                                if not is_on_curve(g2, b2):
                                    return False, b''
                            if p1 == ():
                                continue  # infinity G1: identity contribution
                            if g2 is None:
                                continue  # infinity G2: identity contribution
                            acc = acc * pairing(g2, p1)
                        ok = (acc == FQ12.one())
                    except Exception:
                        return False, b''
                    return True, (b'\x01' + b'\x00' * 31) if ok else b'\x00' * 32
            except Exception:
                return False, b''
        return False, b''

    def _execute_htlc(self, input_data: bytes, caller: str) -> Tuple[bool, bytes]:
        SELECTOR_NEW_CONTRACT = keccak_256(b"newContract(address,bytes32,uint256)")[:4]
        SELECTOR_WITHDRAW = keccak_256(b"withdraw(bytes32,bytes32)")[:4]
        SELECTOR_REFUND = keccak_256(b"refund(bytes32)")[:4]
        SELECTOR_GET_CONTRACT = keccak_256(b"getContract(bytes32)")[:4]
        if len(input_data) < 4:
            return False, b''
        selector = input_data[:4]
        if selector == SELECTOR_NEW_CONTRACT:
            if len(input_data) < 4+20+32+32:
                return False, b''
            # EVM-CONFORMANCE: EIP-214 — newContract locks funds; forbidden
            # under static (getContract below remains allowed).
            # CHANGELOG F-static-guards.
            if self.static_call:
                return False, b''
            offset = 4
            receiver = input_data[offset:offset+20].hex(); offset += 20
            hashlock = input_data[offset:offset+32].hex(); offset += 32
            timelock = int.from_bytes(input_data[offset:offset+32], 'big')
            amount = self.value
            token = b'\x00'*20
            htlc_id = secrets.token_hex(32)
            if token == b'\x00'*20:
                if self.balance_cache.get(caller, 0) < amount:
                    return False, b''
                self.balance_cache[caller] = self.balance_cache.get(caller, 0) - amount
                self.balance_cache[htlc_id] = self.balance_cache.get(htlc_id, 0) + amount
            else:
                key = (token.hex(), caller)
                if self.token_balance_cache.get(key, 0) < amount:
                    return False, b''
                self.token_balance_cache[key] = self.token_balance_cache.get(key, 0) - amount
                self.token_balance_cache[(token.hex(), htlc_id)] = self.token_balance_cache.get((token.hex(), htlc_id), 0) + amount
            htlc_data = {'id': htlc_id, 'sender': caller, 'receiver': receiver, 'hashlock': hashlock, 'timelock': timelock, 'amount': amount, 'token_address': '0x'+token.hex() if token != b'\x00'*20 else '', 'status': 'open'}
            self.htlc_repo.create(htlc_data)
            return True, bytes.fromhex(htlc_id)
        elif selector == SELECTOR_WITHDRAW:
            if len(input_data) < 4+32+32:
                return False, b''
            # EVM-CONFORMANCE: EIP-214 — withdraw moves funds; forbidden
            # under static. CHANGELOG F-static-guards.
            if self.static_call:
                return False, b''
            htlc_id = input_data[4:36].hex()
            preimage = input_data[36:68].hex()
            htlc = self.htlc_repo.get(htlc_id)
            if not htlc or htlc['status'] != 'open':
                return False, b''
            if keccak_256(bytes.fromhex(preimage)).hex() != htlc['hashlock']:
                return False, b''
            if time.time() > htlc['timelock']:
                return False, b''
            token = htlc['token_address']
            amount = htlc['amount']
            receiver = htlc['receiver']
            if token == '' or token == '0x'+'00'*20:
                if self.balance_cache.get(htlc_id, 0) < amount:
                    return False, b''
                self.balance_cache[htlc_id] = self.balance_cache.get(htlc_id, 0) - amount
                self.balance_cache[receiver] = self.balance_cache.get(receiver, 0) + amount
            else:
                key = (token, htlc_id)
                if self.token_balance_cache.get(key, 0) < amount:
                    return False, b''
                self.token_balance_cache[key] = self.token_balance_cache.get(key, 0) - amount
                self.token_balance_cache[(token, receiver)] = self.token_balance_cache.get((token, receiver), 0) + amount
            self.htlc_repo.update_status(htlc_id, 'claimed', time.time(), None)
            return True, b'\x01'
        elif selector == SELECTOR_REFUND:
            if len(input_data) < 4+32:
                return False, b''
            # EVM-CONFORMANCE: EIP-214 — refund moves funds; forbidden
            # under static. CHANGELOG F-static-guards.
            if self.static_call:
                return False, b''
            htlc_id = input_data[4:36].hex()
            htlc = self.htlc_repo.get(htlc_id)
            if not htlc or htlc['status'] != 'open':
                return False, b''
            if time.time() <= htlc['timelock']:
                return False, b''
            sender = htlc['sender']
            token = htlc['token_address']
            amount = htlc['amount']
            if token == '' or token == '0x'+'00'*20:
                if self.balance_cache.get(htlc_id, 0) < amount:
                    return False, b''
                self.balance_cache[htlc_id] = self.balance_cache.get(htlc_id, 0) - amount
                self.balance_cache[sender] = self.balance_cache.get(sender, 0) + amount
            else:
                key = (token, htlc_id)
                if self.token_balance_cache.get(key, 0) < amount:
                    return False, b''
                self.token_balance_cache[key] = self.token_balance_cache.get(key, 0) - amount
                self.token_balance_cache[(token, sender)] = self.token_balance_cache.get((token, sender), 0) + amount
            self.htlc_repo.update_status(htlc_id, 'refunded', None, time.time())
            return True, b'\x01'
        elif selector == SELECTOR_GET_CONTRACT:
            if len(input_data) < 4+32:
                return False, b''
            htlc_id = input_data[4:36].hex()
            htlc = self.htlc_repo.get(htlc_id)
            if not htlc:
                return False, b''
            sender = bytes.fromhex(htlc['sender'][2:])
            receiver = bytes.fromhex(htlc['receiver'][2:])
            amount = htlc['amount'].to_bytes(32, 'big')
            hashlock = bytes.fromhex(htlc['hashlock'])
            timelock = htlc['timelock'].to_bytes(32, 'big')
            status = (1 if htlc['status']=='open' else 0).to_bytes(1, 'big')
            preimage = b'\x00'*32
            return True, sender+receiver+amount+hashlock+timelock+status+preimage
        else:
            return False, b''

    def _execute_dex(self, input_data: bytes, caller: str) -> Tuple[bool, bytes]:
        if len(input_data) < 4:
            return False, b''
        selector = input_data[:4]
        for key, val in self.storage_cache.items():
            if key.startswith("dex_pool_"):
                pool_id = key[9:]
                self._dex_pools[pool_id] = json.loads(val)
        if selector == b'\x01\x00\x00\x00':  # createPool
            if len(input_data) < 4+20+20:
                return False, b''
            # EVM-CONFORMANCE: EIP-214 — all dex selectors mutate pool
            # state; forbidden under static. CHANGELOG F-static-guards.
            if self.static_call:
                return False, b''
            tokenA = input_data[4:24].hex()
            tokenB = input_data[24:44].hex()
            if tokenA > tokenB:
                tokenA, tokenB = tokenB, tokenA
            pair = f"{tokenA}:{tokenB}"
            # R4-sha3-sites: pool address via keccak (last 20 bytes), not
            # NIST SHA3-256 first-20.
            pool_addr = bytes.fromhex(eth_keccak(pair.encode()).hex()[-40:])
            # R4-dex-fix: the pool id IS the pool address. addLiquidity /
            # removeLiquidity look pools up by the 20-byte id they are
            # given, which never matched the old "tokA:tokB" key — every
            # add/remove failed. Stored under the hex id (and the
            # dex_pool_<id> storage key reloads to the same form).
            pool_id = pool_addr.hex()
            if pool_id in self._dex_pools:
                return False, b'\x00'*32
            self._dex_pools[pool_id] = {'tokenA': tokenA, 'tokenB': tokenB, 'reserveA': 0, 'reserveB': 0, 'total_lp': 0, 'lp_balances': {}}
            self.storage_cache[f"dex_pool_{pool_id}"] = json.dumps(self._dex_pools[pool_id])
            return True, pool_addr
        elif selector == b'\x02\x00\x00\x00':  # addLiquidity
            if len(input_data) < 4+20+32+32:
                return False, b''
            # EVM-CONFORMANCE: EIP-214. CHANGELOG F-static-guards.
            if self.static_call:
                return False, b''
            pool_id = input_data[4:24].hex()
            amountA = int.from_bytes(input_data[24:56], 'big')
            amountB = int.from_bytes(input_data[56:88], 'big')
            if pool_id not in self._dex_pools:
                return False, b'\x00'*32
            pool = self._dex_pools[pool_id]
            tokenA, tokenB = pool['tokenA'], pool['tokenB']
            balA = self.token_balance_cache.get((tokenA, caller), 0)
            balB = self.token_balance_cache.get((tokenB, caller), 0)
            if balA < amountA or balB < amountB:
                return False, b'\x00'*32
            if pool['reserveA'] > 0 or pool['reserveB'] > 0:
                if amountA * pool['reserveB'] != amountB * pool['reserveA']:
                    return False, b'\x00'*32
            # R5-dex-cache-restore: validate before the first cache write.
            if pool['reserveA'] == 0 and pool['reserveB'] == 0:
                # R4-dex-fix: integer sqrt + MINIMUM_LIQUIDITY lock (Uniswap
                # V2 shape). The float sqrt could not conserve exactly, and
                # dust first-mints must revert rather than mint ~nothing.
                _lp = math.isqrt(amountA * amountB)
                if _lp < MINIMUM_LIQUIDITY:
                    return False, b'\x00'*32
                lp_minted = _lp - MINIMUM_LIQUIDITY
                _first = True
            else:
                _first = False
                lp_minted = min(amountA * pool['total_lp'] // pool['reserveA'], amountB * pool['total_lp'] // pool['reserveB'])
            if lp_minted == 0:
                return False, b'\x00'*32
            self.token_balance_cache[(tokenA, caller)] = balA - amountA
            self.token_balance_cache[(tokenB, caller)] = balB - amountB
            self.token_balance_cache[(tokenA, pool_id)] = self.token_balance_cache.get((tokenA, pool_id), 0) + amountA
            self.token_balance_cache[(tokenB, pool_id)] = self.token_balance_cache.get((tokenB, pool_id), 0) + amountB
            if _first:
                pool['lp_balances']['0x' + '00' * 20] = pool['lp_balances'].get('0x' + '00' * 20, 0) + MINIMUM_LIQUIDITY
            pool['reserveA'] += amountA
            pool['reserveB'] += amountB
            pool['total_lp'] += lp_minted + (MINIMUM_LIQUIDITY if _first else 0)
            pool['lp_balances'][caller] = pool['lp_balances'].get(caller, 0) + lp_minted
            self.storage_cache[f"dex_pool_{pool_id}"] = json.dumps(pool)
            return True, lp_minted.to_bytes(32, 'big')
        elif selector == b'\x03\x00\x00\x00':  # removeLiquidity
            if len(input_data) < 4+20+32:
                return False, b''
            # EVM-CONFORMANCE: EIP-214. CHANGELOG F-static-guards.
            if self.static_call:
                return False, b''
            pool_id = input_data[4:24].hex()
            lp_amount = int.from_bytes(input_data[24:56], 'big')
            if pool_id not in self._dex_pools:
                return False, b'\x00'*64
            pool = self._dex_pools[pool_id]
            if caller not in pool['lp_balances'] or pool['lp_balances'][caller] < lp_amount:
                return False, b'\x00'*64
            # R4-dex-fix: integer shares. The float division rounded down
            # per-side independently and could leak dust on every exit.
            amountA = pool['reserveA'] * lp_amount // pool['total_lp']
            amountB = pool['reserveB'] * lp_amount // pool['total_lp']
            self.token_balance_cache[(pool['tokenA'], pool_id)] = self.token_balance_cache.get((pool['tokenA'], pool_id), 0) - amountA
            self.token_balance_cache[(pool['tokenB'], pool_id)] = self.token_balance_cache.get((pool['tokenB'], pool_id), 0) - amountB
            self.token_balance_cache[(pool['tokenA'], caller)] = self.token_balance_cache.get((pool['tokenA'], caller), 0) + amountA
            self.token_balance_cache[(pool['tokenB'], caller)] = self.token_balance_cache.get((pool['tokenB'], caller), 0) + amountB
            pool['reserveA'] -= amountA
            pool['reserveB'] -= amountB
            pool['total_lp'] -= lp_amount
            pool['lp_balances'][caller] -= lp_amount
            if pool['lp_balances'][caller] == 0:
                del pool['lp_balances'][caller]
            self.storage_cache[f"dex_pool_{pool_id}"] = json.dumps(pool)
            return True, amountA.to_bytes(32, 'big') + amountB.to_bytes(32, 'big')
        elif selector == b'\x04\x00\x00\x00':  # swap
            if len(input_data) < 4+20+20+32:
                return False, b''
            # EVM-CONFORMANCE: EIP-214. CHANGELOG F-static-guards.
            if self.static_call:
                return False, b''
            token_in = input_data[4:24].hex()
            token_out = input_data[24:44].hex()
            amount_in = int.from_bytes(input_data[44:76], 'big')
            pool_id = None
            for pid, p in self._dex_pools.items():
                if (p['tokenA'] == token_in and p['tokenB'] == token_out) or (p['tokenA'] == token_out and p['tokenB'] == token_in):
                    pool_id = pid; break
            if pool_id is None:
                return False, b'\x00'*32
            pool = self._dex_pools[pool_id]
            if pool['tokenA'] == token_in:
                reserve_in, reserve_out = pool['reserveA'], pool['reserveB']
            else:
                reserve_in, reserve_out = pool['reserveB'], pool['reserveA']
            if reserve_in == 0:
                return False, b'\x00'*32
            if self.token_balance_cache.get((token_in, caller), 0) < amount_in:
                return False, b'\x00'*32
            amount_in_with_fee = amount_in * 997 // 1000
            amount_out = (amount_in_with_fee * reserve_out) // (reserve_in + amount_in_with_fee)
            if amount_out == 0:
                return False, b'\x00'*32
            self.token_balance_cache[(token_in, caller)] = self.token_balance_cache.get((token_in, caller), 0) - amount_in
            self.token_balance_cache[(token_in, pool_id)] = self.token_balance_cache.get((token_in, pool_id), 0) + amount_in
            self.token_balance_cache[(token_out, pool_id)] = self.token_balance_cache.get((token_out, pool_id), 0) - amount_out
            self.token_balance_cache[(token_out, caller)] = self.token_balance_cache.get((token_out, caller), 0) + amount_out
            if pool['tokenA'] == token_in:
                pool['reserveA'] += amount_in
                pool['reserveB'] -= amount_out
            else:
                pool['reserveB'] += amount_in
                pool['reserveA'] -= amount_out
            self.storage_cache[f"dex_pool_{pool_id}"] = json.dumps(pool)
            return True, amount_out.to_bytes(32, 'big')
        else:
            return False, b''


# ─── Subprocess Runner ──────────────────────────────────────
class SyncDB:
    """Sync DB handle for run_vm_in_subprocess (module-level for reuse)."""
    def __init__(self, db_url):
        self.db_url = db_url
        self.conn = None
        if db_url.startswith('sqlite://'):
            path = db_url[9:]
            self.conn = sqlite3.connect(path, check_same_thread=False)
            self.conn.row_factory = sqlite3.Row
        elif db_url.startswith('postgresql://'):
            import psycopg2
            self.conn = psycopg2.connect(db_url)
            self.conn.autocommit = True
        else:
            raise ValueError("Unsupported DB URL")
    def _translate(self, query: str) -> str:
        # R5-pg-placeholders: psycopg2 wants %s, not ?.
        # R6-syncdb-doubled-quote: REFUTED (no code change). A doubled
        # quote ('') exits and immediately re-enters the quoted region,
        # so a literal ? inside stays untranslated; 40k-case differential
        # fuzz old-vs-candidate found zero divergences. See report.
        if self.db_url.startswith('postgresql://') and '?' in query:
            out, in_q, prev = [], False, ''
            for c in query:
                if in_q:
                    out.append(c)
                    if c == "'" and prev != '\\':
                        in_q = False
                elif c == "'":
                    in_q = True
                    out.append(c)
                elif c == '?':
                    out.append('%s')
                else:
                    out.append(c)
                prev = c
            return ''.join(out)
        return query
    def execute(self, query, *args):
        cur = self.conn.cursor()
        cur.execute(self._translate(query), args)
        return cur
    def fetchall(self, query, *args):
        cur = self.conn.cursor()
        cur.execute(self._translate(query), args)
        return cur.fetchall()
    def fetchone(self, query, *args):
        cur = self.conn.cursor()
        cur.execute(self._translate(query), args)
        return cur.fetchone()
    def commit(self):
        self.conn.commit()
    def close(self):
        self.conn.close()


def _vm_require_sandbox_effective() -> bool:
    # R8-sandbox-config (R7-08): the VM worker (spawned subprocess) must
    # honor the EFFECTIVE config, not the import-time global. The parent
    # exports MCX_VM_REQUIRE_SANDBOX from its resolved config before any
    # worker spawns (see export_vm_sandbox_env / MicroCoreNode.__init__);
    # explicit env wins, else the import-time global (unchanged default).
    _env = os.environ.get("MCX_VM_REQUIRE_SANDBOX", "").strip().lower()
    if _env in ("1", "true", "yes", "on"):
        return True
    if _env in ("0", "false", "no", "off"):
        return False
    return bool(VM_REQUIRE_SANDBOX)


def export_vm_sandbox_env(config) -> str:
    # R8-sandbox-config (R7-08): publish the effective require_sandbox so
    # spawned VM workers inherit it through the environment (spawn keeps
    # parent env). Returns the exported value. Call whenever the effective
    # config is (re)resolved, before workers spawn.
    try:
        _want = bool((config or {}).get('vm', {}).get('require_sandbox', False))
    except Exception:
        _want = False
    os.environ["MCX_VM_REQUIRE_SANDBOX"] = "1" if _want else "0"
    return os.environ["MCX_VM_REQUIRE_SANDBOX"]


def _drop_vm_privileges() -> bool:
    # R5-chroot-fail-closed: with require_sandbox, do not continue if privilege drop fails.
    try:
        if hasattr(os, "geteuid") and os.geteuid() == 0:
            os.setgid(int(os.environ.get("MCX_VM_GID", "65534")))
            os.setuid(int(os.environ.get("MCX_VM_UID", "65534")))
            return True
        return False
    except (OSError, PermissionError, ValueError) as _du_e:
        if _vm_require_sandbox_effective():
            sys.stderr.write(f"[VM] FATAL: privilege drop failed ({_du_e}) with require_sandbox=true; refusing to run\n")
            sys.stderr.flush()
            sys.exit(1)
        sys.stderr.write(f"[VM] WARNING: privilege drop failed ({_du_e}); continuing chrooted as current user\n")
        sys.stderr.flush()
        return False


def _apply_vm_worker_limits() -> None:
    """R4-rlimit-nofile: apply one worker's rlimits, each in its own
    try/except. Previously a single block referenced a nonexistent
    RLIMIT_*_FILE name first, so the bare `except: pass` silently skipped
    NOFILE and CORE too. CPU/AS stay first (hardest caps)."""
    if not HAVE_RESOURCE:
        return
    import resource
    try:
        resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_AS, (VM_RLIMIT_AS_BYTES, VM_RLIMIT_AS_BYTES))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
    except (ValueError, OSError):
        pass
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps
    except (ValueError, OSError):
        pass


def run_vm_in_subprocess(bytecode_hex: str, caller: str, origin: str, value: int,
                         gas_limit: int, contract_address: str, input_data_hex: str,
                         static: bool = False, storage_cache: dict = None,
                         code_cache: dict = None, balance_cache: dict = None,
                          token_balance_cache: dict = None, htlc_repo_conn_info: tuple = None,
                          block_height: int = 0, block_ts: float = None) -> Tuple[bool, str, int, List[Dict], dict, dict, dict]:
    # ─── Sanitize environment: strip sensitive vars from subprocess ───
    for _sensitive_key in list(os.environ.keys()):
        if any(_k in _sensitive_key.upper() for _k in ('PASSWORD', 'SECRET', 'KEY', 'TOKEN', 'CREDENTIAL')):
            try:
                del os.environ[_sensitive_key]
            except Exception:
                pass

    # R6-sqlite-subprocess-path: resolve the DB URL once, up front, so the
    # pre-chroot open below (and the plain open on other hosts) use the
    # node's own environment/cwd (chain reset: VM state machine).
    db_url = os.environ.get('MCX_DB_URL', '')
    if not db_url:
        db_host = os.environ.get('MCX_DB_HOST', 'localhost')
        db_port = os.environ.get('MCX_DB_PORT', '5432')
        db_user = os.environ.get('MCX_DB_USER', 'postgres')
        db_pass = os.environ.get('MCX_DB_PASS', 'postgres')
        db_name = os.environ.get('MCX_DB_NAME', 'mcx')
        if os.environ.get('MCX_DB_HOST'):
            db_url = f"postgresql://{db_user}:{db_pass}@{db_host}:{db_port}/{db_name}"
        else:
            db_url = 'sqlite://microcore.db'
    sync_db = None
    if HAVE_RESOURCE:
        _apply_vm_worker_limits()
        # R6-sqlite-subprocess-path: SyncDB opens BEFORE the chroot below.
        # A relative sqlite:// URL must resolve against the node's cwd;
        # opening after chroot/chdir silently rebound cross-contract
        # lookups (BALANCE, EXTCODEHASH fallback) to the sandbox file.
        sync_db = SyncDB(db_url)
        # Sandbox: chroot + drop privileges + disable dangerous syscalls
        try:
            sandbox_dir = "/tmp/mcx_vm_sandbox"
            os.makedirs(sandbox_dir, exist_ok=True)
            os.chroot(sandbox_dir)
            os.chdir("/")
            _drop_vm_privileges()
        except (OSError, PermissionError) as _chroot_e:
            # C-3 (MCX73): chroot may fail in containers — the old code fell
            # back to rlimits-only silently. With vm.require_sandbox: true
            # (mandatory for mainnet) the subprocess refuses to run
            # unsandboxed instead.
            if _vm_require_sandbox_effective():
                sys.stderr.write(f"[VM] FATAL: chroot failed ({_chroot_e}) with require_sandbox=true; refusing to run\n")
                sys.stderr.flush()
                sys.exit(1)
            pass  # chroot may fail in containers — fall back to rlimits only
        try:
            os.setsid()  # new session, no controlling terminal
        except OSError:
            pass
    elif sys.platform == 'win32':
        # Windows: use ctypes to set working set size limits (parity with RLIMIT_AS)
        try:
            import ctypes
            kernel32 = ctypes.windll.kernel32
            cur_handle = kernel32.GetCurrentProcess()
            kernel32.SetProcessWorkingSetSize(cur_handle, VM_RLIMIT_AS_BYTES, VM_RLIMIT_AS_BYTES * 2)
        except Exception:
            pass

    # R6-sqlite-subprocess-path: hosts without resource limits (and the
    # win32 branch above) never chroot, so a plain open here is exact.
    if sync_db is None:
        sync_db = SyncDB(db_url)

    class SyncHTLCRepo:
        """Synchronous HTLC repo for use inside run_vm_in_subprocess.
        The async HTLCRepo can't be called without await from sync _execute_htlc."""
        def __init__(self, db):
            self.db = db
            self.ph = "?" if db.db_url.startswith("sqlite://") else "%s"
        def create(self, htlc):
            cur = self.db.conn.cursor()
            cur.execute(
                f"INSERT INTO htlc_contracts (id,sender,receiver,hashlock,timelock,amount,token_address,status,created_at) VALUES ({self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph},{self.ph})",
                (htlc['id'], htlc['sender'], htlc['receiver'], htlc['hashlock'], htlc['timelock'], htlc['amount'], htlc.get('token_address',''), htlc.get('status','open'), time.time()),
            )
            self.db.conn.commit()
        def get(self, htlc_id):
            cur = self.db.conn.cursor()
            cur.execute(f"SELECT * FROM htlc_contracts WHERE id = {self.ph}", (htlc_id,))
            row = cur.fetchone()
            if row is None:
                return None
            if isinstance(row, dict):
                return row
            # psycopg2 returns tuples; convert to dict using column names
            columns = [desc[0] for desc in cur.description]
            return dict(zip(columns, row))
        def update_status(self, htlc_id, status, claimed_at=None, refunded_at=None):
            cur = self.db.conn.cursor()
            cur.execute(
                f"UPDATE htlc_contracts SET status={self.ph}, claimed_at={self.ph}, refunded_at={self.ph} WHERE id={self.ph}",
                (status, claimed_at, refunded_at, htlc_id),
            )
            self.db.conn.commit()

    htlc_repo = SyncHTLCRepo(sync_db) if sync_db else None

    class DummyRepoProvider:
        def __call__(self):
            return sync_db

    engine = VMExecutionEngine(DummyRepoProvider())
    engine.code_cache = code_cache if code_cache else {}
    engine.balance_cache = balance_cache if balance_cache else {}
    token_cache = {}
    if sync_db:
        cur = sync_db.execute("SELECT token_address, wallet, balance FROM token_balances")
        for token_addr, wallet, bal in cur.fetchall():
            token_cache[(token_addr, wallet)] = bal
    engine.token_balance_cache = token_cache if token_balance_cache is None else token_balance_cache
    engine.htlc_repo = htlc_repo
    engine.set_block_height(int(block_height or 0))
    # R4-opcodes-add: execution-context timestamp for TIMESTAMP.
    engine.set_block_timestamp(block_ts)

    bytecode = bytes.fromhex(bytecode_hex)
    input_data = bytes.fromhex(input_data_hex)

    success, ret, gas_used, logs = engine.execute(
        bytecode, caller, origin, value, gas_limit, contract_address, input_data, static,
        initial_storage=storage_cache if storage_cache else {})

    # NOTE: State changes are NOT persisted here. They are returned to the
    # caller (VMManager.execute) which only applies them to the canonical DB
    # when `success` is True. Persisting here would corrupt state on revert.
    # Element 5 is a PER-ADDRESS storage map (main address first) so the
    # caller can write each address's slots back under that address.
    storage_map = {}
    if engine.storage_address:
        storage_map[engine.storage_address] = dict(engine.storage_cache)
    for _addr, _slots in engine.sub_storage.items():
        storage_map.setdefault(_addr, {}).update(_slots)
    return success, ret.hex(), gas_used, logs, storage_map, engine.balance_cache, engine.token_balance_cache


# ─── VMManager ──────────────────────────────────────────────
class VMManager:
    def __init__(self, db: Database, contract_v2_repo, contract_storage_v2_repo, token_balance_repo, balance_repo, htlc_repo):
        self.db = db
        self.contract_v2_repo = contract_v2_repo
        self.contract_storage_v2_repo = contract_storage_v2_repo
        self.token_balance_repo = token_balance_repo
        self.balance_repo = balance_repo
        self.htlc_repo = htlc_repo
        self.timeout = VM_TIMEOUT
        try:
            mp.set_start_method('spawn', force=True)
        except RuntimeError:
            pass
        # VM-1: asyncio loop.run_in_executor requires an Executor (.submit);
        # mp.Pool has no .submit, so every VM call raised AttributeError and
        # was silently swallowed as "[VM] Execution error".
        # R4-pool-rebuild: constructed via _new_pool (see _run_vm_subprocess).
        self.pool = self._new_pool()
        self._code_cache: Dict[str, bytes] = {}  # address -> bytecode
        self._code_cache_valid = False  # True after first load

    def _current_block_height(self) -> int:
        """Current block height from the owning node; 0 when no node is wired."""
        return int(getattr(getattr(self, 'node', None), 'height', 0) or 0)

    def _new_pool(self) -> ProcessPoolExecutor:
        # R4-pool-rebuild: pool construction in one place so recovery and
        # init stay identical. CHANGELOG R4-pool-rebuild.
        return ProcessPoolExecutor(max_workers=4)

    async def _run_vm_subprocess(self, args: tuple, timeout: float):
        """R4-pool-rebuild: submit run_vm_in_subprocess with one rebuild-and-
        retry on BrokenProcessPool. RLIMIT_CPU is cumulative per worker, so a
        killed worker poisons the pool; previously nothing rebuilt it and
        every later VM call failed. The RLIMIT_CPU kill itself cannot be
        undone per call (hard kill) — only the pool is replaced."""
        loop = asyncio.get_event_loop()
        try:
            return await asyncio.wait_for(
                loop.run_in_executor(self.pool, run_vm_in_subprocess, *args),
                timeout=timeout)
        except BrokenProcessPool as _e:
            _old_id = id(self.pool)
            try:
                self.pool.shutdown(wait=False)
            except Exception as _se:
                logger.debug(f"[VM] R4-pool-rebuild: old pool shutdown raised {_se}")
            self.pool = self._new_pool()
            logger.warning(f"[VM] R4-pool-rebuild: pool {_old_id} broken ({_e}); rebuilt {id(self.pool)}, retrying once")
            return await asyncio.wait_for(
                loop.run_in_executor(self.pool, run_vm_in_subprocess, *args),
                timeout=timeout)

    async def _journal_write(self, block_id: int, namespace: str, addr: str, key: str,
                           old_value, new_value) -> None:
        # B6 (MCX73): write-ahead record for one VM-flush state mutation.
        # No-op when block_id < 0 (static/eth_call paths never mutate and
        # must not journal). None old_value = key absent pre-write; the
        # reorg revert then DELETEs instead of restoring.
        # Case rule: BalanceRepo lowercases wallets on write, so the balance
        # namespace is stored lowered (otherwise the revert DELETE misses on
        # mixed-case addresses). Storage/token namespaces are case-sensitive
        # end to end — stored raw.
        try:
            if block_id is None or int(block_id) < 0:
                return
        except (TypeError, ValueError):
            return
        if namespace == "balance" and isinstance(addr, str):
            addr = addr.lower()
        def _s(v):
            return None if v is None else str(v)
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES (?,?,?,?,?,?)",
                int(block_id), namespace, str(addr), str(key), _s(old_value), _s(new_value))
        else:
            await self.db.execute_dml(
                "INSERT INTO contract_exec_journal (block_id, namespace, addr, key, old_value, new_value) VALUES ($1,$2,$3,$4,$5,$6)",
                int(block_id), namespace, str(addr), str(key), _s(old_value), _s(new_value))

    async def execute(self, contract_address: str, caller: str, origin: str, value: int,
                      gas_limit: int, input_data: bytes, static: bool = False,
                      init_code_hex: str = None, block_id: int = -1,
                      block_ts: float = None) -> Tuple[bool, bytes, int, List[Dict]]:
        # VM-2: a brand-new deploy has no contract_v2 row yet — run the init
        # code directly (mirrors the shadow verifier, which passes init code
        # as bytecode with input_hex='').
        if init_code_hex is not None:
            bytecode = init_code_hex
        else:
            contract = await self.contract_v2_repo.get(contract_address)
            if not contract:
                return False, b'', 0, []
            bytecode = contract['bytecode']
        storage_rows = await self.contract_storage_v2_repo.get_all(contract_address)
        storage_cache = {key: int(value) for key, value in storage_rows.items()}
        # Use cached code if available, otherwise load all contracts and cache
        if not self._code_cache_valid:
            all_contracts = await self.contract_v2_repo.get_all()
            self._code_cache = {c['address']: bytes.fromhex(c['bytecode']) for c in all_contracts}
            self._code_cache_valid = True
        code_cache = self._code_cache
        input_hex = input_data.hex()
        bytecode_hex = bytecode
        os.environ['MCX_DB_URL'] = self.db._pg_target_dsn if self.db.db_type == 'postgres' else 'sqlite://microcore.db'
        loop = asyncio.get_event_loop()
        block_height = self._current_block_height()
        # R4-opcodes-add: execution-context timestamp for TIMESTAMP.
        # Explicit arg (produce/import thread the sealed value) wins; else
        # the sealed row for this height; else wall-clock for static tip
        # reads. Non-static without any source resolves None -> TIMESTAMP
        # pushes 0 (deterministic; all threaded paths supply a value).
        _exec_ts = block_ts
        if _exec_ts is None and block_height:
            try:
                if self.db.db_type == "sqlite":
                    _ts_row = await self.db.fetchrow("SELECT ts FROM blocks WHERE id = ?", block_height)
                else:
                    _ts_row = await self.db.fetchrow("SELECT ts FROM blocks WHERE id = $1", block_height)
                if _ts_row is not None:
                    try:
                        _exec_ts = _ts_row["ts"]
                    except (TypeError, KeyError, IndexError):
                        _exec_ts = _ts_row[0]
            except Exception:
                _exec_ts = None
        if _exec_ts is None and static:
            _exec_ts = time.time()
        try:
            balance_cache = {}
            for addr in {caller, origin, contract_address}:
                if addr:
                    balance_cache[addr] = await self.balance_repo.get(addr)
            # token_balance_cache=None -> subprocess loads real token balances
            # (a {} here used to DISABLE the load, so contracts saw 0 tokens).
            # R4-pool-rebuild: submit via the rebuild-and-retry helper.
            # R4-opcodes-add: thread the execution-context timestamp.
            result = await self._run_vm_subprocess((bytecode_hex, caller, origin, value, gas_limit, contract_address, input_hex, static, storage_cache, code_cache, balance_cache, None, None, block_height, _exec_ts), timeout=self.timeout)
            success, ret_hex, gas_used, logs, updated_storage, updated_balance, updated_token_balance = result
            if not success:
                logger.warning(
                    f"[VM] Execution failed for {contract_address}: "
                    f"gas={gas_used}/{gas_limit} ret={ret_hex!r} logs={logs!r}")
                return False, b'', gas_used, logs
            # CRITICAL: When static=True (eth_call / eth_estimateGas), NEVER write state
            if not static:
                # B6 (MCX73): flush + journal atomically. Every VM-driven
                # state mutation records its pre-image first, so a later
                # reorg restores exactly (previously: logged-only warning).
                # The transaction nests into the importer's block txn when
                # present, else commits standalone.
                async with await self.db.transaction():
                    if updated_storage:
                        main_slots = updated_storage.get(contract_address, {})
                        # Main address: only slots that actually changed vs the
                        # loaded baseline (existing behavior).
                        for key, val in main_slots.items():
                            if val != storage_cache.get(key, 0):
                                _old = storage_cache[key] if key in storage_cache else None
                                await self._journal_write(block_id, "storage", contract_address, key, _old, str(val))
                                await self.contract_storage_v2_repo.set(contract_address, key, str(val))
                        # VM-3: writes routed to OTHER addresses (subcalls /
                        # constructor storage) go back under those addresses;
                        # buckets contain dirty keys only.
                        for addr, slots in updated_storage.items():
                            if addr == contract_address:
                                continue
                            for key, val in slots.items():
                                try:
                                    _old_o = await self.contract_storage_v2_repo.get(addr, key)
                                except Exception:
                                    _old_o = None
                                await self._journal_write(block_id, "storage", addr, key, _old_o, str(val))
                                await self.contract_storage_v2_repo.set(addr, key, str(val))
                    if updated_balance:
                        for addr, bal in updated_balance.items():
                            current = await self.balance_repo.get(addr)
                            if current != bal:
                                await self._journal_write(block_id, "balance", addr, "bal", current, bal)
                                await self.balance_repo.set(addr, bal)
                    if updated_token_balance:
                        for (token_addr, wallet), bal in updated_token_balance.items():
                            current = await self.token_balance_repo.get(token_addr, wallet)
                            if current != bal:
                                await self._journal_write(block_id, "token_balance", token_addr, wallet, current, bal)
                                await self.token_balance_repo.set(token_addr, wallet, bal)
            return success, bytes.fromhex(ret_hex) if ret_hex else b'', gas_used, logs
        except asyncio.TimeoutError:
            logger.warning(f"[VM] Execution timed out for contract {contract_address}")
            return False, b'', 0, []
        except Exception as e:
            logger.error(f"[VM] Execution error: {e}", exc_info=True)
            return False, b'', 0, []

    def close(self):
        # VM-1: ProcessPoolExecutor.shutdown is idempotent (safe to call
        # repeatedly); mp.Pool.terminate/join is not an Executor API.
        try:
            self.pool.shutdown(wait=False)
        except Exception:
            pass


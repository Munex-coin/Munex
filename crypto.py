# Split of MCX81.py (lines 1637-2294). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import bip32utils, eth_keccak, logger, ph
from node.config import BLOCK_FUTURE_SKEW, CONSENSUS_EXCLUDED_FIELDS, SECP256K1_N, _strict_bool
from node.bootstrap import Any, Cipher, PBKDF2HMAC, PKCS7, algorithms, base64, decode_dss_signature, ec, encode_dss_signature, hashes, hashlib, hmac, ipaddress, json, modes, os, re, secrets, serialization, socket, sys


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")

def block_signing_payload(block: dict) -> bytes:
    unsigned = {
        key: value
        for key, value in block.items()
        if key not in CONSENSUS_EXCLUDED_FIELDS
    }
    return canonical_json_bytes(unsigned)

def calculate_block_hash(block: dict) -> str:
    return hashlib.sha256(block_signing_payload(block)).hexdigest()

def sign_bytes(priv_hex: str, message: bytes) -> str:
    priv_int = int(priv_hex, 16)
    priv_key = ec.derive_private_key(priv_int, ec.SECP256K1())
    sig = priv_key.sign(message, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(sig)
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
    return f"{r:064x}{s:064x}"

def verify_signature_bytes(pub_hex: str, message: bytes, sig_hex: str) -> bool:
    # R4-verify-sig-charset: strict hex gates first. int(x, 16) tolerates
    # surrounding whitespace and underscores, so malformed encodings
    # previously reached crypto instead of failing closed at the gate.
    if not isinstance(sig_hex, str) or not re.fullmatch(r"[0-9a-fA-F]{128}", sig_hex):
        return False
    if not isinstance(pub_hex, str) or not re.fullmatch(r"04[0-9a-fA-F]{128}", pub_hex):
        return False
    try:
        if len(pub_hex) != 130 or not pub_hex.startswith("04"):
            return False
        x = int(pub_hex[2:66], 16)
        y = int(pub_hex[66:], 16)
        pub_nums = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
        pub = pub_nums.public_key()
        r = int(sig_hex[:64], 16)
        s = int(sig_hex[64:], 16)
        # Enforce low-s to prevent signature malleability (BIP-62)
        if s > SECP256K1_N // 2:
            return False
        pub.verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False

def seal_block(block: dict, private_key: str) -> dict:
    sealed = dict(block)
    sealed["hash"] = calculate_block_hash(sealed)
    sealed["signature"] = sign_bytes(private_key, bytes.fromhex(sealed["hash"]))
    return sealed

# ─── Backward-compatible wrappers ─────────────────────────────
def sign_message(priv_hex, message):
    if isinstance(message, str):
        message = message.encode("utf-8")
    return sign_bytes(priv_hex, message)

def verify_signature(pub_hex, message, sig_hex):
    if isinstance(message, str):
        message = message.encode("utf-8")
    return verify_signature_bytes(pub_hex, message, sig_hex)

def _block_timestamp_ok(block_ts, parent_ts) -> bool:
    # R8-timestamp-deterministic (R7-11): pure parent-relative validity —
    # strictly after the parent, within BLOCK_FUTURE_SKEW. No wall clock:
    # two nodes with arbitrarily skewed clocks decide identically on the
    # same chain data.
    # SEAL-TS-FAILCLOSED-1: OverflowError (float() of an arbitrary-precision
    # JSON integer in a peer-supplied block) is now a plain False. Previously
    # it escaped verify_block_proof as an exception — still a rejection, but
    # via the exception path (aborting a whole MSG_BLOCKS import batch). The
    # accepted set is unchanged: no input that was valid before is rejected.
    try:
        block_ts = float(block_ts)
        parent_ts = float(parent_ts)
    except (TypeError, ValueError, OverflowError):
        return False
    return parent_ts < block_ts <= parent_ts + BLOCK_FUTURE_SKEW


def hash_block(b):
    return calculate_block_hash(b)

def hash_tx(tx):
    return hashlib.sha256(canonical_json_bytes(tx)).hexdigest()

# R9-txbind (I-R8-08): MERKLE_ACTIVATION_HEIGHT removed — the Merkle
# commitment is enforced unconditionally now, not deferred.
VERIFY_STATE_ROOT = True  # B5 (MCX73): winner-balance state commitment enforced (two-key scope; see README ## State commitment)
# MCX76-state-commitment-scope: the per-block state root commits exactly
# the producer's full trie keys for the block. See README "State
# commitment" for what that does and does not cover.
STATE_COMMITMENT_SCOPE = "two-key"
                           # Scope: {height, balance:<reward_wallet>} only — the producer's
                           # full trie keys per block. Fork blocks skip the check
                           # (pre-state ambiguous; reorg path governs). This rejects
                           # a producer who lies about the winner's post-block
                           # balance, not lies about any other account.

def _topic_to_int(t):
    # R8-getlogs (R7-22): stored topics are stack ints; filters carry
    # 0x-words, decimals, or ints. Normalize to int or return None.
    try:
        if isinstance(t, int):
            return t
        s = str(t).strip()
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (TypeError, ValueError):
        return None


def _log_matches_filter(log_address, log_topics, addresses, topics) -> bool:
    # R8-getlogs (R7-22): eth filter semantics against ONE log (never the
    # receipt contract address). addresses: str | [str] | None (OR, case
    # insensitive). topics: per-position topic | [topics] (OR) | None;
    # a longer filter than the log's topics never matches.
    try:
        if addresses is not None:
            want = [addresses] if isinstance(addresses, str) else list(addresses)
            if str(log_address or "").lower() not in [str(a or "").lower() for a in want]:
                return False
        if topics:
            lt = []
            for _t in (log_topics or []):
                _ti = _topic_to_int(_t)
                if _ti is None:
                    return False
                lt.append(_ti)
            for _i, _f in enumerate(topics):
                if _f is None:
                    continue
                _want = _f if isinstance(_f, list) else [_f]
                _wi = []
                for _x in _want:
                    _xi = _topic_to_int(_x)
                    if _xi is None:
                        return False
                    _wi.append(_xi)
                if _i >= len(lt) or lt[_i] not in _wi:
                    return False
    except Exception:
        return False
    return True


def _enrich_eth_log(log, block_hash, block_number, tx_hash, tx_index, log_index) -> dict:
    # R8-getlogs (R7-22): shape one stored log as an eth log object with
    # real block hash / indexes (was: blank blockHash, no indexes).
    try:
        _topics = []
        for _t in (log.get("topics") or []):
            _ti = _topic_to_int(_t)
            _topics.append("0x" + (int(_ti).to_bytes(32, "big").hex() if _ti is not None else "00" * 32))
    except Exception:
        _topics = []
    _data = log.get("data", "")
    _data = _data if isinstance(_data, str) and _data.startswith("0x") else "0x" + (str(_data) if isinstance(_data, str) else "")
    return {"address": log.get("address", ""), "topics": _topics, "data": _data,
            "blockHash": block_hash, "blockNumber": block_number,
            "transactionHash": tx_hash, "transactionIndex": tx_index,
            "logIndex": hex(log_index), "removed": False}


def _eth_sig_fields(tx: dict):
    # R8-rpc-meta (R7-23): real ECDSA v/r/s for raw Ethereum transactions
    # (decoded from the stored raw signature). Native Munex signatures
    # (64-byte r||s, no recovery id) have no eth v/r/s — return nulls
    # rather than the old constant 0x1b/0x0/0x0 fabrication.
    from node.chain import decode_raw_eth_transaction  # lazy: forward ref, runtime-only
    try:
        sig = tx.get('signature', '')
        if isinstance(sig, str) and (sig.startswith('0x') or len(sig) > 130):
            decoded = decode_raw_eth_transaction(sig)
            v = int(decoded.get('v', 0) or 0)
            r = int(decoded.get('r', 0) or 0)
            s = int(decoded.get('s', 0) or 0)
            if v and r and s:
                return hex(v), hex(r), hex(s)
    except Exception:
        pass
    return None, None, None


def _logs_bloom(logs) -> str:
    # R8-rpc-meta (R7-23): real 2048-bit logs bloom (Yellow Paper / geth
    # bloom.go shape): for the address and each topic, keccak the bytes;
    # for each of 3 two-byte windows set bit (BE16 & 2047), byte
    # 255-(pos>>3), mask 1<<(pos&7). Empty log set -> zero bloom.
    # Residual risk: no mainnet receipt vector available offline to
    # cross-check beyond the structural + hand-recomputed test.
    try:
        arr = bytearray(256)
        items = []
        for log in (logs or []):
            if not isinstance(log, dict):
                continue
            try:
                items.append(bytes.fromhex(str(log.get('address', '')).removeprefix('0x')))
            except (ValueError, AttributeError):
                pass
            for _t in (log.get('topics') or []):
                try:
                    _ti = _topic_to_int(_t)
                    if _ti is None:
                        continue
                    items.append(int(_ti).to_bytes(32, 'big'))
                except Exception:
                    continue
        for _x in items:
            try:
                _h = eth_keccak(bytes(_x))
            except Exception:
                continue
            for _k in range(3):
                _pos = (_h[2 * _k] * 256 + _h[2 * _k + 1]) & 2047
                arr[255 - (_pos >> 3)] |= (1 << (_pos & 7))
        return "0x" + bytes(arr).hex()
    except Exception:
        return "0x" + "00" * 256


def _cumulative_gas_used(ordered_pairs, tx_hash) -> int:
    # R8-rpc-meta (R7-23): cumulative gas = sum of gas_used up to and
    # including tx_hash in block order. ordered_pairs: [(hash, gas)].
    try:
        _total = 0
        for _h, _g in ordered_pairs:
            _total += int(_g or 0)
            if _h == tx_hash:
                return _total
    except Exception:
        pass
    return 0


async def _block_gas_used(db, block_id: int) -> int:
    # R8-rpc-meta (R7-23): a block's real gasUsed = sum of its receipts'
    # gas_used (0 when no receipts recorded).
    try:
        if db.db_type == "sqlite":
            _row = await db.fetchrow(
                "SELECT COALESCE(SUM(gas_used),0) AS s FROM transaction_receipts WHERE block_id = ?",
                block_id)
        else:
            _row = await db.fetchrow(
                "SELECT COALESCE(SUM(gas_used),0) AS s FROM transaction_receipts WHERE block_id = $1",
                block_id)
        return int((_row['s'] if _row else 0) or 0)
    except Exception:
        return 0


def _tx_lists_consistent(tx_hashes, tx_list):
    # R9-txbind (I-R8-08): the committed tx_hashes sequence must EXACTLY
    # equal the ordered envelope hashes — otherwise a block can commit one
    # listing while executing another (receipts/indices/explorers then
    # disagree with execution). Returns (True, "") or (False, reason).
    # Envelope content integrity itself is covered by per-tx signature
    # checks (raw: hash equality; native: message signature); this binds
    # the two SEQUENCES. Chain reset: acceptance change.
    try:
        if not isinstance(tx_hashes, list) or not isinstance(tx_list, list):
            return False, "not lists"
        if len(tx_hashes) != len(tx_list):
            return False, "length mismatch"
        for _h, _t in zip(tx_hashes, tx_list):
            if not isinstance(_t, dict) or _t.get("tx_hash") != _h:
                return False, "ordered hash mismatch"
    except Exception:
        return False, "uncomparable"
    return True, ""


def compute_merkle_root(tx_hashes: list) -> str:
    if not tx_hashes:
        return "0" * 64
    # Raw Ethereum tx hashes are 0x-prefixed; fromhex() raises at position 1
    # on the 'x'. The same normalization runs on the verify side (same
    # function), so builder and verifier always agree.
    level = [
        bytes.fromhex(h[2:] if isinstance(h, str) and h[:2].lower() == "0x" else h)
        for h in tx_hashes
    ]
    while len(level) > 1:
        # MERKLE-1a: promote an odd trailing node unchanged instead of
        # duplicating it (Bitcoin-style duplication is a second-preimage /
        # malleability source).
        carry = level.pop() if len(level) % 2 == 1 else None
        level = [eth_keccak(level[i] + level[i + 1]) for i in range(0, len(level), 2)]
        if carry is not None:
            level.append(carry)
    return level[0].hex()

def _s256(x: int) -> int:
    """Interpret a 256-bit word as two's-complement signed (EVM-OPS)."""
    return x - (1 << 256) if x >= (1 << 255) else x

# ─── Address functions ──────────────────────────────────
def pubkey_to_address(pub_hex: str) -> str:
    pub_hex = pub_hex.removeprefix("0x")
    if pub_hex.startswith("04"):
        pub_bytes = bytes.fromhex(pub_hex)
        if len(pub_bytes) != 65 or pub_bytes[0] != 0x04:
            raise ValueError("Expected an uncompressed secp256k1 public key")
        return "0x" + eth_keccak(pub_bytes[1:])[-20:].hex()
    return pub_hex if pub_hex.startswith("0x") else "0x" + pub_hex

def checksum_address(addr: str) -> str:
    raw = addr.lower().removeprefix("0x")
    if len(raw) != 40 or not all(ch in "0123456789abcdef" for ch in raw):
        raise ValueError("Invalid address")
    digest = eth_keccak(raw.encode("ascii")).hex()
    return "0x" + "".join(
        ch.upper() if ch in "abcdef" and int(digest[i], 16) >= 8 else ch
        for i, ch in enumerate(raw)
    )

# ─── CORS origin gate ─────────────────────────────────────
# CORS fix: node REST/RPC responses must never carry a wildcard origin
# (any webpage could read balances / drive a node's API from a victim
# browser). Only loopback dev origins are echoed back. The munex-site
# frontend talks to the node through a cloud proxy, so no cross-origin
# wildcard is required.
_LOCALHOST_ORIGIN_RE = re.compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$")

def _cors_origin_allowed(origin) -> bool:
    if not origin or not isinstance(origin, str):
        return False
    return bool(_LOCALHOST_ORIGIN_RE.match(origin))


def _validate_ws_bind(ws_bind_ip, ws_port, api_port):
    """ESP-WS-1: validate the miner-WebSocket listener before binding.
    Returns (bind_ip, ws_port, api_port) with ports as ints. Raises
    ValueError naming the bad value (fail clearly instead of an asyncio
    bind traceback). `0.0.0.0`/`::`/''/`all` = all interfaces (LAN miners);
    otherwise a valid IPv4/IPv6 literal is required (hostnames are NOT
    resolved here — put an IP literal or the wildcard in config)."""
    _bind = str(ws_bind_ip if ws_bind_ip not in (None, "") else "0.0.0.0")
    if _bind.lower() == "all":
        _bind = "0.0.0.0"
    if _bind not in ("0.0.0.0", "::"):
        try:
            ipaddress.ip_address(_bind)
        except ValueError:
            raise ValueError(
                f"node.ws_bind_ip must be 0.0.0.0, ::, or a valid IP literal, got {_bind!r}")
    for _name, _p in (("node.ws_port", ws_port), ("node.api_port", api_port)):
        if isinstance(_p, bool):
            raise ValueError(f"{_name} must be an integer port 1..65535, got {_p!r}")
        try:
            _pi = int(str(_p).strip()) if isinstance(_p, str) else int(_p)
        except (TypeError, ValueError):
            raise ValueError(f"{_name} must be an integer port 1..65535, got {_p!r}")
        if isinstance(_p, float) or not 1 <= _pi <= 65535:
            raise ValueError(f"{_name} must be an integer port 1..65535, got {_p!r}")
    return _bind, int(ws_port), int(api_port)


def _detect_lan_ip() -> str:
    """Best-effort LAN IPv4 for log lines (UDP connect trick; no traffic
    sent). Falls back to loopback. Pure best-effort; never raises."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
        return lan_ip or "127.0.0.1"
    except Exception:
        return "127.0.0.1"


class _BadInt(ValueError):
    """Raised by _rint/_rfloat with the offending field name as arg."""


def _rint(data, key, default=0):
    """Strict int for REST fields (J6 audit): garbage yields _BadInt
    (callers answer 400) instead of an unhandled 500."""
    try:
        return int(data.get(key, default))
    except (TypeError, ValueError):
        raise _BadInt(key)


def _rfloat_opt(data, key):
    """Optional float field; None when absent, _BadInt on garbage."""
    if key not in data:
        return None
    try:
        return float(data.get(key))
    except (TypeError, ValueError):
        raise _BadInt(key)


def _ws_page_params(data):
    """Bounded pagination for WS list routes (J5a audit): limit coerced
    to int in [1,500] (default 10), offset clamped >= 0 (default 0).
    Unbounded/garbage values previously drove multi-MB dumps or DB errors."""
    try:
        _lim = int(data.get("limit", 10))
    except (TypeError, ValueError):
        _lim = 10
    try:
        _off = int(data.get("offset", 0))
    except (TypeError, ValueError):
        _off = 0
    return max(1, min(_lim, 500)), max(0, _off)


def _ws_health_handler(request):
    """ESP-WS-1: minimal transport diagnostic on the PUBLIC miner-WS app.
    Exact contract {"status": "ok", "service": "mcx-miner-ws"} — nothing
    else may ever appear here (no secrets, config, wallet, chain or peer
    data of any kind)."""
    from aiohttp import web
    return web.json_response({"status": "ok", "service": "mcx-miner-ws"})


def _ws_app_routes(app, websocket_handler):
    """Register the public miner-WS app routes in one place (keeps the
    route table reviewable and unit-testable without booting a node)."""
    app.router.add_get('/ws', websocket_handler)
    app.router.add_get('/healthz', _ws_health_handler)
    return app


def _rpc_bearer_token(config) -> str:
    """RPC-AUTH-1: operator token from MCX_RPC_TOKEN env or node.rpc_token
    config (env wins). Empty = unset. Never logged."""
    try:
        _env = (os.environ.get("MCX_RPC_TOKEN", "") or "").strip()
        if _env:
            return _env
        return str((((config or {}).get('node', {}) or {}).get('rpc_token', "")) or "").strip()
    except Exception:
        return ""


_RPC_TRUST_BAD_LOGGED = False


# FP1-NULL-1: sentinel distinguishing "key absent" (legacy default True)
# from "key present with any value, including explicit null" (must parse
# strictly; None/invalid fails closed). _strict_bool maps None -> default,
# so returning None here would silently trust an explicit null.
_RPC_TRUST_ABSENT = object()


def _rpc_trust_loopback_raw(config):
    """Raw node.rpc_trust_loopback value (_RPC_TRUST_ABSENT = absent).
    Non-dict config or node section counts as absent (legacy default)."""
    node = config.get('node') if isinstance(config, dict) else None
    if not isinstance(node, dict):
        return _RPC_TRUST_ABSENT
    return node['rpc_trust_loopback'] if 'rpc_trust_loopback' in node else _RPC_TRUST_ABSENT


def validate_rpc_security_config(config) -> None:
    """RPC-LOOPBACK-STRICT-1: boot-time validation. Raises ValueError for a
    node.rpc_trust_loopback that is not a bool / "true" / "false" (CONFIG-BOOL-1
    rules), so a mistyped security flag fails clearly instead of silently.
    FP1-NULL-1: an absent key keeps the legacy default (no raise); an
    explicit null is malformed and raises like any invalid value."""
    _raw = _rpc_trust_loopback_raw(config)
    if _raw is _RPC_TRUST_ABSENT:
        return
    # FP1-NULL-1: _strict_bool maps None -> default, so an explicit null
    # must be rejected here, not passed through (it would silently trust).
    if _raw is None:
        raise ValueError("config node.rpc_trust_loopback must be a boolean (true/false), got None (explicit null is malformed; omit the key for the legacy default)")
    _strict_bool('node.rpc_trust_loopback', _raw, True)


def _rpc_trust_loopback_effective(config) -> bool:
    """RPC-LOOPBACK-STRICT-1: strict parse; absent -> True (legacy default).
    An INVALID value fails CLOSED (loopback not trusted; bearer token
    required) — it used to be bool(...), so the string "false" kept loopback
    trusted, and any parse error returned True."""
    global _RPC_TRUST_BAD_LOGGED
    # FP1-NULL-1: absent -> legacy default True; explicit null/invalid ->
    # fail closed (loopback not trusted, bearer required).
    _raw_eff = _rpc_trust_loopback_raw(config)
    if _raw_eff is _RPC_TRUST_ABSENT:
        return True
    # FP1-NULL-1: explicit null fails closed (see validate path).
    if _raw_eff is None:
        if not _RPC_TRUST_BAD_LOGGED:
            _RPC_TRUST_BAD_LOGGED = True
            logger.error("[RPC-AUTH] config node.rpc_trust_loopback is null (malformed) — failing closed: loopback NOT trusted, bearer token required")
        return False
    try:
        return _strict_bool('node.rpc_trust_loopback', _raw_eff, True)
    except ValueError as _e:
        if not _RPC_TRUST_BAD_LOGGED:
            _RPC_TRUST_BAD_LOGGED = True
            logger.error(f"[RPC-AUTH] {_e} — failing closed: loopback NOT trusted, bearer token required")
        return False


def _rpc_remote_authorized(request, config) -> bool:
    """RPC-AUTH-1: loopback clients are always trusted (local wallets and
    tools work unchanged, no token needed). Non-loopback clients must
    present the configured Bearer token, compared constant-time. Unknown
    remote address or no token configured -> denied. Pure apart from env/
    config reads; unit-testable with request fakes (needs .remote and
    .headers.get)."""
    try:
        if ipaddress.ip_address(request.remote or "").is_loopback:
            # RPC-LOOPBACK-1 (mainnet audit): loopback trust is explicit
            # operator config, not an accident of binding. Default true
            # preserves local-wallet behavior; a same-host reverse proxy
            # otherwise inherits trust silently (any local process dialing
            # 127.0.0.1 bypasses the bearer gate). Proxy deployments must
            # set node.rpc_trust_loopback=false and use bearer tokens.
            if _rpc_trust_loopback_effective(config):
                return True
    except ValueError:
        pass
    except Exception:
        return False
    want = _rpc_bearer_token(config)
    if not want:
        return False
    try:
        auth = (request.headers.get("Authorization", "") or "").strip()
    except Exception:
        return False
    if not auth.lower().startswith("bearer "):
        return False
    try:
        return hmac.compare_digest(auth[7:].strip(), want)
    except Exception:
        return False

# R8-mnemonic-bip39 (R7-24): the BIP-39 English wordlist (2048 words).
# Was a local variable of generate_mnemonic; hoisted so validation and
# tests share the exact list the generator draws from.
_BIP39_WORDS = ['abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse','access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act','action','actor','actress','actual','adapt','add','addict','address','adjust','admit','adult','advance','advice','aerobic','affair','afford','afraid','again','age','agent','agree','ahead','aim','air','airport','aisle','alarm','album','alcohol','alert','alien','all','alley','allow','almost','alone','alpha','already','also','alter','always','amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger','angle','angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety','any','apart','apology','appear','apple','approve','april','arch','arctic','area','arena','argue','arm','armed','armor','army','around','arrange','arrest','arrive','arrow','art','artefact','artist','artwork','ask','aspect','assault','asset','assist','assume','asthma','athlete','atom','attack','attend','attitude','attract','auction','audit','august','aunt','author','auto','autumn','average','avocado','avoid','awake','aware','away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge','bag','balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain','barrel','base','basic','basket','battle','beach','bean','beauty','because','become','beef','before','begin','behave','behind','believe','below','belt','bench','benefit','best','betray','better','between','beyond','bicycle','bid','bike','bind','biology','bird','birth','bitter','black','blade','blame','blanket','blast','bleak','bless','blind','blood','blossom','blouse','blue','blur','blush','board','boat','body','boil','bomb','bone','bonus','book','boost','border','boring','borrow','boss','bottom','bounce','box','boy','bracket','brain','brand','brass','brave','bread','breeze','brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze','broom','brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb','bulk','bullet','bundle','bunker','burden','burger','burst','bus','business','busy','butter','buyer','buzz','cabbage','cabin','cable','cactus','cage','cake','call','calm','camera','camp','can','canal','cancel','candy','cannon','canoe','canvas','canyon','capable','capital','captain','car','carbon','card','cargo','carpet','carry','cart','case','cash','casino','castle','casual','cat','catalog','catch','category','cattle','caught','cause','caution','cave','ceiling','celery','cement','census','century','cereal','certain','chair','chalk','champion','change','chaos','chapter','charge','chase','chat','cheap','check','cheese','chef','cherry','chest','chicken','chief','child','chimney','choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle','citizen','city','civil','claim','clap','clarify','claw','clay','clean','clerk','clever','click','client','cliff','climb','clinic','clip','clock','clog','close','cloth','cloud','clown','club','clump','cluster','clutch','coach','coast','coconut','code','coffee','coil','coin','collect','color','column','combine','come','comfort','comic','common','company','concert','conduct','confirm','congress','connect','consider','control','convince','cook','cool','copper','copy','coral','core','corn','correct','cost','cotton','couch','country','couple','course','cousin','cover','coyote','crack','cradle','craft','cram','crane','crash','crater','crawl','crazy','cream','credit','creek','crew','cricket','crime','crisp','critic','crop','cross','crouch','crowd','crucial','cruel','cruise','crumble','crunch','crush','cry','crystal','cube','culture','cup','cupboard','curious','current','curtain','curve','cushion','custom','cute','cycle','dad','damage','damp','dance','danger','daring','dash','daughter','dawn','day','deal','debate','debris','decade','december','decide','decline','decorate','decrease','deer','defense','define','defy','degree','delay','deliver','demand','demise','denial','dentist','deny','depart','depend','deposit','depth','deputy','derive','describe','desert','design','desk','despair','destroy','detail','detect','develop','device','devote','diagram','dial','diamond','diary','dice','diesel','diet','differ','digital','dignity','dilemma','dinner','dinosaur','direct','dirt','disagree','discover','disease','dish','dismiss','disorder','display','distance','divert','divide','divorce','dizzy','doctor','document','dog','doll','dolphin','domain','donate','donkey','donor','door','dose','double','dove','draft','dragon','drama','drastic','draw','dream','dress','drift','drill','drink','drip','drive','drop','drum','dry','duck','dumb','dune','during','dust','dutch','duty','dwarf','dynamic','eager','eagle','early','earn','earth','easily','east','easy','echo','ecology','economy','edge','edit','educate','effort','egg','eight','either','elbow','elder','electric','elegant','element','elephant','elevator','elite','else','embark','embody','embrace','emerge','emotion','employ','empower','empty','enable','enact','end','endless','endorse','enemy','energy','enforce','engage','engine','enhance','enjoy','enlist','enough','enrich','enroll','ensure','enter','entire','entry','envelope','episode','equal','equip','era','erase','erode','erosion','error','erupt','escape','essay','essence','estate','eternal','ethics','evidence','evil','evoke','evolve','exact','example','excess','exchange','excite','exclude','excuse','execute','exercise','exhaust','exhibit','exile','exist','exit','exotic','expand','expect','expire','explain','expose','express','extend','extra','eye','eyebrow','fabric','face','faculty','fade','faint','faith','fall','false','fame','family','famous','fan','fancy','fantasy','farm','fashion','fat','fatal','father','fatigue','fault','favorite','feature','february','federal','fee','feed','feel','female','fence','festival','fetch','fever','few','fiber','fiction','field','figure','file','film','filter','final','find','fine','finger','finish','fire','firm','first','fiscal','fish','fit','fitness','fix','flag','flame','flash','flat','flavor','flee','flight','flip','float','flock','floor','flower','fluid','flush','fly','foam','focus','fog','foil','fold','follow','food','foot','force','forest','forget','fork','fortune','forum','forward','fossil','foster','found','fox','fragile','frame','frequent','fresh','friend','fringe','frog','front','frost','frown','frozen','fruit','fuel','fun','funny','furnace','fury','future','gadget','gain','galaxy','gallery','game','gap','garage','garbage','garden','garlic','garment','gas','gasp','gate','gather','gauge','gaze','general','genius','genre','gentle','genuine','gesture','ghost','giant','gift','giggle','ginger','giraffe','girl','give','glad','glance','glare','glass','glide','glimpse','globe','gloom','glory','glove','glow','glue','goat','goddess','gold','good','goose','gorilla','gospel','gossip','govern','gown','grab','grace','grain','grant','grape','grass','gravity','great','green','grid','grief','grit','grocery','group','grow','grunt','guard','guess','guide','guilt','guitar','gun','gym','habit','hair','half','hammer','hamster','hand','happy','harbor','hard','harsh','harvest','hat','have','hawk','hazard','head','health','heart','heavy','hedgehog','height','hello','helmet','help','hen','hero','hidden','high','hill','hint','hip','hire','history','hobby','hockey','hold','hole','holiday','hollow','home','honey','hood','hope','horn','horror','horse','hospital','host','hotel','hour','hover','hub','human','humble','humor','hundred','hungry','hunt','hurdle','hurry','hurt','husband','hybrid','ice','icon','idea','identify','idle','ignore','ill','illegal','illness','image','imitate','immense','immune','impact','impose','improve','impulse','inch','include','income','increase','index','indicate','indoor','industry','infant','inflict','inform','inhale','inherit','initial','inject','injury','inmate','inner','innocent','input','inquiry','insane','insect','inside','inspire','install','intact','interest','into','invest','invite','involve','iron','island','isolate','issue','item','ivory','jacket','jaguar','jar','jazz','jealous','jeans','jelly','jewel','job','join','joke','journey','joy','judge','juice','jump','jungle','junior','junk','just','kangaroo','keen','keep','ketchup','key','kick','kid','kidney','kind','kingdom','kiss','kit','kitchen','kite','kitten','kiwi','knee','knife','knock','know','lab','label','labor','ladder','lady','lake','lamp','language','laptop','large','later','latin','laugh','laundry','lava','law','lawn','lawsuit','layer','lazy','leader','leaf','learn','leave','lecture','left','leg','legal','legend','leisure','lemon','lend','length','lens','leopard','lesson','letter','level','liar','liberty','library','license','life','lift','light','like','limb','limit','link','lion','liquid','list','little','live','lizard','load','loan','lobster','local','lock','logic','lonely','long','loop','lottery','loud','lounge','love','loyal','lucky','luggage','lumber','lunar','lunch','luxury','lyrics','machine','mad','magic','magnet','maid','mail','main','major','make','mammal','man','manage','mandate','mango','mansion','manual','maple','marble','march','margin','marine','market','marriage','mask','mass','master','match','material','math','matrix','matter','maximum','maze','meadow','mean','measure','meat','mechanic','medal','media','melody','melt','member','memory','mention','menu','mercy','merge','merit','merry','mesh','message','metal','method','middle','midnight','milk','million','mimic','mind','minimum','minor','minute','miracle','mirror','misery','miss','mistake','mix','mixed','mixture','mobile','model','modify','mom','moment','monitor','monkey','monster','month','moon','moral','more','morning','mosquito','mother','motion','motor','mountain','mouse','move','movie','much','muffin','mule','multiply','muscle','museum','mushroom','music','must','mutual','myself','mystery','myth','naive','name','napkin','narrow','nasty','nation','nature','near','neck','need','negative','neglect','neither','nephew','nerve','nest','net','network','neutral','never','news','next','nice','night','noble','noise','nominee','noodle','normal','north','nose','notable','note','nothing','notice','novel','now','nuclear','number','nurse','nut','oak','obey','object','oblige','obscure','observe','obtain','obvious','occur','ocean','october','odor','off','offer','office','often','oil','okay','old','olive','olympic','omit','once','one','onion','online','only','open','opera','opinion','oppose','option','orange','orbit','orchard','order','ordinary','organ','orient','original','orphan','ostrich','other','outdoor','outer','output','outside','oval','oven','over','own','owner','oxygen','oyster','ozone','pact','paddle','page','pair','palace','palm','panda','panel','panic','panther','paper','parade','parent','park','parrot','party','pass','patch','path','patient','patrol','pattern','pause','pave','payment','peace','peanut','pear','peasant','pelican','pen','penalty','pencil','people','pepper','perfect','permit','person','pet','phone','photo','phrase','physical','piano','picnic','picture','piece','pig','pigeon','pill','pilot','pink','pioneer','pipe','pistol','pitch','pizza','place','planet','plastic','plate','plaza','please','pledge','pluck','plug','plunge','poem','poet','point','polar','pole','police','pond','pony','pool','popular','portion','position','possible','post','potato','pottery','poverty','powder','power','practice','praise','predict','prefer','prepare','present','pretty','prevent','price','pride','primary','print','priority','prison','private','prize','problem','process','produce','profit','program','project','promote','proof','property','prosper','protect','proud','provide','public','pudding','pull','pulp','pulse','pumpkin','punch','pupil','puppy','purchase','purity','purpose','purse','push','put','puzzle','pyramid','quality','quantum','quarter','question','quick','quit','quiz','quote','rabbit','raccoon','race','rack','radar','radio','rail','rain','raise','rally','ramp','ranch','random','range','rapid','rare','rate','rather','raven','raw','razor','ready','real','reason','rebel','rebuild','recall','receive','recipe','record','recycle','reduce','reflect','reform','refuse','region','regret','regular','reject','relax','release','relief','rely','remain','remember','remind','remove','render','renew','rent','reopen','repair','repeat','replace','report','require','rescue','resemble','resist','resource','response','result','retire','retreat','return','reunion','reveal','review','revolution','reward','rhythm','rib','ribbon','rice','rich','ride','ridge','rifle','right','rigid','ring','riot','ripple','risk','ritual','rival','river','road','roast','robot','robust','rocket','romance','roof','rookie','room','rose','rotate','rough','round','route','royal','rubber','rude','rug','rule','run','runway','rural','sad','saddle','sadness','safe','sail','salad','salmon','salon','salt','salute','same','sample','sand','satisfy','satoshi','sauce','sausage','save','say','scale','scan','scare','scatter','scene','scheme','school','science','scissors','scorpion','scout','scrap','screen','script','scrub','sea','search','season','seat','second','secret','section','security','seed','seek','segment','select','sell','seminar','senior','sense','sentence','series','service','session','settle','setup','seven','shadow','shaft','shallow','share','shed','shell','sheriff','shield','shift','shine','ship','shiver','shock','shoe','shoot','shop','short','shoulder','shove','shrimp','shrug','shuffle','shy','sibling','sick','side','siege','sight','sign','silent','silk','silly','silver','similar','simple','since','sing','siren','sister','situate','six','size','skate','sketch','ski','skill','skin','skirt','skull','slab','slam','sleep','slender','slice','slide','slight','slim','slogan','slot','slow','slush','small','smart','smile','smoke','smooth','snack','snake','snap','sniff','snow','soap','soccer','social','sock','soda','soft','solar','soldier','solid','solution','solve','someone','song','soon','sorry','sort','soul','sound','soup','source','south','space','spare','spatial','spawn','speak','special','speed','spell','spend','sphere','spice','spider','spike','spin','spirit','split','spoil','sponsor','spoon','sport','spot','spray','spread','spring','spy','square','squeeze','squirrel','stable','stadium','staff','stage','stairs','stamp','stand','start','state','stay','steak','steel','stem','step','stereo','stick','still','sting','stock','stomach','stone','stool','story','stove','strategy','street','strike','strong','struggle','student','stuff','stumble','style','subject','submit','subway','success','such','sudden','suffer','sugar','suggest','suit','summer','sun','sunny','sunset','super','supply','supreme','sure','surface','surge','surprise','surround','survey','suspect','sustain','swallow','swamp','swap','swarm','swear','sweet','swift','swim','swing','switch','sword','symbol','symptom','syrup','system','table','tackle','tag','tail','talent','talk','tank','tape','target','task','taste','tattoo','taxi','teach','team','tell','ten','tenant','tennis','tent','term','test','text','thank','that','theme','then','theory','there','they','thing','this','thought','three','thrive','throw','thumb','thunder','ticket','tide','tiger','tilt','timber','time','tiny','tip','tired','tissue','title','toast','tobacco','today','toddler','toe','together','toilet','token','tomato','tomorrow','tone','tongue','tonight','tool','tooth','top','topic','topple','torch','tornado','tortoise','toss','total','tourist','toward','tower','town','toy','track','trade','traffic','tragic','train','transfer','trap','trash','travel','tray','treat','tree','trend','trial','tribe','trick','trigger','trim','trip','trophy','trouble','truck','true','truly','trumpet','trust','truth','try','tube','tuition','tumble','tuna','tunnel','turkey','turn','turtle','twelve','twenty','twice','twin','twist','two','type','typical','ugly','umbrella','unable','unaware','uncle','uncover','under','undo','unfair','unfold','unhappy','uniform','unique','unit','universe','unknown','unlock','until','unusual','unveil','update','upgrade','uphold','upon','upper','upset','urban','urge','usage','use','used','useful','useless','usual','utility','vacant','vacuum','vague','valid','valley','valve','van','vanish','vapor','various','vast','vault','vehicle','velvet','vendor','venture','venue','verb','verify','version','very','vessel','veteran','viable','vibrant','vicious','victory','video','view','village','vintage','violin','virtual','virus','visa','visit','visual','vital','vivid','vocal','voice','void','volcano','volume','vote','voyage','wage','wagon','wait','walk','wall','walnut','want','warfare','warm','warrior','wash','wasp','waste','water','wave','way','wealth','weapon','wear','weasel','weather','web','wedding','weekend','weird','welcome','west','wet','whale','what','wheat','wheel','when','where','whip','whisper','wide','width','wife','wild','will','win','window','wine','wing','wink','winner','winter','wire','wisdom','wise','wish','witness','wolf','woman','wonder','wood','wool','word','work','world','worry','worth','wrap','wreck','wrestle','wrist','write','wrong','yard','year','yellow','you','young','youth','zebra','zero','zone','zoo']
def entropy_to_mnemonic(entropy: bytes) -> str:
    # R8-mnemonic-bip39 (R7-24): BIP-39 construction — entropy bits plus
    # SHA256-checksum bits (ENT/32), split into 11-bit word indexes.
    # Strengths 128..256 bits (12/15/18/21/24 words).
    if len(entropy) * 8 not in (128, 160, 192, 224, 256):
        raise ValueError("entropy must be 128/160/192/224/256 bits")
    _hash = hashlib.sha256(bytes(entropy)).digest()
    _bits = "".join(f"{_b:08b}" for _b in bytes(entropy))
    _bits += "".join(f"{_b:08b}" for _b in _hash)[:len(entropy) * 8 // 32]
    return " ".join(_BIP39_WORDS[int(_bits[_i:_i + 11], 2)] for _i in range(0, len(_bits), 11))


def validate_mnemonic(phrase) -> bool:
    # R8-mnemonic-bip39 (R7-24): wordlist membership + checksum verify.
    try:
        if not isinstance(phrase, str):
            return False
        _words = phrase.split(" ")
        if len(_words) not in (12, 15, 18, 21, 24):
            return False
        _bits = "".join(f"{_BIP39_WORDS.index(_w):011b}" for _w in _words)
    except (ValueError, AttributeError):
        return False
    _cs_len = len(_bits) // 33
    _ent_bits, _cs_bits = _bits[:-_cs_len], _bits[-_cs_len:]
    _ent = int(_ent_bits, 2).to_bytes(len(_ent_bits) // 8, "big")
    _expect = "".join(f"{_b:08b}" for _b in hashlib.sha256(_ent).digest())[:_cs_len]
    return _cs_bits == _expect


def generate_mnemonic(strength: int = 128) -> str:
    # R8-mnemonic-bip39 (R7-24): was 12 independent dictionary draws (no
    # entropy/checksum relation — rejected by standard wallet imports).
    # Now real BIP-39 from secrets-grade entropy; default 12 words.
    if strength not in (128, 160, 192, 224, 256):
        raise ValueError("strength must be one of 128/160/192/224/256")
    return entropy_to_mnemonic(secrets.token_bytes(strength // 8))

def mnemonic_to_seed(mnemonic, passphrase=""):
    kdf = PBKDF2HMAC(hashes.SHA512(), length=64, salt=("mnemonic"+passphrase).encode(), iterations=2048)
    return kdf.derive(mnemonic.encode())

def derive_wallet_from_seed(seed_bytes, path="m/44'/60'/0'/0/0"):
    # R6-wallet-derivation-fix: single HD path only; the master-IL fallback derived different wallets per install state.
    if bip32utils is None:
        sys.stderr.write("[WALLET] FATAL: bip32utils is required for seed-phrase derivation (refusing to derive an incompatible wallet)\n")
        sys.stderr.flush()
        sys.exit(1)
    master = bip32utils.BIP32Key.fromEntropy(seed_bytes)
    parts = path[2:].split('/')
    key = master
    for part in parts:
        if part.endswith("'"):
            index = int(part[:-1]) + 0x80000000
        else:
            index = int(part)
        key = key.ChildKey(index)
    priv_bytes = key.PrivateKey()
    priv_int = int.from_bytes(priv_bytes, 'big')
    priv_key = ec.derive_private_key(priv_int, ec.SECP256K1())
    pub = priv_key.public_key()
    pub_bytes = pub.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    pub_hex = pub_bytes.hex()
    return pubkey_to_address(pub_hex), priv_bytes.hex(), pub_hex

def encrypt_private_key(priv_hex, password):
    # KEYSTORE-1: authenticated encryption (AES-256-GCM). Old format was
    # AES-128-CBC with no MAC — bit-flips in the ciphertext produced
    # different-but-plausible key blobs.
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    nonce = os.urandom(12)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encrypted = encryptor.update(priv_hex.encode()) + encryptor.finalize()
    argon_h = ph.hash(password) if ph else hashlib.sha256((password + salt.hex()).encode()).hexdigest()
    return {"salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
            "data": base64.b64encode(encrypted + encryptor.tag).decode(), "argon2_hash": argon_h}

def decrypt_private_key(encrypted, password):
    try:
        if ph and str(encrypted.get('argon2_hash', '')).startswith('$argon2'):
            ph.verify(encrypted['argon2_hash'], password)
        elif 'argon2_hash' in encrypted:
            salt_hex = base64.b64decode(encrypted['salt']).hex()
            expected = hashlib.sha256((password + salt_hex).encode()).hexdigest()
            if not hmac.compare_digest(str(encrypted['argon2_hash']), expected):
                raise ValueError("Invalid password")
    except Exception:
        raise ValueError("Invalid password")
    salt = base64.b64decode(encrypted["salt"])
    data = base64.b64decode(encrypted["data"])
    kdf = PBKDF2HMAC(hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    if "nonce" in encrypted:
        # KEYSTORE-1 current format: AES-256-GCM (authenticated)
        nonce = base64.b64decode(encrypted["nonce"])
        ct, tag = data[:-16], data[-16:]
        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        try:
            return (decryptor.update(ct) + decryptor.finalize()).decode()
        except Exception:
            raise ValueError("Invalid password")
    # Legacy pre-KEYSTORE-1 wallets (iv format): AES-128-CBC, still readable
    iv = base64.b64decode(encrypted["iv"])
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(data) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return (unpadder.update(decrypted) + unpadder.finalize()).decode()


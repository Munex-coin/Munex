# Split of MCX81.py (lines 10072-12532). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import MLKEM_AVAILABLE, logger, mlkem
from node.config import ASN_STATIC_MAP, BAN_THRESHOLD, BIND_IP, BOOTSTRAP_NODES, CHAIN_ID, CHECKPOINT_SYNC_THRESHOLD, CONFIG, DHT_BOOTSTRAP_NODES, DHT_ENTRY_TTL, DHT_MAX_ENTRIES_PER_SHARD, DHT_PEERS_KEY_PREFIX, DHT_PORT, DHT_SHARD_COUNT, DISCOVERY_INTERVAL, DNS_SEEDS, EXTERNAL_IP, FINALITY_EPOCH_LENGTH, GENESIS_NODE_DHT_PORT, GENESIS_NODE_HOST, GENESIS_NODE_P2P_PORT, HEARTBEAT_INTERVAL, MAX_PEERS, MAZE_ROW_COLS, P2P_MAGIC, SYNC_INTERVAL, SYNC_STUCK_TRIP_COOLDOWN, VERSION, _MOVE_ROW_SAFE_COLS, _strict_bool
from node.genesis import MSG_BAN, MSG_BLOCKS, MSG_CHECKPOINT, MSG_GET_BLOCKS, MSG_GET_CHECKPOINT, MSG_GET_PEERS, MSG_GET_STATUS, MSG_NEW_BLOCK, MSG_NEW_MOVE, MSG_NEW_TX, MSG_PEERS, MSG_PING, MSG_PONG, MSG_SLASH, MSG_STATUS, MSG_UNBAN, _write_genesis_file_atomic, genesis_export_verified
from node.crypto import pubkey_to_address, sign_message, verify_signature, verify_signature_bytes
from node.chain import load_peers_from_cache, save_peers_to_cache
from node.database import PeerBanRepo
from node.bootstrap import AESGCM, Dict, HKDF, InvalidTag, List, Optional, OrderedDict, Set, ThreadPoolExecutor, Tuple, asyncio, dataclass, datetime, default_backend, defaultdict, deque, ec, field, hashes, hashlib, ipaddress, json, os, random, serialization, socket, struct, time
from node import config as _config
from node import genesis as _genesis


POW_BASE_DIFFICULTY = 5

# ─── DHT (Kademlia) Integration ──────────────────────────────
try:
    from kademlia.network import Server
    from kademlia.storage import ForgetfulStorage
    DHT_AVAILABLE = True
except ImportError:
    DHT_AVAILABLE = False
    logger.warning("[DHT] kademlia not installed. Falling back to peers cache.")

# ─── Encrypted Peer ────────────────────────────────────────────
@dataclass
class EncryptedPeer:
    """Represents an encrypted P2P connection."""
    address: str                      # "ip:port"
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    send_key: bytes                   # AES-GCM key for sending
    recv_key: bytes                   # AES-GCM key for receiving
    send_nonce: int                   # 12-byte nonce counter (incremented)
    recv_nonce: int
    session_id: bytes                 # 16-byte random session ID
    node_id: str                      # remote node ID
    pub: str                          # remote static (long-term) public key hex
    height: int                       # remote blockchain height
    version: str                      # remote version
    last_seen: float
    p2p_port: int = 8081              # remote listening port
    score: int = 0                    # reputation score
    banned: bool = False
    write_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    pqe: bool = False
    send_queue: asyncio.PriorityQueue = field(
        default_factory=lambda: asyncio.PriorityQueue(maxsize=1000))
    _send_counter: int = 0

    def encrypt_message(self, payload: bytes) -> bytes:
        nonce = self.send_nonce.to_bytes(12, 'big')
        self.send_nonce += 1
        aesgcm = AESGCM(self.send_key)
        return aesgcm.encrypt(nonce, payload, self.session_id + b'\x00'*4)

    def decrypt_message(self, ciphertext: bytes) -> Optional[bytes]:
        nonce = self.recv_nonce.to_bytes(12, 'big')
        self.recv_nonce += 1
        aesgcm = AESGCM(self.recv_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, self.session_id + b'\x00'*4)
        except InvalidTag:
            return None


def parse_ip_port(addr: str, default_port: int = 8081) -> Tuple[str, int]:
    """Parse host and port supporting IPv4, IPv6 ([ipv6]:port), and hostnames."""
    addr = str(addr).strip()
    if addr.startswith("["):
        end_bracket = addr.find("]")
        if end_bracket != -1:
            host = addr[1:end_bracket]
            rest = addr[end_bracket + 1:]
            if rest.startswith(":"):
                try:
                    return host, int(rest[1:])
                except ValueError:
                    pass
            return host, default_port
    if ":" in addr:
        parts = addr.rsplit(":", 1)
        try:
            return parts[0], int(parts[1])
        except ValueError:
            return addr, default_port
    return addr, default_port


def _mutual_dial_keep(local_id, remote_id) -> bool:
    # MUTUAL-DIAL-1 (pure tie-break): the socket dialed by the SMALLER
    # node_id survives at BOTH ends, so a simultaneous open keeps exactly
    # one socket. Returns True iff the local end keeps (local < remote).
    # Falsy/unknown ids and self-dial never keep: both ends close.
    # Partition property: for distinct truthy ids exactly one side keeps.
    try:
        if not local_id or not remote_id:
            return False
        if local_id == remote_id:
            return False
        return local_id < remote_id
    except TypeError:
        return False


def _dial_dup_action(local_id, remote_id, direction, loopback, has_existing) -> str:
    """DIAL-KEEPER-1 (pure): what to do with a freshly handshaked socket to
    a peer.  Returns 'register' | 'close_new' | 'replace_existing'.

    * No socket to this node_id yet -> 'register' (a LONE socket always
      survives, even if the other side never dials back: the partition fixed
      by MUTUAL-DIAL/DIAL-TIE-ONLY-DUP).
    * A duplicate exists:
        - off loopback          -> 'close_new' (unchanged generic behavior).
        - on loopback           -> the socket dialed by the SMALLER node_id is
          the keeper at BOTH ends.  If the new socket is the keeper it
          REPLACES the registered one; otherwise it is closed.  Both ends
          apply the same rule, so for every arrival order they converge on
          the same single socket.  (The previous 'close the second arrival'
          rule let each end keep a DIFFERENT socket in a true simultaneous
          open: both died and the pair redialed forever.)
    direction: 'in' (remote dialed us) or 'out' (we dialed)."""
    if not has_existing:
        return 'register'
    if not loopback:
        return 'close_new'
    if direction == 'in':
        keeper = _mutual_dial_keep(remote_id, local_id)
    else:
        keeper = _mutual_dial_keep(local_id, remote_id)
    return 'replace_existing' if keeper else 'close_new'


# ─── Handshake Implementation ──────────────────────────────────
async def perform_handshake(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                            my_node_id: str, my_height: int, my_version: str,
                            my_priv_key: str, my_pub_key: str,
                            allow_genesis_learn: bool = False) -> Optional[EncryptedPeer]:
    """Perform a Noise-like handshake over a raw TCP connection."""
    # Network magic check
    try:
        writer.write(P2P_MAGIC)
        await writer.drain()
        remote_magic = await reader.readexactly(4)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    if remote_magic != P2P_MAGIC:
        return None

    # Generate ephemeral key pair
    priv_ephemeral = ec.generate_private_key(ec.SECP256K1())
    pub_ephemeral = priv_ephemeral.public_key()
    pub_ephemeral_raw = pub_ephemeral.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )

    # Generate ephemeral NSA CNSA 2.0 ML-KEM-768 key pair if available
    priv_mlkem = None
    pub_mlkem_raw = b""
    if MLKEM_AVAILABLE:
        try:
            priv_mlkem = mlkem.MLKEM768PrivateKey.generate()
            pub_mlkem_raw = priv_mlkem.public_key().public_bytes_raw()
        except Exception:
            priv_mlkem = None

    # Step 1: Send ephemeral public key
    writer.write(struct.pack(">H", len(pub_ephemeral_raw)) + pub_ephemeral_raw)
    await writer.drain()

    # Step 2: Receive remote ephemeral public key
    try:
        len_data = await reader.readexactly(2)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    remote_pub_len = struct.unpack(">H", len_data)[0]
    if remote_pub_len < 33 or remote_pub_len > 65:
        return None
    try:
        remote_pub_raw = await reader.readexactly(remote_pub_len)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    try:
        remote_pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), remote_pub_raw)
    except Exception:
        return None

    # Compute shared secret (ECDH)
    shared_secret = priv_ephemeral.exchange(ec.ECDH(), remote_pub)

    # Derive keys using HKDF
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=80,
        salt=b"mcx_p2p_salt",
        info=b"mcx_p2p_handshake",
        backend=default_backend()
    )
    derived = hkdf.derive(shared_secret)
    key_lo = derived[:32]
    key_hi = derived[32:64]
    # Symmetry-breaking: compare ephemeral public keys
    if pub_ephemeral_raw < remote_pub_raw:
        send_key, recv_key = key_lo, key_hi
    else:
        send_key, recv_key = key_hi, key_lo

    session_id = derived[64:80]

    # Static-key proof-of-possession
    auth_message = f"{pub_ephemeral_raw.hex()}{session_id.hex()}{my_node_id}"
    auth_sig = sign_message(my_priv_key, auth_message)

    # Step 3: Send encrypted hello
    hello_dict = {
        "node_id": my_node_id,
        "height": my_height,
        "version": my_version,
        "session_id": session_id.hex(),
        "pub_key": my_pub_key,
        "auth_sig": auth_sig,
        "p2p_port": _config.P2P_PORT,
        "genesis_hash": _genesis._node_genesis_hash,
        "fork_id": _genesis.FORK_ID,
    }
    if not _genesis._node_genesis_hash:
        hello_dict["want_genesis"] = True
    if _genesis._node_genesis_hash and _genesis._node_genesis_data:
        hello_dict["genesis_body"] = _genesis._node_genesis_data
    if priv_mlkem:
        hello_dict["pqe"] = True
        hello_dict["pqe_pub"] = pub_mlkem_raw.hex()
    hello_payload = json.dumps(hello_dict).encode()
    aesgcm_send = AESGCM(send_key)
    nonce = b'\x00'*12
    encrypted_hello = aesgcm_send.encrypt(nonce, hello_payload, session_id + b'\x00'*4)
    writer.write(struct.pack(">I", len(encrypted_hello)) + encrypted_hello)
    await writer.drain()

    # Step 4: Receive remote hello
    try:
        len_data = await reader.readexactly(4)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    hello_len = struct.unpack(">I", len_data)[0]
    if hello_len <= 0 or hello_len > 65536:
        return None
    try:
        encrypted_remote_hello = await reader.readexactly(hello_len)
    except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
        return None
    aesgcm_recv = AESGCM(recv_key)
    try:
        remote_hello_data = aesgcm_recv.decrypt(nonce, encrypted_remote_hello, session_id + b'\x00'*4)
        remote_hello = json.loads(remote_hello_data.decode())
    except (InvalidTag, json.JSONDecodeError):
        return None

    if remote_hello.get("session_id") != session_id.hex():
        return None

    # Peer address for logging (must be before genesis check)
    peername = writer.get_extra_info('peername')
    if isinstance(peername, tuple):
        host = peername[0]
        port = peername[1]
        if host in ("101.127.80.48", GENESIS_NODE_HOST):
            host = GENESIS_NODE_HOST
        addr_str = f"[{host}]:{port}" if ":" in str(host) else f"{host}:{port}"
    else:
        addr_str = str(peername).replace("101.127.80.48", GENESIS_NODE_HOST)

    # Genesis negotiation
    remote_genesis = remote_hello.get("genesis_hash", "")
    remote_genesis_body = remote_hello.get("genesis_body")
    remote_want_genesis = remote_hello.get("want_genesis", False)
    if _genesis._node_genesis_hash and remote_genesis:
        if remote_genesis != _genesis._node_genesis_hash:
            logger.warning(f"[P2P] Peer genesis mismatch: peer={remote_genesis[:16]} local={_genesis._node_genesis_hash[:16]}")
            return None
    elif _genesis._node_genesis_hash and not remote_genesis:
        if remote_want_genesis:
            logger.info(f"[P2P] Peer {addr_str} has no genesis and requested it — accepting; peer will sync")
        else:
            logger.warning(f"[P2P] Peer handshake rejected: local genesis present, remote genesis empty (no want_genesis flag)")
            return None
    elif not _genesis._node_genesis_hash and remote_genesis:
        if not allow_genesis_learn:
            logger.info(f"[P2P] Peer {addr_str} offered genesis but this is not a bootstrap dial; ignoring")
            return None
        if os.path.exists(_genesis.GENESIS_FILE):
            logger.warning(f"[P2P] Refusing to overwrite existing {_genesis.GENESIS_FILE}")
            return None
        if not isinstance(remote_genesis_body, dict):
            logger.warning(f"[P2P] Peer {addr_str} has genesis but sent no body")
            return None
        if remote_genesis_body.get("hash") != remote_genesis:
            logger.warning(f"[P2P] genesis_body hash does not match hello hash")
            return None
        if int(remote_genesis_body.get("chain_id", 0)) != CHAIN_ID:
            logger.warning(f"[P2P] genesis_body chain_id mismatch")
            return None
        ok, why = genesis_export_verified(remote_genesis_body)
        if not ok:
            logger.warning(f"[P2P] Genesis verification failed: {why} (config.yaml consensus.*/vm.*/fees.*/p2p.ban_duration/validators must match the genesis creator's)")
            return None
        gh = remote_genesis_body.get("hash", "")
        if len(gh) != 64 or not all(c in "0123456789abcdef" for c in gh.lower()):
            logger.warning(f"[P2P] genesis_body hash format invalid")
            return None
        try:
            # GENESIS-LEARN-ATOMIC-1 (mainnet audit): learn through the
            # same atomic tmp+replace writer as every other genesis
            # path -- a crash mid-write must not leave half-JSON that
            # fails the next boot.
            _write_genesis_file_atomic(remote_genesis_body)
        except Exception as e:
            logger.error(f"[P2P] Failed to write {_genesis.GENESIS_FILE}: {e}")
            return None
        _genesis._node_genesis_hash = gh
        _genesis._node_genesis_data = remote_genesis_body
        _genesis.FORK_ID = int(gh[:8], 16) ^ int(gh[8:16], 16)
        logger.info(f"[P2P] Learned genesis from bootstrap {addr_str}: hash={gh[:16]}...")
    else:
        logger.warning(f"[P2P] Peer handshake rejected: both genesis empty")
        return None

    remote_fork_id = remote_hello.get("fork_id", 0)
    if remote_fork_id and _genesis.FORK_ID and remote_fork_id != _genesis.FORK_ID:
        logger.warning(f"[P2P] Peer fork_id mismatch: peer={remote_fork_id} local={_genesis.FORK_ID} (genesis hashes match, possible fork)")

    remote_node_id = remote_hello.get("node_id")
    remote_static_pub = remote_hello.get("pub_key")
    remote_auth_sig = remote_hello.get("auth_sig")
    if not remote_node_id or not remote_static_pub or not remote_auth_sig:
        logger.debug("[Handshake] Peer did not send identity proof — rejecting.")
        return None

    # (1) Self-consistent identity
    try:
        claimed = remote_node_id.lower()
        pub_b = bytes.fromhex(remote_static_pub.removeprefix("0x"))
        addr_keccak = pubkey_to_address(remote_static_pub).lower()
        addr_sha3 = ("0x" + hashlib.sha3_256(pub_b[1:]).digest()[-20:].hex()).lower()
        if claimed not in (addr_keccak, addr_sha3):
            logger.debug(f"[Handshake] node_id does not match claimed pubkey — rejecting (claimed {remote_node_id[:16]})")
            return None
    except Exception:
        return None

    # (2) Proof of possession
    remote_auth_message = f"{remote_pub_raw.hex()}{session_id.hex()}{remote_node_id}"
    if not verify_signature(remote_static_pub, remote_auth_message, remote_auth_sig):
        logger.debug(f"[Handshake] Identity signature failed — rejecting (claimed {remote_node_id[:16]})")
        return None

    # Step 5: Post-Quantum Key Exchange Upgrade (NSA CNSA 2.0 ML-KEM-768 Hybrid)
    pqe_active = False
    remote_pqe_pub_hex = remote_hello.get("pqe_pub")
    if priv_mlkem and remote_hello.get("pqe") and remote_pqe_pub_hex:
        try:
            remote_pqe_pub_bytes = bytes.fromhex(remote_pqe_pub_hex)
            remote_mlkem_pub = mlkem.MLKEM768PublicKey.from_public_bytes(remote_pqe_pub_bytes)

            ss_local, ct_local = remote_mlkem_pub.encapsulate()

            ct_nonce = b"\x01" * 12
            enc_ct_local = aesgcm_send.encrypt(ct_nonce, ct_local, session_id + b"PQE_EXCHANGE")
            writer.write(struct.pack(">I", len(enc_ct_local)) + enc_ct_local)
            await writer.drain()

            len_data = await reader.readexactly(4)
            ct_len = struct.unpack(">I", len_data)[0]
            if ct_len <= 0 or ct_len > 65536:
                return None
            enc_ct_remote = await reader.readexactly(ct_len)
            ct_remote = aesgcm_recv.decrypt(ct_nonce, enc_ct_remote, session_id + b"PQE_EXCHANGE")

            ss_remote = priv_mlkem.decapsulate(ct_remote)

            if pub_ephemeral_raw < remote_pub_raw:
                combined_secret = shared_secret + ss_local + ss_remote
            else:
                combined_secret = shared_secret + ss_remote + ss_local

            hkdf_pq = HKDF(
                algorithm=hashes.SHA384(),
                length=64,
                salt=b"mcx_nsa_cnsa2_pqe_salt",
                info=b"mcx_p2p_mlkem768_aes256gcm",
                backend=default_backend()
            )
            pq_derived = hkdf_pq.derive(combined_secret)
            if pub_ephemeral_raw < remote_pub_raw:
                send_key, recv_key = pq_derived[:32], pq_derived[32:64]
            else:
                send_key, recv_key = pq_derived[32:64], pq_derived[:32]
            pqe_active = True
            logger.info(f"[P2P] Established NSA CNSA 2.0 Hybrid PQE (ML-KEM-768 + SECP256K1 + AES-256-GCM) with {addr_str}")
        except Exception as e:
            logger.warning(f"[P2P] Post-quantum key exchange failed with {addr_str}: {e}")
            return None

    peer = EncryptedPeer(
        address=addr_str,
        reader=reader,
        writer=writer,
        send_key=send_key,
        recv_key=recv_key,
        send_nonce=1,
        recv_nonce=1,
        session_id=session_id,
        node_id=remote_node_id,
        pub=remote_static_pub,
        height=remote_hello.get("height", 0),
        version=remote_hello.get("version", "unknown"),
        last_seen=time.time(),
        p2p_port=remote_hello.get("p2p_port", _config.P2P_PORT),
        pqe=pqe_active,
    )
    return peer


# ─── P2P Node Class ────────────────────────────────────────────
def _ssrf_ip_blocked(ip_str: str) -> bool:
    """R4-ssrf-filter: True if this literal IP must never be dialed —
    private, loopback, link-local, reserved, multicast, or the cloud
    metadata address. Hostnames are resolved by the caller first."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            or ip_obj.is_reserved or ip_obj.is_multicast
            or str(ip_obj) == "169.254.169.254")


def _lan_dialable(ip_str: str) -> bool:
    """TESTNET-LAN-1: IPs a private-LAN test node may dial — RFC1918 and
    loopback only. Never link-local/reserved/multicast, never the cloud
    metadata address (defense in depth: it is link-local anyway)."""
    try:
        o = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if str(o) == "169.254.169.254":
        return False
    return bool(o.is_private or o.is_loopback)


async def _ssrf_allows_dial(h: str, p: int, local_ips, public_ip, allow_private: bool = False) -> Tuple[bool, str, object]:
    # R5-ssrf-async-resolve: resolve off the loop; return the first passing IP for dialing (allowed, reason, dial_ip|None).
    # TESTNET-LAN-1: allow_private (explicit p2p.allow_private_peers on a
    # NON-mainnet node only) additionally permits RFC1918/loopback targets.
    try:
        ipaddress.ip_address(h)
        dial_ips = [h]
    except ValueError:
        try:
            loop = asyncio.get_event_loop()
            _, _, dial_ips = await loop.run_in_executor(None, socket.gethostbyname_ex, h)
        except (OSError, UnicodeError):
            return False, f"unresolvable host {h}", None
        if not dial_ips:
            return False, f"unresolvable host {h}", None
    for dip in dial_ips:
        if _ssrf_ip_blocked(dip):
            if not (allow_private and _lan_dialable(dip)):
                continue
        if (dip in (local_ips or set()) or (public_ip and dip == public_ip)) and int(p or 0) == int(_config.P2P_PORT):
            continue
        return True, ("private-lan" if _lan_dialable(dip) and _ssrf_ip_blocked(dip) else "public"), dip
    return False, f"no dialable address for {h}", None


def resolve_seed_lists(p2p_cfg) -> tuple:
    """Operator-configured seeds win; documented defaults fill only ABSENT keys.

    Returns (genesis_node, dns_seeds, bootstrap_nodes, dht_bootstrap_nodes).
    Previously every list was force-prefixed with munexseed.duckdns.org even
    when the operator configured alternatives, so a private/testnet
    deployment kept dialing the default seed. An explicitly configured
    empty list is respected (isolated testnet/sim with zero seeds);
    defaults apply only when the key is ABSENT (None).
    """
    p2p_cfg = p2p_cfg or {}
    genesis_node = p2p_cfg.get('genesis_node', GENESIS_NODE_HOST) or GENESIS_NODE_HOST
    _cfg_dns = p2p_cfg.get('dns_seeds', None)
    dns_seeds = list(dict.fromkeys(_cfg_dns)) if _cfg_dns is not None else list(DNS_SEEDS)
    _cfg_boot = p2p_cfg.get('bootstrap_nodes', None)
    bootstrap_nodes = list(dict.fromkeys(_cfg_boot)) if _cfg_boot is not None else list(BOOTSTRAP_NODES)
    try:
        dht_port = int(p2p_cfg.get('dht_port', DHT_PORT))
    except (TypeError, ValueError):
        dht_port = DHT_PORT
    raw_dht = p2p_cfg.get('dht_bootstrap_nodes', None)
    if raw_dht is not None:
        dht = []
        for n in raw_dht:
            if isinstance(n, (list, tuple)) and len(n) == 2:
                dht.append((str(n[0]), int(n[1])))
            else:
                h, p = parse_ip_port(str(n), default_port=dht_port)
                dht.append((h, p))
        # Explicit list respected as-is (explicit empty = no DHT seeds).
    else:
        dht = [(parse_ip_port(b, default_port=dht_port)[0], dht_port)
               for b in bootstrap_nodes]
        # SEED-EMPTY-1: the public default DHT seed only backs an ABSENT
        # bootstrap_nodes key; an explicit empty list means "no seeds" and
        # must not silently dial the production network.
        if not dht and _cfg_boot is None:
            dht = [(GENESIS_NODE_HOST, GENESIS_NODE_DHT_PORT)]
    return genesis_node, dns_seeds, bootstrap_nodes, dht


class P2PNode:
    """Encrypted P2P networking with DNS seeding, DHT, and registry."""
    def __init__(self, node, db):
        self.node = node
        self.db = db
        self.peer_ban_repo = PeerBanRepo(db)
        self.peers: Dict[str, EncryptedPeer] = {}
        self.banned_peers: Dict[str, float] = {}
        self.banned_node_ids: Dict[str, float] = {}
        self._pending_checkpoint_requests: Dict[str, asyncio.Future] = {}
        self._lock = asyncio.Lock()
        self._server = None
        self._dht_server = None
        self._dht_task = None
        self._discovery_stop = asyncio.Event()

        self._metrics = {
            "messages_sent": 0,
            "messages_received": 0,
            "bytes_sent": 0,
            "bytes_received": 0,
            "connections": 0,
            "errors": 0,
            "peers_discovered": 0,
        }

        # ─── Mainnet Hardening ─────────────────────────────────────
        # Peer reputation scoring (enhanced)
        self.peer_scores: Dict[str, Dict] = {}  # address -> {score, breakdown, last_update}
        self.reputation_weights = {
            "valid_block": 2,
            "valid_tx": 1,
            "valid_peer_list": 1,
            "ping_response": 1,
            "invalid_message": -2,
            "decrypt_failed": -5,
            "oversized_message": -10,
            "protocol_violation": -15,
            "invalid_block": -20,
            "invalid_tx": -15,
        }
        self.score_decay_interval = 3600  # 1 hour
        self.max_positive_score = 100
        self.min_score_for_ban = -BAN_THRESHOLD

        # Gossip protocol rate limiting (per message type, per peer, per minute)
        self.rate_limits = {
            MSG_PING: (30, 60),          # 30 per minute
            MSG_GET_PEERS: (10, 60),     # 10 per minute
            MSG_GET_BLOCKS: (60, 60),    # 60 per minute
            MSG_GET_STATUS: (30, 60),    # 30 per minute
            MSG_GET_CHECKPOINT: (10, 60), # 10 per minute
            MSG_NEW_BLOCK: (100, 60),    # 100 per minute
            MSG_NEW_TX: (200, 60),       # 200 per minute
            MSG_NEW_MOVE: (1200, 60),     # 1200 per minute: gossip is live (F1) and the
                               # embedded miner bursts >5 moves/s; the old
                               # 300/min limit was sized when the handler was
                               # a no-op and dropped most real moves.
        }
        self.peer_message_counts: Dict[str, Dict[int, List[float]]] = {}  # addr -> msg_type -> [timestamps]

        # Gossip dedup caches: prevent reprocessing/relaying the same block or tx
        self._seen_block_hashes: OrderedDict = OrderedDict()
        self._seen_tx_hashes: OrderedDict = OrderedDict()
        self._seen_max = 8192
        self._bootstrap_cooldown_log_ts: Dict[str, float] = {}

        # Eclipse attack protection: track peer subnets/ASNs
        self.peer_subnets: Dict[str, str] = {}  # addr -> /24 subnet
        self.subnet_peer_count: Dict[str, int] = {}  # subnet -> count
        self.max_peers_per_subnet = int(CONFIG.get('p2p', {}).get('max_peers_per_subnet', 64))
        self.max_peers_per_asn = int(CONFIG.get('p2p', {}).get('max_peers_per_asn', 16))
        self.asn_cache: Dict[str, str] = {}  # ip -> asn
        self.peer_asns: Dict[str, str] = {}
        self.asn_peer_count: Dict[str, int] = {}

        # Initialize public_ip before local interface enumeration (N-2)
        self.public_ip = EXTERNAL_IP if EXTERNAL_IP else None

        # Local IPs discovery for robust self-dial suppression (N-2)
        self._local_ips: Set[str] = {"127.0.0.1", "localhost", "::1", "0.0.0.0", "::"}
        if BIND_IP and BIND_IP not in ("0.0.0.0", "::"):
            self._local_ips.add(BIND_IP)
        if self.public_ip:
            self._local_ips.add(self.public_ip)
        try:
            _hname = socket.gethostname()
            self._local_ips.add(socket.gethostbyname(_hname))
            for _ip in socket.gethostbyname_ex(_hname)[2]:
                self._local_ips.add(_ip)
        except Exception:
            pass

        # Handshake rate limiting
        self._pending_handshakes: Dict[str, int] = {}  # ip -> count of in-flight handshakes
        self._max_pending_handshakes = 4
        self._conn_per_ip: Dict[str, int] = {}  # ip -> established connection count
        self._max_conn_per_ip = 8
        self._handshake_rate_limiter: Dict[str, List[float]] = {}  # ip -> [timestamps]
        self._handshake_rate_limit = (30, 60)  # 30 per minute
        self._pqe_rate_limiter: Dict[str, List[float]] = {}  # ip -> [timestamps]
        self._pqe_rate_limit = (10, 60)  # 10 per minute

        # Short-lived connection tasks (peer loops, writers, sends, connects)
        # so shutdown() can cancel them before closing writers and thus keep
        # them from logging into the Section 9.4 shutdown tail.
        self._conn_tasks: set = set()
        # R8-peer-fanout (R7-06): cap concurrent outbound dials network-wide.
        self._dial_sem = asyncio.Semaphore(8)

        # PQC validation worker pool
        self.pqc_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="pqc-validate")

        # State pruning config
        self.state_pruning_enabled = CONFIG.get('consensus', {}).get('state_pruning', True)
        self.prune_interval = CONFIG.get('consensus', {}).get('prune_interval', 86400)  # daily
        self.max_state_age = CONFIG.get('consensus', {}).get('max_state_age', 2592000)  # 30 days

        # Fee market framework
        self.base_fee_per_gas = 10  # subs/gas
        self.target_gas_per_block = 5_000_000
        self.max_gas_per_block = _config.MAX_BLOCK_GAS   # BLOCK-GAS-1: single source of truth
        self.fee_history: deque = deque(maxlen=100)

        # Fork choice / reorg safety (live bound is genesis-bound
        # PRUNE_BLOCKS, enforced in _reorg_chain; see G1 note above)
        self.finality_epoch_length = FINALITY_EPOCH_LENGTH
        self.checkpoint_interval = CONFIG.get('consensus', {}).get('checkpoint_interval', 100)

        p2p_cfg = getattr(self.node, 'config', {}).get('p2p', {}) if self.node else CONFIG.get('p2p', {})
        # SEEDS-1: operator-configured seeds win (resolve_seed_lists); the
        # default seed is used only when the operator configured nothing.
        (self.genesis_node, self.dns_seeds, self.bootstrap_nodes,
         self.dht_bootstrap_nodes) = resolve_seed_lists(p2p_cfg)
        self.fallback_nodes = list(p2p_cfg.get('fallback_nodes', []))
        self.dht_port = int(p2p_cfg.get('dht_port', DHT_PORT))
        # TESTNET-LAN-1: explicitly enabled private-LAN testing. Forced OFF
        # on mainnet no matter what the config says (mainnet keeps the
        # SSRF private/loopback refusal).
        try:
            _node_mainnet = bool(((getattr(self.node, 'config', {}) or {}).get('node', {}) or {}).get('mainnet', False))
        except Exception:
            _node_mainnet = False
        self.allow_private_peers = _strict_bool('p2p.allow_private_peers', p2p_cfg.get('allow_private_peers', False)) and not _node_mainnet
        # DIAL-BACKOFF-1: per-address retry state for the peer-connection
        # path (see _dial_note_result). Bounded maps; entries reset on
        # success and pruned when the map grows.
        self._dial_backoff: Dict[str, float] = {}
        self._dial_fails: Dict[str, int] = {}
        self._dial_last_log: Dict[str, float] = {}
        self.max_peers = MAX_PEERS
        self.ban_threshold = BAN_THRESHOLD
        self.ban_duration = _config.BAN_DURATION
        self.gossip_fanout = 3
        self.config_discovery_interval = CONFIG.get('p2p', {}).get('discovery_interval', DISCOVERY_INTERVAL)

    def _track_task(self, t: "asyncio.Task") -> "asyncio.Task":
        """Track a short-lived connection task so shutdown can cancel it."""
        self._conn_tasks.add(t)
        t.add_done_callback(self._conn_tasks.discard)
        return t

    # ─── Start / Stop ──────────────────────────────────────────
    async def start(self):
        """Start the P2P server, DHT, discovery loops, and registry."""
        bind_host = None if BIND_IP in ("0.0.0.0", "::", "", "all") else BIND_IP
        self._server = await asyncio.start_server(
            self._handle_connection,
            bind_host,
            _config.P2P_PORT,
            limit=100
        )
        logger.info(f"[P2P] Encrypted server listening on port {_config.P2P_PORT} (dual-stack: {bind_host is None})")

        # Load persisted peer bans
        try:
            now = time.time()
            active_bans = await self.peer_ban_repo.get_active()
            for row in active_bans:
                exp = float(row['expires_at'])
                if exp > now:
                    self.banned_peers[row['address']] = exp
                    if row.get('node_id'):
                        self.banned_node_ids[row['node_id']] = exp
            if active_bans:
                logger.info(f"[P2P] Loaded {len(active_bans)} persisted peer bans")
            await self.peer_ban_repo.delete_expired()
        except Exception as e:
            logger.warning(f"[P2P] Failed to load persisted peer bans: {e}")

        if DHT_AVAILABLE and _config.DHT_ENABLED:
            self._dht_task = asyncio.create_task(self._dht_loop())

        self._bg_tasks = [
            asyncio.create_task(self._discovery_loop()),
            asyncio.create_task(self._heartbeat_loop()),
            asyncio.create_task(self._sync_loop()),
            asyncio.create_task(self._cache_loop()),
            asyncio.create_task(self._score_decay_loop()),
            asyncio.create_task(self._peer_rotation_loop()),
        ]
        await self.start_pruning()

    async def shutdown(self):
        self._discovery_stop.set()

        if self._dht_server is not None:
            try:
                self._dht_server.stop()
            except Exception as e:
                logger.debug(f"[DHT] Stop error: {e}")

        if self._dht_task:
            self._dht_task.cancel()
            try:
                await self._dht_task
            except asyncio.CancelledError:
                pass

        # Cancel background loops and per-connection tasks BEFORE closing
        # writers so nothing logs into the Section 9.4 shutdown tail.
        to_cancel = list(getattr(self, '_bg_tasks', [])) + list(self._conn_tasks)
        prune = getattr(self, '_prune_task', None)
        if prune is not None:
            to_cancel.append(prune)
        for t in to_cancel:
            if not t.done():
                t.cancel()
        for t in to_cancel:
            try:
                await t
            except asyncio.CancelledError:
                pass
            except Exception:
                pass

        if self._server:
            self._server.close()
            await self._server.wait_closed()

        for peer in list(self.peers.values()):
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass
        logger.debug("[P2P] Shutdown complete")

    # ─── Connection Handling ──────────────────────────────────
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        addr = writer.get_extra_info('peername')
        if not addr:
            writer.close()
            # R6-close-wait-closed: await the close like every other
            # early-return path in this handler.
            await writer.wait_closed()
            return
        sock = writer.get_extra_info('socket')
        if sock:
            try:
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            except Exception:
                pass
        addr_str = f"[{addr[0]}]:{addr[1]}" if ":" in str(addr[0]) else f"{addr[0]}:{addr[1]}"

        if self._is_banned(address=addr_str):
            writer.close()
            await writer.wait_closed()
            return

        ip_only = addr[0]
        pending = self._pending_handshakes.get(ip_only, 0)
        if pending >= self._max_pending_handshakes:
            writer.close()
            await writer.wait_closed()
            return
        now_ts = time.time()
        hs_timestamps = self._handshake_rate_limiter.setdefault(ip_only, [])
        hs_timestamps[:] = [t for t in hs_timestamps if now_ts - t < 60]
        if len(hs_timestamps) >= self._handshake_rate_limit[0]:
            writer.close()
            await writer.wait_closed()
            return
        hs_timestamps.append(now_ts)
        self._pending_handshakes[ip_only] = pending + 1
        try:
            peer = await asyncio.wait_for(
                perform_handshake(
                    reader, writer,
                    self.node.node_id,
                    self.node.height,
                    VERSION,
                    self.node.priv,
                    self.node.pub,
                    allow_genesis_learn=False
                ),
                timeout=10.0
            )
        except Exception:
            peer = None
        finally:
            self._pending_handshakes[ip_only] = max(0, self._pending_handshakes.get(ip_only, 1) - 1)
            if self._pending_handshakes[ip_only] == 0:
                self._pending_handshakes.pop(ip_only, None)

        if peer is None:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        if peer.node_id == self.node.node_id:
            logger.debug(f"[P2P] Rejecting self-connection from {peer.address}")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            return

        # DIAL-KEEPER-1: duplicate-socket policy is decided under the lock below (_dial_dup_action).

        if self._is_banned(node_id=peer.node_id):
            logger.info(f"[P2P] Rejecting inbound peer {peer.address}: node_id {peer.node_id[:16]} is banned")
            writer.close()
            await writer.wait_closed()
            return

        async with self._lock:
            existing = [p for p in self.peers.values() if p.node_id == peer.node_id]
            if existing:
                _lb = parse_ip_port(peer.address, _config.P2P_PORT)[0] in ("127.0.0.1", "localhost", "::1")
                if _dial_dup_action(self.node.node_id, peer.node_id, 'in', _lb, True) != 'replace_existing':
                    logger.debug(f"[P2P] Already connected to node {peer.node_id[:16]}, closing inbound duplicate")
                    writer.close()
                    await writer.wait_closed()
                    return
                # DIAL-KEEPER-1: this inbound socket was dialed by the smaller node_id (the keeper) ->
                # it replaces the registered non-keeper socket. The peer loop's finally releases counters.
                logger.debug(f"[P2P] DIAL-KEEPER-1 replacing duplicate socket to node {peer.node_id[:16]} with inbound keeper")
                for _old in existing:
                    try:
                        if _old.writer is not None:
                            _old.writer.close()
                    except Exception:
                        pass
                    if self.peers.get(_old.address) is _old:
                        del self.peers[_old.address]

            peer_ip = parse_ip_port(peer.address, _config.P2P_PORT)[0]
            ip_conns = self._conn_per_ip.get(peer_ip, 0)
            is_bootstrap = any(peer_ip in b for b in self.bootstrap_nodes) or peer_ip == self.genesis_node
            if not is_bootstrap and ip_conns >= self._max_conn_per_ip:
                # R8-subnet-order (R7-19): per-IP rejection runs BEFORE the
                # subnet reservation below, so rejected peers consume no
                # quota (track-then-reject leaked with no peer loop to
                # clean it up).
                logger.info(f"[P2P] Rejecting inbound peer {peer.address}: per-IP cap ({ip_conns}/{self._max_conn_per_ip})")
                writer.close()
                await writer.wait_closed()
                return

            if not self._track_peer_subnet(peer):
                logger.info(f"[P2P] Rejecting inbound peer {peer.address}: subnet diversity cap reached")
                writer.close()
                await writer.wait_closed()
                return
            self._conn_per_ip[peer_ip] = ip_conns + 1

            if len(self.peers) >= self.max_peers:
                oldest = min(self.peers.values(), key=lambda p: p.last_seen)
                # R6-evict-socket-close: close the evicted writer first —
                # deleting the entry alone left the socket (and its loop)
                # running. The peer loop's finally handles the rest.
                try:
                    if oldest.writer is not None:
                        oldest.writer.close()
                except Exception as _ev_e:
                    logger.debug(f"[P2P] evict close failed for {oldest.address}: {_ev_e}")
                del self.peers[oldest.address]
            self.peers[peer.address] = peer
            self._metrics["connections"] += 1
            self._metrics["peers_discovered"] += 1
        logger.info(f"[P2P] New encrypted peer: {peer.address} (node {peer.node_id[:16]})")
        self._track_task(asyncio.create_task(self._send_message(peer, MSG_GET_STATUS, b'{}')))
        self.tip_push(peer)
        self._track_task(asyncio.create_task(self._peer_loop(peer)))

    async def _peer_loop(self, peer: EncryptedPeer):
        writer_task = self._track_task(asyncio.create_task(self._peer_writer(peer)))
        try:
            while True:
                try:
                    len_data = await peer.reader.readexactly(4)
                except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                    break
                msg_len = struct.unpack(">I", len_data)[0]
                if msg_len > 16_000_000:
                    self._ban_peer(peer.address, "message too large", node_id=peer.node_id)
                    break
                try:
                    encrypted_payload = await peer.reader.readexactly(msg_len)
                except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
                    break
                plaintext = peer.decrypt_message(encrypted_payload)
                if plaintext is None:
                    self._ban_peer(peer.address, "decryption failed", node_id=peer.node_id)
                    break
                if len(plaintext) < 1:
                    continue
                msg_type = plaintext[0]
                data = plaintext[1:]
                self._metrics["messages_received"] += 1
                self._metrics["bytes_received"] += len(plaintext)
                await self._process_message(peer, msg_type, data)
                peer.last_seen = time.time()
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            pass
        except Exception as e:
            logger.error(f"[P2P] Error in peer loop {peer.address}: {e}")
        finally:
            writer_task.cancel()
            try:
                await writer_task
            except (asyncio.CancelledError, Exception):
                pass
            async with self._lock:
                # Identity guard: only remove OUR entry. A reconnect may have
                # already registered a fresh peer at the same address — deleting
                # unconditionally would silently orphan the healthy connection.
                if self.peers.get(peer.address) is peer:
                    del self.peers[peer.address]
                subnet = self.peer_subnets.pop(peer.address, None)
                if subnet and subnet in self.subnet_peer_count:
                    self.subnet_peer_count[subnet] = max(0, self.subnet_peer_count[subnet] - 1)
                    if self.subnet_peer_count[subnet] <= 0:
                        self.subnet_peer_count.pop(subnet, None)
                _asn = self.peer_asns.pop(peer.address, None)
                if _asn and _asn in self.asn_peer_count:
                    self.asn_peer_count[_asn] = max(0, self.asn_peer_count[_asn] - 1)
                    if self.asn_peer_count[_asn] <= 0:
                        self.asn_peer_count.pop(_asn, None)
                peer_ip = parse_ip_port(peer.address, _config.P2P_PORT)[0]
                if peer_ip in self._conn_per_ip:
                    self._conn_per_ip[peer_ip] = max(0, self._conn_per_ip[peer_ip] - 1)
                    if self._conn_per_ip[peer_ip] <= 0:
                        self._conn_per_ip.pop(peer_ip, None)
            try:
                peer.writer.close()
                await peer.writer.wait_closed()
            except Exception:
                pass
            logger.info(f"[P2P] Peer disconnected: {peer.address}")

    # ─── Message Processing ────────────────────────────────────
    def _bound_peer_height(self, claimed: int) -> int:
        # R6-peer-height-bound: a hostile peer advertising an extreme
        # height must not become the preferred sync target. Clamp claims
        # more than 100 ahead of our tip back to our tip (chain reset:
        # no — p2p-local policy). Callers max() with the stored height
        # so honest advances still register monotonically.
        try:
            claimed = int(claimed)
        except (TypeError, ValueError):
            return 0
        if claimed > self.node.height + 100:
            return self.node.height
        return max(0, claimed)

    async def _process_message(self, peer: EncryptedPeer, msg_type: int, data: bytes):
        peer.last_seen = time.time()        # Rate limiting check
        if not self._check_rate_limit(peer, msg_type):
            return

        # Payload validation for structured messages
        if msg_type in (MSG_NEW_BLOCK, MSG_GET_BLOCKS, MSG_BLOCKS, MSG_NEW_TX, MSG_GET_PEERS, MSG_PEERS, MSG_GET_STATUS, MSG_STATUS):
            if not await self._validate_payload(peer, msg_type, data):
                self._update_reputation(peer, "protocol_violation")
                return

        try:
            if msg_type == MSG_PING:
                try:
                    if data:
                        info = json.loads(data.decode())
                        if "height" in info:
                            # R6-peer-height-bound: clamp hostile claims.
                            peer.height = max(peer.height, self._bound_peer_height(info["height"]))
                except Exception:
                    pass
                pong_payload = json.dumps({"height": self.node.height}).encode()
                await self._send_message(peer, MSG_PONG, pong_payload)
                peer.last_seen = time.time()
            elif msg_type == MSG_PONG:
                try:
                    if data:
                        info = json.loads(data.decode())
                        if "height" in info:
                            # R6-peer-height-bound: clamp hostile claims.
                            peer.height = max(peer.height, self._bound_peer_height(info["height"]))
                except Exception:
                    pass
                peer.last_seen = time.time()
            elif msg_type == MSG_GET_PEERS:
                async with self._lock:
                    peers_list = []
                    for p in self.peers.values():
                        h = parse_ip_port(p.address)[0]
                        peers_list.append(f"[{h}]:{p.p2p_port}" if ":" in str(h) else f"{h}:{p.p2p_port}")
                payload = json.dumps({"peers": peers_list[:100]}).encode()
                await self._send_message(peer, MSG_PEERS, payload)
            elif msg_type == MSG_PEERS:
                try:
                    data_json = json.loads(data.decode())
                    # R8-peer-fanout (R7-06): dedupe within the message and
                    # cap spawned dials per message (validation already
                    # bounds list/endpoint shape above). Unbounded per-item
                    # task spawn was a remote task/socket exhaustion vector.
                    _seen_eps = set()
                    _spawned = 0
                    for addr in data_json.get("peers", []):
                        if not isinstance(addr, str) or not addr:
                            continue
                        if addr in _seen_eps:
                            continue
                        _seen_eps.add(addr)
                        if addr not in self.peers and not self._is_banned(address=addr):
                            if _spawned >= 32:
                                break
                            _spawned += 1
                            self._track_task(asyncio.create_task(self._connect_to_peer(addr)))
                except Exception as e:
                    logger.debug(f"[P2P] MSG_PEERS error from {peer.address}: {e}")
            elif msg_type == MSG_GET_BLOCKS:
                try:
                    req = json.loads(data.decode())
                    start = req.get("start", 0)
                    end = req.get("end", self.node.height)
                    if end - start > 500:
                        end = start + 500
                    blocks = await self.node.get_blocks_range(start, end)
                    payload = json.dumps({"blocks": blocks}).encode()
                    await self._send_message(peer, MSG_BLOCKS, payload)
                    logger.info(f"[P2P] Served GET_BLOCKS [{start},{end}) -> {len(blocks)} blocks to {peer.address}")
                except Exception as e:
                    logger.warning(f"[P2P] MSG_GET_BLOCKS error from {peer.address}: {e}", exc_info=True)
            elif msg_type == MSG_BLOCKS:
                try:
                    req = json.loads(data.decode())
                    blocks = req.get("blocks", [])
                    await self.node.import_blocks(blocks)
                    # GOSSIP-HEIGHT-1: batch sender is at least at the last
                    # block it just served; keep its height current too.
                    if blocks:
                        try:
                            # R6-peer-height-bound: clamp hostile claims.
                            peer.height = max(peer.height, self._bound_peer_height(int(blocks[-1].get("id", 0)) + 1))
                        except Exception:
                            pass
                    logger.info(f"[P2P] MSG_BLOCKS from {peer.address}: {len(blocks)} blocks processed")
                except Exception as e:
                    logger.warning(f"[P2P] MSG_BLOCKS error from {peer.address}: {e}", exc_info=True)
            elif msg_type == MSG_NEW_BLOCK:
                try:
                    block_data = json.loads(data.decode())
                    # GOSSIP-HEIGHT-1: gossip receipt keeps peer.height fresh
                    # so the equal-height fork fetch / gap sync picks a peer
                    # that actually has the newer tip.
                    try:
                        # R6-peer-height-bound: clamp hostile claims.
                        peer.height = max(peer.height, self._bound_peer_height(int(block_data.get("id", 0)) + 1))
                    except Exception:
                        pass
                    if not self._mark_seen_block(str(block_data.get("hash", ""))):
                        return
                    _status = await self.node.receive_block(block_data)
                    if _status == "rejected":
                        # R8-seen-cache (R7-20): invalid payloads must not
                        # poison the cache against a later valid same-hash
                        # payload. ok/disconnected keep their marks (seen is
                        # true; sync/import paths don't consult this cache).
                        self._unmark_seen_block(str(block_data.get("hash", "")))
                    if _status != "rejected":
                        # FORK-RELAY-1: relay every proof-valid new block, not
                        # just clean appends — the old append-only relay meant
                        # a block landing on a variant tip was dropped silently
                        # and never fanned out; sibling signs then beat the heal
                        # window (attempt6 S10: h14/21/22/33 signed 15-73s
                        # after the rival seal).
                        asyncio.create_task(self.broadcast_block(block_data, force=True))
                    if _status == "disconnected":
                        # FORK-PARENT-1: our tip is a different variant than
                        # this block's parent (or we are behind by >1) — pull
                        # the sender's tail now instead of waiting for the next
                        # sync tick's gap fetch plus its 8s no-progress window
                        # (20-60s observed end-to-end; a sibling can be signed
                        # inside that window). Import scans back 100 blocks for
                        # the common ancestor, so mirror that window here.
                        _bid = int(block_data.get("id", 0) or 0)
                        _fp = json.dumps({"start": max(0, _bid - 100), "end": _bid + 1}).encode()
                        await self._send_message(peer, MSG_GET_BLOCKS, _fp)
                    if peer.height > self.node.height:
                        asyncio.create_task(self.sync_with_peers())
                except Exception as e:
                    logger.debug(f"[P2P] MSG_NEW_BLOCK error from {peer.address}: {e}")
            elif msg_type == MSG_NEW_TX:
                try:
                    tx_data = json.loads(data.decode())
                    _tx_key = tx_data.get("tx_hash") or tx_data.get("hash", "")
                    if not _tx_key:
                        # R8-seen-cache (R7-20): keyless payloads can never
                        # validate — drop without occupying a cache slot
                        # (str(None)="None" used to poison all later keyless
                        # traffic sharing that slot).
                        return
                    if not self._mark_seen_tx(str(_tx_key)):
                        return
                    if not await self.node.receive_transaction(tx_data):
                        # R8-seen-cache (R7-20): rejected payloads unmark so
                        # a later valid same-hash payload is processed.
                        self._unmark_seen_tx(str(_tx_key))
                except Exception as e:
                    logger.debug(f"[P2P] MSG_NEW_TX error from {peer.address}: {e}")
            elif msg_type == MSG_SLASH:
                try:
                    req = json.loads(data.decode())
                    logger.info(f"[P2P] Unverified slash report for miner {str(req.get('miner_id'))[:16]} from peer {peer.address} - ignored (slashing is local-only)")
                except Exception as e:
                    logger.debug(f"[P2P] MSG_SLASH parse error from {peer.address}: {e}")
            elif msg_type == MSG_GET_STATUS:
                status = {
                    "height": self.node.height,
                    "peers": len(self.peers),
                    "miners": len(self.node.miners),
                    "version": VERSION,
                    "last_hash": getattr(self.node, "last_hash", "")
                }
                payload = json.dumps(status).encode()
                await self._send_message(peer, MSG_STATUS, payload)
            elif msg_type == MSG_STATUS:
                try:
                    status = json.loads(data.decode())
                    new_h = int(status.get("height", 0))
                    # R6-peer-height-bound: clamp hostile claims.
                    peer.height = max(peer.height, self._bound_peer_height(new_h))
                    peer.version = status.get("version", "unknown")
                    logger.debug(f"[P2P] Peer {peer.address} status: height={peer.height}, version={peer.version}")
                    if peer.height > self.node.height:
                        asyncio.create_task(self.sync_with_peers())
                except Exception as e:
                    logger.debug(f"[P2P] Error handling MSG_STATUS from {peer.address}: {e}")
            elif msg_type == MSG_GET_CHECKPOINT:
                checkpoint = await self.node.finality_repo.get_latest()
                resp = {"block_id": checkpoint["block_id"] if checkpoint else 0,
                        "hash": checkpoint["hash"] if checkpoint else self.node.blocks[0]["hash"] if self.node.blocks else "",
                        "epoch": checkpoint["epoch"] if checkpoint else 0}
                await self._send_message(peer, MSG_CHECKPOINT, json.dumps(resp).encode())
            elif msg_type == MSG_CHECKPOINT:
                try:
                    resp = json.loads(data.decode())
                    fut = self._pending_checkpoint_requests.get(peer.address)
                    if fut and not fut.done():
                        fut.set_result(resp)
                except Exception as e:
                    logger.debug(f"[P2P] MSG_CHECKPOINT error from {peer.address}: {e}")
            elif msg_type == MSG_BAN:
                try:
                    req = json.loads(data.decode())
                    logger.info(f"[P2P] Unverified ban request for miner {str(req.get('miner_id'))[:16]} from peer {peer.address} - ignored (ban/unban is local-only)")
                except Exception as e:
                    logger.debug(f"[P2P] MSG_BAN/UNBAN parse error from {peer.address}: {e}")
            elif msg_type == MSG_UNBAN:
                try:
                    req = json.loads(data.decode())
                    logger.info(f"[P2P] Unverified unban request for miner {str(req.get('miner_id'))[:16]} from peer {peer.address} - ignored (ban/unban is local-only)")
                except Exception as e:
                    logger.debug(f"[P2P] MSG_UNBAN parse error from {peer.address}: {e}")
            elif msg_type == MSG_NEW_MOVE:
                # NEW-MOVE-GOSSIP: mirror a peer's applied signed move. Data
                # only — no rebroadcast (single hop from the origin).
                # MOVE-GOSSIP-UX-ONLY: under IDEA5-ELIG this gossip never feeds
                # eligibility or the lottery (row/display sync only).
                # ROW-SNAPSHOT: when the origin includes its authoritative
                # post-move row (+ pos history + oscillation flag), verify the
                # miner's signature against the ORIGIN-ATTESTED growthcount/
                # nonce and adopt the row verbatim — follower rows then match
                # the origin exactly (consecutivewallhits, position, goal,
                # ghost), including wall hits the old success-only gossip
                # never sent, and stale followers catch up in one message.
                # Legacy recompute path remains for snapshot-less peers.
                try:
                    req = json.loads(data.decode())
                    g_miner = req.get("miner_id")
                    g_maze = req.get("maze_id") or g_miner
                    g_dir = req.get("direction")
                    g_sig = req.get("signature")
                    g_snap = req.get("row")
                    if g_miner and g_dir and g_sig and getattr(self.node, "consensus", None):
                        g_applied = False
                        if g_snap and req.get("move_nonce") is not None:
                            g_local = await self.node.maze_repo.get_by_maze_id(g_maze)
                            g_mrow = await self.node.miner_repo.get(g_miner) if g_miner else None
                            # ROW-SNAPSHOT pub binding: a follower node has no
                            # miners-table row for a foreign miner (miner records
                            # only exist where the miner registered), so require
                            # the payload pub instead. It is self-certifying:
                            # miner_id = "PC_" + sha256(wallet + "_mcx_miner")[:32]
                            # and wallet = pubkey_to_address(pub), so only the
                            # true key can satisfy the derivation. A local record,
                            # when present, is authoritative over the payload.
                            g_pub = None
                            if g_mrow and g_mrow.get("pub"):
                                g_pub = g_mrow["pub"]
                                if req.get("pub") and str(req["pub"]).lower() != str(g_pub).lower():
                                    g_pub = None
                            elif req.get("pub") and str(g_miner).startswith("PC_"):
                                try:
                                    _g_der = "PC_" + hashlib.sha256(
                                        f"{pubkey_to_address(str(req['pub']))}_mcx_miner".encode()
                                    ).hexdigest()[:32].upper()
                                    if _g_der == g_miner:
                                        g_pub = str(req["pub"])
                                except Exception:
                                    g_pub = None
                            if g_local and g_pub:
                                g_auth = self.node.consensus._move_auth_bytes(
                                    g_miner, g_local.get("maze_id") or g_miner,
                                    int(req.get("growthcount", g_local.get("growthcount", 0))),
                                    int(req["move_nonce"]), g_dir)
                                if verify_signature_bytes(g_pub, g_auth, g_sig):
                                    try:
                                        # Non-regression: only adopt a row whose
                                        # movenonce is >= ours (stale relays of
                                        # moves we already processed are dropped).
                                        if int(g_snap.get("movenonce", -1)) >= int(g_local.get("movenonce", -1)):
                                            # R8-moverow-trust (R7-21): the move
                                            # signature authenticates the move,
                                            # not the row. A forged maze_id /
                                            # minerid would create/overwrite an
                                            # ARBITRARY row via upsert below —
                                            # mismatch falls back to the legacy
                                            # recompute path (no merge at all).
                                            if (("maze_id" in g_snap and str(g_snap["maze_id"]) != str(g_local.get("maze_id")))
                                                    or ("minerid" in g_snap and str(g_snap["minerid"]) != str(g_local.get("minerid")))):
                                                raise ValueError("move-gossip row identity mismatch; legacy path")
                                            g_merged = dict(g_local)
                                            for g_k, g_v in g_snap.items():
                                                if g_k in MAZE_ROW_COLS and g_k in _MOVE_ROW_SAFE_COLS:
                                                    g_merged[g_k] = g_v
                                            # Activity data parity for
                                            # get_eligible — take the higher of
                                            # local/origin; the eligibility rule
                                            # itself is unchanged (LOTTERY-1).
                                            g_merged["lastactiveheight"] = max(
                                                int(g_local.get("lastactiveheight", 0) or 0),
                                                int(g_merged.get("lastactiveheight", 0) or 0))
                                            await self.node.maze_repo.upsert(g_merged)
                                            g_ph = req.get("pos_hist") or []
                                            if g_ph:
                                                g_hist = deque(maxlen=6)
                                                for g_p in g_ph:
                                                    g_hist.append(tuple(int(g_x) for g_x in g_p))
                                                self.node.consensus._pos_history[g_maze] = g_hist
                                            else:
                                                self.node.consensus._pos_history.pop(g_maze, None)
                                            if req.get("oscillating"):
                                                self.node.consensus._oscillating_mazes.add(g_maze)
                                            else:
                                                self.node.consensus._oscillating_mazes.discard(g_maze)
                                            g_applied = True
                                    except Exception as _ge:
                                        logger.debug(f"[P2P] move-gossip snapshot apply error: {_ge}")
                                else:
                                    logger.debug(f"[P2P] move-gossip signature invalid for {str(g_miner)[:16]}")
                            else:
                                logger.debug(f"[P2P] move-gossip snapshot missing local row or pub binding for {str(g_miner)[:16]}")
                        if not g_applied:
                            # Legacy recompute path: verify + re-apply the move
                            # locally. Failures are expected and non-fatal:
                            # unknown miner/maze rows, a row whose
                            # growthcount/movenonce has not been resynced yet,
                            # or a race with a seal-time maze_updates; the next
                            # catch event self-heals those.
                            before_n = len(self.node.consensus._pending_maze_updates)
                            g_ok, g_msg, _g_state = await self.node.consensus.process_move(
                                g_miner, g_maze, g_dir, g_sig, None)
                            if g_ok:
                                # Catch events from this mirrored move are already
                                # queued on the ORIGIN node — drop the follower's
                                # copies so a block this node later produces cannot
                                # re-apply events the origin already included.
                                del self.node.consensus._pending_maze_updates[before_n:]
                                # Align activity with the origin's height (data
                                # parity for get_eligible; the eligibility rule
                                # itself is unchanged).
                                try:
                                    g_row = await self.node.maze_repo.get_by_maze_id(g_maze)
                                    if g_row and int(req.get("height", 0) or 0) > int(g_row.get("lastactiveheight", -1000000) or -1000000):
                                        g_row["lastactiveheight"] = int(req["height"])
                                        await self.node.maze_repo.upsert({**dict(g_row), "updatedat": int(time.time())})
                                except Exception:
                                    pass
                            else:
                                logger.debug(f"[P2P] move-gossip skipped for {str(g_miner)[:16]}: {g_msg}")
                except Exception as e:
                    logger.debug(f"[P2P] MSG_NEW_MOVE apply error: {e}")
            else:
                logger.warning(f"[P2P] Unknown message type: {msg_type}")
        except Exception as e:
            logger.error(f"[P2P] Error processing message: {e}")
            self._update_reputation(peer, "invalid_message")

    # ─── Sending Messages ──────────────────────────────────────
    @staticmethod
    def _msg_priority(msg_type: int) -> int:
        """Lower number = higher priority. Consensus traffic jumps gossip."""
        if msg_type in (MSG_BLOCKS, MSG_NEW_BLOCK, MSG_CHECKPOINT, MSG_GET_CHECKPOINT):
            return 0
        if msg_type in (MSG_PING, MSG_PONG, MSG_STATUS, MSG_GET_STATUS):
            return 1
        if msg_type in (MSG_NEW_TX, MSG_GET_BLOCKS):
            return 2
        return 3

    async def _peer_writer(self, peer: EncryptedPeer):
        """Drain peer.send_queue serially. One writer per peer preserves
        send_nonce ordering even under concurrent producers."""
        try:
            while True:
                _prio, _ctr, msg_type, payload = await peer.send_queue.get()
                if peer.banned:
                    continue
                plaintext = bytes([msg_type]) + payload
                async with peer.write_lock:
                    try:
                        encrypted = peer.encrypt_message(plaintext)
                        peer.writer.write(struct.pack(">I", len(encrypted)) + encrypted)
                        await peer.writer.drain()
                        self._metrics["messages_sent"] += 1
                        self._metrics["bytes_sent"] += len(plaintext)
                    except (ConnectionResetError, BrokenPipeError, OSError) as e:
                        # Transport-level resets are not peer misbehavior (the
                        # remote may simply be restarting/deduplicating) — a
                        # -5 reputation hit here instabanned localhost peers
                        # and collapsed the mesh for the full ban window.
                        logger.info(f"[P2P] Writer to {peer.address} reset: {e}")
                        break
                    except Exception as e:
                        logger.debug(f"[P2P] Writer to {peer.address} unexpected: {e}")
                        break
        except asyncio.CancelledError:
            pass
        finally:
            # Writer death (reset/encrypt error) must tear down the whole
            # connection: otherwise the reader keeps the peer looking alive
            # while every outbound message silently stops draining — a one-way
            # ghost that only the remote's heartbeat ever notices.
            try:
                peer.writer.close()
            except Exception:
                pass

    async def _send_message(self, peer: EncryptedPeer, msg_type: int, payload: bytes):
        """Enqueue a message for the peer's writer. Never blocks on socket I/O."""
        if peer.banned:
            return
        prio = self._msg_priority(msg_type)
        peer._send_counter += 1
        try:
            peer.send_queue.put_nowait((prio, peer._send_counter, msg_type, payload))
        except asyncio.QueueFull:
            logger.debug(f"[P2P] Send queue full for {peer.address}, dropping type={msg_type}")
            self._update_reputation(peer, "invalid_message")

    async def broadcast_message(self, msg_type: int, payload: bytes, exclude: Set[str] = None):
        if exclude is None:
            exclude = set()
        async with self._lock:
            peers_list = list(self.peers.values())
        peers_list = [p for p in peers_list if p.address not in exclude and not p.banned]
        if not peers_list:
            return
        if len(peers_list) <= self.gossip_fanout:
            selected = peers_list
        else:
            selected = random.sample(peers_list, self.gossip_fanout)
        for peer in selected:
            self._track_task(asyncio.create_task(self._send_message(peer, msg_type, payload)))

    # ─── Rate Limiting ─────────────────────────────────────────────
    def _check_rate_limit(self, peer: EncryptedPeer, msg_type: int) -> bool:
        """Check if peer has exceeded rate limit for message type. Returns True if allowed."""
        now = time.time()
        addr = peer.address
        if addr not in self.peer_message_counts:
            self.peer_message_counts[addr] = {}
        if msg_type not in self.peer_message_counts[addr]:
            self.peer_message_counts[addr][msg_type] = []

        # Clean old timestamps
        limit, window = self.rate_limits.get(msg_type, (100, 60))
        cutoff = now - window
        self.peer_message_counts[addr][msg_type] = [
            ts for ts in self.peer_message_counts[addr][msg_type] if ts > cutoff
        ]

        if len(self.peer_message_counts[addr][msg_type]) >= limit:
            self._update_reputation(peer, "invalid_message")
            logger.warning(f"[P2P] Rate limit exceeded: {addr} msg_type={msg_type}")
            return False

        self.peer_message_counts[addr][msg_type].append(now)
        return True

    # ─── Enhanced Reputation Scoring ───────────────────────────────
    def _update_reputation(self, peer: EncryptedPeer, action: str):
        """Update peer reputation score based on action."""
        if action not in self.reputation_weights:
            return

        delta = self.reputation_weights[action]
        old_score = peer.score
        peer.score = max(-1000, min(self.max_positive_score, peer.score + delta))

        # Track breakdown for debugging
        if peer.address not in self.peer_scores:
            self.peer_scores[peer.address] = {"score": 0, "breakdown": defaultdict(int), "last_update": time.time()}
        self.peer_scores[peer.address]["score"] = peer.score
        self.peer_scores[peer.address]["breakdown"][action] += 1
        self.peer_scores[peer.address]["last_update"] = time.time()

        if delta < 0:
            logger.debug(f"[P2P] Reputation decrease: {peer.address} {action} ({old_score} -> {peer.score})")
        else:
            logger.debug(f"[P2P] Reputation increase: {peer.address} {action} ({old_score} -> {peer.score})")

        if peer.score <= self.min_score_for_ban:
            self._ban_peer(peer.address, f"score {peer.score} below threshold", node_id=peer.node_id)

    # ─── Eclipse Attack Protection ─────────────────────────────────
    def _get_subnet(self, address: str) -> str:
        """Extract /24 subnet for IPv4 or /48 prefix for IPv6."""
        try:
            host = parse_ip_port(address)[0]
            ip_obj = ipaddress.ip_address(host)
            if ip_obj.version == 4:
                parts = host.split(".")
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
            else:
                return str(ipaddress.IPv6Network(f"{host}/48", strict=False))
        except Exception:
            pass
        return "unknown"

    def _get_asn(self, ip_str: str) -> str:
        """Offline ASN label. Falls back to a /16 pseudo-ASN so private IPs still bucket sensibly."""
        if ip_str in self.asn_cache:
            return self.asn_cache[ip_str]
        asn = "unknown"
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if isinstance(ip_obj, ipaddress.IPv4Address):
                for net_str, label in ASN_STATIC_MAP:
                    try:
                        if ip_obj in ipaddress.ip_network(net_str):
                            asn = label
                            break
                    except ValueError:
                        continue
                if asn == "unknown":
                    parts = ip_str.split(".")
                    asn = f"AS-{parts[0]}.{parts[1]}.0.0/16"
            else:
                asn = f"AS-IPv6-{str(ip_obj)[:12]}"
        except ValueError:
            pass
        self.asn_cache[ip_str] = asn
        return asn

    def _track_peer_subnet(self, peer: EncryptedPeer) -> bool:
        """Track peer subnet + ASN for diversity. Returns True if peer adds diversity."""
        host = parse_ip_port(peer.address)[0]
        subnet = self._get_subnet(peer.address)
        asn = self._get_asn(host)

        current = self.subnet_peer_count.get(subnet, 0)
        if current >= self.max_peers_per_subnet:
            return False

        try:
            ip_obj = ipaddress.ip_address(host)
            is_private = ip_obj.is_private or ip_obj.is_loopback
        except ValueError:
            is_private = True

        if not is_private:
            asn_current = self.asn_peer_count.get(asn, 0)
            if asn_current >= self.max_peers_per_asn:
                return False
            self.peer_asns[peer.address] = asn
            self.asn_peer_count[asn] = asn_current + 1

        self.peer_subnets[peer.address] = subnet
        self.subnet_peer_count[subnet] = current + 1
        return True

    def _check_eclipse_resistance(self) -> Dict[str, int]:
        """Return subnet distribution for monitoring."""
        return dict(self.subnet_peer_count)

    # ─── Payload Validation ────────────────────────────────────────
    async def _validate_payload(self, peer: EncryptedPeer, msg_type: int, data: bytes) -> bool:
        """Validate message payload structure. Returns True if valid."""
        try:
            if msg_type in (MSG_NEW_BLOCK, MSG_GET_BLOCKS, MSG_BLOCKS):
                payload = json.loads(data.decode())
                if "blocks" in payload:
                    for blk in payload["blocks"]:
                        if not isinstance(blk, dict) or "id" not in blk or "hash" not in blk:
                            return False
                if "start" in payload and not isinstance(payload["start"], int):
                    return False
                if "end" in payload and not isinstance(payload["end"], int):
                    return False

            elif msg_type in (MSG_NEW_TX,):
                payload = json.loads(data.decode())
                if not isinstance(payload, dict) or "tx_hash" not in payload:
                    return False

            elif msg_type == MSG_GET_PEERS:
                if not data or data == b'{}':
                    return True
                payload = json.loads(data.decode())
                return isinstance(payload, dict)

            elif msg_type == MSG_PEERS:
                payload = json.loads(data.decode())
                if not isinstance(payload, dict) or ("peers" in payload and not isinstance(payload["peers"], list)):
                    return False
                # R8-peer-fanout (R7-06): bound the fan-out surface at
                # validation — list length and per-endpoint shape. The
                # handler additionally dedupes and caps spawned dials.
                if "peers" in payload:
                    if len(payload["peers"]) > 128:
                        return False
                    for _ep in payload["peers"]:
                        if not isinstance(_ep, str) or len(_ep) > 256 or not _ep:
                            return False

            elif msg_type == MSG_GET_STATUS:
                if not data or data == b'{}':
                    return True
                payload = json.loads(data.decode())
                return isinstance(payload, dict)

            elif msg_type == MSG_STATUS:
                payload = json.loads(data.decode())
                if not isinstance(payload, dict) or ("height" in payload and not isinstance(payload["height"], int)):
                    return False

            return True
        except Exception as e:
            logger.debug(f"[P2P] Payload validation failed for {peer.address} type={msg_type}: {e}")
            return False

    # ─── Score Decay ───────────────────────────────────────────────
    async def _peer_rotation_loop(self):
        """Periodically drop stale or low-score non-bootstrap peers so fresh
        inbound/outbound peers can enter. Prevents a stable clique from
        ossifying into an eclipse set."""
        while not self._discovery_stop.is_set():
            await asyncio.sleep(600)
            try:
                async with self._lock:
                    snapshot = list(self.peers.values())
                if len(snapshot) < max(4, self.max_peers // 2):
                    continue
                now = time.time()
                at_cap = len(self.peers) >= self.max_peers
                rotated = 0
                candidates = sorted(snapshot, key=lambda p: (p.score, p.last_seen))
                for peer in candidates:
                    peer_ip = parse_ip_port(peer.address, _config.P2P_PORT)[0]
                    is_bootstrap = (
                        any(peer_ip in b for b in self.bootstrap_nodes)
                        or peer_ip == self.genesis_node
                    )
                    if is_bootstrap:
                        continue
                    stale = (now - peer.last_seen) > 300
                    bad_score = peer.score < 0
                    if stale or (at_cap and bad_score):
                        try:
                            peer.writer.close()
                        except Exception:
                            pass
                        rotated += 1
                        if rotated >= 3:
                            break
                if rotated:
                    logger.info(f"[P2P] Peer rotation: dropped {rotated} stale/low-score peers")
            except Exception as e:
                logger.debug(f"[P2P] Rotation loop error: {e}")

    async def _score_decay_loop(self):
        """Periodically decay scores toward zero and clean old rate limit data."""
        while not self._discovery_stop.is_set():
            await asyncio.sleep(self.score_decay_interval)
            try:
                now = time.time()
                async with self._lock:
                    for peer in self.peers.values():
                        # Decay score toward 0
                        if peer.score > 0:
                            peer.score = max(0, peer.score - 1)
                        elif peer.score < 0:
                            peer.score = min(0, peer.score + 1)

                        # Update tracked score
                        if peer.address in self.peer_scores:
                            self.peer_scores[peer.address]["score"] = peer.score

                    # Clean old rate limit data
                    for addr in list(self.peer_message_counts.keys()):
                        if addr not in self.peers:
                            del self.peer_message_counts[addr]
                            continue
                        for msg_type in list(self.peer_message_counts[addr].keys()):
                            limit, window = self.rate_limits.get(msg_type, (100, 60))
                            cutoff = now - window
                            self.peer_message_counts[addr][msg_type] = [
                                ts for ts in self.peer_message_counts[addr][msg_type] if ts > cutoff
                            ]
                            if not self.peer_message_counts[addr][msg_type]:
                                del self.peer_message_counts[addr][msg_type]
                        if not self.peer_message_counts[addr]:
                            del self.peer_message_counts[addr]

                    # Clean old peer_scores
                    for addr in list(self.peer_scores.keys()):
                        if addr not in self.peers and now - self.peer_scores[addr].get("last_update", 0) > 86400:
                            del self.peer_scores[addr]
            except Exception as e:
                logger.error(f"[P2P] Score decay error: {e}")

    # ─── PQC Validation Worker Pool ────────────────────────────────
    # R4-dead-code-remove: _validate_pqc_signature / validate_pqc_async
    # deleted (referenced undefined PQC_AVAILABLE / pqc_verify; zero
    # callers). The F-pqc-doc note is retired with the code.

    # ─── Fee Market Framework ──────────────────────────────────────
    def calculate_base_fee(self) -> int:
        """Calculate current base fee (EIP-1559 style)."""
        if len(self.fee_history) < 2:
            return self.base_fee_per_gas

        # Simple moving average of recent gas usage vs target
        recent_avg = sum(self.fee_history) / len(self.fee_history)
        if recent_avg > self.target_gas_per_block:
            return int(self.base_fee_per_gas * 1.125)
        elif recent_avg < self.target_gas_per_block:
            return int(self.base_fee_per_gas * 0.875)
        return self.base_fee_per_gas

    def record_gas_usage(self, gas_used: int):
        """Record gas usage for fee calculation."""
        self.fee_history.append(gas_used)

    def estimate_fee(self, gas_limit: int, priority_fee: int = 0) -> int:
        """Estimate total fee for a transaction."""
        base = self.calculate_base_fee()
        return gas_limit * (base + priority_fee)

    # NOTE (mainnet audit G1): the old handle_reorg/_validate_reorg/
    # pending_reorgs/get_chain_score path was dead code (zero callers;
    # live reorgs go through _reorg_chain bounded by genesis-bound
    # PRUNE_BLOCKS). Removed to end the dead-gate confusion around the
    # unbound local max_reorg_depth knob.
    
    # ─── State Pruning ─────────────────────────────────────────────
    async def _prune_state_loop(self):
        """Periodic state pruning task."""
        while not self._discovery_stop.is_set():
            await asyncio.sleep(self.prune_interval)
            if not self.state_pruning_enabled:
                continue
            try:
                cutoff_height = self.node.height - 10000
                if cutoff_height > 0:
                    await self.db.execute_dml("DELETE FROM state_trie_nodes WHERE ref_count <= 0 AND node_hash NOT IN (SELECT state_root FROM block_state_roots WHERE block_id > ?)", cutoff_height)
                cutoff = time.time() - self.max_state_age
                # Prune old transaction receipts
                await self.db.execute_dml(
                    "DELETE FROM transaction_receipts WHERE block_id IN (SELECT id FROM blocks WHERE ts < ?)",
                    cutoff
                )
                # Prune old contract events
                await self.db.execute_dml(
                    "DELETE FROM contract_events WHERE timestamp < ?",
                    cutoff
                )
                # Prune old slashing events
                await self.db.execute_dml(
                    "DELETE FROM slashing_events WHERE timestamp < ?",
                    cutoff
                )
                logger.info(f"[P2P] State pruning complete (cutoff: {datetime.fromtimestamp(cutoff)})")
            except Exception as e:
                logger.error(f"[P2P] State pruning error: {e}")

    async def start_pruning(self):
        """Start the state pruning task."""
        if self.state_pruning_enabled:
            self._prune_task = asyncio.create_task(self._prune_state_loop())

    def _mark_seen_block(self, block_hash: str) -> bool:
        """Return True if this block hash is new (and records it); False if already seen."""
        if not block_hash:
            return True
        if block_hash in self._seen_block_hashes:
            self._seen_block_hashes.move_to_end(block_hash)
            return False
        self._seen_block_hashes[block_hash] = True
        while len(self._seen_block_hashes) > self._seen_max:
            self._seen_block_hashes.popitem(last=False)
        return True

    def _mark_seen_tx(self, tx_hash: str) -> bool:
        """Return True if this tx hash is new (and records it); False if already seen."""
        if not tx_hash:
            return True
        if tx_hash in self._seen_tx_hashes:
            self._seen_tx_hashes.move_to_end(tx_hash)
            return False
        self._seen_tx_hashes[tx_hash] = True
        while len(self._seen_tx_hashes) > self._seen_max:
            self._seen_tx_hashes.popitem(last=False)
        return True

    def _unmark_seen_block(self, block_hash: str):
        # R8-seen-cache (R7-20): forget a rejected hash so a later valid
        # payload with the same identifier is processed (no poisoning).
        try:
            self._seen_block_hashes.pop(block_hash, None)
        except Exception:
            pass

    def _unmark_seen_tx(self, tx_hash: str):
        # R8-seen-cache (R7-20): same for transactions.
        try:
            self._seen_tx_hashes.pop(tx_hash, None)
        except Exception:
            pass

    async def broadcast_block(self, block_data: dict, force: bool = False):
        # GOSSIP-RELAY-1: the MSG_NEW_BLOCK handler marks the hash seen
        # BEFORE receive_block relays, so the old dedupe here returned False
        # on every relay — gossip was a dead end and blocks only reached
        # direct first-hop sockets (attempt5 S10: h14 undelivered 41s across
        # churned connections -> stale-tip sibling). force=True re-sends an
        # already-marked hash; receivers still dedupe per hash at the
        # handler, so relays cannot loop.
        if not force and not self._mark_seen_block(str(block_data.get("hash", ""))):
            return
        payload = json.dumps(block_data).encode()
        await self.broadcast_message(MSG_NEW_BLOCK, payload)

    async def rebroadcast_block_later(self, block_data: dict, delay: float):
        # DELIVERY-RETRY-1: producer-side repeats ride through short-lived
        # socket churn; each receiver dedupes by hash so a repeat is a
        # no-op once the block has arrived.
        try:
            await asyncio.sleep(delay)
            await self.broadcast_block(block_data, force=True)
        except Exception:
            pass

    def tip_push(self, peer: EncryptedPeer):
        # TIP-PUSH-1: every (re)connection is a delivery opportunity — push
        # the newest blocks point-to-point so a peer that reconnected after
        # missing gossip catches up without waiting for its next sync tick.
        try:
            for _b in self.node.blocks[-3:]:
                self._track_task(asyncio.create_task(
                    self._send_message(peer, MSG_NEW_BLOCK, json.dumps(_b).encode())))
        except Exception:
            pass

    async def broadcast_transaction(self, tx_data: dict):
        _tx_key = tx_data.get("tx_hash") or tx_data.get("hash", "")
        if not self._mark_seen_tx(str(_tx_key)):
            return
        payload = json.dumps(tx_data).encode()
        await self.broadcast_message(MSG_NEW_TX, payload)

    # ─── Peer Management ──────────────────────────────────────
    def _ban_peer(self, address: str, reason: str, node_id: Optional[str] = None):
        h, _ = parse_ip_port(address)
        if h == GENESIS_NODE_HOST or any(h in b for b in self.bootstrap_nodes):
            now_ts = time.time()
            last_log = self._bootstrap_cooldown_log_ts.get(address, 0.0)
            if now_ts - last_log >= 60.0:
                self._bootstrap_cooldown_log_ts[address] = now_ts
                logger.warning(f"[P2P] Disconnecting bootstrap peer {address}: {reason} (cooldown only, not banning)")
            if address in self.peers:
                del self.peers[address]
            self.banned_peers[address] = time.time() + 15.0
            return
        self.banned_peers[address] = time.time() + self.ban_duration
        if node_id:
            self.banned_node_ids[node_id] = time.time() + self.ban_duration
        if address in self.peers:
            del self.peers[address]
        logger.warning(f"[P2P] Banned peer {address}{f' (node {node_id[:16]})' if node_id else ''}: {reason}")
        try:
            exp = self.banned_peers.get(address, time.time() + self.ban_duration)
            asyncio.get_running_loop().create_task(
                self.peer_ban_repo.upsert(address, node_id, reason, exp))
        except RuntimeError:
            pass  # no running loop (shutdown)
        except Exception as e:
            logger.debug(f"[P2P] Persist ban failed for {address}: {e}")

    def _decrease_score(self, peer: EncryptedPeer):
        peer.score -= 1
        if peer.score <= -self.ban_threshold:
            self._ban_peer(peer.address, "score below threshold", node_id=peer.node_id)

    def _is_banned(self, address: str = None, node_id: str = None) -> bool:
        now = time.time()
        if address and address in self.banned_peers and now < self.banned_peers[address]:
            return True
        if node_id and node_id in self.banned_node_ids and now < self.banned_node_ids[node_id]:
            return True
        return False

    def _is_peer_connected(self, addr: str) -> bool:
        """Check if an address (or resolved IP) is already connected."""
        host, port = parse_ip_port(addr, _config.P2P_PORT)
        for p in list(self.peers.values()):
            if p.address == addr:
                return True
            ph, pp = parse_ip_port(p.address, _config.P2P_PORT)
            if pp == port:
                if ph == host:
                    return True
                if host in ("101.127.80.48", GENESIS_NODE_HOST) and ph in ("101.127.80.48", GENESIS_NODE_HOST):
                    return True
            # DIAL-CHURN-1: inbound peers are keyed by their ephemeral source
            # port (accept handler builds address from get_extra_info), so the
            # fixed-port check above misses an established inbound socket —
            # every discovery tick then redialed a live peer; each redial
            # handshakes, gets closed by node_id dedupe, and redials again
            # (the Attempting/Established-per-1-2s storm in the soak logs;
            # sockets died mid-broadcast and blocks went missing for 15-73s).
            # Match the advertised listening port as well.
            if ph == host and int(p.p2p_port or 0) == int(port):
                return True
        return False

    # ─── Outgoing Connections ──────────────────────────────────
    async def _connect_to_peer(self, addr: str):
        if "101.127.80.48" in addr:
            addr = addr.replace("101.127.80.48", GENESIS_NODE_HOST)
        if self._is_peer_connected(addr) or self._is_banned(address=addr):
            return
        # DIAL-BACKOFF-1: skip addresses in their backoff window (no socket,
        # no log spam). Set by _dial_note_result on failures below.
        try:
            if time.time() < float(self._dial_backoff.get(addr, 0.0)):
                return
        except (TypeError, ValueError, AttributeError):
            pass
        h, p = parse_ip_port(addr, _config.P2P_PORT)
        if h == "101.127.80.48":
            h = GENESIS_NODE_HOST
        # R4-ssrf-filter: refuse non-public dial targets (cloud metadata /
        # RFC1918 / loopback) whether literal or resolved. SELF-DIAL-1 below
        # stays as the own-listener guard for any address that passes.
        # R5-ssrf-async-resolve: resolve off the event loop; dial the approved IP, not the hostname.
        # TESTNET-LAN-1: allow_private_peers (non-mainnet explicit opt-in)
        # additionally permits RFC1918/loopback targets here.
        _ssrf_ok, _ssrf_why, _ssrf_ip = await _ssrf_allows_dial(
            h, p, self._local_ips, self.public_ip,
            allow_private=bool(getattr(self, 'allow_private_peers', False)))
        if not _ssrf_ok:
            logger.info(f"[P2P] R4-ssrf-filter: refusing dial {addr}: {_ssrf_why}")
            return
        # SELF-DIAL-1: never dial our own listener. Loopback + our own port
        # is always this process (nobody else can bind it), so the check must
        # NOT depend on self.public_ip being set — the old guard was gated on
        # it, so loopback-only soak nodes redialed themselves on every
        # MSG_PEERS / discovery tick: ~7s churn storms (run3 S10: sockets
        # thrashed at seal time while the sync was mid-stall).
        if (h in self._local_ips or (self.public_ip and h == self.public_ip)) and p == _config.P2P_PORT:
            logger.debug(f"[P2P] SELF-DIAL-1: refusing own endpoint {addr}")
            return
        logger.info(f"[P2P] Attempting connection to {addr}")
        try:
            async with self._lock:
                for existing_peer in self.peers.values():
                    eh, ep = parse_ip_port(existing_peer.address, _config.P2P_PORT)
                    # DIAL-CHURN-1: also match the peer's advertised listening
                    # port — inbound entries carry an ephemeral source port.
                    if (h == eh or addr == existing_peer.address) and (p == ep or p == int(existing_peer.p2p_port or 0)):
                        return

            reader, writer = None, None
            # R8-peer-fanout (R7-06): bound concurrent outbound dials
            # (socket + handshake burst) regardless of which path queued
            # them — MSG_PEERS fan-out, discovery, or manual connects.
            async with self._dial_sem:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(_ssrf_ip, p),
                    timeout=5.0
                )
                sock = writer.get_extra_info('socket')
                if sock:
                    try:
                        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                    except Exception:
                        pass
                is_bootstrap = (
                    any(addr == b for b in self.bootstrap_nodes)
                    or any(h == parse_ip_port(b, _config.P2P_PORT)[0] for b in self.dns_seeds)
                    or h == self.genesis_node
                )
                peer = await asyncio.wait_for(
                    perform_handshake(
                        reader, writer,
                        self.node.node_id,
                        self.node.height,
                        VERSION,
                        self.node.priv,
                        self.node.pub,
                        allow_genesis_learn=(is_bootstrap and self.node.height == 0)
                    ),
                    timeout=10.0
                )
            if peer is None:
                writer.close()
                await writer.wait_closed()
                # DIAL-BACKOFF-1: handshake rejected/failed — back off like
                # a dial failure or every discovery cycle retries it.
                self._dial_note_result(addr, False)
                return

            if peer.node_id == self.node.node_id:
                logger.debug(f"[P2P] Rejecting self-connection to {addr}")
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass
                return

            # DIAL-KEEPER-1: duplicate-socket policy is decided under the lock below (_dial_dup_action).

            if self._is_banned(node_id=peer.node_id):
                logger.info(f"[P2P] Rejecting outbound peer {addr}: node_id {peer.node_id[:16]} is banned")
                writer.close()
                await writer.wait_closed()
                return

            async with self._lock:
                existing = [p for p in self.peers.values() if p.node_id == peer.node_id]
                if existing:
                    _lb = h in ("127.0.0.1", "localhost", "::1")
                    if _dial_dup_action(self.node.node_id, peer.node_id, 'out', _lb, True) != 'replace_existing':
                        logger.debug(f"[P2P] Already connected to node {peer.node_id[:16]}, closing outbound duplicate")
                        writer.close()
                        await writer.wait_closed()
                        return
                    logger.debug(f"[P2P] DIAL-KEEPER-1 replacing duplicate socket to node {peer.node_id[:16]} with outbound keeper")
                    for _old in existing:
                        try:
                            if _old.writer is not None:
                                _old.writer.close()
                        except Exception:
                            pass
                        if self.peers.get(_old.address) is _old:
                            del self.peers[_old.address]

                peer_ip = h
                ip_conns = self._conn_per_ip.get(peer_ip, 0)
                is_bootstrap = any(peer_ip in b for b in self.bootstrap_nodes) or peer_ip == self.genesis_node
                if not is_bootstrap and ip_conns >= self._max_conn_per_ip:
                    # R8-subnet-order (R7-19): same order as inbound —
                    # per-IP rejection before subnet reservation.
                    logger.info(f"[P2P] Rejecting outbound peer {addr}: per-IP cap ({ip_conns}/{self._max_conn_per_ip})")
                    writer.close()
                    await writer.wait_closed()
                    return

                if not self._track_peer_subnet(peer):
                    logger.info(f"[P2P] Rejecting outbound peer {addr}: subnet diversity cap reached")
                    writer.close()
                    await writer.wait_closed()
                    return
                self._conn_per_ip[peer_ip] = ip_conns + 1

                if len(self.peers) >= self.max_peers:
                    oldest = min(self.peers.values(), key=lambda p: p.last_seen)
                    # R6-evict-socket-close: same close-before-del as the
                    # inbound path (incidental scope: identical defect).
                    try:
                        if oldest.writer is not None:
                            oldest.writer.close()
                    except Exception as _ev_e:
                        logger.debug(f"[P2P] evict close failed for {oldest.address}: {_ev_e}")
                    del self.peers[oldest.address]
                self.peers[peer.address] = peer
                self._metrics["connections"] += 1
                self._metrics["peers_discovered"] += 1
                # DIAL-BACKOFF-1: success clears any backoff for this addr.
                self._dial_note_result(addr, True)
            self._track_task(asyncio.create_task(self._send_message(peer, MSG_GET_STATUS, b'{}')))
            self.tip_push(peer)
            self._track_task(asyncio.create_task(self._peer_loop(peer)))
            logger.info(f"[P2P] Connected to peer: {peer.address} (node {peer.node_id[:16]})")
        except Exception as e:
            # DIAL-BACKOFF-1: record + bound the retry, throttle the log.
            _wait = self._dial_note_result(addr, False)
            self._dial_log_failure(
                addr, f"[P2P] Failed to connect to {addr}: {type(e).__name__}: {e} "
                      f"(retry in {_wait:.0f}s)")

    def _dial_note_result(self, addr: str, ok: bool) -> float:
        """DIAL-BACKOFF-1: per-address retry state for the outbound peer
        path. On failure returns the new backoff wait in seconds (bounded
        exponential: 5s * 2^n capped at 300s, plus 0-2s jitter); on success
        clears the address state and returns 0. Maps are bounded (5000
        entries) so a hostile MSG_PEERS flood cannot grow them forever.
        Callers check _dial_backoff before dialing and skip silently."""
        now = time.time()
        try:
            if ok:
                self._dial_fails.pop(addr, None)
                self._dial_backoff.pop(addr, None)
                return 0.0
            fails = int(self._dial_fails.get(addr, 0)) + 1
            self._dial_fails[addr] = fails
            wait = min(300.0, 5.0 * (2.0 ** min(fails - 1, 6))) + random.uniform(0, 2.0)
            self._dial_backoff[addr] = now + wait
            if len(self._dial_fails) > 5000:
                _oldest = next(iter(self._dial_fails))
                self._dial_fails.pop(_oldest, None)
                self._dial_backoff.pop(_oldest, None)
            return wait
        except Exception:
            return 0.0

    def _dial_log_failure(self, addr: str, msg: str) -> None:
        """Throttled dial-failure logging: INFO at most once per address
        per 60s, debug otherwise. The discovery loop redials every cycle;
        without this a dead seed emits an INFO line per cycle forever."""
        try:
            now = time.time()
            last = float(self._dial_last_log.get(addr, 0.0))
            if now - last > 60.0:
                self._dial_last_log[addr] = now
                if len(self._dial_last_log) > 5000:
                    self._dial_last_log.pop(next(iter(self._dial_last_log)), None)
                logger.info(msg)
            else:
                logger.debug(msg)
        except Exception:
            logger.debug(msg)

    # ─── DNS Seeds Resolution ──────────────────────────────────
    async def _resolve_dns_seeds(self) -> List[str]:
        loop = asyncio.get_running_loop()
        seeds = self.dns_seeds
        discovered_peers = []
        for seed in seeds:
            # DNS-DEFAULT-PORT-1: seeds without an explicit port resolve
            # against the PROTOCOL default (GENESIS_NODE_P2P_PORT), never
            # the mutable local P2P_PORT — a custom-port node must still
            # dial seeds on the network's port.
            host, port = parse_ip_port(seed, GENESIS_NODE_P2P_PORT)
            try:
                addr_info = await loop.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
                for item in addr_info:
                    sockaddr = item[4]
                    ip = sockaddr[0]
                    if ip not in (self.public_ip, "127.0.0.1", "::1", "0.0.0.0", "::"):
                        endpoint = f"{host}:{port}" if host and not host.replace('.', '').isdigit() else (f"[{ip}]:{port}" if ":" in str(ip) else f"{ip}:{port}")
                        if "101.127.80.48" in endpoint:
                            endpoint = endpoint.replace("101.127.80.48", GENESIS_NODE_HOST)
                        discovered_peers.append(endpoint)
            except Exception as e:
                logger.debug(f"[DNS] Failed to resolve DNS seed '{seed}': {e}")
        unique_peers = list(dict.fromkeys(discovered_peers))
        random.shuffle(unique_peers)
        if unique_peers:
            logger.info(f"[DNS] Resolved {len(unique_peers)} peer endpoints from {len(seeds)} DNS seeds")
        return unique_peers

    # ─── DHT Loop ──────────────────────────────────────────────
    async def _dht_loop(self):
        if not DHT_AVAILABLE:
            return
        try:
            self._dht_server = Server(storage=ForgetfulStorage())
            dht_listen_port = getattr(self, 'dht_port', DHT_PORT)
            await self._dht_server.listen(dht_listen_port)
            logger.info(f"[DHT] Server listening on port {dht_listen_port}")
            dht_seeds = getattr(self, 'dht_bootstrap_nodes', DHT_BOOTSTRAP_NODES)
            dht_bootstrap_ok = 0
            for ip, port in dht_seeds:
                try:
                    await self._dht_server.bootstrap([(ip, port)])
                    dht_bootstrap_ok += 1
                    logger.info(f"[DHT] Bootstrapped from {ip}:{port} ({dht_bootstrap_ok}/{len(dht_seeds)})")
                except Exception as e:
                    logger.debug(f"[DHT] Bootstrap to {ip}:{port} failed: {e}")
            if dht_bootstrap_ok == 0:
                logger.warning(f"[DHT] All {len(dht_seeds)} bootstrap attempts failed; will retry next cycle")

            my_shard_base = int(hashlib.sha256(self.node.node_id.encode()).hexdigest(), 16) % DHT_SHARD_COUNT
            dht_cycle = 0

            while not self._discovery_stop.is_set():
                if not self.public_ip:
                    await asyncio.sleep(30)
                    continue
                p2p_addr = f"{self.public_ip}:{_config.P2P_PORT}"
                my_shard = (my_shard_base + dht_cycle) % DHT_SHARD_COUNT
                dht_cycle += 1
                try:
                    shard_key = f"{DHT_PEERS_KEY_PREFIX}{my_shard}".encode()
                    raw = await self._dht_server.get(shard_key)
                    entries = []
                    if raw:
                        try:
                            entries = json.loads(raw.decode())
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            entries = []
                    now = time.time()
                    entries = [e for e in entries if isinstance(e, dict) and now - e.get("ts", 0) < DHT_ENTRY_TTL and e.get("node_id") != self.node.node_id]
                    entries.append({"addr": p2p_addr, "node_id": self.node.node_id, "ts": now})
                    entries = entries[-DHT_MAX_ENTRIES_PER_SHARD:]
                    await self._dht_server.set(shard_key, json.dumps(entries).encode())

                    # Re-bootstrap if our P2P peer table is empty (DHT has rotted)
                    if len(self.peers) == 0:
                        for ip, port in dht_seeds:
                            try:
                                await self._dht_server.bootstrap([(ip, port)])
                                logger.info(f"[DHT] Re-bootstrapped from {ip}:{port}")
                                break
                            except Exception:
                                continue

                    # Discover from other shards
                    for shard_i in range(DHT_SHARD_COUNT):
                        try:
                            raw_s = await self._dht_server.get(f"{DHT_PEERS_KEY_PREFIX}{shard_i}".encode())
                        except Exception:
                            continue
                        if not raw_s:
                            continue
                        try:
                            shard_entries = json.loads(raw_s.decode())
                        except (json.JSONDecodeError, UnicodeDecodeError):
                            continue
                        for e in shard_entries:
                            if not isinstance(e, dict):
                                continue
                            addr = e.get("addr")
                            node_id = e.get("node_id")
                            if not addr or addr == p2p_addr:
                                continue
                            if now - e.get("ts", 0) >= DHT_ENTRY_TTL:
                                continue
                            if addr in self.peers or self._is_banned(address=addr, node_id=node_id):
                                continue
                            self._track_task(asyncio.create_task(self._connect_to_peer(addr)))
                except Exception as e:
                    logger.debug(f"[DHT] Error: {e}")
                await asyncio.sleep(30)
        except Exception as e:
            logger.error(f"[DHT] DHT failed: {e}")

    # ─── Discovery Loop ─────────────────────────────────────────
    async def _discovery_loop(self):
        while not self._discovery_stop.is_set():
            dns_peers = await self._resolve_dns_seeds()
            for addr in dns_peers:
                if not self._is_peer_connected(addr) and not self._is_banned(address=addr):
                    await self._connect_to_peer(addr)
                    if len(self.peers) >= self.max_peers:
                        break

            for addr in self.bootstrap_nodes:
                if not self._is_peer_connected(addr) and not self._is_banned(address=addr):
                    await self._connect_to_peer(addr)

            cached = load_peers_from_cache()
            for addr in cached:
                if not self._is_peer_connected(addr) and not self._is_banned(address=addr):
                    await self._connect_to_peer(addr)

            # Fallback nodes: try if we have too few peers
            if len(self.peers) < 3 and self.fallback_nodes:
                for addr in self.fallback_nodes:
                    if not self._is_peer_connected(addr) and not self._is_banned(address=addr):
                        await self._connect_to_peer(addr)

            # Query existing peers for new peers (Peer Exchange / PEX)
            async with self._lock:
                peers_copy = list(self.peers.values())
            for peer in peers_copy:
                try:
                    await self._send_message(peer, MSG_GET_PEERS, b'{}')
                except Exception:
                    pass

            if len(self.peers) == 0:
                await asyncio.sleep(5.0 + random.uniform(0.5, 2.0))
            else:
                interval = self.config_discovery_interval if hasattr(self, "config_discovery_interval") else DISCOVERY_INTERVAL
                await asyncio.sleep(interval)

    # ─── Heartbeat and Sync ─────────────────────────────────────
    async def _heartbeat_loop(self):
        while not self._discovery_stop.is_set():
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            if self.node and self.node.node_id:
                try:
                    await self.node.node_repo.update_height(self.node.node_id, self.node.height)
                except Exception as error:
                    logger.debug(f"[P2P] Local node heartbeat failed: {error}")
            async with self._lock:
                peers_copy = list(self.peers.values())
            now = time.time()
            ping_payload = json.dumps({"height": self.node.height}).encode()
            for peer in peers_copy:
                if now - peer.last_seen > 90:
                    logger.info(f"[P2P] Peer {peer.address} timed out (no activity for >90s) - closing")
                    try:
                        peer.writer.close()
                    except Exception:
                        pass
                    # Remove the entry so a dead peer can't be re-reported every
                    # interval, selected by sync as best_peer, or block a fresh
                    # redial as a duplicate.
                    async with self._lock:
                        if self.peers.get(peer.address) is peer:
                            del self.peers[peer.address]
                    continue
                try:
                    await self._send_message(peer, MSG_PING, ping_payload)
                except Exception:
                    pass

    async def _request_checkpoints(self, peers: List[EncryptedPeer], timeout: float = 5.0) -> Optional[Dict]:
        futures = {}
        for peer in peers:
            fut = asyncio.get_event_loop().create_future()
            self._pending_checkpoint_requests[peer.address] = fut
            futures[peer.address] = fut
            try:
                await self._send_message(peer, MSG_GET_CHECKPOINT, b'')
            except Exception:
                pass

        try:
            await asyncio.wait(futures.values(), timeout=timeout)
        finally:
            for addr in futures:
                self._pending_checkpoint_requests.pop(addr, None)

        responses = []
        for addr, fut in futures.items():
            if fut.done() and not fut.cancelled():
                try:
                    resp = fut.result()
                    if resp and resp.get("block_id", 0) > 0:
                        responses.append((resp["block_id"], resp.get("hash", "")))
                except Exception:
                    pass

        if not responses:
            return None
        if len(responses) == 1:
            logger.warning("[Sync] Only one peer answered a checkpoint request — using it, but quorum could not be established.")
            block_id, chash = responses[0]
            return {"block_id": block_id, "hash": chash}

        tally = {}
        for r in responses:
            tally[r] = tally.get(r, 0) + 1
        best, count = max(tally.items(), key=lambda kv: kv[1])
        if count * 2 > len(responses):
            return {"block_id": best[0], "hash": best[1]}
        logger.warning(f"[Sync] No majority agreement on latest checkpoint among {len(responses)} peers — falling back to single-peer sync.")
        return None

    async def _sync_loop(self):
        while not self._discovery_stop.is_set():
            await asyncio.sleep(SYNC_INTERVAL)
            # STUCK-CYCLE guard: while tripped, skip GET_BLOCKS entirely for
            # SYNC_STUCK_TRIP_COOLDOWN seconds instead of hammering forever.
            if time.time() < getattr(self, "_sync_paused_until", 0.0):
                continue
            async with self._lock:
                peer_list = list(self.peers.values())
            if not peer_list:
                continue
            # STUCK-CYCLE rotation: exclude the peer that last made us stall so
            # one broken or hostile peer cannot keep tripping us on its own.
            stuck_peer = getattr(self, "_stuck_peer", None)
            candidates = [p for p in peer_list if getattr(p, "address", None) != stuck_peer] or peer_list
            best_peer = max(candidates, key=lambda p: p.height)
            best_height = best_peer.height
            if best_height == self.node.height:
                # IDEA5-FORK-HEAL-1: heights equal but tips may differ
                # (sibling split). The old gate (best_height <= height ->
                # continue) never fetched the fork, so equal-height splits
                # healed only via a later height-gap sync (up to minutes) —
                # the S8/S10 stall class. Fetch the recent window: import
                # weight-sum picks the heavier chain, hash-equal blocks
                # skip, so the steady state is a cheap no-op.
                _fh_start = max(0, self.node.height - 51)
                _fh_payload = json.dumps({"start": _fh_start, "end": self.node.height + 1}).encode()
                await self._send_message(best_peer, MSG_GET_BLOCKS, _fh_payload)
                continue
            if best_height < self.node.height:
                continue

            gap = best_height - self.node.height
            logger.info(f"[P2P] Syncing from {best_peer.address}: local={self.node.height}, remote={best_height}")

            if gap > CHECKPOINT_SYNC_THRESHOLD:
                sample_peers = sorted(peer_list, key=lambda p: -p.height)[:5]
                checkpoint = await self._request_checkpoints(sample_peers)
                if checkpoint:
                    logger.info(f"[Sync] Quorum-agreed checkpoint at block {checkpoint['block_id']} — anchoring catch-up sync on it")

            max_chunks_this_cycle = 25
            rewound_this_stall = False
            for _ in range(max_chunks_this_cycle):
                if self.node.height >= best_height:
                    break
                start = self.node.height
                end = min(best_height, start + 500)
                payload = json.dumps({"start": start, "end": end}).encode()
                await self._send_message(best_peer, MSG_GET_BLOCKS, payload)

                waited = 0.0
                while self.node.height <= start and waited < 8.0:
                    await asyncio.sleep(0.25)
                    waited += 0.25
                if self.node.height <= start and not rewound_this_stall:
                    # Our tip may sit on a lighter fork: blocks above our tip
                    # on the peer's chain have ancestors we lack, so import
                    # never finds a common parent. One bounded rewind re-fetches
                    # the fork window (import scans back 100 blocks for the
                    # common ancestor) so the weight-based reorg can trigger.
                    rewound_this_stall = True
                    rewind_start = max(0, start - 100)
                    logger.info(
                        f"[Sync] No progress on [{start},{end}); rewinding fetch to "
                        f"[{rewind_start},{end}) to locate fork point"
                    )
                    payload = json.dumps({"start": rewind_start, "end": end}).encode()
                    await self._send_message(best_peer, MSG_GET_BLOCKS, payload)
                    waited = 0.0
                    # Rewind batches span the whole known chain plus the fork
                    # window; give verification of the fork blocks more than
                    # the normal 8s progress window before declaring failure.
                    while self.node.height <= start and waited < 30.0:
                        await asyncio.sleep(0.25)
                        waited += 0.25
                if self.node.height <= start:
                    logger.warning(
                        f"[Sync] Stuck at height {self.node.height} — no progress importing "
                        f"[{start},{end}) from {best_peer.address}. "
                        f"Tip is likely below a rejected block. Check logs above for "
                        f"[Verify] rejections; the loop will rotate to another peer and "
                        f"auto-retry after a cooldown."
                    )
                    self._stuck_cycles = getattr(self, "_stuck_cycles", 0) + 1
                    self._stuck_peer = best_peer.address
                    if self._stuck_cycles >= 3:
                        # STUCK-CYCLE guard: pause GET_BLOCKS (this loop) and block
                        # production for SYNC_STUCK_TRIP_COOLDOWN instead of spamming
                        # forever or halting permanently. Both resume automatically;
                        # production re-enables only once sync makes progress again.
                        self._sync_paused_until = time.time() + SYNC_STUCK_TRIP_COOLDOWN
                        self.node._producing_enabled = False
                        logger.error(
                            f"[Sync] Three consecutive stuck cycles — pausing GET_BLOCKS "
                            f"and block production for {SYNC_STUCK_TRIP_COOLDOWN}s "
                            f"(auto-retry with peer rotation; production re-enables once "
                            f"sync progress resumes). A restart also clears this state."
                        )
                    break
                self._stuck_cycles = 0
                self._stuck_peer = None
                if not self.node._producing_enabled and not self.node._shutdown_flag:
                    self._sync_paused_until = 0.0
                    self.node._producing_enabled = True
                    logger.info("[Sync] Progress resumed after stuck-cycle trip — re-enabling block production.")
                rewound_this_stall = False

    async def _cache_loop(self):
        while not self._discovery_stop.is_set():
            await asyncio.sleep(300)
            async with self._lock:
                peers = list(self.peers.keys())
            save_peers_to_cache(peers)

    # ─── Public API ─────────────────────────────────────────────
    def get_peer_count(self) -> int:
        return len(self.peers)

    def get_metrics(self) -> dict:
        return {
            "peers": len(self.peers),
            "banned": len(self.banned_peers),
            "messages_sent": self._metrics["messages_sent"],
            "messages_received": self._metrics["messages_received"],
            "bytes_sent": self._metrics["bytes_sent"],
            "bytes_received": self._metrics["bytes_received"],
            "connections": self._metrics["connections"],
            "errors": self._metrics["errors"],
        }

    async def sync_with_peers(self):
        if not self.peers:
            return
        best_peer = max(self.peers.values(), key=lambda p: p.height)
        latest = await self.node.block_repo.get_latest()
        if latest is None:
            batch_end = min(best_peer.height, 500)
            logger.info(f"[SYNC] Requesting genesis/initial blocks from {best_peer.address} (0 -> {batch_end} of {best_peer.height})")
            payload = json.dumps({"start": 0, "end": batch_end}).encode()
            await self._send_message(best_peer, MSG_GET_BLOCKS, payload)
            await asyncio.sleep(2)
            return

        if best_peer.height <= self.node.height:
            return
        batch_end = min(best_peer.height, self.node.height + 500)
        logger.info(f"[SYNC] Starting sync from {best_peer.address} (height {self.node.height} -> {batch_end} of {best_peer.height})")
        payload = json.dumps({"start": self.node.height, "end": batch_end}).encode()
        await self._send_message(best_peer, MSG_GET_BLOCKS, payload)
        await asyncio.sleep(2)


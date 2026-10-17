# Split of MCX81.py (lines 7937-10071). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import eth_keccak, logger
from node.config import BASE_DENSITY_PPM, BASE_TURBULENCE_PPM, BLOCK_TIME, CHAIN_ID, CONSENSUS_EXCLUDED_FIELDS, EPOCH_LENGTH, GROWTH_DIFFICULTY_EXP, MAX_SUPPLY, MAX_TX_PER_BLOCK, MIN_MAZE_SIZE, MIN_WALL_DENSITY_PPM, OFFLINE_DECAY_RATE, SHRINK_INTERVAL, SNAPSHOT_INTERVAL, SUBS, VERSION, _filter_validator_candidates, _maze_threshold, _maze_ticket, _tx_declared_gas, _valid_maze_size, mutate_maze_walls
from node.genesis import ConsensusRng
from node.crypto import _block_timestamp_ok, canonical_json_bytes, compute_merkle_root, verify_signature_bytes
from node.chain import get_block_reward
from node.database import LotteryRepo, MazeAttestationRepo, SlashRepo
from node.maze import DIRS_3D, Maze3DGenerator, SparseMaze, dense_to_sparse, sparse_to_dense
from node.bootstrap import Dict, List, Optional, OrderedDict, Set, ThreadPoolExecutor, Tuple, asyncio, deque, hashlib, json, time
from node import config as _config


# ─── PoMRConsensus (Multi-Maze with Shared Learning) ───────
_SEAL_TS_LOG_AT = {}
_SEAL_TS_LOG_INTERVAL = 60.0


def _seal_ts_log_due(key: str) -> bool:
    """FP1-LOGBOUND-1: at most one seal-deferral log line per key per
    minute. Pure time check over monotonic wall-clock; never raises."""
    try:
        now = time.monotonic()
    except Exception:
        return True
    try:
        last = _SEAL_TS_LOG_AT.get(key, 0.0)
        if now - last < _SEAL_TS_LOG_INTERVAL:
            return False
        _SEAL_TS_LOG_AT[key] = now
        return True
    except Exception:
        return True


class PoGConsensus:
    DIRS = DIRS_3D

    def __init__(self, node):
        self.node = node
        self.round_active = False
        self.block_id = -1
        self.epoch = 0

        self._move_locks: Dict[str, asyncio.Lock] = {}
        self._inflight_moves: set = set()
        self._move_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="move")
        self._watchdog_task = None
        self._height_last_advanced = time.time()
        self._catch_times = deque(maxlen=20)
        self.block_times = deque(maxlen=20)

        self.db = node.db
        self.block_repo = node.block_repo
        self.tx_repo = node.tx_repo
        self.miner_repo = node.miner_repo
        self.balance_repo = node.balance_repo
        self.network_state_repo = node.network_state_repo
        self.receipt_repo = node.receipt_repo
        self.maze_repo = node.maze_repo
        self.maze_attestation_repo = getattr(node, 'maze_attestation_repo', None) or MazeAttestationRepo(self.db)
        self.mempool = node.mempool
        self.finality_repo = node.finality_repo
        self.vm_manager = node.vm_manager
        self.epoch_length = EPOCH_LENGTH

        self._pending_pow: Dict[str, Tuple[str, int, float]] = {}  # seed, difficulty, timestamp

        # Accumulated maze catch events since last block. Each entry is a dict
        # with miner_id, old_size, new_size, old_density, new_density, knowledge,
        # mazeroot, seed, etc. Drained by produce_block and included in the block.
        self._pending_maze_updates: List[Dict] = []

        # SLASH-REPLICA: slash events queued since this node last sealed a
        # block. Carried in block['slashes'] so followers apply the same
        # reductions — slash effects were previously node-local only.
        self._pending_slashes: List[Dict] = []

        # In-memory per-maze learning state (keyed by maze_id). Not persisted on
        # purpose: it tracks the miner's exploration trace so the goal can flee
        # into unexplored regions. Survives while the node runs.
        self._maze_visited: Dict[str, Set[Tuple[int, int, int]]] = {}
        self._sealed_walls: Dict[str, set] = {}  # maze_id -> set of sealed (x,y,z) cells (walls closing behind miner)
        self._goal_move_nonce: Dict[str, int] = {}   # how many times goal has moved
        # Previous goal position per maze — goal won't move back to where it was last turn
        self._goal_prev_pos: Dict[str, Tuple[int, int, int]] = {}
        # Recent goal positions per maze — goal won't cycle between tied cells
        self._goal_recent: Dict[str, deque] = {}  # maze_id -> deque(maxlen=4) of recent goal positions
        # Goal flee cooldown: goal only flees every N moves (not every move)
        self._goal_flee_cooldown: Dict[str, int] = {}

        # Oscillation tracker: maze_id -> deque of last 4 positions
        # If positions alternate A→B→A→B, miner is oscillating and excluded from lottery
        self._pos_history: Dict[str, deque] = {}
        # Oscillating mazes are blocked from lottery until position changes
        self._oscillating_mazes: Set[str] = set()

        # Ghost oscillation sweep state (active when maze_id in _oscillating_mazes)
        self._ghost_frozen_target: Dict[str, Tuple[int, int, int]] = {}
        self._ghost_cycle: Dict[str, list] = {}
        self._ghost_cycle_idx: Dict[str, int] = {}

        # Maze cache: keyed by (seed_hex, size, density_ppm, turb_ppm) -> maze array.
        # Avoids regenerating the same deterministic maze multiple times.
        self._maze_cache: OrderedDict = OrderedDict()
        self._maze_cache_max = 256

        # Global average maze size – updated every block by production_loop.
        # Drives GLOBAL_SHRINK_FACTOR and difficulty scaling.
        self._global_avg_size: float = 5.0

        # Commit-reveal lottery: height -> {miner_id: value}
        self._lottery_commits: Dict[int, Dict[str, str]] = {}
        self._lottery_reveals: Dict[int, Dict[str, str]] = {}

        # Persistent lottery/slash repos (node-level instances are reused when present)
        self.lottery_repo = getattr(node, 'lottery_repo', None) or LotteryRepo(self.db)
        self.slash_repo = getattr(node, 'slash_repo', None) or SlashRepo(self.db)
        # Per-miner signing refusal counter (MAX_MISSES ban driver)
        self._signing_refusals: Dict[str, int] = {}

    def _lock_for(self, maze_id: str) -> asyncio.Lock:
        return self._move_locks.setdefault(maze_id, asyncio.Lock())

    async def _produce_timestamp_ok(self, block_id: int, ts) -> bool:
        # SEAL-SELF-VERIFY-TS-1: the producer must not seal what verifiers
        # reject. Mirrors verify_block_proof's parent-relative timestamp
        # rule (_block_timestamp_ok) on the seal path: strictly after the
        # parent, within BLOCK_FUTURE_SKEW, keyed off the parent row only.
        #
        # SEAL-TS-FAILCLOSED-1: this gate FAILS CLOSED. It used to return
        # True when the parent lookup raised and when the parent row was
        # missing, so a repository error let the producer execute txs and
        # seal a block whose timestamp was never checked. Now only the
        # genesis position (block_id <= 0: no parent exists by
        # construction) has nothing to compare against. Genesis is persisted
        # at id 0 before any block is produced and pruning never removes
        # the tip (prune_height = height - prune_blocks), so for block_id >= 1
        # the parent (block_id - 1) always exists on a healthy node; a
        # lookup error, a missing parent, or an unreadable parent timestamp
        # means the check cannot be made and the seal is deferred.
        # Block-validity rules (_block_timestamp_ok) are unchanged: this only
        # alters producer error handling, so peers see the same chain rules.
        try:
            _ts = float(ts)
            _bid = int(block_id)
        except (TypeError, ValueError, OverflowError):
            return False
        if _bid <= 0:
            return True
        try:
            parent = await self.block_repo.get_by_id(_bid - 1)
        except Exception as _e:
            # FP1-LOGBOUND-1: a persistently broken parent lookup would
            # otherwise log an ERROR every deferral (~1/sec). Throttle the
            # repeat; the deferral itself is unchanged.
            if _seal_ts_log_due("lookup"):
                logger.error(f"[SEAL-TS-FAILCLOSED-1] block {block_id}: parent lookup failed "
                             f"({type(_e).__name__}: {str(_e)[:120]!r}) — timestamp unverifiable, deferring seal")
            return False
        if not parent:
            if _seal_ts_log_due("missing"):
                logger.error(f"[SEAL-TS-FAILCLOSED-1] block {block_id}: parent {_bid - 1} not found "
                             f"— timestamp unverifiable, deferring seal")
            return False
        _pts = parent.get('ts', 0)
        if hasattr(_pts, 'timestamp'):
            try:
                _pts = _pts.timestamp()
            except Exception:
                return False
        try:
            return _block_timestamp_ok(_ts, _pts)
        except (OverflowError, ArithmeticError):
            # float(parent_ts) of an out-of-range int: unreadable parent ts.
            return False

    @staticmethod
    def _maze_weight(size: int) -> int:
        if size <= 5:
            return 0
        return size ** 3 - 125

    def _apply_shrink(self, row: dict, current_height: int = None) -> dict:
        # Shrink is a pure function of (lastactiveheight, current_height).
        # No time.time() calls — deterministic for all verifiers.
        last_height = int(row.get("lastactiveheight", 0))
        height = current_height if current_height is not None else 0
        if height <= last_height:
            return row
        raw_steps = (height - last_height) // SHRINK_INTERVAL
        if raw_steps <= 0:
            return row

        size = int(row["size"])
        if size <= MIN_MAZE_SIZE:
            return row

        per_step = OFFLINE_DECAY_RATE * _config.GLOBAL_SHRINK_FACTOR
        total_loss = per_step * raw_steps
        if total_loss < 1.0:
            return row

        loss = int(total_loss)
        new_size = max(MIN_MAZE_SIZE, size - loss)
        actual_loss = size - new_size
        if actual_loss <= 0:
            return row

        new_row = dict(row)
        new_row["size"] = new_size
        # Shrink clamps pos/goal into the smaller grid. Without this a maze
        # can end up with coordinates outside [0, size) (e.g. pos (13,9,10)
        # in a 5³ maze) — the miner then reports "No path to goal" forever,
        # never moves, lastactiveheight rots to -1000000, and the maze is
        # permanently ineligible (chain halt: "Eligible mazes: []").
        _nmax = new_size - 1
        for _k in ("posx", "posy", "posz", "goalx", "goaly", "goalz"):
            new_row[_k] = max(0, min(int(row.get(_k, 0)), _nmax))
        if (new_row["posx"], new_row["posy"], new_row["posz"]) == \
           (new_row["goalx"], new_row["goaly"], new_row["goalz"]):
            # Clamping collapsed spawn onto goal — nudge spawn back one cell
            # so the maze is still winnable (goal stays authoritative).
            new_row["posx"] = max(0, new_row["goalx"] - 1)
        new_row["walldensityppm"] = max(MIN_WALL_DENSITY_PPM, int(row["walldensityppm"]) - actual_loss * 15000)
        new_row["turbulenceppm"] = max(0, int(row["turbulenceppm"] * (0.85 ** actual_loss)))
        return new_row

    def _compute_new_maze_params(self, row: dict, catch_height: int, entropy: bytes) -> dict:
        newsize = int(row["size"]) + 1
        # Density and turbulence scale with global average maze size.
        # Even at start, maze is already 50% walls (BASE_DENSITY_PPM).
        # As network grows, difficulty increases globally.
        avg = self._global_avg_size
        newdensity = int(BASE_DENSITY_PPM + (avg ** 1.5) * 200)
        newturb = int(BASE_TURBULENCE_PPM + (avg ** 1.5) * 50)
        newseed = eth_keccak(
            b"MCXPOGGROWTHV1"
            + bytes.fromhex(row["seed"])
            + entropy
            + row["minerid"].encode()
            + int(row["growthcount"] + 1).to_bytes(8, "big")
        ).hex()
        return {
            "size": newsize,
            "walldensityppm": newdensity,
            "turbulenceppm": newturb,
            "seed": newseed,
            "growthcount": int(row["growthcount"]) + 1,
            "consecutivewallhits": 0,
            "lastgoalheight": catch_height,
        }

    def _select_open_cell(self, maze, seed_bytes: bytes, exclude: Tuple[int, int, int] = None) -> Tuple[int, int, int]:
        open_cells = Maze3DGenerator.open_cells(maze)
        if not open_cells:
            return (0, 0, 0)
        if exclude and len(open_cells) > 1:
            open_cells = [c for c in open_cells if c != exclude]
        idx = int.from_bytes(eth_keccak(b"MCXPOGGOALV1" + seed_bytes), "big") % len(open_cells)
        return open_cells[idx]

    def _select_spawn(self, maze, prev_pos: Tuple[int, int, int], seed_bytes: bytes) -> Tuple[int, int, int]:
        open_cells = Maze3DGenerator.open_cells(maze)
        if not open_cells:
            return (0, 0, 0)
        if prev_pos in open_cells:
            return prev_pos
        return open_cells[int.from_bytes(eth_keccak(b"MCXPOGSPAWNV1" + seed_bytes), "big") % len(open_cells)]

    def _generate_deterministic_maze(self, seed_hex: str, size: int, density_ppm: int, turb_ppm: int, block_height: int = 0) -> SparseMaze:
        # MAZE-MIN-1: fail closed on undersized dimensions (verify callers
        # turn this into block rejection; prod paths only pass valid sizes).
        _size = _valid_maze_size(size)
        if _size is None:
            raise ValueError(f"refusing to generate maze with invalid size {size!r}")
        size = _size
        cache_key = (seed_hex, size, density_ppm, turb_ppm)
        if cache_key in self._maze_cache:
            self._maze_cache.move_to_end(cache_key)
            return self._maze_cache[cache_key]

        rng = ConsensusRng(bytes.fromhex(seed_hex))
        density = density_ppm / 1_000_000.0
        maze = [[[True] * size for _ in range(size)] for _ in range(size)]

        def carve(x0, y0, z0, x1, y1, z1):
            width, depth, height = x1 - x0, y1 - y0, z1 - z0
            if min(width, depth, height) <= 2:
                for z in range(z0, z1):
                    for y in range(y0, y1):
                        for x in range(x0, x1):
                            maze[z][y][x] = False
                return
            axis = 0
            max_dim = width
            if depth > max_dim:
                axis = 1; max_dim = depth
            if height > max_dim:
                axis = 2
            bounds = [(x0, x1), (y0, y1), (z0, z1)]
            low, high = bounds[axis]
            split = rng.randbelow(high - low - 2) + low + 1
            bounds_a = [list(b) for b in bounds]
            bounds_b = [list(b) for b in bounds]
            bounds_a[axis][1] = split
            bounds_b[axis][0] = split + 1
            carve(bounds_a[0][0], bounds_a[1][0], bounds_a[2][0],
                  bounds_a[0][1], bounds_a[1][1], bounds_a[2][1])
            carve(bounds_b[0][0], bounds_b[1][0], bounds_b[2][0],
                  bounds_b[0][1], bounds_b[1][1], bounds_b[2][1])
            px = rng.randbelow(x1 - x0) + x0
            py = rng.randbelow(y1 - y0) + y0
            pz = rng.randbelow(z1 - z0) + z0
            passage = [px, py, pz]
            passage[axis] = split
            maze[passage[2]][passage[1]][passage[0]] = False
            adj = list(passage)
            adj[axis] += 1
            maze[adj[2]][adj[1]][adj[0]] = False

        carve(0, 0, 0, size, size, size)
        maze[0][0][0] = False
        maze[size - 1][size - 1][size - 1] = False

        if not Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
            logger.warning(f"[Maze] BSP carve not connected for size={size}, retrying with dense fill fallback")
            maze = [[[True] * size for _ in range(size)] for _ in range(size)]
            for z in range(size):
                for y in range(size):
                    for x in range(size):
                        maze[z][y][x] = False
            maze[0][0][0] = False
            maze[size - 1][size - 1][size - 1] = False

        # Add extra walls — density_ratio derived from walldensityppm.
        # density_ppm=500000 → ratio=0.50 → ~25% open. Higher ppm = denser maze.
        density_ratio = max(0.25, min(0.90, density_ppm / 1_000_000.0))
        open_cells = [(x, y, z) for z in range(size) for y in range(size) for x in range(size)
                       if not maze[z][y][x] and (x, y, z) not in ((0,0,0), (size-1,size-1,size-1))]
        for i in range(len(open_cells) - 1, 0, -1):
            j = rng.randbelow(i + 1)
            open_cells[i], open_cells[j] = open_cells[j], open_cells[i]
        extra = int(len(open_cells) * density_ratio)
        for x, y, z in open_cells[:extra]:
            maze[z][y][x] = True
            if not Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
                maze[z][y][x] = False

        # Break ALL straight corridors: every 2+ open cells gets a wall
        corridor_threshold = 2
        corridor_chance = 95
        for axis in range(3):
            for a in range(size):
                for b in range(size):
                    run = 0
                    for c in range(size):
                        coords = [0, 0, 0]
                        coords[axis] = c
                        coords[(axis+1)%3] = a
                        coords[(axis+2)%3] = b
                        x, y, z = coords
                        if not maze[z][y][x]:
                            run += 1
                            if run >= corridor_threshold and rng.randbelow(100) < corridor_chance:
                                if (x, y, z) not in [(0, 0, 0), (size-1, size-1, size-1)]:
                                    maze[z][y][x] = True
                                    if not Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
                                        maze[z][y][x] = False
                                    run = 0
                        else:
                            run = 0

        if not Maze3DGenerator.is_connected(maze, (0, 0, 0), (size - 1, size - 1, size - 1)):
            logger.warning(f"[Maze] Final connectivity check failed for size={size}, reverting extra walls")
            maze = [[[False] * size for _ in range(size)] for _ in range(size)]
            for z in range(size):
                for y in range(size):
                    for x in range(size):
                        maze[z][y][x] = False
            maze[0][0][0] = False
            maze[size-1][size-1][size-1] = False

        sparse = dense_to_sparse(maze)

        if len(self._maze_cache) >= self._maze_cache_max:
            self._maze_cache.popitem(last=False)
        self._maze_cache[cache_key] = sparse
        return sparse

    def _calculate_maze_root(self, maze) -> str:
        if isinstance(maze, SparseMaze):
            flat = bytearray()
            for z in range(maze.size):
                for y in range(maze.size):
                    for x in range(maze.size):
                        flat.append(1 if (x, y, z) in maze.walls else 0)
        else:
            flat = bytearray()
            for z in range(len(maze)):
                for y in range(len(maze[z])):
                    for x in range(len(maze[z][y])):
                        flat.append(1 if maze[z][y][x] else 0)
        return eth_keccak(bytes(flat)).hex()

    # Stake-based leader election removed — lottery determines block producer

    async def get_active_miners(self) -> List[Dict]:
        miners = await self.miner_repo.get_active()
        return [miner for miner in miners if miner.get('miner_id') in self.node.miner_websockets]

    async def get_active_miner_ids(self) -> List[str]:
        miners = await self.get_active_miners()
        return [m['miner_id'] for m in miners]

    @staticmethod
    def _ghost_tuple(row) -> Optional[tuple]:
        """Ghost position lives on the maze row (ghostx/ghosty/ghostz columns)."""
        if not row:
            return None
        gx, gy, gz = row.get('ghostx'), row.get('ghosty'), row.get('ghostz')
        if gx is None or gy is None or gz is None:
            return None
        return (int(gx), int(gy), int(gz))

    @staticmethod
    def _set_ghost(d: dict, ghost) -> None:
        """Write a ghost tuple (or None) onto ghostx/ghosty/ghostz of a row dict."""
        if ghost is None:
            d['ghostx'] = None
            d['ghosty'] = None
            d['ghostz'] = None
        else:
            d['ghostx'] = int(ghost[0])
            d['ghosty'] = int(ghost[1])
            d['ghostz'] = int(ghost[2])

    @staticmethod
    def _move_auth_bytes(miner_id: str, maze_id_val: str, growthcount, move_nonce, direction: str) -> bytes:
        """MOVE-AUTH canonical bytes: shared by live process_move and
        MSG_NEW_MOVE gossip verification so both sides sign/verify the
        exact same payload."""
        return canonical_json_bytes({
            "domain": "MCXPOGMOVEV1",
            "chainid": CHAIN_ID,
            "minerid": miner_id,
            "mazeid": maze_id_val,
            "mazeversion": int(growthcount),
            "movenonce": int(move_nonce),
            "direction": direction,
        })

    async def process_move(self, miner_id: str, maze_id: str, direction: str, signature: str, move_nonce: int = None) -> Tuple[bool, str, dict]:
        from node.p2p import POW_BASE_DIFFICULTY  # lazy: forward ref, runtime-only
        async with self._lock_for(maze_id):
            if direction not in self.DIRS:
                return False, "Invalid direction", {}

            miner = await self.miner_repo.get(miner_id)
            if not miner:
                return False, "Unknown miner", {}

            row = await self.maze_repo.get_by_maze_id(maze_id)
            if not row:
                return False, "No maze state", {}

            # MAZE-OWNER-1: the signer may only move a maze it owns. The
            # signature below binds (miner_id, maze_id) but is verified
            # against miner_id's own key, so without this check any
            # registered miner could sign a valid move for ANOTHER miner's
            # maze_id. Reject before any state read/mutation.
            if str(row.get("minerid") or "") != str(miner_id):
                logger.warning(f"[MAZE-OWNER-1] move rejected: signer {str(miner_id)[:16]} does not own maze {str(maze_id)[:16]}")
                return False, "Maze not owned by signer", {}

            expected_nonce = int(row["movenonce"]) + 1
            if move_nonce is not None and move_nonce != expected_nonce:
                return False, f"Nonce mismatch: expected {expected_nonce}, got {move_nonce}", {}
            move_nonce = expected_nonce

            auth_msg = self._move_auth_bytes(
                miner_id, row.get("maze_id") or miner_id,
                row["growthcount"], move_nonce, direction)
            if not verify_signature_bytes(miner['pub'], auth_msg, signature):
                logger.warning(f"[SIG FAIL] minerid={miner_id} mazeid={row.get('maze_id')} growthcount={row['growthcount']} movenonce={move_nonce} dir={direction} chainid={CHAIN_ID}")
                logger.warning(f"[SIG FAIL] pub={miner['pub']} sig={signature[:32]}... auth_msg={auth_msg}")
                return False, "Invalid signature", {}

            if maze_id in self._pending_pow:
                seed, difficulty, ts = self._pending_pow[maze_id]
                if time.time() - ts > 60:
                    self._pending_pow.pop(maze_id, None)
                else:
                    return False, "Wall hit", {"type": "wall_hit", "seed": seed, "difficulty": difficulty}

            size = int(row["size"])
            sx, sy, sz = int(row["posx"]), int(row["posy"]), int(row["posz"])
            dx, dy, dz = self.DIRS[direction]
            nx, ny, nz = sx + dx, sy + dy, sz + dz

            maze_seed = bytes.fromhex(row["seed"])
            loop = asyncio.get_event_loop()
            maze = await loop.run_in_executor(
                None, self._generate_deterministic_maze,
                row["seed"], size, int(row["walldensityppm"]), int(row["turbulenceppm"]), self.node.height)

            if not (0 <= nx < size and 0 <= ny < size and 0 <= nz < size):
                return False, "Out of bounds", {}
            if maze[nz][ny][nx]:
                wall_seed = eth_keccak(
                    b"MCXPOGWALLV1"
                    + bytes.fromhex(row["mazeroot"])
                    + miner_id.encode()
                    + move_nonce.to_bytes(8, "big")
                    + bytes((nx, ny, nz))
                ).hex()
                # Wall-hit PoW: difficulty scales with global avg maze size
                difficulty = int(POW_BASE_DIFFICULTY + max(0, self._global_avg_size - 5) * GROWTH_DIFFICULTY_EXP)
                row["consecutivewallhits"] = int(row["consecutivewallhits"]) + 1
                await self.maze_repo.upsert({**dict(row), "updatedat": int(time.time())})
                self._pending_pow[maze_id] = (wall_seed, difficulty, time.time())
                # Ghost still advances on wall hits
                ghost_pos = self._ghost_tuple(row)
                if ghost_pos:
                    gdx, gdy, gdz = self._bfs_next_step(maze, size, ghost_pos, (sx, sy, sz))
                    if gdx is not None:
                        new_gpos = (ghost_pos[0]+gdx, ghost_pos[1]+gdy, ghost_pos[2]+gdz)
                        self._set_ghost(row, new_gpos)
                        await self.maze_repo.upsert({**dict(row), "updatedat": int(time.time())})
                        if new_gpos == (sx, sy, sz):
                            restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                            if restart_ev:
                                self._set_ghost(row, self._ghost_tuple(restart_ev))
                                await self.maze_repo.upsert({**dict(row), **restart_ev})
                                # Propagate ghost-catch shrink to block (consensus sync)
                                ghost_update = {
                                    "maze_id": row.get("maze_id") or miner_id,
                                    "miner_id": miner_id, "height": self.node.height,
                                    "old_size": size, "new_size": restart_ev.get("size", size),
                                    "old_density": int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM)),
                                    "new_density": restart_ev.get("walldensityppm", int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM))),
                                    "seed": restart_ev.get("seed", row["seed"]),
                                    "mazeroot": restart_ev.get("mazeroot", row.get("mazeroot", "")),
                                    "goal": [restart_ev.get("goalx", row["goalx"]), restart_ev.get("goaly", row["goaly"]), restart_ev.get("goalz", row["goalz"])],
                                    "spawn": [restart_ev.get("posx", row["posx"]), restart_ev.get("posy", row["posy"]), restart_ev.get("posz", row["posz"])],
                                    "turbulenceppm": restart_ev.get("turbulenceppm", 0),
                                }
                                self._pending_maze_updates.append(ghost_update)
                resp_ghost = self._ghost_tuple(row)
                return False, "Wall hit", {"type": "wall_hit", "seed": wall_seed, "difficulty": difficulty,
                    "ghost": list(resp_ghost) if resp_ghost else None,
                    "position": [sx, sy, sz], "size": size, "movenonce": int(row["movenonce"]),
                    "growthcount": int(row["growthcount"])}

            gx, gy, gz = int(row["goalx"]), int(row["goaly"]), int(row["goalz"])

            updated = dict(row)
            updated["posx"] = nx
            updated["posy"] = ny
            updated["posz"] = nz
            updated["movenonce"] = move_nonce
            updated["consecutivewallhits"] = 0
            updated["lastactiveheight"] = self.node.height
            updated["updatedat"] = int(time.time())

            # Oscillation detection: track last 6 positions per maze
            # Detects 2-cycles (A-B-A-B) and 3-cycles (A-B-C-A-B-C)
            pos_hist = self._pos_history.setdefault(maze_id, deque(maxlen=6))
            pos_hist.append((nx, ny, nz))
            detected = False
            if len(pos_hist) >= 4:
                a, b, c, d = list(pos_hist)[-4:]
                if a == c and b == d and a != b:
                    detected = True
            if not detected and len(pos_hist) >= 6:
                p1, p2, p3, p4, p5, p6 = list(pos_hist)[-6:]
                if p1 == p4 and p2 == p5 and p3 == p6 and len({p1, p2, p3}) == 3:
                    detected = True
            if detected:
                self._oscillating_mazes.add(maze_id)
            elif (nx, ny, nz) != (sx, sy, sz):
                # Moving to a new cell — clear oscillation
                self._oscillating_mazes.discard(maze_id)

            caught = (nx == gx and ny == gy and nz == gz)
            state_info = {
                "type": "mazemove",
                "minerid": miner_id,
                "position": (nx, ny, nz),
                "movenonce": move_nonce,
                "caught": caught,
            }
            if caught:
                new_params = self._compute_new_maze_params(dict(row), self.node.height, eth_keccak(direction.encode() + move_nonce.to_bytes(8, "big")))
                updated.update(new_params)
                knowledge_val = int(row.get("knowledge", 0)) + max(1, int(size * 0.5))
                new_density_ppm = min(900000, int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM)) + (knowledge_val * 15000) + (size * 4000))
                updated["knowledge"] = knowledge_val
                updated["walldensityppm"] = new_density_ppm
                new_maze = await loop.run_in_executor(
                    None, self._generate_deterministic_maze,
                    new_params["seed"], new_params["size"], new_density_ppm, new_params["turbulenceppm"], self.node.height)
                new_root = self._calculate_maze_root(new_maze)
                new_spawn = self._select_spawn(new_maze, (nx, ny, nz), bytes.fromhex(new_params["seed"]))
                new_goal = self._select_open_cell(new_maze, bytes.fromhex(new_params["seed"]), exclude=new_spawn)
                updated["mazeroot"] = new_root
                updated["goalx"], updated["goaly"], updated["goalz"] = new_goal
                updated["posx"], updated["posy"], updated["posz"] = new_spawn
                state_info["newsize"] = new_params["size"]
                state_info["newgoal"] = new_goal
                state_info["newspawn"] = new_spawn
                state_info["new_growthcount"] = new_params["growthcount"]
                state_info["new_movenonce"] = updated["movenonce"]

                # Accumulate maze update event for next block
                maze_update_event = {
                    "maze_id": row.get("maze_id") or miner_id,
                    "miner_id": miner_id,
                    "height": self.node.height,
                    "old_size": size,
                    "new_size": new_params["size"],
                    "old_density": int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM)),
                    "new_density": new_density_ppm,
                    "old_growthcount": int(row["growthcount"]),
                    "new_growthcount": new_params.get("growthcount", int(row["growthcount"])),
                    "knowledge": knowledge_val,
                    "seed": new_params["seed"],
                    "mazeroot": new_root,
                    "goal": list(new_goal),
                    "spawn": list(new_spawn),
                    "turbulenceppm": new_params.get("turbulenceppm", 0),
                    "caught_at_nonce": move_nonce,
                    "caught_by_direction": direction,
                    "parent_mazeroot": row["mazeroot"],
                    "parent_size": size,
                    "parent_pos": [sx, sy, sz],
                    "parent_goal": [gx, gy, gz],
                    "parent_seed": row["seed"],
                    "parent_density": int(row["walldensityppm"]),
                    "parent_turbulence": int(row["turbulenceppm"]),
                    "parent_pos_attested": [int(row["posx"]), int(row["posy"]), int(row["posz"])],
                    "parent_movenonce": int(row["movenonce"]),
                }
                self._pending_maze_updates.append(maze_update_event)
                # Clear goal tracking state for new maze
                new_maze_id = row.get("maze_id") or miner_id
                self._maze_visited.pop(new_maze_id, None)
                self._goal_prev_pos.pop(new_maze_id, None)
                self._goal_recent.pop(new_maze_id, None)
                self._pos_history.pop(new_maze_id, None)
                self._oscillating_mazes.discard(new_maze_id)
                self._ghost_frozen_target.pop(new_maze_id, None)
                self._ghost_cycle.pop(new_maze_id, None)
                self._ghost_cycle_idx.pop(new_maze_id, None)
                # Reset ghost — spawn opposite corner from new spawn (only if size > 5)
                if new_params["size"] > 5:
                    _new_ghost = (new_params["size"]-1, new_params["size"]-1, new_params["size"]-1) if new_spawn == (0,0,0) else (0, 0, 0)
                else:
                    _new_ghost = None
                self._set_ghost(updated, _new_ghost)
                self._set_ghost(row, _new_ghost)
                self._sealed_walls.pop(new_maze_id, None)
                # Persist to DB for crash recovery
                try:
                    cur_block = self.node.height + 1
                    await self.node.db.execute_dml(
                        "INSERT OR REPLACE INTO pending_maze_updates (block_id,minerid,update_json) VALUES (?,?,?)",
                        cur_block, miner_id, json.dumps(maze_update_event, default=str)
                    )
                except Exception:
                    pass
            else:
                # The goal learns from the miner: it moves at the same speed the
                # miner can move, fleeing into unexplored regions when the miner
                # gets close. Record the visited cell and possibly shift the goal.
                maze_id = row.get("maze_id") or miner_id
                self._maze_visited.setdefault(maze_id, set()).add((nx, ny, nz))
                # Goal flee cooldown: goal only flees every max(5, size*2) moves
                # In small mazes (5³) this gives the miner 10 moves before goal runs
                flee_interval = max(5, size * 2)
                last_flee = self._goal_flee_cooldown.get(maze_id, 0)
                if move_nonce - last_flee >= flee_interval:
                    prev_goal = self._goal_prev_pos.get(maze_id)
                    new_goal = self._maybe_flee_goal(maze, (nx, ny, nz), (gx, gy, gz), maze_id, size, move_nonce)
                    # Anti-oscillation: don't move goal back to its previous position
                    if new_goal is not None and new_goal != (gx, gy, gz) and new_goal != prev_goal:
                        updated["goalx"], updated["goaly"], updated["goalz"] = new_goal
                        state_info["goal"] = new_goal
                        state_info["goal_moved"] = True
                        self._goal_flee_cooldown[maze_id] = move_nonce

                # ─── GHOST: BFS-chase the miner ───
                ghost_pos = self._ghost_tuple(row)
                if ghost_pos and ghost_pos != (gx, gy, gz):
                    if ghost_pos == (nx, ny, nz):
                        # Ghost already on miner — catch immediately
                        restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                        if restart_ev:
                            updated.update(restart_ev)
                            state_info["caught"] = True
                    else:
                        # Detects 2-cycles (A-B-A-B) and 3-cycles (A-B-C-A-B-C).
                        # Longer cycles are not detected; the client-side cooldown handles those.
                        if maze_id in self._oscillating_mazes:
                            # ─── Oscillation mode ───
                            # Freeze BFS target to a stable cycle cell, sweep all cycle cells
                            if maze_id not in self._ghost_cycle:
                                cycle_cells = []
                                for p in self._pos_history.get(maze_id, []):
                                    if p not in cycle_cells:
                                        cycle_cells.append(p)
                                def _manh(a, b):
                                    return abs(a[0]-b[0]) + abs(a[1]-b[1]) + abs(a[2]-b[2])
                                farthest_idx = max(range(len(cycle_cells)),
                                                   key=lambda i: _manh(ghost_pos, cycle_cells[i]))
                                self._ghost_cycle[maze_id] = cycle_cells
                                self._ghost_cycle_idx[maze_id] = farthest_idx
                                self._ghost_frozen_target[maze_id] = cycle_cells[farthest_idx]

                            cycle_cells = self._ghost_cycle[maze_id]
                            idx = self._ghost_cycle_idx[maze_id]
                            target = cycle_cells[idx]

                            # If ghost reached current target, advance to next cycle cell
                            if ghost_pos == target:
                                idx = (idx + 1) % len(cycle_cells)
                                self._ghost_cycle_idx[maze_id] = idx
                                target = cycle_cells[idx]

                            # Two BFS steps per tick while in oscillation mode
                            moved = False
                            for _ in range(2):
                                gdx, gdy, gdz = self._bfs_next_step(maze, size, ghost_pos, target)
                                if gdx is None:
                                    break
                                ghost_pos = (ghost_pos[0]+gdx, ghost_pos[1]+gdy, ghost_pos[2]+gdz)
                                self._set_ghost(updated, ghost_pos)
                                self._set_ghost(row, ghost_pos)
                                moved = True
                                if ghost_pos == (nx, ny, nz):
                                    break
                            if moved:
                                state_info["ghost"] = ghost_pos
                            if ghost_pos == (nx, ny, nz):
                                restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                                if restart_ev:
                                    updated.update(restart_ev)
                                    state_info["caught"] = True
                                    ghost_update = {
                                        "maze_id": row.get("maze_id") or miner_id,
                                        "miner_id": miner_id, "height": self.node.height,
                                        "old_size": size, "new_size": restart_ev.get("size", size),
                                        "old_density": int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM)),
                                        "new_density": restart_ev.get("walldensityppm", int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM))),
                                        "seed": restart_ev.get("seed", row["seed"]),
                                        "mazeroot": restart_ev.get("mazeroot", row.get("mazeroot", "")),
                                        "goal": [restart_ev.get("goalx", row["goalx"]), restart_ev.get("goaly", row["goaly"]), restart_ev.get("goalz", row["goalz"])],
                                        "spawn": [restart_ev.get("posx", row["posx"]), restart_ev.get("posy", row["posy"]), restart_ev.get("posz", row["posz"])],
                                        "turbulenceppm": restart_ev.get("turbulenceppm", 0),
                                    }
                                    self._pending_maze_updates.append(ghost_update)
                        else:
                            # ─── Normal mode ───
                            # Clear stale oscillation state
                            self._ghost_frozen_target.pop(maze_id, None)
                            self._ghost_cycle.pop(maze_id, None)
                            self._ghost_cycle_idx.pop(maze_id, None)

                            gdx, gdy, gdz = self._bfs_next_step(maze, size, ghost_pos, (nx, ny, nz))
                            if gdx is not None:
                                new_ghost = (ghost_pos[0]+gdx, ghost_pos[1]+gdy, ghost_pos[2]+gdz)
                                self._set_ghost(updated, new_ghost)
                                self._set_ghost(row, new_ghost)
                                state_info["ghost"] = new_ghost
                                if new_ghost == (nx, ny, nz):
                                    restart_ev = await self._restart_position(dict(row), maze_id, miner_id, size)
                                    if restart_ev:
                                        updated.update(restart_ev)
                                        state_info["caught"] = True
                                        ghost_update = {
                                            "maze_id": row.get("maze_id") or miner_id,
                                            "miner_id": miner_id, "height": self.node.height,
                                            "old_size": size, "new_size": restart_ev.get("size", size),
                                            "old_density": int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM)),
                                            "new_density": restart_ev.get("walldensityppm", int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM))),
                                            "seed": restart_ev.get("seed", row["seed"]),
                                            "mazeroot": restart_ev.get("mazeroot", row.get("mazeroot", "")),
                                            "goal": [restart_ev.get("goalx", row["goalx"]), restart_ev.get("goaly", row["goaly"]), restart_ev.get("goalz", row["goalz"])],
                                            "spawn": [restart_ev.get("posx", row["posx"]), restart_ev.get("posy", row["posy"]), restart_ev.get("posz", row["posz"])],
                                            "turbulenceppm": restart_ev.get("turbulenceppm", 0),
                                        }
                                        self._pending_maze_updates.append(ghost_update)

                # ─── CORRIDOR SEALING: walls close around miner as it moves ───
                # Only seal on mazes > 6³ — small mazes are too fragile.
                # Seals cells in FRONT of miner (adjacent to current position),
                # never on the miner's position itself.
                if size > 6:
                    seal_interval = max(3, size * 2)
                    if move_nonce % seal_interval == 0:
                        sealed_set = self._sealed_walls.setdefault(maze_id, set())
                        dense_maze = sparse_to_dense(maze)
                        # Collect open cells around CURRENT position (in front of miner)
                        seal_candidates = []
                        for ddx, ddy, ddz in DIRS_3D.values():
                            cx, cy, cz = nx+ddx, ny+ddy, nz+ddz
                            if 0 <= cx < size and 0 <= cy < size and 0 <= cz < size and not dense_maze[cz][cy][cx]:
                                # Never seal miner position, goal, or ghost
                                if (cx, cy, cz) != (nx, ny, nz) and (cx, cy, cz) != (gx, gy, gz) and (cx, cy, cz) != ghost_pos:
                                    # Don't seal the cell we just came from
                                    if (cx, cy, cz) != (sx, sy, sz):
                                        seal_candidates.append((cx, cy, cz))
                        sealed = 0
                        temp_blocked = set()
                        dense_maze = sparse_to_dense(maze)
                        # Use mutated maze for solvability check (matches miner's view)
                        mutated_maze = [row_layer[:] for row_layer in dense_maze]
                        mutate_maze_walls(mutated_maze, int(row["movenonce"]), size,
                                          {(nx, ny, nz), (gx, gy, gz)})
                        for (cx, cy, cz) in seal_candidates:
                            if sealed >= 1:
                                break
                            seal_key = eth_keccak(f"SEALV1{row['seed']}{cx}{cy}{cz}{move_nonce}".encode()).hex()
                            if int(seal_key[:8], 16) % 100 < 25:
                                test_blocked = sealed_set | temp_blocked | {(cx, cy, cz)}
                                if self._path_exists(mutated_maze, size, (nx, ny, nz), (gx, gy, gz), test_blocked):
                                    sealed_set.add((cx, cy, cz))
                                    temp_blocked.add((cx, cy, cz))
                                    sealed += 1
                                    state_info.setdefault("sealed_walls", []).append([cx, cy, cz])
                                    # Open a random wall cell elsewhere to keep maze connected
                                    # Find wall cells that are adjacent to open cells
                                    open_candidates = []
                                    seal_rng = ConsensusRng(eth_keccak(f"OPENRNGV1{row['seed']}{move_nonce}".encode()))
                                    for _ in range(20):
                                        rx = seal_rng.randbelow(size)
                                        ry = seal_rng.randbelow(size)
                                        rz = seal_rng.randbelow(size)
                                        if dense_maze[rz][ry][rx] == 1 and (rx, ry, rz) != (cx, cy, cz):
                                            # Check it's adjacent to an open cell
                                            for ddx2, ddy2, ddz2 in DIRS_3D.values():
                                                ax, ay, az = rx+ddx2, ry+ddy2, rz+ddz2
                                                if 0 <= ax < size and 0 <= ay < size and 0 <= az < size and not dense_maze[az][ay][ax]:
                                                    open_key = eth_keccak(f"OPENV1{row['seed']}{rx}{ry}{rz}{move_nonce}".encode()).hex()
                                                    if int(open_key[:8], 16) % 100 < 15:
                                                        open_candidates.append((rx, ry, rz))
                                                    break
                                    if open_candidates:
                                        ox, oy, oz = open_candidates[seal_rng.randbelow(len(open_candidates))]
                                        # Remove from sealed set if it was sealed
                                        sealed_set.discard((ox, oy, oz))
                                        state_info.setdefault("opened_walls", []).append([ox, oy, oz])
            await self.maze_repo.upsert(updated)
            return True, "Move accepted", state_info

    def _maybe_flee_goal(self, maze, miner_pos, goal_pos, maze_id, size, move_nonce) -> Optional[Tuple[int, int, int]]:
        """Goal flees by picking a TARGET (globally farthest cell from miner via BFS)
        and moving 1 step toward it. Prevents oscillation — the goal consistently
        moves toward a stable target rather than greedily picking farthest adjacent cell."""
        gx, gy, gz = goal_pos
        mnx, mny, mnz = miner_pos

        def cell_ok(x, y, z):
            return 0 <= x < size and 0 <= y < size and 0 <= z < size and not maze[z][y][x]

        # Full BFS from miner to find the globally farthest open cell (TARGET)
        dist_from_miner = {}
        q = deque()
        q.append((mnx, mny, mnz))
        dist_from_miner[(mnx, mny, mnz)] = 0
        while q:
            cx, cy, cz = q.popleft()
            for ddx, ddy, ddz in DIRS_3D.values():
                nnx, nny, nnz = cx+ddx, cy+ddy, cz+ddz
                if cell_ok(nnx, nny, nnz) and (nnx, nny, nnz) not in dist_from_miner:
                    dist_from_miner[(nnx, nny, nnz)] = dist_from_miner[(cx, cy, cz)] + 1
                    q.append((nnx, nny, nnz))

        if not dist_from_miner or len(dist_from_miner) <= 1:
            return None

        # Pick TARGET: globally farthest cell from miner (exclude miner position)
        max_d = max(d for pos, d in dist_from_miner.items() if pos != (mnx, mny, mnz))
        target_pool = [pos for pos, d in dist_from_miner.items() if d == max_d and pos != (mnx, mny, mnz)]
        if not target_pool:
            return None
        # Filter out recently used targets to prevent A→B→A→B cycling
        recent = self._goal_recent.get(maze_id, deque(maxlen=4))
        fresh_targets = [t for t in target_pool if t not in recent]
        if fresh_targets:
            target = fresh_targets[move_nonce % len(fresh_targets)]
        else:
            # All targets are recent — pick least-recent (oldest in deque)
            target = target_pool[move_nonce % len(target_pool)]

        # If goal is already at the target, stay put
        if (gx, gy, gz) == target:
            return None

        # BFS from TARGET to find shortest path to goal — move goal 1 step toward target
        dist_from_target = {}
        q2 = deque()
        q2.append(target)
        dist_from_target[target] = 0
        while q2:
            cx, cy, cz = q2.popleft()
            for ddx, ddy, ddz in DIRS_3D.values():
                nnx, nny, nnz = cx+ddx, cy+ddy, cz+ddz
                if cell_ok(nnx, nny, nnz) and (nnx, nny, nnz) not in dist_from_target:
                    dist_from_target[(nnx, nny, nnz)] = dist_from_target[(cx, cy, cz)] + 1
                    q2.append((nnx, nny, nnz))

        # From goal's adjacent cells, pick the one closest to target
        best_next = None
        best_dist = 9999
        for ddx, ddy, ddz in DIRS_3D.values():
            nx, ny, nz = gx+ddx, gy+ddy, gz+ddz
            if cell_ok(nx, ny, nz) and (nx, ny, nz) != (mnx, mny, mnz):
                d = dist_from_target.get((nx, ny, nz), 9999)
                if d < best_dist:
                    best_dist = d
                    best_next = (nx, ny, nz)

        if best_next is not None:
            self._goal_prev_pos[maze_id] = (gx, gy, gz)
            recent = self._goal_recent.setdefault(maze_id, deque(maxlen=4))
            recent.append(best_next)
            return best_next
        return None

    def _path_exists(self, maze, size, start, goal, extra_blocked=None):
        """Quick BFS check: can we reach goal from start, avoiding extra_blocked cells?"""
        if start == goal:
            return True
        if extra_blocked and goal in extra_blocked:
            return False
        q = deque()
        q.append(start)
        visited = {start}
        if extra_blocked:
            visited |= extra_blocked
        while q:
            cx, cy, cz = q.popleft()
            for ddx, ddy, ddz in DIRS_3D.values():
                nx, ny, nz = cx+ddx, cy+ddy, cz+ddz
                if (nx, ny, nz) == goal:
                    return True
                if 0 <= nx < size and 0 <= ny < size and 0 <= nz < size and (nx, ny, nz) not in visited and maze[nz][ny][nx] == 0:
                    visited.add((nx, ny, nz))
                    q.append((nx, ny, nz))
        return False

    def _bfs_next_step(self, maze, size, src, dst):
        """BFS from src toward dst; return (dx,dy,dz) of the first step, or (None,...) if unreachable."""
        if src == dst:
            return None, None, None
        visited = {src}
        q = deque([(src, None)])
        while q:
            (cx, cy, cz), first_step = q.popleft()
            for ddx, ddy, ddz in DIRS_3D.values():
                nx, ny, nz = cx+ddx, cy+ddy, cz+ddz
                if (nx, ny, nz) in visited:
                    continue
                if not (0 <= nx < size and 0 <= ny < size and 0 <= nz < size):
                    continue
                if maze[nz][ny][nx]:
                    continue
                step = (ddx, ddy, ddz) if first_step is None else first_step
                if (nx, ny, nz) == dst:
                    return step
                visited.add((nx, ny, nz))
                q.append(((nx, ny, nz), step))
        return None, None, None

    async def _restart_position(self, row, maze_id, miner_id, current_size):
        """Ghost caught miner — shrink maze by 1 (floor MIN_MAZE_SIZE), relocate to random open cell."""
        new_size = max(MIN_MAZE_SIZE, current_size - 1)
        if new_size >= current_size:
            return None
        shrink_amount = current_size - new_size
        old_density = int(row.get("walldensityppm", MIN_WALL_DENSITY_PPM))
        new_density = old_density + shrink_amount * 6000
        new_turb = int(row.get("turbulenceppm", 0)) + shrink_amount * 8000
        # Deterministic seed from chain data (not time.time())
        move_nonce = int(row.get("movenonce", 0))
        seed = eth_keccak(b"SHRINKGHOSTV2" + bytes.fromhex(row["mazeroot"]) + move_nonce.to_bytes(8, "big") + new_size.to_bytes(4, "big")).hex()
        loop = asyncio.get_event_loop()
        new_maze = await loop.run_in_executor(
            self._move_executor,
            self._generate_deterministic_maze, seed, new_size, new_density, new_turb, self.node.height)
        root_seed = bytes.fromhex(seed)
        new_spawn = self._select_open_cell(new_maze, root_seed)
        new_goal = self._select_open_cell(new_maze, root_seed, exclude=new_spawn)
        ghost_start = (new_size-1, new_size-1, new_size-1) if new_spawn == (0, 0, 0) else (0, 0, 0)
        self._sealed_walls.pop(maze_id, None)
        self._maze_visited.pop(maze_id, None)
        self._goal_prev_pos.pop(maze_id, None)
        self._goal_recent.pop(maze_id, None)
        self._pos_history.pop(maze_id, None)
        self._oscillating_mazes.discard(maze_id)
        self._ghost_frozen_target.pop(maze_id, None)
        self._ghost_cycle.pop(maze_id, None)
        self._ghost_cycle_idx.pop(maze_id, None)
        logger.info(f"[GHOST SHRINK] Miner {miner_id[:16]} caught → size {current_size}→{new_size}, relocated to {new_spawn}")
        return {
            "size": new_size,
            "seed": seed,
            "mazeroot": self._calculate_maze_root(new_maze),
            "posx": new_spawn[0], "posy": new_spawn[1], "posz": new_spawn[2],
            "goalx": new_goal[0], "goaly": new_goal[1], "goalz": new_goal[2],
            "walldensityppm": new_density,
            "turbulenceppm": new_turb,
            "ghostx": ghost_start[0] if new_size > 5 else None,
            "ghosty": ghost_start[1] if new_size > 5 else None,
            "ghostz": ghost_start[2] if new_size > 5 else None,
        }

    def get_state(self, miner_id: str) -> Optional[dict]:
        return getattr(self, '_cached_states', {}).get(miner_id)

    def _pow_active(self, maze_id: str) -> bool:
        """POW-FRESHNESS: an unsolved wall-hit challenge only excludes a maze
        while it is within the 60s solve window. process_move() expires stale
        entries (60s) but the produce_block eligibility filter only checked
        membership — a lapsed challenge left in _pending_pow forever excluded
        the maze from the lottery (chain stall)."""
        ent = self._pending_pow.get(maze_id)
        if ent is None:
            return False
        if time.time() - ent[2] > 60:
            self._pending_pow.pop(maze_id, None)
            return False
        return True

    def _find_nearest_open(self, maze, size, x, y, z):
        """BFS from (x,y,z) to find nearest open cell."""
        q = deque()
        visited = set()
        start = (x, y, z)
        q.append((start, 0))
        visited.add(start)
        while q:
            (cx, cy, cz), dist = q.popleft()
            if 0 <= cx < size and 0 <= cy < size and 0 <= cz < size:
                if maze[cz][cy][cx] == 0:
                    return (cx, cy, cz)
            for dx, dy, dz in [(1,0,0),(-1,0,0),(0,1,0),(0,-1,0),(0,0,1),(0,0,-1)]:
                nx, ny, nz = cx+dx, cy+dy, cz+dz
                if (nx, ny, nz) not in visited:
                    visited.add((nx, ny, nz))
                    q.append(((nx, ny, nz), dist+1))
        return (x, y, z)  # fallback

    async def _load_or_create_maze(self, miner_id: str, maze_id: str = None) -> dict:
        if not maze_id:
            maze_id = miner_id
        existing = await self.maze_repo.get_by_maze_id(maze_id)
        if existing:
            row = dict(existing)
            # MAZE-MIN-1: quarantine undersized rows with a loud diagnostic
            # instead of letting them flow into eligibility/weight paths.
            # Quarantined rows stay stored but are excluded everywhere sizes
            # matter (get_eligible requires size > MIN_MAZE_SIZE;
            # _maze_att_weight floors at MIN_MAZE_SIZE). No silent repair:
            # rewriting the dimension would invalidate the sealed mazeroot
            # commitment, so the row is left intact for operator action.
            if _valid_maze_size(row.get("size")) is None:
                logger.error(f"[MAZE-QUARANTINE] {maze_id[:16]} has invalid size {row.get('size')!r} "
                             f"(minimum {MIN_MAZE_SIZE}); excluded from lottery/weight until repaired out-of-band")
                return row
            # Guard: only allow rebind if the previous miner is disconnected or stale
            prev_miner = row.get("minerid")
            if prev_miner and prev_miner != miner_id:
                prev_ws = self.node.miner_websockets.get(prev_miner)
                if prev_ws is not None:
                    logger.warning(f"[MAZE] {maze_id[:16]} already bound to active miner {prev_miner[:16]}, rejecting {miner_id[:16]}")
                    return None
            # Bind the active (volatile) miner identity to this persistent maze.
            # NO-OFFLINE-SHRINK-1: _apply_shrink no longer runs on rebind.
            row["minerid"] = miner_id
            if row["minerid"] != existing["minerid"]:
                await self.maze_repo.upsert(row)
            # MAZE-SELF-HEAL: repair rows whose pos/goal are out of bounds,
            # on a wall, or collapsed onto each other (the state _apply_shrink
            # historically produced). Such a row makes the embedded miner log
            # "No path to goal" in a loop, never move, and never re-enter the
            # lottery — one broken row on the sole eligible miner halts the
            # chain. Spawn/goal are re-derived from the SAME seed/size/density
            # so mazeroot (wall commitments) is untouched.
            try:
                _sz = int(row["size"])
                _px, _py, _pz = int(row["posx"]), int(row["posy"]), int(row["posz"])
                _gx, _gy, _gz = int(row["goalx"]), int(row["goaly"]), int(row["goalz"])
                _inb = lambda v: 0 <= v < _sz
                _need = not (_inb(_px) and _inb(_py) and _inb(_pz)
                             and _inb(_gx) and _inb(_gy) and _inb(_gz))
                if not _need and (_px, _py, _pz) == (_gx, _gy, _gz):
                    _need = True
                if not _need:
                    loop_h = asyncio.get_event_loop()
                    _maze_h = await loop_h.run_in_executor(
                        self._move_executor, self._generate_deterministic_maze,
                        row["seed"], _sz, int(row["walldensityppm"]),
                        int(row["turbulenceppm"]), self.node.height)
                    # Both cells must be open — otherwise the BFS from spawn
                    # can never reach goal ("No path to goal").
                    if _maze_h[_pz][_py][_px] or _maze_h[_gz][_gy][_gx]:
                        _need = True
                    else:
                        _step = self._bfs_next_step(_maze_h, _sz, (_px, _py, _pz), (_gx, _gy, _gz))
                        if _step[0] is None:
                            _need = True
                if _need:
                    loop_h = asyncio.get_event_loop()
                    _maze_h = await loop_h.run_in_executor(
                        self._move_executor, self._generate_deterministic_maze,
                        row["seed"], _sz, int(row["walldensityppm"]),
                        int(row["turbulenceppm"]), self.node.height)
                    _seed_b = bytes.fromhex(row["seed"])
                    _new_spawn = self._select_spawn(
                        _maze_h, (_px, _py, _pz) if (_inb(_px) and _inb(_py) and _inb(_pz)) else (0, 0, 0),
                        _seed_b)
                    _new_goal = self._select_open_cell(_maze_h, _seed_b, exclude=_new_spawn)
                    row["posx"], row["posy"], row["posz"] = _new_spawn
                    row["goalx"], row["goaly"], row["goalz"] = _new_goal
                    await self.maze_repo.upsert(row)
                    logger.warning(
                        f"[MAZE-SELF-HEAL] {maze_id[:16]} size={_sz}: repaired "
                        f"pos ({_px},{_py},{_pz})→{_new_spawn}, goal "
                        f"({_gx},{_gy},{_gz})→{_new_goal}")
            except Exception as _heal_exc:
                logger.warning(f"[MAZE-SELF-HEAL] {maze_id[:16]} skipped: {_heal_exc}")
            # Ensure ghost state exists for this maze (only if size > 5)
            if self._ghost_tuple(row) is None:
                size = int(row["size"])
                if size > 5:
                    sx, sy, sz = int(row["posx"]), int(row["posy"]), int(row["posz"])
                    self._set_ghost(row, (size-1, size-1, size-1) if (sx, sy, sz) == (0,0,0) else (0, 0, 0))
                    await self.maze_repo.upsert(row)
                self._sealed_walls.setdefault(maze_id, set())
                self._ghost_frozen_target.pop(maze_id, None)
                self._ghost_cycle.pop(maze_id, None)
                self._ghost_cycle_idx.pop(maze_id, None)
            return row
        seed = eth_keccak(b"MCXPOGSEEDV1" + maze_id.encode()).hex()
        loop = asyncio.get_event_loop()
        maze = await loop.run_in_executor(
            self._move_executor,
            self._generate_deterministic_maze, seed, MIN_MAZE_SIZE, MIN_WALL_DENSITY_PPM, 0, self.node.height
        )
        root = self._calculate_maze_root(maze)
        spawn = self._select_spawn(maze, (0, 0, 0), bytes.fromhex(seed))
        goal = self._select_open_cell(maze, bytes.fromhex(seed), exclude=spawn)
        now = int(time.time())
        row = {
            "minerid": miner_id, "maze_id": maze_id, "size": MIN_MAZE_SIZE,
            "walldensityppm": MIN_WALL_DENSITY_PPM, "seed": seed,
            "posx": spawn[0], "posy": spawn[1], "posz": spawn[2],
            "goalx": goal[0], "goaly": goal[1], "goalz": goal[2],
            "movenonce": 0, "consecutivewallhits": 0,
            "turbulenceppm": 0, "growthcount": 0,
            "lastgoalheight": 0, "lastactiveheight": self.node.height,
            "mazeroot": root, "invitedguest": None, "guestlock": False,
            "createdat": now, "updatedat": now,
        }
        # Spawn ghost only if maze is larger than base (5³)
        if MIN_MAZE_SIZE > 5:
            ghost_start = (MIN_MAZE_SIZE-1, MIN_MAZE_SIZE-1, MIN_MAZE_SIZE-1) if spawn == (0,0,0) else (0, 0, 0)
            self._set_ghost(row, ghost_start)
        await self.maze_repo.upsert(row)
        self._sealed_walls[maze_id] = set()
        return row

    async def produce_block(self) -> bool:
        now = time.time()
        if now < self.node._next_block_time:
            return False

        latest = await self.block_repo.get_latest()
        if latest and latest['id'] >= self.node.height:
            self.node.height = latest['id'] + 1
            self.node.last_hash = latest['hash']
            latest_ts = latest.get('ts', now)
            if hasattr(latest_ts, 'timestamp'):
                latest_ts = latest_ts.timestamp()
            self.node._next_block_time = max(now, float(latest_ts) + BLOCK_TIME)
            return False

        block_id = self.node.height
        prev_hash = self.node.last_hash

        # SEAL-STALE-TIP-1: never seal on a tip peers have already advanced
        # past. run3 S10: node3's sync was mid-rewind (local tip 33s behind)
        # when its rank-1 ladder attempt elected a local winner and sealed a
        # sibling at 32 — the 33/34 cascade pushed competing signatures past
        # the gate. PING/PONG carry peer heights in the same count convention
        # as node.height, so a peer strictly ahead proves a block exists that
        # we have not imported: fetch it first instead of competing. Peer
        # heights never exceed ours in a real partition (liveness takeover is
        # unaffected — there nobody is ahead).
        _p2p = getattr(self.node, "p2p", None)
        if _p2p is not None:
            try:
                async with _p2p._lock:
                    _ahead_h = max([int(getattr(_p, "height", 0) or 0)
                                    for _p in _p2p.peers.values()] or [0])
            except Exception:
                _ahead_h = 0
            if _ahead_h > block_id:
                logger.warning(f"[SEAL-STALE-TIP-1] block {block_id}: peer height {_ahead_h} already ahead — syncing instead of sealing")
                asyncio.create_task(_p2p.sync_with_peers())
                self.node._next_block_time = max(time.time() + 1.0, self.node._next_block_time)
                return False

        # SEAL-SELF-VERIFY-TS-1: gate the seal on the same parent-relative
        # timestamp rule verifiers enforce — never seal (and never execute
        # txs for) a block that verify_block_proof must reject.
        # SEAL-TS-FAILCLOSED-1: an unexpected exception from the gate is a
        # deferral, never a pass (this used to be `_ts_ok = True`).
        try:
            _ts_ok = await self._produce_timestamp_ok(block_id, now)
        except Exception as _ts_err:
            logger.error(f"[SEAL-TS-FAILCLOSED-1] block {block_id}: timestamp gate error "
                         f"({type(_ts_err).__name__}: {str(_ts_err)[:120]!r}) — deferring seal")
            _ts_ok = False
        if not _ts_ok:
            # FP1-LOGBOUND-1: throttle the repeat warning (see gate).
            if _seal_ts_log_due("caller"):
                logger.warning(f"[SEAL-TS] block {block_id}: candidate ts outside parent-relative bounds — deferring seal")
            self.node._next_block_time = max(time.time() + 1.0, self.node._next_block_time)
            return False

        async with self.node.blockexecutionlock:
            # ORDER: select the winner FIRST, execute txs only once a block is
            # certain to be attempted. Executing before the eligibility checks
            # stranded receipts/balance/contract side effects whenever the
            # block was then skipped ("No eligible miners"), committing state
            # that no block ever referenced.
            # IDEA5-ELECT: the attestation set on chain is the canonical half
            # of the candidate pool — identical on every node (written on
            # append, rolled back on reorg, restored by IDEA5-ATTEST-REORG-2),
            # so in steady state all nodes rank the same winner.
            # IDEA5-ELECT-LOCAL-1: connected local mazes join the pool for
            # first wins and partition liveness. Chain-only membership is
            # winner-take-all: only past winners ever attest, so the
            # bootstrapping maze would monopolize the set forever and a
            # partition lacking its host could not produce at all (soak
            # S5/S9 caught exactly that stall). Once every maze has attested
            # once, the pool is chain-identical again and competition stops.
            candidate_rows = []
            _seen = set()
            all_atts = await self.maze_attestation_repo.get_all()
            if not all_atts:
                # IDEA5-ELECT-BOOTSTRAP-1: no attestations yet (block 1) —
                # local candidates only for this first block.
                logger.info(f"[IDEA5-ELECT-BOOTSTRAP-1] no chain attestations yet — local candidates for block {block_id}")
            for _att in (all_atts or []):
                _mid = str(_att.get("maze_id", ""))
                _size = int(_att.get("last_size", 0))
                if _mid:
                    _seen.add(_mid)
                if _size > MIN_MAZE_SIZE:
                    candidate_rows.append({"maze_id": _mid, "size": _size})
            for _mid in list(self.node.miner_websockets):
                for _row in (await self.maze_repo.get_by_miner_id(_mid) or []):
                    if str(_row.get("maze_id", "")) in _seen:
                        continue
                    if int(_row.get("size", 0)) > MIN_MAZE_SIZE:
                        candidate_rows.append(_row)
                        _seen.add(str(_row.get("maze_id", "")))
            # IDEA5-ELECT-UNIFORM-1: candidates are filtered ONLY by chain
            # state (attestations + local size rows). The old shared filter
            # also dropped pow-active and inactive/banned miners from the
            # LOCAL view: _pending_pow is set only where the wall-hit move
            # was processed (host-local), and foreign miners never get a
            # local miners row (IMPORT-SLASH records the event only), so any
            # node's filter could disagree with its peers — divergent
            # passing lists -> different winners at the same rank ->
            # competing sibling blocks (SOAK-ELECT). BAN-KICK-1 still kicks
            # banned sockets at the slash paths, and the rank ladder /
            # IDEA5-LIVENESS-2 takeover covers liveness when a kicked miner
            # would otherwise have signed.
            candidate_rows = [r for r in candidate_rows if str(r.get("maze_id", ""))]
            candidate_rows = _filter_validator_candidates(candidate_rows)   # VALIDATOR-CAND-1
            # GLOBAL_SHRINK_FACTOR from the candidate snapshot (sealed in the block; followers apply it)
            if candidate_rows:
                total_size = sum(int(r["size"]) for r in candidate_rows)
                avg_size = total_size / len(candidate_rows)
                computed_shrink_factor = max(1.0, avg_size / 10)
            else:
                computed_shrink_factor = 1.0
            if self._oscillating_mazes:
                logger.info(f"[PoG] Oscillating mazes detected (ghost will catch): {list(self._oscillating_mazes)}")
            logger.info(f"[PoG] IDEA5-ELIG candidates: {[(str(r['maze_id'])[:16], int(r['size'])) for r in candidate_rows]}")
            # LOTTERY-SCALE-1 + IDEA5-ELECT: passing candidates are ticket <
            # threshold(size), ordered ascending by ticket (maze_id pre-sort
            # for determinism). The verifier checks only ticket < threshold for
            # the block's own attestation, so any passing rank verifies.
            passing = []
            for _row in sorted(candidate_rows, key=lambda r: str(r["maze_id"])):
                try:
                    _t = _maze_ticket(prev_hash, block_id, _row["maze_id"])
                except Exception:
                    continue
                if _t < _maze_threshold(int(_row["size"])):
                    passing.append((_t, _row))
            passing.sort(key=lambda p: p[0])
            if not passing:
                logger.info(f"[PoG] No lottery winner among {len(candidate_rows)} candidates — skipping block {block_id}")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False
            # IDEA5-LIVENESS-1: rank measured from the SCHEDULED production
            # moment (T_prev + BLOCK_TIME) — the first BLOCK_TIME seconds are
            # rank-0, then +SLOT_TIMEOUT per rank. Failed attempts retry at
            # the next rank boundary (scheduled below), so no rank is skipped.
            prev_ts = now
            if latest is not None:
                prev_ts = latest.get('ts', now)
                if hasattr(prev_ts, 'timestamp'):
                    prev_ts = prev_ts.timestamp()
                try:
                    prev_ts = float(prev_ts)
                except (TypeError, ValueError):
                    prev_ts = now
            elapsed = max(0.0, now - prev_ts)
            # IDEA5-LIVENESS-2: raw (uncapped) rank drives the takeover gate
            # only; capped rank keeps driving winner selection and skip
            # scheduling so it can never index past the passing list.
            raw_rank = int(max(0.0, elapsed - BLOCK_TIME) // _config.SLOT_TIMEOUT)
            rank = min(raw_rank, len(passing) - 1)
            winner_row = passing[rank][1]
            winner = winner_row["maze_id"]
            winner_miner_id = winner_row.get("minerid")
            # SEAL-CLAIM-1: the elect-time chain-attested size floors the
            # sealed claim. The local pool row is mutable host state (offline
            # decay / ghost shrink) and can sit below the chain-attested size;
            # embedding it raw produced seals peers reject (attestation size
            # <= MIN_MAZE_SIZE / lottery threshold mismatch) — the chain then
            # forks below our own block and sync stalls (attempt8 block 19).
            winner_elect_size = int(winner_row["size"])
            if winner_miner_id is None:
                # chain candidate: resolve the live local row (miner binding +
                # current size for the self-attested claim); foreign winners
                # have no local row and fall through to the hosting check.
                _wrow = await self.maze_repo.get_by_maze_id(winner)
                if _wrow:
                    winner_row = _wrow
                    winner_miner_id = _wrow.get("minerid")
            logger.info(f"[PoG] Winner: {winner}, rank={rank} (IDEA5-LIVENESS-1), miner={winner_miner_id[:16] if winner_miner_id else None}")

            if not winner_miner_id or winner_miner_id not in self.node.miner_websockets:
                # IDEA5-LIVENESS-1 takeover: when escalation is exhausted and
                # the winner's host is absent or behind, produce this node's
                # own best passing candidate instead — any passing candidate
                # verifies.
                # IDEA5-LIVENESS-2: the gate is the UNCAPPED raw rank one
                # full slot past the LAST-ranked host's boundary (raw >= len,
                # i.e. >=30s after its boundary — past the hard 25s sign
                # wait_for deadline, so a live host that signed has already
                # advanced the tip and the loop-start tip check aborts us;
                # a live host still mid-sign is impossible at +30s). The old
                # gate fired AT the last rank's boundary (rank >= len-1) and
                # raced that host's in-flight sign roundtrip — the dominant
                # SOAK-ELECT sibling source.
                _hosted = []
                for _t, _row in passing:
                    _mid_h = _row.get("minerid")
                    if _mid_h is None:
                        _hr = await self.maze_repo.get_by_maze_id(str(_row.get("maze_id", "")))
                        _mid_h = _hr.get("minerid") if _hr else None
                    if _mid_h and _mid_h in self.node.miner_websockets:
                        _hosted.append((_t, _row, _mid_h))
                if _hosted and raw_rank >= len(passing):
                    _hosted.sort(key=lambda p: p[0])
                    _t, _row, _mid_h = _hosted[0]
                    winner_row = _row
                    winner_miner_id = _mid_h
                    # SEAL-CLAIM-1: elect-time size floors the claim (rank path).
                    winner_elect_size = int(_row["size"])
                    _liv = await self.maze_repo.get_by_maze_id(str(_row.get("maze_id", "")))
                    if _liv:
                        winner_row = _liv
                    winner = winner_row["maze_id"]
                    logger.info(f"[PoG] IDEA5-LIVENESS-1/2 takeover (raw rank {raw_rank}): unhosted winner -> {str(winner)[:16]}")
                else:
                    logger.warning(f"[PoG] Winner {str(winner)[:16]} (rank {rank}/raw {raw_rank}) not hosted here — skipping block {block_id} (IDEA5-LIVENESS-1)")
                    if raw_rank < len(passing):
                        # next raw-rank boundary: elapsed 0 is T_prev + BLOCK_TIME
                        # (walks to the IDEA5-LIVENESS-2 takeover gate at raw = len)
                        _next = prev_ts + BLOCK_TIME + (raw_rank + 1) * _config.SLOT_TIMEOUT + 0.5
                    else:
                        # escalation exhausted and nothing legal to claim
                        # here — wait, never hot-spin on a static key
                        _next = time.time() + _config.SLOT_TIMEOUT
                    self.node._next_block_time = max(time.time() + 0.5, _next)
                    return False

            # IDEA5-ATTEST: self-attested maze size (replaces lottery_proof).
            # The claim is capped by the stored prior attestation so sizes grow
            # at most ATTEST_GROWTH_PER_BLOCK per block; a miner's very first
            # claim is capped at MIN_MAZE_SIZE + ATTEST_FRESH_BUFFER.
            # Built BEFORE tx execution so a rejected claim aborts with zero
            # side effects (same as the no-winner skip path).
            _prev_att = await self.maze_attestation_repo.get(winner)
            if _prev_att and int(_prev_att.get("last_block", -1)) >= block_id:
                # SEAL-SELF-VERIFY-1: the local attestation row already sits at/
                # after this height (imported competing chain) — every peer's
                # verify rejects such a seal (ATTEST-CAP-STRICT), so do not
                # build it: the fork it creates stalls sync below our own
                # rejected block (three stuck cycles -> 300s production pause)
                # and S10 starves.
                logger.warning(f"[SEAL-SELF-VERIFY-1] block {block_id} local attestation for {str(winner)[:16]} already at {int(_prev_att.get('last_block', -1))} (>= id) — peers reject (ATTEST-CAP-STRICT), skipping")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False
            if _prev_att:
                _att_cap = int(_prev_att.get("last_size", MIN_MAZE_SIZE)) + _config.ATTEST_GROWTH_PER_BLOCK * (block_id - int(_prev_att["last_block"]))
            else:
                _att_cap = MIN_MAZE_SIZE + _config.ATTEST_FRESH_BUFFER  # ATTEST-FRESH-BUFFER-1
            maze_attestation = {
                "maze_id": winner,
                "pubkey": winner,  # IDEA5-ATTEST: maze_id IS the maze public key
                "size": min(max(int(winner_row["size"]), winner_elect_size), _att_cap),
                "block": block_id,
            }
            logger.info(f"[IDEA5-ATTEST] {str(winner)[:16]} size={maze_attestation['size']} cap={_att_cap} prior={'none' if not _prev_att else _prev_att.get('last_block')}")
            # SEAL-SELF-VERIFY-1: check the sealed claim exactly the way each
            # peer's verify_block_proof will — eligibility and the lottery
            # threshold against the FINAL size (min(row, growth-cap)), not the
            # elect-time row size. A seal that fails peer verification is
            # accepted only by this node: peers reject it, sync stalls below
            # our own rejected block and the peers' competing blocks at the
            # same height become SOAK-ELECT sibling signatures (attempt8:
            # block 19 sealed at attestation size 5, rejected by both peers
            # as not eligible).
            if int(maze_attestation["size"]) <= MIN_MAZE_SIZE:
                logger.warning(f"[SEAL-SELF-VERIFY-1] block {block_id} sealed attestation size {maze_attestation['size']} <= {MIN_MAZE_SIZE} — peers would reject, skipping")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False
            try:
                _seal_ticket = _maze_ticket(prev_hash, block_id, winner)
            except Exception as _seal_e:
                logger.warning(f"[SEAL-SELF-VERIFY-1] block {block_id} ticket computation failed: {_seal_e} — skipping")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False
            if _seal_ticket >= _maze_threshold(int(maze_attestation["size"])):
                logger.warning(f"[SEAL-SELF-VERIFY-1] block {block_id} lottery would fail at sealed size {maze_attestation['size']} (ticket >= threshold) — peers would reject, skipping")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False

            # B5-fix (MCX73): snapshot the winner's balance BEFORE executing
            # mempool txs. The sealed trie key commits pre-tx balance +
            # reward so verifiers reproduce it from parent state alone — a
            # live re-read after execution would include this block's own tx
            # effects, making producer and verifier disagree on every block
            # whose txs touch the winner (observed: all blocks from #4 on,
            # total stall). Uses the same repos as the seal path below.
            _seal_wallet = ""
            _seal_pre_bal = 0
            try:
                if winner_miner_id:
                    _swm = await self.miner_repo.get(winner_miner_id)
                    if _swm and _swm.get("wallet"):
                        _seal_wallet = _swm["wallet"]
                        _seal_pre_bal = int(await self.balance_repo.get(_seal_wallet) or 0)
            except Exception:
                pass
            pending_txs = await self.mempool.get(limit=min(MAX_TX_PER_BLOCK, _config.MAX_BLOCK_TXS))
            executed_txs = []
            total_fees = 0
            had_contract_deploy = False
            _blk_gas = 0   # BLOCK-GAS-1 running declared-gas total
            for tx_data in pending_txs:
                if len(executed_txs) >= _config.MAX_BLOCK_TXS:
                    break
                try:
                    _g = _tx_declared_gas(tx_data)
                except (TypeError, ValueError, OverflowError):
                    continue
                if _blk_gas + _g > _config.MAX_BLOCK_GAS:
                    continue   # does not fit; stays in mempool for a later block
                try:
                    success, result = await self.node.execute_transaction(tx_data, block_id, block_ts=now)
                except Exception as exc:
                    # One malformed tx must not abort block production for
                    # every other pending tx — log and leave it in mempool.
                    logger.warning(
                        f"[Mempool] tx {str(tx_data.get('tx_hash'))[:16]} "
                        f"raised {type(exc).__name__}: {exc}")
                    continue
                if success:
                    executed_txs.append(tx_data)
                    _blk_gas += _g
                    total_fees += tx_data.get('fee', 0)
                    if tx_data.get('tx_type') == 'contract_deploy':
                        had_contract_deploy = True
                else:
                    logger.warning(
                        f"[Mempool] tx {str(tx_data.get('tx_hash'))[:16]} "
                        f"execution failed (stays in mempool): {result}")
            # Invalidate code cache if contracts were deployed
            if had_contract_deploy and self.node.vm_manager:
                self.node.vm_manager._code_cache_valid = False

            base_reward = get_block_reward(block_id)
            # Enforce MAX_SUPPLY cap
            if self.node.total_minted + base_reward > MAX_SUPPLY:
                base_reward = max(0, MAX_SUPPLY - self.node.total_minted)
            # Spatial Tokens V2: no reward-pool cut. The producer keeps the
            # full base reward + all tx fees. (V1 took 10% of base into the
            # pool and split deploy fees 50/50; both are gone.)
            producer_base_reward = base_reward
            # SPATIAL-REWARD-SPLIT-1 (brief PART 6 fix): the producer used to
            # credit total_reward (base + fees) but add 100% of base to
            # total_minted, while followers recompute `_mint = reward -
            # total_fees = producer_base_reward` — a 10%/block divergence.
            # Both sides now add producer_base_reward. Do NOT change the
            # follower's _mint line (_append_block).
            total_reward = producer_base_reward + total_fees
            # Spatial Tokens V2: maze cuts travel with each executed tx in
            # block['transactions'] (tx['_spatial_fee_maze_cut'], set for
            # creates and fee-bearing transfers; absent/0 otherwise).
            # Spatial Tokens V2: sealed amount is the FULL spatial fee sum.
            # _distribute_spatial_fee takes its 90% cut from this total, so
            # summing only maze_cuts here would double-apply the 90% (81% to
            # mazes, 9% burned). Reconstruct each tx's full fee as sealed
            # producer_cut + maze_cut (type-gated so forged cuts on
            # non-spatial txs are ignored, mirroring
            # _spatial_fee_amount_ok).
            spatial_fee_to_mazes = 0
            for _tx in executed_txs:
                if _tx.get('tx_type') in ('spatial_token_create',
                                           'spatial_token_transfer'):
                    try:
                        spatial_fee_to_mazes += int(_tx.get('fee', 0) or 0) + \
                            int(_tx.get('_spatial_fee_maze_cut', 0) or 0)
                    except (TypeError, ValueError):
                        continue
            spatial_fee_total = spatial_fee_to_mazes

            # B5-fix: drop any stale uncommitted trie keys from a prior
            # failed seal attempt (R6-statetrie-dirty-clear: dirt survives
            # until mark_committed, so an exception between put and commit
            # would otherwise pollute the next seal's root with a foreign
            # winner's key).
            self.node.state_trie._dirty.clear()
            await self.node.state_trie.put("height", block_id)
            reward_credited = False
            async with await self.node.db.transaction():
                if winner_miner_id:
                    winner_miner = await self.miner_repo.get(winner_miner_id)
                    if winner_miner:
                        # SEAL-CREDIT-ATOMIC-1: the balance_repo credit is NOT
                        # committed here anymore. Only the trie balance key
                        # moves pre-sign so the sealed state_root matches what
                        # followers compute on import; the actual credit
                        # commits in ONE transaction with block_repo.create
                        # after the sign roundtrip (below). The old pre-sign
                        # credit left a permanent +reward phantom whenever the
                        # post-sign create() raced a sibling block already
                        # appended at this height (IntegrityError escaped the
                        # try — no rollback) — S8 ledger equality failed on
                        # every forked run.
                        # B5-fix: commit the PRE-TX-EXECUTION snapshot above,
                        # not a live re-read (see _seal_pre_bal).
                        _seal_w = winner_miner['wallet']
                        if _seal_w == _seal_wallet:
                            _pre_bal = _seal_pre_bal
                        else:
                            # Winner row changed mid-produce (re-registration
                            # race) — fall back to a live read. A concurrent
                            # import crediting this wallet inside the seal
                            # window can still skew the root; production then
                            # retries next boundary.
                            _pre_bal = int(await self.balance_repo.get(_seal_w) or 0)
                        await self.node.state_trie.put(f"balance:{_seal_w}", _pre_bal + total_reward)
                        reward_credited = True
                # Capture the pre-commit dirt for the state snapshot saved
                # at seal time below (R6-statetrie-dirty-clear: commit no
                # longer clears; mark_committed runs after this block).
                snapshot_dirty = dict(self.node.state_trie._dirty) if self.node.state_trie._dirty else {}
                state_root = await self.node.state_trie.commit()

            # R6-statetrie-dirty-clear: the outer transaction above exited
            # successfully — only now forget the dirt. If it had raised,
            # this line is skipped and a retry replays _dirty intact.
            self.node.state_trie.mark_committed()

            async def _rollback_producer_credit():
                # SIGN-FAIL-ROLLBACK + SEAL-CREDIT-ATOMIC-1: pre-sign failures
                # only ever reverted the state trie (the balance_repo credit
                # now commits post-sign together with block_repo.create), so
                # this MUST NOT subtract from balances — that would phantom-
                # debit the winner. Revert the trie balance key to the current
                # ledger balance (re-read so a concurrent import credit at
                # this height is not clobbered with a stale snapshot).
                if not reward_credited or winner_miner is None:
                    return
                try:
                    _cur = int(await self.balance_repo.get(winner_miner['wallet']) or 0)
                    await self.node.state_trie.put(f"balance:{winner_miner['wallet']}", _cur)
                    await self.node.state_trie.commit()
                    logger.warning(f"[SIGN-FAIL-ROLLBACK] Reverted trie credit {total_reward} for {winner_miner['wallet'][:16]} after failed seal attempt of block {block_id}")
                except Exception as _rb_e:
                    logger.warning(f"[SIGN-FAIL-ROLLBACK] trie revert failed for block {block_id}: {_rb_e}")

            computed_merkle_root = compute_merkle_root([tx['tx_hash'] for tx in executed_txs])
            # IDEA5-REWARD-WALLET-1: seal the wallet this producer credits so
            # followers without a miners row credit the identical wallet.
            _reward_wallet = ""
            if winner_miner_id:
                _rwm = await self.miner_repo.get(winner_miner_id)
                if _rwm:
                    _reward_wallet = _rwm.get("wallet", "")
            unsigned_block = {
                "id": block_id,
                "ts": now,
                "phash": prev_hash,
                "miners": [winner_miner_id] if winner_miner_id else [],
                "reward": total_reward if winner_miner_id else 0,
                "tx_count": len(executed_txs),
                "merkle_root": computed_merkle_root,
                "nonce": 0,
                "difficulty": 0,
                "version": VERSION,
                "challenge": "",
                "coverage": 1.0,
                "total_tx_value": sum(tx.get('value', 0) for tx in executed_txs),
                "total_fees": total_fees,
                "tx_hashes": [tx['tx_hash'] for tx in executed_txs],
                "transactions": executed_txs,
                "winner": winner_miner_id,
                "maze_attestation": maze_attestation,  # IDEA5-ATTEST
                "reward_wallet": _reward_wallet,       # IDEA5-REWARD-WALLET-1
                "state_root": state_root,
                "maze_updates": list(self._pending_maze_updates),  # MAZE-UPDATES-UX-1
                "slashes": list(self._pending_slashes),
                "global_shrink_factor": computed_shrink_factor,
                # Spatial Tokens V2: sealed fee amount — followers apply it
                # verbatim, never recompute.
                "spatial_fee_amount": int(spatial_fee_total),
            }

            ws = self.node.miner_websockets[winner_miner_id]
            block_signed = False

            logger.info(f"[PoG] Sending produce_block to winning miner {winner_miner_id[:16]}")
            try:
                future = asyncio.get_event_loop().create_future()
                self.node._block_sign_futures[winner_miner_id] = future
                await self.node.send_to_miner(winner_miner_id, {
                    "type": "produce_block",
                    "block": unsigned_block,
                    "pending_txs": [tx['tx_hash'] for tx in executed_txs],
                    "prev_hash": prev_hash,
                    "height": block_id,
                })
                signed_block = await asyncio.wait_for(future, timeout=25)
                self.node._block_sign_futures.pop(winner_miner_id, None)
                stripped = {k: v for k, v in signed_block.items() if k not in CONSENSUS_EXCLUDED_FIELDS}
                block_hash = hashlib.sha256(canonical_json_bytes(stripped)).hexdigest()
                # EQUIV-1 guard: record this miner's signature for this block
                # height — but only slash on REAL equivocation (the same
                # producer signing two chains with different phash/tx set at
                # the same height). Blocks carry `ts: now`, so a retried
                # production at the same height always hashes differently;
                # that must NOT be treated as equivocation (it previously
                # caused a permanent 1h-ban loop that halted the chain).
                if self.db.db_type == "sqlite":
                    prior = await self.db.fetchrow("SELECT block_hash FROM signed_blocks WHERE miner_id = ? AND block_id = ?", winner_miner_id, block_id)
                else:
                    prior = await self.db.fetchrow("SELECT block_hash FROM signed_blocks WHERE miner_id = $1 AND block_id = $2", winner_miner_id, block_id)
                if prior and prior.get('block_hash') != block_hash:
                    prior_block = await self.block_repo.get_by_id(block_id)
                    if prior_block is None:
                        # Nothing was committed for this height — the earlier
                        # signature is stale (failed attempt); replace it.
                        if self.db.db_type == "sqlite":
                            await self.db.execute_dml("DELETE FROM signed_blocks WHERE miner_id = ? AND block_id = ?", winner_miner_id, block_id)
                        else:
                            await self.db.execute_dml("DELETE FROM signed_blocks WHERE miner_id = $1 AND block_id = $2", winner_miner_id, block_id)
                    elif (prior_block.get('phash') != unsigned_block['phash']
                          or prior_block.get('tx_hashes') != unsigned_block['tx_hashes']):
                        # A block IS committed at this height and this miner's
                        # prior signature covers a different chain — real
                        # equivocation.
                        await self._slash_equivocation(winner_miner_id, block_id, prior.get('block_hash'), block_hash)
                        await _rollback_producer_credit()
                        return False
                    # else: same-chain re-sign with a different ts — allow.
                # Guard approved (or no prior row): record this attempt's hash.
                if self.db.db_type == "sqlite":
                    await self.db.execute_dml(
                        "INSERT OR REPLACE INTO signed_blocks (miner_id, block_id, block_hash, signed_at) VALUES (?,?,?,?)",
                        winner_miner_id, block_id, block_hash, time.time())
                else:
                    await self.db.execute_dml(
                        "INSERT INTO signed_blocks (miner_id, block_id, block_hash, signed_at) VALUES ($1,$2,$3,$4) ON CONFLICT (miner_id, block_id) DO UPDATE SET block_hash=$3, signed_at=$4",
                        winner_miner_id, block_id, block_hash, time.time())
                if signed_block and signed_block.get("hash") == block_hash and verify_signature_bytes(signed_block.get("producer_pub", ""), bytes.fromhex(block_hash), signed_block.get("signature", "")):
                    # IDEA5-ATTEST: VRF/lottery_proof verification removed — the
                    # attestation is compared against the unsigned block below.
                    _compare_fields = ("id", "phash", "ts", "transactions", "state_root", "maze_updates", "maze_attestation", "reward_wallet", "reward", "winner", "miners", "slashes", "spatial_fee_amount")  # Spatial Tokens V2
                    tampered = False
                    for _fk in _compare_fields:
                        if signed_block.get(_fk) != unsigned_block.get(_fk):
                            logger.warning(f"[PoG] Miner returned altered block — rejecting (field '{_fk}' differs)")
                            tampered = True
                            break
                    if tampered:
                        self.node._next_block_time = time.time() + BLOCK_TIME
                        await _rollback_producer_credit()
                        # R5-sign-fail-rollback: invert this attempt tx effects so the retry starts from pre-attempt state.
                        _foreign = await self.node.block_repo.get_by_id(block_id)
                        if _foreign is None:
                            async with await self.node.db.transaction():
                                await self.node._invert_block_txs(block_id - 1, [t.get('tx_hash') for t in executed_txs if t.get('tx_hash')])
                        else:
                            logger.error(f"[SIGN-FAIL-ROLLBACK] foreign block won height {block_id} during sign; attempt effects left for reorg machinery")
                        return False
                    block = signed_block
                    block["finalized"] = False
                    block_signed = True
                    logger.info(f"[PoG] Received valid signed block from miner {winner_miner_id[:16]}")
                else:
                    logger.warning(f"[PoG] Signed block from {winner_miner_id[:16]} failed validation — skipping block {block_id}")
                    self.node._next_block_time = time.time() + BLOCK_TIME
                    await _rollback_producer_credit()
                    # R5-sign-fail-rollback: invert this attempt tx effects so the retry starts from pre-attempt state.
                    _foreign = await self.node.block_repo.get_by_id(block_id)
                    if _foreign is None:
                        async with await self.node.db.transaction():
                            await self.node._invert_block_txs(block_id - 1, [t.get('tx_hash') for t in executed_txs if t.get('tx_hash')])
                    else:
                        logger.error(f"[SIGN-FAIL-ROLLBACK] foreign block won height {block_id} during sign; attempt effects left for reorg machinery")
                    return False
            except asyncio.TimeoutError:
                self.node._block_sign_futures.pop(winner_miner_id, None)
                self.node._sign_timeout_total += 1
                logger.warning(f"[PoG] Miner {winner_miner_id[:16]} timed out producing block — skipping block {block_id}")
                await self._slash_signing_refusal(winner_miner_id)
                await _rollback_producer_credit()
                # R5-sign-fail-rollback: invert this attempt tx effects so the retry starts from pre-attempt state.
                _foreign = await self.node.block_repo.get_by_id(block_id)
                if _foreign is None:
                    async with await self.node.db.transaction():
                        await self.node._invert_block_txs(block_id - 1, [t.get('tx_hash') for t in executed_txs if t.get('tx_hash')])
                else:
                    logger.error(f"[SIGN-FAIL-ROLLBACK] foreign block won height {block_id} during sign; attempt effects left for reorg machinery")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False
            except Exception as e:
                self.node._block_sign_futures.pop(winner_miner_id, None)
                logger.error(f"[PoG] Error receiving signed block from {winner_miner_id[:16]}: {e} — skipping block {block_id}")
                await self._slash_signing_refusal(winner_miner_id)
                await _rollback_producer_credit()
                # R5-sign-fail-rollback: invert this attempt tx effects so the retry starts from pre-attempt state.
                _foreign = await self.node.block_repo.get_by_id(block_id)
                if _foreign is None:
                    async with await self.node.db.transaction():
                        await self.node._invert_block_txs(block_id - 1, [t.get('tx_hash') for t in executed_txs if t.get('tx_hash')])
                else:
                    logger.error(f"[SIGN-FAIL-ROLLBACK] foreign block won height {block_id} during sign; attempt effects left for reorg machinery")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False

            try:
                # SEAL-CREDIT-ATOMIC-1: block insert + producer reward credit
                # in ONE transaction. Previously create() ran alone here; a
                # sibling race (peer already appended this height -> plain
                # INSERT IntegrityError) escaped the sign try/except above and
                # left the pre-sign credit committed with no block — a
                # permanent +reward phantom. On failure the trie credit is
                # rolled back and production retries at the next boundary.
                async with await self.node.db.transaction():
                    await self.block_repo.create(block)
                    if reward_credited and winner_miner is not None:
                        await self.balance_repo.add(winner_miner['wallet'], total_reward)
                    # P1 (MCX72): fee pay + record join the seal txn (B1) — a
                    # crash between them can no longer leave paid-but-unrecorded
                    # fee state. Use block['spatial_fee_amount'] verbatim
                    # (same value followers apply in _append_block). A
                    # distribution failure now rolls the block back too
                    # (production retries next boundary) instead of sealing a
                    # block whose payouts followers cannot reproduce.
                    _fee_amt = int(block.get("spatial_fee_amount", 0) or 0)
                    if _fee_amt > 0:
                        _payouts = await self.node._distribute_spatial_fee(_fee_amt, block_id)
                        if _payouts:
                            await self.node._record_spatial_fee_payouts(block_id, _payouts)
            except Exception as _seal_e:
                logger.error(f"[SEAL-CREDIT-ATOMIC-1] block {block_id} seal failed: {type(_seal_e).__name__}: {_seal_e} — rolling back producer credit (sibling race?)")
                await _rollback_producer_credit()
                # R5-sign-fail-rollback: invert this attempt tx effects so the retry starts from pre-attempt state.
                _foreign = await self.node.block_repo.get_by_id(block_id)
                if _foreign is None:
                    async with await self.node.db.transaction():
                        await self.node._invert_block_txs(block_id - 1, [t.get('tx_hash') for t in executed_txs if t.get('tx_hash')])
                else:
                    logger.error(f"[SIGN-FAIL-ROLLBACK] foreign block won height {block_id} during sign; attempt effects left for reorg machinery")
                self.node._next_block_time = time.time() + BLOCK_TIME
                return False
            # IDEA5-ATTEST: seal this block's attestation on the producing node
            # (followers apply the same row in _append_block).
            try:
                await self.maze_attestation_repo.upsert({
                    "maze_id": maze_attestation["maze_id"],
                    "last_size": int(maze_attestation["size"]),
                    "last_block": int(block_id),
                    "last_block_hash": str(block["hash"]),
                    "pubkey": str(maze_attestation.get("pubkey", "")),
                })
            except Exception as _e:
                logger.warning(f"[IDEA5-ATTEST] producer upsert failed for block {block_id}: {_e}")
            # MEMPOOL-RETRY: drop included txs only now that the block is
            # sealed. Removing them at execute-success lost every tx whose
            # sign roundtrip failed: state/receipt were written, the tx left
            # the mempool, and the retried block sealed without it —
            # followers never replayed it and diverged.
            for _tx in executed_txs:
                await self.mempool.remove(_tx.get('tx_hash'))
                # R8-confirmed-wire (R7-17): sealed nonces feed the admission
                # bound promptly (next-expected semantics).
                try:
                    _w = _tx.get('from_wallet', '')
                    if _w:
                        self.mempool.note_confirmed_nonce(_w, int(_tx.get('nonce', 0)) + 1)
                except (TypeError, ValueError):
                    pass
            root_query = "INSERT OR REPLACE INTO block_state_roots (block_id,state_root,receipt_root) VALUES (?,?,?)" if self.db.db_type == "sqlite" else "INSERT INTO block_state_roots (block_id,state_root,receipt_root) VALUES ($1,$2,$3) ON CONFLICT (block_id) DO UPDATE SET state_root=$2,receipt_root=$3"
            await self.db.execute_dml(root_query, block_id, state_root, "0x" + "00" * 32)
            await self.node.finality_gadget.on_block(block)
            self.node.blocks.append(block)
            self.node.height = block_id + 1
            self.node.last_hash = block["hash"]
            self.node._next_block_time = time.time() + BLOCK_TIME
            self._height_last_advanced = time.time()
            # Update total_minted — the full base is newly minted here
            # (Spatial Tokens V2 removed the 10% pool cut; producer_base_
            # reward == base_reward). Fees are transfers.
            if winner_miner_id:
                self.node.total_minted += producer_base_reward
                await self.node.network_state_repo.set("total_minted", str(self.node.total_minted))
                await self.node.db.execute_dml("UPDATE miners SET blocks = blocks + 1, rewards = rewards + ? WHERE miner_id = ?", total_reward, winner_miner_id)
                # MINER-MISSES: a successful sign resets the refusal counter —
                # without this the counter is never cleared, so after MAX_MISSES
                # (3) accumulated timeouts the next single timeout instantly
                # re-bans a previously healthy miner for an hour.
                await self.node.db.execute_dml("UPDATE miners SET consecutive_misses = 0 WHERE miner_id = ?", winner_miner_id)
            # Broadcast new block height to all connected miners
            height_msg = {"type": "block_height_update", "height": self.node.height, "block_id": block_id}
            for mid, mws in list(self.node.miner_websockets.items()):
                try:
                    await mws.send_json(height_msg)
                except Exception:
                    pass
            # Drain pending maze updates — they are now committed in this block
            self._pending_maze_updates.clear()
            # R6-slash-state-order: apply the locally-queued slash events now
            # that they are sealed (deferred from _slash_*); followers apply
            # the same events in _append_block, so producer and followers
            # converge. A failure raises before the clear below, leaving the
            # queue intact for the next seal (the helper dedupes replays).
            for _ev in list(self._pending_slashes):
                if await self.node._apply_slash_event(_ev, block_id):
                    await self._kick_banned_socket(_ev.get("miner_id"), f"sealed {_ev.get('reason', 'slash')}")
            # SLASH-REPLICA: the queued events are sealed into this block.
            self._pending_slashes.clear()
            try:
                await self.node.db.execute_dml("DELETE FROM pending_maze_updates WHERE block_id <= ?", block_id)
            except Exception:
                pass

            if winner_miner_id:
                logger.info(f"[PoG] Block {block_id} won by {winner_miner_id[:16]}, reward={total_reward // SUBS} MCX")
            else:
                logger.info(f"[PoG] Block {block_id} burned (no winner)")

            await self.node.distribute_token_mining_rewards(block_id)
            if block_id % self.epoch_length == 0:
                await self._create_finality_checkpoint(block_id, self.node.last_hash)

            # Save state snapshot every SNAPSHOT_INTERVAL blocks for fast sync
            if block_id % SNAPSHOT_INTERVAL == 0 and block_id > 0:
                try:
                    # R8-snapshot-restore (R7-04): canonical snapshot encoding
                    # — snapshot_data maps key -> the exact JSON
                    # value-encoding already in _dirty (strings verbatim).
                    # Restore stores these WITHOUT re-encoding.
                    snapshot_data = json.dumps(snapshot_dirty, sort_keys=True) if snapshot_dirty else "{}"
                    if self.db.db_type == "sqlite":
                        await self.db.execute_dml("INSERT OR REPLACE INTO state_snapshots (block_id,state_root,receipt_root,snapshot_data,created_at) VALUES (?,?,?,?,?)", block_id, state_root, "0x" + "00" * 32, snapshot_data, int(time.time()))
                    else:
                        await self.db.execute_dml("INSERT INTO state_snapshots (block_id,state_root,receipt_root,snapshot_data,created_at) VALUES ($1,$2,$3,$4,$5) ON CONFLICT (block_id) DO UPDATE SET state_root=$2,snapshot_data=$4", block_id, state_root, "0x" + "00" * 32, snapshot_data, int(time.time()))
                    logger.info(f"[PoG] State snapshot saved at block {block_id}")
                except Exception as e:
                    logger.warning(f"[PoG] Failed to save snapshot at block {block_id}: {e}")

            await self.node.p2p.broadcast_block(block)
            # DELIVERY-RETRY-1: repeat the push after the seal — the first
            # fanout can land on sockets mid-churn and is then lost forever
            # (attempt5 S10: node1's h14 never reached node2 for 41s and
            # node2 produced a sibling from the stale tip).
            for _d in (3.0, 9.0):
                self.node.p2p._track_task(asyncio.create_task(
                    self.node.p2p.rebroadcast_block_later(block, _d)))
            self.node.health_checker.record_block(block_id)
            return True

    @staticmethod
    def _select_weighted_winner(seed: bytes, eligible: list) -> Tuple[Optional[str], int, dict]:
        weights = {
            minerid: PoGConsensus._maze_weight(size)
            for minerid, size in sorted(eligible)
        }
        total = sum(weights.values())
        if total <= 0:
            return None, 0, weights
        ticket = int.from_bytes(
            eth_keccak(b"MCXPOGTICKETV1" + seed),
            "big",
        ) % total
        cursor = 0
        for minerid in sorted(weights):
            cursor += weights[minerid]
            if ticket < cursor:
                return minerid, ticket, weights
        raise AssertionError("Lottery selection fell through")

    async def _create_finality_checkpoint(self, block_id: int, block_hash: str):
        self.epoch += 1
        await self.finality_repo.create_checkpoint(block_id, block_hash, self.epoch)
        await self.block_repo.mark_finalized(block_id)
        logger.info(f"[PoG] Finality checkpoint at block {block_id} (epoch {self.epoch})")

    async def _shrink_and_ghost_chase(self, block_id: int):
        """Shrink and ghost chase OUTSIDE blockexecutionlock.
        Uses run_in_executor for CPU-heavy maze generation so the event
        loop stays free for WS move handlers."""
        loop = asyncio.get_event_loop()
        # GHOST-CONNECTED-1: chase only mazes whose miner is connected — ghost
        # pressure on offline rows kept resurrecting dead mazes every block.
        # NO-OFFLINE-SHRINK-1: the block-time _apply_shrink call is removed
        # (the ghost-catch path below still restarts position on contact).
        all_mazes = [
            mz for mz in await self.maze_repo.get_eligible(block_id)
            if mz.get("minerid") in self.node.miner_websockets
        ]
        for mz in all_mazes:
            # --- Ghost chase ---
            mid = mz["maze_id"]
            sz = int(mz["size"])
            if sz > 5:
                gpos = self._ghost_tuple(mz)
                if gpos:
                    mx, my, mz_pos = int(mz["posx"]), int(mz["posy"]), int(mz["posz"])
                    miner_pos = (mx, my, mz_pos)
                    if gpos != miner_pos:
                        ghost_moved = False
                        ghost_caught = False
                        # Run CPU-heavy maze gen in thread pool
                        maze_arr = await loop.run_in_executor(
                            self._move_executor,
                            self._generate_deterministic_maze,
                            mz["seed"], sz, int(mz["walldensityppm"]),
                            int(mz["turbulenceppm"]), self.node.height
                        )
                        if mid in self._oscillating_mazes:
                            # Oscillation mode: sweep frozen cycle cells, 2 steps per block
                            if mid not in self._ghost_cycle:
                                cycle_cells = []
                                for p in self._pos_history.get(mid, []):
                                    if p not in cycle_cells:
                                        cycle_cells.append(p)
                                if cycle_cells:
                                    def _manh(a, b):
                                        return abs(a[0]-b[0]) + abs(a[1]-b[1]) + abs(a[2]-b[2])
                                    farthest_idx = max(range(len(cycle_cells)),
                                                       key=lambda i: _manh(gpos, cycle_cells[i]))
                                    self._ghost_cycle[mid] = cycle_cells
                                    self._ghost_cycle_idx[mid] = farthest_idx
                                    self._ghost_frozen_target[mid] = cycle_cells[farthest_idx]
                            if mid in self._ghost_cycle:
                                cycle_cells = self._ghost_cycle[mid]
                                idx = self._ghost_cycle_idx[mid]
                                target = cycle_cells[idx]
                                if gpos == target:
                                    idx = (idx + 1) % len(cycle_cells)
                                    self._ghost_cycle_idx[mid] = idx
                                    target = cycle_cells[idx]
                                for _ in range(2):
                                    gdx, gdy, gdz = self._bfs_next_step(maze_arr, sz, gpos, target)
                                    if gdx is None:
                                        break
                                    gpos = (gpos[0]+gdx, gpos[1]+gdy, gpos[2]+gdz)
                                    ghost_moved = True
                                    if gpos == miner_pos:
                                        break
                                if gpos == miner_pos:
                                    restart_ev = await self._restart_position(dict(mz), mid, mz["minerid"], sz)
                                    if restart_ev:
                                        ghost_caught = True
                                        await self.maze_repo.upsert({**dict(mz), **restart_ev})
                        else:
                            # Normal mode: 1 step toward live miner position
                            gdx, gdy, gdz = self._bfs_next_step(maze_arr, sz, gpos, miner_pos)
                            if gdx is not None:
                                new_gpos = (gpos[0]+gdx, gpos[1]+gdy, gpos[2]+gdz)
                                gpos = new_gpos
                                ghost_moved = True
                                if new_gpos == miner_pos:
                                    restart_ev = await self._restart_position(dict(mz), mid, mz["minerid"], sz)
                                    if restart_ev:
                                        ghost_caught = True
                                        await self.maze_repo.upsert({**dict(mz), **restart_ev})
                        if ghost_moved and not ghost_caught:
                            self._set_ghost(mz, gpos)
                            await self.maze_repo.upsert(dict(mz))
            # Yield to event loop after each maze
            await asyncio.sleep(0)

    async def _update_global_shrink_factor(self):
        """Recalculate GLOBAL_SHRINK_FACTOR from eligible miners in the database.
        Called by both production_loop (producing nodes) and receive_block (non-producing)."""
        try:
            eligible_rows = await self.maze_repo.get_eligible(self.node.height)
            if eligible_rows:
                total_size = sum(int(r["size"]) for r in eligible_rows)
                self._global_avg_size = total_size / len(eligible_rows)
                _config.GLOBAL_SHRINK_FACTOR = max(1.0, self._global_avg_size / 10)
        except Exception:
            pass

    async def production_loop(self):
        last_height_broadcast = 0
        while not self.node._shutdown_flag:
            try:
                if not self.node._producing_enabled:
                    await asyncio.sleep(10)
                    continue

                # Recalculate global shrink factor every block cycle
                await self._update_global_shrink_factor()

                await self.produce_block()

                # Shrink + ghost chase OUTSIDE blockexecutionlock
                # Run in thread pool so maze gen doesn't block event loop
                try:
                    await self._shrink_and_ghost_chase(self.node.height)
                except Exception as e:
                    logger.error(f"[PoG] Shrink/ghost error: {e}")

                # Broadcast height to miners every BLOCK_TIME even if no block produced
                now = time.time()
                if now - last_height_broadcast >= BLOCK_TIME and self.node.miner_websockets:
                    last_height_broadcast = now
                    height_msg = {"type": "block_height_update", "height": self.node.height, "block_id": self.node.height - 1}
                    for mid, mws in list(self.node.miner_websockets.items()):
                        try:
                            await mws.send_json(height_msg)
                        except Exception:
                            pass

                await asyncio.sleep(0.1)
            except Exception as e:
                logger.error(f"[PoG] Production loop error: {e}", exc_info=True)
                await asyncio.sleep(5)

# ─── Legacy alias ─────────────────────────────────────────────

    async def _kick_banned_socket(self, miner_id: str, why: str):
        # BAN-KICK-1: a banned miner's socket must not linger — while it
        # stays in miner_websockets, hosting/hosting checks still see it as
        # connected and it can keep signing on the same connection.
        ws = self.node.miner_websockets.pop(miner_id, None)
        self.node.miners.pop(miner_id, None)
        self.node.miner_rate_limiters.pop(miner_id, None)
        if ws:
            try:
                await ws.close(code=1000, message=b"banned")
            except Exception:
                pass
        logger.warning(f"[BAN-KICK-1] disconnected {str(miner_id)[:16]} ({why})")

    async def _slash_signing_refusal(self, miner_id: str):
        """Slash a miner for refusing to sign a block they were selected to produce."""
        # R6-slash-state-order: queue + broadcast ONLY (chain reset:
        # state-machine change). Miner-state mutation used to apply here
        # immediately while only the queued event rode the next sealed
        # block, so a detecting node that never sealed diverged. Local
        # application now happens at seal time via _apply_slash_event.
        miner = await self.miner_repo.get(miner_id)
        if not miner:
            return
        slash_amount = max(1, int(miner.get('rewards', 0) * 5 // 100))
        # SLASH-REPLICA: queue the event; it commits with the next block this
        # node seals so followers apply the identical reduction.
        self._pending_slashes.append({"miner_id": miner_id, "amount": slash_amount, "reason": "signing_refusal", "block_id": self.node.height})
        # Broadcast slash to peers
        slash_msg = {
            "type": "slash",
            "miner_id": miner_id,
            "amount": slash_amount,
            "reason": "signing_refusal",
            "block_id": self.node.height
        }
        for mid, mws in list(self.node.miner_websockets.items()):
            try:
                await mws.send_json({"type": "slash", "data": slash_msg})
            except Exception:
                pass
        # R6-slash-state-order: the dead per-detection counter is gone with
        # the immediate path (incidental scope: write-only, never read).
        logger.warning(f"[Slash] Miner {miner_id[:16]} slashed for signing refusal: {slash_amount} subunits")

    async def _slash_equivocation(self, miner_id: str, block_id: int, hash_a: str, hash_b: str):
        """Slash a miner for equivocation (signing two different blocks at the same height)."""
        # R6-slash-state-order: queue + broadcast ONLY (see
        # _slash_signing_refusal). The stale "already applied locally"
        # note below is deleted with the immediate path.
        miner = await self.miner_repo.get(miner_id)
        if not miner:
            return
        slash_amount = max(1, int(miner.get('rewards', 0) * 10 // 100))
        # SLASH-REPLICA: queue the event; it commits with the next block this
        # node seals so followers apply the identical reduction.
        self._pending_slashes.append({"miner_id": miner_id, "amount": slash_amount, "reason": "equivocation", "block_id": block_id, "hash_a": hash_a, "hash_b": hash_b})
        slash_msg = {
            "type": "slash",
            "miner_id": miner_id,
            "amount": slash_amount,
            "reason": "equivocation",
            "block_id": block_id,
            "hash_a": hash_a,
            "hash_b": hash_b
        }
        for mid, mws in list(self.node.miner_websockets.items()):
            try:
                await mws.send_json({"type": "slash", "data": slash_msg})
            except Exception:
                pass
        logger.error(f"[Slash] Miner {miner_id[:16]} EQUIVOCATED at block {block_id}: {hash_a[:16]} vs {hash_b[:16]}, slashed {slash_amount}")



PoMRConsensus = PoGConsensus


# Split of MCX81.py (lines 7736-7936). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import List, Optional, Tuple, deque, random
from node import config as _config


# ─── SparseMaze (node-side) ──────────────────────────────────
class _SparseZRow:
    """Proxy for maze[z] — supports maze[z][y][x] indexing."""
    __slots__ = ('_walls', '_size', '_z')
    def __init__(self, walls, size, z):
        self._walls = walls; self._size = size; self._z = z
    def __getitem__(self, y):
        return _SparseXYRow(self._walls, self._size, self._z, y)
    def __len__(self):
        return self._size

class _SparseXYRow:
    """Proxy for maze[z][y] — supports maze[z][y][x] indexing."""
    __slots__ = ('_walls', '_size', '_z', '_y')
    def __init__(self, walls, size, z, y):
        self._walls = walls; self._size = size; self._z = z; self._y = y
    def __getitem__(self, x):
        return (x, self._y, self._z) in self._walls
    def __len__(self):
        return self._size

class SparseMaze:
    """Sparse maze representation — stores only wall coordinates as a set.
    Supports the same maze[z][y][x] indexing as dense lists."""
    __slots__ = ('walls', 'size')
    def __init__(self, walls: set, size: int):
        self.walls = walls
        self.size = size
    def __getitem__(self, z):
        return _SparseZRow(self.walls, self.size, z)
    def __len__(self):
        return self.size

def dense_to_sparse(maze) -> SparseMaze:
    """Convert dense 3D maze to SparseMaze."""
    size = len(maze)
    walls = set()
    for z in range(size):
        for y in range(size):
            for x in range(size):
                if maze[z][y][x]:
                    walls.add((x, y, z))
    return SparseMaze(walls, size)

def sparse_to_dense(sparse: SparseMaze) -> list:
    """Convert SparseMaze back to dense 3D list."""
    size = sparse.size
    maze = [[[False] * size for _ in range(size)] for _ in range(size)]
    for x, y, z in sparse.walls:
        maze[z][y][x] = True
    return maze

# ─── Maze3DGenerator ──────────────────────────────────────────
class Maze3DGenerator:
    @staticmethod
    def generate(seed: str, size: int, density: float = _config.WALL_DENSITY_3D) -> List[List[List[bool]]]:
        attempts = 0
        while attempts < 20:
            rng = random.Random(seed + str(attempts))
            maze = [[[True] * size for _ in range(size)] for _ in range(size)]

            def carve(x0, y0, z0, x1, y1, z1):
                width, depth, height = x1 - x0, y1 - y0, z1 - z0
                if min(width, depth, height) <= 2:
                    for z in range(z0, z1):
                        for y in range(y0, y1):
                            for x in range(x0, x1):
                                maze[z][y][x] = False
                    return
                axis = max(range(3), key=lambda idx: (x1, y1, z1)[idx] - (x0, y0, z0)[idx])
                bounds = [(x0, x1), (y0, y1), (z0, z1)]
                low, high = bounds[axis]
                split = rng.randrange(low + 1, high - 1)
                bounds_a = [list(b) for b in bounds]
                bounds_b = [list(b) for b in bounds]
                bounds_a[axis][1] = split
                bounds_b[axis][0] = split + 1
                carve(*[v for pair in bounds_a for v in pair])
                carve(*[v for pair in bounds_b for v in pair])
                passage = [rng.randrange(start, end) for start, end in bounds]
                passage[axis] = split
                maze[passage[2]][passage[1]][passage[0]] = False
                adj = passage.copy()
                adj[axis] += 1
                maze[adj[2]][adj[1]][adj[0]] = False

            carve(0, 0, 0, size, size, size)

            # Ensure start and goal are open
            maze[0][0][0] = False
            maze[size - 1][size - 1][size - 1] = False

            # Check connectivity
            if Maze3DGenerator.is_connected(maze, (0,0,0), (size-1,size-1,size-1)):
                # Add extra random walls (3% of cells) to create labyrinthine mazes
                extra = int(size * size * size * 0.03)
                for _ in range(extra):
                    x = rng.randrange(0, size)
                    y = rng.randrange(0, size)
                    z = rng.randrange(0, size)
                    if (x, y, z) in [(0, 0, 0), (size-1, size-1, size-1)]:
                        continue
                    if not maze[z][y][x]:
                        maze[z][y][x] = True
                        if not Maze3DGenerator.is_connected(maze, (0,0,0), (size-1,size-1,size-1)):
                            maze[z][y][x] = False
                return maze
            attempts += 1

        # Fallback: empty maze (all open)
        return [[[False] * size for _ in range(size)] for _ in range(size)]

    @staticmethod
    def is_connected(maze,
                      start: Tuple[int, int, int],
                      goal: Tuple[int, int, int]) -> bool:
        if isinstance(maze, SparseMaze):
            size = maze.size
            walls = maze.walls
            is_wall = lambda x, y, z: (x, y, z) in walls
        else:
            size = len(maze)
            is_wall = lambda x, y, z: maze[z][y][x]
        visited = {start}
        queue = deque([start])
        while queue:
            x, y, z = queue.popleft()
            for dx, dy, dz in DIRS_3D.values():
                nx, ny, nz = x + dx, y + dy, z + dz
                if (0 <= nx < size and 0 <= ny < size and 0 <= nz < size
                        and (nx, ny, nz) not in visited and not is_wall(nx, ny, nz)):
                    visited.add((nx, ny, nz))
                    queue.append((nx, ny, nz))
        total_open = size * size * size - len(walls) if isinstance(maze, SparseMaze) else sum(1 for zz in range(size) for yy in range(size) for xx in range(size) if not maze[zz][yy][xx])
        return len(visited) == total_open

    @staticmethod
    def open_cells(maze) -> List[Tuple[int, int, int]]:
        if isinstance(maze, SparseMaze):
            size = maze.size
            walls = maze.walls
            return [(x, y, z) for z in range(size) for y in range(size) for x in range(size)
                    if (x, y, z) not in walls]
        else:
            size = len(maze)
            return [(x, y, z) for z in range(size) for y in range(size) for x in range(size)
                    if not maze[z][y][x]]

    @staticmethod
    def bfs_distance(maze,
                     start: Tuple[int, int, int],
                     goal: Tuple[int, int, int]) -> Optional[int]:
        """Return shortest path length from start to goal, or None if unreachable."""
        if isinstance(maze, SparseMaze):
            size = maze.size
            walls = maze.walls
            is_wall = lambda x, y, z: (x, y, z) in walls
        else:
            size = len(maze)
            is_wall = lambda x, y, z: maze[z][y][x]
        if not (0 <= start[0] < size and 0 <= start[1] < size and 0 <= start[2] < size):
            return None
        if not (0 <= goal[0] < size and 0 <= goal[1] < size and 0 <= goal[2] < size):
            return None
        if is_wall(start[0], start[1], start[2]) or is_wall(goal[0], goal[1], goal[2]):
            return None
        visited = {start}
        queue = deque([(start, 0)])
        while queue:
            (x, y, z), dist = queue.popleft()
            if (x, y, z) == goal:
                return dist
            for dx, dy, dz in DIRS_3D.values():
                nx, ny, nz = x + dx, y + dy, z + dz
                if (0 <= nx < size and 0 <= ny < size and 0 <= nz < size
                        and (nx, ny, nz) not in visited and not is_wall(nx, ny, nz)):
                    visited.add((nx, ny, nz))
                    queue.append(((nx, ny, nz), dist + 1))
        return None
DIRS_3D = {
    "east":  (1, 0, 0),
    "west":  (-1, 0, 0),
    "north": (0, 1, 0),
    "south": (0, -1, 0),
    "up":    (0, 0, 1),
    "down":  (0, 0, -1),
}

# ─── FUTURE: ALLOWED STORAGE CONCEPT (Planned Feature) ──────────
# STORAGE_PER_CELL_KB = 10 (constant). Each maze cell (x,y,z) maps to a
# storage shard of exactly 10 KB, regardless of maze size. No exponential growth.
# The miner must store encrypted data for each cell they occupy or have explored.
# On every maze_move, the miner includes a storage_proof (hash of the shard data)
# in the signed payload. The node verifies the proof against the expected hash
# (derived deterministically from maze seed + coordinates).
# If proof is missing or invalid -> move treated as a wall hit.
# On maze growth, new cell shards are generated; miner must allocate storage before
# moving into them. On maze shrink, shards outside the new size can be deleted.
# This turns PoG into a hybrid Proof-of-Growth + Proof-of-Space.
# NOT ACTIVE IN THIS VERSION – placeholder for future implementation.


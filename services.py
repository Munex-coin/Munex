# Split of MCX81.py (lines 4919-4998). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.config import BLOCK_TIME, VERSION
from node.bootstrap import Dict, asyncio, deque, time


# ─── Rate Limiter ────────────────────────────────────────────
class RateLimiter:
    def __init__(self, max_requests: int = 60, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window = window_seconds
        self._requests: Dict[str, deque] = {}
        self._lock = asyncio.Lock()
        self._cleanup_task = None

    async def start_cleanup(self):
        async def cleanup_loop():
            while True:
                await asyncio.sleep(60)
                await self._cleanup()
        self._cleanup_task = asyncio.create_task(cleanup_loop())

    async def _cleanup(self):
        async with self._lock:
            now = time.time()
            for ip in list(self._requests.keys()):
                while self._requests[ip] and now - self._requests[ip][0] > self.window:
                    self._requests[ip].popleft()
                if not self._requests[ip]:
                    del self._requests[ip]

    async def is_allowed(self, client_ip: str) -> bool:
        async with self._lock:
            now = time.time()
            if client_ip not in self._requests:
                self._requests[client_ip] = deque()
            while self._requests[client_ip] and now - self._requests[client_ip][0] > self.window:
                self._requests[client_ip].popleft()
            if len(self._requests[client_ip]) >= self.max_requests:
                return False
            self._requests[client_ip].append(now)
            return True


# ─── Health Checker ──────────────────────────────────────────
class HealthChecker:
    def __init__(self):
        self.start_time = time.time()
        self.last_block_time = time.time()
        self.blocks_produced = 0
        self.peer_count = 0
        self.miner_count = 0
        self.errors = 0
        self.status = "starting"
        self._block_history = deque(maxlen=100)

    def get_status(self) -> dict:
        uptime = int(time.time() - self.start_time)
        block_rate = len(self._block_history) / max(uptime / 3600, 0.1)
        return {
            "status": self.status,
            "uptime": uptime,
            "uptime_hours": uptime / 3600,
            "blocks_produced": self.blocks_produced,
            "block_rate_per_hour": block_rate,
            "peers": self.peer_count,
            "miners": self.miner_count,
            "errors": self.errors,
            "error_rate": self.errors / max(uptime / 3600, 0.1),
            "last_block": int(self.last_block_time),
            "last_block_age": int(time.time() - self.last_block_time),
            "version": VERSION,
            "healthy": self.errors < 10 and (time.time() - self.last_block_time) < BLOCK_TIME * 6
        }

    def record_block(self, block_id: int):
        self.blocks_produced += 1
        self.last_block_time = time.time()
        self._block_history.append((block_id, time.time()))

    def record_error(self, error: str):
        self.errors += 1
        if self.errors > 100:
            self.status = "degraded"



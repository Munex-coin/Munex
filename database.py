# Split of MCX81.py (lines 2678-4576). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import asyncpg, logger, psycopg2
from node.config import ACTIVE_MINER_WINDOW_BLOCKS, CHAIN_ID, CONFIG, MIN_MAZE_SIZE, SCHEMA_VERSION, VERSION, _BLOCK_PROOF_KEYS
from node.crypto import pubkey_to_address, verify_signature
from node.bootstrap import Any, ContextVar, Optional, Tuple, asyncio, hashlib, json, os, re, sqlite3, sys, time, urlparse


# ─── Database ────────────────────────────────────────────
def _pg_convert_placeholders(query):
    """Convert ? placeholders to $N for PostgreSQL, skipping ? inside single-quoted strings."""
    result = []
    param_num = 1
    in_quote = False
    for i, c in enumerate(query):
        if in_quote:
            result.append(c)
            if c == "'" and (i == 0 or query[i - 1] != '\\'):
                in_quote = False
        elif c == "'":
            in_quote = True
            result.append(c)
        elif c == '?':
            result.append(f'${param_num}')
            param_num += 1
        else:
            result.append(c)
    return ''.join(result)

_pg_conn_context: ContextVar[Optional[Any]] = ContextVar("_pg_conn_context", default=None)
_sqlite_in_tx: ContextVar[bool] = ContextVar("_sqlite_in_tx", default=False)
# R5-sqlite-tx-task-local: transaction membership is per-task, not per-connection.


def _redact_dsn(text: str) -> str:
    """DB-BACKEND-1: strip embedded credentials (scheme://user:pass@host)
    from driver error text before logging. Userinfo without a password is
    left alone. Pure; never raises."""
    try:
        return re.sub(r"(://)([^/@\s]+)@",
                      lambda m: m.group(1) + ("***" if ":" in m.group(2) else m.group(2)) + "@",
                      str(text or ""))
    except Exception:
        return "<unprintable db error>"


class Database:
    def __init__(self, db_url=None, require_postgres=None):
        self.db_type = None
        self.conn = None
        self.cursor = None
        self._pool = None
        self._initialized = False
        self._pg_dsn = None
        self._pg_target_dsn = None
        self._db_url = db_url
        self._sqlite_lock = asyncio.Lock()
        # R5-sqlite-tx-task-local: membership lives in _sqlite_in_tx (module ContextVar).
        # R4-mainnet-guard-consistency: the effective value comes from the
        # owning node (which honors --config/--db-url); the module-level
        # CONFIG read is only the default when no node passes one.
        self.require_postgres = (require_postgres if require_postgres is not None
                                 else CONFIG.get('database', {}).get('require_postgres', False))
        if db_url:
            if db_url.startswith("sqlite://"):
                # DB-BACKEND-1: an explicit sqlite URL together with
                # require_postgres is a misconfiguration that would
                # silently split node state onto SQLite — refuse instead.
                if getattr(self, 'require_postgres', False):
                    logger.error("[DB] Explicit SQLite URL conflicts with database.require_postgres: true. Exiting.")
                    sys.exit(1)
                self.db_type = "sqlite"
                path = db_url[9:] if db_url.startswith("sqlite://") else db_url
                self.conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
                self.conn.row_factory = sqlite3.Row
                self.conn.execute("PRAGMA journal_mode=WAL")
                self.conn.execute("PRAGMA synchronous=NORMAL")
                self.cursor = self.conn.cursor()
                self._initialized = True
                logger.info(f"[DB] SQLite forced (WAL): {path}")
                return
            if db_url and db_url.startswith("postgresql://") and psycopg2 is None:
                # startup bootstrap owns installs now; if we're here it was
                # skipped or pip failed — fall back to SQLite like before
                if getattr(self, 'require_postgres', False):
                    logger.error("[DB] PostgreSQL required but not available. Exiting.")
                    sys.exit(1)
                logger.warning("[DB] psycopg2 unavailable — falling back to SQLite.")
                self._fallback_sqlite()
                return
            elif db_url.startswith("postgresql://"):
                self.db_type = "postgres"
                self._pg_target_dsn = db_url
                parsed = urlparse(db_url)
                default_db = parsed._replace(path='/postgres').geturl()
                self._pg_dsn = default_db
                logger.info("[DB] PostgreSQL DSN provided.")
                return
        self._auto_detect_and_connect()

    def _auto_detect_and_connect(self):
        if psycopg2 is None:
            if getattr(self, 'require_postgres', False):
                logger.error("[DB] PostgreSQL required but not available. Exiting.")
                sys.exit(1)
            logger.warning("[DB] psycopg2 not installed — falling back to SQLite. "
                           "Install with: pip install psycopg2-binary")
            self._fallback_sqlite()
            return
        pg_user = os.environ.get("MCX_PG_USER", "postgres")
        pg_password = os.environ.get("MCX_PG_PASSWORD", "postgres")
        pg_host = os.environ.get("MCX_PG_HOST", "localhost")
        pg_port = os.environ.get("MCX_PG_PORT", "5432")
        if pg_user == "postgres" and pg_password == "postgres":
            logger.warning("[SECURITY] Using default PostgreSQL credentials (postgres:postgres). "
                          "Set MCX_PG_USER and MCX_PG_PASSWORD environment variables for production.")
        self._pg_user = pg_user; self._pg_password = pg_password; self._pg_host = pg_host; self._pg_port = pg_port
        self._pg_dsn = f"postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}/postgres"
        self._pg_target_dsn = f"postgresql://{pg_user}:{pg_password}@{pg_host}:{pg_port}/mcx"
        try:
            conn = psycopg2.connect(self._pg_dsn)
            conn.close()
            self.db_type = "postgres"
            logger.info("[DB] PostgreSQL detected.")
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            # DB-BACKEND-1: driver errors echo connection parameters — redact
            # any embedded credentials before logging.
            logger.warning(f"[DB] PostgreSQL not reachable ({_redact_dsn(str(e))})")
            if getattr(self, 'require_postgres', False):
                logger.error("[DB] PostgreSQL required but not available. Exiting.")
                sys.exit(1)
            logger.warning("[DB] Falling back to SQLite. Set database.require_postgres: true in config.yaml to make this fatal on mainnet.")
            self._fallback_sqlite()

    def _fallback_sqlite(self):
        logger.info("[DB] Falling back to SQLite.")
        self.db_type = "sqlite"
        path = os.path.join(os.getcwd(), "microcore.db")
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.cursor = self.conn.cursor()
        self._initialized = True
        logger.info(f"[DB] SQLite connected (WAL): {path}")

    async def initialize(self):
        if self.db_type == "postgres":
            try:
                self._pool = await asyncpg.create_pool(self._pg_target_dsn, min_size=2, max_size=10)
                self._initialized = True
                logger.info("[DB] PostgreSQL connected successfully.")
                await self._apply_postgres_migrations()
                return
            except asyncpg.exceptions.InvalidCatalogNameError:
                logger.warning("[DB] Database 'mcx' does not exist. Creating...")
                conn = await asyncpg.connect(self._pg_dsn)
                await conn.execute("CREATE DATABASE mcx;")
                await conn.close()
                self._pool = await asyncpg.create_pool(self._pg_target_dsn)
                self._initialized = True
                logger.info("[DB] PostgreSQL created and connected.")
                await self._apply_postgres_migrations()
                return
            except Exception as e:
                # DB-BACKEND-1: redact before logging (see _redact_dsn).
                logger.error(f"[DB] PostgreSQL connection failed: {_redact_dsn(str(e))}")
                if getattr(self, 'require_postgres', False):
                    logger.error("[DB] PostgreSQL required but not available. Exiting.")
                    sys.exit(1)
                self._fallback_sqlite()
        else:
            self._initialized = True

    async def _apply_postgres_migrations(self):
        try:
            async with self._pool.acquire() as conn:
                await conn.execute("ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS maze_id TEXT")
                await conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_minermazes_maze_id ON minermazes(maze_id) WHERE maze_id IS NOT NULL")
                await conn.execute("ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS knowledge INTEGER NOT NULL DEFAULT 0")
                await conn.execute("ALTER TABLE miners ADD COLUMN IF NOT EXISTS block_signing_pub TEXT")
                await conn.execute("ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS lastknowledgeheight BIGINT NOT NULL DEFAULT 0")
                await conn.execute("ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS ghostx INTEGER")
                await conn.execute("ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS ghosty INTEGER")
                await conn.execute("ALTER TABLE minermazes ADD COLUMN IF NOT EXISTS ghostz INTEGER")
                # Fix: REAL (float32) truncates Python float64 values on round-trip,
                # causing hash mismatches. Migrate to DOUBLE PRECISION.
                await conn.execute("ALTER TABLE blocks ALTER COLUMN coverage TYPE DOUBLE PRECISION USING coverage::DOUBLE PRECISION")
        except Exception as e:
            logger.warning(f"[DB] Postgres migration (minermazes.maze_id) skipped: {e}")


    async def close(self):
        if self.db_type == "postgres" and self._pool:
            await self._pool.close()
        elif self.db_type == "sqlite" and self.conn:
            self.conn.close()
        logger.debug("[DB] Closed")

    async def execute(self, query, *args):
        if self.db_type == "postgres":
            if "?" in query:
                query = _pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                return await conn.fetch(query, *args)
            async with self._pool.acquire() as conn:
                return await conn.fetch(query, *args)
        else:
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                return self.cursor.fetchall()

    async def execute_dml(self, query, *args):
        if self.db_type == "postgres":
            if "?" in query:
                query = _pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                return await conn.execute(query, *args)
            async with self._pool.acquire() as conn:
                return await conn.execute(query, *args)
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                return str(self.cursor.rowcount)
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                self.conn.commit()
                return str(self.cursor.rowcount)

    async def fetch(self, query, *args):
        if self.db_type == "postgres":
            if "?" in query:
                query = _pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                rows = await conn.fetch(query, *args)
                return [dict(r) for r in rows]
            async with self._pool.acquire() as conn:
                rows = await conn.fetch(query, *args)
                return [dict(r) for r in rows]
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                return [dict(r) for r in self.cursor.fetchall()]
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                return [dict(r) for r in self.cursor.fetchall()]

    async def fetchrow(self, query, *args):
        if self.db_type == "postgres":
            if "?" in query:
                query = _pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                row = await conn.fetchrow(query, *args)
                return dict(row) if row else None
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(query, *args)
                return dict(row) if row else None
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return dict(row) if row else None
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return dict(row) if row else None

    async def fetchval(self, query, *args):
        if self.db_type == "postgres":
            if "?" in query:
                query = _pg_convert_placeholders(query)
            conn = _pg_conn_context.get()
            if conn is not None:
                return await conn.fetchval(query, *args)
            async with self._pool.acquire() as conn:
                return await conn.fetchval(query, *args)
        else:
            if _sqlite_in_tx.get():
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return row[0] if row else None
            async with self._sqlite_lock:
                self.cursor.execute(query, args)
                row = self.cursor.fetchone()
                return row[0] if row else None

    async def commit(self):
        if self.db_type != "postgres":
            if _sqlite_in_tx.get():
                self.conn.commit()
            else:
                async with self._sqlite_lock:
                    self.conn.commit()

    async def rollback(self):
        if self.db_type != "postgres":
            if _sqlite_in_tx.get():
                self.conn.rollback()
            else:
                async with self._sqlite_lock:
                    self.conn.rollback()

    class _sqlite_transaction:
        def __init__(self, db):
            self._db = db
            self._nested = False
        async def __aenter__(self):
            if self._db.db_type == "sqlite":
                if not _sqlite_in_tx.get():
                    await self._db._sqlite_lock.acquire()
                    _sqlite_in_tx.set(True)
                    self._db.conn.execute("BEGIN IMMEDIATE")
                    self._nested = False
                else:
                    self._nested = True
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            if self._db.db_type == "sqlite":
                if not self._nested:
                    try:
                        if exc_type:
                            self._db.conn.rollback()
                        else:
                            self._db.conn.commit()
                    finally:
                        _sqlite_in_tx.set(False)
                        self._db._sqlite_lock.release()
            return False

    class _pg_transaction:
        """PG-1: asyncpg transaction bound to a pooled connection via ContextVar."""
        def __init__(self, db):
            self._db = db
            self._conn = None
            self._tx = None
            self._token = None
            self._nested = False
        async def __aenter__(self):
            current_conn = _pg_conn_context.get()
            if current_conn is not None:
                self._conn = current_conn
                self._nested = True
                self._tx = self._conn.transaction()
                await self._tx.start()
            else:
                self._conn = await self._db._pool.acquire()
                self._tx = self._conn.transaction()
                await self._tx.start()
                self._token = _pg_conn_context.set(self._conn)
            return self
        async def __aexit__(self, exc_type, exc_val, exc_tb):
            try:
                if exc_type:
                    await self._tx.rollback()
                else:
                    await self._tx.commit()
            finally:
                if not self._nested:
                    if self._token is not None:
                        _pg_conn_context.reset(self._token)
                    await self._db._pool.release(self._conn)
            return False

    async def transaction(self):
        # PG-1: return the driver-appropriate context. The old code always
        # returned the sqlite context manager (BEGIN IMMEDIATE), which is
        # invalid against asyncpg.
        if getattr(self, "db_type", "sqlite") == "postgres":
            return self._pg_transaction(self)
        return self._sqlite_transaction(self)

    async def create_tables(self):
        if self.db_type == "postgres":
            async with self._pool.acquire() as conn:
                await conn.execute("""
                    CREATE TABLE IF NOT EXISTS miners (
                        miner_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, pub TEXT NOT NULL,
                        rewards BIGINT DEFAULT 0, blocks BIGINT DEFAULT 0, slashes INTEGER DEFAULT 0,
                        uptime INTEGER DEFAULT 0, today_uptime INTEGER DEFAULT 0, type TEXT DEFAULT 'web',
                        liquidity BIGINT DEFAULT 0, fees BIGINT DEFAULT 0, last_ping DOUBLE PRECISION DEFAULT 0,
                        banned_until DOUBLE PRECISION DEFAULT 0, created_at TIMESTAMP DEFAULT NOW(),
                        last_block BIGINT DEFAULT 0, consecutive_misses INTEGER DEFAULT 0, total_uptime INTEGER DEFAULT 0,
                        ip_address TEXT DEFAULT '', node_id TEXT DEFAULT '', version TEXT DEFAULT '',
                        active BOOLEAN DEFAULT TRUE, confirmed_balance BIGINT DEFAULT 0, password_hash TEXT DEFAULT '',
                        private_key_encrypted TEXT DEFAULT '', gas_collected BIGINT DEFAULT 0, maze_wins INTEGER DEFAULT 0,
                        block_signing_pub TEXT
                    );
                    CREATE INDEX IF NOT EXISTS idx_miners_wallet ON miners(wallet);
                    CREATE INDEX IF NOT EXISTS idx_miners_active ON miners(active);

                    CREATE TABLE IF NOT EXISTS nodes (
                        node_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, ip TEXT DEFAULT '', port INTEGER DEFAULT 0,
                        last_seen TIMESTAMP DEFAULT NOW(), height BIGINT DEFAULT 0, active BOOLEAN DEFAULT TRUE,
                        rewards_earned BIGINT DEFAULT 0, version TEXT DEFAULT '', mining_enabled BOOLEAN DEFAULT TRUE,
                        staking_enabled BOOLEAN DEFAULT TRUE, last_sync TIMESTAMP DEFAULT NOW(),
                        is_multisig_signer BOOLEAN DEFAULT FALSE, public_key TEXT DEFAULT ''
                    );
                    CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(active);

                    CREATE TABLE IF NOT EXISTS blocks (
                        id BIGINT PRIMARY KEY, ts DOUBLE PRECISION NOT NULL, phash TEXT NOT NULL,
                        miners TEXT[] DEFAULT '{}', hash TEXT NOT NULL, reward BIGINT DEFAULT 0,
                        tx_count INTEGER DEFAULT 0, merkle_root TEXT DEFAULT '', nonce BIGINT DEFAULT 0,
                        difficulty INTEGER DEFAULT 1, version TEXT DEFAULT '', challenge TEXT DEFAULT '',
                        coverage REAL DEFAULT 1, total_tx_value BIGINT DEFAULT 0, total_fees BIGINT DEFAULT 0,
                        tx_hashes TEXT[] DEFAULT '{}', finalized BOOLEAN DEFAULT FALSE
                    );
                    ALTER TABLE blocks ADD COLUMN IF NOT EXISTS proof JSONB DEFAULT '{}';
                    CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(id);
                    CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);
                    CREATE INDEX IF NOT EXISTS idx_blocks_finalized ON blocks(finalized);

                    CREATE TABLE IF NOT EXISTS transactions (
                        tx_hash TEXT PRIMARY KEY, from_wallet TEXT NOT NULL, to_wallet TEXT NOT NULL,
                        amount BIGINT NOT NULL, fee BIGINT DEFAULT 0, timestamp DOUBLE PRECISION NOT NULL,
                        block_id BIGINT DEFAULT -1, status TEXT DEFAULT 'pending', tx_type TEXT DEFAULT 'send',
                        signature TEXT DEFAULT '', nonce BIGINT DEFAULT 0, confirmations INTEGER DEFAULT 0,
                        data JSONB DEFAULT '{}', confirmed BOOLEAN DEFAULT FALSE, token_address TEXT DEFAULT '',
                        contract_address TEXT DEFAULT '', function TEXT DEFAULT '', params JSONB DEFAULT '[]'
                    );
                    CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_id);
                    CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_wallet);
                    CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_wallet);
                    CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);

                    CREATE TABLE IF NOT EXISTS balances (wallet TEXT PRIMARY KEY, bal BIGINT DEFAULT 0, updated_at TIMESTAMP DEFAULT NOW());
                    CREATE TABLE IF NOT EXISTS tokens (address TEXT PRIMARY KEY, name TEXT NOT NULL, symbol TEXT NOT NULL, owner TEXT NOT NULL, total_supply BIGINT NOT NULL, decimals INTEGER DEFAULT 18, created_at TIMESTAMP DEFAULT NOW(), fee_paid BIGINT NOT NULL, mintable BOOLEAN DEFAULT TRUE, burnable BOOLEAN DEFAULT FALSE, mining_type TEXT DEFAULT '', mining_reward BIGINT DEFAULT 0, mining_interval INTEGER DEFAULT 1, mining_difficulty INTEGER DEFAULT 1, stake_threshold BIGINT DEFAULT 0, last_mined_block BIGINT DEFAULT 0, total_mined BIGINT DEFAULT 0, max_mineable_supply BIGINT DEFAULT 1000000000000000);
                    CREATE INDEX IF NOT EXISTS idx_tokens_owner ON tokens(owner);
                    CREATE INDEX IF NOT EXISTS idx_tokens_symbol ON tokens(symbol);

                    CREATE TABLE IF NOT EXISTS token_balances (token_address TEXT NOT NULL, wallet TEXT NOT NULL, balance BIGINT DEFAULT 0, PRIMARY KEY (token_address, wallet));
                    CREATE INDEX IF NOT EXISTS idx_token_balances_wallet ON token_balances(wallet);

                    CREATE TABLE IF NOT EXISTS contracts (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi JSONB NOT NULL, created_at TIMESTAMP DEFAULT NOW(), tx_hash TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS contract_state (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));
                    CREATE INDEX IF NOT EXISTS idx_contract_state_key ON contract_state(key);

                    CREATE TABLE IF NOT EXISTS contract_events (id SERIAL PRIMARY KEY, contract_address TEXT NOT NULL, event_name TEXT NOT NULL, data JSONB NOT NULL, block_id BIGINT NOT NULL, tx_hash TEXT NOT NULL, timestamp TIMESTAMP DEFAULT NOW());
                    CREATE INDEX IF NOT EXISTS idx_contract_events_address ON contract_events(contract_address);
                    CREATE INDEX IF NOT EXISTS idx_contract_events_block ON contract_events(block_id);

                    CREATE TABLE IF NOT EXISTS slashing_events (id SERIAL PRIMARY KEY, miner_id TEXT NOT NULL, amount BIGINT DEFAULT 0, reason TEXT DEFAULT '', timestamp TIMESTAMP DEFAULT NOW(), block_id BIGINT DEFAULT -1);
                    CREATE INDEX IF NOT EXISTS idx_slashing_miner ON slashing_events(miner_id);

                    CREATE TABLE IF NOT EXISTS signed_blocks (
                        miner_id TEXT NOT NULL,
                        block_id BIGINT NOT NULL,
                        block_hash TEXT NOT NULL,
                        signed_at TIMESTAMP DEFAULT NOW(),
                        PRIMARY KEY (miner_id, block_id)
                    );

                    CREATE TABLE IF NOT EXISTS lottery_commits (
                        height BIGINT NOT NULL,
                        miner_id TEXT NOT NULL,
                        "commit" TEXT NOT NULL,
                        PRIMARY KEY (height, miner_id)
                    );

                    CREATE TABLE IF NOT EXISTS lottery_reveals (
                        height BIGINT NOT NULL,
                        miner_id TEXT NOT NULL,
                        secret TEXT NOT NULL,
                        PRIMARY KEY (height, miner_id)
                    );

                    CREATE TABLE IF NOT EXISTS validator_history (id SERIAL PRIMARY KEY, miner_id TEXT NOT NULL, block_id BIGINT NOT NULL, timestamp TIMESTAMP DEFAULT NOW(), reward BIGINT DEFAULT 0);
                    CREATE INDEX IF NOT EXISTS idx_validator_miner ON validator_history(miner_id);
                    CREATE INDEX IF NOT EXISTS idx_validator_block ON validator_history(block_id);

                    CREATE TABLE IF NOT EXISTS network_state (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE IF NOT EXISTS memory_challenges (miner_id TEXT PRIMARY KEY, seed TEXT NOT NULL, commitment TEXT NOT NULL, memory_size INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW(), last_verified TIMESTAMP DEFAULT NOW(), passes INTEGER DEFAULT 0, failures INTEGER DEFAULT 0);

                    CREATE TABLE IF NOT EXISTS token_stakes (token_address TEXT NOT NULL, wallet TEXT NOT NULL, stake_amount BIGINT DEFAULT 0, staked_at TIMESTAMP DEFAULT NOW(), last_reward_block BIGINT DEFAULT 0, PRIMARY KEY (token_address, wallet));
                    CREATE INDEX IF NOT EXISTS idx_token_stakes_token ON token_stakes(token_address);

                    CREATE TABLE IF NOT EXISTS multisig_wallets (address TEXT PRIMARY KEY, public_keys JSONB NOT NULL, threshold INTEGER NOT NULL, created_at TIMESTAMP DEFAULT NOW());
                    CREATE TABLE IF NOT EXISTS signing_challenges (wallet TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires TIMESTAMP NOT NULL);
                    CREATE TABLE IF NOT EXISTS mempool_persist (tx_hash TEXT PRIMARY KEY, tx_json TEXT NOT NULL, stored_at DOUBLE PRECISION NOT NULL);

                    CREATE TABLE IF NOT EXISTS transaction_receipts (tx_hash TEXT PRIMARY KEY, block_id BIGINT NOT NULL, status INTEGER DEFAULT 1, gas_used BIGINT DEFAULT 0, logs JSONB DEFAULT '[]', contract_address TEXT DEFAULT '', result TEXT DEFAULT '');
                    CREATE INDEX IF NOT EXISTS idx_receipts_block ON transaction_receipts(block_id);

                    CREATE TABLE IF NOT EXISTS finality_checkpoints (block_id BIGINT PRIMARY KEY, hash TEXT NOT NULL, finalized_at TIMESTAMP DEFAULT NOW(), epoch INTEGER NOT NULL);
                    CREATE INDEX IF NOT EXISTS idx_finality_epoch ON finality_checkpoints(epoch);

                    CREATE TABLE IF NOT EXISTS contract_v2 (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi JSONB NOT NULL, created_at TIMESTAMP DEFAULT NOW(), tx_hash TEXT NOT NULL, storage_root TEXT DEFAULT '', code_hash TEXT NOT NULL);
                    CREATE INDEX IF NOT EXISTS idx_contract_v2_owner ON contract_v2(owner);

                    CREATE TABLE IF NOT EXISTS contract_storage_v2 (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));
                    CREATE INDEX IF NOT EXISTS idx_contract_storage_v2_address ON contract_storage_v2(contract_address);
                    -- B6 (MCX73): write-ahead journal for VM-flush state mutations (storage, balances, token balances) so a later reorg restores pre-block values.
                    CREATE TABLE IF NOT EXISTS contract_exec_journal (seq BIGSERIAL, block_id BIGINT NOT NULL, namespace TEXT NOT NULL, addr TEXT NOT NULL, key TEXT NOT NULL, old_value TEXT, new_value TEXT);
                    ALTER TABLE contract_exec_journal ADD COLUMN IF NOT EXISTS seq BIGSERIAL;
                    CREATE INDEX IF NOT EXISTS idx_contract_exec_journal_block ON contract_exec_journal(block_id);

                    CREATE TABLE IF NOT EXISTS htlc_contracts (id TEXT PRIMARY KEY, sender TEXT NOT NULL, receiver TEXT NOT NULL, hashlock TEXT NOT NULL, timelock BIGINT NOT NULL, amount BIGINT NOT NULL, token_address TEXT DEFAULT '', status TEXT DEFAULT 'open', created_at TIMESTAMP DEFAULT NOW(), claimed_at TIMESTAMP, refunded_at TIMESTAMP);
                    CREATE INDEX IF NOT EXISTS idx_htlc_sender ON htlc_contracts(sender);
                    CREATE INDEX IF NOT EXISTS idx_htlc_receiver ON htlc_contracts(receiver);
                    CREATE INDEX IF NOT EXISTS idx_htlc_status ON htlc_contracts(status);
                    CREATE TABLE IF NOT EXISTS shards (
                        shard_id TEXT PRIMARY KEY,
                        kind INTEGER NOT NULL,
                        data_hash TEXT NOT NULL,
                        tenant TEXT NOT NULL,
                        total BIGINT NOT NULL,
                        idx BIGINT NOT NULL,
                        parent_id TEXT,
                        miner_id TEXT,
                        x BIGINT,
                        y BIGINT,
                        z BIGINT,
                        occupied_since_block BIGINT,
                        status TEXT NOT NULL DEFAULT 'unplaced',
                        created_at_block BIGINT NOT NULL,
                        updated_at_block BIGINT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_shards_tenant ON shards(tenant);
                    CREATE INDEX IF NOT EXISTS idx_shards_miner ON shards(miner_id);
                    CREATE INDEX IF NOT EXISTS idx_shards_status ON shards(status);
                    CREATE TABLE IF NOT EXISTS state_trie_nodes (
                        node_hash TEXT PRIMARY KEY, node_data TEXT NOT NULL, ref_count INTEGER DEFAULT 1
                    );
                    CREATE TABLE IF NOT EXISTS block_state_roots (
                        block_id BIGINT PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS state_snapshots (
                        block_id BIGINT PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT DEFAULT '', snapshot_data TEXT NOT NULL, created_at BIGINT NOT NULL
                    );
                    CREATE TABLE IF NOT EXISTS pending_maze_updates (
                        block_id BIGINT NOT NULL, minerid TEXT NOT NULL, update_json TEXT NOT NULL,
                        PRIMARY KEY (block_id, minerid)
                    );
                    CREATE TABLE IF NOT EXISTS minermazes (
                        maze_id TEXT PRIMARY KEY,
                        minerid TEXT NOT NULL,
                        size INTEGER NOT NULL,
                        walldensityppm INTEGER NOT NULL,
                        seed TEXT NOT NULL,
                        posx INTEGER NOT NULL,
                        posy INTEGER NOT NULL,
                        posz INTEGER NOT NULL,
                        goalx INTEGER NOT NULL,
                        goaly INTEGER NOT NULL,
                        goalz INTEGER NOT NULL,
                        movenonce BIGINT NOT NULL DEFAULT 0,
                        consecutivewallhits INTEGER NOT NULL DEFAULT 0,
                        turbulenceppm INTEGER NOT NULL DEFAULT 0,
                        growthcount BIGINT NOT NULL DEFAULT 0,
                        knowledge INTEGER NOT NULL DEFAULT 0,
                        lastgoalheight BIGINT NOT NULL DEFAULT 0,
                        lastactiveheight BIGINT NOT NULL DEFAULT 0,
                        mazeroot TEXT NOT NULL,
                        invitedguest TEXT,
                        guestlock BOOLEAN NOT NULL DEFAULT FALSE,
                        lastknowledgeheight BIGINT NOT NULL DEFAULT 0,
                        createdat BIGINT NOT NULL,
                        updatedat BIGINT NOT NULL,
                        ghostx INTEGER,
                        ghosty INTEGER,
                        ghostz INTEGER
                    );
                    CREATE INDEX IF NOT EXISTS idx_minermazes_minerid ON minermazes(minerid);
                    CREATE TABLE IF NOT EXISTS maze_attestations (
                        maze_id TEXT PRIMARY KEY,
                        last_size BIGINT NOT NULL,
                        last_block BIGINT NOT NULL,
                        last_block_hash TEXT NOT NULL,
                        pubkey TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_maze_attestations_last_block ON maze_attestations(last_block);
                    CREATE TABLE IF NOT EXISTS automations (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        owner TEXT NOT NULL,
                        trigger_type TEXT NOT NULL,
                        trigger_config JSONB NOT NULL,
                        action_type TEXT NOT NULL,
                        action_config JSONB NOT NULL,
                        enabled BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT NOW(),
                        last_run_at TIMESTAMP,
                        run_count INTEGER DEFAULT 0,
                        last_result TEXT DEFAULT '',
                        -- R6-automation-last-block-persist: firing height
                        last_block_run BIGINT DEFAULT 0
                    );
                    CREATE INDEX IF NOT EXISTS idx_automations_owner ON automations(owner);
                    -- AUTO-REPLAY-SEEN-1 (mainnet audit): durable replay
                    -- guard surviving restarts (memory set does not).
                    CREATE TABLE IF NOT EXISTS automation_replay_seen (
                        sig_hash TEXT PRIMARY KEY, seen_at DOUBLE PRECISION NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS schema_version (
                        version INTEGER PRIMARY KEY,
                        applied_at TIMESTAMP DEFAULT NOW()
                    );
                    CREATE TABLE IF NOT EXISTS peer_bans (
                        address TEXT PRIMARY KEY,
                        node_id TEXT,
                        reason TEXT NOT NULL DEFAULT '',
                        banned_at TIMESTAMP DEFAULT NOW(),
                        expires_at DOUBLE PRECISION NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_peer_bans_expires ON peer_bans(expires_at);
                    CREATE TABLE IF NOT EXISTS spatial_tokens (
                        address TEXT PRIMARY KEY,
                        creator TEXT NOT NULL,
                        name TEXT NOT NULL,
                        symbol TEXT NOT NULL,
                        supply BIGINT NOT NULL,
                        decimals INTEGER NOT NULL,
                        deploy_block BIGINT NOT NULL,
                        preferred_x INTEGER NOT NULL,
                        preferred_y INTEGER NOT NULL,
                        preferred_z INTEGER NOT NULL,
                        bundle_count INTEGER NOT NULL,
                        deploy_nonce BIGINT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_spatial_tokens_creator ON spatial_tokens(creator);
                    CREATE TABLE IF NOT EXISTS spatial_token_balances (
                        token_address TEXT NOT NULL,
                        wallet TEXT NOT NULL,
                        balance BIGINT NOT NULL,
                        PRIMARY KEY (token_address, wallet)
                    );
                    CREATE INDEX IF NOT EXISTS idx_spatial_token_balances_wallet ON spatial_token_balances(wallet);
                    CREATE TABLE IF NOT EXISTS spatial_pool_payouts (
                        block_id BIGINT NOT NULL,
                        wallet TEXT NOT NULL,
                        amount BIGINT NOT NULL,
                        PRIMARY KEY (block_id, wallet)
                    );
                    CREATE TABLE IF NOT EXISTS spatial_fee_payouts (
                        block_id BIGINT NOT NULL,
                        wallet TEXT NOT NULL,
                        amount BIGINT NOT NULL,
                        PRIMARY KEY (block_id, wallet)
                    );
                """)
                await conn.execute(
                    # R4-sqlite-parity: schema_version is created in the DDL
                    # block above before this insert runs (pinned by test).
                    "INSERT INTO schema_version (version) VALUES ($1) ON CONFLICT (version) DO NOTHING",
                    SCHEMA_VERSION)
        else:
            self.cursor.executescript("""
                CREATE TABLE IF NOT EXISTS miners (miner_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, pub TEXT NOT NULL, rewards INTEGER DEFAULT 0, blocks INTEGER DEFAULT 0, slashes INTEGER DEFAULT 0, uptime INTEGER DEFAULT 0, today_uptime INTEGER DEFAULT 0, type TEXT DEFAULT 'web', liquidity INTEGER DEFAULT 0, fees INTEGER DEFAULT 0, last_ping REAL DEFAULT 0, banned_until REAL DEFAULT 0, created_at REAL DEFAULT 0, last_block INTEGER DEFAULT 0, consecutive_misses INTEGER DEFAULT 0, total_uptime INTEGER DEFAULT 0, ip_address TEXT DEFAULT '', node_id TEXT DEFAULT '', version TEXT DEFAULT '', active INTEGER DEFAULT 1, confirmed_balance INTEGER DEFAULT 0, password_hash TEXT DEFAULT '', private_key_encrypted TEXT DEFAULT '', gas_collected INTEGER DEFAULT 0, maze_wins INTEGER DEFAULT 0, block_signing_pub TEXT);
                CREATE INDEX IF NOT EXISTS idx_miners_wallet ON miners(wallet);
                CREATE INDEX IF NOT EXISTS idx_miners_active ON miners(active);
                CREATE TABLE IF NOT EXISTS nodes (node_id TEXT PRIMARY KEY, wallet TEXT NOT NULL, ip TEXT DEFAULT '', port INTEGER DEFAULT 0, last_seen REAL DEFAULT 0, height INTEGER DEFAULT 0, active INTEGER DEFAULT 1, rewards_earned INTEGER DEFAULT 0, version TEXT DEFAULT '', mining_enabled INTEGER DEFAULT 1, staking_enabled INTEGER DEFAULT 1, last_sync REAL DEFAULT 0, is_multisig_signer INTEGER DEFAULT 0, public_key TEXT DEFAULT '');
                CREATE INDEX IF NOT EXISTS idx_nodes_active ON nodes(active);
                CREATE TABLE IF NOT EXISTS blocks (id INTEGER PRIMARY KEY, ts REAL NOT NULL, phash TEXT NOT NULL, miners TEXT DEFAULT '', hash TEXT NOT NULL, reward INTEGER DEFAULT 0, tx_count INTEGER DEFAULT 0, merkle_root TEXT DEFAULT '', nonce INTEGER DEFAULT 0, difficulty INTEGER DEFAULT 1, version TEXT DEFAULT '', challenge TEXT DEFAULT '', coverage REAL DEFAULT 1, total_tx_value INTEGER DEFAULT 0, total_fees INTEGER DEFAULT 0, tx_hashes TEXT DEFAULT '', finalized INTEGER DEFAULT 0);
                CREATE INDEX IF NOT EXISTS idx_blocks_height ON blocks(id);
                CREATE INDEX IF NOT EXISTS idx_blocks_hash ON blocks(hash);
                CREATE INDEX IF NOT EXISTS idx_blocks_finalized ON blocks(finalized);
                CREATE TABLE IF NOT EXISTS transactions (tx_hash TEXT PRIMARY KEY, from_wallet TEXT NOT NULL, to_wallet TEXT NOT NULL, amount INTEGER NOT NULL, fee INTEGER DEFAULT 0, timestamp REAL NOT NULL, block_id INTEGER DEFAULT -1, status TEXT DEFAULT 'pending', tx_type TEXT DEFAULT 'send', signature TEXT DEFAULT '', nonce INTEGER DEFAULT 0, confirmations INTEGER DEFAULT 0, data TEXT DEFAULT '{}', confirmed INTEGER DEFAULT 0, token_address TEXT DEFAULT '', contract_address TEXT DEFAULT '', function TEXT DEFAULT '', params TEXT DEFAULT '[]');
                CREATE INDEX IF NOT EXISTS idx_transactions_block ON transactions(block_id);
                CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions(from_wallet);
                CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions(to_wallet);
                CREATE INDEX IF NOT EXISTS idx_transactions_status ON transactions(status);
                CREATE TABLE IF NOT EXISTS balances (wallet TEXT PRIMARY KEY, bal INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS tokens (address TEXT PRIMARY KEY, name TEXT NOT NULL, symbol TEXT NOT NULL, owner TEXT NOT NULL, total_supply INTEGER NOT NULL, decimals INTEGER DEFAULT 18, created_at REAL NOT NULL, fee_paid INTEGER NOT NULL, mintable INTEGER DEFAULT 1, burnable INTEGER DEFAULT 0, mining_type TEXT DEFAULT '', mining_reward INTEGER DEFAULT 0, mining_interval INTEGER DEFAULT 1, mining_difficulty INTEGER DEFAULT 1, stake_threshold INTEGER DEFAULT 0, last_mined_block INTEGER DEFAULT 0, total_mined INTEGER DEFAULT 0, max_mineable_supply INTEGER DEFAULT 0);
                CREATE INDEX IF NOT EXISTS idx_tokens_owner ON tokens(owner);
                CREATE INDEX IF NOT EXISTS idx_tokens_symbol ON tokens(symbol);
                CREATE TABLE IF NOT EXISTS token_balances (token_address TEXT NOT NULL, wallet TEXT NOT NULL, balance INTEGER NOT NULL, PRIMARY KEY (token_address, wallet));
                CREATE INDEX IF NOT EXISTS idx_token_balances_wallet ON token_balances(wallet);
                CREATE TABLE IF NOT EXISTS contracts (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi TEXT NOT NULL, created_at REAL NOT NULL, tx_hash TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS contract_state (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));
                CREATE INDEX IF NOT EXISTS idx_contract_state_key ON contract_state(key);
                CREATE TABLE IF NOT EXISTS contract_events (id INTEGER PRIMARY KEY AUTOINCREMENT, contract_address TEXT NOT NULL, event_name TEXT NOT NULL, data TEXT NOT NULL, block_id INTEGER NOT NULL, tx_hash TEXT NOT NULL, timestamp REAL NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_contract_events_address ON contract_events(contract_address);
                CREATE INDEX IF NOT EXISTS idx_contract_events_block ON contract_events(block_id);
                CREATE TABLE IF NOT EXISTS slashing_events (id INTEGER PRIMARY KEY AUTOINCREMENT, miner_id TEXT NOT NULL, amount INTEGER DEFAULT 0, reason TEXT DEFAULT '', timestamp REAL NOT NULL, block_id INTEGER DEFAULT -1);
                CREATE INDEX IF NOT EXISTS idx_slashing_miner ON slashing_events(miner_id);

                CREATE TABLE IF NOT EXISTS signed_blocks (
                    miner_id TEXT NOT NULL,
                    block_id INTEGER NOT NULL,
                    block_hash TEXT NOT NULL,
                    signed_at REAL NOT NULL,
                    PRIMARY KEY (miner_id, block_id)
                );

                CREATE TABLE IF NOT EXISTS lottery_commits (
                    height INTEGER NOT NULL,
                    miner_id TEXT NOT NULL,
                    "commit" TEXT NOT NULL,
                    PRIMARY KEY (height, miner_id)
                );

                CREATE TABLE IF NOT EXISTS lottery_reveals (
                    height INTEGER NOT NULL,
                    miner_id TEXT NOT NULL,
                    secret TEXT NOT NULL,
                    PRIMARY KEY (height, miner_id)
                );

                CREATE TABLE IF NOT EXISTS validator_history (id INTEGER PRIMARY KEY AUTOINCREMENT, miner_id TEXT NOT NULL, block_id INTEGER NOT NULL, timestamp REAL NOT NULL, reward INTEGER DEFAULT 0);
                CREATE INDEX IF NOT EXISTS idx_validator_miner ON validator_history(miner_id);
                CREATE INDEX IF NOT EXISTS idx_validator_block ON validator_history(block_id);
                CREATE TABLE IF NOT EXISTS network_state (key TEXT PRIMARY KEY, value TEXT);
                CREATE TABLE IF NOT EXISTS memory_challenges (miner_id TEXT PRIMARY KEY, seed TEXT NOT NULL, commitment TEXT NOT NULL, memory_size INTEGER NOT NULL, created_at REAL NOT NULL, last_verified REAL DEFAULT 0, passes INTEGER DEFAULT 0, failures INTEGER DEFAULT 0);
                CREATE TABLE IF NOT EXISTS token_stakes (token_address TEXT NOT NULL, wallet TEXT NOT NULL, stake_amount INTEGER NOT NULL, staked_at REAL NOT NULL, last_reward_block INTEGER DEFAULT 0, PRIMARY KEY (token_address, wallet));
                CREATE INDEX IF NOT EXISTS idx_token_stakes_token ON token_stakes(token_address);
                CREATE TABLE IF NOT EXISTS multisig_wallets (address TEXT PRIMARY KEY, public_keys TEXT NOT NULL, threshold INTEGER NOT NULL, created_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS signing_challenges (wallet TEXT PRIMARY KEY, nonce TEXT NOT NULL, expires REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS mempool_persist (tx_hash TEXT PRIMARY KEY, tx_json TEXT NOT NULL, stored_at REAL NOT NULL);
                CREATE TABLE IF NOT EXISTS transaction_receipts (tx_hash TEXT PRIMARY KEY, block_id INTEGER NOT NULL, status INTEGER DEFAULT 1, gas_used INTEGER DEFAULT 0, logs TEXT DEFAULT '[]', contract_address TEXT DEFAULT '', result TEXT DEFAULT '');
                CREATE INDEX IF NOT EXISTS idx_receipts_block ON transaction_receipts(block_id);
                CREATE TABLE IF NOT EXISTS finality_checkpoints (block_id INTEGER PRIMARY KEY, hash TEXT NOT NULL, finalized_at REAL NOT NULL, epoch INTEGER NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_finality_epoch ON finality_checkpoints(epoch);
                CREATE TABLE IF NOT EXISTS contract_v2 (address TEXT PRIMARY KEY, owner TEXT NOT NULL, bytecode TEXT NOT NULL, abi TEXT NOT NULL, created_at REAL NOT NULL, tx_hash TEXT NOT NULL, storage_root TEXT DEFAULT '', code_hash TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS idx_contract_v2_owner ON contract_v2(owner);
                CREATE TABLE IF NOT EXISTS contract_storage_v2 (contract_address TEXT NOT NULL, key TEXT NOT NULL, value TEXT NOT NULL, PRIMARY KEY (contract_address, key));
                CREATE INDEX IF NOT EXISTS idx_contract_storage_v2_address ON contract_storage_v2(contract_address);
                -- B6 (MCX73): write-ahead journal for VM-flush state mutations (storage, balances, token balances) so a later reorg restores pre-block values.
                CREATE TABLE IF NOT EXISTS contract_exec_journal (block_id INTEGER NOT NULL, namespace TEXT NOT NULL, addr TEXT NOT NULL, key TEXT NOT NULL, old_value TEXT, new_value TEXT);
                CREATE INDEX IF NOT EXISTS idx_contract_exec_journal_block ON contract_exec_journal(block_id);
                CREATE TABLE IF NOT EXISTS htlc_contracts (id TEXT PRIMARY KEY, sender TEXT NOT NULL, receiver TEXT NOT NULL, hashlock TEXT NOT NULL, timelock INTEGER NOT NULL, amount INTEGER NOT NULL, token_address TEXT DEFAULT '', status TEXT DEFAULT 'open', created_at REAL NOT NULL, claimed_at REAL, refunded_at REAL);
                CREATE INDEX IF NOT EXISTS idx_htlc_sender ON htlc_contracts(sender);
                CREATE INDEX IF NOT EXISTS idx_htlc_receiver ON htlc_contracts(receiver);
                CREATE INDEX IF NOT EXISTS idx_htlc_status ON htlc_contracts(status);
                CREATE TABLE IF NOT EXISTS state_trie_nodes (node_hash TEXT PRIMARY KEY, node_data TEXT NOT NULL, ref_count INTEGER DEFAULT 1);
                CREATE TABLE IF NOT EXISTS block_state_roots (block_id INTEGER PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS state_snapshots (block_id INTEGER PRIMARY KEY, state_root TEXT NOT NULL, receipt_root TEXT DEFAULT '', snapshot_data TEXT NOT NULL, created_at INTEGER NOT NULL);
                CREATE TABLE IF NOT EXISTS pending_maze_updates (
                    block_id INTEGER NOT NULL,
                    minerid TEXT NOT NULL,
                    update_json TEXT NOT NULL,
                    PRIMARY KEY (block_id, minerid)
                );
                CREATE TABLE IF NOT EXISTS minermazes (
                    maze_id TEXT PRIMARY KEY,
                    minerid TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    walldensityppm INTEGER NOT NULL,
                    seed TEXT NOT NULL,
                    posx INTEGER NOT NULL,
                    posy INTEGER NOT NULL,
                    posz INTEGER NOT NULL,
                    goalx INTEGER NOT NULL,
                    goaly INTEGER NOT NULL,
                    goalz INTEGER NOT NULL,
                    movenonce BIGINT NOT NULL DEFAULT 0,
                    consecutivewallhits INTEGER NOT NULL DEFAULT 0,
                    turbulenceppm INTEGER NOT NULL DEFAULT 0,
                    growthcount BIGINT NOT NULL DEFAULT 0,
                    knowledge INTEGER NOT NULL DEFAULT 0,
                    lastgoalheight BIGINT NOT NULL DEFAULT 0,
                    lastactiveheight BIGINT NOT NULL DEFAULT 0,
                    mazeroot TEXT NOT NULL,
                    invitedguest TEXT,
                    guestlock INTEGER NOT NULL DEFAULT 0,
                    lastknowledgeheight BIGINT NOT NULL DEFAULT 0,
                    createdat REAL NOT NULL,
                    updatedat REAL NOT NULL,
                    ghostx INTEGER,
                    ghosty INTEGER,
                    ghostz INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_minermazes_minerid ON minermazes(minerid);
                CREATE TABLE IF NOT EXISTS maze_attestations (
                    maze_id TEXT PRIMARY KEY,
                    last_size INTEGER NOT NULL,
                    last_block INTEGER NOT NULL,
                    last_block_hash TEXT NOT NULL,
                    pubkey TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_maze_attestations_last_block ON maze_attestations(last_block);
                CREATE TABLE IF NOT EXISTS automations (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    trigger_type TEXT NOT NULL,
                    trigger_config TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    action_config TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    created_at REAL NOT NULL,
                    last_run_at REAL,
                    run_count INTEGER DEFAULT 0,
                    last_result TEXT DEFAULT '',
                    -- R6-automation-last-block-persist: firing height
                    last_block_run INTEGER DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_automations_owner ON automations(owner);
                -- AUTO-REPLAY-SEEN-1 (mainnet audit): durable replay
                -- guard surviving restarts (memory set does not).
                CREATE TABLE IF NOT EXISTS automation_replay_seen (
                    sig_hash TEXT PRIMARY KEY, seen_at REAL NOT NULL
                );
                CREATE TABLE IF NOT EXISTS peer_bans (
                    address TEXT PRIMARY KEY,
                    node_id TEXT,
                    reason TEXT NOT NULL DEFAULT '',
                    banned_at REAL NOT NULL,
                    expires_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_peer_bans_expires ON peer_bans(expires_at);
                CREATE TABLE IF NOT EXISTS spatial_tokens (
                    address TEXT PRIMARY KEY,
                    creator TEXT NOT NULL,
                    name TEXT NOT NULL,
                    symbol TEXT NOT NULL,
                    supply INTEGER NOT NULL,
                    decimals INTEGER NOT NULL,
                    deploy_block INTEGER NOT NULL,
                    preferred_x INTEGER NOT NULL,
                    preferred_y INTEGER NOT NULL,
                    preferred_z INTEGER NOT NULL,
                    bundle_count INTEGER NOT NULL,
                    deploy_nonce INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_spatial_tokens_creator ON spatial_tokens(creator);
                CREATE TABLE IF NOT EXISTS spatial_token_balances (
                    token_address TEXT NOT NULL,
                    wallet TEXT NOT NULL,
                    balance INTEGER NOT NULL,
                    PRIMARY KEY (token_address, wallet)
                );
                CREATE INDEX IF NOT EXISTS idx_spatial_token_balances_wallet ON spatial_token_balances(wallet);
                CREATE TABLE IF NOT EXISTS spatial_pool_payouts (
                    block_id INTEGER NOT NULL,
                    wallet TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    PRIMARY KEY (block_id, wallet)
                );
                CREATE TABLE IF NOT EXISTS spatial_fee_payouts (
                    block_id INTEGER NOT NULL,
                    wallet TEXT NOT NULL,
                    amount INTEGER NOT NULL,
                    PRIMARY KEY (block_id, wallet)
                );
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY,
                    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            self.cursor.execute("PRAGMA table_info(blocks)")
            columns = [row[1] for row in self.cursor.fetchall()]
            if "proof" not in columns:
                self.cursor.execute("ALTER TABLE blocks ADD COLUMN proof TEXT DEFAULT '{}'")

            self.cursor.execute("PRAGMA table_info(minermazes)")
            mcols = [row[1] for row in self.cursor.fetchall()]
            if "maze_id" not in mcols:
                self.cursor.execute("ALTER TABLE minermazes ADD COLUMN maze_id TEXT")
                self.cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_minermazes_maze_id ON minermazes(maze_id)")
            if "knowledge" not in mcols:
                self.cursor.execute("ALTER TABLE minermazes ADD COLUMN knowledge INTEGER NOT NULL DEFAULT 0")
            if "lastknowledgeheight" not in mcols:
                self.cursor.execute("ALTER TABLE minermazes ADD COLUMN lastknowledgeheight BIGINT NOT NULL DEFAULT 0")
            if "ghostx" not in mcols:
                self.cursor.execute("ALTER TABLE minermazes ADD COLUMN ghostx INTEGER")
            if "ghosty" not in mcols:
                self.cursor.execute("ALTER TABLE minermazes ADD COLUMN ghosty INTEGER")
            if "ghostz" not in mcols:
                self.cursor.execute("ALTER TABLE minermazes ADD COLUMN ghostz INTEGER")

            # Migrate schema: maze_id as PRIMARY KEY (multiple mazes per miner)
            self.cursor.execute("PRAGMA table_info(minermazes)")
            pk_cols = [row[1] for row in self.cursor.fetchall() if row[5] == 1]
            if pk_cols and pk_cols[0] != "maze_id":
                logger.info("[DB] Migrating minermazes: maze_id → PRIMARY KEY")
                self.cursor.execute("""
                    CREATE TABLE IF NOT EXISTS minermazes_new (
                        maze_id TEXT PRIMARY KEY, minerid TEXT NOT NULL,
                        size INTEGER NOT NULL, walldensityppm INTEGER NOT NULL,
                        seed TEXT NOT NULL, posx INTEGER NOT NULL, posy INTEGER NOT NULL, posz INTEGER NOT NULL,
                        goalx INTEGER NOT NULL, goaly INTEGER NOT NULL, goalz INTEGER NOT NULL,
                        movenonce BIGINT NOT NULL DEFAULT 0, consecutivewallhits INTEGER NOT NULL DEFAULT 0,
                        turbulenceppm INTEGER NOT NULL DEFAULT 0, growthcount BIGINT NOT NULL DEFAULT 0,
                        knowledge INTEGER NOT NULL DEFAULT 0, lastgoalheight BIGINT NOT NULL DEFAULT 0,
                        lastactiveheight BIGINT NOT NULL DEFAULT 0, mazeroot TEXT NOT NULL,
                        invitedguest TEXT, guestlock INTEGER NOT NULL DEFAULT 0,
                        lastknowledgeheight BIGINT NOT NULL DEFAULT 0,
                        createdat REAL NOT NULL, updatedat REAL NOT NULL,
                        ghostx INTEGER, ghosty INTEGER, ghostz INTEGER
                    )
                """)
                self.cursor.execute("""
                    INSERT OR IGNORE INTO minermazes_new
                    SELECT COALESCE(maze_id, minerid), minerid, size, walldensityppm, seed,
                           posx, posy, posz, goalx, goaly, goalz,
                           movenonce, consecutivewallhits, turbulenceppm, growthcount,
                           knowledge, lastgoalheight, lastactiveheight, mazeroot,
                           invitedguest, guestlock, lastknowledgeheight, createdat, updatedat,
                           ghostx, ghosty, ghostz
                    FROM minermazes
                """)
                self.cursor.execute("DROP TABLE IF EXISTS minermazes")
                self.cursor.execute("ALTER TABLE minermazes_new RENAME TO minermazes")
                self.cursor.execute("CREATE INDEX IF NOT EXISTS idx_minermazes_minerid ON minermazes(minerid)")
                logger.info("[DB] Migration complete: maze_id is now PRIMARY KEY")

            self.cursor.execute("PRAGMA table_info(miners)")
            mncols = [row[1] for row in self.cursor.fetchall()]
            if "block_signing_pub" not in mncols:
                self.cursor.execute("ALTER TABLE miners ADD COLUMN block_signing_pub TEXT")
            self.cursor.execute(
                # R4-sqlite-parity: schema_version is created by the
                # executescript above before this insert runs (both branches
                # create-then-insert; pinned by test_r4_schema).
                "INSERT OR IGNORE INTO schema_version (version, applied_at) VALUES (?, ?)",
                (SCHEMA_VERSION, time.time()))
            self.conn.commit()
        logger.info(f"[DB] Tables ready for {self.db_type}")

# ─── Repository Classes ──────────────────────────────────
class BlockRepo:
    def __init__(self, db): self.db = db
    def _unpack_block(self, row):
        if not row: return row
        if self.db.db_type == "sqlite":
            row['miners'] = row['miners'].split(',') if row['miners'] else []
            row['tx_hashes'] = json.loads(row['tx_hashes']) if row['tx_hashes'] else []
        proof = row.get('proof')
        if proof:
            if isinstance(proof, str):
                try: proof = json.loads(proof)
                except Exception: proof = {}
            for k,v in proof.items():
                if k in _BLOCK_PROOF_KEYS:
                    row[k] = v
            del row['proof']
        return row
    async def create(self, block):
        proof_fields = {k: block[k] for k in ("winner","producer_pub","signature","state_root","transactions","maze_attestation","reward_wallet","maze_updates","global_shrink_factor","slashes","spatial_fee_amount") if k in block}  # IDEA5-ATTEST, Spatial Tokens V2 (both sides of _unpack_block must match or fee never persists)
        proof_json = json.dumps(proof_fields)
        if self.db.db_type == "sqlite":
            query = "INSERT INTO blocks (id,ts,phash,miners,hash,reward,tx_count,merkle_root,nonce,difficulty,version,challenge,coverage,total_tx_value,total_fees,tx_hashes,finalized,proof) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            params = (block['id'], block['ts'], block['phash'], ','.join(str(m) for m in block.get('miners', [])), block['hash'], block['reward'], block['tx_count'], block['merkle_root'], 0, block['difficulty'], block['version'], block['challenge'], block['coverage'], block['total_tx_value'], block['total_fees'], json.dumps(block['tx_hashes']), block.get('finalized', False), proof_json)
        else:
            query = "INSERT INTO blocks (id,ts,phash,miners,hash,reward,tx_count,merkle_root,nonce,difficulty,version,challenge,coverage,total_tx_value,total_fees,tx_hashes,finalized,proof) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"
            params = (block['id'], block['ts'], block['phash'], block['miners'], block['hash'], block['reward'], block['tx_count'], block['merkle_root'], 0, block['difficulty'], block['version'], block['challenge'], block['coverage'], block['total_tx_value'], block['total_fees'], block['tx_hashes'], block.get('finalized', False), proof_json)
        await self.db.execute_dml(query, *params)
    async def get_by_id(self, block_id):
        query = "SELECT * FROM blocks WHERE id = ?" if self.db.db_type == "sqlite" else "SELECT * FROM blocks WHERE id = $1"
        return self._unpack_block(await self.db.fetchrow(query, block_id))
    async def get_latest(self):
        query = "SELECT * FROM blocks ORDER BY id DESC LIMIT 1"
        return self._unpack_block(await self.db.fetchrow(query))
    async def get_range(self, start, end, limit=100):
        query = "SELECT * FROM blocks WHERE id >= ? AND id <= ? ORDER BY id LIMIT ?" if self.db.db_type == "sqlite" else "SELECT * FROM blocks WHERE id >= $1 AND id <= $2 ORDER BY id LIMIT $3"
        return [self._unpack_block(r) for r in await self.db.fetch(query, start, end, limit)]
    async def mark_finalized(self, block_id):
        query = "UPDATE blocks SET finalized = 1 WHERE id = ?" if self.db.db_type == "sqlite" else "UPDATE blocks SET finalized = TRUE WHERE id = $1"
        await self.db.execute_dml(query, block_id)

class TransactionRepo:
    def __init__(self, db): self.db = db
    async def create(self, tx):
        # Spatial Tokens V2: transactions has no _spatial_fee_maze_cut
        # column, so a real reorg (SELECT * rows) must still see the maze
        # cut. Mirror the field into the existing data JSON at INSERT time
        # — without mutating the input dict (execute/seal/tests keep reading
        # the top-level field). Non-spatial txs (no maze cut) serialize
        # exactly as before. (V1 mirrored _spatial_pool_contrib here; that
        # field is gone — test chains reset on the V1->V2 consensus change.)
        _data = tx.get('data', {})
        # BUG 2 (MCX75): same mirror pattern for the token burn tax so the
        # reorg inverse can debit net_amount and restore supply/burned.
        # Only when > 0: other rows serialize exactly as before, and the
        # input dict is never mutated (copied above when needed).
        try:
            _burn = int(tx.get('_burn_tax', 0) or 0)
        except (TypeError, ValueError):
            _burn = 0
        if _burn > 0:
            _data = dict(_data) if isinstance(_data, dict) else {}
            _data['_burn_tax'] = _burn
        # Spatial Tokens V2: mirror the maze cut the same way (only when
        # nonzero, so fee=0 transfers serialize exactly as before).
        try:
            _mcut = int(tx.get('_spatial_fee_maze_cut', 0) or 0)
        except (TypeError, ValueError):
            _mcut = 0
        if _mcut:
            _data = dict(_data) if isinstance(_data, dict) else {}
            _data['_spatial_fee_maze_cut'] = _mcut
        # R5-sign-fail-rollback: mirror the top-level value-move marker the
        # same way (only when nonzero; the inverse reads it from re-fetched
        # rows, which carry no transient top-level fields). Non-dict data is
        # wrapped, not dropped (replay reads init code/calldata from it).
        try:
            _vmv = int(tx.get('_value_moved', 0) or 0)
        except (TypeError, ValueError):
            _vmv = 0
        if _vmv:
            if isinstance(_data, dict):
                _data = dict(_data)
            elif isinstance(_data, (bytes, bytearray)):
                _data = {'raw': bytes(_data).hex()}
            else:
                _data = {'raw': _data}
            _data['_value_moved'] = _vmv
        if self.db.db_type == "sqlite":
            query = "INSERT OR REPLACE INTO transactions (tx_hash,from_wallet,to_wallet,amount,fee,timestamp,block_id,status,tx_type,signature,nonce,confirmations,data,confirmed,token_address,contract_address,function,params) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            params = (tx['tx_hash'], tx['from_wallet'], tx['to_wallet'], tx['amount'], tx['fee'], tx['timestamp'], tx.get('block_id',-1), tx['status'], tx['tx_type'], tx.get('signature',''), tx.get('nonce',0), tx.get('confirmations',0), json.dumps(_data), tx.get('confirmed',False), tx.get('token_address',''), tx.get('contract_address',''), tx.get('function',''), json.dumps(tx.get('params',[])))
        else:
            query = "INSERT INTO transactions (tx_hash,from_wallet,to_wallet,amount,fee,timestamp,block_id,status,tx_type,signature,nonce,confirmations,data,confirmed,token_address,contract_address,function,params) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18) ON CONFLICT (tx_hash) DO UPDATE SET block_id=$7, status=$8, confirmed=$14"
            params = (tx['tx_hash'], tx['from_wallet'], tx['to_wallet'], tx['amount'], tx['fee'], tx['timestamp'], tx.get('block_id',-1), tx['status'], tx['tx_type'], tx.get('signature',''), tx.get('nonce',0), tx.get('confirmations',0), json.dumps(_data), tx.get('confirmed',False), tx.get('token_address',''), tx.get('contract_address',''), tx.get('function',''), json.dumps(tx.get('params',[])))
        await self.db.execute_dml(query, *params)
    async def update_status(self, tx_hash, status, block_id):
        query = "UPDATE transactions SET status = ?, block_id = ?, confirmed = 1 WHERE tx_hash = ?" if self.db.db_type == "sqlite" else "UPDATE transactions SET status = $1, block_id = $2, confirmed = TRUE WHERE tx_hash = $3"
        await self.db.execute_dml(query, status, block_id, tx_hash)
    async def get_pending(self, limit=1000):
        query = "SELECT * FROM transactions WHERE status = 'pending' ORDER BY fee DESC, timestamp ASC LIMIT ?" if self.db.db_type == "sqlite" else "SELECT * FROM transactions WHERE status = 'pending' ORDER BY fee DESC, timestamp ASC LIMIT $1"
        return await self.db.fetch(query, limit)
    async def get_by_hash(self, tx_hash):
        query = "SELECT * FROM transactions WHERE tx_hash = ?" if self.db.db_type == "sqlite" else "SELECT * FROM transactions WHERE tx_hash = $1"
        return await self.db.fetchrow(query, tx_hash)
    async def get_for_wallet(self, wallet, limit=100):
        query = "SELECT * FROM transactions WHERE from_wallet = ? OR to_wallet = ? ORDER BY timestamp DESC LIMIT ?" if self.db.db_type == "sqlite" else "SELECT * FROM transactions WHERE from_wallet = $1 OR to_wallet = $2 ORDER BY timestamp DESC LIMIT $3"
        return await self.db.fetch(query, wallet, wallet, limit)

class BalanceRepo:
    def __init__(self, db): self.db = db
    async def get(self, wallet):
        query = "SELECT bal FROM balances WHERE wallet = ?" if self.db.db_type == "sqlite" else "SELECT bal FROM balances WHERE wallet = $1"
        row = await self.db.fetchrow(query, wallet.lower() if isinstance(wallet, str) else wallet)
        return row['bal'] if row else 0
    async def set(self, wallet, amount):
        w = wallet.lower() if isinstance(wallet, str) else wallet
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO balances (wallet, bal) VALUES (?,?)", w, amount)
        else:
            await self.db.execute_dml("INSERT INTO balances (wallet, bal, updated_at) VALUES ($1,$2,NOW()) ON CONFLICT (wallet) DO UPDATE SET bal = $2, updated_at = NOW()", w, amount)
    async def add(self, wallet, amount):
        w = wallet.lower() if isinstance(wallet, str) else wallet
        if self.db.db_type == "sqlite":
            await self.set(w, await self.get(w) + amount)
        else:
            await self.db.execute_dml("INSERT INTO balances (wallet, bal) VALUES ($1,$2) ON CONFLICT (wallet) DO UPDATE SET bal = balances.bal + $2, updated_at = NOW()", w, amount)
    async def subtract(self, wallet, amount):
        w = wallet.lower() if isinstance(wallet, str) else wallet
        current = await self.get(w)
        if current < amount: return False
        await self.set(w, current - amount)
        return True

class MinerRepo:
    def __init__(self, db): self.db = db
    async def create(self, miner):
        priv_enc = miner.get('private_key_encrypted')
        if isinstance(priv_enc, dict): priv_enc = json.dumps(priv_enc)
        elif priv_enc is None: priv_enc = ''
        if self.db.db_type == "sqlite":
            query = "INSERT INTO miners (miner_id,wallet,pub,rewards,blocks,slashes,uptime,today_uptime,type,liquidity,fees,last_ping,banned_until,created_at,last_block,consecutive_misses,total_uptime,ip_address,node_id,version,active,confirmed_balance,password_hash,private_key_encrypted,gas_collected,maze_wins,block_signing_pub) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            params = (miner['miner_id'], miner['wallet'], miner['pub'], miner.get('rewards',0), miner.get('blocks',0), miner.get('slashes',0), miner.get('uptime',0), miner.get('today_uptime',0), miner.get('type','web'), miner.get('liquidity',0), miner.get('fees',0), miner.get('last_ping',time.time()), miner.get('banned_until',0), miner.get('created_at',time.time()), miner.get('last_block',0), miner.get('consecutive_misses',0), miner.get('total_uptime',0), miner.get('ip_address',''), miner.get('node_id',''), miner.get('version',VERSION), 1 if miner.get('active',True) else 0, miner.get('confirmed_balance',0), miner.get('password_hash',''), priv_enc, miner.get('gas_collected',0), miner.get('maze_wins',0), miner.get('block_signing_pub',''))
        else:
            query = "INSERT INTO miners (miner_id,wallet,pub,rewards,blocks,slashes,uptime,today_uptime,type,liquidity,fees,last_ping,banned_until,created_at,last_block,consecutive_misses,total_uptime,ip_address,node_id,version,active,confirmed_balance,password_hash,private_key_encrypted,gas_collected,maze_wins,block_signing_pub) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW(),$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)"
            params = (miner['miner_id'], miner['wallet'], miner['pub'], miner.get('rewards',0), miner.get('blocks',0), miner.get('slashes',0), miner.get('uptime',0), miner.get('today_uptime',0), miner.get('type','web'), miner.get('liquidity',0), miner.get('fees',0), miner.get('last_ping',time.time()), miner.get('banned_until',0), miner.get('last_block',0), miner.get('consecutive_misses',0), miner.get('total_uptime',0), miner.get('ip_address',''), miner.get('node_id',''), miner.get('version',VERSION), miner.get('active',True), miner.get('confirmed_balance',0), miner.get('password_hash',''), priv_enc, miner.get('gas_collected',0), miner.get('maze_wins',0), miner.get('block_signing_pub',''))
        await self.db.execute_dml(query, *params)
    async def update(self, miner):
        priv_enc = miner.get('private_key_encrypted')
        if isinstance(priv_enc, dict): priv_enc = json.dumps(priv_enc)
        elif priv_enc is None: priv_enc = ''
        if self.db.db_type == "sqlite":
            query = "UPDATE miners SET wallet=?,pub=?,rewards=?,blocks=?,slashes=?,uptime=?,today_uptime=?,type=?,liquidity=?,fees=?,last_ping=?,banned_until=?,last_block=?,consecutive_misses=?,total_uptime=?,ip_address=?,node_id=?,version=?,active=?,confirmed_balance=?,password_hash=?,private_key_encrypted=?,gas_collected=?,maze_wins=?,block_signing_pub=? WHERE miner_id=?"
            params = (miner['wallet'], miner['pub'], miner['rewards'], miner['blocks'], miner['slashes'], miner['uptime'], miner['today_uptime'], miner['type'], miner['liquidity'], miner['fees'], miner['last_ping'], miner['banned_until'], miner['last_block'], miner['consecutive_misses'], miner['total_uptime'], miner['ip_address'], miner['node_id'], miner['version'], 1 if miner['active'] else 0, miner['confirmed_balance'], miner['password_hash'], priv_enc, miner['gas_collected'], miner['maze_wins'], miner.get('block_signing_pub',''), miner['miner_id'])
        else:
            query = "UPDATE miners SET wallet=$2,pub=$3,rewards=$4,blocks=$5,slashes=$6,uptime=$7,today_uptime=$8,type=$9,liquidity=$10,fees=$11,last_ping=$12,banned_until=$13,last_block=$14,consecutive_misses=$15,total_uptime=$16,ip_address=$17,node_id=$18,version=$19,active=$20,confirmed_balance=$21,password_hash=$22,private_key_encrypted=$23,gas_collected=$24,maze_wins=$25,block_signing_pub=$26 WHERE miner_id=$1"
            params = (miner['miner_id'], miner['wallet'], miner['pub'], miner['rewards'], miner['blocks'], miner['slashes'], miner['uptime'], miner['today_uptime'], miner['type'], miner['liquidity'], miner['fees'], miner['last_ping'], miner['banned_until'], miner['last_block'], miner['consecutive_misses'], miner['total_uptime'], miner['ip_address'], miner['node_id'], miner['version'], miner['active'], miner['confirmed_balance'], miner['password_hash'], priv_enc, miner['gas_collected'], miner['maze_wins'], miner.get('block_signing_pub',''))
        await self.db.execute_dml(query, *params)
    async def get(self, miner_id):
        query = "SELECT * FROM miners WHERE miner_id = ?" if self.db.db_type == "sqlite" else "SELECT * FROM miners WHERE miner_id = $1"
        row = await self.db.fetchrow(query, miner_id)
        if row and row.get('private_key_encrypted'):
            try:
                val = json.loads(row['private_key_encrypted'])
                if isinstance(val, dict): row['private_key_encrypted'] = val
            except Exception: pass
        return row
    async def get_active(self):
        if self.db.db_type == "sqlite":
            rows = await self.db.fetch("SELECT * FROM miners WHERE active = 1 AND banned_until < ?", time.time())
        else:
            rows = await self.db.fetch("SELECT * FROM miners WHERE active = TRUE AND banned_until < EXTRACT(EPOCH FROM NOW())")
        for row in rows:
            if row.get('private_key_encrypted'):
                try:
                    val = json.loads(row['private_key_encrypted'])
                    if isinstance(val, dict): row['private_key_encrypted'] = val
                except Exception: pass
        return rows
    async def get_by_wallet(self, wallet):
        query = "SELECT * FROM miners WHERE wallet = ?" if self.db.db_type == "sqlite" else "SELECT * FROM miners WHERE wallet = $1"
        rows = await self.db.fetch(query, wallet)
        for row in rows:
            if row.get('private_key_encrypted'):
                try:
                    val = json.loads(row['private_key_encrypted'])
                    if isinstance(val, dict): row['private_key_encrypted'] = val
                except Exception: pass
        return rows
    async def update_last_ping(self, miner_id):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("UPDATE miners SET last_ping = ? WHERE miner_id = ?", time.time(), miner_id)
        else:
            await self.db.execute_dml("UPDATE miners SET last_ping = EXTRACT(EPOCH FROM NOW()) WHERE miner_id = $1", miner_id)
    async def increment_blocks(self, miner_id, reward):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("UPDATE miners SET blocks = blocks + 1, rewards = rewards + ? WHERE miner_id = ?", reward, miner_id)
        else:
            await self.db.execute_dml("UPDATE miners SET blocks = blocks + 1, rewards = rewards + $1 WHERE miner_id = $2", reward, miner_id)

class NodeRepo:
    def __init__(self, db): self.db = db
    async def create(self, node):
        if self.db.db_type == "sqlite":
            query = "INSERT INTO nodes (node_id,wallet,ip,port,last_seen,height,active,rewards_earned,version,mining_enabled,staking_enabled,last_sync,is_multisig_signer,public_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            params = (node['node_id'], node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], 1 if node['active'] else 0, node['rewards_earned'], node['version'], 1 if node['mining_enabled'] else 0, 1 if node['staking_enabled'] else 0, node['last_sync'], 1 if node['is_multisig_signer'] else 0, node['public_key'])
        else:
            query = "INSERT INTO nodes (node_id,wallet,ip,port,last_seen,height,active,rewards_earned,version,mining_enabled,staking_enabled,last_sync,is_multisig_signer,public_key) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)"
            params = (node['node_id'], node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], node['active'], node['rewards_earned'], node['version'], node['mining_enabled'], node['staking_enabled'], node['last_sync'], node['is_multisig_signer'], node['public_key'])
        await self.db.execute_dml(query, *params)
    async def update(self, node):
        if self.db.db_type == "sqlite":
            query = "UPDATE nodes SET wallet=?,ip=?,port=?,last_seen=?,height=?,active=?,rewards_earned=?,version=?,mining_enabled=?,staking_enabled=?,last_sync=?,is_multisig_signer=?,public_key=? WHERE node_id=?"
            params = (node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], 1 if node['active'] else 0, node['rewards_earned'], node['version'], 1 if node['mining_enabled'] else 0, 1 if node['staking_enabled'] else 0, node['last_sync'], 1 if node['is_multisig_signer'] else 0, node['public_key'], node['node_id'])
        else:
            query = "UPDATE nodes SET wallet=$2,ip=$3,port=$4,last_seen=$5,height=$6,active=$7,rewards_earned=$8,version=$9,mining_enabled=$10,staking_enabled=$11,last_sync=$12,is_multisig_signer=$13,public_key=$14 WHERE node_id=$1"
            params = (node['node_id'], node['wallet'], node['ip'], node['port'], node['last_seen'], node['height'], node['active'], node['rewards_earned'], node['version'], node['mining_enabled'], node['staking_enabled'], node['last_sync'], node['is_multisig_signer'], node['public_key'])
        await self.db.execute_dml(query, *params)
    async def get(self, node_id):
        query = "SELECT * FROM nodes WHERE node_id = ?" if self.db.db_type == "sqlite" else "SELECT * FROM nodes WHERE node_id = $1"
        return await self.db.fetchrow(query, node_id)
    async def get_active(self):
        query = "SELECT * FROM nodes WHERE active = 1" if self.db.db_type == "sqlite" else "SELECT * FROM nodes WHERE active = TRUE"
        return await self.db.fetch(query)
    async def update_height(self, node_id, height):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("UPDATE nodes SET height = ?, last_seen = ? WHERE node_id = ?", height, time.time(), node_id)
        else:
            await self.db.execute_dml("UPDATE nodes SET height = $1, last_seen = NOW() WHERE node_id = $2", height, node_id)

class TokenRepo:
    def __init__(self, db): self.db = db
    async def create(self, token):
        if self.db.db_type == "sqlite":
            query = "INSERT INTO tokens (address,name,symbol,owner,total_supply,decimals,created_at,fee_paid,mintable,burnable,mining_type,mining_reward,mining_interval,mining_difficulty,stake_threshold,last_mined_block,total_mined,max_mineable_supply) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
            params = (token['address'], token['name'], token['symbol'], token['owner'], token['total_supply'], token['decimals'], token['created_at'], token['fee_paid'], 1 if token['mintable'] else 0, 1 if token['burnable'] else 0, token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'])
        else:
            query = "INSERT INTO tokens (address,name,symbol,owner,total_supply,decimals,created_at,fee_paid,mintable,burnable,mining_type,mining_reward,mining_interval,mining_difficulty,stake_threshold,last_mined_block,total_mined,max_mineable_supply) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"
            params = (token['address'], token['name'], token['symbol'], token['owner'], token['total_supply'], token['decimals'], token['created_at'], token['fee_paid'], token['mintable'], token['burnable'], token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'])
        await self.db.execute_dml(query, *params)
    async def get(self, address):
        query = "SELECT * FROM tokens WHERE address = ?" if self.db.db_type == "sqlite" else "SELECT * FROM tokens WHERE address = $1"
        return await self.db.fetchrow(query, address)
    async def get_by_owner(self, owner):
        query = "SELECT * FROM tokens WHERE owner = ?" if self.db.db_type == "sqlite" else "SELECT * FROM tokens WHERE owner = $1"
        return await self.db.fetch(query, owner)
    async def update(self, token):
        if self.db.db_type == "sqlite":
            query = "UPDATE tokens SET name=?,symbol=?,total_supply=?,decimals=?,mintable=?,burnable=?,mining_type=?,mining_reward=?,mining_interval=?,mining_difficulty=?,stake_threshold=?,last_mined_block=?,total_mined=?,max_mineable_supply=? WHERE address=?"
            params = (token['name'], token['symbol'], token['total_supply'], token['decimals'], 1 if token['mintable'] else 0, 1 if token['burnable'] else 0, token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'], token['address'])
        else:
            query = "UPDATE tokens SET name=$2,symbol=$3,total_supply=$4,decimals=$5,mintable=$6,burnable=$7,mining_type=$8,mining_reward=$9,mining_interval=$10,mining_difficulty=$11,stake_threshold=$12,last_mined_block=$13,total_mined=$14,max_mineable_supply=$15 WHERE address=$1"
            params = (token['address'], token['name'], token['symbol'], token['total_supply'], token['decimals'], token['mintable'], token['burnable'], token['mining_type'], token['mining_reward'], token['mining_interval'], token['mining_difficulty'], token['stake_threshold'], token['last_mined_block'], token['total_mined'], token['max_mineable_supply'])
        await self.db.execute_dml(query, *params)
    async def upsert(self, token):
        existing = await self.get(token['address'])
        if existing:
            await self.update(token)
        else:
            await self.create(token)

class TokenBalanceRepo:
    def __init__(self, db): self.db = db
    async def get(self, token, wallet):
        query = "SELECT balance FROM token_balances WHERE token_address = ? AND wallet = ?" if self.db.db_type == "sqlite" else "SELECT balance FROM token_balances WHERE token_address = $1 AND wallet = $2"
        row = await self.db.fetchrow(query, token, wallet)
        return row['balance'] if row else 0
    async def set(self, token, wallet, balance):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO token_balances (token_address,wallet,balance) VALUES (?,?,?)", token, wallet, balance)
        else:
            await self.db.execute_dml("INSERT INTO token_balances (token_address,wallet,balance) VALUES ($1,$2,$3) ON CONFLICT (token_address,wallet) DO UPDATE SET balance=$3", token, wallet, balance)

class ContractStateRepo:
    def __init__(self, db): self.db = db
    async def get(self, contract, key):
        query = "SELECT value FROM contract_state WHERE contract_address = ? AND key = ?" if self.db.db_type == "sqlite" else "SELECT value FROM contract_state WHERE contract_address = $1 AND key = $2"
        row = await self.db.fetchrow(query, contract, key)
        return row['value'] if row else None
    async def set(self, contract, key, value):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO contract_state (contract_address,key,value) VALUES (?,?,?)", contract, key, value)
        else:
            await self.db.execute_dml("INSERT INTO contract_state (contract_address,key,value) VALUES ($1,$2,$3) ON CONFLICT (contract_address,key) DO UPDATE SET value=$3", contract, key, value)
    async def get_all(self, contract):
        query = "SELECT key,value FROM contract_state WHERE contract_address = ?" if self.db.db_type == "sqlite" else "SELECT key,value FROM contract_state WHERE contract_address = $1"
        rows = await self.db.fetch(query, contract)
        return {r['key']: r['value'] for r in rows}

class ContractEventRepo:
    def __init__(self, db): self.db = db
    async def create(self, event):
        data_json = json.dumps(event['data']) if isinstance(event['data'], (dict, list)) else event['data']
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT INTO contract_events (contract_address,event_name,data,block_id,tx_hash,timestamp) VALUES (?,?,?,?,?,?)", event['contract_address'], event['event_name'], data_json, event['block_id'], event['tx_hash'], time.time())
        else:
            await self.db.execute_dml("INSERT INTO contract_events (contract_address,event_name,data,block_id,tx_hash,timestamp) VALUES ($1,$2,$3::jsonb,$4,$5,NOW())", event['contract_address'], event['event_name'], data_json, event['block_id'], event['tx_hash'])
    async def get_by_contract(self, contract, limit=100):
        query = "SELECT * FROM contract_events WHERE contract_address = ? ORDER BY id DESC LIMIT ?" if self.db.db_type == "sqlite" else "SELECT * FROM contract_events WHERE contract_address = $1 ORDER BY id DESC LIMIT $2"
        return await self.db.fetch(query, contract, limit)

class MultisigRepo:
    def __init__(self, db): self.db = db
    async def create(self, address, public_keys, threshold):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO multisig_wallets (address,public_keys,threshold,created_at) VALUES (?,?,?,?)", address, json.dumps(public_keys), threshold, time.time())
        else:
            await self.db.execute_dml("INSERT INTO multisig_wallets (address,public_keys,threshold,created_at) VALUES ($1,$2::jsonb,$3,NOW())", address, json.dumps(public_keys), threshold)
    async def get(self, address):
        query = "SELECT * FROM multisig_wallets WHERE address = ?" if self.db.db_type == "sqlite" else "SELECT * FROM multisig_wallets WHERE address = $1"
        return await self.db.fetchrow(query, address)

class ChallengeRepo:
    def __init__(self, db): self.db = db
    async def create(self, wallet, nonce, expires):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO signing_challenges (wallet,nonce,expires) VALUES (?,?,?)", wallet, nonce, expires)
        else:
            await self.db.execute_dml("INSERT INTO signing_challenges (wallet,nonce,expires) VALUES ($1,$2,to_timestamp($3)) ON CONFLICT (wallet) DO UPDATE SET nonce=$2, expires=to_timestamp($3)", wallet, nonce, expires)
    async def get(self, wallet):
        query = "SELECT nonce, expires FROM signing_challenges WHERE wallet = ?" if self.db.db_type == "sqlite" else "SELECT nonce, EXTRACT(EPOCH FROM expires) AS expires FROM signing_challenges WHERE wallet = $1"
        return await self.db.fetchrow(query, wallet)
    async def delete(self, wallet):
        query = "DELETE FROM signing_challenges WHERE wallet = ?" if self.db.db_type == "sqlite" else "DELETE FROM signing_challenges WHERE wallet = $1"
        await self.db.execute_dml(query, wallet)

class ReceiptRepo:
    def __init__(self, db): self.db = db
    async def create(self, receipt):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT INTO transaction_receipts (tx_hash,block_id,status,gas_used,logs,contract_address,result) VALUES (?,?,?,?,?,?,?)", receipt['tx_hash'], receipt['block_id'], receipt['status'], receipt['gas_used'], json.dumps(receipt['logs']), receipt['contract_address'], receipt['result'])
        else:
            await self.db.execute_dml("INSERT INTO transaction_receipts (tx_hash,block_id,status,gas_used,logs,contract_address,result) VALUES ($1,$2,$3,$4,$5::jsonb,$6,$7)", receipt['tx_hash'], receipt['block_id'], receipt['status'], receipt['gas_used'], json.dumps(receipt['logs']), receipt['contract_address'], receipt['result'])
    async def get(self, tx_hash):
        query = "SELECT * FROM transaction_receipts WHERE tx_hash = ?" if self.db.db_type == "sqlite" else "SELECT * FROM transaction_receipts WHERE tx_hash = $1"
        return await self.db.fetchrow(query, tx_hash)

class FinalityRepo:
    def __init__(self, db): self.db = db
    async def create_checkpoint(self, block_id, block_hash, epoch):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO finality_checkpoints (block_id,hash,finalized_at,epoch) VALUES (?,?,?,?)", block_id, block_hash, time.time(), epoch)
        else:
            await self.db.execute_dml("INSERT INTO finality_checkpoints (block_id,hash,finalized_at,epoch) VALUES ($1,$2,NOW(),$3) ON CONFLICT (block_id) DO UPDATE SET hash=$2, finalized_at=NOW(), epoch=$3", block_id, block_hash, epoch)
    async def get_latest(self):
        query = "SELECT * FROM finality_checkpoints ORDER BY block_id DESC LIMIT 1"
        return await self.db.fetchrow(query)
    async def get_by_epoch(self, epoch: int):
        query = "SELECT * FROM finality_checkpoints WHERE epoch = ?" if self.db.db_type == "sqlite" else "SELECT * FROM finality_checkpoints WHERE epoch = $1"
        return await self.db.fetch(query, epoch)


class FinalityGadget:
    """Epoch-based finality: every EPOCH_SIZE blocks, a checkpoint is created.
    All blocks in the epoch are marked finalized once the checkpoint is committed.

    R8-finality-advisory (R7-03): checkpoints are ADVISORY burial-order
    bookkeeping (pruning/fast-sync hints), NOT a fork-choice veto. This
    chain has no quorum-certificate protocol, so a locally imported
    checkpoint cannot prove network agreement; refusing reorgs below it
    split partitions permanently. Fork choice heals by attestation weight
    at any depth (bounded only by PRUNE_BLOCKS retention). Treat
    `finalized` flags as probabilistic-burial hints, never irreversibility.
    """
    EPOCH_SIZE = 100

    def __init__(self, node):
        self.node = node
        self._last_finalized_block = 0

    async def on_block(self, block):
        """Called after each block is imported. Creates checkpoint at epoch boundaries."""
        block_id = block.get("id", 0)
        if block_id > 0 and block_id % self.EPOCH_SIZE == 0:
            await self.create_checkpoint(block_id, block.get("hash", ""), block_id // self.EPOCH_SIZE)

    async def create_checkpoint(self, block_id, block_hash, epoch):
        """Commit a finality checkpoint — all blocks up to block_id are now finalized."""
        try:
            await self.node.finality_repo.create_checkpoint(block_id, block_hash, epoch)
            block_repo = BlockRepo(self.node.db)
            # R6-finality-query-paged: page with LIMIT 1000 until empty
            # instead of loading every unfinalized row at once. No OFFSET:
            # marked rows drop out of later pages, so OFFSET would skip.
            if self.node.db.db_type == "sqlite":
                _page_q = "SELECT id FROM blocks WHERE id <= ? AND finalized = 0 LIMIT 1000"
            else:
                _page_q = "SELECT id FROM blocks WHERE id <= $1 AND finalized = FALSE LIMIT 1000"
            _total = 0
            while True:
                rows = await self.node.db.fetch(_page_q, block_id)
                if not rows:
                    break
                for row in rows:
                    await block_repo.mark_finalized(row['id'])
                    _total += 1
            self._last_finalized_block = max(self._last_finalized_block, block_id)
            logger.info(f"[Finality] Epoch {epoch} finalized at block {block_id} ({_total} blocks)")
        except Exception as e:
            logger.error(f"[Finality] Failed to create checkpoint at block {block_id}: {e}")

    def get_last_finalized_block(self):
        return self._last_finalized_block

    async def ensure_loaded(self):
        """Load last finalized block from DB if not yet loaded."""
        if self._last_finalized_block == 0:
            latest = await self.node.finality_repo.get_latest()
            if latest:
                self._last_finalized_block = latest['block_id']

    def is_finalized(self, block_id):
        return block_id <= self._last_finalized_block

class NetworkStateRepo:
    def __init__(self, db): self.db = db
    async def get(self, key):
        query = "SELECT value FROM network_state WHERE key = ?" if self.db.db_type == "sqlite" else "SELECT value FROM network_state WHERE key = $1"
        row = await self.db.fetchrow(query, key)
        return row['value'] if row else None
    async def set(self, key, value):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO network_state (key,value) VALUES (?,?)", key, value)
        else:
            await self.db.execute_dml("INSERT INTO network_state (key,value) VALUES ($1,$2) ON CONFLICT (key) DO UPDATE SET value=$2", key, value)

class ContractV2Repo:
    def __init__(self, db): self.db = db
    async def create(self, contract):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO contract_v2 (address,owner,bytecode,abi,created_at,tx_hash,storage_root,code_hash) VALUES (?,?,?,?,?,?,?,?)", contract['address'], contract['owner'], contract['bytecode'], contract['abi'], contract['created_at'], contract['tx_hash'], contract['storage_root'], contract['code_hash'])
        else:
            await self.db.execute_dml("INSERT INTO contract_v2 (address,owner,bytecode,abi,created_at,tx_hash,storage_root,code_hash) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)", contract['address'], contract['owner'], contract['bytecode'], contract['abi'], contract['created_at'], contract['tx_hash'], contract['storage_root'], contract['code_hash'])
    async def get(self, address):
        query = "SELECT * FROM contract_v2 WHERE address = ?" if self.db.db_type == "sqlite" else "SELECT * FROM contract_v2 WHERE address = $1"
        return await self.db.fetchrow(query, address)
    async def get_all(self):
        query = "SELECT * FROM contract_v2"
        return await self.db.fetch(query)
    async def update(self, contract):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("UPDATE contract_v2 SET bytecode=?,abi=?,storage_root=?,code_hash=? WHERE address=?", contract['bytecode'], contract['abi'], contract['storage_root'], contract['code_hash'], contract['address'])
        else:
            await self.db.execute_dml("UPDATE contract_v2 SET bytecode=$1,abi=$2,storage_root=$3,code_hash=$4 WHERE address=$5", contract['bytecode'], contract['abi'], contract['storage_root'], contract['code_hash'], contract['address'])

class ContractStorageV2Repo:
    def __init__(self, db): self.db = db
    async def set(self, contract, key, value):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT OR REPLACE INTO contract_storage_v2 (contract_address,key,value) VALUES (?,?,?)", contract, key, value)
        else:
            await self.db.execute_dml("INSERT INTO contract_storage_v2 (contract_address,key,value) VALUES ($1,$2,$3) ON CONFLICT (contract_address,key) DO UPDATE SET value=$3", contract, key, value)
    async def get(self, contract, key):
        query = "SELECT value FROM contract_storage_v2 WHERE contract_address = ? AND key = ?" if self.db.db_type == "sqlite" else "SELECT value FROM contract_storage_v2 WHERE contract_address = $1 AND key = $2"
        row = await self.db.fetchrow(query, contract, key)
        return row['value'] if row else None
    async def get_all(self, contract):
        query = "SELECT key,value FROM contract_storage_v2 WHERE contract_address = ?" if self.db.db_type == "sqlite" else "SELECT key,value FROM contract_storage_v2 WHERE contract_address = $1"
        rows = await self.db.fetch(query, contract)
        return {r['key']: r['value'] for r in rows}

def verify_automation_delete_auth(auto_id, owner, pub_key, signature, ts) -> Tuple[bool, str]:
    """R4-automations-delete-auth: gate automation DELETE like CREATE —
    canonical signed message, pub_key must hash to owner, timestamp fresh
    (±300s). Returns (True, owner) or (False, error). Pure function so the
    handler stays thin and the gate is unit-testable."""
    if not pub_key or not signature:
        return False, "Missing signature"
    if ts is None:
        return False, "Missing timestamp"
    try:
        ts_f = float(ts)
    except (TypeError, ValueError):
        return False, "Bad timestamp"
    if abs(time.time() - ts_f) > 300:
        return False, "Stale timestamp"
    try:
        if pubkey_to_address(pub_key).lower() != str(owner).lower():
            return False, "pub_key does not match owner"
    except Exception:
        return False, "Invalid pub_key"
    message = f"{CHAIN_ID}:delete_automation:{auto_id}:{owner}:{int(ts_f)}"
    if not verify_signature(pub_key, message, signature):
        return False, "Invalid signature"
    return True, str(owner)


def _automation_replay_key(message) -> str:
    # AUTOMATION-REPLAY-KEY-1: key the replay guard on the digest of the SIGNED MESSAGE, not on the signature text.
    # verify_signature_bytes accepts either hex case (and any equivalent encoding of the same r||s), so keying on
    # str(signature) let a captured request be replayed by upper/lower-casing its signature. The signed message
    # (owner|name|trigger|action|configs|int(timestamp)) is what the owner authorized; identical message == replay.
    if isinstance(message, str):
        message = message.encode("utf-8")
    return hashlib.sha256(bytes(message)).hexdigest()


def _automation_sig_replay(seen: dict, sig: str, now: float, window: float = 300.0) -> bool:
    # O3-replay-guard: a signed automation-create request is valid for
    # +-window seconds by timestamp, so without a seen-set it can be
    # rePOSTed for duplicates the whole window. Returns True when this
    # exact signature was already accepted (caller must reject), else
    # records it and returns False. Prunes expired entries, so memory is
    # bounded by one window of creates. Pure apart from mutating `seen`.
    try:
        _now = float(now)
    except (TypeError, ValueError, OverflowError):
        return False
    try:
        _win = float(window)
    except (TypeError, ValueError, OverflowError):
        _win = 300.0
    for _k, _ts in list(seen.items()):
        try:
            if _now - float(_ts) > _win:
                seen.pop(_k, None)
        except (TypeError, ValueError, OverflowError):
            seen.pop(_k, None)
    if sig in seen:
        return True
    seen[sig] = _now
    return False


class AutomationRepo:
    def __init__(self, db): self.db = db

    @staticmethod
    def _redact(d: dict) -> dict:
        """R4-automations-redact: strip signed tx bodies at the repo
        boundary. action_config.txs keeps only {tx_hash, tx_type}; the rest
        of action_config is preserved. Returns a copy; stored rows untouched."""
        ac = d.get("action_config")
        if not isinstance(ac, dict):
            return d
        txs = ac.get("txs")
        if not isinstance(txs, list):
            return d
        red = [{"tx_hash": t.get("tx_hash"), "tx_type": t.get("tx_type")}
               for t in txs if isinstance(t, dict)]
        out = dict(d)
        out_ac = dict(ac)
        out_ac["txs"] = red
        out["action_config"] = out_ac
        return out

    async def create(self, data: dict):
        t_conf = json.dumps(data.get("trigger_config", {}))
        a_conf = json.dumps(data.get("action_config", {}))
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT OR REPLACE INTO automations (id,name,owner,trigger_type,trigger_config,action_type,action_config,enabled,created_at,last_run_at,run_count,last_result) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                data["id"], data["name"], data["owner"], data["trigger_type"], t_conf, data["action_type"], a_conf,
                1 if data.get("enabled", True) else 0, data.get("created_at", time.time()), data.get("last_run_at"), data.get("run_count", 0), data.get("last_result", "")
            )
        else:
            await self.db.execute_dml(
                "INSERT INTO automations (id,name,owner,trigger_type,trigger_config,action_type,action_config,enabled,created_at,last_run_at,run_count,last_result) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) ON CONFLICT (id) DO UPDATE SET name=$2, trigger_type=$4, trigger_config=$5, action_type=$6, action_config=$7, enabled=$8, last_run_at=$10, run_count=$11, last_result=$12",
                data["id"], data["name"], data["owner"], data["trigger_type"], t_conf, data["action_type"], a_conf,
                bool(data.get("enabled", True)), data.get("created_at", time.time()), data.get("last_run_at"), data.get("run_count", 0), data.get("last_result", "")
            )
    async def get(self, auto_id: str):
        q = "SELECT * FROM automations WHERE id = ?" if self.db.db_type == "sqlite" else "SELECT * FROM automations WHERE id = $1"
        row = await self.db.fetchrow(q, auto_id)
        if not row: return None
        d = dict(row)
        if isinstance(d.get("trigger_config"), str):
            try: d["trigger_config"] = json.loads(d["trigger_config"])
            except Exception: pass
        if isinstance(d.get("action_config"), str):
            try: d["action_config"] = json.loads(d["action_config"])
            except Exception: pass
        return AutomationRepo._redact(d)
    async def list_active(self):
        q = "SELECT * FROM automations WHERE enabled = 1" if self.db.db_type == "sqlite" else "SELECT * FROM automations WHERE enabled = TRUE"
        rows = await self.db.fetch(q)
        res = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("trigger_config"), str):
                try: d["trigger_config"] = json.loads(d["trigger_config"])
                except Exception: pass
            if isinstance(d.get("action_config"), str):
                try: d["action_config"] = json.loads(d["action_config"])
                except Exception: pass
            res.append(AutomationRepo._redact(d))
        return res
    async def list_by_owner(self, owner: str):
        q = "SELECT * FROM automations WHERE owner = ?" if self.db.db_type == "sqlite" else "SELECT * FROM automations WHERE owner = $1"
        rows = await self.db.fetch(q, owner)
        res = []
        for r in rows:
            d = dict(r)
            if isinstance(d.get("trigger_config"), str):
                try: d["trigger_config"] = json.loads(d["trigger_config"])
                except Exception: pass
            if isinstance(d.get("action_config"), str):
                try: d["action_config"] = json.loads(d["action_config"])
                except Exception: pass
            res.append(AutomationRepo._redact(d))
        return res
    async def update_run(self, auto_id: str, last_run_at: float, run_count: int, last_result: str, last_block_run: int = 0):
        # R6-automation-last-block-persist: persist the firing height
        # (chain reset: schema gains last_block_run) so block triggers do
        # not refire every loop iteration.
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("UPDATE automations SET last_run_at = ?, run_count = ?, last_result = ?, last_block_run = ? WHERE id = ?", last_run_at, run_count, str(last_result), int(last_block_run or 0), auto_id)
        else:
            await self.db.execute_dml("UPDATE automations SET last_run_at = $1, run_count = $2, last_result = $3, last_block_run = $4 WHERE id = $5", last_run_at, run_count, str(last_result), int(last_block_run or 0), auto_id)
    async def set_enabled(self, auto_id: str, enabled: bool):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("UPDATE automations SET enabled = ? WHERE id = ?", 1 if enabled else 0, auto_id)
        else:
            await self.db.execute_dml("UPDATE automations SET enabled = $1 WHERE id = $2", bool(enabled), auto_id)
    async def delete(self, auto_id: str):
        q = "DELETE FROM automations WHERE id = ?" if self.db.db_type == "sqlite" else "DELETE FROM automations WHERE id = $1"
        await self.db.execute_dml(q, auto_id)

    async def note_replay_seen(self, key: str, now: float, window: float = 300.0) -> bool:
        """Durable replay guard (AUTO-REPLAY-SEEN-1): True when this key
        was recorded within the window (caller must reject); otherwise
        records it and returns False. Expired rows are pruned on every
        call, so the table holds at most one window of creates. Residual:
        two nodes/processes accepting the same bytes in the same instant
        can both pass (no distributed lock); the in-process memory guard
        covers the single-node concurrent case."""
        try:
            _now = float(now)
            _win = float(window)
        except (TypeError, ValueError, OverflowError):
            return False
        _cut = _now - _win
        try:
            if self.db.db_type == "sqlite":
                await self.db.execute_dml(
                    "DELETE FROM automation_replay_seen WHERE seen_at < ?", _cut)
                row = await self.db.fetchrow(
                    "SELECT seen_at FROM automation_replay_seen WHERE sig_hash = ?", str(key))
                if row is not None:
                    return True
                await self.db.execute_dml(
                    "INSERT OR REPLACE INTO automation_replay_seen (sig_hash, seen_at) VALUES (?, ?)",
                    str(key), _now)
            else:
                await self.db.execute_dml(
                    "DELETE FROM automation_replay_seen WHERE seen_at < $1", _cut)
                row = await self.db.fetchrow(
                    "SELECT seen_at FROM automation_replay_seen WHERE sig_hash = $1", str(key))
                if row is not None:
                    return True
                await self.db.execute_dml(
                    "INSERT INTO automation_replay_seen (sig_hash, seen_at) VALUES ($1, $2) "
                    "ON CONFLICT (sig_hash) DO UPDATE SET seen_at = EXCLUDED.seen_at",
                    str(key), _now)
        except Exception:
            return False
        return False

class HTLCRepo:
    def __init__(self, db): self.db = db
    async def create(self, htlc):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("INSERT INTO htlc_contracts (id,sender,receiver,hashlock,timelock,amount,token_address,status,created_at) VALUES (?,?,?,?,?,?,?,?,?)", htlc['id'], htlc['sender'], htlc['receiver'], htlc['hashlock'], htlc['timelock'], htlc['amount'], htlc.get('token_address',''), htlc.get('status','open'), time.time())
        else:
            await self.db.execute_dml("INSERT INTO htlc_contracts (id,sender,receiver,hashlock,timelock,amount,token_address,status,created_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())", htlc['id'], htlc['sender'], htlc['receiver'], htlc['hashlock'], htlc['timelock'], htlc['amount'], htlc.get('token_address',''), htlc.get('status','open'))
    async def get(self, htlc_id):
        query = "SELECT * FROM htlc_contracts WHERE id = ?" if self.db.db_type == "sqlite" else "SELECT * FROM htlc_contracts WHERE id = $1"
        return await self.db.fetchrow(query, htlc_id)
    async def update_status(self, htlc_id, status, claimed_at=None, refunded_at=None):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("UPDATE htlc_contracts SET status=?, claimed_at=?, refunded_at=? WHERE id=?", status, claimed_at, refunded_at, htlc_id)
        else:
            await self.db.execute_dml("UPDATE htlc_contracts SET status=$1, claimed_at=$2, refunded_at=$3 WHERE id=$4", status, claimed_at, refunded_at, htlc_id)
    async def get_open_by_receiver(self, receiver):
        query = "SELECT * FROM htlc_contracts WHERE receiver = ? AND status = 'open'" if self.db.db_type == "sqlite" else "SELECT * FROM htlc_contracts WHERE receiver = $1 AND status = 'open'"
        return await self.db.fetch(query, receiver)

# ─── MinerMazeRepo (persistent maze state) ───────────────────────
class MinerMazeRepo:
    def __init__(self, db): self.db = db

    async def get(self, miner_id: str):
        query = "SELECT * FROM minermazes WHERE minerid = ?" if self.db.db_type == "sqlite" else "SELECT * FROM minermazes WHERE minerid = $1"
        return await self.db.fetch(query, miner_id)

    async def get_by_maze_id(self, maze_id: str):
        if not maze_id:
            return None
        query = "SELECT * FROM minermazes WHERE maze_id = ?" if self.db.db_type == "sqlite" else "SELECT * FROM minermazes WHERE maze_id = $1"
        return await self.db.fetchrow(query, maze_id)

    async def create_for_maze(self, maze_id: str, miner_id: str, row: dict):
        row = dict(row)
        row["maze_id"] = maze_id
        row["minerid"] = miner_id
        await self.upsert(row)
        return row

    async def bind_miner(self, maze_id: str, miner_id: str):
        """Attach a miner identity to an existing maze row (one active miner per maze)."""
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "UPDATE minermazes SET minerid=?, updatedat=? WHERE maze_id=?",
                miner_id, int(time.time()), maze_id)
        else:
            await self.db.execute_dml(
                "UPDATE minermazes SET minerid=$1, updatedat=$2 WHERE maze_id=$3",
                miner_id, int(time.time()), maze_id)

    async def get_by_miner_id(self, miner_id: str):
        query = "SELECT * FROM minermazes WHERE minerid = ?" if self.db.db_type == "sqlite" else "SELECT * FROM minermazes WHERE minerid = $1"
        return await self.db.fetch(query, miner_id)

    async def upsert(self, m: dict):
        now = int(time.time())
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT OR REPLACE INTO minermazes (maze_id,minerid,size,walldensityppm,seed,posx,posy,posz,goalx,goaly,goalz,movenonce,consecutivewallhits,turbulenceppm,growthcount,knowledge,lastgoalheight,lastactiveheight,mazeroot,invitedguest,guestlock,lastknowledgeheight,createdat,updatedat,ghostx,ghosty,ghostz) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                m.get('maze_id', m['minerid']), m['minerid'], m['size'], m['walldensityppm'], m['seed'],
                m['posx'], m['posy'], m['posz'],
                m['goalx'], m['goaly'], m['goalz'],
                m.get('movenonce', 0), m.get('consecutivewallhits', 0),
                m.get('turbulenceppm', 0), m.get('growthcount', 0),
                m.get('knowledge', 0),
                m.get('lastgoalheight', 0), m.get('lastactiveheight', 0),
                m['mazeroot'], m.get('invitedguest', None),
                1 if m.get('guestlock', False) else 0,
                m.get('lastknowledgeheight', 0),
                m.get('createdat', now), now,
                m.get('ghostx'), m.get('ghosty'), m.get('ghostz'))
        else:
            await self.db.execute_dml(
                """INSERT INTO minermazes (maze_id,minerid,size,walldensityppm,seed,posx,posy,posz,goalx,goaly,goalz,movenonce,consecutivewallhits,turbulenceppm,growthcount,knowledge,lastgoalheight,lastactiveheight,mazeroot,invitedguest,guestlock,lastknowledgeheight,createdat,updatedat,ghostx,ghosty,ghostz)
                   VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27)
                   ON CONFLICT (maze_id) DO UPDATE SET minerid=$2,size=$3,walldensityppm=$4,seed=$5,posx=$6,posy=$7,posz=$8,goalx=$9,goaly=$10,goalz=$11,movenonce=$12,consecutivewallhits=$13,turbulenceppm=$14,growthcount=$15,knowledge=$16,lastgoalheight=$17,lastactiveheight=$18,mazeroot=$19,invitedguest=$20,guestlock=$21,lastknowledgeheight=$22,updatedat=$24,ghostx=$25,ghosty=$26,ghostz=$27""",
                m.get('maze_id', m['minerid']), m['minerid'], m['size'], m['walldensityppm'], m['seed'],
                m['posx'], m['posy'], m['posz'],
                m['goalx'], m['goaly'], m['goalz'],
                m.get('movenonce', 0), m.get('consecutivewallhits', 0),
                m.get('turbulenceppm', 0), m.get('growthcount', 0),
                m.get('knowledge', 0),
                m.get('lastgoalheight', 0), m.get('lastactiveheight', 0),
                m['mazeroot'], m.get('invitedguest', None),
                m.get('guestlock', False),
                m.get('lastknowledgeheight', 0),
                m.get('createdat', now), now,
                m.get('ghostx'), m.get('ghosty'), m.get('ghostz'))

    async def get_eligible(self, block_id: int) -> list:
        cutoff_height = max(0, block_id - ACTIVE_MINER_WINDOW_BLOCKS)
        # MAZE-MIN-1: eligibility is strictly above the minimum — a size-5
        # maze is valid but ineligible to win (see the attestation check).
        _min_elig = int(MIN_MAZE_SIZE)
        if self.db.db_type == "sqlite":
            rows = await self.db.fetch(
                f"SELECT * FROM minermazes WHERE lastactiveheight >= ? AND size > {_min_elig}", cutoff_height)
        else:
            rows = await self.db.fetch(
                f"SELECT * FROM minermazes WHERE lastactiveheight >= $1 AND size > {_min_elig}", cutoff_height)
        return rows

    async def update_miner_inactive(self, miner_id: str):
        """Drop a banned miner's mazes out of the lottery eligibility window.
        lastactiveheight is reset so get_eligible() excludes them; the value is
        restored to node height on their next accepted move."""
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "UPDATE minermazes SET lastactiveheight = -1000000 WHERE minerid = ?", miner_id)
        else:
            await self.db.execute_dml(
                "UPDATE minermazes SET lastactiveheight = -1000000 WHERE minerid = $1", miner_id)

    async def get_all(self) -> list:
        if self.db.db_type == "sqlite":
            return await self.db.fetch("SELECT * FROM minermazes")
        else:
            return await self.db.fetch("SELECT * FROM minermazes")

# ─── MazeAttestationRepo (IDEA5-ATTEST) ──────────────────────────────
class MazeAttestationRepo:
    """Idea 5: per-maze self-attested sizes, rewritten by each winning block.

    rollback_after(h) drops attestations written by blocks above height h so a
    reorg back to h restores the pre-fork claims (IDEA5-ATTEST-REORG-1)."""
    def __init__(self, db): self.db = db

    async def get(self, maze_id: str):
        if self.db.db_type == "sqlite":
            return await self.db.fetchrow("SELECT * FROM maze_attestations WHERE maze_id = ?", maze_id)
        else:
            return await self.db.fetchrow("SELECT * FROM maze_attestations WHERE maze_id = $1", maze_id)

    async def get_all(self):
        # IDEA5-ELECT: the whole attestation set — the deterministic candidate
        # source (identical on every node: written on append, rolled back on
        # reorg, restored by IDEA5-ATTEST-REORG-2).
        return await self.db.fetch("SELECT * FROM maze_attestations")

    async def upsert(self, att: dict):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT OR REPLACE INTO maze_attestations (maze_id,last_size,last_block,last_block_hash,pubkey) VALUES (?,?,?,?,?)",
                str(att["maze_id"]), int(att["last_size"]), int(att["last_block"]),
                str(att.get("last_block_hash", "")), str(att.get("pubkey", "")))
        else:
            await self.db.execute_dml(
                "INSERT INTO maze_attestations (maze_id,last_size,last_block,last_block_hash,pubkey) VALUES ($1,$2,$3,$4,$5) "
                "ON CONFLICT (maze_id) DO UPDATE SET last_size=$2,last_block=$3,last_block_hash=$4,pubkey=$5",
                str(att["maze_id"]), int(att["last_size"]), int(att["last_block"]),
                str(att.get("last_block_hash", "")), str(att.get("pubkey", "")))

    async def rollback_after(self, common_height: int):
        # IDEA5-ATTEST-REORG-1: rows attested by orphaned blocks (last_block > common_height)
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("DELETE FROM maze_attestations WHERE last_block > ?", common_height)
        else:
            await self.db.execute_dml("DELETE FROM maze_attestations WHERE last_block > $1", common_height)

# ─── LotteryRepo ────────────────────────────────────────────────────
class LotteryRepo:
    def __init__(self, db): self.db = db

    async def put_commit(self, height: int, miner_id: str, commit: str):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                'INSERT OR REPLACE INTO lottery_commits (height, miner_id, "commit") VALUES (?,?,?)',
                height, miner_id, commit)
        else:
            await self.db.execute_dml(
                'INSERT INTO lottery_commits (height, miner_id, "commit") VALUES ($1,$2,$3) ON CONFLICT (height, miner_id) DO UPDATE SET "commit"=EXCLUDED."commit"',
                height, miner_id, commit)

    async def get_commit(self, height: int, miner_id: str):
        if self.db.db_type == "sqlite":
            return await self.db.fetchrow("SELECT * FROM lottery_commits WHERE height = ? AND miner_id = ?", height, miner_id)
        else:
            return await self.db.fetchrow("SELECT * FROM lottery_commits WHERE height = $1 AND miner_id = $2", height, miner_id)

    async def put_reveal(self, height: int, miner_id: str, secret: str):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT OR REPLACE INTO lottery_reveals (height, miner_id, secret) VALUES (?,?,?)",
                height, miner_id, secret)
        else:
            await self.db.execute_dml(
                "INSERT INTO lottery_reveals (height, miner_id, secret) VALUES ($1,$2,$3) ON CONFLICT (height, miner_id) DO UPDATE SET secret=EXCLUDED.secret",
                height, miner_id, secret)

    async def get_reveals_for_height(self, height: int):
        if self.db.db_type == "sqlite":
            return await self.db.fetch("SELECT * FROM lottery_reveals WHERE height = ?", height)
        else:
            return await self.db.fetch("SELECT * FROM lottery_reveals WHERE height = $1", height)

    async def clear_height(self, height: int):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("DELETE FROM lottery_commits WHERE height = ?", height)
            await self.db.execute_dml("DELETE FROM lottery_reveals WHERE height = ?", height)
        else:
            await self.db.execute_dml("DELETE FROM lottery_commits WHERE height = $1", height)
            await self.db.execute_dml("DELETE FROM lottery_reveals WHERE height = $1", height)

# ─── SlashRepo ────────────────────────────────────────────────────
class SlashRepo:
    def __init__(self, db): self.db = db

    async def create(self, miner_id: str, amount: int, reason: str, block_id: int):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT INTO slashing_events (miner_id, amount, reason, timestamp, block_id) VALUES (?,?,?,?,?)",
                miner_id, amount, reason, time.time(), block_id)
        else:
            await self.db.execute_dml(
                "INSERT INTO slashing_events (miner_id, amount, reason, timestamp, block_id) VALUES ($1,$2,$3,$4,$5)",
                miner_id, amount, reason, time.time(), block_id)

    async def get_by_miner(self, miner_id: str):
        if self.db.db_type == "sqlite":
            return await self.db.fetch("SELECT * FROM slashing_events WHERE miner_id = ?", miner_id)
        else:
            return await self.db.fetch("SELECT * FROM slashing_events WHERE miner_id = $1", miner_id)

# ─── PeerBanRepo ────────────────────────────────────────────────────
class PeerBanRepo:
    def __init__(self, db): self.db = db

    async def upsert(self, address: str, node_id: Optional[str], reason: str, expires_at: float):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT OR REPLACE INTO peer_bans (address,node_id,reason,banned_at,expires_at) VALUES (?,?,?,?,?)",
                address, node_id or '', reason, time.time(), expires_at)
        else:
            await self.db.execute_dml(
                "INSERT INTO peer_bans (address,node_id,reason,banned_at,expires_at) VALUES ($1,$2,$3,NOW(),$4) "
                "ON CONFLICT (address) DO UPDATE SET node_id=$2, reason=$3, banned_at=NOW(), expires_at=$4",
                address, node_id or '', reason, expires_at)

    async def get_active(self):
        if self.db.db_type == "sqlite":
            return await self.db.fetch("SELECT * FROM peer_bans WHERE expires_at > ?", time.time())
        else:
            return await self.db.fetch("SELECT * FROM peer_bans WHERE expires_at > $1", time.time())

    async def delete_expired(self):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml("DELETE FROM peer_bans WHERE expires_at <= ?", time.time())
        else:
            await self.db.execute_dml("DELETE FROM peer_bans WHERE expires_at <= $1", time.time())


# ─── SpatialTokenRepo / SpatialTokenBalanceRepo (V2 removed SpatialPoolAccumulatorRepo) ──
# Spatial Tokens V1 (replaces SpatialAssetRepo + SpatialChallengeRepo).
class SpatialTokenRepo:
    def __init__(self, db): self.db = db

    async def create(self, t: dict):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT INTO spatial_tokens (address,creator,name,symbol,supply,decimals,"
                "deploy_block,preferred_x,preferred_y,preferred_z,bundle_count,deploy_nonce)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                t["address"], t["creator"], t["name"], t["symbol"], int(t["supply"]),
                int(t["decimals"]), int(t["deploy_block"]), int(t["preferred_x"]),
                int(t["preferred_y"]), int(t["preferred_z"]), int(t["bundle_count"]),
                int(t["deploy_nonce"]))
        else:
            await self.db.execute_dml(
                "INSERT INTO spatial_tokens (address,creator,name,symbol,supply,decimals,"
                "deploy_block,preferred_x,preferred_y,preferred_z,bundle_count,deploy_nonce)"
                " VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                t["address"], t["creator"], t["name"], t["symbol"], int(t["supply"]),
                int(t["decimals"]), int(t["deploy_block"]), int(t["preferred_x"]),
                int(t["preferred_y"]), int(t["preferred_z"]), int(t["bundle_count"]),
                int(t["deploy_nonce"]))

    async def get(self, address: str):
        q = "SELECT * FROM spatial_tokens WHERE address = ?" if self.db.db_type == "sqlite" \
            else "SELECT * FROM spatial_tokens WHERE address = $1"
        return await self.db.fetchrow(q, address)

    async def get_all(self):
        return await self.db.fetch("SELECT * FROM spatial_tokens")

    async def set_preferred_home(self, address: str, x: int, y: int, z: int):
        q = "UPDATE spatial_tokens SET preferred_x = ?, preferred_y = ?, preferred_z = ? WHERE address = ?" \
            if self.db.db_type == "sqlite" else \
            "UPDATE spatial_tokens SET preferred_x = $1, preferred_y = $2, preferred_z = $3 WHERE address = $4"
        await self.db.execute_dml(q, int(x), int(y), int(z), address)

    async def delete(self, address: str):
        q = "DELETE FROM spatial_tokens WHERE address = ?" if self.db.db_type == "sqlite" \
            else "DELETE FROM spatial_tokens WHERE address = $1"
        await self.db.execute_dml(q, address)

    async def count_at_coord(self, x: int, y: int, z: int) -> int:
        q = "SELECT COUNT(*) AS c FROM spatial_tokens WHERE preferred_x = ? AND preferred_y = ? AND preferred_z = ?" \
            if self.db.db_type == "sqlite" else \
            "SELECT COUNT(*) AS c FROM spatial_tokens WHERE preferred_x = $1 AND preferred_y = $2 AND preferred_z = $3"
        row = await self.db.fetchrow(q, int(x), int(y), int(z))
        return int(row["c"]) if row else 0


class SpatialTokenBalanceRepo:
    def __init__(self, db): self.db = db

    async def get(self, token: str, wallet: str):
        q = "SELECT balance FROM spatial_token_balances WHERE token_address = ? AND wallet = ?" \
            if self.db.db_type == "sqlite" else \
            "SELECT balance FROM spatial_token_balances WHERE token_address = $1 AND wallet = $2"
        row = await self.db.fetchrow(q, token, wallet)
        return int(row["balance"]) if row else 0

    async def set(self, token: str, wallet: str, bal: int):
        if self.db.db_type == "sqlite":
            await self.db.execute_dml(
                "INSERT INTO spatial_token_balances (token_address,wallet,balance) VALUES (?,?,?) "
                "ON CONFLICT(token_address,wallet) DO UPDATE SET balance = excluded.balance",
                token, wallet, int(bal))
        else:
            await self.db.execute_dml(
                "INSERT INTO spatial_token_balances (token_address,wallet,balance) VALUES ($1,$2,$3) "
                "ON CONFLICT(token_address,wallet) DO UPDATE SET balance = excluded.balance",
                token, wallet, int(bal))

    async def add(self, token: str, wallet: str, delta: int):
        await self.set(token, wallet, await self.get(token, wallet) + int(delta))

    async def get_all_for_token(self, token: str):
        q = "SELECT * FROM spatial_token_balances WHERE token_address = ?" \
            if self.db.db_type == "sqlite" else \
            "SELECT * FROM spatial_token_balances WHERE token_address = $1"
        return await self.db.fetch(q, token)



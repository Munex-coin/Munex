#!/usr/bin/env python3

# ─── Dependency bootstrap ────────────────────────────────────────────────────
# Runs before any third-party import below (aiohttp/websockets in the mega-import).
_DEPS = [
    ("yaml", "PyYAML", True),
    ("requests", "requests", True),
    ("rlp", "rlp", True),
    ("eth_utils", "eth-utils", True),
    ("eth_account", "eth-account", True),
    ("eth_keys", "eth-keys", True),
    ("cryptography", "cryptography", True),
    ("argon2", "argon2-cffi", True),
    ("bcrypt", "bcrypt", True),
    ("aiohttp", "aiohttp", True),
    ("websockets", "websockets", True),
    ("pythonjsonlogger", "python-json-logger", True),
    ("py_ecc", "py_ecc", True),
    ("psycopg2", "psycopg2-binary", False),
    ("asyncpg", "asyncpg", False),
    ("bip32utils", "bip32utils", False),
    ("uvloop", "uvloop", False),
    ("kademlia", "kademlia", False),
    ("Crypto", "pycryptodome", False),
]


def _ensure_dependencies() -> None:
    import os, sys
    if os.environ.get("MCX_SKIP_AUTO_INSTALL", "").strip().lower() in ("1", "true", "yes", "on"):
        print("[MCX] Dependency auto-install skipped (environment override).", file=sys.stderr)
        return
    try:
        import importlib.util as _ilu
    except Exception:
        return

    def _absent():
        out = []
        for imp, pip_name, required in _DEPS:
            if imp == "uvloop" and sys.platform == "win32":
                continue  # import is platform-gated below; no win32 wheels exist
            try:
                found = _ilu.find_spec(imp) is not None
            except Exception:
                found = False
            if not found:
                out.append((pip_name, required))
        return out

    missing = _absent()
    if not missing:
        return
    # DEPS-1: never pip-install silently (supply-chain safety). Installs are
    # opt-in via MCX_ALLOW_AUTO_INSTALL=1; without it we only report and exit
    # when REQUIRED packages are missing.
    allow_install = os.environ.get(
        "MCX_ALLOW_AUTO_INSTALL", "").strip().lower() in ("1", "true", "yes", "on")
    if not allow_install:
        required_missing = [p for p, req in missing if req]
        print("[MCX] Missing Python packages: " + ", ".join(p for p, _ in missing),
              file=sys.stderr)
        if required_missing:
            print("[MCX] FATAL: required packages missing: "
                  + ", ".join(required_missing), file=sys.stderr)
            print("[MCX] Auto-install is disabled by default (supply-chain safety). "
                  "Set MCX_ALLOW_AUTO_INSTALL=1 to permit pip installs, or install "
                  "the packages yourself.", file=sys.stderr)
            sys.exit(1)
        print("[MCX] Optional packages unavailable (some features stay disabled).",
              file=sys.stderr)
        return
    print("[MCX] Installing missing Python packages: " + ", ".join(p for p, _ in missing),
          file=sys.stderr)
    try:
        import subprocess
        # R9-deploy-pins (I-R8-12): install the PINNED manifest when it sits
        # next to the source (reproducible versions, including optionals —
        # converging the env, not just the missing piece). Bare names only
        # if the manifest is absent. Still strictly opt-in (gate above);
        # default remains fail-fast with actionable errors, before any
        # mainnet guard runs.
        _manifest = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                 "requirements-mcx78.txt")
        _pip_args = (["-r", _manifest] if os.path.exists(_manifest)
                     else [p for p, _ in missing])
        subprocess.run([sys.executable, "-m", "pip", "install", *_pip_args],
                       timeout=600)
    except Exception as e:
        print(f"[MCX] pip install error: {e}", file=sys.stderr)
    still_missing = _absent()
    required_missing = [p for p, req in still_missing if req]
    if required_missing:
        print("[MCX] FATAL: required packages still missing after install attempt: "
              + ", ".join(required_missing), file=sys.stderr)
        print("[MCX] Fix pip/network access and rerun, or set MCX_SKIP_AUTO_INSTALL=1 "
              "if you manage dependencies yourself.", file=sys.stderr)
        sys.exit(1)
    if still_missing:
        print("[MCX] Optional packages unavailable (some features stay disabled): "
              + ", ".join(p for p, _ in still_missing), file=sys.stderr)


_ensure_dependencies()
import sys, io, os, time, json, hashlib, hmac, secrets, random, struct, socket, subprocess, re, argparse, traceback, logging, base64, binascii, ipaddress, math, asyncio, aiohttp, websockets, signal, importlib, warnings, sqlite3, copy
# CONSENSUS-DETERMINISM: datetime was referenced by _prune_state_loop
# (datetime.fromtimestamp) but never imported; the NameError was swallowed
# by the surrounding try/except, silently disabling prune-completion
# logging. Import the class to match the call-site usage.
# CHANGELOG F-datetime.
from datetime import datetime
from collections import defaultdict, deque, OrderedDict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union, Any, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from enum import IntEnum
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from concurrent.futures.process import BrokenProcessPool  # R4-pool-rebuild
import multiprocessing as mp
import heapq
import tempfile

warnings.filterwarnings("default")
if sys.platform == 'win32':
    # DISCLOSED ADDITIVE FIX (Section 7): the previous
    # `sys.stdout = io.TextIOWrapper(sys.stdout.buffer, ...)` created a second
    # wrapper over the SAME buffer; when that wrapper was garbage-collected
    # (e.g. pytest restores the original stream at teardown) its finalizer
    # CLOSED the shared buffer, crashing capture teardown with
    # "ValueError: I/O operation on closed file". `reconfigure()` mutates the
    # existing wrapper in place instead, preserving the utf-8 intent without
    # taking ownership of the buffer.
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(encoding='utf-8')
        except Exception:
            pass

import requests
try:
    import rlp
except ImportError:
    rlp = None

try:
    from eth_utils import keccak as eth_keccak
except ImportError:
    import Crypto.Hash.keccak
    def eth_keccak(data: bytes) -> bytes:
        if isinstance(data, str):
            data = data.encode('utf-8')
        k = Crypto.Hash.keccak.new(digest_bits=256)
        k.update(data)
        return k.digest()
try:
    from eth_account import Account
except ImportError:
    Account = None
from cryptography.hazmat.primitives.asymmetric import ec
try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
    MLKEM_AVAILABLE = True
except (ImportError, AttributeError):
    mlkem = None
    MLKEM_AVAILABLE = False
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature, InvalidTag
try:
    from argon2 import PasswordHasher
except ImportError:
    PasswordHasher = None
try:
    import bcrypt
except ImportError:
    bcrypt = None
from logging.handlers import RotatingFileHandler
try:
    import psycopg2
    import psycopg2.extras
except ImportError:
    psycopg2 = None

try:
    import asyncpg
except ImportError:
    asyncpg = None
from urllib.parse import urlparse
try:
    import bip32utils
except ImportError:
    bip32utils = None
try:
    from pythonjsonlogger import jsonlogger
    class JsonFormatter(jsonlogger.JsonFormatter):
        def add_fields(self, log_record, record, message_dict):
            super().add_fields(log_record, record, message_dict)
            log_record['level'] = record.levelname
            log_record['timestamp'] = time.time()
except ImportError:
    class JsonFormatter(logging.Formatter):
        def format(self, record):
            return json.dumps({
                "timestamp": time.time(),
                "level": record.levelname,
                "name": record.name,
                "message": record.getMessage()
            })

log_handler = logging.StreamHandler()
log_handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] [%(trace_id)s] %(name)s: %(message)s'))
logger = logging.getLogger('mcx')
logger.setLevel(logging.DEBUG)
logger.addHandler(log_handler)

# ─── Trace-ID context ─────────────────────────────────────────────────
# Correlates log lines belonging to the same logical request. Set at the
# top of any async entry point; propagates to child tasks via contextvars.
trace_id_var: ContextVar[str] = ContextVar("mcx_trace_id", default="-")

def new_trace_id() -> str:
    return secrets.token_hex(8)

def set_trace_id(tid: Optional[str] = None) -> str:
    tid = tid or new_trace_id()
    trace_id_var.set(tid)
    return tid

class _TraceIdFilter(logging.Filter):
    """Injects the current trace ID into every log record."""
    def filter(self, record):
        try:
            record.trace_id = trace_id_var.get()
        except Exception:
            record.trace_id = "-"
        return True

_trace_filter = _TraceIdFilter()
for _h in list(logger.handlers):
    _h.addFilter(_trace_filter)

ph = PasswordHasher(time_cost=4, memory_cost=262144, parallelism=8, hash_len=32, salt_len=16) if PasswordHasher is not None else None

if sys.platform != 'win32':
    try:
        import uvloop
        asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    except ImportError:
        pass
HAVE_RESOURCE = sys.platform != 'win32'
if HAVE_RESOURCE:
    import resource

try:
    import yaml
except ImportError:
    print("[MCX] FATAL: PyYAML is required but not installed.", file=sys.stderr)
    print("[MCX] Run: pip install PyYAML  (or leave startup auto-install enabled "
          "instead of skipping it).", file=sys.stderr)
    sys.exit(1)
try:
    from logging.handlers import TimedRotatingFileHandler

    class SafeTimedRotatingFileHandler(TimedRotatingFileHandler):
        def doRollover(self):
            try:
                super().doRollover()
            except PermissionError:
                # Windows/OneDrive can briefly lock the active file during rotation.
                self.rolloverAt = self.computeRollover(time.time())

    file_handler = SafeTimedRotatingFileHandler('mcx.log', when='midnight', interval=1, backupCount=5)
    file_handler.setFormatter(JsonFormatter('%(timestamp)s %(level)s [%(trace_id)s] %(name)s %(message)s'))
    file_handler.addFilter(_trace_filter)
    # File log is production-grade (INFO); DEBUG diagnostics stay on the
    # console handler. Also required so shutdown-time DEBUG lines cannot
    # break Section 9.4's final-three-lines contract of mcx.log.
    file_handler.setLevel(logging.INFO)
    logger.addHandler(file_handler)
except Exception as e:
    logger.warning(f"File logging disabled: {e}")

# ─── Colours ──────────────────────────────────────────
RESET, GREEN, CYAN, YELLOW, RED, BOLD = "\033[0m","\033[92m","\033[96m","\033[93m","\033[91m","\033[1m"


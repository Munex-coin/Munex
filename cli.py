# Split of MCX81.py (lines 20237-20330). Logic unchanged; this header only
# adds imports so the moved code keeps its original namespace.

from node.bootstrap import GREEN, RESET, logger
from node.config import NAME, SYMBOL, VERSION, apply_consensus_config, load_config, validate_validators_config
from node.genesis import resolve_genesis_file
from node.core import MicroCoreNode
from node.bootstrap import argparse, asyncio, os, sys
from node import config as _config


# ─── Main Entry Point ──────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(description=f'{NAME} Node v{VERSION}')
    parser.add_argument('--config', type=str, default=_config.CONFIG_PATH, help='Path to config file')
    parser.add_argument('--wallet', type=str, help='Wallet address')
    parser.add_argument('--password', type=str, help='Password for encrypted private key')
    parser.add_argument('--external-ip', type=str, help='Public IP or hostname for P2P (overrides config)')
    parser.add_argument('--db-url', type=str, help='Database URL (overrides config)')
    parser.add_argument('--public-ip', type=str, help='Public IP for P2P (overrides auto-detect)')
    parser.add_argument('--no-dht', action='store_true', help='Disable DHT')
    parser.add_argument('--allow-new-genesis', action='store_true', help='DELIBERATE new-chain init (seed node only): create a genesis when none can be synced. NEVER use on joining nodes - they must copy genesis.json from the network instead.')
    parser.add_argument('--genesis-file', type=str, default=None, help='Path to the intended genesis file (overrides MCX_GENESIS_FILE env, node.genesis_file config, and the genesis.json default)')
    args = parser.parse_args()

    # Merge args with config
    config = load_config()
    if args.config:
        _config.CONFIG_PATH = args.config
        config = load_config()  # reload after config change
    if args.external_ip:
        config['node']['external_ip'] = args.external_ip
    if args.db_url:
        config['database'] = {'url': args.db_url}
    if args.public_ip:
        os.environ['MCX_PUBLIC_IP'] = args.public_ip
    if args.wallet:
        config['wallet'] = args.wallet
    if args.password:
        config['password'] = args.password
        # R4-password-cli: argv is visible in the process list — prefer MCX_PASSWORD.
        logger.warning("[Node] R4-password-cli: --password exposes the secret via the process list; prefer the MCX_PASSWORD environment variable")
    if args.no_dht:
        config['p2p']['dht_enabled'] = False

    # Override DHT enabled from config
    _config.DHT_ENABLED = config['p2p'].get('dht_enabled', True)

    # GENESIS-PATH-1: resolve the intended genesis file once (CLI > env >
    # config > default) so every loader/writer uses the same file. Logs the
    # winning source — a wrong-path genesis is a classic mismatch cause.
    _gen_src = "default genesis.json"
    if args.genesis_file:
        _gen_src = "--genesis-file CLI"
    elif (os.environ.get("MCX_GENESIS_FILE", "") or "").strip():
        _gen_src = "MCX_GENESIS_FILE env"
    elif isinstance(((config.get('node', {}) or {}).get('genesis_file', "")), str) and ((config.get('node', {}) or {}).get('genesis_file', "") or "").strip():
        _gen_src = "node.genesis_file config"
    _genesis.GENESIS_FILE = resolve_genesis_file(config, args.genesis_file)
    logger.info(f"[GENESIS] Using genesis file {os.path.abspath(_genesis.GENESIS_FILE)} (source: {_gen_src})")

    # GENESIS-VAL-2: refuse malformed validator configuration BEFORE anything
    # derives a ruleset from it (fail closed, never silent open mode).
    try:
        validate_validators_config(_config.VALIDATORS)
        validate_validators_config((config.get('consensus') or {}).get('validators'))
    except ValueError as _ve:
        logger.error(f"[CONFIG] {_ve}; refusing to start")
        sys.exit(1)

    # R9-consensus-config (I-R8-07): align import-time consensus globals
    # with the CLI-selected effective config before anything validates.
    # CONFIG-VALID-1: invalid supplied values fail closed here with a clear
    # error (never a traceback, never silent import-time retention).
    try:
        apply_consensus_config(config)
    except ValueError as _ve:
        logger.error(f"[CONFIG] {_ve}; refusing to start")
        sys.exit(1)

    # Create node
    node = MicroCoreNode(config)
    node._allow_new_genesis = args.allow_new_genesis

    print(f"\n{'='*60}")
    print(f"{GREEN}{NAME} ({SYMBOL}) COMPLETE NODE v{VERSION}{RESET}")
    print(f"{'='*60}")
    print(f"Node ID: {node.node_id[:16]}...")
    print(f"Wallet: {node.wallet}")
    print(f"Height: {node.height}")
    print(f"Peers: {node.p2p.get_peer_count() if node.p2p else 0}")
    print(f"Miners: {len(node.miners)}")
    print(f"{'='*60}\n")

    try:
        await node.start()
    except asyncio.CancelledError:
        logger.info("[Node] Cancelled")
    finally:
        await node.shutdown()



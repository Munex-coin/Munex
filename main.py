#!/usr/bin/env python3
"""Entry point: run the whole node package at once.

Usage:
    python node/main.py [node args...]     (from anywhere)
    python -m node [node args...]          (from the folder above node/)
"""
import os as _os
import sys as _sys
_sys.path.insert(0, _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__))))
from node.bootstrap import RED, RESET, asyncio, sys, traceback
from node.cli import main


def run():
    try:
        if sys.platform == 'win32':
            import ctypes
            def _win_ctrl_handler(dw):
                if dw in (0, 1):
                    ctypes.pythonapi.PyErr_SetInterrupt()
                    return True
                return False
            _win_ctrl_cb = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int)(
                _win_ctrl_handler)
            ctypes.windll.kernel32.SetConsoleCtrlHandler(_win_ctrl_cb, True)
        asyncio.run(main())
    except KeyboardInterrupt:
        print('\n[SHUTDOWN] Interrupted by user')
        sys.exit(0)
    except Exception as e:
        print(f'\n{RED}[ERROR] {e}{RESET}')
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    run()

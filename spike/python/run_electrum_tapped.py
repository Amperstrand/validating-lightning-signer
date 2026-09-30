#!/usr/bin/env python3
"""Run the Electrum daemon with the VLS tap installed (live mirror mode).

Usage: run_electrum_tapped.py <normal electrum daemon arguments>
Env:   VLS_BRIDGE_SOCKET - unix socket of the vls_bridge (default /tmp/vls-m5-bridge.sock)
"""

import os
import runpy
import sys

HERE = os.path.dirname(os.path.realpath(__file__))
ELECTRUM_SRC = os.environ.get("ELECTRUM_SRC", "/tmp/opencode/electrum")
sys.path.insert(0, ELECTRUM_SRC)
sys.path.insert(0, HERE)

from electrum_tap import ElectrumTap, SyncBridgeClient

socket_path = os.environ.get("VLS_BRIDGE_SOCKET", "/tmp/vls-m5-bridge.sock")
tap = ElectrumTap(SyncBridgeClient(socket_path), live=True)
tap.install()
print(f"tap: live mode installed, bridge={socket_path}", flush=True)

sys.argv = [os.path.join(ELECTRUM_SRC, "run_electrum")] + sys.argv[1:]
runpy.run_path(sys.argv[0], run_name="__main__")

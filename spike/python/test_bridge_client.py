#!/usr/bin/env python3
"""Smoke test: drive the vls-bridge binary from Python over its Unix socket.

Asserts the same KAT vector values as the Rust e2e (tests/bridge_e2e.rs),
proving the Python/Electrum-shaped consumer path end-to-end.
"""

import argparse
import asyncio
import json
import os
import signal
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_BINARIES = [
    os.environ.get("VLS_BRIDGE_BIN", ""),
    str(Path.home() / "validating-lightning-signer/target/debug/vls_bridge"),
    str(SCRIPT_DIR.parent.parent / "target/debug/vls_bridge"),
]


def find_binary(explicit: str | None) -> str:
    candidates = [explicit] if explicit else [p for p in DEFAULT_BINARIES if p]
    for path in candidates:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    raise SystemExit(f"vls_bridge binary not found; tried: {candidates}")


def fabricated_pubkey(electrum_src: str, label: str) -> str:
    sys.path.insert(0, electrum_src)
    from electrum.crypto import sha256
    from electrum.lnutil import secret_to_pubkey

    return secret_to_pubkey(int.from_bytes(sha256(label.encode()), "big")).hex()


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=None)
    parser.add_argument("--vectors", default=str(SCRIPT_DIR.parent / "tests" / "vectors" / "electrum_kat.json"))
    parser.add_argument("--electrum-src", default="/tmp/opencode/electrum")
    args = parser.parse_args()

    binary = find_binary(args.binary)
    vectors = json.loads(Path(args.vectors).read_text())
    case = vectors["cases"][0]

    socket_path = os.path.join(tempfile.mkdtemp(prefix="vls-bridge-smoke-"), "bridge.sock")
    proc = subprocess.Popen(
        [binary, socket_path, case["wallet_seed"], "regtest"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        for _ in range(100):
            if os.path.exists(socket_path):
                break
            if proc.poll() is not None:
                raise SystemExit(f"bridge died: {proc.stderr.read().decode()}")
            time.sleep(0.05)
        else:
            raise SystemExit("bridge socket never appeared")

        from vls_client import VlsBridgeClient

        client = await VlsBridgeClient(socket_path).connect()

        info = await client.call("node_info")
        assert info["node_id"] == case["node_key"]["pubkey"], info
        print("node_info.node_id == Electrum node_key  OK")

        new_channel = await client.call("new_channel", {"channel_seed": case["channel_seed"]})
        pubkeys = new_channel["pubkeys"]
        assert pubkeys["funding_pubkey"] == case["multisig_key"]["pubkey"], pubkeys
        assert pubkeys["htlc_basepoint"] == case["htlc_basepoint"]["pubkey"], pubkeys
        assert pubkeys["delayed_payment_basepoint"] == case["delayed_basepoint"]["pubkey"], pubkeys
        assert pubkeys["revocation_basepoint"] == case["revocation_basepoint"]["pubkey"], pubkeys
        print("new_channel pubkeys == Electrum basepoints  OK")
        channel_id = new_channel["channel_id"]

        funding_txid = bytes([2] + [1] * 31)[::-1].hex()
        await client.call(
            "setup_channel",
            {
                "channel_id": channel_id,
                "is_outbound": True,
                "channel_value_sat": 123456,
                "push_value_msat": 0,
                "funding_txid": funding_txid,
                "funding_vout": 1,
                "holder_selected_contest_delay": 10,
                "counterparty_selected_contest_delay": 11,
                "commitment_type": "StaticRemoteKey",
                "counterparty_points": {
                    "funding_pubkey": fabricated_pubkey(args.electrum_src, "cp funding"),
                    "revocation_basepoint": fabricated_pubkey(args.electrum_src, "cp revocation"),
                    "payment_point": fabricated_pubkey(args.electrum_src, "cp payment"),
                    "delayed_payment_basepoint": fabricated_pubkey(args.electrum_src, "cp delayed"),
                    "htlc_basepoint": fabricated_pubkey(args.electrum_src, "cp htlc"),
                },
            },
        )
        await client.call(
            "confirm_funding_lock",
            {"channel_id": channel_id, "funding_txid": funding_txid, "funding_vout": 1},
        )
        print("setup_channel + confirm_funding_lock  OK")

        for entry in case["shachain"][:2]:
            ctn = entry["ctn"]
            result = await client.call(
                "get_per_commitment_point", {"channel_id": channel_id, "ctn": ctn}
            )
            assert result["point"] == entry["point"], (ctn, result, entry["point"])
        print("per-commitment points ctn 0,1 == Electrum shachain points  OK")

        await client.close()
        print("SMOKE PASS")
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)


if __name__ == "__main__":
    asyncio.run(main())

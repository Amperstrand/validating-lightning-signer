#!/usr/bin/env python3
"""M3 harness: real Electrum channels (built by Electrum's own test helpers)
mirrored into the vls-bridge through the tap. Zero divergences = the mirror
holds across Electrum's live channel state machine, not just static KATs.
"""

import argparse
import asyncio
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


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=None)
    parser.add_argument("--electrum-src", default="/tmp/opencode/electrum")
    args = parser.parse_args()

    binary = find_binary(args.binary)
    sys.path.insert(0, args.electrum_src)

    from tests.lnhelpers import _create_mock_lnwallet, create_test_channels
    from electrum.lnutil import LOCAL

    from electrum_tap import ElectrumTap, SyncBridgeClient

    base = tempfile.mkdtemp(prefix="vls-tap-")
    alice_wallet = _create_mock_lnwallet(
        name="alice", has_anchors=True, data_dir=os.path.join(base, "alice")
    )
    bob_wallet = _create_mock_lnwallet(
        name="bob", has_anchors=True, data_dir=os.path.join(base, "bob")
    )
    alice_channel, bob_channel = create_test_channels(
        alice_lnwallet=alice_wallet,
        bob_lnwallet=bob_wallet,
        random_seed=os.urandom(32),
    )

    socket_path = os.path.join(base, "bridge.sock")
    proc = subprocess.Popen(
        [binary, socket_path, "11" * 32, "regtest"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    client = None
    tap = None
    try:
        for _ in range(100):
            if os.path.exists(socket_path):
                break
            if proc.poll() is not None:
                raise SystemExit(f"bridge died: {proc.stderr.read().decode()}")
            time.sleep(0.05)
        else:
            raise SystemExit("bridge socket never appeared")

        client = SyncBridgeClient(socket_path)
        tap = ElectrumTap(client)
        tap.install()
        tap.register_channel(alice_channel, name="alice")
        tap.register_channel(bob_channel, name="bob")
        print("registered channels; basepoint comparisons done")

        for ctn in range(3):
            alice_channel.get_secret_and_point(LOCAL, ctn)
            bob_channel.get_secret_and_point(LOCAL, ctn)

        sig_64, htlc_sigs = alice_channel.sign_next_commitment()
        bob_channel.receive_new_commitment(sig_64, htlc_sigs)
        bob_revocation = bob_channel.revoke_current_commitment()
        alice_channel.receive_revocation(bob_revocation)
        alice_channel.get_secret_and_point(LOCAL, 1)

        print(f"commitment round done; {tap.comparisons} point comparisons")
        if tap.divergences:
            for d in tap.divergences:
                print(f"DIVERGENCE: {d}")
            raise SystemExit(f"{len(tap.divergences)} divergences")
        print("TAP PASS — 0 divergences")
    finally:
        if tap is not None:
            tap.uninstall()
        if client is not None:
            client.close()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=5)
        for lnwallet in (alice_wallet, bob_wallet):
            try:
                await lnwallet.stop()
                await lnwallet.wallet.stop()
            except Exception as exc:
                print(f"wallet stop noise: {exc!r}", file=sys.stderr)


if __name__ == "__main__":
    asyncio.run(main())

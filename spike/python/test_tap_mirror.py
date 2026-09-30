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


def build_witscripts(chan, counterparty_chan, commitment, ctn, pcp):
    import hashlib

    from electrum import lnutil
    from electrum.lnutil import LOCAL, REMOTE

    local = chan.config[LOCAL]
    remote = chan.config[REMOTE]
    # both basepoint-party assignments and both delay sources are candidates;
    # the sha256 program match decides
    to_local_candidates = [
        lnutil.make_commitment_output_to_local_witness_script(
            lnutil.derive_blinded_pubkey(rev_base, pcp),
            delay,
            lnutil.derive_pubkey(delayed_base, pcp),
        )
        for rev_base, delayed_base in (
            (local.revocation_basepoint.pubkey, remote.delayed_basepoint.pubkey),
            (remote.revocation_basepoint.pubkey, local.delayed_basepoint.pubkey),
        )
        for delay in (remote.to_self_delay, local.to_self_delay)
    ]
    candidates = to_local_candidates + [
        lnutil.make_commitment_output_to_remote_witness_script(remote.payment_basepoint.pubkey),
        lnutil.make_commitment_output_to_remote_witness_script(local.payment_basepoint.pubkey),
        lnutil.make_commitment_output_to_anchor_witness_script(remote.multisig_key.pubkey),
        lnutil.make_commitment_output_to_anchor_witness_script(local.multisig_key.pubkey),
    ]
    witscripts = []
    for idx, o in enumerate(commitment.outputs()):
        spk = o.scriptpubkey
        match = b""
        if len(spk) == 34 and spk[0] == 0x00 and spk[1] == 0x20:
            program = spk[2:]
            for cand in candidates:
                if hashlib.sha256(cand).digest() == program:
                    match = cand
                    break
            if not match:
                print(f"PROBE-DIAG output[{idx}] value={o.value} program={program.hex()}")
                for cidx, cand in enumerate(candidates):
                    print(
                        f"PROBE-DIAG   candidate[{cidx}] sha256={hashlib.sha256(cand).digest().hex()}"
                    )
        witscripts.append(match.hex())
    return witscripts


async def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=None)
    parser.add_argument("--electrum-src", default="/tmp/opencode/electrum")
    args = parser.parse_args()

    binary = find_binary(args.binary)
    sys.path.insert(0, args.electrum_src)

    from tests.lnhelpers import _create_mock_lnwallet, create_test_channels
    from electrum.lnutil import LOCAL, REMOTE

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

        tap.mirror_channel_setup(alice_channel, "alice")
        print("mirrored alice channel setup into bridge")

        commitment = alice_channel.get_next_commitment(REMOTE)
        # commitment locktimes mix in funding-locktime privacy bits, so the
        # authoritative number is the HTLC manager's counter
        commitment_ctn = alice_channel.get_next_ctn(REMOTE)
        # the counterparty's pcp derived from its own seed — alice's
        # next_per_commitment_point tracking cannot be trusted over the source
        from electrum import lnutil as _lnutil

        pcp_bytes = _lnutil.secret_to_pubkey(
            int.from_bytes(
                _lnutil.get_per_commitment_secret_from_seed(
                    bob_channel.config[LOCAL].per_commitment_secret_seed,
                    _lnutil.RevocationStore.START_INDEX - commitment_ctn,
                ),
                "big",
            )
        )
        per_commitment_point = pcp_bytes.hex()

        witscripts = build_witscripts(alice_channel, bob_channel, commitment, commitment_ctn, pcp_bytes)

        tap.sync_commitment_state(alice_channel, commitment_ctn, per_commitment_point)
        sig_64, htlc_sigs = alice_channel.sign_next_commitment()
        tap.compare_counterparty_signature_raw(
            alice_channel,
            "alice",
            sig_64,
            commitment,
            witscripts,
            per_commitment_point,
            commitment_ctn,
            6000,
        )
        print(f"signature cross-check done at ctn={commitment_ctn}")

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

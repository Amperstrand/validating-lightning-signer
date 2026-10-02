"""Monkey-patch tap mirroring real Electrum Channel calls into the vls-bridge.

Taps `Channel.get_secret_and_point` (fires during signing, revocation and
sweeps) and compares Electrum's per-commitment points against the bridge's.
The tapped methods are synchronous, so this module carries its own
synchronous JSON-lines client; the asyncio client in vls_client.py is for the
future Electrum plugin.
"""

import json
import os
import socket


class SyncBridgeClient:
    def __init__(self, path: str):
        self.path = path
        self.sock = None
        self.f = None
        self._id = 0

    def _connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(self.path)
        self.f = self.sock.makefile("rwb")

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        request = {"id": self._id, "method": method, "params": params or {}}
        for attempt in (0, 1):
            if self.f is None:
                self._connect()
            try:
                self.f.write((json.dumps(request) + "\n").encode())
                self.f.flush()
                line = self.f.readline()
                if not line:
                    raise RuntimeError(f"bridge closed connection during {method}")
                response = json.loads(line)
                if "error" in response:
                    raise RuntimeError(f"{method}: {response['error']}")
                return response.get("result", {})
            except (BrokenPipeError, OSError):
                self.f = None
                self.sock = None
                if attempt:
                    raise

    def close(self) -> None:
        if self.f is not None:
            self.f.close()
        if self.sock is not None:
            self.sock.close()


from derivation_auditor import DerivationAuditor


class ElectrumTap:
    def __init__(self, client: SyncBridgeClient, live: bool = False):
        self.client = client
        self.live = live
        self.bridge_channels: dict[str, str] = {}
        self.divergences: list[str] = []
        self.comparisons = 0
        self._original_get_secret_and_point = None
        self._original_sign_next_commitment = None
        self._original_receive_revocation = None
        self.auditor = DerivationAuditor(client)
        self.auditor.tap = self
        self.gate_enabled = os.environ.get("VLS_GATE") == "1"
        self.fault_inject = os.environ.get("VLS_FAULT", "")
        self.gate_log = []

    def install(self) -> None:
        from electrum.lnchannel import Channel
        from electrum.lnutil import LOCAL

        original = Channel.get_secret_and_point
        tap = self

        def get_secret_and_point(chan, subject, ctn, *args, **kwargs):
            if subject == LOCAL and tap.live:
                try:
                    tap.ensure_registered(chan)
                except Exception as exc:
                    tap.divergences.append(f"{name_of(chan)} live-register: {exc!r}")
            secret, point = original(chan, subject, ctn, *args, **kwargs)
            if subject == LOCAL:
                try:
                    tap.compare_point(chan, ctn, point)
                except Exception as exc:
                    tap.divergences.append(f"{name_of(chan)} ctn={ctn}: tap error: {exc!r}")
            return secret, point

        Channel.get_secret_and_point = get_secret_and_point
        self._original_get_secret_and_point = original

        if self.live:
            import electrum.lnsweep as lnsweep_mod
            from electrum.lnutil import REMOTE as REMOTE_CONST

            extract_original = lnsweep_mod.extract_ctx_secrets

            def extract_ctx_secrets(chan, ctx):
                result = extract_original(chan, ctx)
                try:
                    from electrum.lnutil import extract_ctn_from_tx_and_chan
                    ctn = extract_ctn_from_tx_and_chan(ctx, chan)
                    oldest = chan.get_oldest_unrevoked_ctn(REMOTE_CONST)
                    if result is None:
                        print(f"tap: CTN ctn={ctn} oldest_unrevoked={oldest} → None (derivation failed)", flush=True)
                    else:
                        _, _, is_rev, _ = result
                        cls = "BREACH" if is_rev else ("current" if ctn == oldest else "next" if ctn == oldest + 1 else "other")
                        print(f"tap: CTN ctn={ctn} oldest_unrevoked={oldest} → {cls}", flush=True)
                except Exception as exc:
                    print(f"tap: CTN-diag {exc!r}", flush=True)
                return result

            lnsweep_mod.extract_ctx_secrets = extract_ctx_secrets
            self._original_extract = extract_original

            justice_original = lnsweep_mod.sweep_their_ctx_justice

            def sweep_their_ctx_justice(chan, ctx, per_commitment_secret):
                print(f"tap: justice wrap CALLED for {name_of(chan)}", flush=True)
                tap.cross_check_justice(chan, ctx, per_commitment_secret)
                return justice_original(chan, ctx, per_commitment_secret)

            lnsweep_mod.sweep_their_ctx_justice = sweep_their_ctx_justice
            self._original_justice = justice_original

            htlc_justice_original = lnsweep_mod.sweep_their_htlctx_justice

            def sweep_their_htlctx_justice(chan, ctx, htlc_tx):
                result = htlc_justice_original(chan, ctx, htlc_tx)
                n = len(result) if isinstance(result, dict) else 0
                print(f"tap: HTLC-justice wrap CALLED for {name_of(chan)}: {n} sweep infos", flush=True)
                if n:
                    for prevout, info in result.items():
                        print(f"tap: HTLC-justice sweep {info.name} {prevout}", flush=True)
                return result

            lnsweep_mod.sweep_their_htlctx_justice = sweep_their_htlctx_justice
            self._original_htlc_justice = htlc_justice_original

            sign_original = Channel.sign_next_commitment

            def sign_next_commitment(chan, *args, **kwargs):
                capture = tap.capture_commitment(chan)
                if capture is not None and tap.gate_enabled and not tap.gate_approve(chan, capture):
                    raise RuntimeError("VLS gate rejected the commitment; signature suppressed")
                sig_64, htlc_sigs = sign_original(chan, *args, **kwargs)
                if capture is not None:
                    tap.cross_check_signature(chan, sig_64, capture)
                return sig_64, htlc_sigs

            Channel.sign_next_commitment = sign_next_commitment
            self._original_sign_next_commitment = sign_original

            revoke_original = Channel.receive_revocation

            def receive_revocation(chan, revocation, *args, **kwargs):
                result = revoke_original(chan, revocation, *args, **kwargs)
                tap.validate_revocation(chan, revocation)
                try:
                    tap.auditor.checkpoint_commitment(chan)
                except Exception as exc:
                    print(f"tap: auditor checkpoint failed: {exc}", flush=True)
                return result

            Channel.receive_revocation = receive_revocation
            self._original_receive_revocation = revoke_original

    def uninstall(self) -> None:
        from electrum.lnchannel import Channel

        if self._original_get_secret_and_point is not None:
            Channel.get_secret_and_point = self._original_get_secret_and_point
            self._original_get_secret_and_point = None
        if self._original_sign_next_commitment is not None:
            Channel.sign_next_commitment = self._original_sign_next_commitment
            self._original_sign_next_commitment = None
        if getattr(self, "_original_receive_revocation", None) is not None:
            Channel.receive_revocation = self._original_receive_revocation
            self._original_receive_revocation = None
        if getattr(self, "_original_htlc_justice", None) is not None:
            from electrum import lnsweep as lnsweep_uninstall

            lnsweep_uninstall.sweep_their_htlctx_justice = self._original_htlc_justice
            self._original_htlc_justice = None

    def validate_revocation(self, chan, revocation) -> None:
        from electrum.lnutil import LOCAL, REMOTE

        try:
            self.ensure_registered(chan)
            key = chan.config[LOCAL].channel_seed.hex()
            bridge_channel_id = self.bridge_channels.get(key)
            if bridge_channel_id is None:
                print("tap: justice skipped (channel not in bridge)", flush=True)
                return
            # the revealed secret is for the remote's CURRENT point, i.e.
            # electrum ctn; VLS numbering is electrum ctn + 1
            revoke_num = chan.get_latest_ctn(REMOTE) + 1
            self.client.call(
                "validate_counterparty_revocation",
                {
                    "channel_id": bridge_channel_id,
                    "revoke_num": revoke_num,
                    "secret": revocation.per_commitment_secret.hex(),
                },
            )
            print(f"tap: revocation validated ctn={revoke_num}", flush=True)
        except Exception as exc:
            self.divergences.append(f"{name_of(chan)} revocation: {exc!r}")
            print(f"tap: REVOCATION-FAIL {name_of(chan)}: {exc!r}", flush=True)

    def cross_check_justice(self, chan, ctx, per_commitment_secret) -> None:
        """Synthetic comparison: build a fixed sweep of the revoked to_local,
        sign it on both sides, verify VLS's signature over electrum's sighash."""
        print("tap: cross_check_justice ENTERED", flush=True)
        from electrum import bitcoin as ebitcoin
        from electrum import lnutil
        from electrum.crypto import sha256, sha256d
        from electrum.lnutil import LOCAL, REMOTE
        from electrum_ecc import ECPubkey
        from electrum.transaction import PartialTransaction, PartialTxInput, PartialTxOutput

        try:
            self.ensure_registered(chan)
            self.auditor.checkpoint_justice(chan, ctx, per_commitment_secret)
            key = chan.config[LOCAL].channel_seed.hex()
            bridge_channel_id = self.bridge_channels.get(key)
            if bridge_channel_id is None:
                print("tap: justice skipped (not in bridge after register)", flush=True)
                return
            pcp = lnutil.secret_to_pubkey(
                int.from_bytes(per_commitment_secret, "big")
            )
            # electrum's own derivation (lnsweep.sweep_their_ctx_justice)
            our_rev_priv = lnutil.derive_blinded_privkey(
                chan.config[LOCAL].revocation_basepoint.privkey,
                per_commitment_secret,
            )
            this_delayed_pub = lnutil.derive_pubkey(
                chan.config[REMOTE].delayed_basepoint.pubkey, pcp
            )
            # electrum's own derivation (lnsweep.sweep_their_ctx_justice):
            # to_self_delay comes from the NON-broadcaster (LOCAL/us) — the
            # delay we impose on them for their to_local
            witness_script = lnutil.make_commitment_output_to_local_witness_script(
                lnutil.secret_to_pubkey(int.from_bytes(our_rev_priv, "big")),
                chan.config[LOCAL].to_self_delay,
                this_delayed_pub,
            )
            program = sha256(witness_script)
            spk = bytes([0x00, 0x20]) + program
            # electrum's own derivation for comparison
            from electrum.lnutil import derive_blinded_pubkey, derive_pubkey
            from electrum import bitcoin as btc_mod
            electrum_rev_pub = derive_blinded_pubkey(
                chan.config[LOCAL].revocation_basepoint.pubkey, pcp
            )
            electrum_delayed = derive_pubkey(
                chan.config[REMOTE].delayed_basepoint.pubkey, pcp
            )
            electrum_script = lnutil.make_commitment_output_to_local_witness_script(
                electrum_rev_pub,
                chan.config[LOCAL].to_self_delay,
                electrum_delayed,
            )
            electrum_spk = bytes([0x00, 0x20]) + sha256(electrum_script)
            if electrum_spk != spk:
                print(f"tap: SCRIPT-MISMATCH mine={witness_script.hex()}", flush=True)
                print(f"tap: SCRIPT-MISMATCH electrum={electrum_script.hex()}", flush=True)
            else:
                print(f"tap: SCRIPT-AGREE spk={spk.hex()}", flush=True)
                for i, o in enumerate(ctx.outputs()):
                    if o.scriptpubkey == spk:
                        print(f"tap: FOUND at out[{i}] val={o.value}", flush=True)
                        break
            # compare both derivation paths for the revocation pubkey
            from electrum.lnutil import derive_blinded_pubkey
            rev_pub_from_priv = lnutil.secret_to_pubkey(int.from_bytes(our_rev_priv, "big"))
            rev_pub_from_pub = derive_blinded_pubkey(
                chan.config[LOCAL].revocation_basepoint.pubkey, pcp
            )
            if rev_pub_from_priv != rev_pub_from_pub:
                print(f"tap: REV-KEY-MISMATCH priv_path={rev_pub_from_priv.hex()} pub_path={rev_pub_from_pub.hex()}", flush=True)
            output_idx = None
            amount = None
            for i, o in enumerate(ctx.outputs()):
                if o.scriptpubkey == spk:
                    output_idx, amount = i, o.value
                    break
            if output_idx is None:
                print(f"tap: SPK-DIFF derived={spk.hex()}", flush=True)
                print(f"tap: SPK-DIFF pcp={pcp.hex()}", flush=True)
                print(f"tap: SPK-DIFF delay={chan.config[LOCAL].to_self_delay} script={witness_script.hex()}", flush=True)
                for i, o in enumerate(ctx.outputs()):
                    print(f"tap: SPK-DIFF out[{i}]={o.scriptpubkey.hex()} val={o.value}", flush=True)
                print("tap: justice cross-check skipped (to_local not found)", flush=True)
                return
            from electrum.bitcoin import address_to_script
            dest = address_to_script(
                ebitcoin.pubkey_to_address("p2wpkh", chan.config[LOCAL].payment_basepoint.pubkey.hex())
            )
            from electrum.transaction import TxOutpoint
            txin = PartialTxInput(prevout=TxOutpoint(txid=ctx.txid(), out_idx=output_idx))
            txin.witness_script = witness_script
            txin.privkey = our_rev_priv
            txin.block_height = 0
            sweep = PartialTransaction(
                inputs=[txin],
                outputs=[PartialTxOutput(scriptpubkey=dest, value=amount - 1000)],
                locktime=0,
                version=2,
            )
            pre_hash = sweep.serialize_preimage(0)
            msg_hash = sha256d(pre_hash)
            electrum_sig = sweep.sign_txin(0, our_rev_priv)
            tx_hex = sweep.serialize_to_network(include_sigs=False)
            result = self.client.call(
                "sign_justice_sweep",
                {
                    "channel_id": bridge_channel_id,
                    "tx": tx_hex,
                    "input": 0,
                    "revocation_secret": per_commitment_secret.hex(),
                    "redeemscript": witness_script.hex(),
                    "amount_sat": amount,
                },
            )
            vls_sig = bytes.fromhex(result["signature"])
            # verify VLS's signature over electrum's sighash with electrum's derived pubkey
            rev_pub = lnutil.secret_to_pubkey(int.from_bytes(our_rev_priv, "big"))
            if not ECPubkey(rev_pub).ecdsa_verify(vls_sig, msg_hash):
                self.divergences.append(
                    f"{name_of(chan)} justice: VLS sig does not verify against electrum sighash"
                )
                print("tap: JUSTICE-DIVERGENCE — VLS sig invalid over electrum sighash", flush=True)
            else:
                self.comparisons += 1
                print(
                    f"tap: justice cross-checked (vls sig verifies, out={amount}) "
                    f"comparisons={self.comparisons}",
                    flush=True,
                )
        except Exception as exc:
            self.divergences.append(f"{name_of(chan)} justice cross-check: {exc!r}")
            print(f"tap: JUSTICE-FAIL {name_of(chan)}: {exc!r}", flush=True)

    def ensure_registered(self, chan) -> None:
        from electrum.lnutil import LOCAL

        if chan.config[LOCAL].channel_seed.hex() in self.bridge_channels:
            return
        name = name_of(chan)
        self.register_channel(chan, name)
        self.mirror_channel_setup(chan, name)
        # a live channel registers mid-life: fast-forward the bridge's
        # numbering to the channel's current counters
        holder_num = chan.hm.log[LOCAL]["ctn"]
        sync_point = self.bridge_channels.get(chan.config[LOCAL].channel_seed.hex())
        if sync_point is None:
            return
        from electrum import lnutil
        from electrum.lnutil import REMOTE

        pcp = chan.config[REMOTE].next_per_commitment_point
        self.client.call(
            "sync_commitment_state",
            {
                "channel_id": sync_point,
                "commit_num": holder_num,
                "revoke_num": max(holder_num - 1, 0),
                "holder_commit_num": holder_num,
                "per_commitment_point": pcp.hex(),
            },
        )
        print(f"tap: live-registered channel {name} (holder ctn={holder_num})", flush=True)

    def capture_commitment(self, chan):
        from electrum.lnutil import LOCAL, REMOTE

        try:
            self.ensure_registered(chan)
            commitment = chan.get_next_commitment(REMOTE)
            return {
                "commitment": commitment,
                "ctn": chan.get_next_ctn(REMOTE),
                "pcp": chan.config[REMOTE].next_per_commitment_point,
                "witscripts": build_witscripts(chan, commitment, chan.config[REMOTE].next_per_commitment_point),
                "feerate": chan.hm.get_feerate_in_next_ctx(REMOTE),
            }
        except Exception as exc:
            self.divergences.append(f"{name_of(chan)} capture: {exc!r}")
            print(f"tap: CAPTURE-FAIL {name_of(chan)}: {exc!r}", flush=True)
            return None

    def cross_check_signature(self, chan, sig_64: bytes, capture: dict) -> None:
        try:
            self.sync_commitment_state(chan, capture["ctn"], capture["pcp"].hex())
            self.compare_counterparty_signature_raw(
                chan,
                name_of(chan),
                sig_64,
                capture["commitment"],
                capture["witscripts"],
                capture["pcp"].hex(),
                capture["ctn"],
                capture["feerate"],
            )
            print(
                f"tap: signature cross-checked ctn={capture['ctn']} "
                f"comparisons={self.comparisons} divergences={len(self.divergences)}",
                flush=True,
            )
        except Exception as exc:
            self.divergences.append(f"{name_of(chan)} cross-check: {exc!r}")
            print(f"tap: CROSSCHECK-FAIL {name_of(chan)}: {exc!r}", flush=True)
        if self.divergences:
            print(f"tap: DIVERGENCES ({len(self.divergences)}):", flush=True)
            for d in self.divergences[-5:]:
                print(f"tap:   {d}", flush=True)

    def gate_approve(self, chan, capture) -> bool:
        from electrum.lnutil import LOCAL

        try:
            self.sync_commitment_state(chan, capture["ctn"], capture["pcp"].hex())
            bridge_channel_id = self.bridge_channels[chan.config[LOCAL].channel_seed.hex()]
            params = {
                "channel_id": bridge_channel_id,
                "tx": capture["commitment"].serialize_to_network(include_sigs=False),
                "witscripts": capture["witscripts"],
                "per_commitment_point": capture["pcp"].hex(),
                "ctn": capture["ctn"],
                "feerate_per_kw": capture["feerate"],
            }
            if self.fault_inject == "stale_ctn":
                params["ctn"] = max(0, params["ctn"] - 10)
            elif self.fault_inject == "tamper_tx":
                raw = bytearray(bytes.fromhex(params["tx"]))
                raw[len(raw) * 3 // 4] ^= 0x02
                params["tx"] = bytes(raw).hex()
            result = self.client.call("sign_counterparty_commitment_raw", params)
            if not isinstance(result, dict) or "signature" not in result:
                self._gate_closed(f"no signature in result: {result!r}")
                return False
        except Exception as exc:
            self._gate_closed(f"{exc!r}")
            return False
        self.gate_log.append({"decision": "open", "ctn": capture["ctn"], "fault": self.fault_inject or None})
        print(f"GATE: open ctn={capture['ctn']}", flush=True)
        self._write_gate_log()
        return True

    def _gate_closed(self, reason) -> None:
        self.gate_log.append(
            {"decision": "closed", "reason": str(reason)[:300], "fault": self.fault_inject or None}
        )
        print(f"GATE: CLOSED — {reason}", flush=True)
        self._write_gate_log()

    def _write_gate_log(self) -> None:
        with open("/tmp/vls-gate.jsonl", "a") as f:
            f.write(json.dumps(self.gate_log[-1]) + "\n")

    def register_channel(self, chan, name: str) -> str:
        from electrum.lnutil import LOCAL

        local = chan.config[LOCAL]
        # anchors channels derive the funding key from the wallet
        # funding_root_secret, so the live wallet's real key must be injected
        result = self.client.call(
            "new_channel",
            {
                "channel_seed": local.channel_seed.hex(),
                "funding_privkey": local.multisig_key.privkey.hex(),
                "payment_privkey": local.payment_basepoint.privkey.hex(),
            },
        )
        expected = {
            "funding_pubkey": local.multisig_key.pubkey.hex(),
            "htlc_basepoint": local.htlc_basepoint.pubkey.hex(),
            "delayed_payment_basepoint": local.delayed_basepoint.pubkey.hex(),
            "revocation_basepoint": local.revocation_basepoint.pubkey.hex(),
            "payment_point": local.payment_basepoint.pubkey.hex(),
        }
        for field, want in expected.items():
            got = result["pubkeys"][field]
            if got != want:
                self.divergences.append(f"{name} basepoint {field}: bridge {got} != electrum {want}")
        # both sides of a channel share channel_id (it derives from the funding
        # outpoint), so the registry is keyed by channel_seed instead
        self.bridge_channels[local.channel_seed.hex()] = result["channel_id"]
        return result["channel_id"]

    def mirror_channel_setup(self, chan, name: str) -> None:
        from electrum.lnutil import LOCAL, REMOTE

        local = chan.config[LOCAL]
        remote = chan.config[REMOTE]
        outpoint = chan.funding_outpoint
        bridge_channel_id = self.bridge_channels[local.channel_seed.hex()]
        self.client.call(
            "setup_channel",
            {
                "channel_id": bridge_channel_id,
                "is_outbound": chan.constraints.is_initiator,
                "channel_value_sat": chan.constraints.capacity,
                "push_value_msat": remote.initial_msat,
                "funding_txid": outpoint.txid,
                "funding_vout": outpoint.output_index,
                "holder_selected_contest_delay": local.to_self_delay,
                "counterparty_selected_contest_delay": remote.to_self_delay,
                "commitment_type": "AnchorsZeroFeeHtlc",
                "counterparty_points": {
                    "funding_pubkey": remote.multisig_key.pubkey.hex(),
                    "revocation_basepoint": remote.revocation_basepoint.pubkey.hex(),
                    "payment_point": remote.payment_basepoint.pubkey.hex(),
                    "delayed_payment_basepoint": remote.delayed_basepoint.pubkey.hex(),
                    "htlc_basepoint": remote.htlc_basepoint.pubkey.hex(),
                },
            },
        )
        self.client.call(
            "confirm_funding_lock",
            {
                "channel_id": bridge_channel_id,
                "funding_txid": outpoint.txid,
                "funding_vout": outpoint.output_index,
            },
        )

    def sync_commitment_state(self, chan, commit_num: int, current_point_hex: str) -> None:
        from electrum.lnutil import LOCAL

        bridge_channel_id = self.bridge_channels[chan.config[LOCAL].channel_seed.hex()]
        self.client.call(
            "sync_commitment_state",
            {
                "channel_id": bridge_channel_id,
                "commit_num": commit_num,
                "revoke_num": commit_num - 1,
                "per_commitment_point": current_point_hex,
            },
        )

    def compare_counterparty_signature_raw(
        self,
        chan,
        name: str,
        sig_64: bytes,
        commitment,
        witscripts: list,
        per_commitment_point_hex: str,
        ctn: int,
        feerate_per_kw: int,
    ) -> None:
        from electrum.lnutil import LOCAL

        bridge_channel_id = self.bridge_channels[chan.config[LOCAL].channel_seed.hex()]
        result = self.client.call(
            "sign_counterparty_commitment_raw",
            {
                "channel_id": bridge_channel_id,
                "tx": commitment.serialize_to_network(include_sigs=False),
                "witscripts": witscripts,
                "per_commitment_point": per_commitment_point_hex,
                "ctn": ctn,
                "feerate_per_kw": feerate_per_kw,
            },
        )
        # verification over electrum's own BIP-143 sighash is the semantic
        # check; byte equality would additionally require identical nonce
        # derivation across signer implementations
        from electrum.crypto import sha256d
        from electrum_ecc import ECPubkey

        msg_hash = sha256d(commitment.serialize_preimage(0))
        funding_pubkey = chan.config[LOCAL].multisig_key.pubkey
        if not ECPubkey(funding_pubkey).ecdsa_verify(sig_64, msg_hash):
            self.divergences.append(f"{name} ctn={ctn} sanity: electrum sig does not verify")
            return
        bridge_sig = bytes.fromhex(result["signature"])
        self.comparisons += 1
        if not ECPubkey(funding_pubkey).ecdsa_verify(bridge_sig, msg_hash):
            self.divergences.append(
                f"{name} ctn={ctn} signature(raw): bridge sig does not verify against electrum sighash"
            )
        elif bridge_sig != sig_64:
            print(f"signatures verify equal at ctn={ctn}; bytes differ (nonce derivation)")

    def compare_counterparty_signature(
        self,
        chan,
        name: str,
        sig_64: bytes,
        per_commitment_point_hex: str,
        ctn: int,
        feerate_per_kw: int,
        to_holder_sat: int,
        to_counterparty_sat: int,
    ) -> None:
        from electrum.lnutil import LOCAL

        outpoint = chan.funding_outpoint
        bridge_channel_id = self.bridge_channels[chan.config[LOCAL].channel_seed.hex()]
        result = self.client.call(
            "sign_counterparty_commitment",
            {
                "channel_id": bridge_channel_id,
                "funding_txid": outpoint.txid,
                "funding_vout": outpoint.output_index,
                "per_commitment_point": per_commitment_point_hex,
                "ctn": ctn,
                "feerate_per_kw": feerate_per_kw,
                "to_holder_sat": to_holder_sat,
                "to_counterparty_sat": to_counterparty_sat,
            },
        )
        self.comparisons += 1
        if result["signature"] != sig_64.hex():
            self.divergences.append(
                f"{name} ctn={ctn} signature: bridge {result['signature']} != electrum {sig_64.hex()}"
            )

    def compare_point(self, chan, ctn: int, point: bytes) -> None:
        from electrum.lnutil import LOCAL

        key = chan.config[LOCAL].channel_seed.hex()
        bridge_channel_id = self.bridge_channels.get(key)
        if bridge_channel_id is None:
            return
        try:
            result = self.client.call(
                "get_per_commitment_point", {"channel_id": bridge_channel_id, "ctn": ctn}
            )
        except RuntimeError as exc:
            # peek-ahead past the synced numbering window is expected: the
            # point for ctn+1 is queried before the next numbering sync
            if "commitment_number" in str(exc) and "invalid" in str(exc):
                return
            raise
        self.comparisons += 1
        if result["point"] != point.hex():
            self.divergences.append(
                f"{name_of(chan)} ctn={ctn}: bridge {result['point']} != electrum {point.hex()}"
            )


def build_witscripts(chan, commitment, pcp):
    import hashlib

    from electrum import lnutil
    from electrum.lnutil import LOCAL, REMOTE

    local = chan.config[LOCAL]
    remote = chan.config[REMOTE]
    # single-sided live variant: no peer seed, so both basepoint-party
    # assignments and both delay sources are candidates and the sha256
    # program match decides
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
    try:
        htlc_records = chan.hm.get_htlcs_in_next_ctx(REMOTE)
    except Exception:
        htlc_records = []
    has_anchors = chan.has_anchors()
    for _direction, htlc in htlc_records:
        cltv = getattr(htlc, "cltv_abs", getattr(htlc, "cltv_expiry", None))
        for rev_base, owner_bp, other_bp in (
            (local.revocation_basepoint.pubkey, local.htlc_basepoint.pubkey, remote.htlc_basepoint.pubkey),
            (remote.revocation_basepoint.pubkey, remote.htlc_basepoint.pubkey, local.htlc_basepoint.pubkey),
        ):
            for is_received in (True, False):
                try:
                    candidates.append(
                        lnutil.make_htlc_output_witness_script(
                            is_received_htlc=is_received,
                            remote_revocation_pubkey=lnutil.derive_blinded_pubkey(rev_base, pcp),
                            remote_htlc_pubkey=lnutil.derive_pubkey(owner_bp, pcp),
                            local_htlc_pubkey=lnutil.derive_pubkey(other_bp, pcp),
                            payment_hash=htlc.payment_hash,
                            cltv_abs=cltv,
                            has_anchors=has_anchors,
                        )
                    )
                except Exception:
                    pass
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
                print(
                    f"tap: DIAG output[{idx}] value={o.value} program={program.hex()} "
                    f"candidates={[hashlib.sha256(c).digest().hex() for c in candidates]}",
                    flush=True,
                )
        witscripts.append(match.hex())
    return witscripts


def name_of(chan) -> str:
    return getattr(chan, "name", type(chan).__name__)

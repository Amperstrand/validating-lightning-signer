"""Derivation-checkpoint auditor: compares Electrum and VLS derivations at
each checkpoint, producing a JSONL audit trail.

The bridge's derive_and_report RPC exposes VLS's channel inputs (basepoints,
delays, optional per-commitment point). Electrum's side is derived here via
lnutil. Signature-level agreement is proven separately by the tap's
sign_justice_sweep cross-check (verification, not comparison).
"""

import json
import time
from pathlib import Path

BASEPOINT_FIELDS = [
    "funding_pubkey",
    "revocation_basepoint",
    "htlc_basepoint",
    "delayed_basepoint",
    "payment_basepoint",
]


class DerivationAuditor:
    def __init__(self, client, audit_path="/tmp/audit-trail.jsonl"):
        self.client = client
        self.audit_path = Path(audit_path)
        self.tap = None
        self.checks = 0
        self.matches = 0
        self.divergences = 0

    def _emit(self, record):
        record["timestamp"] = time.time()
        self.checks += 1
        verdict = record.get("verdict")
        if verdict == "match":
            self.matches += 1
        elif verdict == "diverge":
            self.divergences += 1
            print(
                f"auditor: DIVERGENCE at {record['checkpoint']}: "
                f"{record.get('divergence_detail', '')}",
                flush=True,
            )
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def _cannot_determine(self, checkpoint, exc):
        self._emit(
            {
                "checkpoint": checkpoint,
                "verdict": "cannot_determine",
                "divergence_detail": f"auditor error: {exc}",
            }
        )

    def _bridge_channel_id(self, chan):
        from electrum.lnutil import LOCAL

        key = chan.config[LOCAL].channel_seed.hex()
        self.tap.ensure_registered(chan)
        return self.tap.bridge_channels.get(key)

    def _vls_report(self, bridge_channel_id, revocation_secret=None):
        params = {"channel_id": bridge_channel_id}
        if revocation_secret is not None:
            params["revocation_secret"] = revocation_secret.hex()
        return self.client.call("derive_and_report", params)

    def _electrum_inputs(self, chan, revocation_secret=None):
        from electrum import lnutil
        from electrum.lnutil import LOCAL, REMOTE

        local = chan.config[LOCAL]
        remote = chan.config[REMOTE]
        record = {
            "funding_pubkey": local.multisig_key.pubkey.hex(),
            "revocation_basepoint": local.revocation_basepoint.pubkey.hex(),
            "htlc_basepoint": local.htlc_basepoint.pubkey.hex(),
            "delayed_basepoint": local.delayed_basepoint.pubkey.hex(),
            "payment_basepoint": local.payment_basepoint.pubkey.hex(),
            "to_self_delay": local.to_self_delay,
        }
        if revocation_secret is not None:
            pcp = lnutil.secret_to_pubkey(int.from_bytes(revocation_secret, "big"))
            rev_pub = lnutil.derive_blinded_pubkey(local.revocation_basepoint.pubkey, pcp)
            delayed_pub = lnutil.derive_pubkey(remote.delayed_basepoint.pubkey, pcp)
            witness_script = lnutil.make_commitment_output_to_local_witness_script(
                rev_pub, local.to_self_delay, delayed_pub
            )
            from electrum.bitcoin import script_to_p2wsh

            record["per_commitment_point"] = pcp.hex()
            record["revocation_pubkey"] = rev_pub.hex()
            record["delayed_pubkey"] = delayed_pub.hex()
            record["to_local_script"] = witness_script.hex()
            record["to_local_spk"] = script_to_p2wsh(witness_script)
        return record

    def _compare(self, checkpoint, electrum, vls, strict_fields, context):
        if not isinstance(vls, dict) or "error" in vls:
            detail = vls.get("error") if isinstance(vls, dict) else str(vls)
            self._emit(
                {
                    "checkpoint": checkpoint,
                    "verdict": "cannot_determine",
                    "divergence_detail": f"VLS error: {detail}",
                    "electrum": {k: electrum.get(k) for k in strict_fields},
                    "context": context,
                }
            )
            return
        mismatches = []
        for field in strict_fields:
            if electrum.get(field) != vls.get(field):
                mismatches.append(
                    f"{field}: electrum={str(electrum.get(field))[:32]}"
                    f" vls={str(vls.get(field))[:32]}"
                )
        record = {
            "checkpoint": checkpoint,
            "context": context,
            "electrum": {k: electrum.get(k) for k in strict_fields},
            "vls": {k: vls.get(k) for k in strict_fields},
        }
        if mismatches:
            record["verdict"] = "diverge"
            record["divergence_detail"] = "; ".join(mismatches)
        else:
            record["verdict"] = "match"
        self._emit(record)

    def checkpoint_commitment(self, chan):
        try:
            bridge_channel_id = self._bridge_channel_id(chan)
            if not bridge_channel_id:
                return
            electrum = self._electrum_inputs(chan)
            vls = dict(self._vls_report(bridge_channel_id))
            vls["to_self_delay"] = vls.get("holder_selected_contest_delay")
            self._compare(
                "commitment_round",
                electrum,
                vls,
                BASEPOINT_FIELDS + ["to_self_delay"],
                {},
            )
        except Exception as exc:
            self._cannot_determine("commitment_round", exc)

    def checkpoint_justice(self, chan, ctx, per_commitment_secret):
        try:
            bridge_channel_id = self._bridge_channel_id(chan)
            if not bridge_channel_id:
                return
            electrum = self._electrum_inputs(chan, revocation_secret=per_commitment_secret)
            vls = dict(self._vls_report(bridge_channel_id, revocation_secret=per_commitment_secret))
            ctx_outputs = [o.scriptpubkey.hex() for o in ctx.outputs()]
            context = {
                "revocation_secret": per_commitment_secret.hex()[:16] + "...",
                "ctx_txid": str(ctx.txid()),
                "ctx_outputs": ctx_outputs,
                "electrum_to_local_script": electrum.get("to_local_script"),
                "electrum_to_local_spk": electrum.get("to_local_spk"),
                "on_chain_match": electrum.get("to_local_spk") in ctx_outputs,
            }
            vls["to_self_delay"] = vls.get("holder_selected_contest_delay")
            self._compare(
                "justice",
                electrum,
                vls,
                BASEPOINT_FIELDS + ["to_self_delay", "per_commitment_point"],
                context,
            )
        except Exception as exc:
            self._cannot_determine("justice", exc)

    def report(self):
        return {
            "total_checks": self.checks,
            "matches": self.matches,
            "divergences": self.divergences,
            "cannot_determine": self.checks - self.matches - self.divergences,
            "audit_path": str(self.audit_path),
        }

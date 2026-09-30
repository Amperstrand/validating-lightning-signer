"""Monkey-patch tap mirroring real Electrum Channel calls into the vls-bridge.

Taps `Channel.get_secret_and_point` (fires during signing, revocation and
sweeps) and compares Electrum's per-commitment points against the bridge's.
The tapped methods are synchronous, so this module carries its own
synchronous JSON-lines client; the asyncio client in vls_client.py is for the
future Electrum plugin.
"""

import json
import socket


class SyncBridgeClient:
    def __init__(self, path: str):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(path)
        self.f = self.sock.makefile("rwb")
        self._id = 0

    def call(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        request = {"id": self._id, "method": method, "params": params or {}}
        self.f.write((json.dumps(request) + "\n").encode())
        self.f.flush()
        line = self.f.readline()
        if not line:
            raise RuntimeError(f"bridge closed connection during {method}")
        response = json.loads(line)
        if "error" in response:
            raise RuntimeError(f"{method}: {response['error']}")
        return response.get("result", {})

    def close(self) -> None:
        self.f.close()
        self.sock.close()


class ElectrumTap:
    def __init__(self, client: SyncBridgeClient):
        self.client = client
        self.bridge_channels: dict[str, str] = {}
        self.divergences: list[str] = []
        self.comparisons = 0
        self._original_get_secret_and_point = None

    def install(self) -> None:
        from electrum.lnchannel import Channel
        from electrum.lnutil import LOCAL

        original = Channel.get_secret_and_point
        tap = self

        def get_secret_and_point(chan, subject, ctn, *args, **kwargs):
            secret, point = original(chan, subject, ctn, *args, **kwargs)
            if subject == LOCAL:
                try:
                    tap.compare_point(chan, ctn, point)
                except Exception as exc:
                    tap.divergences.append(f"{name_of(chan)} ctn={ctn}: tap error: {exc!r}")
            return secret, point

        Channel.get_secret_and_point = get_secret_and_point
        self._original_get_secret_and_point = original

    def uninstall(self) -> None:
        if self._original_get_secret_and_point is not None:
            from electrum.lnchannel import Channel

            Channel.get_secret_and_point = self._original_get_secret_and_point
            self._original_get_secret_and_point = None

    def register_channel(self, chan, name: str) -> str:
        from electrum.lnutil import LOCAL

        local = chan.config[LOCAL]
        result = self.client.call("new_channel", {"channel_seed": local.channel_seed.hex()})
        expected = {
            "funding_pubkey": local.multisig_key.pubkey.hex(),
            "htlc_basepoint": local.htlc_basepoint.pubkey.hex(),
            "delayed_payment_basepoint": local.delayed_basepoint.pubkey.hex(),
            "revocation_basepoint": local.revocation_basepoint.pubkey.hex(),
        }
        # payment_point is skipped: anchors payment basepoints need the
        # channel-context seam documented in the README.
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
        result = self.client.call(
            "get_per_commitment_point", {"channel_id": bridge_channel_id, "ctn": ctn}
        )
        self.comparisons += 1
        if result["point"] != point.hex():
            self.divergences.append(
                f"{name_of(chan)} ctn={ctn}: bridge {result['point']} != electrum {point.hex()}"
            )


def name_of(chan) -> str:
    return getattr(chan, "name", type(chan).__name__)

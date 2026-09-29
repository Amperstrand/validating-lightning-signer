#!/usr/bin/env python3
"""Generate known-answer vectors for the VLS ElectrumKeyDerive spike.

Uses Electrum's own derivation code (unmodified) from a source checkout, so the
vectors are authoritative for "how Electrum derives keys".

Usage: gen_vectors.py /path/to/electrum-source out.json
"""
import json
import sys


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    electrum_src, out_path = sys.argv[1], sys.argv[2]
    sys.path.insert(0, electrum_src)

    # Derivations are network-independent (we never serialize xprvs); Electrum's
    # default mainnet constants are fine here.

    from electrum import lnutil
    from electrum.bip32 import BIP32Node
    from electrum.lnutil import (
        LnKeyFamily,
        RevocationStore,
        derive_blinded_privkey,
        derive_multisig_funding_key_if_they_opened,
        derive_multisig_funding_key_if_we_opened,
        derive_payment_basepoint,
        derive_pubkey,
        generate_keypair,
        get_per_commitment_secret_from_seed,
        secret_to_pubkey,
    )
    from electrum.util import bfh

    # name, wallet_seed, channel_seed, remote_node_id (33B), remote_funding_pubkey (33B), nlocktime
    CASES = [
        ("zeros", "00" * 32, "01" * 32, "02" + "aa" * 32, "03" + "bb" * 32, 700_000),
        ("ones", "ff" * 32, "7e" * 32, "02" + "11" * 32, "03" + "22" * 32, 42),
        ("mixed", "e7010f" + "ab" * 28 + "99", "deadbeef" + "55" * 28, "03" + "c0" * 32, "02" + "de" * 32, 2_100_000_000),
    ]

    def kp_hex(kp):
        return {"pubkey": kp.pubkey.hex(), "privkey": kp.privkey.hex()}

    out = {
        "generator": "electrum-lnutil",
        "start_index": RevocationStore.START_INDEX,
        "num_bits": RevocationStore.NUM_BITS,
        "node_id_prefix_len": 16,
        "cases": [],
    }
    for name, ws_hex, cs_hex, rn_hex, rfp_hex, nlocktime in CASES:
        wallet_seed, channel_seed = bfh(ws_hex), bfh(cs_hex)
        remote_node_id, remote_funding_pubkey = bfh(rn_hex), bfh(rfp_hex)

        # wallet-level: ln_xprv = m/67'/ off the wallet BIP32 master
        master = BIP32Node.from_rootseed(wallet_seed, xtype="standard")
        lnroot = master.subkey_at_private_derivation("m/67'/")
        node_key = generate_keypair(lnroot, LnKeyFamily.NODE_KEY)
        funding_root = generate_keypair(lnroot, LnKeyFamily.FUNDING_ROOT_KEY)
        static_payment = generate_keypair(lnroot, LnKeyFamily.PAYMENT_BASE)

        # channel-level: fresh BIP32 master from the random channel_seed
        chnode = BIP32Node.from_rootseed(channel_seed, xtype="standard")
        multisig = generate_keypair(chnode, LnKeyFamily.MULTISIG)
        htlc = generate_keypair(chnode, LnKeyFamily.HTLC_BASE)
        delayed = generate_keypair(chnode, LnKeyFamily.DELAY_BASE)
        revocation = generate_keypair(chnode, LnKeyFamily.REVOCATION_BASE)
        pcss = generate_keypair(chnode, LnKeyFamily.REVOCATION_ROOT).privkey

        # anchors-only derivations
        fk_we = derive_multisig_funding_key_if_we_opened(
            funding_root_secret=funding_root.privkey,
            remote_node_id_or_prefix=remote_node_id,
            nlocktime=nlocktime,
        )
        fk_they = derive_multisig_funding_key_if_they_opened(
            funding_root_secret=funding_root.privkey,
            remote_node_id_or_prefix=remote_node_id,
            remote_funding_pubkey=remote_funding_pubkey,
        )
        pay_bp = derive_payment_basepoint(
            static_payment_secret=static_payment.privkey,
            funding_pubkey=multisig.pubkey,
        )

        # BOLT-3 shachain per-commitment secrets: consecutive ctns plus scattered
        # far-future ones to exercise high-bit flips in the derivation
        CTNS = list(range(64)) + [64, 65, 100, 4_095, 65_536, 1_000_000, 2**24, 2**40, RevocationStore.START_INDEX - 1]
        shachain = []
        for ctn in CTNS:
            idx = RevocationStore.START_INDEX - ctn
            s = get_per_commitment_secret_from_seed(pcss, idx)
            shachain.append(
                {
                    "ctn": ctn,
                    "index": idx,
                    "secret": s.hex(),
                    "point": secret_to_pubkey(int.from_bytes(s, "big")).hex(),
                }
            )

        blinded = {
            "htlc_at_ctn0": derive_pubkey(htlc.pubkey, bytes.fromhex(shachain[0]["point"])).hex(),
            "delayed_at_ctn1": derive_pubkey(delayed.pubkey, bytes.fromhex(shachain[1]["point"])).hex(),
            "revocation_blinded_priv_at_ctn0": derive_blinded_privkey(
                revocation.privkey, bytes.fromhex(shachain[0]["secret"])
            ).hex(),
        }

        out["cases"].append(
            {
                "name": name,
                "network": "regtest",
                "wallet_seed": ws_hex,
                "channel_seed": cs_hex,
                "remote_node_id": rn_hex,
                "remote_funding_pubkey": rfp_hex,
                "nlocktime": nlocktime,
                "node_key": kp_hex(node_key),
                "funding_root_key": kp_hex(funding_root),
                "static_payment_key": kp_hex(static_payment),
                "multisig_key": kp_hex(multisig),
                "htlc_basepoint": kp_hex(htlc),
                "delayed_basepoint": kp_hex(delayed),
                "revocation_basepoint": kp_hex(revocation),
                "per_commitment_secret_seed": pcss.hex(),
                "anchors_funding_key_we_opened": kp_hex(fk_we),
                "anchors_funding_key_they_opened": kp_hex(fk_they),
                "payment_basepoint": kp_hex(pay_bp),
                "shachain": shachain,
                "blinded": blinded,
            }
        )

    with open(out_path, "w") as f:
        json.dump(out, f, indent=1)
    print(f"wrote {out_path}: {len(out['cases'])} cases")


if __name__ == "__main__":
    main()

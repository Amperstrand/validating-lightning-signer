# VLS × Electrum Spike — Runbook

One-page index for driving the rig. Everything here was earned live;
the details live in the linked docs.

## The rig

| Piece | Where | Notes |
|---|---|---|
| herdr tab `electrum-vls-m5` | w1:tY | p16 tunnel, p17 bridge, p18 tapped daemon |
| ssh tunnel | p16: `ssh -N -o ServerAliveInterval=15 ... -L 50001/9735/18443 ai-legion` | keepalives are load-bearing |
| bridge | p17: `~/vls-electrum-spike/target/debug/vls_bridge /tmp/vls-m5-bridge.sock 1111… regtest` | restart picks up code changes |
| docker lab | ai-legion `~/vls-m5/regtest-lab.yml` | bitcoind / electrumx / CLN |
| electrum src | `/tmp/opencode/electrum` (master) | tapped daemon imports electrum_tap from spike/python |

## Before anything

```bash
bash ~/lightning-playground/scripts/rig-preflight.sh
```

Green = go. It checks the traps that actually bit us: degraded tunnel,
dead bridge socket, unloaded miner wallet, low disk (a 100%-full disk
segfaulted bitcoind mid-matrix once), CLN mid-restart.

## Fresh wallet + channel + payments

```bash
bash ~/lightning-playground/scripts/rig-new-wallet.sh mytest     # funded, gossip mode
# open channel:
.../run_electrum --regtest --dir /tmp/vls-mytest/edir -w /tmp/vls-mytest/wallet \
    open_channel 028021c65e…@localhost:9735 0.05 --push_amount 0.02
# then mine 6; invoices via CLN; lnpay to pay
```

Gate mode: `VLS_GATE=1` (VLS approves before Electrum signs), faults
`VLS_FAULT=stale_ctn|tamper_tx` — both pass through rig-new-wallet.

## Breach scenarios

```bash
AUTO_RESTART=1 WALLET=… EDIR=… bash ~/lightning-playground/scripts/justice-replay.sh 3 8
HOLD_AMT=50000 … # parks a hold-invoice HTLC pre-snapshot (needs: docker cp the hold plugin, plugin start /tmp/hold)
bash ~/lightning-playground/scripts/breach-matrix.sh 0 1 11 27      # fresh wallet per position
```

The audit trail lands at `/tmp/audit-trail.jsonl`; gate decisions at
`/tmp/vls-gate.jsonl`. Summarize:

```bash
python ~/vls-electrum-spike/spike/python/audit_summary.py /tmp/audit-trail.jsonl
```

## Verdicts you should see

Justice records: `on_chain_match: true`, input agreement 7/7. Gate:
`open` on clean flows, `closed` on tamper/stale-ctn. Anything else is
a finding — check it against the chain (`getrawtransaction 1`) before
believing your instrumentation (see lesson 9 in the playground's
justice-lessons.md: the instrumentation was the bug, once).

## Maps

- `docs/derivation-checkpoint-protocol.md` — the auditor design
- `docs/gate-mode.md` — gate + fault injection + the ctn guard
- `~/lightning-playground/docs/justice-lessons.md` — nine earned lessons
- `Amperstrand/electrum-shachain-issue` (private) — EVIDENCE.md + all trails
- `~/lightning-playground/scripts/` — rig-*, justice-replay, breach-matrix

## Known sharp edges

- CLN restores drop the dynamically-loaded hold plugin — restart it.
- bitcoind container recreation loses the wallet autoload — preflight catches it.
- `pkill -f run_electrum_tapped` in a command that spells the pattern
  elsewhere kills your own shell — use rig-kill-daemons.sh.
- The bridge's ctn-guard state is in-process (restart forgets replays).
- Long jobs go in tmux; nohup from an interactive shell gets reaped.

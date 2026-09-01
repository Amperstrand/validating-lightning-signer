// Serialized-data schema: names are the API; schema docs in docs/splice-trace.md.
#![allow(missing_docs)]

//! Normalized channel state snapshots — the funding-era-first-class view.
//!
//! The logical model the protocol requires is "N coexisting funding
//! generations"; the implementation keeps `setup` + `prev_setup` +
//! `prev_prev_setup`. The snapshot represents what exists *and* makes
//! absences visible (`retired`/dropped eras appear in
//! [`crate::event::EventPayload::FundingLocked`], watcher ownership for
//! retired eras is the tracker's, not the channel's — recorded as such).
//!
//! Commitment summaries are built through the same era-aware resolvers
//! the signer itself uses (`EnforcementState::holder_commit_info_for`),
//! so the visualization cannot disagree with what VLS would resolve.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::channel::Channel;
use crate::prelude::{String, Vec};

/// Per-era commitment state, resolved through the era-aware resolvers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitmentSummary {
    /// `holder` | `counterparty`
    pub broadcaster: String,
    pub to_broadcaster_sat: u64,
    pub to_countersigner_sat: u64,
    pub feerate_per_kw: u32,
    pub offered_htlc_count: usize,
    pub received_htlc_count: usize,
    /// Sum of offered+received HTLC value, sat
    pub htlc_total_sat: u64,
    /// Individual HTLCs (capped at 24; counts above stay in the counters)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub htlcs: Vec<HtlcSummary>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HtlcSummary {
    pub value_sat: u64,
    pub payment_hash: String,
    pub cltv_expiry: u32,
    pub offered: bool,
}

/// One funding generation of the channel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FundingEraView {
    /// Stable sink-assigned label: `A`, `B`, `C`…
    pub label: String,
    pub outpoint: String,
    pub value_sat: u64,
    /// Raw push value; note CLN's fundee-relative convention on splices
    /// (may wrap on splice-outs — recorded verbatim, not normalized).
    pub push_msat: u64,
    pub remote_funding_key: String,
    pub is_outbound: bool,
    /// `current` | `previous` | `prev_prev` | `locked`
    pub lifecycle: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_commitment: Option<CommitmentSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty_commitment: Option<CommitmentSummary>,
    /// Funding txids the channel's own monitor watches for THIS era
    /// (only reliably known for the current era; older eras' watchers
    /// live in the node tracker — `None` there, the viewer shows the gap).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub watched_txids: Vec<String>,
}

/// Channel-scoped enforcement numbers (commitment numbering is
/// channel-level in the implementation; era ownership of the *infos*
/// is recorded by the funding tags below).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnforcementSummary {
    pub next_holder_commit_num: u64,
    pub next_counterparty_commit_num: u64,
    pub next_counterparty_revoke_num: u64,
    /// Era label the channel-scoped holder info currently belongs to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder_commitment_funding: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub counterparty_commitment_funding: Option<String>,
    /// The justice-window snapshot for the retiring funding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_funding_commitment: Option<Value>,
    pub channel_closed: bool,
}

/// Chain/monitor state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainSummary {
    /// A splice window is open (`prev_setup` present).
    pub splice_pending: bool,
    /// The confirmed (mutual splice_locked) funding outpoint, if locked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funding_locked_outpoint: Option<String>,
    /// Funding txids the channel monitor currently watches.
    pub watched_txids: Vec<String>,
    pub funding_depth: u32,
    pub funding_double_spent_depth: u32,
    pub closing_depth: u32,
    /// The outpoint the monitor last identified as on-chain funding.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor_funding_outpoint: Option<String>,
}

/// Normalized channel state at a point in time.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChannelSnapshot {
    pub channel_id: String,
    /// Live eras in lineage order (original first).
    pub eras: Vec<FundingEraView>,
    pub enforcement: EnforcementSummary,
    pub chain: ChainSummary,
}

fn commit_summary(info: &crate::tx::tx::CommitmentInfo2) -> CommitmentSummary {
    let mut htlcs = info
        .offered_htlcs
        .iter()
        .map(|h| HtlcSummary {
            value_sat: h.value_sat,
            payment_hash: hex::encode(h.payment_hash.0),
            cltv_expiry: h.cltv_expiry,
            offered: true,
        })
        .chain(info.received_htlcs.iter().map(|h| HtlcSummary {
            value_sat: h.value_sat,
            payment_hash: hex::encode(h.payment_hash.0),
            cltv_expiry: h.cltv_expiry,
            offered: false,
        }))
        .collect::<Vec<_>>();
    let offered_count = info.offered_htlcs.len();
    let received_count = info.received_htlcs.len();
    let htlc_total = htlcs.iter().map(|h| h.value_sat).sum();
    htlcs.truncate(24);
    CommitmentSummary {
        broadcaster: if info.is_counterparty_broadcaster {
            "counterparty".into()
        } else {
            "holder".into()
        },
        to_broadcaster_sat: info.to_broadcaster_value_sat,
        to_countersigner_sat: info.to_countersigner_value_sat,
        feerate_per_kw: info.feerate_per_kw,
        offered_htlc_count: offered_count,
        received_htlc_count: received_count,
        htlc_total_sat: htlc_total,
        htlcs,
    }
}

fn era_label_or_none(outpoint: &bitcoin::OutPoint) -> Option<String> {
    crate::trace::sink::label_for_outpoint(outpoint)
}

fn prev_funding_value(snap: &crate::policy::validator::PrevFundingCommitment) -> Value {
    serde_json::json!({
        "outpoint": snap.outpoint.to_string(),
        "era": era_label_or_none(&snap.outpoint),
        "has_holder_info": snap.current_holder_info.is_some(),
        "has_holder_signatures": snap.current_holder_signatures.is_some(),
        "has_next_holder_info": snap.next_holder_info.is_some(),
        "has_counterparty_info": snap.current_counterparty_info.is_some(),
        "holder_commitment": snap.current_holder_info.as_ref().map(commit_summary),
        "counterparty_commitment": snap.current_counterparty_info.as_ref().map(commit_summary),
    })
}

fn era_view(
    label: String,
    setup: &crate::channel::ChannelSetup,
    lifecycle: &str,
    locked: Option<&bitcoin::OutPoint>,
    chan: &Channel,
) -> FundingEraView {
    let es = &chan.enforcement_state;
    let monitor_txids: Vec<String> =
        chan.monitor.watched_funding_txids().iter().map(ToString::to_string).collect();
    let lifecycle =
        if locked == Some(&setup.funding_outpoint) { "locked".into() } else { lifecycle.into() };
    FundingEraView {
        label,
        outpoint: setup.funding_outpoint.to_string(),
        value_sat: setup.channel_value_sat,
        push_msat: setup.push_value_msat,
        remote_funding_key: setup.counterparty_points.funding_pubkey.to_string(),
        is_outbound: setup.is_outbound,
        lifecycle,
        holder_commitment: es.holder_commit_info_for(&setup.funding_outpoint).map(commit_summary),
        counterparty_commitment: es
            .counterparty_commit_info_for(&setup.funding_outpoint)
            .map(commit_summary),
        watched_txids: if monitor_txids
            .iter()
            .any(|t| *t == setup.funding_outpoint.txid.to_string())
        {
            monitor_txids
        } else {
            Vec::new()
        },
    }
}

/// Build the normalized snapshot of a channel's current state.
pub fn snapshot_channel(chan: &Channel) -> ChannelSnapshot {
    let es = &chan.enforcement_state;
    let chain_state = chan.monitor.as_chain_state();
    let mut eras = Vec::new();
    if let Some(pp) = &chan.prev_prev_setup {
        let label = era_label_or_none(&pp.funding_outpoint).unwrap_or_else(|| "?".into());
        eras.push(era_view(label, pp, "prev_prev", chan.funding_locked.as_ref(), chan));
    }
    if let Some(p) = &chan.prev_setup {
        let label = era_label_or_none(&p.funding_outpoint).unwrap_or_else(|| "?".into());
        eras.push(era_view(label, p, "previous", chan.funding_locked.as_ref(), chan));
    }
    {
        let label = era_label_or_none(&chan.setup.funding_outpoint).unwrap_or_else(|| "?".into());
        eras.push(era_view(label, &chan.setup, "current", chan.funding_locked.as_ref(), chan));
    }

    let watched_txids: Vec<String> =
        chan.monitor.watched_funding_txids().iter().map(ToString::to_string).collect();
    let monitor_funding = chan.monitor.funding_outpoint().map(|o| o.to_string());

    ChannelSnapshot {
        channel_id: hex::encode(chan.id0.as_slice()),
        eras,
        enforcement: EnforcementSummary {
            next_holder_commit_num: es.next_holder_commit_num,
            next_counterparty_commit_num: es.next_counterparty_commit_num,
            next_counterparty_revoke_num: es.next_counterparty_revoke_num,
            holder_commitment_funding: es
                .holder_commitment_funding
                .as_ref()
                .and_then(era_label_or_none),
            counterparty_commitment_funding: es
                .counterparty_commitment_funding
                .as_ref()
                .and_then(era_label_or_none),
            prev_funding_commitment: es.prev_funding_commitment.as_ref().map(prev_funding_value),
            channel_closed: es.channel_closed,
        },
        chain: ChainSummary {
            splice_pending: chan.prev_setup.is_some(),
            funding_locked_outpoint: chan.funding_locked.map(|o| o.to_string()),
            watched_txids,
            funding_depth: chain_state.funding_depth,
            funding_double_spent_depth: chain_state.funding_double_spent_depth,
            closing_depth: chain_state.closing_depth,
            monitor_funding_outpoint: monitor_funding,
        },
    }
}

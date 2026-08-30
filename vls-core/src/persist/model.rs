use serde::Deserialize;
use serde::Serialize;

use crate::channel::ChannelId;
use crate::channel::ChannelSetup;
use crate::node::NodeState;
use crate::policy::validator::EnforcementState;
use crate::prelude::*;

/// A persistence layer entry for a Node
#[allow(missing_docs)]
pub struct NodeEntry {
    pub key_derivation_style: u8,
    pub network: String,
    pub state: NodeState,
}

/// Persistent state for a channel.
///
/// Contains channel configuration, current enforcement state, and metadata.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct ChannelEntry {
    /// Channel capacity in satoshis
    pub channel_value_satoshis: u64,
    /// Channel setup configuration (funding, keys, scripts)
    pub channel_setup: Option<ChannelSetup>,
    /// Permanent channel ID (if different from initial ID)
    pub id: Option<ChannelId>,
    /// Enforcement and validation state for the channel
    pub enforcement_state: EnforcementState,
    /// The retiring funding's setup during a splice window — restored so
    /// old-funding commitments keep their view across restarts (the crash9
    /// fix: a hardcoded None validated them against the post-splice
    /// funding — "fee underflow 894199 - 995120").
    #[serde(default)]
    pub prev_setup: Option<ChannelSetup>,
    /// fork-local (inr2-splice-dev) RBF: the two-deep prev chain's second
    /// hop (the original funding during an RBF window).
    #[serde(default)]
    pub prev_prev_setup: Option<ChannelSetup>,
    /// Birth blockheight for stub channels, None for regular channels
    pub blockheight: Option<u32>,
}

//! #268 sec-sweep rails: signer-side hardening pins.
//!
//! Rail 1 (unfixed-host detector): when the wrapped-push tolerance trips
//! (push_value_msat > i64::MAX — a host that still wraps negative
//! splice-out contributions instead of converting sats→msat), the lockin
//! baseline must fall back to the initial_holder_value split, never to
//! the garbage wrapped value. A warn! now fires at both tolerance sites
//! (channel.rs lockin, node.rs splice re-setup).

use crate::mutant_rails_tests::splice_a_to_b;
use crate::util::test_utils::{fund_test_channel, test_node_ctx};

#[test]
fn rail_wrapped_push_lockin_falls_back_to_initial_holder_value() {
    let node_ctx = test_node_ctx(1);
    let mut chan_ctx = fund_test_channel(&node_ctx, 1_000_000);
    let channel_id = chan_ctx.channel_id.clone();

    let initial_holder: u64 = node_ctx
        .node
        .with_channel(&channel_id, |c| Ok(c.enforcement_state.initial_holder_value))
        .expect("initial_holder_value read");

    // The wrapped splice-out shape: push beyond i64::MAX would be a
    // near-u64-max garbage value from an unfixed host.
    chan_ctx.setup.push_value_msat = (i64::MAX as u64) * 2;
    let outpoint_b = splice_a_to_b(&node_ctx, &mut chan_ctx);

    node_ctx
        .node
        .confirm_funding_lock(&channel_id, &outpoint_b)
        .expect("splice funding locked");

    let info = node_ctx
        .node
        .with_channel(&channel_id, |c| {
            Ok(c.enforcement_state.current_holder_commit_info.clone())
        })
        .expect("commit info read")
        .expect("lockin baseline installed");

    let value_b = chan_ctx.setup.channel_value_sat;
    assert_eq!(
        info.to_broadcaster_value_sat, initial_holder,
        "wrapped push must fall back to the initial_holder_value split"
    );
    assert_eq!(info.to_countersigner_value_sat, value_b - initial_holder);
}

//! Shuttle randomized scheduler tests for Node class concurrency.
//!
//! These tests verify that the Node's locking patterns are correct by testing
//! specific method combinations that could potentially deadlock or race.
//!
//! See LOCK ORDERING comment in node.rs for the documented lock order.

#[cfg(all(test, feature = "shuttle"))]
mod shuttle_tests {
    use lightning_signer::util::test_utils::make_node;

    use shuttle::sync::Arc;
    use shuttle::thread;

    /// State + Channels Lock Order
    ///
    /// Tests the documented lock order: channels -> slot -> state
    /// - Thread 1: forget_channel() acquires channels -> slot -> state
    /// - Thread 2: new_channel_with_random_id() acquires tracker -> channels
    #[test]
    fn test_state_channels_lock_order() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                // Create initial channel
                let (channel_id, _) = node.new_channel_with_random_id(&node).unwrap();

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // Acquires channels -> slot -> state
                    node1.forget_channel(&channel_id).unwrap();
                });

                let t2 = thread::spawn(move || {
                    // Acquires tracker -> channels
                    node2.new_channel_with_random_id(&node2).unwrap();
                });

                t1.join().unwrap();
                t2.join().unwrap();

                // One channel removed, one created -> exactly one remains
                let channels = node.get_channels();
                assert_eq!(channels.len(), 1);
            },
            100,
        );
    }

    /// Same Channel Concurrent Access
    ///
    /// Multiple threads accessing the same channel slot concurrently.
    #[test]
    fn test_same_channel_concurrent_access() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let (channel_id, _) = node.new_channel_with_random_id(&node).unwrap();

                let node1 = node.clone();
                let node2 = node.clone();
                let cid1 = channel_id.clone();
                let cid2 = channel_id.clone();

                let t1 = thread::spawn(move || {
                    if let Ok(slot) = node1.get_channel(&cid1) {
                        let _lock = slot.lock().unwrap();
                        // Hold the lock briefly
                    }
                });

                let t2 = thread::spawn(move || {
                    if let Ok(slot) = node2.get_channel(&cid2) {
                        let _lock = slot.lock().unwrap();
                        // Hold the lock briefly
                    }
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// with_channel + forget_channel Race
    ///
    /// Tests race between channel access and channel removal.
    /// - Thread 1: with_channel_base() acquires channels -> slot
    /// - Thread 2: forget_channel() acquires channels -> slot -> state
    #[test]
    fn test_with_channel_forget_race() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let (channel_id, _) = node.new_channel_with_random_id(&node).unwrap();

                let node1 = node.clone();
                let node2 = node.clone();
                let cid1 = channel_id.clone();
                let cid2 = channel_id.clone();

                let t1 = thread::spawn(move || {
                    // with_channel_base acquires channels -> slot
                    let _ = node1.with_channel_base(&cid1, |_base| Ok(()));
                });

                let t2 = thread::spawn(move || {
                    // forget_channel acquires channels -> slot -> state
                    let _ = node2.forget_channel(&cid2);
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// Persist All with Channel Operations
    ///
    /// Tests persist_all(), which takes state on its own and then channels -> slots -> tracker,
    /// against concurrent channel creation.
    #[test]
    fn test_persist_all_concurrent() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                // Create some initial channels
                for _ in 0..2 {
                    node.new_channel_with_random_id(&node).unwrap();
                }

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // Acquires state (released), then channels -> slots, then tracker
                    node1.persist_all();
                });

                let t2 = thread::spawn(move || {
                    // Acquires tracker -> channels
                    node2.new_channel_with_random_id(&node2).unwrap();
                });

                t1.join().unwrap();
                t2.join().unwrap();

                // Two created in setup plus one here; persist_all leaves the count
                let channels = node.get_channels();
                assert_eq!(channels.len(), 3);
            },
            100,
        );
    }

    /// Tracker + Channels Interleaving
    ///
    /// Tests potential deadlock from opposite lock ordering:
    /// - Thread 1: get_tracker() then get_channels()
    /// - Thread 2: new_channel_with_random_id() which acquires tracker -> channels
    ///
    /// Both threads now follow the documented lock order: tracker -> channels.
    #[test]
    fn test_tracker_channels_interleaving() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // Acquires tracker, then channels
                    let _tracker = node1.get_tracker();
                    let _channels = node1.get_channels();
                });

                let t2 = thread::spawn(move || {
                    // Acquires tracker -> channels internally
                    let _ = node2.new_channel_with_random_id(&node2);
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// Multiple Channel Operations
    ///
    /// Tests multiple concurrent channel creation and access operations.
    #[test]
    fn test_multiple_channel_operations() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // Create channel and get all channels
                    node1.new_channel_with_random_id(&node1).unwrap();
                    let _channels = node1.get_channels();
                });

                let t2 = thread::spawn(move || {
                    // Create channel and get all channels
                    node2.new_channel_with_random_id(&node2).unwrap();
                    let _channels = node2.get_channels();
                });

                t1.join().unwrap();
                t2.join().unwrap();

                // Each thread creates one channel -> exactly two
                let channels = node.get_channels();
                assert_eq!(channels.len(), 2);
            },
            100,
        );
    }

    /// Find Channel During Forget
    ///
    /// Tests channel lookup during channel removal.
    /// - Thread 1: find_channel_with_funding_outpoint() acquires channels
    /// - Thread 2: forget_channel() acquires channels -> slot -> state
    #[test]
    fn test_find_channel_during_forget() {
        use bitcoin::hashes::Hash;
        use bitcoin::OutPoint;

        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let (channel_id, _) = node.new_channel_with_random_id(&node).unwrap();

                // Create a dummy outpoint for searching
                let outpoint =
                    OutPoint { txid: bitcoin::Txid::from_slice(&[0u8; 32]).unwrap(), vout: 0 };

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // Acquires channels lock for lookup
                    let _ = node1.find_channel_with_funding_outpoint(&outpoint);
                });

                let t2 = thread::spawn(move || {
                    // Acquires channels -> slot -> state
                    let _ = node2.forget_channel(&channel_id);
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// Concurrent Forget Operations
    ///
    /// Tests multiple threads trying to forget channels concurrently.
    #[test]
    fn test_concurrent_forget_operations() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                // Create two channels
                let (channel_id1, _) = node.new_channel_with_random_id(&node).unwrap();
                let (channel_id2, _) = node.new_channel_with_random_id(&node).unwrap();

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    let _ = node1.forget_channel(&channel_id1);
                });

                let t2 = thread::spawn(move || {
                    let _ = node2.forget_channel(&channel_id2);
                });

                t1.join().unwrap();
                t2.join().unwrap();

                // Invariant: both channels should be removed
                let channels = node.get_channels();
                assert_eq!(channels.len(), 0);
            },
            100,
        );
    }

    /// Allowlist Set vs Add Race
    ///
    /// Tests concurrent set_allowlist and add_allowlist operations.
    #[test]
    fn test_allowlist_set_add_race() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    let _ = node1
                        .set_allowlist(&["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx".to_string()]);
                });

                let t2 = thread::spawn(move || {
                    let _ = node2.add_allowlist(&[
                        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7"
                            .to_string(),
                    ]);
                });

                t1.join().unwrap();
                t2.join().unwrap();

                // Invariant: allowlist should have 1 or 2 entries depending on order
                let list = node.allowlist().unwrap();
                assert!(list.len() >= 1 && list.len() <= 2);
            },
            100,
        );
    }

    /// Get Channels While Creating
    ///
    /// Tests iterating over channels while another thread creates new ones.
    #[test]
    fn test_get_channels_while_creating() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                // Create initial channel
                let _ = node.new_channel_with_random_id(&node);

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // Hold channels lock and iterate
                    let channels = node1.get_channels();
                    for (_id, slot) in channels.iter() {
                        let _lock = slot.lock().unwrap();
                    }
                });

                let t2 = thread::spawn(move || {
                    // Try to create new channel
                    let _ = node2.new_channel_with_random_id(&node2);
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// Three-Way Channel Race
    ///
    /// Tests three threads racing on channel operations.
    #[test]
    fn test_three_way_channel_race() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let (channel_id, _) = node.new_channel_with_random_id(&node).unwrap();

                let node1 = node.clone();
                let node2 = node.clone();
                let node3 = node.clone();
                let cid = channel_id.clone();

                let t1 = thread::spawn(move || {
                    let _ = node1.new_channel_with_random_id(&node1);
                });

                let t2 = thread::spawn(move || {
                    let _ = node2.get_channel(&cid);
                });

                let t3 = thread::spawn(move || {
                    let _ = node3.forget_channel(&channel_id);
                });

                t1.join().unwrap();
                t2.join().unwrap();
                t3.join().unwrap();
            },
            100,
        );
    }

    /// Set Validator Factory Race
    ///
    /// Concurrent replace (set_validator_factory) vs use (update_velocity_controls)
    /// of the validator factory. Neither nests validator_factory with another lock
    /// (update_velocity_controls takes validator_factory then state, but releases
    /// the first before the second), so this checks the swap and read do not race,
    /// not a lock ordering.
    #[test]
    fn test_set_validator_factory_race() {
        use lightning_signer::policy::simple_validator::SimpleValidatorFactory;

        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // Replace the validator factory
                    let new_factory = Arc::new(SimpleValidatorFactory::new());
                    node1.set_validator_factory(new_factory);
                });

                let t2 = thread::spawn(move || {
                    // Use the validator factory
                    node2.update_velocity_controls();
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// Persist All + Forget Channel Race
    ///
    /// Tests persist_all (state, then channels) against forget_channel (channels ->
    /// slot -> state). This should catch lock order violations in forget_channel.
    #[test]
    fn test_persist_all_forget_race() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                // Create initial channel
                let (channel_id, _) = node.new_channel_with_random_id(&node).unwrap();

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // persist_all takes state, releases it, then channels
                    node1.persist_all();
                });

                let t2 = thread::spawn(move || {
                    // forget_channel should acquire channels -> slot -> state
                    let _ = node2.forget_channel(&channel_id);
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// Persist All vs Tracker -> Channels Order
    ///
    /// Tests potential deadlock between:
    /// - Thread 1: persist_all() acquires channels -> slots, then tracker
    /// - Thread 2: Operations that acquire tracker -> channels
    ///
    /// persist_all acquires tracker AFTER channels, but other methods
    /// acquire tracker BEFORE channels.
    #[test]
    fn test_persist_all_vs_tracker_channels() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                // Create some channels
                let _ = node.new_channel_with_random_id(&node);

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // persist_all: state (released), then channels -> slots, then tracker
                    node1.persist_all();
                });

                let t2 = thread::spawn(move || {
                    // Acquire tracker then channels (documented order)
                    let _tracker = node2.get_tracker();
                    let _channels = node2.get_channels();
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// Multiple Channels with State Access
    ///
    /// Tests multiple threads each holding different channel_slots
    /// and trying to acquire state concurrently.
    #[test]
    fn test_multiple_channels_state_access() {
        shuttle::check_random(
            || {
                let (_, node, _) = make_node();
                let node = Arc::new(node);

                let (channel_id1, _) = node.new_channel_with_random_id(&node).unwrap();
                let (channel_id2, _) = node.new_channel_with_random_id(&node).unwrap();

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    if let Ok(slot) = node1.get_channel(&channel_id1) {
                        let _channel_lock = slot.lock().unwrap();
                        let _state = node1.get_state();
                    }
                });

                let t2 = thread::spawn(move || {
                    if let Ok(slot) = node2.get_channel(&channel_id2) {
                        let _channel_lock = slot.lock().unwrap();
                        let _state = node2.get_state();
                    }
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// channel_balance vs a slot -> state signing method, over a READY channel
    ///
    /// This is the integration deadlock (integration-lnrod-local hung here):
    /// the frontend chain follower calls get_heartbeat -> channel_balance while
    /// LDK concurrently signs on a p2p thread, and signing holds a channel slot
    /// and then takes node state (Node::with_channel -> Channel::htlcs_fulfilled
    /// -> Node::get_state).
    ///
    /// - Thread 1: channel_balance() (channels -> slot -> state)
    /// - Thread 2: locks the slot, then acquires state (slot -> state)
    ///
    /// A READY channel is required: channel_balance short-circuits stubs to
    /// ChannelBalance::stub() and never reaches chan.balance(), so a stub-only
    /// node cannot exercise the state/slot pairing at all. This calls
    /// channel_balance directly rather than through get_heartbeat: the
    /// surrounding heartbeat work (invoice pruning, tracker, prune_channels)
    /// dwarfs the critical section, and random scheduling does not reach the
    /// interleaving through it. When channel_balance held state across the slot
    /// lock, Shuttle reports a deadlock here within a few iterations.
    #[test]
    fn test_channel_balance_vs_signing_ready() {
        use lightning_signer::node::NodeMonitor;
        use lightning_signer::util::test_utils::{
            init_node_and_channel, make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
        };

        shuttle::check_random(
            || {
                let (node, channel_id) = init_node_and_channel(
                    TEST_NODE_CONFIG,
                    TEST_SEED[1],
                    make_test_channel_setup(),
                );

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // frontend heartbeat / admin RPC: channels -> slot -> state
                    let _ = node1.channel_balance();
                });

                let t2 = thread::spawn(move || {
                    // signing path: channel_slot -> state
                    if let Ok(slot) = node2.get_channel(&channel_id) {
                        let _channel_lock = slot.lock().unwrap();
                        let _state = node2.get_state();
                    }
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// get_heartbeat end to end vs a slot -> state signing method
    ///
    /// Covers the production caller (vls-proxy/src/nodefront.rs do_beat) over the
    /// whole sequence: state (released), channel_balance, then tracker ->
    /// channels -> slot via prune_channels.
    ///
    /// This is a smoke test, NOT the regression guard. get_heartbeat does far
    /// more work than its critical section, so random scheduling does not reach
    /// the state/slot interleaving through it - this test passes even with the
    /// inversion present. test_channel_balance_vs_signing_ready is the guard
    /// that actually fails on the bug. Kept because get_heartbeat is the caller
    /// that deadlocked in integration-lnrod-local, so the full path should stay
    /// exercised.
    #[test]
    fn test_heartbeat_vs_signing_ready() {
        use lightning_signer::util::test_utils::{
            init_node_and_channel, make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
        };

        shuttle::check_random(
            || {
                let (node, channel_id) = init_node_and_channel(
                    TEST_NODE_CONFIG,
                    TEST_SEED[1],
                    make_test_channel_setup(),
                );

                let node1 = node.clone();
                let node2 = node.clone();

                let t1 = thread::spawn(move || {
                    // frontend chain follower
                    let _ = node1.get_heartbeat();
                });

                let t2 = thread::spawn(move || {
                    // signing path: channel_slot -> state
                    if let Ok(slot) = node2.get_channel(&channel_id) {
                        let _channel_lock = slot.lock().unwrap();
                        let _state = node2.get_state();
                    }
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }

    /// forget_channel vs channel_balance over a READY channel (regression)
    ///
    /// Both run off the signing path (admin RPC, heartbeat). forget_channel used
    /// to hold node state across the channels and slot locks, inverting the
    /// channels -> slot -> state order that chan.balance() forces on
    /// channel_balance, and deadlocking under real concurrency. forget_channel
    /// now takes state only after dropping the slot guard, so this passes;
    /// before the fix Shuttle reports a deadlock.
    ///
    /// A READY channel is required: stubs never reach chan.balance().
    #[test]
    fn test_forget_vs_channel_balance_ready() {
        use lightning_signer::node::NodeMonitor;
        use lightning_signer::util::test_utils::{
            init_node_and_channel, make_test_channel_setup, TEST_NODE_CONFIG, TEST_SEED,
        };

        shuttle::check_random(
            || {
                let (node, channel_id) = init_node_and_channel(
                    TEST_NODE_CONFIG,
                    TEST_SEED[1],
                    make_test_channel_setup(),
                );

                let node1 = node.clone();
                let node2 = node.clone();
                let cid = channel_id.clone();

                let t1 = thread::spawn(move || {
                    // forget path: channels -> slot -> state
                    let _ = node1.forget_channel(&cid);
                });

                let t2 = thread::spawn(move || {
                    // admin RPC / heartbeat path: channels -> slot -> state
                    let _ = node2.channel_balance();
                });

                t1.join().unwrap();
                t2.join().unwrap();
            },
            100,
        );
    }
}

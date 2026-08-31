#![no_main]

use libfuzzer_sys::fuzz_target;
use vls_fuzz::channel_splice::{SpliceAction, SpliceChannelFuzz};

fuzz_target!(|data: Vec<SpliceAction>| {
    let mut fuzz = SpliceChannelFuzz::new();
    fuzz.run(data);
});

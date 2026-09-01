# Fuzzing

## Setup

The latest stable Rust toolchain should work.  We are not currently using address sanitation because
we don't have use unsafe code.  We should however also fuzz with address sanitation from time to time in case
one of our dependencies introduces a bug.  That would require a nightly toolchain.

Install the fuzzing tools:

* `cargo install cargo-fuzz`

Optional, if you want support for afl:

* `cargo install cargo-afl`

see also https://www.wzdftpd.net/blog/rust-fuzzers.html

## Run

* `./scripts/fuzz`

or with afl:

* `./scripts/fuzz-afl`

## Reproduce a crash

When a fuzzer produces a crash file, the file will include the input that caused the crash.
You can reproduce the crash with:

* `cargo fuzz run channel ARTIFACT`

or

* `cargo run --features debug,repro --bin channel-afl < ARTIFACT`

## Running the seed/regression tests (2026-09-01, earned by a false-alarm issue)

`cargo test` in this crate MUST carry the fuzzing cfg — the tests use
dummy signatures and the sig checks are `#[cfg(fuzzing)]`-skipped:

    RUSTFLAGS="--cfg=fuzzing" cargo test

Without it, channel.rs tests fail "commit sig verify failed" — that is
the invocation, not a regression (issue #102's false alarm).

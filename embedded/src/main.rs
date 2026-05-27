#![cfg_attr(feature = "device", feature(alloc_error_handler))]
#![cfg_attr(feature = "device", no_std)]
#![cfg_attr(feature = "device", no_main)]

extern crate alloc;

#[cfg_attr(not(feature = "device"), allow(dead_code))]
mod tests;

#[cfg(feature = "device")]
mod entry;

#[cfg(not(feature = "device"))]
fn main() {}

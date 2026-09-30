use std::env;

use electrum_vls_spike::bridge::{make_bridge, serve};
use lightning_signer::bitcoin::Network;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("usage: vls_bridge SOCKET WALLET_SEED_HEX [regtest|testnet|signet|bitcoin]");
        std::process::exit(2);
    }
    let socket_path = args[1].clone();
    let wallet_seed: [u8; 32] = hex::decode(&args[2])?
        .try_into()
        .map_err(|_| "wallet seed must be 32 bytes of hex")?;
    let network = match args.get(3).map(String::as_str) {
        None | Some("regtest") => Network::Regtest,
        Some("testnet") => Network::Testnet,
        Some("signet") => Network::Signet,
        Some("bitcoin") | Some("mainnet") => Network::Bitcoin,
        Some(other) => return Err(format!("unknown network: {other}").into()),
    };
    let bridge = make_bridge(wallet_seed, network);
    println!("node_id {}", hex::encode(bridge.node.get_id().serialize()));
    serve(bridge, &socket_path)?;
    Ok(())
}

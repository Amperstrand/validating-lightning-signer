use jsonrpsee::core::traits::ToRpcParams;
use lightning_signer::bitcoin::{self, bip32::DerivationPath};
use serde::{Deserialize, Serialize};
use serde_json::{json, value::RawValue};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InfoModel {
    height: u32,
    channels: u32,
    version: String,
    node_id: String,
    network: String,
    bip32_xpub: String,
}

impl InfoModel {
    pub fn new(
        height: u32,
        channels: u32,
        version: String,
        node_id: String,
        network: String,
        bip32_xpub: String,
    ) -> Self {
        Self { height, channels, version, node_id, network, bip32_xpub }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelInfo {
    pub channel_id: String,
    pub state: String,
    pub channel_value_sat: Option<u64>,
    pub is_outbound: Option<bool>,
    pub funding_outpoint: Option<String>,
    pub commitment_type: Option<String>,
    pub channel_closed: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelListResponse {
    pub channels: Vec<ChannelInfo>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ChannelBalanceResponse {
    pub claimable_sat: u64,
    pub received_htlc_sat: u64,
    pub offered_htlc_sat: u64,
    pub sweeping_sat: u64,
    pub channel_count: u32,
    pub stub_count: u32,
    pub unconfirmed_count: u32,
    pub closing_count: u32,
    pub received_htlc_count: u32,
    pub offered_htlc_count: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NodeStateResponse {
    pub velocity_current_msat: u64,
    pub velocity_limit_msat: Option<u64>,
    pub fee_velocity_current_msat: u64,
    pub fee_velocity_limit_msat: Option<u64>,
    pub invoice_count: usize,
    pub payment_count: usize,
    pub last_summary: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressListRequest {
    pub address_type: Option<AddressType>,
    pub start: Option<u32>,
    pub count: Option<u32>,
    pub path: Option<DerivationPath>,
}

impl ToRpcParams for AddressListRequest {
    fn to_rpc_params(self) -> Result<Option<Box<serde_json::value::RawValue>>, serde_json::Error> {
        let json = json!(&self).to_string();
        Ok(Some(RawValue::from_string(json).expect("AddressListRequest is Serializable")))
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddressVerifyRequest {
    pub address: String,
    pub start: Option<u32>,
    pub limit: Option<u32>,
    pub path: Option<DerivationPath>,
}

impl ToRpcParams for AddressVerifyRequest {
    fn to_rpc_params(self) -> Result<Option<Box<serde_json::value::RawValue>>, serde_json::Error> {
        let json = json!(&self).to_string();
        Ok(Some(RawValue::from_string(json).expect("AddressVerifyRequest is Serializable")))
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, clap::ValueEnum)]
pub enum AddressType {
    Native,
    Taproot,
    Wrapped,
}

impl AddressType {
    pub fn purpose(&self) -> u32 {
        match self {
            Self::Wrapped => 49,
            Self::Native => 84,
            Self::Taproot => 86,
        }
    }

    pub fn all() -> Vec<AddressType> {
        vec![Self::Native, Self::Taproot, Self::Wrapped]
    }
}

impl From<bitcoin::AddressType> for AddressType {
    fn from(value: bitcoin::AddressType) -> Self {
        match value {
            bitcoin::AddressType::P2wpkh => Self::Native,
            bitcoin::AddressType::P2sh => Self::Wrapped,
            bitcoin::AddressType::P2tr => Self::Taproot,
            _ => unimplemented!(
                "only native segwit, wrapped segwit and taproot addresses are supported"
            ),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressInfo {
    pub address: String,
    pub path: String,
    pub address_type: AddressType,
    pub script_pubkey: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressListResponse {
    pub addresses: Vec<AddressInfo>,
    pub network: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressVerifyResponse {
    pub address: String,
    pub valid: bool,
    pub address_info: Option<AddressInfo>,
}

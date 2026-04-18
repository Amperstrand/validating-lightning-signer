use crate::rpc_server::address_generation::DEFAULT_GAP_LIMIT;

use super::address_generation::DEFAULT_ADDRESS_COUNT;
use anyhow::Result;
use jsonrpsee::{
    server::{RpcModule, Server},
    types::{error::ErrorCode, ErrorObject},
};
use lightning_signer::channel::ChannelSlot;
use lightning_signer::hex;
use lightning_signer::node::NodeMonitor;
use lightning_signer::util::status::Status;
use lightning_signer::wallet::Wallet;
use lightning_signer::{bitcoin::bip32::DerivationPath, node::Node};
use log::{error, info};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tower::ServiceBuilder;

use super::address_generation::{generate_addresses, verify_address_derivation};
use super::model::{
    AddressListRequest, AddressListResponse, AddressType, AddressVerifyRequest,
    AddressVerifyResponse, ChannelBalanceResponse, ChannelInfo, ChannelListResponse, InfoModel,
    NodeStateResponse,
};

use vls_util::GIT_DESC;

/// The `RpcServer` handles incoming RPC requests and dispatches them
/// to the appropriate handlers. It holds a reference to the `Node`
/// to perform core operations.
pub struct RpcServer {
    pub node: Arc<Node>,
}

impl RpcServer {
    pub fn new(node: Arc<Node>) -> Self {
        Self { node }
    }

    pub fn handle_info(&self) -> Result<InfoModel, Status> {
        info!("Handling info request");
        let height = self.node.get_chain_height();
        let channels = self.node.get_channels().len() as u32;
        let node_id = hex::encode(self.node.get_id().serialize());
        let network = self.node.network().to_string();
        let bip32_xpub = self.node.get_account_extended_pubkey().to_string();
        Ok(InfoModel::new(height, channels, GIT_DESC.to_owned(), node_id, network, bip32_xpub))
    }

    pub fn handle_channel_list(&self) -> Result<ChannelListResponse, Status> {
        info!("Handling channel_list request");
        let channels_guard = self.node.get_channels();
        let channels = channels_guard
            .iter()
            .map(|(_, slot_arc)| {
                let slot = slot_arc.lock().unwrap();
                match &*slot {
                    ChannelSlot::Stub(stub) => ChannelInfo {
                        channel_id: hex::encode(stub.id0.as_slice()),
                        state: "stub".to_string(),
                        channel_value_sat: None,
                        is_outbound: None,
                        funding_outpoint: None,
                        commitment_type: None,
                        channel_closed: None,
                    },
                    ChannelSlot::Ready(chan) => ChannelInfo {
                        channel_id: hex::encode(chan.id0.as_slice()),
                        state: "ready".to_string(),
                        channel_value_sat: Some(chan.setup.channel_value_sat),
                        is_outbound: Some(chan.setup.is_outbound),
                        funding_outpoint: Some(format!(
                            "{}:{}",
                            chan.setup.funding_outpoint.txid, chan.setup.funding_outpoint.vout
                        )),
                        commitment_type: Some(
                            serde_json::to_value(&chan.setup.commitment_type)
                                .ok()
                                .and_then(|v| v.as_str().map(str::to_string))
                                .unwrap_or_default(),
                        ),
                        channel_closed: Some(chan.enforcement_state.channel_closed),
                    },
                }
            })
            .collect();
        Ok(ChannelListResponse { channels })
    }

    pub fn handle_channel_balance(&self) -> Result<ChannelBalanceResponse, Status> {
        info!("Handling channel_balance request");
        let bal = self.node.channel_balance();
        Ok(ChannelBalanceResponse {
            claimable_sat: bal.claimable,
            received_htlc_sat: bal.received_htlc,
            offered_htlc_sat: bal.offered_htlc,
            sweeping_sat: bal.sweeping,
            channel_count: bal.channel_count,
            stub_count: bal.stub_count,
            unconfirmed_count: bal.unconfirmed_count,
            closing_count: bal.closing_count,
            received_htlc_count: bal.received_htlc_count,
            offered_htlc_count: bal.offered_htlc_count,
        })
    }

    pub fn handle_node_state(&self) -> Result<NodeStateResponse, Status> {
        info!("Handling node_state request");
        let state = self.node.get_state();
        let vc = &state.velocity_control;
        let fvc = &state.fee_velocity_control;
        Ok(NodeStateResponse {
            velocity_current_msat: vc.velocity(),
            velocity_limit_msat: if vc.is_unlimited() { None } else { Some(vc.limit) },
            fee_velocity_current_msat: fvc.velocity(),
            fee_velocity_limit_msat: if fvc.is_unlimited() { None } else { Some(fvc.limit) },
            invoice_count: state.issued_invoices.len(),
            payment_count: state.payments.len(),
            last_summary: state.last_summary.clone(),
        })
    }

    /// Handles the `address_list` request.
    ///
    /// It generates a list of addresses based on the specified types and count.
    /// If no types are provided, it defaults to `Native`.
    pub fn handle_address_list(
        &self,
        request: AddressListRequest,
    ) -> Result<AddressListResponse, Status> {
        info!("Handling address_list request: {:?}", request);

        let count = request.count.unwrap_or(DEFAULT_ADDRESS_COUNT);
        let addresses = generate_addresses(
            &self.node,
            request.address_type.unwrap_or(AddressType::Native),
            request.start.unwrap_or(0),
            count,
            &request.path.unwrap_or(DerivationPath::master()),
        )?;

        Ok(AddressListResponse { addresses, network: self.node.network().to_string() })
    }

    /// Handles the `address_verify` request.
    ///
    /// This function can verify the path by searching through standard BIP paths.
    pub fn handle_address_verify(
        &self,
        request: AddressVerifyRequest,
    ) -> Result<AddressVerifyResponse, Status> {
        info!("Handling address_verify request: {:?}", request);

        let result = verify_address_derivation(
            &self.node,
            &request.address,
            request.start.unwrap_or(0),
            request.limit.unwrap_or(DEFAULT_GAP_LIMIT),
            &request.path.unwrap_or(DerivationPath::master()),
        );

        match result {
            Ok(info) => Ok(AddressVerifyResponse {
                address: request.address,
                valid: if info.is_some() { true } else { false },
                address_info: info,
            }),
            Err(e) => {
                error!("Failed to verify address: {}", e);
                Err(e)
            }
        }
    }
}

#[derive(Debug)]
pub enum RpcMethods {
    Info,
    Version,
    AllowlistDisplay,
    AllowlistAdd,
    AllowlistRemove,
    AddressList,
    AddressVerify,
    ChannelList,
    ChannelBalance,
    NodeState,
}

impl RpcMethods {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Version => "version",
            Self::AllowlistDisplay => "allowlist_display",
            Self::AllowlistAdd => "allowlist_add",
            Self::AllowlistRemove => "allowlist_remove",
            Self::AddressList => "address_list",
            Self::AddressVerify => "address_verify",
            Self::ChannelList => "channel_list",
            Self::ChannelBalance => "channel_balance",
            Self::NodeState => "node_state",
        }
    }
}

pub async fn start_rpc_server(
    node: Arc<Node>,
    ip: IpAddr,
    port: u16,
    username: &str,
    password: &str,
    shutdown_signal: triggered::Listener,
) -> anyhow::Result<(SocketAddr, JoinHandle<()>)> {
    let rpc_server = RpcServer::new(node);
    let mut module = RpcModule::new(rpc_server);

    module.register_method(RpcMethods::Info.as_str(), |_, context, _| {
        info!("rpc_server: info");
        match context.handle_info() {
            Ok(info) => Ok(info),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    module.register_method(RpcMethods::Version.as_str(), |_, _, _| {
        Ok::<_, ErrorObject>(GIT_DESC.to_string())
    })?;

    module.register_method(RpcMethods::AllowlistDisplay.as_str(), |_, context, _| {
        return match context.node.allowlist() {
            Ok(allowlist) => Ok(allowlist),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        };
    })?;

    module.register_method(RpcMethods::AllowlistAdd.as_str(), |params, context, _| {
        info!("rpc_server: allow list add, params {:?}", params);
        let address = params.one::<String>().map_err(|_| ErrorCode::InvalidParams)?;
        match context.node.add_allowlist(&[address.clone()]) {
            Ok(_) => {
                info!("successfully added address:{}", address);
                Ok::<_, ErrorObject>(())
            }
            Err(e) => {
                error!("failed to add address:{}, error:{:?}", address, e);
                Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>))
            }
        }
    })?;

    module.register_method(RpcMethods::AllowlistRemove.as_str(), |params, context, _| {
        info!("rpc_server: allow list remove, params {:?}", params);
        let address = params.one::<String>().map_err(|_| ErrorCode::InvalidParams)?;
        match context.node.remove_allowlist(&[address.clone()]) {
            Ok(_) => {
                info!("successfully removed address:{}", address);
                Ok::<_, ErrorObject>(())
            }
            Err(e) => {
                error!("failed to remove address:{}, error:{:?}", address, e);
                Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>))
            }
        }
    })?;

    module.register_method(RpcMethods::AddressList.as_str(), |params, context, _| {
        info!("rpc_server: address_list, params {:?}", params);
        let request: AddressListRequest = params.parse().map_err(|_| ErrorCode::InvalidParams)?;
        match context.handle_address_list(request) {
            Ok(response) => Ok(response),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    module.register_method(RpcMethods::AddressVerify.as_str(), |params, context, _| {
        info!("rpc_server: address_verify, params {:?}", params);
        let request: AddressVerifyRequest = params.parse().map_err(|_| ErrorCode::InvalidParams)?;
        match context.handle_address_verify(request) {
            Ok(response) => Ok(response),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    module.register_method(RpcMethods::ChannelList.as_str(), |_, context, _| {
        info!("rpc_server: channel_list");
        match context.handle_channel_list() {
            Ok(response) => Ok(response),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    module.register_method(RpcMethods::ChannelBalance.as_str(), |_, context, _| {
        info!("rpc_server: channel_balance");
        match context.handle_channel_balance() {
            Ok(response) => Ok(response),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    module.register_method(RpcMethods::NodeState.as_str(), |_, context, _| {
        info!("rpc_server: node_state");
        match context.handle_node_state() {
            Ok(response) => Ok(response),
            Err(e) => Err(ErrorObject::owned(e.code() as i32, e.message(), None::<bool>)),
        }
    })?;

    let auth_middleware = ServiceBuilder::new()
        .layer(tower_http::auth::AddAuthorizationLayer::basic(username, password));

    let server = Server::builder()
        .set_http_middleware(auth_middleware)
        .http_only()
        .build(SocketAddr::new(ip, port))
        .await?;

    let addr = server.local_addr()?;
    let handle = server.start(module);
    info!("rpc_server: listening on {} on port {}", addr, port);

    let join_handle = tokio::spawn(async move {
        shutdown_signal.await;
        handle.stop().expect("not already stopped");
        handle.stopped().await;
    });

    Ok((addr, join_handle))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use jsonrpsee::types::Params;
    use lightning_signer::lightning::types::payment::PaymentHash;
    use lightning_signer::util::{
        status::Code,
        test_utils::{
            init_node, init_node_and_channel, make_test_channel_setup, LDK_TEST_NODE_CONFIG,
            REGTEST_NODE_CONFIG, TEST_NODE_CONFIG, TEST_SEED,
        },
    };

    #[test]
    fn test_address_list_default_types() {
        let node = init_node(LDK_TEST_NODE_CONFIG, &TEST_SEED[1]);
        let server = RpcServer::new(node);
        let request = AddressListRequest {
            address_type: None,
            start: Some(1),
            count: Some(3),
            path: Some(DerivationPath::from_str("11h/4").unwrap()),
        };

        let response = server.handle_address_list(request).unwrap();

        assert_eq!(response.addresses.len(), 3);
        assert_eq!(response.network, "testnet");
        assert_eq!(
            0,
            response.addresses.iter().filter(|a| a.address_type != AddressType::Native).count()
        );

        assert_eq!("tb1q2hr2jnqvv8ruegfxs4rau0pm34sa8hk4mlsu3p", response.addresses[0].address);
        assert_eq!("11'/4/1", response.addresses[0].path);
        assert_eq!("tb1q5ranxtm72p6lpujkewj2tj4nkpe9922zfvcxqt", response.addresses[1].address);
        assert_eq!("11'/4/2", response.addresses[1].path);
        assert_eq!("tb1qkqeuxx69rtxfzjw8r3r2yw7jgynrersjue5vc8", response.addresses[2].address);
        assert_eq!("11'/4/3", response.addresses[2].path);
    }

    #[test]
    fn test_address_list_specific_types() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[1]);
        let server = RpcServer::new(node);
        let request = AddressListRequest {
            address_type: Some(AddressType::Wrapped),
            start: Some(0),
            count: Some(3),
            path: None,
        };

        let response = server.handle_address_list(request).unwrap();

        assert_eq!(response.addresses.len(), 3);
        assert_eq!(
            0,
            response.addresses.iter().filter(|a| a.address_type != AddressType::Wrapped).count()
        );
    }

    #[test]
    fn test_address_verify() {
        let node = init_node(REGTEST_NODE_CONFIG, &TEST_SEED[0]);
        let server = RpcServer::new(node.clone());
        let address = "bcrt1q64wyjwvrmdj3uyz8w32mr4qgcv08a833zepjm3".to_owned();
        let request = AddressVerifyRequest {
            address: address.clone(),
            start: Some(9),
            limit: Some(20),
            path: None,
        };

        let response = server.handle_address_verify(request).unwrap();

        assert_eq!(address, response.address);
        assert!(response.valid);
        assert!(response.address_info.is_some());
        let derivation = response.address_info.unwrap();
        assert_eq!(derivation.address_type, AddressType::Native);
        assert_eq!(derivation.path, "11");
    }

    #[test]
    fn test_address_verify_invalid_address() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[1]);
        let server = RpcServer::new(node);

        let request = AddressVerifyRequest {
            address: "invalid_address".to_string(),
            start: Some(0),
            limit: Some(20),
            path: None,
        };

        let result = server.handle_address_verify(request);
        assert!(result.is_err());

        let error = result.unwrap_err();
        assert_eq!(error.code(), Code::InvalidArgument);
        assert_eq!("invalid address: base58 error", error.message());
    }

    #[test]
    fn test_address_verify_not_found_in_range() {
        let node = init_node(REGTEST_NODE_CONFIG, &TEST_SEED[0]);
        let server = RpcServer::new(node);
        let address = "bcrt1q64wyjwvrmdj3uyz8w32mr4qgcv08a833zepjm3".to_owned();
        let request = AddressVerifyRequest {
            address: address.clone(),
            start: Some(0),
            limit: Some(5),
            path: None,
        };

        let result = server.handle_address_verify(request).unwrap();
        assert_eq!(address, result.address);
        assert!(!result.valid);
    }

    #[test]
    fn test_request_parsing() {
        let params = Params::new(Some("{\"address_type\":null,\"count\":null}"));
        let addresslist: AddressListRequest = params.parse().unwrap();
        assert!(addresslist.address_type.is_none());
    }

    #[test]
    fn test_handle_info_includes_node_id() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[0]);
        let server = RpcServer::new(node);

        let info = server.handle_info().unwrap();

        let serialized = serde_json::to_value(&info).unwrap();
        assert_eq!(
            "0266e4598d1d3c415f572a8488830b60f7e744ed9235eb0b1ba93283b315c03518",
            serialized["node_id"].as_str().unwrap()
        );
        assert_eq!("testnet", serialized["network"].as_str().unwrap());
        assert!(!serialized["bip32_xpub"].as_str().unwrap().is_empty());
    }

    #[test]
    fn test_handle_channel_balance_empty() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[0]);
        let server = RpcServer::new(node);

        let response = server.handle_channel_balance().unwrap();

        assert_eq!(0, response.claimable_sat);
        assert_eq!(0, response.channel_count);
        assert_eq!(0, response.stub_count);
    }

    #[test]
    fn test_handle_node_state() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[0]);
        let payee_id = init_node(TEST_NODE_CONFIG, &TEST_SEED[1]).get_id();
        node.add_keysend(payee_id, PaymentHash([1; 32]), 1000).unwrap();
        let server = RpcServer::new(node);

        let response = server.handle_node_state().unwrap();

        assert_eq!(0, response.invoice_count);
        assert_eq!(1, response.payment_count);
        assert_eq!(1000, response.velocity_current_msat);
    }

    #[test]
    fn test_handle_channel_list_with_channel() {
        let (node, _) =
            init_node_and_channel(TEST_NODE_CONFIG, TEST_SEED[0], make_test_channel_setup());
        let server = RpcServer::new(node);

        let response = server.handle_channel_list().unwrap();

        assert_eq!(1, response.channels.len());
        let ch = &response.channels[0];
        assert_eq!("ready", ch.state);
        assert_eq!(Some(3_000_000), ch.channel_value_sat);
        assert_eq!(Some(true), ch.is_outbound);
        assert_eq!(
            Some("0202020202020202020202020202020202020202020202020202020202020202:0"),
            ch.funding_outpoint.as_deref()
        );
        assert_eq!(Some("StaticRemoteKey"), ch.commitment_type.as_deref());
    }

    #[test]
    fn test_handle_channel_balance_with_stub() {
        let node = init_node(TEST_NODE_CONFIG, &TEST_SEED[0]);
        node.new_channel(1, &[0u8; 33], &node).unwrap();
        let server = RpcServer::new(Arc::clone(&node));

        let response = server.handle_channel_balance().unwrap();

        assert_eq!(1, response.stub_count);
        assert_eq!(0, response.channel_count);

        let list_response = server.handle_channel_list().unwrap();
        assert_eq!(1, list_response.channels.len());
        assert_eq!("stub", list_response.channels[0].state);
        assert_eq!(82, list_response.channels[0].channel_id.len());
    }
}

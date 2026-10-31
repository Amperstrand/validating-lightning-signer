use std::collections::BTreeMap;
use std::pin::Pin;
use std::result::Result as StdResult;
use std::sync::Arc;

use async_trait::async_trait;
use futures::{Stream, StreamExt};
use log::*;
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::task::JoinHandle;
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};

use super::incoming::TcpIncoming;
use crate::grpc::signer_loop::InitMessageCache;
use std::sync::atomic::{AtomicU64, Ordering};
use tonic::transport::Error;
use triggered::{Listener, Trigger};
use vlsd::grpc::hsmd::{
    hsmd_server, HsmRequestContext, PingReply, PingRequest, SignerRequest, SignerResponse,
};

struct Requests {
    requests: BTreeMap<u64, ChannelRequest>,
    request_id: AtomicU64,
}

const DUMMY_REQUEST_ID: u64 = u64::MAX;

/// Adapt the hsmd UNIX socket protocol to gRPC streaming
#[derive(Clone)]
pub struct ProtocolAdapter {
    receiver: Arc<Mutex<Receiver<ChannelRequest>>>,
    requests: Arc<Mutex<Requests>>,
    shutdown_trigger: Trigger,
    shutdown_signal: Listener,
    init_message_cache: Arc<std::sync::Mutex<InitMessageCache>>,
}

pub type SignerStream =
    Pin<Box<dyn Stream<Item = StdResult<SignerRequest, Status>> + Send + 'static>>;

impl ProtocolAdapter {
    pub fn new(
        receiver: Receiver<ChannelRequest>,
        shutdown_trigger: Trigger,
        shutdown_signal: Listener,
        init_message_cache: Arc<std::sync::Mutex<InitMessageCache>>,
    ) -> Self {
        ProtocolAdapter {
            receiver: Arc::new(Mutex::new(receiver)),
            requests: Arc::new(Mutex::new(Requests {
                requests: BTreeMap::new(),
                request_id: AtomicU64::new(0),
            })),
            shutdown_trigger,
            shutdown_signal,
            init_message_cache,
        }
    }
    // Get requests from the parent process and feed them to gRPC.
    // Will abort the stream reader task of the parent process goes away.
    pub async fn writer_stream(&self, stream_reader_task: JoinHandle<()>) -> SignerStream {
        let receiver = self.receiver.clone();
        let requests = self.requests.clone();
        let shutdown_signal = self.shutdown_signal.clone();

        let cache = self.init_message_cache.lock().unwrap().clone();
        let output = async_stream::try_stream! {
            // send any init message
            if let Some(message) = cache.init_message.as_ref() {
                yield SignerRequest {
                    request_id: DUMMY_REQUEST_ID,
                    message: message.clone(),
                    context: None,
                };
            }

            // Retransmit any requests that were not processed during the signer's previous connection.
            // We reacquire the lock on each iteration because we yield inside the loop.
            let mut ind = 0;
            loop {
                let reqs = requests.lock().await;
                if ind == 0 {
                    info!("retransmitting {} outstanding requests", reqs.requests.len());
                }
                // get the first key/value where key >= ind
                if let Some((&request_id, req)) = reqs.requests.range(ind..).next() {
                    ind = request_id + 1;
                    debug!("writer sending request {} to signer", request_id);
                    yield Self::make_signer_request(request_id, req);
                } else {
                    break;
                }
            };

            let mut receiver = receiver.lock().await;

            // read requests from parent
            loop {
                tokio::select! {
                    _ = shutdown_signal.clone() => {
                        info!("writer got shutdown_signal");
                        break;
                    }
                    resp_opt = receiver.recv() => {
                        if let Some(req) = resp_opt {
                            let mut reqs = requests.lock().await;
                            let request_id = reqs.request_id.fetch_add(1, Ordering::AcqRel);
                            debug!("writer sending request {} to signer", request_id);
                            let signer_request = Self::make_signer_request(request_id, &req);
                            reqs.requests.insert(request_id, req);
                            yield signer_request;
                        } else {
                            // parent closed UNIX fd - we are shutting down
                            info!("writer: parent closed - shutting down signer stream");
                            break;
                        }
                    }
                }
            }
            info!("stream writer loop finished");
            stream_reader_task.abort();
            // ignore join result
            let _ = stream_reader_task.await;
        };

        Box::pin(output)
    }

    // Get signer responses from gRPC and feed them back to the parent process
    pub fn start_stream_reader(&self, mut stream: Streaming<SignerResponse>) -> JoinHandle<()> {
        let requests = self.requests.clone();
        let shutdown_signal = self.shutdown_signal.clone();
        let shutdown_trigger = self.shutdown_trigger.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_signal.clone() => {
                        info!("reader got shutdown_signal");
                        break;
                    }
                    resp_opt = stream.next() => {
                        match resp_opt {
                            Some(Ok(resp)) => {
                                debug!("got signer response {}", resp.request_id);
                                // A permanent signer refusal is delivered to the
                                // pending request as a first-class error; the
                                // signer loop maps it to an hsmd error reply so
                                // the node fails THAT request loudly. The old
                                // shapes both wedged: the dev build dropped the
                                // reply (the empty-message retry loop = the
                                // silent STFU/signpsbt wedges), the non-dev
                                // build shut the whole proxy down (node death).
                                let permanent_error = if !resp.error.is_empty() && !resp.is_temporary_failure {
                                    error!("signer error on request {}: {}", resp.request_id, resp.error);
                                    Some(resp.error.clone())
                                } else {
                                    None
                                };

                                if resp.is_temporary_failure {
                                    warn!("signer temporary failure on {}: {}", resp.request_id, resp.error);
                                }

                                if resp.request_id == DUMMY_REQUEST_ID {
                                    // A permanently failing replayed init must not
                                    // be discarded: the signer can never initialize
                                    // on this connection (rejected cached init,
                                    // unavailable persistence), so reconnects would
                                    // replay the same failing init forever while
                                    // ordinary requests pend — the silent node wedge.
                                    // Shut the proxy down so the node fails loudly
                                    // and hsmd gets restarted (issue #17).
                                    if let Some(err_text) = permanent_error {
                                        error!(
                                            "replayed init failed permanently: {} — shutting down",
                                            err_text
                                        );
                                        shutdown_trigger.trigger();
                                        break;
                                    }
                                    // TODO do something clever with the init reply message
                                    continue;
                                }

                                let mut reqs = requests.lock().await;
                                let channel_req_opt = reqs.requests.remove(&resp.request_id);
                                if let Some(channel_req) = channel_req_opt {
                                    let reply = ChannelReply {
                                        reply: resp.message,
                                        is_temporary_failure: resp.is_temporary_failure,
                                        error: permanent_error,
                                    };
                                    let send_res = channel_req.reply_tx.send(reply);
                                    if send_res.is_err() {
                                        // The awaiting task is gone (connection
                                        // teardown aborts in-flight request tasks —
                                        // e.g. lightningd's restart closes the hsmd
                                        // socket). The reply is undeliverable by
                                        // definition; dropping it is correct. The
                                        // old proxy-wide shutdown here starved the
                                        // restarted node's HsmdInit (restart-death).
                                        warn!("dropping signer reply: requesting task is gone");
                                    }
                                } else {
                                    // A duplicate or late delivery: the vlsd's stream may
                                    // redeliver a completed request's reply (at-least-once
                                    // semantics, e.g. around reconnects). The pending entry
                                    // was already consumed — dropping the duplicate is
                                    // correct. The old proxy-wide shutdown here re-introduced
                                    // the teardown-abort class (the quiet-box probe failure:
                                    // 'unknown request ID 1' seconds after launch).
                                    warn!(
                                        "dropping reply for unknown request ID {}",
                                        resp.request_id
                                    );
                                }
                            }
                            Some(Err(err)) => {
                                // signer connection error
                                error!("got signer gRPC error {}", err);
                                break;
                            }
                            None => {
                                // signer closed connection
                                info!("response task closing - EOF");
                                break;
                            }
                        }
                    }
                }
            }
            info!("stream reader loop finished");
        })
    }

    fn make_signer_request(request_id: u64, req: &ChannelRequest) -> SignerRequest {
        let context = req.client_id.as_ref().map(|c| HsmRequestContext {
            peer_id: c.peer_id.to_vec(),
            dbid: c.dbid,
            capabilities: 0,
        });
        SignerRequest { request_id, message: req.message.clone(), context }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grpc::signer_loop::InitMessageCache;
    use std::sync::{Arc, Mutex};
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio::time::{timeout, Duration};
    use vlsd::grpc::hsmd::hsmd_client::HsmdClient;
    use vlsd::grpc::hsmd::hsmd_server::HsmdServer;
    use vlsd::grpc::hsmd::SignerResponse;

    async fn spawn_hsmd_service(service: HsmdService) -> std::net::SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind loopback");
        let addr = listener.local_addr().expect("local addr");
        let incoming = futures::stream::poll_fn(move |cx| match listener.poll_accept(cx) {
            std::task::Poll::Ready(Ok((stream, _))) => std::task::Poll::Ready(Some(Ok(stream))),
            std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Some(Err(e))),
            std::task::Poll::Pending => std::task::Poll::Pending,
        });
        tokio::spawn(async move {
            tonic::transport::Server::builder()
                .add_service(HsmdServer::new(service))
                .serve_with_incoming(incoming)
                .await
                .expect("hsmd test service");
        });
        addr
    }

    fn seeded_init_cache() -> Arc<Mutex<InitMessageCache>> {
        let cache = Arc::new(Mutex::new(InitMessageCache::new()));
        // content is opaque to the adapter; only presence matters
        cache.lock().unwrap().init_message = Some(vec![0x0b, 0x00]);
        cache
    }

    #[tokio::test]
    async fn replayed_init_permanent_failure_triggers_shutdown() {
        let (shutdown_trigger, shutdown_signal) = triggered::trigger();
        let service =
            HsmdService::new(shutdown_trigger, shutdown_signal.clone(), seeded_init_cache());
        let addr = spawn_hsmd_service(service).await;

        let mut client = HsmdClient::connect(format!("http://{}", addr)).await.expect("connect");
        let (tx, rx) = mpsc::channel(1);
        let outbound = futures::stream::unfold(rx, |mut rx| async move {
            rx.recv().await.map(|resp| (resp, rx))
        });
        let mut response_stream =
            client.signer_stream(outbound).await.expect("signer_stream").into_inner();

        // The writer must first replay the cached init at DUMMY_REQUEST_ID.
        let first = timeout(Duration::from_secs(30), response_stream.next())
            .await
            .expect("timed out waiting for the replayed init")
            .expect("stream open")
            .expect("replayed init ok");
        assert_eq!(first.request_id, u64::MAX);

        // A permanent refusal of the replayed init must shut the proxy
        // down: the old reader discarded it at the dummy-ID check and the
        // reconnect loop replayed the failing init forever while ordinary
        // requests pend — the silent node wedge (issue #17).
        if tx
            .send(SignerResponse {
                request_id: u64::MAX,
                message: vec![],
                error: "persistence unavailable".to_string(),
                is_temporary_failure: false,
            })
            .await
            .is_err()
        {
            panic!("refusal receiver gone before delivery");
        }

        let fired = timeout(Duration::from_secs(30), shutdown_signal).await;
        assert!(fired.is_ok(), "a permanently failing replayed init must trigger shutdown");
    }
}

/// A request
/// Responses are received on the oneshot sender inside this struct
pub struct ChannelRequest {
    pub message: Vec<u8>,
    pub reply_tx: oneshot::Sender<ChannelReply>,
    pub client_id: Option<ClientId>,
}

// mpsc reply
pub struct ChannelReply {
    pub reply: Vec<u8>,
    pub is_temporary_failure: bool,
    /// Permanent signer refusal text (error set, is_temporary_failure unset):
    /// the signer loop maps this to an hsmd error reply for the pending
    /// request instead of retrying or shutting down.
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub struct ClientId {
    pub peer_id: [u8; 33],
    pub dbid: u64,
}

/// Listens for a connection from the signer, and then sends requests to it
#[derive(Clone)]
pub struct HsmdService {
    #[allow(unused)]
    shutdown_trigger: Trigger,
    adapter: ProtocolAdapter,
    sender: Sender<ChannelRequest>,
}

impl HsmdService {
    /// Create the service
    pub fn new(
        shutdown_trigger: Trigger,
        shutdown_signal: Listener,
        init_message_cache: Arc<std::sync::Mutex<InitMessageCache>>,
    ) -> Self {
        let (sender, receiver) = mpsc::channel(1000);
        let adapter = ProtocolAdapter::new(
            receiver,
            shutdown_trigger.clone(),
            shutdown_signal.clone(),
            init_message_cache,
        );

        HsmdService { shutdown_trigger, adapter, sender }
    }

    pub async fn start(
        self,
        incoming: TcpIncoming,
        shutdown_signal: Listener,
    ) -> Result<(), Error> {
        let service = Server::builder()
            .add_service(hsmd_server::HsmdServer::new(self))
            .serve_with_incoming_shutdown(incoming, shutdown_signal);
        service.await
    }

    /// Get the sender for the request channel
    pub fn sender(&self) -> Sender<ChannelRequest> {
        self.sender.clone()
    }
}

#[async_trait]
impl hsmd_server::Hsmd for HsmdService {
    async fn ping(&self, request: Request<PingRequest>) -> StdResult<Response<PingReply>, Status> {
        info!("got ping request");
        let r = request.into_inner();
        Ok(Response::new(PingReply { message: r.message }))
    }

    type SignerStreamStream = SignerStream;

    async fn signer_stream(
        &self,
        request: Request<Streaming<SignerResponse>>,
    ) -> StdResult<Response<Self::SignerStreamStream>, Status> {
        let request_stream = request.into_inner();

        let stream_reader_task = self.adapter.start_stream_reader(request_stream);

        let response_stream = self.adapter.writer_stream(stream_reader_task).await;

        Ok(Response::new(response_stream as Self::SignerStreamStream))
    }
}

//! RPC connection support, mainloop, and protocol implementation.

pub(crate) mod auth;
mod methods;
use std::{
    collections::HashMap,
    io::Error as IoError,
    pin::Pin,
    sync::{Arc, Mutex, RwLock, Weak},
};

use asynchronous_codec::JsonCodecError;
use derive_deftly::Deftly;
use futures::{
    channel::mpsc,
    stream::{FusedStream, FuturesUnordered},
    AsyncWriteExt as _, FutureExt, Sink, SinkExt as _, StreamExt,
};
use rpc::dispatch::BoxedUpdateSink;
use serde_json::error::Category as JsonErrorCategory;
use tor_async_utils::{mpsc_channel_no_memquota, SinkExt as _};

use crate::{
    cancel::{self, Cancel, CancelHandle},
    err::RequestParseError,
    globalid::{GlobalId, MacKey},
    msgs::{BoxedResponse, FlexibleRequest, ReqMeta, Request, RequestId, ResponseBody},
    objmap::{GenIdx, ObjMap},
    RpcMgr,
};

use tor_rpcbase::templates::*;
use tor_rpcbase::{self as rpc, RpcError};

/// An open connection from an RPC client.
///
/// Tracks information that persists from one request to another.
///
/// The client might not have authenticated;
/// access and permissions control is handled via the capability system.
/// Specifically, the `objects` table in `Inner` hold capabilities
/// that the client will use to do things,
/// including an `RpcSession`.
///
/// # In the Arti RPC System
///
/// A connection to Arti.
///
/// This object is available as soon as you open a connection to Arti RPC,
/// even before you authenticate.  Its ObjectId is always `"connection"`.
///
/// Because this object is available before authentication,
/// it provides only those methods that you need
/// in order to perform authentication
/// and receive an `RpcSession`.
#[derive(Deftly)]
#[derive_deftly(Object)]
pub struct Connection {
    /// The mutable state of this connection.
    inner: Mutex<Inner>,

    /// Lookup table to find the implementations for methods
    /// based on RPC object and method types.
    ///
    /// **NOTE: observe the [Lock hierarchy](crate::mgr::Inner#lock-hierarchy)**
    dispatch_table: Arc<RwLock<rpc::DispatchTable>>,

    /// A unique identifier for this connection.
    ///
    /// This kind of ID is used to refer to the connection from _outside_ of the
    /// context of an RPC connection: it can uniquely identify the connection
    /// from e.g. a SOCKS session so that clients can attach streams to it.
    connection_id: ConnectionId,

    /// A `MacKey` used to create `GlobalIds` for the objects whose identifiers
    /// need to exist outside this connection.
    global_id_mac_key: MacKey,

    /// A reference to the manager associated with this session.
    mgr: Weak<RpcMgr>,

    /// The authentication type that's required in order to get a session.
    require_auth: tor_rpc_connect::auth::RpcAuth,
}

/// The inner, lock-protected part of an RPC connection.
struct Inner {
    /// Map from request ID to handles; used when we need to cancel a request.
    //
    // TODO: We have two options here for handling colliding IDs.  We can either turn
    // this into a multimap, or we can declare that cancelling a request only
    // cancels the most recent request sent with that ID.
    inflight: HashMap<RequestId, Option<CancelHandle>>,

    /// An object map used to look up most objects by ID, and keep track of
    /// which objects are owned by this connection.
    objects: ObjMap,

    /// A reference to this connection itself.
    ///
    /// Used when we're looking up the connection within the RPC system as an object.
    ///
    /// TODO RPC: Maybe there is an easier way to do this while keeping `context` object-save?
    this_connection: Option<Weak<Connection>>,
}

/// How many updates can be pending, per connection, before they start to block?
const UPDATE_CHAN_SIZE: usize = 128;

/// A type-erased [`FusedStream`] yielding [`Request`]s.
//
// (We name this type and [`BoxedResponseSink`] below so as to keep the signature for run_loop
// nice and simple.)
pub(crate) type BoxedRequestStream = Pin<
    Box<dyn FusedStream<Item = Result<FlexibleRequest, asynchronous_codec::JsonCodecError>> + Send>,
>;

/// A type-erased [`Sink`] accepting [`BoxedResponse`]s.
pub(crate) type BoxedResponseSink =
    Pin<Box<dyn Sink<BoxedResponse, Error = asynchronous_codec::JsonCodecError> + Send>>;

/// A random value used to identify an connection.
#[derive(
    Copy,
    Clone,
    Debug,
    Eq,
    PartialEq,
    Hash,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
)]
pub(crate) struct ConnectionId([u8; 16]);

impl ConnectionId {
    /// The length of a ConnectionId.
    pub(crate) const LEN: usize = 16;
}

impl Connection {
    /// A special object ID that indicates the connection itself.
    ///
    /// On a fresh connection, this is the only ObjectId that exists.
    //
    // TODO: We might want to move responsibility for tracking this ID and its value into ObjMap.
    const CONNECTION_OBJ_ID: &'static str = "connection";

    /// Create a new connection.
    pub(crate) fn new(
        connection_id: ConnectionId,
        dispatch_table: Arc<RwLock<rpc::DispatchTable>>,
        global_id_mac_key: MacKey,
        mgr: Weak<RpcMgr>,
        require_auth: tor_rpc_connect::auth::RpcAuth,
    ) -> Arc<Self> {
        Arc::new_cyclic(|this_connection| Self {
            inner: Mutex::new(Inner {
                inflight: HashMap::new(),
                objects: ObjMap::new(),
                this_connection: Some(Weak::clone(this_connection)),
            }),
            dispatch_table,
            connection_id,
            global_id_mac_key,
            mgr,
            require_auth,
        })
    }

    /// If possible, convert an `ObjectId` into a `GenIdx` that can be used in
    /// this connection's ObjMap.
    fn id_into_local_idx(&self, id: &rpc::ObjectId) -> Result<GenIdx, rpc::LookupError> {
        // TODO RPC: Use a tag byte instead of a magic length.

        if id.as_ref().len() == GlobalId::B64_ENCODED_LEN {
            // This is the right length to be a GlobalId; let's see if it really
            // is one.
            //
            // Design note: It's not really necessary from a security POV to
            // check the MAC here; any possible GenIdx we return will either
            // refer to some object we're allowed to name in this session, or to
            // no object at all.  Still, we check anyway, since it shouldn't
            // hurt to do so.
            let global_id = GlobalId::try_decode(&self.global_id_mac_key, id)?;
            // We have a GlobalId with a valid MAC. Let's make sure it applies
            // to this connection's ObjMap.  (We do not support referring to
            // anyone else's objects.)
            //
            // Design note: As above, this check is a protection against
            // accidental misuse, not a security feature: even if we removed
            // this check, we would still only allow objects that this session
            // is allowed to name.
            if global_id.connection == self.connection_id {
                Ok(global_id.local_id)
            } else {
                Err(rpc::LookupError::NoObject(id.clone()))
            }
        } else {
            // It's not a GlobalId; let's see if we can make sense of it as an
            // ObjMap index.
            Ok(GenIdx::try_decode(id)?)
        }
    }

    /// Look up a given object by its object ID relative to this connection.
    pub(crate) fn lookup_object(
        &self,
        id: &rpc::ObjectId,
    ) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        if id.as_ref() == Self::CONNECTION_OBJ_ID {
            let this = self
                .inner
                .lock()
                .expect("lock poisoned")
                .this_connection
                .as_ref()
                .ok_or_else(|| rpc::LookupError::NoObject(id.clone()))?
                .upgrade()
                .ok_or_else(|| rpc::LookupError::NoObject(id.clone()))?;
            Ok(this as Arc<_>)
        } else {
            let local_id = self.id_into_local_idx(id)?;

            self.lookup_by_idx(local_id)
                .ok_or(rpc::LookupError::NoObject(id.clone()))
        }
    }

    /// As `lookup_object`, but expect a `GenIdx`.
    pub(crate) fn lookup_by_idx(&self, idx: crate::objmap::GenIdx) -> Option<Arc<dyn rpc::Object>> {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.objects.lookup(idx)
    }

    /// Un-register the request `id` and stop tracking its information.
    fn remove_request(&self, id: &RequestId) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.inflight.remove(id);
    }

    /// Register the request `id` as a cancellable request.
    ///
    /// If `handle` is none, register it as an uncancellable request.
    fn register_request(&self, id: RequestId, handle: Option<CancelHandle>) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.inflight.insert(id, handle);
    }

    /// Try to cancel the request `id`.
    ///
    /// Return an error when `id` cannot be found, or cannot be cancelled.
    /// (These cases are indistinguishable.)
    fn cancel_request(&self, id: &RequestId) -> Result<(), CancelError> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        match inner.inflight.remove(id) {
            Some(Some(handle)) => {
                drop(inner);
                handle.cancel()?;
                Ok(())
            }
            Some(None) => {
                // Put it back in case somebody tries again.
                inner.inflight.insert(id.clone(), None);
                Err(CancelError::CannotCancelRequest)
            }
            None => Err(CancelError::RequestNotFound),
        }
    }

    /// Run in a loop, decoding JSON requests from `input` and
    /// writing JSON responses onto `output`.
    pub async fn run<IN, OUT>(
        self: Arc<Self>,
        input: IN,
        mut output: OUT,
    ) -> Result<(), ConnectionError>
    where
        IN: futures::AsyncRead + Send + Sync + Unpin + 'static,
        OUT: futures::AsyncWrite + Send + Sync + Unpin + 'static,
    {
        /// Banner line to send, indicating that Arti is ready to receive requests.
        ///
        /// The key in this json object is mandatory; the value can be anything.
        const BANNER: &[u8] = b"{\"arti_rpc\":{}}\n";

        output
            .write_all(BANNER)
            .await
            .map_err(|e| ConnectionError::WriteFailed(Arc::new(e)))?;

        let write = Box::pin(asynchronous_codec::FramedWrite::new(
            output,
            crate::codecs::JsonLinesEncoder::<BoxedResponse>::default(),
        ));

        let read = Box::pin(
            asynchronous_codec::FramedRead::new(
                input,
                asynchronous_codec::JsonCodec::<(), FlexibleRequest>::new(),
            )
            .fuse(),
        );

        self.run_loop(read, write).await
    }

    /// Run in a loop, handling requests from `request_stream` and writing
    /// responses onto `response_stream`.
    ///
    /// After this returns, even if it returns `Ok(())`, the connection must no longer be used.
    pub(crate) async fn run_loop(
        self: Arc<Self>,
        mut request_stream: BoxedRequestStream,
        mut response_sink: BoxedResponseSink,
    ) -> Result<(), ConnectionError> {
        // This function will multiplex on three streams:
        // * `request_stream` -- a stream of incoming requests from the client.
        // * `finished_requests` -- a stream of requests that are done.
        // * `rx_response` -- a stream of updates and final responses sent from
        //   in-progress tasks. (We put updates and final responsese onto the
        //   same channel to ensure that they stay in-order for each method
        //   invocation.
        //
        // Note that the blocking behavior here is deliberate: We want _all_ of
        // these reads to start blocking when response_sink.send is blocked.

        // TODO RPC should this queue participate in memquota?
        let (tx_response, mut rx_response) =
            mpsc_channel_no_memquota::<BoxedResponse>(UPDATE_CHAN_SIZE);

        let mut finished_requests = FuturesUnordered::new();
        finished_requests.push(futures::future::pending().boxed());

        /// Helper: enforce an explicit "continue".
        struct Continue;

        // We create a separate async block here and immediately await it,
        // so that any internal `returns` and `?`s do not escape the function.
        let outcome = async {
            loop {
                let _: Continue = futures::select! {
                    r = finished_requests.next() => {
                        // A task is done, so we can forget about it.
                        let () = r.expect("Somehow, future::pending() terminated.");
                        Continue
                    }

                    r = rx_response.next() => {
                        // The future for some request has sent a response (success,
                        // failure, or update), so we can inform the client.
                        let update = r.expect("Somehow, tx_update got closed.");
                        debug_assert!(! update.body.is_final());
                        // Calling `await` here (and below) is deliberate: we _want_
                        // to stop reading the client's requests if the client is
                        // not reading their responses (or not) reading them fast
                        // enough.
                        response_sink.send(update).await.map_err(ConnectionError::writing)?;
                        Continue
                    }

                    req = request_stream.next() => {
                        match req {
                            None => {
                                // We've reached the end of the stream of requests;
                                // time to close.
                                return Ok(());
                            }
                            Some(Err(e)) => {
                                // We got a non-recoverable error from the JSON codec.
                                return Err(ConnectionError::from_read_error(e));

                            }
                            Some(Ok(FlexibleRequest::Invalid(bad_req))) => {
                                // We decoded the request as Json, but not as a `Valid`` request.
                                // Send back a response indicating what was wrong with it.
                                let response = BoxedResponse::from_error(
                                    bad_req.id().cloned(), bad_req.error()
                                );
                                response_sink
                                    .send(response)
                                    .await
                                    .map_err( ConnectionError::writing)?;
                                if bad_req.id().is_none() {
                                    // The spec says we must close the connection in this case.
                                    return Err(bad_req.error().into());
                                }
                                Continue

                            }
                            Some(Ok(FlexibleRequest::Valid(req))) => {
                                // We have a request. Time to launch it!
                                let tx = tx_response.clone();
                                let fut = self.run_method_and_deliver_response(tx, req);
                                finished_requests.push(fut.boxed());
                                Continue
                            }
                        }
                    }
                };
            }
        }
        .await;

        match outcome {
            Err(e) if e.is_connection_close() => Ok(()),
            other => other,
        }
    }

    /// Invoke `request` and send all of its responses to `tx_response`.
    async fn run_method_and_deliver_response(
        self: &Arc<Self>,
        mut tx_response: mpsc::Sender<BoxedResponse>,
        request: Request,
    ) {
        let Request {
            id,
            obj,
            meta,
            method,
        } = request;

        let update_sender: BoxedUpdateSink = if meta.updates {
            let id_clone = id.clone();
            let sink =
                tx_response
                    .clone()
                    .with_fn(move |obj: Box<dyn erased_serde::Serialize + Send>| {
                        Result::<BoxedResponse, _>::Ok(BoxedResponse {
                            id: Some(id_clone.clone()),
                            body: ResponseBody::Update(obj),
                        })
                    });
            Box::pin(sink)
        } else {
            let sink = futures::sink::drain().sink_err_into();
            Box::pin(sink)
        };

        let is_cancellable = method.is_cancellable();

        // Create `run_method_lowlevel` future, and make it cancellable.
        let fut = self.run_method_lowlevel(update_sender, obj, method, meta);

        // Optionally register the future as cancellable.  Then run it to completion.
        let outcome = if is_cancellable {
            let (handle, fut) = Cancel::new(fut);
            self.register_request(id.clone(), Some(handle));
            fut.await
        } else {
            self.register_request(id.clone(), None);
            Ok(fut.await)
        };

        // Figure out how to respond.
        let body = match outcome {
            Ok(Ok(value)) => ResponseBody::Success(value),
            // TODO: If we're going to box this, let's do so earlier.
            Ok(Err(err)) => {
                if err.is_internal() {
                    tracing::warn!(
                        "Reporting an internal error on an RPC connection: {:?}",
                        err
                    );
                }
                ResponseBody::Error(Box::new(err))
            }
            Err(_cancelled) => ResponseBody::Error(Box::new(rpc::RpcError::from(RequestCancelled))),
        };

        // Send the response.
        //
        // (It's okay to ignore the error here, since it can only mean that the
        // RPC connection has closed.)
        let _ignore_err = tx_response
            .send(BoxedResponse {
                id: Some(id.clone()),
                body,
            })
            .await;

        // Unregister the request.
        //
        // TODO: This may unregister a different request if the user sent
        // in another request with the same ID.
        self.remove_request(&id);
    }

    /// Run a single method, and return its final response.
    ///
    /// If `tx_updates` is provided, and this method generates updates, it
    /// should send those updates on `tx_updates`
    ///
    /// Note that this function is able to send responses with IDs that do not
    /// match the original.  It should enforce correct IDs on whatever response
    /// it generates.
    async fn run_method_lowlevel(
        self: &Arc<Self>,
        tx_updates: rpc::dispatch::BoxedUpdateSink,
        obj_id: rpc::ObjectId,
        method: Box<dyn rpc::DeserMethod>,
        meta: ReqMeta,
    ) -> Result<Box<dyn erased_serde::Serialize + Send + 'static>, rpc::RpcError> {
        let obj = self.lookup_object(&obj_id)?;

        if !meta.require.is_empty() {
            // TODO RPC: Eventually, we will need a way to tell which "features" are actually
            // available.  But for now, we have no features, so if the require list is nonempty,
            // we can safely reject the request.
            return Err(MissingFeaturesError(meta.require).into());
        }

        let context: Arc<dyn rpc::Context> = self.clone() as Arc<_>;

        let invoke_future =
            rpc::invoke_rpc_method(context, &obj_id, obj, method.upcast_box(), tx_updates)?;

        // Note that we drop the read lock before we await this future!
        invoke_future.await
    }

    /// Try to get a strong reference to the RpcMgr for this connection, and
    /// return an error if we can't.
    pub(crate) fn mgr(&self) -> Result<Arc<RpcMgr>, MgrDisappearedError> {
        self.mgr
            .upgrade()
            .ok_or(MgrDisappearedError::RpcMgrDisappeared)
    }
}

/// An error returned when an RPC request lists some feature as required,
/// but we don't have every such feature.
#[derive(Clone, Debug, thiserror::Error)]
#[error("Required features not available")]
struct MissingFeaturesError(
    /// A list of the features that were requested but not available.
    Vec<String>,
);

impl From<MissingFeaturesError> for RpcError {
    fn from(err: MissingFeaturesError) -> Self {
        let mut e = RpcError::new(
            err.to_string(),
            tor_rpcbase::RpcErrorKind::FeatureNotPresent,
        );
        e.set_datum("rpc:unsupported_features".to_string(), err.0)
            .expect("invalid keyword");
        e
    }
}

/// A failure that results in closing a [`Connection`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConnectionError {
    /// Unable to write to our connection.
    #[error("Could not write to connection")]
    WriteFailed(#[source] Arc<IoError>),
    /// Read error from connection.
    #[error("Problem reading from connection")]
    ReadFailed(#[source] Arc<IoError>),
    /// Read something that we could not decode.
    #[error("Unable to decode request from connection")]
    DecodeFailed(#[source] Arc<serde_json::Error>),
    /// Unable to write our response as json.
    #[error("Unable to encode response onto connection")]
    EncodeFailed(#[source] Arc<serde_json::Error>),
    /// We encountered a problem when parsing a request that was (in our judgment)
    /// too severe to recover from.
    #[error("Unrecoverable problem from parsed request")]
    RequestParseFailed(#[from] RequestParseError),
}

impl ConnectionError {
    /// Construct a new `ConnectionError` from a `JsonCodecError` that has occurred while writing.
    fn writing(error: JsonCodecError) -> Self {
        match error {
            JsonCodecError::Io(e) => Self::WriteFailed(Arc::new(e)),
            JsonCodecError::Json(e) => Self::EncodeFailed(Arc::new(e)),
        }
    }

    /// Return true if this error is (or might be) due to the peer closing the connection.
    ///
    /// Such errors should be tolerated without much complaint;
    /// other errors should at least be logged somewhere.
    fn is_connection_close(&self) -> bool {
        use std::io::ErrorKind as IK;
        use JsonErrorCategory as JK;
        #[allow(clippy::match_like_matches_macro)]
        match self {
            Self::ReadFailed(e) | Self::WriteFailed(e) => match e.kind() {
                IK::UnexpectedEof | IK::ConnectionAborted | IK::BrokenPipe => true,
                _ => false,
            },
            Self::DecodeFailed(e) => match e.classify() {
                JK::Eof => true,
                _ => false,
            },
            _ => false,
        }
    }

    /// Construct a `ConnectionError` from a JsonCodecError that occurred while reading.
    fn from_read_error(error: JsonCodecError) -> Self {
        match error {
            JsonCodecError::Io(e) => Self::ReadFailed(Arc::new(e)),
            JsonCodecError::Json(e) => Self::DecodeFailed(Arc::new(e)),
        }
    }
}

/// A failure from trying to upgrade a `Weak<RpcMgr>`.
#[derive(Clone, Debug, thiserror::Error, serde::Serialize)]
pub(crate) enum MgrDisappearedError {
    /// We tried to upgrade our reference to the RpcMgr, and failed.
    #[error("RPC manager disappeared; Arti is shutting down?")]
    RpcMgrDisappeared,
}
impl tor_error::HasKind for MgrDisappearedError {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::ArtiShuttingDown
    }
}

impl rpc::Context for Connection {
    fn lookup_object(&self, id: &rpc::ObjectId) -> Result<Arc<dyn rpc::Object>, rpc::LookupError> {
        Connection::lookup_object(self, id)
    }

    fn register_owned(&self, object: Arc<dyn rpc::Object>) -> rpc::ObjectId {
        let use_global_id = object.expose_outside_of_session();
        let local_id = self
            .inner
            .lock()
            .expect("Lock poisoned")
            .objects
            .insert_strong(object);

        // Design note: It is a deliberate decision to _always_ use GlobalId for
        // objects whose IDs are _ever_ exported for use in SOCKS requests.  Some
        // alternatives would be to use GlobalId conditionally, or to have a
        // separate Method to create a new GlobalId given an existing LocalId.
        if use_global_id {
            GlobalId::new(self.connection_id, local_id).encode(&self.global_id_mac_key)
        } else {
            local_id.encode()
        }
    }

    fn release_owned(&self, id: &rpc::ObjectId) -> Result<(), rpc::LookupError> {
        let removed_some = if id.as_ref() == Self::CONNECTION_OBJ_ID {
            self.inner
                .lock()
                .expect("Lock poisoned")
                .this_connection
                .take()
                .is_some()
        } else {
            let idx = self.id_into_local_idx(id)?;

            if !idx.is_strong() {
                return Err(rpc::LookupError::WrongType(id.clone()));
            }

            self.inner
                .lock()
                .expect("Lock poisoned")
                .objects
                .remove(idx)
                .is_some()
        };

        if removed_some {
            Ok(())
        } else {
            Err(rpc::LookupError::NoObject(id.clone()))
        }
    }

    fn dispatch_table(&self) -> &Arc<std::sync::RwLock<rpc::DispatchTable>> {
        &self.dispatch_table
    }
}

/// An error given when an RPC request is cancelled.
///
/// This is a separate type from [`crate::cancel::Cancelled`] since eventually
/// we want to move that type into a general-purpose location, and make it not
/// RPC-specific.
#[derive(thiserror::Error, Clone, Debug, serde::Serialize)]
#[error("RPC request was cancelled")]
pub(crate) struct RequestCancelled;

impl From<RequestCancelled> for RpcError {
    fn from(_: RequestCancelled) -> Self {
        RpcError::new(
            "Request cancelled".into(),
            rpc::RpcErrorKind::RequestCancelled,
        )
    }
}

/// An error given when we attempt to cancel an RPC request, but cannot.
///
#[derive(thiserror::Error, Clone, Debug, serde::Serialize)]
pub(crate) enum CancelError {
    /// We didn't find any request with the provided ID.
    ///
    /// Since we don't keep track of requests after they finish or are cancelled,
    /// we cannot distinguish the cases where a request has finished,
    /// where the request has been cancelled,
    /// or where the request never existed.
    /// Therefore we collapse them into a single error type.
    #[error("RPC request not found")]
    RequestNotFound,

    /// This kind of request cannot be cancelled.
    #[error("Uncancellable request")]
    CannotCancelRequest,

    /// We tried to cancel a request but found out it was already cancelled.
    ///
    /// This error should be impossible.
    #[error("Request somehow cancelled twice!")]
    AlreadyCancelled,
}

impl From<cancel::CannotCancel> for CancelError {
    fn from(value: cancel::CannotCancel) -> Self {
        use cancel::CannotCancel as CC;
        use CancelError as CE;
        match value {
            CC::Cancelled => CE::AlreadyCancelled,
            // We map "finished" to RequestNotFound since it is not in the general case
            // distinguishable from it; see documentation on RequestNotFound.
            CC::Finished => CE::RequestNotFound,
        }
    }
}

impl From<CancelError> for RpcError {
    fn from(err: CancelError) -> Self {
        use rpc::RpcErrorKind as REK;
        use CancelError as CE;
        let code = match err {
            CE::RequestNotFound => REK::RequestError,
            CE::CannotCancelRequest => REK::RequestError,
            CE::AlreadyCancelled => REK::InternalError,
        };
        RpcError::new(err.to_string(), code)
    }
}

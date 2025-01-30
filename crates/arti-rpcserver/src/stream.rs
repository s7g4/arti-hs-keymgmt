//! Objects that can become or wrap a [`arti_client::DataStream`].

use arti_client::rpc::{
    ClientConnectionResult, ConnectWithPrefs, ResolvePtrWithPrefs, ResolveWithPrefs,
};
use derive_deftly::Deftly;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tor_error::into_internal;
use tor_proto::stream::ClientDataStreamCtrl;
use tor_rpcbase::{self as rpc, templates::*};

use crate::RpcSession;

/// An RPC object representing a single-use client that captures a data-stream.
///
/// This object is returned by the `arti:new_oneshot_client` method, and starts out with
/// enough information to know how to create a `DataStream`, or to respond
/// to some other SOCKS request.
/// When this object is the target of a SOCKS request,
/// it takes its target address, port, and isolation parameters from the SOCKS handshake,
/// and launches a data stream.
/// It then becomes interchangeable with the stream that was launched.
///
/// This object is single-use: once a SOCKS request has referred to it,
/// it cannot be used for any other SOCKS request.
/// (Otherwise, it could not be usable interchangeably with the `DataStream` it creates.)
///
/// The ObjectID for this object can be used as the target of a SOCKS request.
#[derive(Deftly)]
#[derive_deftly(Object)]
#[deftly(rpc(expose_outside_of_session))]
pub(crate) struct OneshotClient {
    /// The inner state of this object.
    inner: Mutex<Inner>,
}

/// The inner state of an `OneshotClient`.
///
/// A stream is created in the "Unused" state.
enum Inner {
    /// Newly constructed: Waiting for a SOCKS command.
    ///
    /// This is the initial state for every OneshotClient.
    ///
    /// It may become `Launching` or `UsedToResolve`.
    Unused(Arc<dyn rpc::Object>),

    /// The actual connection is being made, ie we are within `connect_with_prefs`
    ///
    /// If the state is `Launching`, no one except `connect_with_prefs` may change it.
    ///
    /// From this state, a stream may become `Stream`, or `StreamFailed`.
    Launching,

    /// Stream constructed; may or may not be connected.
    ///
    /// A stream does not exit this state.  Even if the stream is closed or fails,
    /// its `ClientDataStreamCtrl` remains until it is dropped.
    Stream(Arc<ClientDataStreamCtrl>),

    /// Stream was used for a resolve or resolve_ptr request; there is no underlying stream.
    ///
    /// A stream does not exit this state, even if resolve request fails.
    //
    // TODO RPC: We may want to make this state hold more information if someday we
    // make DNS requests into objects that we can inspect while they are running.
    UsedToResolve,

    /// Failed to construct the tor_proto::DataStream object.
    ///
    /// A stream does not exit this state.
    StreamFailed,
}

/// Error returned by an operations from OneshotClient.
#[derive(Debug, Clone, thiserror::Error)]
enum OneshotClientError {
    /// Application tried to open a stream using a OneshotClient,
    /// but that OneshotClient had already been used previously.
    #[error("Data stream object already used")]
    AlreadyUsed,
}

impl tor_error::HasKind for OneshotClientError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use OneshotClientError as E;
        match self {
            E::AlreadyUsed => EK::BadApiUsage, // TODO RPC: is this the correct ErrorKind?
        }
    }
}

impl OneshotClient {
    /// Construct a new unused OneshotClient that will make its connection
    /// with `connector`.
    ///
    /// The `connector` object should implement at least one of ConnectWithPrefs, ResolveWithPrefs,
    /// or ResolvePtrWithPrefs, or else it won't actually be useful for anything.
    pub(crate) fn new(connector: Arc<dyn rpc::Object>) -> Self {
        Self {
            inner: Mutex::new(Inner::Unused(connector)),
        }
    }

    /// If this `OneshotClient` is in state Unused, replace its state with `new_state`
    /// and return the ClientConnectionTarget.  Otherwise, leave its state unchanged
    /// and return an error.
    fn take_connector(&self, new_state: Inner) -> Result<Arc<dyn rpc::Object>, OneshotClientError> {
        let mut inner = self.inner.lock().expect("poisoned lock");
        let val = std::mem::replace(&mut *inner, new_state);
        if let Inner::Unused(conn) = val {
            Ok(conn)
        } else {
            *inner = val;
            Err(OneshotClientError::AlreadyUsed)
        }
    }

    /// Return the `ClientDataStreamCtrl` for this stream, if it has one.
    #[allow(dead_code)]
    fn get_ctrl(&self) -> Option<Arc<ClientDataStreamCtrl>> {
        let inner = self.inner.lock().expect("poisoned lock");
        if let Inner::Stream(s) = &*inner {
            Some(s.clone())
        } else {
            None
        }
    }
}

/// Invoke ConnectWithPrefs on an OneshotClient.
///
/// Unlike the other methods on OneshotClient, this one is somewhat complex, since it must
/// re-register the resulting datastream once it has one.
async fn oneshot_client_connect_with_prefs(
    rpc_data_stream: Arc<OneshotClient>,
    mut method: Box<ConnectWithPrefs>,
    ctx: Arc<dyn rpc::Context>,
) -> ClientConnectionResult<arti_client::DataStream> {
    // Extract the connector.
    //
    // As we do this, we put this OneshotClient into a Launching state.
    //
    // (`Launching`` wouldn't need to exist if we `connect_with_prefs` were synchronous,
    // but it isn't synchronous, so `Launching` is an observable state.)
    let connector = rpc_data_stream
        .take_connector(Inner::Launching)
        .map_err(|e| Box::new(e) as _)?;

    let was_optimistic = method.prefs.is_optimistic();
    // We want this to be treated internally as an "optimistic" connection,
    // so that inner connect_with_prefs() will return ASAP.
    method.prefs.optimistic();

    // Now, launch the connection.  Since we marked it as optimistic,
    // this call should return almost immediately.
    let stream: Result<arti_client::DataStream, _> =
        *rpc::invoke_special_method(ctx, connector, method)
            .await
            .map_err(|e| Box::new(into_internal!("unable to delegate to connector")(e)) as _)?;

    // Pick the new state for this object, and install it.
    let new_obj = match &stream {
        Ok(s) => Inner::Stream(
            s.client_stream_ctrl()
                .expect("Created a client stream with no ClientDataStreamCtrl!?")
                .clone(),
        ),
        Err(_) => Inner::StreamFailed, // TODO RPC: Remember some error information here.
    };
    {
        let mut inner = rpc_data_stream.inner.lock().expect("poisoned lock");
        *inner = new_obj;
    }
    // Return early on failure.
    let mut stream = stream?;

    if !was_optimistic {
        // Implement non-optimistic behavior, if that is what was originally configured.
        stream
            .wait_for_connection()
            .await
            .map_err(|e| Box::new(e) as _)?;
    }

    // Return the stream; the SOCKS layer will take it from here.
    Ok(stream)
}

/// Invoke ResolveWithPrefs on an OneshotClient
async fn oneshot_client_resolve_with_prefs(
    rpc_data_stream: Arc<OneshotClient>,
    method: Box<ResolveWithPrefs>,
    ctx: Arc<dyn rpc::Context>,
) -> ClientConnectionResult<Vec<IpAddr>> {
    let connector = rpc_data_stream
        .take_connector(Inner::UsedToResolve)
        .map_err(|e| Box::new(e) as _)?;

    let result = rpc::invoke_special_method(ctx, connector, method)
        .await
        .map_err(|e| Box::new(into_internal!("unable to delegate to connector")(e)) as _)?;

    *result
}

/// Invoke ResolvePtrWithPrefs on an OneshotClient
async fn oneshot_client_resolve_ptr_with_prefs(
    rpc_data_stream: Arc<OneshotClient>,
    method: Box<ResolvePtrWithPrefs>,
    ctx: Arc<dyn rpc::Context>,
) -> ClientConnectionResult<Vec<String>> {
    let connector = rpc_data_stream
        .take_connector(Inner::UsedToResolve)
        .map_err(|e| Box::new(e) as _)?;

    let result = rpc::invoke_special_method(ctx, connector, method)
        .await
        .map_err(|e| Box::new(into_internal!("unable to delegate to connector")(e)) as _)?;

    *result
}

/// Create a new `RpcOneshotClient` to wait for a SOCKS request.
///
/// The resulting ObjectID will be a handle to an `RpcOneshotClient`.
/// It can be used as the target of a single SOCKS request.
///
/// Once used for a SOCKS connect request,
/// the object will become a handle for the the underlying DataStream
/// that was created with the request.
#[derive(Debug, serde::Deserialize, serde::Serialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "arti:new_oneshot_client"))]
pub(crate) struct NewOneshotClient {}

impl rpc::RpcMethod for NewOneshotClient {
    type Output = rpc::SingleIdResponse;
    type Update = rpc::NoUpdates; // TODO actually, updates are quite suitable here.
}

/// Helper: construct and register an OneshotClient.
fn new_oneshot_client_impl(
    connector: Arc<dyn rpc::Object>,
    ctx: &dyn rpc::Context,
) -> rpc::ObjectId {
    let rpc_stream = Arc::new(OneshotClient::new(connector));
    ctx.register_owned(rpc_stream as _)
}

/// Implement NewOneshotClient for clients.
pub(crate) async fn new_oneshot_client_on_client<R: tor_rtcompat::Runtime>(
    client: Arc<arti_client::TorClient<R>>,
    _method: Box<NewOneshotClient>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingleIdResponse, rpc::RpcError> {
    Ok(new_oneshot_client_impl(client, ctx.as_ref()).into())
}

/// Implement NewOneshotClient for RpcSession.
async fn new_oneshot_client_on_session(
    session: Arc<RpcSession>,
    _method: Box<NewOneshotClient>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<rpc::SingleIdResponse, rpc::RpcError> {
    Ok(new_oneshot_client_impl(session, ctx.as_ref()).into())
}
rpc::static_rpc_invoke_fn! {
    new_oneshot_client_on_session;
    @special oneshot_client_connect_with_prefs;
    @special oneshot_client_resolve_with_prefs;
    @special oneshot_client_resolve_ptr_with_prefs;
}

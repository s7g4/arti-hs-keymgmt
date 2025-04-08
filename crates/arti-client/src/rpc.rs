use derive_deftly::Deftly;
use dyn_clone::DynClone;
use futures::{SinkExt as _, StreamExt as _};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, sync::Arc};
use tor_proto::stream::DataStream;

use tor_rpcbase as rpc;
use tor_rtcompat::Runtime;

use crate::{StreamPrefs, TorAddr, TorClient, ClientConnectionError}; // Added import for ClientConnectionError

impl<R: Runtime> tor_rpcbase::Object for TorClient<R> {
    // Implement the required methods for the tor_rpcbase::Object trait
}

impl<R: Runtime> TorClient<R> {
    /// Ensure that every RPC method is registered for this instantiation of TorClient.
    pub fn rpc_methods() -> Vec<rpc::dispatch::InvokerEnt> {
        rpc::invoker_ent_list![
            get_client_status::<R>,
            watch_client_status::<R>,
            isolated_client::<R>,
            @special client_connect_with_prefs::<R>,
            @special client_resolve_with_prefs::<R>,
            @special client_resolve_ptr_with_prefs::<R>,
            @special resolve_with_prefs::<R>,
            @special resolve_ptr_with_prefs::<R>,
        ]
    }
}

/// RPC method implementation: perform a remote DNS lookup using a `TorClient`.
pub struct ClientConnectionError; // Defined ClientConnectionError struct

pub async fn resolve_with_prefs<R: Runtime>(
    client: Arc<TorClient<R>>,
    method: Box<ResolveWithPrefs>,
    _ctx: Arc<dyn rpc::Context>,
) -> Result<Vec<IpAddr>, Box<dyn ClientConnectionError>> {
    // Implement the logic for resolving with preferences
    let result = client.resolve_with_prefs(&method.hostname, &method.prefs).await;
    result.map_err(|e| Box::new(e) as _)
}

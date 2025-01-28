//! "Inherent" authentication, where the ability to establish a connection proves that the user is
//! authorized.
use std::sync::Arc;

use super::{AuthenticateReply, AuthenticationFailure, AuthenticationScheme, RpcAuthentication};
use crate::Connection;
use derive_deftly::Deftly;
use tor_rpc_connect::auth::RpcAuth;
use tor_rpcbase as rpc;
use tor_rpcbase::templates::*;

/// Authenticate on an RPC Connection, returning a new Session.
///
/// After connecting to Arti, clients use this method to create a Session,
/// which they then use to access other functionality.
///
/// This method supports simple authentication schemes,
/// where only a single pass is necessary to open a session.
/// For now, only the `auth:inherent` scheme is supported here;
/// other schemes will be implemented in the future.
///
/// See also the `auth:begin_cookie` method.
///
/// You typically won't need to invoke this method yourself;
/// instead, your RPC library (such as `arti-rpc-client-core`)
/// should handle it for you.
#[derive(Debug, serde::Deserialize, Deftly)]
#[derive_deftly(DynMethod)]
#[deftly(rpc(method_name = "auth:authenticate"))]
struct Authenticate {
    /// The authentication scheme as enumerated in the spec.
    ///
    /// The only supported one for now is "auth:inherent"
    scheme: AuthenticationScheme,
}

impl rpc::RpcMethod for Authenticate {
    type Output = AuthenticateReply;
    type Update = rpc::NoUpdates;
}

/// Invoke the "authenticate" method on a connection.
async fn authenticate_connection(
    unauth: Arc<Connection>,
    method: Box<Authenticate>,
    ctx: Arc<dyn rpc::Context>,
) -> Result<AuthenticateReply, rpc::RpcError> {
    match (method.scheme, &unauth.require_auth) {
        // For now, we only support AF_UNIX connections, and we assume that if
        // you have permission to open such a connection to us, you have
        // permission to use Arti. We will refine this later on!
        (AuthenticationScheme::Inherent, RpcAuth::Inherent) => {}
        (_, _) => return Err(AuthenticationFailure::IncorrectMethod.into()),
    }

    let auth = RpcAuthentication {};
    let session = {
        let mgr = unauth.mgr()?;
        mgr.create_session(&auth)
    };
    let session = ctx.register_owned(session);
    Ok(AuthenticateReply { session })
}
rpc::static_rpc_invoke_fn! {
    authenticate_connection;
}

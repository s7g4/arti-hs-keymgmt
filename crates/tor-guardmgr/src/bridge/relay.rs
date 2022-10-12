//! Implementation code to make a bridge something that we can connect to and use to relay traffic.

use std::sync::Arc;

use tor_linkspec::{
    ChanTarget, CircTarget, HasAddrs, HasChanMethod, HasRelayIds, RelayIdRef, RelayIdType,
};

use super::{BridgeConfig, BridgeDesc};

/// The information about a Bridge that is necessary to connect to it and send
/// it traffic.
#[derive(Clone, Debug)]

pub struct BridgeRelay {
    /// The local configurations for the bridge.
    ///
    /// This is _always_ necessary, since it without it we can't know whether
    /// any pluggable transports are needed.
    bridge_line: Arc<BridgeConfig>,

    /// A descriptor for the bridge.
    ///
    /// If present, it MUST have every RelayId that the `bridge_line` does.
    desc: Option<BridgeDesc>,
}

/// A BridgeRelay that is known to have its full information available, and
/// which is therefore usable for multi-hop circuits.
///
/// (All bridges can be used for single-hop circuits, but we need to know the
/// bridge's descriptor in order to construct proper multi-hop circuits
/// with forward secrecy through it.)
#[derive(Clone, Debug)]
pub struct BridgeRelayWithDesc<'a>(
    /// This will _always_ be a bridge relay with a non-None desc.
    &'a BridgeRelay,
);

impl BridgeRelay {
    /// Return true if this BridgeRelay has a known descriptor and can be used for relays.
    pub fn has_descriptor(&self) -> bool {
        self.desc.is_some()
    }

    /// If we have enough information about this relay to build a circuit through it,
    /// return a BridgeRelayWithDesc for it.
    // TODO pt-client rename XXXX
    pub fn for_circuit_usage(&self) -> Option<BridgeRelayWithDesc<'_>> {
        self.desc.is_some().then(|| BridgeRelayWithDesc(self))
    }
}

impl HasRelayIds for BridgeRelay {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.bridge_line
            .identity(key_type)
            .or_else(|| self.desc.as_ref().and_then(|d| d.identity(key_type)))
    }
}

impl HasAddrs for BridgeRelay {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        todo!()
    }
}

impl HasChanMethod for BridgeRelay {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        todo!()
    }
}

impl ChanTarget for BridgeRelay {}

impl<'a> HasRelayIds for BridgeRelayWithDesc<'a> {
    fn identity(&self, key_type: RelayIdType) -> Option<RelayIdRef<'_>> {
        self.0.identity(key_type)
    }
}
impl<'a> HasAddrs for BridgeRelayWithDesc<'a> {
    fn addrs(&self) -> &[std::net::SocketAddr] {
        // TODO pt-client: This is a tricky case and we'll need to audit the
        // semantics of HasAddrs.
        //
        // The problem is that the addresses this method returns can be _either_
        // addresses at which the relay resides, and which we use to detect
        // familyhood (in which case we should return any addresses from the
        // members of this object), _or_ they can be addresses which we should
        // try to contact directly to perform the Tor handshake, in which case
        // this method should return an empty list.
        &[]
    }
}
impl<'a> HasChanMethod for BridgeRelayWithDesc<'a> {
    fn chan_method(&self) -> tor_linkspec::ChannelMethod {
        todo!()
    }
}

impl<'a> ChanTarget for BridgeRelayWithDesc<'a> {}

impl<'a> BridgeRelayWithDesc<'a> {
    /// Return a reference to the BridgeDesc in this reference.
    fn desc(&self) -> &BridgeDesc {
        self.0
            .desc
            .as_ref()
            .expect("There was supposed to be a descriptor here")
    }
}

impl<'a> CircTarget for BridgeRelayWithDesc<'a> {
    fn ntor_onion_key(&self) -> &tor_llcrypto::pk::curve25519::PublicKey {
        self.desc().as_ref().ntor_onion_key()
    }

    fn protovers(&self) -> &tor_protover::Protocols {
        self.desc().as_ref().protocols()
    }
}

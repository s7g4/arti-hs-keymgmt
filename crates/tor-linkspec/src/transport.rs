//! Support for identifying a particular transport.
//!
//! A "transport" is a mechanism to connect to a relay on the Tor network and
//! make a `Channel`. Currently, two types of transports exist: the "built-in"
//! transport, which uses TLS over TCP, and various anti-censorship "pluggable
//! transports", which use TLS over other protocols to avoid detection by
//! censors.

use std::fmt::{self, Display};
use std::net::SocketAddr;
use std::slice;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::HasAddrs;

/// Identify a type of Transport.
///
/// If this crate is compiled with the `pt-client` feature, this type can
/// support pluggable transports; otherwise, only the built-in transport type is
/// supported.
#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub struct TransportId(Inner);

/// Helper type to implement [`TransportId`].
///
/// This is a separate type so that TransportId can be opaque.
#[derive(Debug, Clone, Eq, PartialEq, Hash, educe::Educe)]
#[educe(Default)]
enum Inner {
    /// The built-in transport type.
    #[educe(Default)]
    BuiltIn,

    /// A pluggable transport type, specified by its name.
    #[cfg(feature = "pt-client")]
    Pluggable(PtTransportName),
}

/// Pluggable transport name
///
/// The name for a pluggable transport.
/// The name has been syntax checked.
#[derive(
    Debug,
    Clone,
    Default,
    Eq,
    PartialEq,
    Hash,
    serde_with::DeserializeFromStr,
    serde_with::SerializeDisplay,
)]

pub struct PtTransportName(String);

impl FromStr for PtTransportName {
    type Err = TransportIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_string().try_into()
    }
}

impl TryFrom<String> for PtTransportName {
    type Error = TransportIdError;

    fn try_from(s: String) -> Result<PtTransportName, Self::Error> {
        if is_well_formed_id(&s) {
            Ok(PtTransportName(s))
        } else {
            Err(TransportIdError::BadId(s))
        }
    }
}

impl AsRef<str> for PtTransportName {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl PtTransportName {
    /// Return the name as a `String`
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl Display for PtTransportName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self.0, f)
    }
}

/// This identifier is used to indicate the built-in transport.
//
// Actual pluggable transport names are restricted to the syntax of C identifiers.
// This string deliberately is not in that syntax so as to avoid clashes.
const BUILT_IN_ID: &str = "<none>";

impl FromStr for TransportId {
    type Err = TransportIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == BUILT_IN_ID {
            return Ok(TransportId(Inner::BuiltIn));
        };

        #[cfg(feature = "pt-client")]
        {
            let name: PtTransportName = s.parse()?;
            Ok(TransportId(Inner::Pluggable(name)))
        }

        #[cfg(not(feature = "pt-client"))]
        Err(TransportIdError::NoSupport)
    }
}

impl Display for TransportId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Inner::BuiltIn => write!(f, "{}", BUILT_IN_ID),
            #[cfg(feature = "pt-client")]
            Inner::Pluggable(name) => write!(f, "{}", name),
        }
    }
}

#[cfg(feature = "pt-client")]
impl From<PtTransportName> for TransportId {
    fn from(name: PtTransportName) -> Self {
        TransportId(Inner::Pluggable(name))
    }
}

/// Return true if `s` is a well-formed transport ID.
///
/// According to the specification, a well-formed transport ID follows the same
/// rules as a C99 identifier: It must follow the regular expression
/// `[a-zA-Z_][a-zA-Z0-9_]*`.
fn is_well_formed_id(s: &str) -> bool {
    // It's okay to use a bytes iterator, since non-ascii strings are not
    // allowed.
    let mut bytes = s.bytes();

    if let Some(first) = bytes.next() {
        (first.is_ascii_alphabetic() || first == b'_')
            && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
            && !s.eq_ignore_ascii_case("bridge")
    } else {
        false
    }
}

/// An error related to parsing a TransportId.
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransportIdError {
    /// Arti was compiled without client-side pluggable transport support, and
    /// we tried to use a pluggable transport.
    #[error("Not compiled with pluggable transport support")]
    NoSupport,

    /// Tried to parse a pluggable transport whose name was not well-formed.
    #[error("{0:?} is not a valid pluggable transport ID")]
    BadId(String),
}

impl TransportId {
    /// Return true if this is the built-in transport.
    pub fn is_builtin(&self) -> bool {
        self.0 == Inner::BuiltIn
    }
}

/// This identifier is used to indicate no transport address.
const NONE_ADDR: &str = "-";

/// An address that an be passed to a pluggable transport to tell it where to
/// connect (typically, to a bridge).
///
/// Not every transport accepts all kinds of addresses.
#[derive(
    Clone, Debug, PartialEq, Eq, Hash, serde_with::DeserializeFromStr, serde_with::SerializeDisplay,
)]
#[non_exhaustive]
pub enum PtTargetAddr {
    /// An IP address and port for a Tor relay.
    ///
    /// This is the only address type supported by the BuiltIn transport.
    IpPort(std::net::SocketAddr),
    /// A hostname-and-port target address.  Some transports may support this.
    HostPort(String, u16),
    /// A completely absent target address.  Some transports support this.
    None,
}

/// An error from parsing a [`PtTargetAddr`].
#[derive(Clone, Debug, thiserror::Error)]
#[non_exhaustive]
pub enum PtAddrError {
    /// We were compiled without support for addresses of this type.
    #[error("Not compiled with pluggable transport support.")]
    NoSupport,
    /// We cannot parse this address.
    #[error("Cannot parse {0:?} as an address.")]
    BadAddress(String),
}

impl FromStr for PtTargetAddr {
    type Err = PtAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Ok(addr) = s.parse() {
            Ok(PtTargetAddr::IpPort(addr))
        } else if let Some((name, port)) = s.rsplit_once(':') {
            let port = port
                .parse()
                .map_err(|_| PtAddrError::BadAddress(s.to_string()))?;

            Ok(Self::HostPort(name.to_string(), port))
        } else if s == NONE_ADDR {
            Ok(Self::None)
        } else {
            Err(PtAddrError::BadAddress(s.to_string()))
        }
    }
}

impl Display for PtTargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PtTargetAddr::IpPort(addr) => write!(f, "{}", addr),
            PtTargetAddr::HostPort(host, port) => write!(f, "{}:{}", host, port),
            PtTargetAddr::None => write!(f, "{}", NONE_ADDR),
        }
    }
}

/// A set of options to be passed along to a pluggable transport along with a
/// single target bridge relay.
///
/// These options typically describe aspects of the targeted bridge relay that
/// are not included in its address and Tor keys, such as additional
/// transport-specific keys or parameters.
///
/// This type is _not_ for settings that apply to _all_ of the connections over
/// a transport.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
// TODO pt-client: I am not sure we will want to keep this type, rather than
// just inlining it.  I am leaving it as a separate type for now, though, for a
// few reasons:
// 1) to avoid confusing it with the parameters passed to a transport when it
//    starts;
// 2) to give us some flexibility about the representation.
//
// TODO pt-client: This type ought to validate that the keys do not contain `=`
//                 and that the keys and values do not contain whitespace.
// See this spec issue https://gitlab.torproject.org/tpo/core/torspec/-/issues/173
#[serde(transparent)]
pub struct PtTargetSettings {
    /// A list of (key,value) pairs
    settings: Vec<(String, String)>,
}

/// The set of information passed to the  pluggable transport subsystem in order
/// to establish a connection to a bridge relay.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PtTarget {
    /// The transport to be used.
    transport: PtTransportName,
    /// The address of the bridge relay, if any.
    addr: PtTargetAddr,
    /// Any additional settings used by the transport.
    #[serde(default)]
    settings: PtTargetSettings,
}

/// Invalid PT parameter setting
#[derive(Error, Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PtTargetInvalidSetting {
    /// Currently: the key contains whitespace or `=`
    ///
    /// Will probably be generated for a greater variety of values
    /// when the spec is more nailed down.
    #[error("key {0:?} has invalid or unsupported syntax")]
    Key(String),

    /// Currently: the value contains whitespace
    ///
    /// Will probably be generated for a greater variety of values
    /// when the spec is more nailed down.
    #[error("value {0:?} has invalid or unsupported syntax")]
    Value(String),
}

impl PtTarget {
    /// Create a new `PtTarget` (with no settings)
    pub fn new(transport: PtTransportName, addr: PtTargetAddr) -> Self {
        PtTarget {
            transport,
            addr,
            settings: Default::default(),
        }
    }

    /// Add a setting (to be passed during the SOCKS handshake)
    pub fn push_setting(
        &mut self,
        k: impl Into<String>,
        v: impl Into<String>,
    ) -> Result<(), PtTargetInvalidSetting> {
        let k = k.into();
        let v = v.into();

        // Unfortunately the spec is not very clear about the valid syntax.
        // https://gitlab.torproject.org/tpo/core/torspec/-/issues/173
        //
        // For now we reject things that cannot be represented in a bridge line
        if k.find(|c: char| c == '=' || c.is_whitespace()).is_some() {
            return Err(PtTargetInvalidSetting::Key(k));
        }
        if v.find(|c: char| c.is_whitespace()).is_some() {
            return Err(PtTargetInvalidSetting::Value(v));
        }
        self.settings.settings.push((k, v));
        Ok(()) // TODO pt-client: check the syntax
    }

    /// Get the transport name
    pub fn transport(&self) -> &PtTransportName {
        &self.transport
    }

    /// Get the transport target address (or host and port)
    pub fn addr(&self) -> &PtTargetAddr {
        &self.addr
    }

    /// Iterate over the PT setting strings
    pub fn settings(&self) -> impl Iterator<Item = (&str, &str)> {
        self.settings.settings.iter().map(|(k, v)| (&**k, &**v))
    }
}

/// The way to approach a single relay in order to open a channel.
///
/// For direct connections, this is simply an address.  For connections via a
/// pluggable transport, this includes information about the transport, and any
/// address and settings information that transport requires.
#[derive(Clone, Debug, Eq, PartialEq)]
#[allow(clippy::exhaustive_enums)]
// TODO pt-client: I am not in love with this enum name --nm.
// TODO pt-client: Maybe "ContactMethod" would be better?
pub enum ChannelMethod {
    /// Connect to the relay directly at one of several addresses.
    Direct(Vec<std::net::SocketAddr>),

    // TODO pt-client: We may want to have a third variant for "Direct" with a
    // single address. Maybe?
    /// Connect to a bridge relay via a pluggable transport.
    #[cfg(feature = "pt-client")]
    Pluggable(PtTarget),
}

impl ChannelMethod {
    /// Return an advertised socket address that this method connects to.
    ///
    /// NOTE that this is not necessarily an address to which you can open a
    /// TCP connection! If this `ChannelMethod` is using a non-`Direct`
    /// transport, then this address will be interpreted by that transport's
    /// implementation.
    pub fn declared_peer_addr(&self) -> Option<&std::net::SocketAddr> {
        match self {
            ChannelMethod::Direct(addr) if !addr.is_empty() => Some(&addr[0]),

            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(PtTarget {
                addr: PtTargetAddr::IpPort(addr),
                ..
            }) => Some(addr),

            #[cfg_attr(not(feature = "pt-client"), allow(unreachable_patterns))]
            _ => None,
        }
    }

    /// Return a PtTargetAddr that this ChannelMethod uses.
    pub fn target_addr(&self) -> Option<PtTargetAddr> {
        match self {
            ChannelMethod::Direct(addr) if !addr.is_empty() => Some(PtTargetAddr::IpPort(addr[0])),

            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(PtTarget { addr, .. }) => Some(addr.clone()),

            _ => None,
        }
    }

    /// Return true if this is a method for a direct connection.
    pub fn is_direct(&self) -> bool {
        matches!(self, ChannelMethod::Direct(_))
    }

    /// Return an identifier for the Transport to be used by this `ChannelMethod`.
    pub fn transport_id(&self) -> TransportId {
        match self {
            ChannelMethod::Direct(_) => TransportId::default(),
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(target) => target.transport().clone().into(),
        }
    }
}

impl HasAddrs for PtTargetAddr {
    fn addrs(&self) -> &[SocketAddr] {
        match self {
            PtTargetAddr::IpPort(sockaddr) => slice::from_ref(sockaddr),
            PtTargetAddr::HostPort(..) | PtTargetAddr::None => &[],
        }
    }
}

impl HasAddrs for ChannelMethod {
    fn addrs(&self) -> &[SocketAddr] {
        match self {
            ChannelMethod::Direct(addrs) => addrs,
            #[cfg(feature = "pt-client")]
            ChannelMethod::Pluggable(pt) => pt.addr.addrs(),
        }
    }
}

#[cfg(test)]
mod test {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn builtin() {
        assert!(TransportId::default().is_builtin());
        assert_eq!(
            TransportId::default(),
            "<none>".parse().expect("Couldn't parse default ID")
        );
    }

    #[test]
    #[cfg(not(feature = "pt-client"))]
    fn nosupport() {
        // We should get this error whenever we parse a non-default PT and we have no PT support.
        assert!(matches!(
            TransportId::from_str("obfs4"),
            Err(TransportIdError::NoSupport)
        ));
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn wellformed() {
        for id in &["snowflake", "obfs4", "_ohai", "Z", "future_WORK2"] {
            assert!(is_well_formed_id(id));
        }

        for id in &[" ", "Mölm", "12345", ""] {
            assert!(!is_well_formed_id(id));
        }
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn parsing() {
        let obfs = TransportId::from_str("obfs4").unwrap();
        let dflt = TransportId::default();
        let dflt2 = TransportId::from_str("<none>").unwrap();
        let snow = TransportId::from_str("snowflake").unwrap();
        let obfs_again = TransportId::from_str("obfs4").unwrap();

        assert_eq!(obfs, obfs_again);
        assert_eq!(dflt, dflt2);
        assert_ne!(snow, obfs);
        assert_ne!(snow, dflt);

        assert!(matches!(
            TransportId::from_str("12345"),
            Err(TransportIdError::BadId(_))
        ));
        assert!(matches!(
            TransportId::from_str("bridge"),
            Err(TransportIdError::BadId(_))
        ));
    }

    #[test]
    fn addr() {
        for addr in &["1.2.3.4:555", "[::1]:9999"] {
            let a: PtTargetAddr = addr.parse().unwrap();
            assert_eq!(&a.to_string(), addr);

            let sa: SocketAddr = addr.parse().unwrap();
            assert_eq!(a.addrs(), &[sa]);
        }

        for addr in &["www.example.com:9100", "-"] {
            let a: PtTargetAddr = addr.parse().unwrap();
            assert_eq!(&a.to_string(), addr);
            assert_eq!(a.addrs(), &[]);
        }

        for addr in &["foobar", "<<<>>>"] {
            let e = PtTargetAddr::from_str(addr).unwrap_err();
            assert!(matches!(e, PtAddrError::BadAddress(_)));
        }
    }
}

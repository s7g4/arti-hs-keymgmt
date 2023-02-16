//! Encoding and decoding for relay messages related to onion services.

#![allow(dead_code, unused_variables)] // TODO hs: remove.

// TODO hs: we'll need accessors for the useful fields in all these types.

use super::msg::{self, Body};
use caret::caret_int;
use tor_bytes::{EncodeError, EncodeResult, Error as BytesError, Result};
use tor_bytes::{Reader, Writer};
use tor_hscrypto::RendCookie;
use tor_llcrypto::pk::rsa::RsaIdentity;

pub mod est_intro;
mod ext;

pub use ext::UnrecognizedExt;

caret_int! {
    /// The type of the introduction point auth key
    pub struct AuthKeyType(u8) {
        /// Ed25519; SHA3-256
        ED25519_SHA3_256 = 2,
    }
}

/// A message sent from client to rendezvous point.
#[derive(Debug, Clone)]
pub struct EstablishRendezvous {
    /// A rendezvous cookie is an arbitrary 20-byte value,
    /// chosen randomly by the client.
    cookie: [u8; EstablishRendezvous::COOKIE_LEN], // TODO hs: Make this a RendCookie.
}
impl EstablishRendezvous {
    /// The only acceptable length of a rendezvous cookie.
    pub const COOKIE_LEN: usize = 20;

    /// Construct a new establish rendezvous cell.
    pub fn new(cookie: [u8; Self::COOKIE_LEN]) -> Self {
        Self { cookie }
    }
}
impl msg::Body for EstablishRendezvous {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let cookie = r.extract()?;
        r.take_rest();
        Ok(Self { cookie })
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write(&self.cookie)
    }
}

#[derive(Debug, Clone)]
/// A message sent from client to introduction point.
pub struct Introduce1(Introduce);

impl msg::Body for Introduce1 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(Introduce::decode_from_reader(r)?))
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.0.encode_onto(w)
    }
}

impl Introduce1 {
    /// All arguments constructor
    pub fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self(Introduce::new(auth_key_type, auth_key, encrypted))
    }
}

#[derive(Debug, Clone)]
/// A message sent from introduction point to hidden service host.
pub struct Introduce2(Introduce);

impl msg::Body for Introduce2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        Ok(Self(Introduce::decode_from_reader(r)?))
    }
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        self.0.encode_onto(w)
    }
}

impl Introduce2 {
    /// All arguments constructor
    pub fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self(Introduce::new(auth_key_type, auth_key, encrypted))
    }
}

#[derive(Debug, Clone)]
/// A message body shared by Introduce1 and Introduce2
struct Introduce {
    /// Introduction point auth key type and the type of
    /// the MAC used in `handshake_auth`.
    auth_key_type: AuthKeyType,
    /// The public introduction point auth key.
    auth_key: Vec<u8>,
    /// Up to end of relay payload.
    encrypted: Vec<u8>,
}

impl Introduce {
    /// All arguments constructor
    fn new(auth_key_type: AuthKeyType, auth_key: Vec<u8>, encrypted: Vec<u8>) -> Self {
        Self {
            auth_key_type,
            auth_key,
            encrypted,
        }
    }
    /// Decode an Introduce message body from the given reader
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        let legacy_key_id: RsaIdentity = r.extract()?;
        if !legacy_key_id.is_zero() {
            return Err(BytesError::InvalidMessage(
                "legacy key id in Introduce1.".into(),
            ));
        }
        let auth_key_type = r.take_u8()?.into();
        let auth_key_len = r.take_u16()?;
        let auth_key = r.take(auth_key_len as usize)?.into();
        let n_ext = r.take_u8()?;
        for _ in 0..n_ext {
            let _ext_type = r.take_u8()?;
            r.read_nested_u8len(|r| {
                r.take_rest();
                Ok(())
            })?;
        }
        let encrypted = r.take_rest().into();
        Ok(Self {
            auth_key_type,
            auth_key,
            encrypted,
        })
    }
    /// Encode an Introduce message body onto the given writer
    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        w.write_all(&[0_u8; 20]);
        w.write_u8(self.auth_key_type.get());
        w.write_u16(u16::try_from(self.auth_key.len()).map_err(|_| EncodeError::BadLengthValue)?);
        w.write_all(&self.auth_key[..]);
        // No Introduce1 extension for now.
        w.write_u8(0_u8);
        w.write_all(&self.encrypted[..]);
        Ok(())
    }
}

/// A message sent from an onion service to a rendezvous point, telling it to
/// make a connection to the client.
#[derive(Debug, Clone)]
pub struct Rendezvous1 {
    /// The cookie originally sent by the client in its ESTABLISH_REND message.
    cookie: RendCookie,
    /// The message to send the client.
    message: Vec<u8>,
}

impl Body for Rendezvous1 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

/// A message sent from the rendezvous point to the client, telling it about the
/// onion service's message.
#[derive(Debug, Clone)]
pub struct Rendezvous2 {
    /// The message from the onion service.
    message: Vec<u8>,
}

impl Body for Rendezvous2 {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

/// Reply sent from the introduction point to the onion service, telling it that
/// an introduction point is now established.
#[derive(Debug, Clone)]
pub struct IntroEstablished {
    /// The extensions included in this cell.
    //
    // TODO hs: we should extract this with any DOS related extensions, depending on what we
    // decide to do with extension in general.
    extensions: Vec<IntroEstExtension>,
}

impl Body for IntroEstablished {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

/// An extension included in an [`IntroEstablished`] message.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IntroEstExtension {
    /// An unrecognized extension.
    Unrecognized(Vec<u8>),
}

/// A reply from the introduction point to the client, telling it that its
/// introduce1 was received.
#[derive(Clone, Debug)]
pub struct IntroduceAck {
    // TODO hs: use a caret enum for this.
    /// The status reported for the Introduce1 message.
    status_code: u16,
    // TODO hs: add extensions.
}

impl Body for IntroduceAck {
    fn decode_from_reader(r: &mut Reader<'_>) -> Result<Self> {
        todo!()
    }

    fn encode_onto<W: Writer + ?Sized>(self, w: &mut W) -> EncodeResult<()> {
        todo!()
    }
}

super::msg::empty_body! {
    /// Acknowledges an EstablishRendezvous message.
    pub struct RendezvousEstablished {}
}

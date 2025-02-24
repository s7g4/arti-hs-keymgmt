//! Module providing [`CircuitExtender`].

use super::{MetaCellDisposition, MetaCellHandler, Reactor, ReactorResultChannel};
use crate::crypto::cell::{
    ClientLayer, CryptInit, HopNum, InboundClientLayer, OutboundClientLayer,
};
use crate::crypto::handshake::fast::CreateFastClient;
#[cfg(feature = "ntor_v3")]
use crate::crypto::handshake::ntor_v3::NtorV3Client;
use crate::tunnel::circuit::unique_id::UniqId;
use crate::tunnel::circuit::CircParameters;
use crate::{Error, Result};
use oneshot_fused_workaround as oneshot;
use std::borrow::Borrow;
use std::marker::PhantomData;
use tor_cell::chancell::msg::HandshakeType;
use tor_cell::relaycell::msg::{Extend2, Extended2};
use tor_cell::relaycell::{AnyRelayMsgOuter, RelayCellFormat, UnparsedRelayMsg};
use tor_error::internal;

use crate::crypto::handshake::ntor::NtorClient;
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::tunnel::circuit::path;
use crate::tunnel::reactor::SendRelayCell;
use tor_cell::relaycell::extend::NtorV3Extension;
use tor_linkspec::{EncodedLinkSpec, OwnedChanTarget};
use tracing::trace;

/// An object that can extend a circuit by one hop, using the `MetaCellHandler` trait.
///
/// Yes, I know having trait bounds on structs is bad, but in this case it's necessary
/// since we want to be able to use `H::KeyType`.
pub(super) struct CircuitExtender<H, L, FWD, REV>
where
    H: ClientHandshake,
{
    /// The peer that we're extending to.
    ///
    /// Used to extend our record of the circuit's path.
    peer_id: OwnedChanTarget,
    /// Handshake state.
    state: Option<H::StateType>,
    /// Parameters used for this extension.
    params: CircParameters,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// The hop we're expecting the EXTENDED2 cell to come back from.
    expected_hop: HopNum,
    /// The relay cell format we intend to use for this hop.
    relay_cell_format: RelayCellFormat,
    /// A oneshot channel that we should inform when we are done with this extend operation.
    operation_finished: Option<oneshot::Sender<Result<()>>>,
    /// `PhantomData` used to make the other type parameters required for a circuit extension
    /// part of the `struct`, instead of having them be provided during a function call.
    ///
    /// This is done this way so we can implement `MetaCellHandler` for this type, which
    /// doesn't include any generic type parameters; we need them to be part of the type
    /// so we know what they are for that `impl` block.
    phantom: PhantomData<(L, FWD, REV)>,
}
impl<H, L, FWD, REV> CircuitExtender<H, L, FWD, REV>
where
    H: ClientHandshake + HandshakeAuxDataHandler,
    H::KeyGen: KeyGenerator,
    L: CryptInit + ClientLayer<FWD, REV>,
    FWD: OutboundClientLayer + 'static + Send,
    REV: InboundClientLayer + 'static + Send,
{
    /// Start extending a circuit, sending the necessary EXTEND cell and returning a
    /// new `CircuitExtender` to be called when the reply arrives.
    ///
    /// The `handshake_id` is the numeric identifier for what kind of
    /// handshake we're doing.  The `key` is the relay's onion key that
    /// goes along with the handshake, and the `linkspecs` are the
    /// link specifiers to include in the EXTEND cell to tell the
    /// current last hop which relay to connect to.
    #[allow(clippy::too_many_arguments)]
    #[allow(clippy::blocks_in_conditions)]
    pub(super) fn begin(
        relay_cell_format: RelayCellFormat,
        peer_id: OwnedChanTarget,
        handshake_id: HandshakeType,
        key: &H::KeyType,
        linkspecs: Vec<EncodedLinkSpec>,
        params: CircParameters,
        client_aux_data: &impl Borrow<H::ClientAuxData>,
        reactor: &mut Reactor,
        done: ReactorResultChannel<()>,
    ) -> Result<(Self, SendRelayCell)> {
        match (|| {
            let mut rng = rand::thread_rng();
            let unique_id = reactor.unique_id;

            let (state, msg) = H::client1(&mut rng, key, client_aux_data)?;
            let n_hops = reactor.crypto_out.n_layers();
            let hop = ((n_hops - 1) as u8).into();
            trace!(
                "{}: Extending circuit to hop {} with {:?}",
                unique_id,
                n_hops + 1,
                linkspecs
            );
            let extend_msg = Extend2::new(linkspecs, handshake_id, msg);
            let cell = AnyRelayMsgOuter::new(None, extend_msg.into());
            // Prepare a message to send message to the last hop...
            let cell = SendRelayCell {
                hop,
                early: true, // use a RELAY_EARLY cel
                cell,
            };

            trace!("{}: waiting for EXTENDED2 cell", unique_id);
            // ... and now we wait for a response.
            let extender = Self {
                peer_id,
                state: Some(state),
                params,
                unique_id,
                expected_hop: hop,
                operation_finished: None,
                phantom: Default::default(),
                relay_cell_format,
            };

            Ok::<(CircuitExtender<_, _, _, _>, SendRelayCell), Error>((extender, cell))
        })() {
            Ok(mut result) => {
                result.0.operation_finished = Some(done);
                Ok(result)
            }
            Err(e) => {
                // It's okay if the receiver went away.
                let _ = done.send(Err(e.clone()));
                Err(e)
            }
        }
    }

    /// Perform the work of extending the circuit another hop.
    ///
    /// This is a separate function to simplify the error-handling work of handle_msg().
    fn extend_circuit(
        &mut self,
        msg: UnparsedRelayMsg,
        reactor: &mut Reactor,
    ) -> Result<MetaCellDisposition> {
        let msg = msg
            .decode::<Extended2>()
            .map_err(|e| Error::from_bytes_err(e, "extended2 message"))?
            .into_msg();

        let relay_handshake = msg.into_body();

        trace!(
            "{}: Received EXTENDED2 cell; completing handshake.",
            self.unique_id
        );
        // Now perform the second part of the handshake, and see if it
        // succeeded.
        let (server_aux_data, keygen) = H::client2(
            self.state
                .take()
                .expect("CircuitExtender::finish() called twice"),
            relay_handshake,
        )?;

        // Handle auxiliary data returned from the server, e.g. validating that
        // requested extensions have been acknowledged.
        H::handle_server_aux_data(&self.params, &server_aux_data)?;

        let layer = L::construct(keygen)?;

        trace!("{}: Handshake complete; circuit extended.", self.unique_id);

        // If we get here, it succeeded.  Add a new hop to the circuit.
        let (layer_fwd, layer_back, binding) = layer.split();
        reactor.add_hop(
            self.relay_cell_format,
            path::HopDetail::Relay(self.peer_id.clone()),
            Box::new(layer_fwd),
            Box::new(layer_back),
            Some(binding),
            &self.params,
        );
        Ok(MetaCellDisposition::ConversationFinished)
    }
}

impl<H, L, FWD, REV> MetaCellHandler for CircuitExtender<H, L, FWD, REV>
where
    H: ClientHandshake + HandshakeAuxDataHandler,
    H::StateType: Send,
    H::KeyGen: KeyGenerator,
    L: CryptInit + ClientLayer<FWD, REV> + Send,
    FWD: OutboundClientLayer + 'static + Send,
    REV: InboundClientLayer + 'static + Send,
{
    fn expected_hop(&self) -> HopNum {
        self.expected_hop
    }
    fn handle_msg(
        &mut self,
        msg: UnparsedRelayMsg,
        reactor: &mut Reactor,
    ) -> Result<MetaCellDisposition> {
        let status = self.extend_circuit(msg, reactor);

        if let Some(done) = self.operation_finished.take() {
            // ignore it if the receiving channel went away.
            let _ = done.send(status.as_ref().map(|_| ()).map_err(Clone::clone));
            status
        } else {
            Err(Error::from(internal!(
                "Passed two messages to an CircuitExtender!"
            )))
        }
    }
}

/// Specifies handling of auxiliary handshake data for a given `ClientHandshake`.
//
// For simplicity we implement this as a trait of the handshake object itself.
// This is currently sufficient because
//
// 1. We only need or want one handler implementation for a given handshake type.
// 2. We currently don't need to keep extra state; i.e. its method doesn't take
//    &self.
//
// If we end up wanting to instantiate objects for one or both of the
// `ClientHandshake` object or the `HandshakeAuxDataHandler` object, we could
// decouple them by making this something like:
//
// ```
// trait HandshakeAuxDataHandler<H> where H: ClientHandshake
// ```
pub(super) trait HandshakeAuxDataHandler: ClientHandshake {
    /// Handle auxiliary handshake data returned when creating or extending a
    /// circuit.
    fn handle_server_aux_data(
        params: &CircParameters,
        data: &<Self as ClientHandshake>::ServerAuxData,
    ) -> Result<()>;
}

#[cfg(feature = "ntor_v3")]
impl HandshakeAuxDataHandler for NtorV3Client {
    fn handle_server_aux_data(_params: &CircParameters, data: &Vec<NtorV3Extension>) -> Result<()> {
        // There are currently no accepted server extensions,
        // particularly since we don't request any extensions yet.
        if !data.is_empty() {
            return Err(Error::HandshakeProto(
                "Received unexpected ntorv3 extension".into(),
            ));
        }
        Ok(())
    }
}

impl HandshakeAuxDataHandler for NtorClient {
    fn handle_server_aux_data(_params: &CircParameters, _data: &()) -> Result<()> {
        // This handshake doesn't have any auxiliary data; nothing to do.
        Ok(())
    }
}

impl HandshakeAuxDataHandler for CreateFastClient {
    fn handle_server_aux_data(_params: &CircParameters, _data: &()) -> Result<()> {
        // This handshake doesn't have any auxiliary data; nothing to do.
        Ok(())
    }
}

//! Tunnel module that will encompass a generic tunnel wrapping around a circuit reactor that can
//! be single or multi path.

pub mod circuit;
mod halfstream;
#[cfg(feature = "send-control-msg")]
pub(crate) mod msghandler;
pub(crate) mod reactor;
mod streammap;

use futures::SinkExt as _;
use oneshot_fused_workaround as oneshot;
use std::pin::Pin;
use std::sync::Arc;

use crate::crypto::cell::HopNum;
use crate::{Error, Result};
use circuit::ClientCirc;
use circuit::{handshake, StreamMpscSender, CIRCUIT_BUFFER_SIZE};
use reactor::CtrlMsg;

use tor_async_utils::SinkCloseChannel as _;
use tor_cell::relaycell::msg::AnyRelayMsg;
use tor_cell::relaycell::StreamId;

/// Internal handle, used to implement a stream on a particular circuit.
///
/// The reader and the writer for a stream should hold a `StreamTarget` for the stream;
/// the reader should additionally hold an `mpsc::Receiver` to get
/// relay messages for the stream.
///
/// When all the `StreamTarget`s for a stream are dropped, the Reactor will
/// close the stream by sending an END message to the other side.
/// You can close a stream earlier by using [`StreamTarget::close`]
/// or [`StreamTarget::close_pending`].
#[derive(Clone, Debug)]
pub(crate) struct StreamTarget {
    /// Which hop of the circuit this stream is with.
    hop_num: HopNum,
    /// Reactor ID for this stream.
    stream_id: StreamId,
    /// Channel to send cells down.
    tx: StreamMpscSender<AnyRelayMsg>,
    /// Reference to the circuit that this stream is on.
    // TODO(conflux): this should be a ClientTunnel
    circ: Arc<ClientCirc>,
}

impl StreamTarget {
    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: AnyRelayMsg) -> Result<()> {
        self.tx.send(msg).await.map_err(|_| Error::CircuitClosed)?;
        Ok(())
    }

    /// Close the pending stream that owns this StreamTarget, delivering the specified
    /// END message (if any)
    ///
    /// The stream is closed by sending a [`CtrlMsg::ClosePendingStream`] message to the reactor.
    ///
    /// Returns a [`oneshot::Receiver`] that can be used to await the reactor's response.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    ///
    /// Note that in many cases, the actual contents of an END message can leak unwanted
    /// information. Please consider carefully before sending anything but an
    /// [`End::new_misc()`](tor_cell::relaycell::msg::End::new_misc) message over a `ClientCirc`.
    /// (For onion services, we send [`DONE`](tor_cell::relaycell::msg::EndReason::DONE) )
    ///
    /// In addition to sending the END message, this function also ensures
    /// the state of the stream map entry of this stream is updated
    /// accordingly.
    ///
    /// Normally, you shouldn't need to call this function, as streams are implicitly closed by the
    /// reactor when their corresponding `StreamTarget` is dropped. The only valid use of this
    /// function is for closing pending incoming streams (a stream is said to be pending if we have
    /// received the message initiating the stream but have not responded to it yet).
    ///
    /// **NOTE**: This function should be called at most once per request.
    /// Calling it twice is an error.
    #[cfg(feature = "hs-service")]
    pub(crate) fn close_pending(
        &self,
        message: reactor::CloseStreamBehavior,
    ) -> Result<oneshot::Receiver<Result<()>>> {
        let (tx, rx) = oneshot::channel();

        self.circ
            .control
            .unbounded_send(CtrlMsg::ClosePendingStream {
                stream_id: self.stream_id,
                hop_num: self.hop_num,
                message,
                done: tx,
            })
            .map_err(|_| Error::CircuitClosed)?;

        Ok(rx)
    }

    /// Queue a "close" for the stream corresponding to this StreamTarget.
    ///
    /// Unlike `close_pending`, this method does not allow the caller to provide an `END` message.
    ///
    /// Once this method has been called, no more messages may be sent with [`StreamTarget::send`],
    /// on this `StreamTarget`` or any clone of it.
    /// The reactor *will* try to flush any already-send messages before it closes the stream.
    ///
    /// You don't need to call this method if the stream is closing because all of its StreamTargets
    /// have been dropped.
    pub(crate) fn close(&mut self) {
        Pin::new(&mut self.tx).close_channel();
    }

    /// Called when a circuit-level protocol error has occurred and the
    /// circuit needs to shut down.
    pub(crate) fn protocol_error(&mut self) {
        self.circ.protocol_error();
    }

    /// Send a SENDME cell for this stream.
    pub(crate) fn send_sendme(&mut self) -> Result<()> {
        self.circ
            .control
            .unbounded_send(CtrlMsg::SendSendme {
                stream_id: self.stream_id,
                hop_num: self.hop_num,
            })
            .map_err(|_| Error::CircuitClosed)?;
        Ok(())
    }

    /// Return a reference to the circuit that this `StreamTarget` is using.
    #[cfg(any(feature = "experimental-api", feature = "stream-ctrl"))]
    pub(crate) fn circuit(&self) -> &Arc<ClientCirc> {
        &self.circ
    }
}

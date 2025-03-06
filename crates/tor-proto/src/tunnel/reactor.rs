//! Code to handle incoming cells on a circuit.
//!
//! ## On message validation
//!
//! There are three steps for validating an incoming message on a stream:
//!
//! 1. Is the message contextually appropriate? (e.g., no more than one
//!    `CONNECTED` message per stream.) This is handled by calling
//!    [`CmdChecker::check_msg`](crate::stream::CmdChecker::check_msg).
//! 2. Does the message comply with flow-control rules? (e.g., no more data than
//!    we've gotten SENDMEs for.) For open streams, the stream itself handles
//!    this; for half-closed streams, the reactor handles it using the
//!    `halfstream` module.
//! 3. Does the message have an acceptable command type, and is the message
//!    well-formed? For open streams, the streams themselves handle this check.
//!    For half-closed streams, the reactor handles it by calling
//!    `consume_checked_msg()`.

pub(super) mod circuit;
mod conflux;
mod control;
pub(super) mod syncview;

use crate::crypto::cell::HopNum;
#[cfg(feature = "ntor_v3")]
use crate::crypto::handshake::ntor_v3::NtorV3PublicKey;
use crate::memquota::{CircuitAccount, StreamAccount};
use crate::stream::AnyCmdChecker;
#[cfg(feature = "hs-service")]
use crate::stream::{IncomingStreamRequest, IncomingStreamRequestFilter};
use crate::tunnel::circuit::celltypes::ClientCircChanMsg;
use crate::tunnel::circuit::unique_id::UniqId;
use crate::tunnel::circuit::CircuitRxReceiver;
use crate::tunnel::circuit::MutableState;
use crate::tunnel::streammap;
use crate::util::err::ReactorError;
use crate::util::skew::ClockSkew;
use crate::{Error, Result};
use circuit::Circuit;
use conflux::ConfluxSet;
use control::ControlHandler;
use std::mem::size_of;
use tor_cell::relaycell::msg::{AnyRelayMsg, End, Sendme};
use tor_cell::relaycell::{AnyRelayMsgOuter, StreamId, UnparsedRelayMsg};
use tor_error::{internal, Bug};

use futures::channel::mpsc;
use futures::StreamExt;
use futures::{select_biased, FutureExt as _};
use oneshot_fused_workaround as oneshot;

use std::result::Result as StdResult;
use std::sync::{Arc, Mutex};

use crate::channel::Channel;
use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
use crate::tunnel::circuit::{StreamMpscReceiver, StreamMpscSender};
use derive_deftly::Deftly;
use derive_more::From;
use tor_cell::chancell::CircId;
use tor_llcrypto::pk;
use tor_memquota::derive_deftly_template_HasMemoryCost;
use tor_memquota::mq_queue::{self, MpscSpec};
use tracing::trace;

pub(super) use control::CtrlCmd;
pub(super) use control::CtrlMsg;

/// The type of a oneshot channel used to inform reactor users of the result of an operation.
pub(super) type ReactorResultChannel<T> = oneshot::Sender<Result<T>>;

pub(crate) use circuit::{RECV_WINDOW_INIT, STREAM_READER_BUFFER};

/// MPSC queue containing stream requests
#[cfg(feature = "hs-service")]
type StreamReqSender = mq_queue::Sender<StreamReqInfo, MpscSpec>;

/// A handshake type, to be used when creating circuit hops.
#[derive(Clone, Debug)]
pub(crate) enum CircuitHandshake {
    /// Use the CREATE_FAST handshake.
    CreateFast,
    /// Use the ntor handshake.
    Ntor {
        /// The public key of the relay.
        public_key: NtorPublicKey,
        /// The Ed25519 identity of the relay, which is verified against the
        /// identity held in the circuit's channel.
        ed_identity: pk::ed25519::Ed25519Identity,
    },
    /// Use the ntor-v3 handshake.
    #[cfg(feature = "ntor_v3")]
    NtorV3 {
        /// The public key of the relay.
        public_key: NtorV3PublicKey,
    },
}

/// A behavior to perform when closing a stream.
///
/// We don't use `Option<End>`` here, since the behavior of `SendNothing` is so surprising
/// that we shouldn't let it pass unremarked.
#[derive(Clone, Debug)]
pub(crate) enum CloseStreamBehavior {
    /// Send nothing at all, so that the other side will not realize we have
    /// closed the stream.
    ///
    /// We should only do this for incoming onion service streams when we
    /// want to black-hole the client's requests.
    SendNothing,
    /// Send an End cell, if we haven't already sent one.
    SendEnd(End),
}
impl Default for CloseStreamBehavior {
    fn default() -> Self {
        Self::SendEnd(End::new_misc())
    }
}

/// One or more [`RunOnceCmdInner`] to run inside [`Reactor::run_once`].
#[derive(From, Debug)]
enum RunOnceCmd {
    /// Run a single `RunOnceCmdInner` command.
    Single(RunOnceCmdInner),
    /// Run multiple `RunOnceCmdInner` commands.
    //
    // Note: this whole enum *could* be replaced with Vec<RunOnceCmdInner>,
    // but most of the time we're only going to have *one* RunOnceCmdInner
    // to run per run_once() loop. The enum enables us avoid the extra heap
    // allocation for the `RunOnceCmd::Single` case.
    Multiple(Vec<RunOnceCmdInner>),
}

/// Instructions for running something in the reactor loop.
///
/// Run at the end of [`Reactor::run_once`].
//
// TODO: many of the variants of this enum have an identical CtrlMsg counterpart.
// We should consider making each variant a tuple variant and deduplicating the fields.
#[derive(educe::Educe)]
#[educe(Debug)]
enum RunOnceCmdInner {
    /// Send a RELAY cell.
    Send {
        /// The cell to send.
        cell: SendRelayCell,
        /// A channel for sending completion notifications.
        done: Option<ReactorResultChannel<()>>,
    },
    /// Send a given control message on this circuit, and install a control-message handler to
    /// receive responses.
    #[cfg(feature = "send-control-msg")]
    SendMsgAndInstallHandler {
        /// The message to send, if any
        msg: Option<AnyRelayMsgOuter>,
        /// A message handler to install.
        ///
        /// If this is `None`, there must already be a message handler installed
        #[educe(Debug(ignore))]
        handler: Option<Box<dyn MetaCellHandler + Send + 'static>>,
        /// A sender that we use to tell the caller that the message was sent
        /// and the handler installed.
        done: oneshot::Sender<Result<()>>,
    },
    /// Handle a SENDME message.
    HandleSendMe {
        /// The hop number.
        hop: HopNum,
        /// The SENDME message to handle.
        sendme: Sendme,
    },
    /// Begin a stream with the provided hop in this circuit.
    ///
    /// Uses the provided stream ID, and sends the provided message to that hop.
    BeginStream {
        /// The cell to send.
        cell: Result<(SendRelayCell, StreamId)>,
        /// Oneshot channel to notify on completion, with the allocated stream ID.
        done: ReactorResultChannel<StreamId>,
    },
    /// Close the specified stream.
    CloseStream {
        /// The hop number.
        hop_num: HopNum,
        /// The ID of the stream to close.
        sid: StreamId,
        /// The stream-closing behavior.
        behav: CloseStreamBehavior,
        /// The reason for closing the stream.
        reason: streammap::TerminateReason,
        /// A channel for sending completion notifications.
        done: Option<ReactorResultChannel<()>>,
    },
    /// Get the clock skew claimed by the first hop of the circuit.
    FirstHopClockSkew {
        /// Oneshot channel to return the clock skew.
        answer: oneshot::Sender<StdResult<ClockSkew, Bug>>,
    },
    /// Perform a clean shutdown on this circuit.
    CleanShutdown,
}

// Cmd for sending a relay cell.
//
// The contents of this struct are passed to `send_relay_cell`
#[derive(educe::Educe)]
#[educe(Debug)]
pub(crate) struct SendRelayCell {
    /// The hop number.
    pub(crate) hop: HopNum,
    /// Whether to use a RELAY_EARLY cell.
    pub(crate) early: bool,
    /// The cell to send.
    pub(crate) cell: AnyRelayMsgOuter,
}

/// A command to execute at the end of [`Reactor::run_once`].
#[derive(From, Debug)]
enum CircuitAction {
    /// Run a single `RunOnceCmdInner` command.
    Single(RunOnceCmdInner),
    /// Handle a control message
    HandleControl(CtrlMsg),
    /// Handle an input message.
    HandleCell(ClientCircChanMsg),
    /// Remove the specified circuit leg.
    RemoveLeg(LegIdKey),
}

/// An object that's waiting for a meta cell (one not associated with a stream) in order to make
/// progress.
///
/// # Background
///
/// The `Reactor` can't have async functions that send and receive cells, because its job is to
/// send and receive cells: if one of its functions tried to do that, it would just hang forever.
///
/// To get around this problem, the reactor can send some cells, and then make one of these
/// `MetaCellHandler` objects, which will be run when the reply arrives.
pub(crate) trait MetaCellHandler: Send {
    /// The hop we're expecting the message to come from. This is compared against the hop
    /// from which we actually receive messages, and an error is thrown if the two don't match.
    fn expected_hop(&self) -> HopNum;
    /// Called when the message we were waiting for arrives.
    ///
    /// Gets a copy of the `Reactor` in order to do anything it likes there.
    ///
    /// If this function returns an error, the reactor will shut down.
    fn handle_msg(
        &mut self,
        msg: UnparsedRelayMsg,
        reactor: &mut Circuit,
    ) -> Result<MetaCellDisposition>;
}

/// A possible successful outcome of giving a message to a [`MsgHandler`](super::msghandler::MsgHandler).
#[derive(Debug, Clone)]
#[cfg_attr(feature = "send-control-msg", visibility::make(pub))]
#[non_exhaustive]
pub(crate) enum MetaCellDisposition {
    /// The message was consumed; the handler should remain installed.
    #[cfg(feature = "send-control-msg")]
    Consumed,
    /// The message was consumed; the handler should be uninstalled.
    ConversationFinished,
    /// The message was consumed; the circuit should be closed.
    #[cfg(feature = "send-control-msg")]
    CloseCirc,
    // TODO: Eventually we might want the ability to have multiple handlers
    // installed, and to let them say "not for me, maybe for somebody else?".
    // But right now we don't need that.
}

/// A unique identifier for a circuit leg.
///
/// After the circuit is torn down, its `LegId` becomes invalid.
/// The same `LegId` won't be reused for a future circuit.
//
// TODO(#1857): make this pub
#[allow(unused)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct LegId(pub(crate) LegIdKey);

slotmap_careful::new_key_type! {
    /// A key type for the circuit leg slotmap
    ///
    /// See [`LegId`].
    pub(crate) struct LegIdKey;
}

/// Unwrap the specified [`Option`], returning a [`ReactorError::Shutdown`] if it is `None`.
///
/// This is a macro instead of a function to work around borrowck errors
/// in the select! from run_once().
macro_rules! unwrap_or_shutdown {
    ($self:expr, $res:expr, $reason:expr) => {{
        match $res {
            None => {
                trace!("{}: reactor shutdown due to {}", $self.unique_id, $reason);
                Err(ReactorError::Shutdown)
            }
            Some(v) => Ok(v),
        }
    }};
}

/// Object to handle incoming cells and background tasks on a circuit
///
/// This type is returned when you finish a circuit; you need to spawn a
/// new task that calls `run()` on it.
#[must_use = "If you don't call run() on a reactor, the circuit won't work."]
pub struct Reactor {
    /// Receiver for control messages for this reactor, sent by `ClientCirc` objects.
    ///
    /// This channel is polled in [`Reactor::run_once`], but only if the `chan_sender` sink
    /// is ready to accept cells.
    control: mpsc::UnboundedReceiver<CtrlMsg>,
    /// Receiver for command messages for this reactor, sent by `ClientCirc` objects.
    ///
    /// This channel is polled in [`Reactor::run_once`].
    ///
    /// NOTE: this is a separate channel from `control`, because some messages
    /// have higher priority and need to be handled even if the `chan_sender` is not
    /// ready (whereas `control` messages are not read until the `chan_sender` sink
    /// is ready to accept cells).
    command: mpsc::UnboundedReceiver<CtrlCmd>,
    /// A oneshot sender that is used to alert other tasks when this reactor is
    /// finally dropped.
    ///
    /// It is a sender for Void because we never actually want to send anything here;
    /// we only want to generate canceled events.
    #[allow(dead_code)] // the only purpose of this field is to be dropped.
    reactor_closed_tx: oneshot::Sender<void::Void>,
    /// A set of circuits that form a tunnel.
    ///
    /// Contains 1 or more circuits.
    ///
    /// Circuits may be added to this set throughout the lifetime of the reactor.
    //
    // TODO(conflux): add a control command for adding a circuit leg,
    // and update these docs to explain how legs are added
    ///
    /// Sometimes, the reactor will remove circuits from this set,
    /// for example if the `LINKED` message takes too long to arrive,
    /// or if congestion control negotiation fails.
    /// The reactor will continue running with the remaining circuits.
    /// It will shut down if *all* the circuits are removed.
    ///
    // TODO(conflux): document all the reasons why the reactor might
    // chose to tear down a circuit or tunnel (timeouts, protocol violations, etc.)
    circuits: ConfluxSet,
    /// An identifier for logging about this reactor's circuit.
    unique_id: UniqId,
    /// Handlers, shared with `Circuit`.
    cell_handlers: CellHandlers,
}

/// Cell handlers, shared between the Reactor and its underlying `Circuit`s.
struct CellHandlers {
    /// A handler for a meta cell, together with a result channel to notify on completion.
    meta_handler: Option<Box<dyn MetaCellHandler + Send>>,
    /// A handler for incoming stream requests.
    #[cfg(feature = "hs-service")]
    incoming_stream_req_handler: Option<IncomingStreamRequestHandler>,
}

/// Information about an incoming stream request.
#[cfg(feature = "hs-service")]
#[derive(Debug, Deftly)]
#[derive_deftly(HasMemoryCost)]
pub(crate) struct StreamReqInfo {
    /// The [`IncomingStreamRequest`].
    pub(crate) req: IncomingStreamRequest,
    /// The ID of the stream being requested.
    pub(crate) stream_id: StreamId,
    /// The [`HopNum`].
    //
    // TODO: When we add support for exit relays, we need to turn this into an Option<HopNum>.
    // (For outbound messages (towards relays), there is only one hop that can send them: the client.)
    //
    // TODO: For onion services, we might be able to enforce the HopNum earlier: we would never accept an
    // incoming stream request from two separate hops.  (There is only one that's valid.)
    pub(crate) hop_num: HopNum,
    /// A channel for receiving messages from this stream.
    #[deftly(has_memory_cost(indirect_size = "0"))] // estimate
    pub(crate) receiver: StreamMpscReceiver<UnparsedRelayMsg>,
    /// A channel for sending messages to be sent on this stream.
    #[deftly(has_memory_cost(indirect_size = "size_of::<AnyRelayMsg>()"))] // estimate
    pub(crate) msg_tx: StreamMpscSender<AnyRelayMsg>,
    /// The memory quota account to be used for this stream
    #[deftly(has_memory_cost(indirect_size = "0"))] // estimate (it contains an Arc)
    pub(crate) memquota: StreamAccount,
}

/// Data required for handling an incoming stream request.
#[cfg(feature = "hs-service")]
#[derive(educe::Educe)]
#[educe(Debug)]
struct IncomingStreamRequestHandler {
    /// A sender for sharing information about an incoming stream request.
    incoming_sender: StreamReqSender,
    /// A [`AnyCmdChecker`] for validating incoming stream requests.
    cmd_checker: AnyCmdChecker,
    /// The hop to expect incoming stream requests from.
    hop_num: HopNum,
    /// An [`IncomingStreamRequestFilter`] for checking whether the user wants
    /// this request, or wants to reject it immediately.
    #[educe(Debug(ignore))]
    filter: Box<dyn IncomingStreamRequestFilter>,
}

impl Reactor {
    /// Create a new circuit reactor.
    ///
    /// The reactor will send outbound messages on `channel`, receive incoming
    /// messages on `input`, and identify this circuit by the channel-local
    /// [`CircId`] provided.
    ///
    /// The internal unique identifier for this circuit will be `unique_id`.
    #[allow(clippy::type_complexity)] // TODO
    pub(super) fn new(
        channel: Arc<Channel>,
        channel_id: CircId,
        unique_id: UniqId,
        input: CircuitRxReceiver,
        memquota: CircuitAccount,
    ) -> (
        Self,
        mpsc::UnboundedSender<CtrlMsg>,
        mpsc::UnboundedSender<CtrlCmd>,
        oneshot::Receiver<void::Void>,
        Arc<Mutex<MutableState>>,
    ) {
        let (control_tx, control_rx) = mpsc::unbounded();
        let (command_tx, command_rx) = mpsc::unbounded();
        let mutable = Arc::new(Mutex::new(MutableState::default()));

        let (reactor_closed_tx, reactor_closed_rx) = oneshot::channel();

        let cell_handlers = CellHandlers {
            meta_handler: None,
            #[cfg(feature = "hs-service")]
            incoming_stream_req_handler: None,
        };

        let circuit_leg = Circuit::new(
            channel,
            channel_id,
            unique_id,
            input,
            memquota,
            Arc::clone(&mutable),
        );

        let reactor = Reactor {
            circuits: ConfluxSet::new(circuit_leg),
            control: control_rx,
            command: command_rx,
            reactor_closed_tx,
            unique_id,
            cell_handlers,
        };

        (reactor, control_tx, command_tx, reactor_closed_rx, mutable)
    }

    /// Launch the reactor, and run until the circuit closes or we
    /// encounter an error.
    ///
    /// Once this method returns, the circuit is dead and cannot be
    /// used again.
    pub async fn run(mut self) -> Result<()> {
        trace!("{}: Running circuit reactor", self.unique_id);
        let result: Result<()> = loop {
            match self.run_once().await {
                Ok(()) => (),
                Err(ReactorError::Shutdown) => break Ok(()),
                Err(ReactorError::Err(e)) => break Err(e),
            }
        };
        trace!("{}: Circuit reactor stopped: {:?}", self.unique_id, result);
        result
    }

    /// Helper for run: doesn't mark the circuit closed on finish.  Only
    /// processes one cell or control message.
    async fn run_once(&mut self) -> StdResult<(), ReactorError> {
        // If all the circuits are closed, shut down the reactor
        //
        // TODO(conflux): we might need to rethink this behavior
        if self.circuits.is_empty() {
            trace!(
                "{}: Circuit reactor shutting down: all circuits have closed",
                self.unique_id
            );

            return Err(ReactorError::Shutdown);
        }

        // If this is a single path circuit, we need to wait until the first hop
        // is created before doing anything else
        if self.circuits.single_leg_mut().is_ok_and(|c| !c.has_hops()) {
            self.wait_for_create().await?;

            return Ok(());
        }

        // TODO(conflux): support adding and linking circuits
        // TODO(conflux): support switching the primary leg

        let mut circs = self.circuits.circuit_action();

        let action = select_biased! {
            res = self.command.next() => {
                let cmd = unwrap_or_shutdown!(self, res, "command channel drop")?;
                // Drop circs so we can borrow self mutably.
                drop(circs);
                return ControlHandler::new(self).handle_cmd(cmd);
            },
            // Check whether we've got a control message pending.
            //
            // Note: unfortunately, reading from control here means we might start
            // handling control messages before our chan_senders are ready.
            // With the current design, this is inevitable: we can't know which circuit leg
            // a control message is meant for without first reading the control message from
            // the channel, and at that point, we can't know for sure whether that particular
            // circuit is ready for sending.
            ret = self.control.next() => {
                let msg = unwrap_or_shutdown!(self, ret, "control drop")?;
                Some(CircuitAction::HandleControl(msg))
            },
            res = circs.next().fuse() => {
                unwrap_or_shutdown!(self, res, "empty conflux set")???
            }
        };

        drop(circs);

        let cmd = match action {
            None => None,
            Some(CircuitAction::Single(cmd)) => Some(RunOnceCmd::Single(cmd)),
            Some(CircuitAction::HandleControl(ctrl)) => ControlHandler::new(self)
                .handle_msg(ctrl)?
                .map(RunOnceCmd::Single),
            Some(CircuitAction::HandleCell(cell)) => {
                // TODO(conflux): put the LegId of the circuit the cell was received on
                // inside HandleCell
                //let circ = self.circuits.leg(leg_id)?;

                let circ = self.circuits.primary_leg_mut()?;
                circ.handle_cell(&mut self.cell_handlers, cell)?
            }
            Some(CircuitAction::RemoveLeg(leg_id)) => {
                self.circuits.remove(leg_id)?;
                None
            }
        };

        if let Some(cmd) = cmd {
            self.handle_run_once_cmd(cmd).await?;
        }

        Ok(())
    }

    /// Handle a [`RunOnceCmd`].
    async fn handle_run_once_cmd(&mut self, cmd: RunOnceCmd) -> StdResult<(), ReactorError> {
        match cmd {
            RunOnceCmd::Single(cmd) => return self.handle_single_run_once_cmd(cmd).await,
            RunOnceCmd::Multiple(cmds) => {
                // While we know `sendable` is ready to accept *one* cell,
                // we can't be certain it will be able to accept *all* of the cells
                // that need to be sent here. This means we *may* end up buffering
                // in its underlying SometimesUnboundedSink! That is OK, because
                // RunOnceCmd::Multiple is only used for handling packed cells.
                for cmd in cmds {
                    self.handle_single_run_once_cmd(cmd).await?;
                }
            }
        }

        Ok(())
    }

    /// Handle a [`RunOnceCmd`].
    async fn handle_single_run_once_cmd(
        &mut self,
        cmd: RunOnceCmdInner,
    ) -> StdResult<(), ReactorError> {
        match cmd {
            RunOnceCmdInner::Send { cell, done } => {
                // TODO: check the cc window

                // TODO(conflux): let the RunOnceCmdInner specify which leg to send the cell on
                let res = self.circuits.primary_leg_mut()?.send_relay_cell(cell).await;
                if let Some(done) = done {
                    // Don't care if the receiver goes away
                    let _ = done.send(res.clone());
                }
                res?;
            }
            #[cfg(feature = "send-control-msg")]
            RunOnceCmdInner::SendMsgAndInstallHandler { msg, handler, done } => {
                let cell: Result<Option<SendRelayCell>> =
                    self.prepare_msg_and_install_handler(msg, handler);

                match cell {
                    Ok(Some(cell)) => {
                        // TODO(conflux): let the RunOnceCmdInner specify which leg to send the cell on
                        let outcome = self.circuits.primary_leg_mut()?.send_relay_cell(cell).await;
                        // don't care if receiver goes away.
                        let _ = done.send(outcome.clone());
                        outcome?;
                    }
                    Ok(None) => {
                        // don't care if receiver goes away.
                        let _ = done.send(Ok(()));
                    }
                    Err(e) => {
                        // don't care if receiver goes away.
                        let _ = done.send(Err(e.clone()));
                        return Err(e.into());
                    }
                }
            }
            // TODO(conflux)/TODO(#1857): should this take a leg_id argument?
            // Currently, we always begin streams on the primary leg
            RunOnceCmdInner::BeginStream { cell, done } => {
                match cell {
                    Ok((cell, stream_id)) => {
                        // TODO(conflux): let the RunOnceCmdInner specify which leg to send the cell on
                        // (currently it is an error to use BeginStream on a multipath tunnel)
                        let outcome = self.circuits.single_leg_mut()?.send_relay_cell(cell).await;
                        // don't care if receiver goes away.
                        let _ = done.send(outcome.clone().map(|_| stream_id));
                        outcome?;
                    }
                    Err(e) => {
                        // don't care if receiver goes away.
                        let _ = done.send(Err(e.clone()));
                        return Err(e.into());
                    }
                }
            }
            RunOnceCmdInner::CloseStream {
                hop_num,
                sid,
                behav,
                reason,
                done,
            } => {
                // TODO(conflux): currently, it is an error to use CloseStream
                // with a multi-path circuit.
                let leg = self.circuits.single_leg_mut()?;
                let res: Result<()> = leg.close_stream(hop_num, sid, behav, reason).await;

                if let Some(done) = done {
                    // don't care if the sender goes away
                    let _ = done.send(res);
                }
            }
            RunOnceCmdInner::HandleSendMe { hop, sendme } => {
                // TODO(conflux): this should specify which leg of the circuit the SENDME
                // came on
                let leg = self.circuits.single_leg_mut()?;
                // NOTE: it's okay to await. We are only awaiting on the congestion_signals
                // future which *should* resolve immediately
                let signals = leg.congestion_signals().await;
                leg.handle_sendme(hop, sendme, signals)?;
            }
            RunOnceCmdInner::FirstHopClockSkew { answer } => {
                let res = self.circuits.single_leg_mut().map(|leg| leg.clock_skew());

                // don't care if the sender goes away
                let _ = answer.send(res);
            }
            RunOnceCmdInner::CleanShutdown => {
                trace!("{}: reactor shutdown due to handled cell", self.unique_id);
                return Err(ReactorError::Shutdown);
            }
        }

        Ok(())
    }

    /// Wait for a [`CtrlMsg::Create`] to come along to set up the circuit.
    ///
    /// Returns an error if an unexpected `CtrlMsg` is received.
    async fn wait_for_create(&mut self) -> StdResult<(), ReactorError> {
        let msg = select_biased! {
            res = self.command.next() => {
                let cmd = unwrap_or_shutdown!(self, res, "shutdown channel drop")?;
                match cmd {
                    CtrlCmd::Shutdown => return self.handle_shutdown().map(|_| ()),
                    #[cfg(test)]
                    CtrlCmd::AddFakeHop {
                        relay_cell_format: format,
                        fwd_lasthop,
                        rev_lasthop,
                        params,
                        done,
                    } => {
                        self.circuits.single_leg_mut()?.handle_add_fake_hop(format, fwd_lasthop, rev_lasthop, &params, done);
                        return Ok(())
                    },
                    _ => {
                        trace!("reactor shutdown due to unexpected command: {:?}", cmd);
                        return Err(Error::CircProto(format!("Unexpected control {cmd:?} on client circuit")).into());
                    }
                }
            },
            res = self.control.next() => unwrap_or_shutdown!(self, res, "control drop")?,
        };

        match msg {
            CtrlMsg::Create {
                recv_created,
                handshake,
                params,
                done,
            } => {
                // TODO(conflux): instead of crashing the reactor, it might be better
                // to send the error via the done channel instead
                let leg = self.circuits.single_leg_mut()?;
                leg.handle_create(recv_created, handshake, &params, done)
                    .await
            }
            _ => {
                trace!("reactor shutdown due to unexpected cell: {:?}", msg);

                Err(Error::CircProto(format!("Unexpected {msg:?} cell on client circuit")).into())
            }
        }
    }

    /// Prepare a `SendRelayCell` request, and install the given meta-cell handler.
    fn prepare_msg_and_install_handler(
        &mut self,
        msg: Option<AnyRelayMsgOuter>,
        handler: Option<Box<dyn MetaCellHandler + Send + 'static>>,
    ) -> Result<Option<SendRelayCell>> {
        let msg = msg
            .map(|msg| {
                let handlers = &mut self.cell_handlers;
                let handler = handler
                    .as_ref()
                    .or(handlers.meta_handler.as_ref())
                    .ok_or_else(|| internal!("tried to use an ended Conversation"))?;
                Ok::<_, crate::Error>(SendRelayCell {
                    hop: handler.expected_hop(),
                    early: false,
                    cell: msg,
                })
            })
            .transpose()?;

        if let Some(handler) = handler {
            self.cell_handlers.set_meta_handler(handler)?;
        }

        Ok(msg)
    }

    /// Handle a shutdown request.
    fn handle_shutdown(&self) -> StdResult<Option<RunOnceCmdInner>, ReactorError> {
        trace!(
            "{}: reactor shutdown due to explicit request",
            self.unique_id
        );

        Err(ReactorError::Shutdown)
    }

    /// Handle a request to shutdown the reactor and return the only [`Circuit`] in this tunnel.
    ///
    /// Returns an error over the `answer` channel if the reactor has no circuits,
    /// or more than one circuit. The reactor will shut down regardless.
    #[cfg(feature = "conflux")]
    fn handle_shutdown_and_return_circuit(
        &mut self,
        answer: oneshot::Sender<StdResult<Circuit, Bug>>,
    ) -> StdResult<(), ReactorError> {
        // Don't care if the receiver goes away
        let _ = answer.send(self.circuits.take_single_leg());
        self.handle_shutdown().map(|_| ())
    }
}

impl CellHandlers {
    /// Try to install a given meta-cell handler to receive any unusual cells on
    /// this circuit, along with a result channel to notify on completion.
    fn set_meta_handler(&mut self, handler: Box<dyn MetaCellHandler + Send>) -> Result<()> {
        if self.meta_handler.is_none() {
            self.meta_handler = Some(handler);
            Ok(())
        } else {
            Err(Error::from(internal!(
                "Tried to install a meta-cell handler before the old one was gone."
            )))
        }
    }

    /// Try to install a given cell handler on this circuit.
    #[cfg(feature = "hs-service")]
    fn set_incoming_stream_req_handler(
        &mut self,
        handler: IncomingStreamRequestHandler,
    ) -> Result<()> {
        if self.incoming_stream_req_handler.is_none() {
            self.incoming_stream_req_handler = Some(handler);
            Ok(())
        } else {
            Err(Error::from(internal!(
                "Tried to install a BEGIN cell handler before the old one was gone."
            )))
        }
    }
}

#[cfg(test)]
mod test {
    // Tested in [`crate::tunnel::circuit::test`].
}

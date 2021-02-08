//! Multi-hop paths over the Tor network.
//!
//! Right now, we only implement "client circuits" -- also sometimes
//! called "origin circuits".  A client circuit is one that is
//! constructed by this Tor instance, and used in its own behalf to
//! send data over the Tor network.
//!
//! Each circuit has multiple hops over the Tor network: each hop
//! knows only the hop before and the hop after.  The client shares a
//! separate set of keys with each hop.
//!
//! To build a circuit, first create a [crate::channel::Channel], then
//! call its [crate::channel::Channel::new_circ] method.  This yields
//! a [PendingClientCirc] object that won't become live until you call
//! one of the methods that extends it to its first hop.  After you've
//! done that, you can call [ClientCirc::extend_ntor] on the circuit to
//! build it into a multi-hop circuit.  Finally, you can use
//! [ClientCirc::begin_stream] to get a Stream object that can be used
//! for anonymized data.
//!
//! # Implementation
//!
//! Each open circuit has a corresponding Reactor object that runs in
//! an asynchronous task, and manages incoming cells from the
//! circuit's upstream channel.  These cells are either RELAY cells or
//! DESTROY cells.  DESTROY cells are handled immediately.
//! RELAY cells are either for a particular stream, in which case they
//! get forwarded to a TorStream object, or for no particular stream,
//! in which case they are considered "meta" cells (like EXTENEDED2)
//! that should only get accepted if something is waiting for them.
//!
//! # Limitations
//!
//! This is client-only.
//!
//! There's one big mutex on the whole circuit: the reactor needs to hold
//! it to process a cell, and streams need to hold it to send.
//!
//! There is no flow-control or rate-limiting or fairness.

pub(crate) mod celltypes;
pub(crate) mod halfcirc;
mod halfstream;
pub(crate) mod reactor;
pub(crate) mod sendme;
mod streammap;
mod unique_id;

use crate::channel::{Channel, CircDestroyHandle};
use crate::circuit::celltypes::*;
use crate::circuit::reactor::{CtrlMsg, CtrlResult};
pub use crate::circuit::unique_id::UniqId;
use crate::crypto::cell::{
    ClientLayer, CryptInit, HopNum, InboundClientLayer, OutboundClientCrypt, OutboundClientLayer,
    RelayCellBody,
};
use crate::crypto::handshake::{ClientHandshake, KeyGenerator};
use crate::stream::{DataStream, TorStream};
use crate::{Error, Result};
use tor_cell::chancell::{self, msg::ChanMsg, ChanCell, CircId};
use tor_cell::relaycell::msg::{RelayMsg, Sendme};
use tor_cell::relaycell::{RelayCell, RelayCmd, StreamId};

use tor_linkspec::LinkSpec;

pub use tor_cell::relaycell::msg::IPVersionPreference;

use futures::channel::{mpsc, oneshot};
use futures::lock::Mutex;
use futures::sink::SinkExt;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use rand::{thread_rng, CryptoRng, Rng};

use log::{debug, trace, warn};

/// A circuit that we have constructed over the Tor network.
pub struct ClientCirc {
    /// This circuit can't be used because it has been closed, locally
    /// or remotely.
    closed: AtomicBool,
    /// A unique identifier for this circuit.
    unique_id: UniqId,

    /// Reference-counted locked reference to the inner circuit object.
    c: Mutex<ClientCircImpl>,
}

/// A ClientCirc that needs to send a create cell and receive a created* cell.
///
/// To use one of these, call create_firsthop_fast() or create_firsthop_ntor()
/// to negotiate the cryptographic handshake with the first hop.
pub struct PendingClientCirc {
    /// A oneshot receiver on which we'll receive a CREATED* cell,
    /// or a DESTROY cell.
    recvcreated: oneshot::Receiver<CreateResponse>,
    /// The ClientCirc object that we can expose on success.
    circ: Arc<ClientCirc>,
}

/// Description of the network's current rules for building circuits.
#[derive(Clone, Debug)]
pub struct CircParameters {
    /// Initial value to use for our outbound circuit-level windows.
    initial_send_window: u16,
    /// Whether we should include ed25519 identities when we send
    /// EXTEND2 cells.
    extend_by_ed25519_id: bool,
}

impl Default for CircParameters {
    fn default() -> CircParameters {
        CircParameters {
            initial_send_window: 1000,
            extend_by_ed25519_id: true,
        }
    }
}

impl CircParameters {
    /// Override the default initial send window for these parameters.
    /// Ignores any value over 1000.
    ///
    /// You should probably not call this.
    pub fn set_initial_send_window(&mut self, v: u16) {
        if v <= 1000 {
            self.initial_send_window = v;
        } else {
            warn!("internal error: bad value {}", v);
        }
    }
    /// Override the default decision about whether to use ed25519
    /// identities in outgoing EXTEND2 cells.
    ///
    /// You should probably not call this.
    pub fn set_extend_by_ed25519_id(&mut self, v: bool) {
        self.extend_by_ed25519_id = v;
    }
}

/// A result type used to tell a circuit about some a "meta-cell"
/// (like extended, intro_established, etc).
type MetaResult = Result<(HopNum, RelayMsg)>;

/// The implementation type for this circuit.
struct ClientCircImpl {
    /// This circuit's ID on the upstream channel.
    id: CircId,
    /// The channel that this circuit uses to send its cells to the
    /// next hop.
    channel: Arc<Channel>,
    /// The cryptographic state for this circuit for outbound cells.
    /// This object is divided into multiple layers, each of which is
    /// shared with one hop of the circuit
    crypto_out: OutboundClientCrypt,
    /// When this is dropped, the channel reactor is told to send a DESTROY
    /// cell.
    circ_closed: Option<CircDestroyHandle>,
    /// Per-hop circuit information.
    ///
    /// Note that hops.len() must be the same as crypto.n_layers().
    hops: Vec<CircHop>,
    /// A stream that can be used to register streams with the reactor.
    control: mpsc::Sender<CtrlResult>,
    /// A oneshot sender that can be used to tell the reactor to shut down.
    sendshutdown: Option<oneshot::Sender<CtrlMsg>>,
    /// A oneshot sender that can be used by the reactor to report a
    /// meta-cell to an owning task.
    ///
    /// For the purposes of this implementation, a "meta" cell
    /// is a RELAY cell with a stream ID value of 0.
    sendmeta: Option<oneshot::Sender<MetaResult>>,

    /// An identifier for this circuit, for logging purposes.
    /// TODO: Make this field go away in favor of the one in ClientCirc.
    unique_id: UniqId,
}

/// A handle to a circuit as held by a stream. Used to send cells.
///
/// Rather than using the stream directly, the stream uses this object
/// to send its relay cells to the correct hop, using the correct stream ID.
///
/// When this object is dropped, the reactor will be told to close the stream.
// XXXX TODO: rename this
pub(crate) struct StreamTarget {
    /// The stream ID for this stream on its circuit.
    stream_id: StreamId,
    /// Which hop on this circuit is this stream built from?
    // XXXX Using 'hop' by number here will cause bugs if circuits can get
    // XXXX truncated and then re-extended.
    hop: HopNum,
    /// Reference to the circuit that this stream is on.
    circ: Arc<ClientCirc>,
    /// Window for sending cells on this circuit.
    window: sendme::StreamSendWindow,
    /// One-shot sender that should get a message once this stream
    /// is dropped.
    stream_closed: Option<oneshot::Sender<CtrlMsg>>,
    /// Window to track incoming cells and SENDMEs.
    // XXXX Putting this field here in this object means that this
    // object isn't really so much a "target", since a "target"
    // doesn't know how to receive.  Maybe we should rename it to be
    // some kind of a "handle" or something?
    pub(crate) recvwindow: sendme::StreamRecvWindow,
}

/// Information about a single hop of a client circuit, from the sender-side
/// point of view.
///
/// (see also circuit::reactor::InboundHop)
struct CircHop {
    /// If true, this hop is using an older link protocol and we
    /// shouldn't expect good authenticated SENDMEs from it.
    auth_sendme_optional: bool,
    /// Window used to say how many cells we can send.
    sendwindow: sendme::CircSendWindow,
}

impl CircHop {
    /// Construct a new (sender-side) view of a circuit hop.
    fn new(auth_sendme_optional: bool, initial_window: u16) -> Self {
        CircHop {
            auth_sendme_optional,
            sendwindow: sendme::CircSendWindow::new(initial_window),
        }
    }
}

impl ClientCirc {
    /// Helper: Register a handler that will be told about the RELAY message
    /// with StreamId 0.
    ///
    /// This pattern is useful for parts of the protocol where the circuit
    /// originator sends a single request, and waits for a single relay
    /// message in response.  (For example, EXTEND/EXTENDED,
    /// ESTABLISH_RENDEZVOUS/RENDEZVOUS_ESTABLISHED, and so on.)
    ///
    /// It isn't suitable for SENDME cells, INTRODUCE2 cells, or TRUNCATED
    /// cells.
    ///
    /// Only one handler can be registerd at a time; until it fires or is
    /// cancelled, you can't register another.
    ///
    /// Note that you should register a meta handler _before_ you send whatever
    /// cell you're waiting a response to, or you might miss the response.
    // TODO: It would be cool for this to take a list of allowable
    // cell types to get in response, so that any other cell types are
    // treated as circuit protocol violations automatically.
    async fn register_meta_handler(&self) -> Result<oneshot::Receiver<MetaResult>> {
        let (sender, receiver) = oneshot::channel();

        let mut circ = self.c.lock().await;
        // Was there previously a handler?
        if circ.sendmeta.is_some() {
            return Err(Error::InternalError(
                "Tried to register a second meta-cell handler".into(),
            ));
        }
        circ.sendmeta = Some(sender);

        trace!("{}: Registered a meta-cell handler", circ.unique_id);

        Ok(receiver)
    }

    /// Helper: return the number of hops for this circuit
    #[cfg(test)]
    async fn n_hops(&self) -> usize {
        let c = self.c.lock().await;
        c.crypto_out.n_layers()
    }

    /// Helper: extend the circuit by one hop.
    ///
    /// The `rng` is used to generate handshake material.  The
    /// `handshake_id` is the numeric identifer for what kind of
    /// handshake we're doing.  The `key is the relay's onion key that
    /// goes along with the handshake, and the `linkspecs` are the
    /// link specifiers to include in the EXTEND cell to tell the
    /// current last hop which relay to connect to.
    async fn extend_impl<R, L, FWD, REV, H>(
        &self,
        rng: &mut R,
        handshake_id: u16,
        key: &H::KeyType,
        linkspecs: Vec<LinkSpec>,
        supports_flowctrl_1: bool,
        params: &CircParameters,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer<FWD, REV>,
        FWD: OutboundClientLayer + 'static + Send,
        REV: InboundClientLayer + 'static + Send,
        H: ClientHandshake,
        H::KeyGen: KeyGenerator,
    {
        use tor_cell::relaycell::msg::{Body, Extend2};
        // Perform the first part of the cryptographic handshake
        let (state, msg) = H::client1(rng, &key)?;
        // Cloning linkspecs is only necessary because of the log
        // below. Would be nice to fix that.
        let extend_msg = Extend2::new(linkspecs.clone(), handshake_id, msg);
        let cell = RelayCell::new(0.into(), extend_msg.into_message());

        // We'll be waiting for an EXTENDED2 cell; install the handler.
        let receiver = self.register_meta_handler().await?;

        // Now send the EXTEND2 cell to the the last hop...
        let (unique_id, hop) = {
            let mut c = self.c.lock().await;
            let n_hops = c.crypto_out.n_layers();
            let hop = ((n_hops - 1) as u8).into();
            debug!(
                "{}: Extending circuit to hop {} with {:?}",
                c.unique_id,
                n_hops + 1,
                linkspecs
            );

            // Send the message to the last hop...
            c.send_relay_cell(
                hop, true, // use a RELAY_EARLY cell
                cell,
            )
            .await?;

            (c.unique_id, hop)
            // note that we're dropping the lock here, since we're going
            // to wait for a response.
        };

        trace!("{}: waiting for EXTENDED2 cell", unique_id);
        // ... and now we wait for a response.
        let (from_hop, msg) = receiver.await.map_err(|_| {
            Error::CircDestroy("Circuit closed while waiting for extended cell".into())
        })??;

        // XXXX If two EXTEND cells are of these are launched on the
        // same circuit at once, could they collide in this part of
        // the function?  I don't _think_ so, but it might be a good idea
        // to have an "extending" bit that keeps two tasks from entering
        // extend_impl at the same time.

        // Did we get the right response?
        if from_hop != hop || msg.cmd() != RelayCmd::EXTENDED2 {
            self.protocol_error().await;
            return Err(Error::CircProto(format!(
                "wanted EXTENDED2 from {}; got {} from {}",
                hop,
                msg.cmd(),
                from_hop
            )));
        }

        // ???? Do we need to shutdown the circuit for the remaining error
        // ???? cases in this function?

        let msg = match msg {
            RelayMsg::Extended2(e) => e,
            _ => return Err(Error::InternalError("Body didn't match cmd".into())),
        };
        let server_handshake = msg.into_body();

        trace!(
            "{}: Received EXTENDED2 cell; completing handshake.",
            unique_id
        );
        // Now perform the second part of the handshake, and see if it
        // succeeded.
        let keygen = H::client2(state, server_handshake)?;
        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit extended.", unique_id);

        // If we get here, it succeeded.  Add a new hop to the circuit.
        let (layer_fwd, layer_back) = layer.split();
        self.add_hop(
            supports_flowctrl_1,
            Box::new(layer_fwd),
            Box::new(layer_back),
            params,
        )
        .await
    }

    /// Add a hop to the end of this circuit.
    ///
    /// This function is a bit tricky, since we need to add the
    /// hop to our own structures, and tell the reactor to add it to the
    /// reactor's structures as well, and wait for the reactor to tell us
    /// that it did.
    async fn add_hop<'a>(
        &'a self,
        supports_flowctrl_1: bool,
        fwd: Box<dyn OutboundClientLayer + 'static + Send>,
        rev: Box<dyn InboundClientLayer + 'static + Send>,
        params: &'a CircParameters,
    ) -> Result<()> {
        let inbound_hop = crate::circuit::reactor::InboundHop::new();
        let (snd, rcv) = oneshot::channel();
        {
            let mut c = self.c.lock().await;
            c.control
                .send(Ok(CtrlMsg::AddHop(inbound_hop, rev, snd)))
                .await
                .map_err(|_| Error::InternalError("Can't queue AddHop request".into()))?;
        }

        // I think we don't need to worry about two hops being added at
        // once, because there can only be on meta-message receiver at
        // a time.

        rcv.await
            .map_err(|_| Error::InternalError("AddHop request cancelled".into()))?;

        {
            let mut c = self.c.lock().await;
            let hop = CircHop::new(supports_flowctrl_1, params.initial_send_window);
            c.hops.push(hop);
            c.crypto_out.add_layer(fwd);
        }
        Ok(())
    }

    /// Extend the circuit via the ntor handshake to a new target last
    /// hop.  Same caveats apply from extend_impl.
    pub async fn extend_ntor<R, Tg>(
        &self,
        rng: &mut R,
        target: &Tg,
        params: &CircParameters,
    ) -> Result<()>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::CircTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let key = NtorPublicKey {
            id: *target.rsa_identity(),
            pk: *target.ntor_onion_key(),
        };
        let mut linkspecs = target.linkspecs();
        if !params.extend_by_ed25519_id {
            linkspecs.retain(|ls| !matches!(ls, LinkSpec::Ed25519Id(_)));
        }
        // FlowCtrl=1 means that this hop supports authenticated SENDMEs
        let supports_flowctrl_1 = target
            .protovers()
            .supports_known_subver(tor_protover::ProtoKind::FlowCtrl, 1);
        self.extend_impl::<R, Tor1RelayCrypto, _, _, NtorClient>(
            rng,
            0x0002,
            &key,
            linkspecs,
            supports_flowctrl_1,
            params,
        )
        .await
    }

    /// Helper, used to begin a stream.
    ///
    /// This function allocates a stream ID, and sends the message
    /// (like a BEGIN or RESOLVE), but doesn't wait for a response.
    ///
    /// The caller will typically want to see the first cell in response,
    /// to see whether it is e.g. an END or a CONNECTED.
    async fn begin_stream_impl(self: &Arc<Self>, begin_msg: RelayMsg) -> Result<TorStream> {
        // TODO: Possibly this should take a hop, rather than just
        // assuming it's the last hop.

        // XXXX Both a bound and a lack of bound are scary here :/
        let (sender, receiver) = mpsc::channel(128);

        let (send_close, recv_close) = oneshot::channel::<CtrlMsg>();
        let window = sendme::StreamSendWindow::new(StreamTarget::SEND_WINDOW_INIT);

        let (id_snd, id_rcv) = oneshot::channel();
        let hopnum;
        {
            let mut c = self.c.lock().await;
            let h = c.hops.len() - 1;
            hopnum = (h as u8).into();

            c.control
                .send(Ok(CtrlMsg::AddStream(
                    hopnum,
                    sender,
                    window.new_ref(),
                    id_snd,
                )))
                .await
                .map_err(|_| Error::InternalError("Can't queue new-stream request.".into()))?;
        }

        let id = id_rcv
            .await
            .map_err(|_| Error::InternalError("Didn't receive a stream ID.".into()))?;
        let id = id?;

        let relaycell = RelayCell::new(id, begin_msg);

        {
            let mut c = self.c.lock().await;
            c.send_relay_cell(hopnum, false, relaycell).await?;
            c.control
                .send(Ok(CtrlMsg::Register(recv_close)))
                .await
                .map_err(|_| Error::InternalError("Can't queue stream closer".into()))?;
        }

        /// Initial value for inbound flow-control window on streams.
        const STREAM_RECV_INIT: u16 = 500;

        let target = StreamTarget {
            circ: Arc::clone(self),
            stream_id: id,
            hop: hopnum,
            window,
            recvwindow: sendme::StreamRecvWindow::new(STREAM_RECV_INIT),
            stream_closed: Some(send_close),
        };

        Ok(TorStream::new(target, receiver))
    }

    /// Start a DataStream connection to the given address and port,
    /// using a BEGIN cell.
    async fn begin_data_stream(self: Arc<Self>, msg: RelayMsg) -> Result<DataStream> {
        let stream = self.begin_stream_impl(msg).await?;
        // TODO: waiting for a response here preculdes optimistic data.

        // Setup a timeout for new streams
        // XXXX: Make this configurable (is it the same as SocksTimeout)?
        let stream_timeout = Duration::from_secs(120);

        let response = tor_rtcompat::timer::timeout(stream_timeout, stream.recv()).await??;

        if response.cmd() == RelayCmd::CONNECTED {
            Ok(DataStream::new(stream))
        } else if response.cmd() == RelayCmd::END {
            Err(Error::StreamClosed("end cell when waiting for connection"))
        } else {
            self.protocol_error().await;
            Err(Error::StreamProto(format!(
                "Received {} while waiting for connection",
                response.cmd()
            )))
        }
    }

    /// Start a connection to the given address and port, using a BEGIN
    /// cell.
    ///
    /// The use of a string for the address is intentional: you should let
    /// the remote Tor relay do the hostname lookup for you.
    pub async fn begin_stream(
        self: Arc<Self>,
        target: &str,
        port: u16,
        flags: Option<IPVersionPreference>,
    ) -> Result<DataStream> {
        let flags = flags.unwrap_or_default();
        let beginmsg = tor_cell::relaycell::msg::Begin::new(target, port, flags)?;
        self.begin_data_stream(beginmsg.into()).await
    }

    /// Start a new connection to the last router in the circuit, using
    /// a BEGIN_DIR cell.
    pub async fn begin_dir_stream(self: Arc<Self>) -> Result<DataStream> {
        self.begin_data_stream(RelayMsg::BeginDir).await
    }
    // XXXX Add a RESOLVE implementation, it will be simple.

    /// Helper: Encode the relay cell `cell`, encrypt it, and send it to the
    /// 'hop'th hop.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_relay_cell(&self, hop: HopNum, early: bool, cell: RelayCell) -> Result<()> {
        if self.closed.load(Ordering::SeqCst) {
            return Err(Error::CircuitClosed);
        }
        let mut c = self.c.lock().await;
        c.send_relay_cell(hop, early, cell).await
    }

    /// Shut down this circuit immediately, along with all streams that
    /// are using it.
    ///
    /// Note that other references to this circuit may exist.  If they
    /// do, they will stop working after you call this function.
    ///
    /// It's not necessary to call this method if you're just done
    /// with a circuit: the channel should close on its own once nothing
    /// is using it any more.
    pub async fn terminate(&self) {
        let outcome = self
            .closed
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst);
        if outcome == Ok(false) {
            // The old value was false and the new value is true.
            self.c.lock().await.shutdown_reactor();
        }
    }

    /// Called when a circuit-level protocol error has occured and the
    /// circuit needs to shut down.
    ///
    /// This is a separate function because we may eventually want to have
    /// it do more than just shut down.
    pub(crate) async fn protocol_error(&self) {
        self.terminate().await;
    }

    /// Return true if this circuit is closed and therefore unusable.
    pub fn is_closing(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    /// Return a process-unique identifier for this circui.
    pub fn unique_id(&self) -> UniqId {
        self.unique_id
    }
}

impl ClientCircImpl {
    /// Return a mutable reference to the nth hop of this circuit, if one
    /// exists.
    fn hop_mut(&mut self, hopnum: HopNum) -> Option<&mut CircHop> {
        self.hops.get_mut(Into::<usize>::into(hopnum))
    }

    /// Handle a RELAY cell on this circuit with stream ID 0.
    async fn handle_meta_cell(&mut self, hopnum: HopNum, msg: RelayMsg) -> Result<()> {
        // SENDME cells and TRUNCATED get handled internally by the circuit.
        if let RelayMsg::Sendme(s) = msg {
            return self.handle_sendme(hopnum, s).await;
        }
        if let RelayMsg::Truncated(_) = msg {
            // XXXX need to handle Truncated cells. This isn't the right
            // way, but at least it's safe.
            return Err(Error::CircuitClosed);
        }

        trace!("{}: Received meta-cell {:?}", self.unique_id, msg);

        // For all other command types, we'll only get them in response
        // to another command, which should have registered a responder.
        //
        // TODO: that means that service-introduction circuits will need
        // a different implementation, but that should be okay. We'll work
        // something out.
        if let Some(sender) = self.sendmeta.take() {
            // Somebody was waiting for a message -- maybe this message
            sender
                .send(Ok((hopnum, msg)))
                // I think this means that the channel got closed.
                .map_err(|_| Error::CircuitClosed)
        } else {
            // No need to call shutdown here, since this error will
            // propagate to the reactor shut it down.
            Err(Error::CircProto(format!(
                "Unexpected {} cell on client circuit",
                msg.cmd()
            )))
        }
    }

    /// Handle a RELAY_SENDME cell on this circuit with stream ID 0.
    async fn handle_sendme(&mut self, hopnum: HopNum, msg: Sendme) -> Result<()> {
        // No need to call "shutdown" on errors in this function;
        // it's called from the reactor task and errors will propagate there.
        let hop = self
            .hop_mut(hopnum)
            .ok_or_else(|| Error::CircProto(format!("Couldn't find {} hop", hopnum)))?;

        let auth: Option<[u8; 20]> = match msg.into_tag() {
            Some(v) if v.len() == 20 => {
                // XXXX ugly code.
                let mut tag = [0u8; 20];
                (&mut tag).copy_from_slice(&v[..]);
                Some(tag)
            }
            Some(_) => return Err(Error::CircProto("malformed tag on circuit sendme".into())),
            None => {
                if !hop.auth_sendme_optional {
                    return Err(Error::CircProto("missing tag on circuit sendme".into()));
                } else {
                    None
                }
            }
        };
        match hop.sendwindow.put(auth).await {
            Some(_) => Ok(()),
            None => Err(Error::CircProto("bad auth tag on circuit sendme".into())),
        }
    }

    /// Helper: Put a cell onto this circuit's channel.
    ///
    /// This takes a raw cell that has already been encrypted, puts
    /// a circuit ID on it, and sends it.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_msg(&mut self, msg: ChanMsg) -> Result<()> {
        let cell = ChanCell::new(self.id, msg);
        self.channel.send_cell(cell).await?;
        Ok(())
    }

    /// Helper: Encode the relay cell `cell`, encrypt it, and send it to the
    /// 'hop'th hop.
    ///
    /// Does not check whether the cell is well-formed or reasonable.
    async fn send_relay_cell(&mut self, hop: HopNum, early: bool, cell: RelayCell) -> Result<()> {
        let c_t_w = sendme::cell_counts_towards_windows(&cell);
        let mut body: RelayCellBody = cell.encode(&mut thread_rng())?.into();
        let tag = self.crypto_out.encrypt(&mut body, hop)?;
        let msg = chancell::msg::Relay::from_raw(body.into());
        let msg = if early {
            ChanMsg::RelayEarly(msg)
        } else {
            ChanMsg::Relay(msg)
        };
        // If the cell counted towards our sendme window, decrement
        // that window, and maybe remember the authentication tag.
        if c_t_w {
            // XXXX I wish I didn't have to copy the tag.
            // TODO: I'd like to use get_hops_mut here, but the borrow checker
            // won't let me.
            assert!(tag.len() == 20); // XXXX risky
            let mut tag_copy = [0u8; 20];
            (&mut tag_copy[..]).copy_from_slice(&tag[..]);
            // This blocks if the send window is empty.
            self.hops[Into::<usize>::into(hop)]
                .sendwindow
                .take(&tag_copy)
                .await?;
        }
        self.send_msg(msg).await
    }

    /// Shut down this circuit's reactor and send a DESTROY cell.
    ///
    /// This is idempotent and safe to call more than once.
    fn shutdown_reactor(&mut self) {
        if let Some(sender) = self.sendshutdown.take() {
            // ignore the error, since it can only be canceled.
            let _ = sender.send(CtrlMsg::Shutdown);
        }
        // Drop the circuit destroy handle now so that a DESTROY cell
        // gets sent.
        drop(self.circ_closed.take());
    }
}

impl PendingClientCirc {
    /// Instantiate a new circuit object: used from Channel::new_circ().
    ///
    /// Does not send a CREATE* cell on its own.
    ///
    ///
    pub(crate) fn new(
        id: CircId,
        channel: Arc<Channel>,
        createdreceiver: oneshot::Receiver<CreateResponse>,
        circ_closed: Option<CircDestroyHandle>,
        input: mpsc::Receiver<ClientCircChanMsg>,
        unique_id: UniqId,
    ) -> (PendingClientCirc, reactor::Reactor) {
        let crypto_out = OutboundClientCrypt::new();
        let (sendclosed, recvclosed) = oneshot::channel::<CtrlMsg>();
        // Should this be bounded, really? XXX
        let (sendctrl, recvctrl) = mpsc::channel::<CtrlResult>(128);
        let hops = Vec::new();

        let circuit_impl = ClientCircImpl {
            id,
            channel,
            crypto_out,
            hops,
            circ_closed,
            control: sendctrl,
            sendshutdown: Some(sendclosed),
            sendmeta: None,
            unique_id,
        };
        let circuit = ClientCirc {
            closed: AtomicBool::new(false),
            c: Mutex::new(circuit_impl),
            unique_id,
        };
        let circuit = Arc::new(circuit);
        let pending = PendingClientCirc {
            recvcreated: createdreceiver,
            circ: Arc::clone(&circuit),
        };
        let reactor = reactor::Reactor::new(circuit, recvctrl, recvclosed, input, unique_id);
        (pending, reactor)
    }

    /// Testing only: extract the circuit ID for thid pending circuit.
    #[cfg(test)]
    pub(crate) async fn peek_circid(&self) -> CircId {
        let c = self.circ.c.lock().await;
        c.id
    }

    /// Helper: create the first hop of a circuit.
    ///
    /// This is parameterized not just on the RNG, but a wrapper object to
    /// build the right kind of create cell, a handshake object to perform
    /// the cryptographic cryptographic handshake, and a layer type to
    /// handle relay crypto after this hop is built.
    async fn create_impl<R, L, FWD, REV, H, W>(
        self,
        rng: &mut R,
        wrap: &W,
        key: &H::KeyType,
        supports_flowctrl_1: bool,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        R: Rng + CryptoRng,
        L: CryptInit + ClientLayer<FWD, REV> + 'static + Send, // need all this?XXXX
        FWD: OutboundClientLayer + 'static + Send,
        REV: InboundClientLayer + 'static + Send,
        H: ClientHandshake,
        W: CreateHandshakeWrap,
        H::KeyGen: KeyGenerator,
    {
        // We don't need to shut down the circuit on failure here, since this
        // function consumes the PendingClientCirc and only returns
        // a ClientCirc on success.

        let PendingClientCirc { circ, recvcreated } = self;
        let (state, msg) = H::client1(rng, &key)?;
        let create_cell = wrap.to_chanmsg(msg);
        let unique_id = {
            let mut c = circ.c.lock().await;
            debug!(
                "{}: Extending to hop 1 with {}",
                c.unique_id,
                create_cell.cmd()
            );
            c.send_msg(create_cell).await?;
            c.unique_id
        };

        let reply = recvcreated
            .await
            .map_err(|_| Error::CircProto("Circuit closed while waiting".into()))?;

        let server_handshake = wrap.from_chanmsg(reply)?;
        let keygen = H::client2(state, server_handshake)?;

        let layer = L::construct(keygen)?;

        debug!("{}: Handshake complete; circuit created.", unique_id);

        let (layer_fwd, layer_back) = layer.split();
        circ.add_hop(
            supports_flowctrl_1,
            Box::new(layer_fwd),
            Box::new(layer_back),
            params,
        )
        .await?;
        Ok(circ)
    }

    /// Use the (questionable!) CREATE_FAST handshake to connect to the
    /// first hop of this circuit.
    ///
    /// There's no authentication in CRATE_FAST,
    /// so we don't need to know whom we're connecting to: we're just
    /// connecting to whichever relay the channel is for.
    pub async fn create_firsthop_fast<R>(
        self,
        rng: &mut R,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        R: Rng + CryptoRng,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::fast::CreateFastClient;
        let wrap = CreateFastWrap;
        self.create_impl::<R, Tor1RelayCrypto, _, _, CreateFastClient, _>(
            rng,
            &wrap,
            &(),
            false,
            params,
        )
        .await
    }

    /// Use the ntor handshake to connect to the first hop of this circuit.
    ///
    /// Note that the provided 'target' must match the channel's target,
    /// or the handshake will fail.
    pub async fn create_firsthop_ntor<R, Tg>(
        self,
        rng: &mut R,
        target: &Tg,
        params: &CircParameters,
    ) -> Result<Arc<ClientCirc>>
    where
        R: Rng + CryptoRng,
        Tg: tor_linkspec::CircTarget,
    {
        use crate::crypto::cell::Tor1RelayCrypto;
        use crate::crypto::handshake::ntor::{NtorClient, NtorPublicKey};
        let wrap = Create2Wrap {
            handshake_type: 0x0002, // ntor
        };
        let key = NtorPublicKey {
            id: *target.rsa_identity(),
            pk: *target.ntor_onion_key(),
        };
        // FlowCtrl=1 means that this hop supports authenticated SENDMEs
        let supports_flowctrl_1 = target
            .protovers()
            .supports_known_subver(tor_protover::ProtoKind::FlowCtrl, 1);
        self.create_impl::<R, Tor1RelayCrypto, _, _, NtorClient, _>(
            rng,
            &wrap,
            &key,
            supports_flowctrl_1,
            params,
        )
        .await
    }
}

/// An object that can put a given handshake into a ChanMsg for a CREATE*
/// cell, and unwrap a CREATED* cell.
trait CreateHandshakeWrap {
    /// Construct an appropriate ChanMsg to hold this kind of handshake.
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg;
    /// Decode a ChanMsg to an appropriate handshake value, checking
    /// its type.
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>>;
}

/// A CreateHandshakeWrap that generates CREATE_FAST and handles CREATED_FAST.
struct CreateFastWrap;

impl CreateHandshakeWrap for CreateFastWrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        chancell::msg::CreateFast::new(bytes).into()
    }
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            CreatedFast(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with DESTROY.",
            )),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE_FAST with unexpected cell.",
            )),
        }
    }
}

/// A CreateHandshakeWrap that generates CREATE2 and handles CREATED2
struct Create2Wrap {
    /// The handshake type to put in the CREATE2 cell.
    handshake_type: u16,
}
impl CreateHandshakeWrap for Create2Wrap {
    fn to_chanmsg(&self, bytes: Vec<u8>) -> ChanMsg {
        chancell::msg::Create2::new(self.handshake_type, bytes).into()
    }
    fn from_chanmsg(&self, msg: CreateResponse) -> Result<Vec<u8>> {
        use CreateResponse::*;
        match msg {
            Created2(m) => Ok(m.into_body()),
            Destroy(_) => Err(Error::CircExtend("Relay replied to CREATE2 with DESTROY.")),
            _ => Err(Error::CircExtend(
                "Relay replied to CREATE2 with unexpected cell.",
            )),
        }
    }
}

impl StreamTarget {
    /// Initial value for outbound flow-control window on streams.
    const SEND_WINDOW_INIT: u16 = 500;

    /// Deliver a relay message for the stream that owns this StreamTarget.
    ///
    /// The StreamTarget will set the correct stream ID and pick the
    /// right hop, but will not validate that the message is well-formed
    /// or meaningful in context.
    pub(crate) async fn send(&mut self, msg: RelayMsg) -> Result<()> {
        if sendme::msg_counts_towards_windows(&msg) {
            // Decrement the stream window (and block if it's empty)
            self.window.take(&()).await?;
        }
        let cell = RelayCell::new(self.stream_id, msg);
        self.circ.send_relay_cell(self.hop, false, cell).await
    }

    /// Called when a circuit-level protocol error has occured and the
    /// circuit needs to shut down.
    pub(crate) async fn protocol_error(&mut self) {
        self.circ.protocol_error().await;
    }
}

impl Drop for ClientCircImpl {
    fn drop(&mut self) {
        self.shutdown_reactor();
    }
}

impl Drop for StreamTarget {
    fn drop(&mut self) {
        if let Some(sender) = self.stream_closed.take() {
            // This "clone" call is a bit dangerous: it means that we might
            // allow the other side to send a couple of cells that get
            // decremented from self.recvwindow but don't get reflected
            // in the circuit-owned view of the window.
            let window = self.recvwindow.clone();
            let _ = sender.send(CtrlMsg::CloseStream(self.hop, self.stream_id, window));
        }
        // If there's an error, no worries: it's hard-cancel, and we
        // can just ignore it. XXXX (I hope?)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::channel::test::fake_channel;
    use chanmsg::{ChanMsg, Created2, CreatedFast};
    use futures::stream::StreamExt;
    use futures_await_test::async_test;
    use hex_literal::hex;
    use tor_cell::chancell::msg as chanmsg;
    use tor_cell::relaycell::msg as relaymsg;
    use tor_llcrypto::pk;

    struct ExampleTarget {
        ntor_key: pk::curve25519::PublicKey,
        protovers: tor_protover::Protocols,
        ed_id: pk::ed25519::Ed25519Identity,
        rsa_id: pk::rsa::RSAIdentity,
    }
    impl tor_linkspec::ChanTarget for ExampleTarget {
        fn addrs(&self) -> &[std::net::SocketAddr] {
            &[]
        }
        fn ed_identity(&self) -> &pk::ed25519::Ed25519Identity {
            &self.ed_id
        }
        fn rsa_identity(&self) -> &pk::rsa::RSAIdentity {
            &self.rsa_id
        }
    }
    impl tor_linkspec::CircTarget for ExampleTarget {
        fn ntor_onion_key(&self) -> &pk::curve25519::PublicKey {
            &self.ntor_key
        }
        fn protovers(&self) -> &tor_protover::Protocols {
            &self.protovers
        }
    }
    /// return an ExampleTarget that can get used for an ntor handshake.
    fn example_target() -> ExampleTarget {
        ExampleTarget {
            ntor_key: hex!("395cb26b83b3cd4b91dba9913e562ae87d21ecdd56843da7ca939a6a69001253")
                .into(),
            protovers: "FlowCtrl=1".parse().unwrap(),
            ed_id: [6_u8; 32].into(),
            rsa_id: [10_u8; 20].into(),
        }
    }
    fn example_serverkey() -> crate::crypto::handshake::ntor::NtorSecretKey {
        crate::crypto::handshake::ntor::NtorSecretKey::new(
            hex!("7789d92a89711a7e2874c61ea495452cfd48627b3ca2ea9546aafa5bf7b55803").into(),
            hex!("395cb26b83b3cd4b91dba9913e562ae87d21ecdd56843da7ca939a6a69001253").into(),
            [10_u8; 20].into(),
        )
    }

    fn test_create(fast: bool) {
        // We want to try progressing from a pending circuit to a circuit
        // via a crate_fast handshake.

        // XXXX Make this use join!() instead.
        use crate::crypto::handshake::{fast::CreateFastServer, ntor::NtorServer, ServerHandshake};
        use futures::executor::LocalPool;
        use futures::future::FutureExt;
        use futures::task::LocalSpawnExt;

        let (chan, mut ch) = fake_channel();
        let circid = 128.into();
        let (created_send, created_recv) = oneshot::channel();
        let (_circmsg_send, circmsg_recv) = mpsc::channel(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, reactor) = PendingClientCirc::new(
            circid,
            chan,
            created_recv,
            None, // circ_closed.
            circmsg_recv,
            unique_id,
        );

        // one to reply as a relay, and one to be the reactor.
        let simulate_relay_fut = async move {
            let mut rng = rand::thread_rng();
            let create_cell = ch.cells.next().await.unwrap();
            assert_eq!(create_cell.circid(), 128.into());
            let reply = if fast {
                let cf = match create_cell.msg() {
                    ChanMsg::CreateFast(cf) => cf,
                    _ => panic!(),
                };
                let (_, rep) = CreateFastServer::server(&mut rng, &[()], cf.body()).unwrap();
                CreateResponse::CreatedFast(CreatedFast::new(rep))
            } else {
                let c2 = match create_cell.msg() {
                    ChanMsg::Create2(c2) => c2,
                    _ => panic!(),
                };
                let (_, rep) =
                    NtorServer::server(&mut rng, &[example_serverkey()], c2.body()).unwrap();
                CreateResponse::Created2(Created2::new(rep))
            };
            created_send.send(reply).unwrap();
        };
        let client_fut = async move {
            let mut rng = rand::thread_rng();
            let target = example_target();
            let params = CircParameters::default();
            if fast {
                pending.create_firsthop_fast(&mut rng, &params).await
            } else {
                pending
                    .create_firsthop_ntor(&mut rng, &target, &params)
                    .await
            }
        };
        let reactor_fut = reactor.run().map(|_| ());

        let mut pool = LocalPool::new();
        let spawner = pool.spawner();
        spawner.spawn_local(reactor_fut).unwrap();
        spawner.spawn_local(simulate_relay_fut).unwrap();
        let client_handle = spawner.spawn_local_with_handle(client_fut).unwrap();
        pool.run_until_stalled();

        let _circuit = client_handle.now_or_never().unwrap().unwrap();

        // pfew!  We've build a circuit!  Let's make sure it has one hop.
        /* TODO: reinstate this.
        let inner = Arc::get_mut(&mut circuit).unwrap().c.into_inner();
        assert_eq!(inner.hops.len(), 1);
         */
    }

    #[test]
    fn test_create_fast() {
        test_create(true)
    }
    #[test]
    fn test_create_ntor() {
        test_create(false)
    }

    // An encryption layer that doesn't do any crypto.
    struct DummyCrypto {
        fixed_tag: [u8; 20],
        lasthop: bool,
    }
    impl crate::crypto::cell::OutboundClientLayer for DummyCrypto {
        fn originate_for(&mut self, _cell: &mut RelayCellBody) -> &[u8] {
            &self.fixed_tag
        }
        fn encrypt_outbound(&mut self, _cell: &mut RelayCellBody) {}
    }
    impl crate::crypto::cell::InboundClientLayer for DummyCrypto {
        fn decrypt_inbound(&mut self, _cell: &mut RelayCellBody) -> Option<&[u8]> {
            if self.lasthop {
                Some(&self.fixed_tag)
            } else {
                None
            }
        }
    }
    impl DummyCrypto {
        fn new(lasthop: bool) -> Self {
            DummyCrypto {
                fixed_tag: [77; 20],
                lasthop,
            }
        }
    }

    // Helper: set up a 3-hop circuit with no encryption.
    async fn newcirc(
        chan: Arc<Channel>,
    ) -> (
        Arc<ClientCirc>,
        reactor::Reactor,
        mpsc::Sender<ClientCircChanMsg>,
    ) {
        let circid = 128.into();
        let (_created_send, created_recv) = oneshot::channel();
        let (circmsg_send, circmsg_recv) = mpsc::channel(64);
        let unique_id = UniqId::new(23, 17);

        let (pending, mut reactor) = PendingClientCirc::new(
            circid,
            Arc::clone(&chan),
            created_recv,
            None, // circ_closed.
            circmsg_recv,
            unique_id,
        );

        let PendingClientCirc {
            circ,
            recvcreated: _,
        } = pending;

        for idx in 0_u8..3 {
            let params = CircParameters::default();
            let (hopf, reacf) = futures::join!(
                circ.add_hop(
                    true,
                    Box::new(DummyCrypto::new(idx == 2)),
                    Box::new(DummyCrypto::new(idx == 2)),
                    &params,
                ),
                reactor.run_once()
            );
            assert!(hopf.is_ok());
            assert!(reacf.is_ok());
        }

        (circ, reactor, circmsg_send)
    }

    // Try sending a cell via send_relay_cell
    #[async_test]
    async fn send_simple() {
        let (chan, mut ch) = fake_channel();
        let (circ, _reactor, _send) = newcirc(chan).await;
        let begindir = RelayCell::new(0.into(), RelayMsg::BeginDir);
        circ.send_relay_cell(2.into(), false, begindir)
            .await
            .unwrap();

        // Here's what we tried to put on the TLS channel.  Note that
        // we're using dummy relay crypto for testing convenience.
        let rcvd = ch.cells.next().await.unwrap();
        assert_eq!(rcvd.circid(), 128.into());
        let m = match rcvd.into_circid_and_msg().1 {
            ChanMsg::Relay(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
            _ => panic!(),
        };
        assert!(matches!(m.msg(), RelayMsg::BeginDir));
    }

    // Try getting a "meta-cell", which is what we're calling those not
    // for a specific circuit.
    #[async_test]
    async fn recv_meta() {
        let (chan, _ch) = fake_channel();
        let (circ, mut reactor, mut sink) = newcirc(chan).await;

        // 1: Try doing it via handle_meta_cell directly.
        let meta_receiver = circ.register_meta_handler().await.unwrap();
        let extended: RelayMsg = relaymsg::Extended2::new((*b"123").into()).into();
        {
            circ.c
                .lock()
                .await
                .handle_meta_cell(2.into(), extended.clone())
                .await
                .unwrap();
        }
        let (hop, msg) = meta_receiver.await.unwrap().unwrap();
        assert_eq!(hop, 2.into());
        assert!(matches!(msg, RelayMsg::Extended2(_)));

        // 2: Try doing it via the reactor.
        let body: RelayCellBody = RelayCell::new(0.into(), extended.clone())
            .encode(&mut thread_rng())
            .unwrap()
            .into();
        let relay = chanmsg::Relay::from_raw(body.into());

        let meta_receiver = circ.register_meta_handler().await.unwrap();
        sink.send(ClientCircChanMsg::Relay(relay.clone()))
            .await
            .unwrap();
        reactor.run_once().await.unwrap();
        let (hop, msg) = meta_receiver.await.unwrap().unwrap();
        assert_eq!(hop, 2.into());
        assert!(matches!(msg, RelayMsg::Extended2(_)));

        // 3: Try getting a meta cell that we didn't want.
        let e = {
            circ.c
                .lock()
                .await
                .handle_meta_cell(2.into(), extended.clone())
                .await
                .err()
                .unwrap()
        };
        assert_eq!(
            format!("{}", e),
            "circuit protocol violation: Unexpected EXTENDED2 cell on client circuit"
        );
    }

    #[async_test]
    async fn extend() {
        use crate::crypto::handshake::{ntor::NtorServer, ServerHandshake};

        let (chan, mut ch) = fake_channel();
        let (circ, mut reactor, mut sink) = newcirc(chan).await;
        let params = CircParameters::default();

        let extend_fut = async move {
            let target = example_target();
            let mut rng = thread_rng();
            circ.extend_ntor(&mut rng, &target, &params).await.unwrap();
            circ // gotta keep the circ alive, or the reactor would exit.
        };
        let reply_fut = async move {
            // We've disabled encryption on this circuit, so we can just
            // read the extend2 cell.
            let (id, chmsg) = ch.cells.next().await.unwrap().into_circid_and_msg();
            assert_eq!(id, 128.into());
            let rmsg = match chmsg {
                ChanMsg::RelayEarly(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
                _ => panic!(),
            };
            let e2 = match rmsg.msg() {
                RelayMsg::Extend2(e2) => e2,
                _ => panic!(),
            };
            let mut rng = thread_rng();
            let (_, reply) =
                NtorServer::server(&mut rng, &[example_serverkey()], e2.handshake()).unwrap();
            let rc = RelayCell::new(0.into(), relaymsg::Extended2::new(reply).into())
                .encode(&mut rng)
                .unwrap();
            let rm = chanmsg::Relay::from_raw(rc.into());
            sink.send(ClientCircChanMsg::Relay(rm.into()))
                .await
                .unwrap();
            sink // gotta keep the sink alive, or the reactor will exit.
        };
        let reactor_fut = async move {
            reactor.run_once().await.unwrap(); // to deliver the relay cell
            reactor.run_once().await.unwrap(); // to handle the AddHop
        };

        let (circ, _, _) = futures::join!(extend_fut, reply_fut, reactor_fut);

        // Did we really add another hop?
        assert_eq!(circ.n_hops().await, 4);
    }

    #[async_test]
    async fn begindir() {
        let (chan, mut ch) = fake_channel();
        let (circ, mut reactor, mut sink) = newcirc(chan).await;

        let begin_fut = async move { circ.begin_dir_stream().await.unwrap() };
        let reply_fut = async move {
            // We've disabled encryption on this circuit, so we can just
            // read the extend2 cell.
            let (id, chmsg) = ch.cells.next().await.unwrap().into_circid_and_msg();
            assert_eq!(id, 128.into());
            let rmsg = match chmsg {
                ChanMsg::Relay(r) => RelayCell::decode(r.into_relay_body()).unwrap(),
                _ => panic!(),
            };
            let (streamid, rmsg) = rmsg.into_streamid_and_msg();
            assert!(matches!(rmsg, RelayMsg::BeginDir));
            let mut rng = thread_rng();
            let rc = RelayCell::new(streamid, relaymsg::Connected::new_empty().into())
                .encode(&mut rng)
                .unwrap();
            let rm = chanmsg::Relay::from_raw(rc.into());
            sink.send(ClientCircChanMsg::Relay(rm.into()))
                .await
                .unwrap();
            sink // gotta keep the sink alive, or the reactor will exit.
        };
        let reactor_fut = async move {
            reactor.run_once().await.unwrap(); // AddStream
            reactor.run_once().await.unwrap(); // Register stream closer
            reactor.run_once().await.unwrap(); // Connected cell
            reactor
        };

        let (_stream, _, _) = futures::join!(begin_fut, reply_fut, reactor_fut);
    }
}

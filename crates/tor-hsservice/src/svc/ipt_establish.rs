//! IPT Establisher
//!
//! Responsible for maintaining and establishing one introduction point.
//!
//! TODO HSS: move docs from `hssvc-ipt-algorithm.md`

#![allow(dead_code, unused_variables)] // TODO hss remove.
#![allow(clippy::needless_pass_by_value)] // TODO HSS remove

use std::sync::{Arc, Mutex};

use futures::{channel::mpsc, task::SpawnExt as _, Future, FutureExt as _};
use itertools::Itertools;
use safelog::Redactable as _;
use tor_async_utils::oneshot;
use tor_async_utils::DropNotifyWatchSender;
use tor_cell::relaycell::{
    hs::est_intro::{self, EstablishIntroDetails},
    msg::{AnyRelayMsg, IntroEstablished},
    RelayMsg as _,
};
use tor_circmgr::hspool::HsCircPool;
use tor_error::{bad_api_usage, debug_report, internal, into_internal};
use tor_hscrypto::{
    pk::{HsBlindIdKey, HsIdKey, HsIntroPtSessionIdKeypair, HsSvcNtorKeypair},
    time::TimePeriod,
    Subcredential,
};
use tor_keymgr::{KeyMgr, KeyPathPatternSet, KeyPathRange};
use tor_keymgr::{KeyPath, KeyPathPattern};
use tor_linkspec::CircTarget;
use tor_linkspec::{HasRelayIds as _, RelayIds};
use tor_netdir::NetDirProvider;
use tor_proto::circuit::{ClientCirc, ConversationInHandler, MetaCellDisposition};
use tor_rtcompat::{Runtime, SleepProviderExt as _};
use tracing::debug;
use void::{ResultVoidErrExt as _, Void};

use crate::keys::{HsSvcHsIdKeyRole, HsSvcKeyRoleWithTimePeriod};
use crate::HsSvcKeySpecifier;
use crate::{
    req::RendRequestContext,
    svc::{LinkSpecs, NtorPublicKey},
    HsNickname,
};
use crate::{FatalError, IptLocalId, RendRequest};

use super::netdir::{wait_for_netdir, wait_for_netdir_to_list, NetdirProviderShutdown};

/// Handle onto the task which is establishing and maintaining one IPT
pub(crate) struct IptEstablisher {
    /// A oneshot sender that notifies the running task that it's time to shut
    /// down.
    terminate_tx: oneshot::Sender<Void>,

    /// Mutable state shared with the Establisher, Reactor, and MsgHandler.
    state: Arc<Mutex<EstablisherState>>,
}

/// When the `IptEstablisher` is dropped it is torn down
///
/// Synchronously
///
///  * No rendezvous requests will be accepted
///    that arrived after `Drop::drop` returns.
///
/// Asynchronously
///
///  * Circuits constructed for this IPT are torn down
///  * The `rend_reqs` sink is closed (dropped)
///  * `IptStatusStatus::Faulty` will be indicated
impl Drop for IptEstablisher {
    fn drop(&mut self) {
        // Make sure no more requests are accepted once this returns.
        //
        // TODO HSS: Note that if we didn't care about the "no more rendezvous
        // requests will be accepted" requirement, we could do away with this
        // code and the corresponding check for `RequestDisposition::Shutdown` in
        // `IptMsgHandler::handle_msg`.)
        self.state.lock().expect("posioned lock").accepting_requests = RequestDisposition::Shutdown;

        // Tell the reactor to shut down... by doing nothing.
        //
        // (When terminate_tx is dropped, it will send an error to the
        // corresponding terminate_rx.)
    }
}

/// An error from trying to work with an IptEstablisher.
#[derive(Clone, Debug, thiserror::Error)]
pub(crate) enum IptError {
    /// We couldn't get a network directory to use when building circuits.
    #[error("No network directory available")]
    NoNetdir(#[source] tor_netdir::Error),

    /// The network directory provider is shutting down without giving us the
    /// netdir we asked for.
    #[error("{0}")]
    NetdirProviderShutdown(#[from] NetdirProviderShutdown),

    /// When we tried to establish this introduction point, we found that the
    /// netdir didn't list it.
    #[error("Introduction point not listed in network directory")]
    IntroPointNotListed,

    /// We encountered an error while building a circuit to an intro point.
    #[error("Unable to build circuit to introduction point")]
    BuildCircuit(#[source] tor_circmgr::Error),

    /// We encountered an error while building and signing our establish_intro
    /// message.
    #[error("Unable to construct signed ESTABLISH_INTRO message")]
    CreateEstablishIntro(#[source] tor_cell::Error),

    /// We encountered a timeout after building the circuit.
    #[error("Timeout during ESTABLISH_INTRO handshake.")]
    EstablishTimeout,

    /// We encountered an error while sending our establish_intro
    /// message.
    #[error("Unable to send an ESTABLISH_INTRO message")]
    SendEstablishIntro(#[source] tor_proto::Error),

    /// We did not receive an INTRO_ESTABLISHED message like we wanted.
    #[error("Did not receive INTRO_ESTABLISHED message")]
    // TODO HSS: I'd like to receive more information here.  What happened
    // instead?  But the information might be in the MsgHandler, might be in the
    // Circuit,...
    ReceiveAck,

    /// We received an invalid INTRO_ESTABLISHED message.
    #[error("Got an invalid INTRO_ESTABLISHED message")]
    BadEstablished,

    /// We encountered a programming error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl tor_error::HasKind for IptError {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use IptError as E;
        match self {
            E::NoNetdir(_) => EK::BootstrapRequired, // TODO HSS maybe not right.
            E::NetdirProviderShutdown(_) => EK::ArtiShuttingDown,
            E::IntroPointNotListed => EK::TorDirectoryError, // TODO HSS Not correct kind.
            E::BuildCircuit(e) => e.kind(),
            E::EstablishTimeout => EK::TorNetworkTimeout, // TODO HSS right?
            E::SendEstablishIntro(e) => e.kind(),
            E::ReceiveAck => EK::RemoteProtocolViolation, // TODO HSS not always right.
            E::BadEstablished => EK::RemoteProtocolViolation,
            E::CreateEstablishIntro(_) => EK::Internal,
            E::Bug(e) => e.kind(),
        }
    }
}

impl IptError {
    /// Return true if this error appears to be the introduction point's fault.
    fn is_ipt_failure(&self) -> bool {
        // TODO HSS: actually test something here.
        true
    }
}

/// Parameters for an introduction point
///
/// Consumed by `IptEstablisher::new`.
/// Primarily serves as a convenient way to bundle the many arguments required.
///
/// Does not include:
///  * The runtime (which would force this struct to have a type parameter)
///  * The circuit builder (leaving this out makes it possible to use this
///    struct during mock execution, where we don't call `IptEstablisher::new`).
#[allow(clippy::missing_docs_in_private_items)] // TODO HSS document these and remove
pub(crate) struct IptParameters {
    // TODO HSS: maybe this should be a bunch of refs.
    pub(crate) netdir_provider: Arc<dyn NetDirProvider>,
    pub(crate) introduce_tx: mpsc::Sender<RendRequest>,
    pub(crate) lid: IptLocalId,
    // TODO HSS: Should this and the following elements be part of some
    // configuration object?
    pub(crate) target: RelayIds,
    /// `K_hs_ipt_sid`
    pub(crate) k_sid: Arc<HsIntroPtSessionIdKeypair>,
    pub(crate) accepting_requests: RequestDisposition,
    pub(crate) k_ntor: Arc<HsSvcNtorKeypair>,
}

impl IptEstablisher {
    /// Try to set up, and maintain, an IPT at `target`.
    ///
    /// Rendezvous requests will be rejected or accepted
    /// depending on the value of `accepting_requests`
    /// (which must be `Advertised` or `NotAdvertised`).
    ///
    /// Also returns a stream of events that is produced whenever we have a
    /// change in the IptStatus for this intro point.  Note that this stream is
    /// potentially lossy.
    ///
    /// The returned `watch::Receiver` will yield `Faulty` if the IPT
    /// establisher is shut down (or crashes).
    // TODO HSS rename to "launch" since it starts the task?
    pub(crate) fn new<R: Runtime>(
        runtime: R,
        nickname: HsNickname,
        params: IptParameters,
        pool: Arc<HsCircPool<R>>,
        keymgr: Arc<KeyMgr>,
    ) -> Result<(Self, postage::watch::Receiver<IptStatus>), FatalError> {
        // This exhaustive deconstruction ensures that we don't
        // accidentally forget to handle any of our inputs.
        let IptParameters {
            netdir_provider,
            introduce_tx,
            lid,
            target,
            k_sid,
            k_ntor,
            accepting_requests,
        } = params;
        if matches!(accepting_requests, RequestDisposition::Shutdown) {
            return Err(bad_api_usage!(
                "Tried to create a IptEstablisher that that was already shutting down?"
            )
            .into());
        }

        let state = Arc::new(Mutex::new(EstablisherState { accepting_requests }));

        // We need the subcredential for the *current time period* in order to do the hs_ntor
        // handshake. But that can change over time.  We will instead use KeyMgr::get_matching to
        // find all current subcredentials.
        //
        // TODO HSS: perhaps the subcredentials should be retrieved in
        // server_receive_intro_no_keygen instead? See also the TODO in HsNtorServiceInput
        let subcredentials = compute_subcredentials(&nickname, &keymgr)?;

        let request_context = Arc::new(RendRequestContext {
            // TODO HSS: This is a workaround because HsSvcNtorSecretKey is not
            // clone.  We should either make it Clone, or hold it in an Arc.
            kp_hss_ntor: Arc::clone(&k_ntor),
            kp_hs_ipt_sid: k_sid.as_ref().as_ref().public.into(),
            subcredentials,
            netdir_provider: netdir_provider.clone(),
            circ_pool: pool.clone(),
        });

        let reactor = Reactor {
            runtime: runtime.clone(),
            pool,
            netdir_provider,
            lid,
            target,
            k_sid, // TODO HSS this is now redundant.
            introduce_tx,
            // TODO HSS This should come from the configuration.
            extensions: EstIntroExtensionSet { dos_params: None },
            state: state.clone(),
            request_context,
        };

        let (status_tx, status_rx) = postage::watch::channel_with(IptStatus::new());
        let (terminate_tx, mut terminate_rx) = oneshot::channel::<Void>();
        let status_tx = DropNotifyWatchSender::new(status_tx);

        runtime
            .spawn(async move {
                futures::select_biased!(
                    terminated = terminate_rx => {
                        // Only Err is possible, but the compiler can't tell that.
                        let oneshot::Canceled = terminated.void_unwrap_err();
                    }
                    outcome = reactor.keep_intro_established(status_tx).fuse() =>  {
                        // TODO HSS: probably we should report this outcome.
                        let _ = outcome;
                    }
                );
            })
            .map_err(|e| FatalError::Spawn {
                spawning: "introduction point establisher",
                cause: Arc::new(e),
            })?;
        let establisher = IptEstablisher {
            terminate_tx,
            state,
        };
        Ok((establisher, status_rx))
    }

    /// Begin accepting requests from this introduction point.
    ///
    /// If any introduction requests are sent before we have called this method,
    /// they are treated as an error and our connection to this introduction
    /// point is closed.
    pub(crate) fn start_accepting(&self) {
        self.state.lock().expect("poisoned lock").accepting_requests =
            RequestDisposition::Advertised;
    }
}

/// Obtain the all current `Subcredential`s of `nickname`
/// from the `K_hs_blind_id` read from the keystore.
fn compute_subcredentials(
    nickname: &HsNickname,
    keymgr: &Arc<KeyMgr>,
) -> Result<Vec<Subcredential>, FatalError> {
    let hsid_role = HsSvcHsIdKeyRole::HsIdPublicKey;
    let hsid_key_spec = HsSvcKeySpecifier::new(nickname, hsid_role);
    let hsid = keymgr
        .get::<HsIdKey>(&hsid_key_spec)?
        .ok_or_else(|| FatalError::MissingKey(hsid_role.to_string()))?;

    let blind_id_pat =
        HsSvcKeySpecifier::arti_pattern(nickname, HsSvcKeyRoleWithTimePeriod::BlindIdPublicKey);

    let pattern = KeyPathPatternSet::new(
        blind_id_pat,
        // TODO HSS: this won't match any C-Tor keys
        KeyPathPattern::new(""),
    );

    let blind_id_kps: Vec<(HsBlindIdKey, TimePeriod)> = keymgr
        .list_matching(&pattern, parse_time_period)?
        .iter()
        .map(
            |(path, key_type, period)| -> Result<Option<_>, FatalError> {
                // Try to retrieve the key.
                keymgr
                    .get_with_type::<HsBlindIdKey>(path, key_type)
                    .map_err(FatalError::Keystore)
                    // If the key is not found, it means it has been garbage collected between the time
                    // we queried the keymgr for the list of keys matching the pattern and now.
                    // This is OK, because we only need the "current" keys
                    .map(|maybe_key| maybe_key.map(|key| (key, *period)))
            },
        )
        .flatten_ok()
        .collect::<Result<Vec<_>, FatalError>>()?;

    Ok(blind_id_kps
        .iter()
        .map(|(blind_id_key, period)| hsid.compute_subcredential(blind_id_key, *period))
        .collect())
}

/// Try to parse the `captures` of `path` as a [`TimePeriod`].
fn parse_time_period(
    path: &KeyPath,
    captures: &[KeyPathRange],
) -> Result<TimePeriod, tor_keymgr::Error> {
    use std::str::FromStr;

    let path = match path {
        KeyPath::Arti(path) => path,
        KeyPath::CTor(_) => todo!(),
        _ => todo!(),
    };

    let [len_range, interval_range, offset_range] = captures else {
        return Err(internal!(
            "invalid number of metadata captures: expected 3, found {}",
            captures.len()
        )
        .into());
    };

    let (length, interval_num, offset_in_sec) = (|| {
        let length = u32::from_str(path.substring(len_range)?).ok()?;
        let interval_num = u64::from_str(path.substring(interval_range)?).ok()?;
        let offset_in_sec = u32::from_str(path.substring(offset_range)?).ok()?;

        Some((length, interval_num, offset_in_sec))
    })()
    .ok_or_else(|| internal!("invalid key metadata"))?;

    Ok(TimePeriod::from_parts(length, interval_num, offset_in_sec))
}

/// The current status of an introduction point, as defined in
/// `hssvc-ipt-algorithms.md`.
///
/// TODO HSS Make that file unneeded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum IptStatusStatus {
    /// We are (re)establishing our connection to the IPT
    ///
    /// But we don't think there's anything wrong with it.
    Establishing,

    /// The IPT is established and ready to accept rendezvous requests
    ///
    /// Also contains information about the introduction point
    /// necessary for making descriptors,
    /// including information from the netdir about the relay
    Good(GoodIptDetails),

    /// We don't have the IPT and it looks like it was the IPT's fault
    ///
    /// This should be used whenever trying another IPT relay is likely to work better;
    /// regardless of whether attempts to establish *this* IPT can continue.
    Faulty,
}

/// Details of a good introduction point
///
/// This struct contains similar information to
/// [`tor_linkspec::verbatim::VerbatimLinkSpecCircTarget`].
/// However, that insists that the contained `T` is a [`CircTarget`],
/// which `<NtorPublicKey>` isn't.
/// And, we don't use this as a circuit target (at least, not here -
/// the client will do so, as a result of us publishing the information).
///
/// See <https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1559#note_2937974>
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GoodIptDetails {
    /// The link specifiers to be used in the descriptor
    ///
    /// As obtained and converted from the netdir.
    pub(crate) link_specifiers: LinkSpecs,

    /// The introduction point relay's ntor key (from the netdir)
    pub(crate) ipt_kp_ntor: NtorPublicKey,
}

impl GoodIptDetails {
    /// Try to copy out the relevant parts of a CircTarget into a GoodIptDetails.
    fn try_from_circ_target(relay: &impl CircTarget) -> Result<Self, IptError> {
        Ok(Self {
            link_specifiers: relay
                .linkspecs()
                .map_err(into_internal!("Unable to encode relay link specifiers"))?,
            ipt_kp_ntor: *relay.ntor_onion_key(),
        })
    }
}

/// `Err(IptWantsToRetire)` indicates that the IPT Establisher wants to retire this IPT
///
/// This happens when the IPT has had (too) many rendezvous requests.
///
/// This must *not* be used for *errors*, because it will cause the IPT manager to
/// *immediately* start to replace the IPT, regardless of rate limits etc.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IptWantsToRetire;

/// State shared between the IptEstablisher and the Reactor.
struct EstablisherState {
    /// True if we are accepting requests right now.
    accepting_requests: RequestDisposition,
}

/// Current state of an introduction point; determines what we want to do with
/// any incoming messages.
#[derive(Copy, Clone, Debug)]
pub(crate) enum RequestDisposition {
    /// We are not yet advertised: the message handler should complain if it
    /// gets any requests and shut down.
    NotAdvertised,
    /// We are advertised: the message handler should pass along any requests
    Advertised,
    /// We are shutting down cleanly: the message handler should exit but not complain.
    Shutdown,
}

/// The current status of an introduction point.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct IptStatus {
    /// The current state of this introduction point as defined by
    /// `hssvc-ipt-algorithms.md`.
    ///
    /// TODO HSS Make that file unneeded.
    pub(crate) status: IptStatusStatus,

    /// How many times have we transitioned into a Faulty state?
    ///
    /// (This is not the same as the total number of failed attempts, since it
    /// does not count times we retry from a Faulty state.)
    pub(crate) n_faults: u32,

    /// The current status of whether this introduction point circuit wants to be
    /// retired based on having processed too many requests.
    pub(crate) wants_to_retire: Result<(), IptWantsToRetire>,
}

impl IptStatus {
    /// Record that we have successfully connected to an introduction point.
    #[allow(unreachable_code, clippy::diverging_sub_expression)] // TODO HSS remove
    fn note_open(&mut self, ipt_details: GoodIptDetails) {
        self.status = IptStatusStatus::Good(ipt_details);
    }

    /// Record that we are trying to connect to an introduction point.
    fn note_attempt(&mut self) {
        use IptStatusStatus::*;
        self.status = match self.status {
            Establishing | Good(..) => Establishing,
            Faulty => Faulty, // We don't change status if we think we're broken.
        }
    }

    /// Record that an error has occurred.
    fn note_error(&mut self, err: &IptError) {
        use IptStatusStatus::*;
        if err.is_ipt_failure() {
            // TODO HSS remove n_faults (nothing reads it)
            self.n_faults += 1;
            self.status = Faulty;
        }
    }

    /// Return an `IptStatus` representing an establisher that has not yet taken
    /// any action.
    fn new() -> Self {
        Self {
            status: IptStatusStatus::Establishing,
            n_faults: 0,
            wants_to_retire: Ok(()),
        }
    }

    /// Produce an `IptStatus` representing a shut down or crashed establisher
    fn new_terminated() -> Self {
        IptStatus {
            status: IptStatusStatus::Faulty,
            n_faults: u32::MAX,
            // If we're broken, we simply tell the manager that that is the case.
            // It will decide for itself whether it wants to replace us.
            wants_to_retire: Ok(()),
        }
    }
}

impl Default for IptStatus {
    fn default() -> Self {
        Self::new()
    }
}

impl tor_async_utils::DropNotifyEofSignallable for IptStatus {
    fn eof() -> IptStatus {
        IptStatus::new_terminated()
    }
}

tor_cell::restricted_msg! {
    /// An acceptable message to receive from an introduction point.
     enum IptMsg : RelayMsg {
         IntroEstablished,
         Introduce2,
     }
}

/// A set of extensions to send with our `ESTABLISH_INTRO` message.
///
/// NOTE: we eventually might want to support unrecognized extensions.  But
/// that's potentially troublesome, since the set of extensions we sent might
/// have an affect on how we validate the reply.
#[derive(Clone, Debug)]
pub(crate) struct EstIntroExtensionSet {
    /// Parameters related to rate-limiting to prevent denial-of-service
    /// attacks.
    dos_params: Option<est_intro::DosParams>,
}

/// Implementation structure for the task that implements an IptEstablisher.
struct Reactor<R: Runtime> {
    /// A copy of our runtime, used for timeouts and sleeping.
    runtime: R,
    /// A pool used to create circuits to the introduction point.
    pool: Arc<HsCircPool<R>>,
    /// A provider used to select the other relays in the circuit.
    netdir_provider: Arc<dyn NetDirProvider>,
    /// Identifier for the intro point.
    ///
    /// TODO HSS: I am assuming that this type will be a unique identifier, and
    /// will change whenever RelayIds and/or HsIntroPtSessionIdKeypair changes.
    lid: IptLocalId,
    /// The target introduction point.
    target: RelayIds,
    /// The keypair to use when establishing the introduction point.
    ///
    /// Knowledge of this private key prevents anybody else from impersonating
    /// us to the introduction point.
    k_sid: Arc<HsIntroPtSessionIdKeypair>,
    /// The extensions to use when establishing the introduction point.
    ///
    /// TODO: Should this be able to change over time if we re-establish this
    /// intro point?
    extensions: EstIntroExtensionSet,

    /// The stream that will receive INTRODUCE2 messages.
    introduce_tx: mpsc::Sender<RendRequest>,

    /// Mutable state shared with the Establisher, Reactor, and MsgHandler.
    state: Arc<Mutex<EstablisherState>>,

    /// Context information that we'll need to answer rendezvous requests.
    request_context: Arc<RendRequestContext>,
}

/// An open session with a single introduction point.
//
// TODO: I've used Ipt and IntroPt in this module; maybe we shouldn't.
pub(crate) struct IntroPtSession {
    /// The circuit to the introduction point, on which we're receiving
    /// Introduce2 messages.
    intro_circ: Arc<ClientCirc>,
}

impl<R: Runtime> Reactor<R> {
    /// Run forever, keeping an introduction point established.
    async fn keep_intro_established(
        &self,
        mut status_tx: DropNotifyWatchSender<IptStatus>,
    ) -> Result<(), IptError> {
        let mut retry_delay = tor_basic_utils::retry::RetryDelay::from_msec(1000);
        loop {
            status_tx.borrow_mut().note_attempt();
            match self.establish_intro_once().await.and_then(|session| {
                let netdir = self
                    .netdir_provider
                    .timely_netdir()
                    .map_err(|_| IptError::IntroPointNotListed)?;
                let relay = netdir
                    .by_ids(&self.target)
                    .ok_or(IptError::IntroPointNotListed)?;
                Ok((session, GoodIptDetails::try_from_circ_target(&relay)?))
            }) {
                Ok((session, good_ipt_details)) => {
                    // TODO HSS we need to monitor the netdir for changes to this relay
                    // Eg,
                    //   - if it becomes unlisted, we should declare the IPT faulty
                    //     (until it perhaps reappears)
                    //
                    //     TODO SPEC  Continuing to use an unlisted relay is dangerous
                    //     It might be malicious.  We should withdraw our IPT then,
                    //     and hope that clients find another, working, IPT.
                    //
                    //   - if it changes its ntor key or link specs,
                    //     we need to update the GoodIptDetails in our status report,
                    //     so that the updated info can make its way to the descriptor
                    //
                    // Possibly some this could/should be done by the IPT Manager instead,
                    // but Diziet thinks it is probably cleanest to do it here.

                    status_tx.borrow_mut().note_open(good_ipt_details);

                    debug!(
                        "Successfully established introduction point with {}",
                        self.target.display_relay_ids().redacted()
                    );
                    // Now that we've succeeded, we can stop backing off for our
                    // next attempt.
                    retry_delay.reset();

                    // Wait for the session to be closed.
                    session.wait_for_close().await;
                }
                Err(e @ IptError::IntroPointNotListed) => {
                    // The network directory didn't include this relay.  Wait
                    // until it does.
                    //
                    // TODO HSS: Perhaps we should distinguish possible error cases
                    // here?  See notes in `wait_for_netdir_to_list`.
                    status_tx.borrow_mut().note_error(&e);
                    wait_for_netdir_to_list(self.netdir_provider.as_ref(), &self.target).await?;
                }
                Err(e) => {
                    status_tx.borrow_mut().note_error(&e);
                    debug_report!(
                        e,
                        "Problem establishing introduction point with {}",
                        self.target.display_relay_ids().redacted()
                    );
                    let retry_after = retry_delay.next_delay(&mut rand::thread_rng());
                    self.runtime.sleep(retry_after).await;
                }
            }
        }
    }

    /// Try, once, to make a circuit to a single relay and establish an introduction
    /// point there.
    ///
    /// Does not retry.  Does not time out except via `HsCircPool`.
    async fn establish_intro_once(&self) -> Result<IntroPtSession, IptError> {
        let circuit = {
            let netdir = wait_for_netdir(
                self.netdir_provider.as_ref(),
                tor_netdir::Timeliness::Timely,
            )
            .await?;
            let circ_target = netdir
                .by_ids(&self.target)
                .ok_or(IptError::IntroPointNotListed)?;

            let kind = tor_circmgr::hspool::HsCircKind::SvcIntro;
            self.pool
                .get_or_launch_specific(netdir.as_ref(), kind, circ_target)
                .await
                .map_err(IptError::BuildCircuit)?
            // note that netdir is dropped here, to avoid holding on to it any
            // longer than necessary.
        };
        let intro_pt_hop = circuit
            .last_hop_num()
            .map_err(into_internal!("Somehow built a circuit with no hops!?"))?;

        let establish_intro = {
            let ipt_sid_id = (*self.k_sid).as_ref().public.into();
            let mut details = EstablishIntroDetails::new(ipt_sid_id);
            if let Some(dos_params) = &self.extensions.dos_params {
                details.set_extension_dos(dos_params.clone());
            }
            let circuit_binding_key = circuit
                .binding_key(intro_pt_hop)
                .ok_or(internal!("No binding key for introduction point!?"))?;
            let body: Vec<u8> = details
                .sign_and_encode((*self.k_sid).as_ref(), circuit_binding_key.hs_mac())
                .map_err(IptError::CreateEstablishIntro)?;

            // TODO HSS: This is ugly, but it is the sensible way to munge the above
            // body into a format that AnyRelayCell will accept without doing a
            // redundant parse step.
            //
            // One alternative would be allowing start_conversation to take an `impl
            // RelayMsg` rather than an AnyRelayMsg.
            //
            // Or possibly, when we feel like it, we could rename one or more of
            // these "Unrecognized"s to Unparsed or Uninterpreted.  If we do that, however, we'll
            // potentially face breaking changes up and down our crate stack.
            AnyRelayMsg::Unrecognized(tor_cell::relaycell::msg::Unrecognized::new(
                tor_cell::relaycell::RelayCmd::ESTABLISH_INTRO,
                body,
            ))
        };

        let (established_tx, established_rx) = oneshot::channel();

        let handler = IptMsgHandler {
            established_tx: Some(established_tx),
            introduce_tx: self.introduce_tx.clone(),
            state: self.state.clone(),
            lid: self.lid,
            request_context: self.request_context.clone(),
        };
        let conversation = circuit
            .start_conversation(Some(establish_intro), handler, intro_pt_hop)
            .await
            .map_err(IptError::SendEstablishIntro)?;
        // At this point, we have `await`ed for the Conversation to exist, so we know
        // that the message was sent.  We have to wait for any actual `established`
        // message, though.

        let ack_timeout = self
            .pool
            .estimate_timeout(&tor_circmgr::timeouts::Action::RoundTrip {
                length: circuit.n_hops(),
            });
        let established = self
            .runtime
            .timeout(ack_timeout, established_rx)
            .await
            .map_err(|_| IptError::EstablishTimeout)?
            .map_err(|_| IptError::ReceiveAck)?;

        if established.iter_extensions().next().is_some() {
            // We do not support any extensions from the introduction point; if it
            // sent us any, that's a protocol violation.
            return Err(IptError::BadEstablished);
        }

        Ok(IntroPtSession {
            intro_circ: circuit,
        })
    }
}

impl IntroPtSession {
    /// Wait for this introduction point session to be closed.
    fn wait_for_close(&self) -> impl Future<Output = ()> {
        self.intro_circ.wait_for_close()
    }
}

/// MsgHandler type to implement a conversation with an introduction point.
///
/// This, like all MsgHandlers, is installed at the circuit's reactor, and used
/// to handle otherwise unrecognized message types.
struct IptMsgHandler {
    /// A oneshot sender used to report our IntroEstablished message.
    ///
    /// If this is None, then we already sent an IntroEstablished and we shouldn't
    /// send any more.
    established_tx: Option<oneshot::Sender<IntroEstablished>>,

    /// A channel used to report Introduce2 messages.
    introduce_tx: mpsc::Sender<RendRequest>,

    /// Keys that we'll need to answer the introduction requests.
    request_context: Arc<RendRequestContext>,

    /// Mutable state shared with the Establisher, Reactor, and MsgHandler.
    state: Arc<Mutex<EstablisherState>>,

    /// Unique identifier for the introduction point (including the current
    /// keys).  Used to tag requests.
    lid: IptLocalId,
}

impl tor_proto::circuit::MsgHandler for IptMsgHandler {
    fn handle_msg(
        &mut self,
        conversation: ConversationInHandler<'_, '_, '_>,
        any_msg: AnyRelayMsg,
    ) -> tor_proto::Result<MetaCellDisposition> {
        // TODO HSS: Implement rate-limiting.
        //
        // TODO HSS: Is CircProto right or should this be a new error type?
        let msg: IptMsg = any_msg.try_into().map_err(|m: AnyRelayMsg| {
            tor_proto::Error::CircProto(format!("Invalid message type {}", m.cmd()))
        })?;

        if match msg {
            IptMsg::IntroEstablished(established) => match self.established_tx.take() {
                Some(tx) => tx.send(established).map_err(|_| ()),
                None => {
                    return Err(tor_proto::Error::CircProto(
                        "Received a redundant INTRO_ESTABLISHED".into(),
                    ));
                }
            },
            IptMsg::Introduce2(introduce2) => {
                if self.established_tx.is_some() {
                    return Err(tor_proto::Error::CircProto(
                        "Received an INTRODUCE2 message before INTRO_ESTABLISHED".into(),
                    ));
                }
                let disp = self.state.lock().expect("poisoned lock").accepting_requests;
                match disp {
                    RequestDisposition::NotAdvertised => {
                        return Err(tor_proto::Error::CircProto(
                            "Received an INTRODUCE2 message before we were accepting requests!"
                                .into(),
                        ))
                    }
                    RequestDisposition::Shutdown => return Ok(MetaCellDisposition::CloseCirc),
                    RequestDisposition::Advertised => {}
                }

                let request = RendRequest::new(self.lid, introduce2, self.request_context.clone());
                match self.introduce_tx.try_send(request) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        if e.is_disconnected() {
                            // The receiver is disconnected, meaning that
                            // messages from this intro point are no longer
                            // wanted.  Close the circuit.
                            Err(())
                        } else {
                            // The receiver is full; we have no real option but
                            // to drop the request like C-tor does when the
                            // backlog is too large.
                            //
                            // See discussion at
                            // https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1465#note_2928349
                            //
                            // TODO HSS: record when this happens.
                            Ok(())
                        }
                    }
                }
            }
        } == Err(())
        {
            // If the above return an error, we failed to send.  That means that
            // we need to close the circuit, since nobody is listening on the
            // other end of the tx.
            return Ok(MetaCellDisposition::CloseCirc);
        }

        Ok(MetaCellDisposition::Consumed)
    }
}

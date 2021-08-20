//! `tor-circmgr`: circuits through the Tor network on demand.
//!
//! # Overview
//!
//! This crate is part of
//! [Arti](https://gitlab.torproject.org/tpo/core/arti/), a project to
//! implement [Tor](https://www.torproject.org/) in Rust.
//!
//! In Tor, a circuit is an encrypted multi-hop tunnel over multiple
//! relays.  This crate's purpose, long-term, is to manage a set of
//! circuits for a client.  It should construct circuits in response
//! to a client's needs, and preemptively construct circuits so as to
//! anticipate those needs.  If a client request can be satisfied with
//! an existing circuit, it should return that circuit instead of
//! constructing a new one.
//!
//! # Limitations
//!
//! But for now, this `tor-circmgr` code is extremely preliminary; its
//! data structures are all pretty bad, and it's likely that the API
//! is wrong too.
//!
//! The path generation code in this crate is missing a colossal
//! number of features that you'd probably want in production: the
//! paths it generates should not be considered secure.

#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![warn(clippy::clone_on_ref_ptr)]
#![warn(clippy::cognitive_complexity)]
#![deny(clippy::debug_assert_with_mut_call)]
#![deny(clippy::exhaustive_enums)]
#![deny(clippy::exhaustive_structs)]
#![deny(clippy::expl_impl_clone_on_copy)]
#![deny(clippy::fallible_impl_from)]
#![deny(clippy::implicit_clone)]
#![deny(clippy::large_stack_arrays)]
#![warn(clippy::manual_ok_or)]
#![deny(clippy::missing_docs_in_private_items)]
#![deny(clippy::missing_panics_doc)]
#![warn(clippy::needless_borrow)]
#![warn(clippy::needless_pass_by_value)]
#![warn(clippy::option_option)]
#![warn(clippy::rc_buffer)]
#![deny(clippy::ref_option_ref)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]

use tor_chanmgr::ChanMgr;
use tor_netdir::{fallback::FallbackDir, NetDir};
use tor_proto::circuit::{CircParameters, ClientCirc, UniqId};
use tor_rtcompat::Runtime;

use futures::task::SpawnExt;
use std::convert::TryInto;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tracing::{debug, warn};

pub mod build;
mod config;
mod err;
mod impls;
mod mgr;
pub mod path;
mod state;
mod timeouts;
mod usage;

pub use err::Error;
pub use usage::{IsolationToken, TargetPort};

pub use config::{
    CircMgrConfig, CircMgrConfigBuilder, CircuitTiming, CircuitTimingBuilder, PathConfig,
    PathConfigBuilder, RequestTiming, RequestTimingBuilder,
};

use usage::TargetCircUsage;

/// A Result type as returned from this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Represents what we know about the Tor network.
///
/// This can either be a complete directory, or a list of fallbacks.
///
/// Not every DirInfo can be used to build every kind of circuit:
/// if you try to build a path with an inadequate DirInfo, you'll get a
/// NeedConsensus error.
#[derive(Debug, Copy, Clone)]
#[non_exhaustive]
pub enum DirInfo<'a> {
    /// A list of fallbacks, for use when we don't know a network directory.
    Fallbacks(&'a [FallbackDir]),
    /// A complete network directory
    Directory(&'a NetDir),
}

impl<'a> From<&'a [FallbackDir]> for DirInfo<'a> {
    fn from(v: &'a [FallbackDir]) -> DirInfo<'a> {
        DirInfo::Fallbacks(v)
    }
}
impl<'a> From<&'a NetDir> for DirInfo<'a> {
    fn from(v: &'a NetDir) -> DirInfo<'a> {
        DirInfo::Directory(v)
    }
}
impl<'a> DirInfo<'a> {
    /// Return a set of circuit parameters for this DirInfo.
    fn circ_params(&self) -> CircParameters {
        use tor_netdir::params::NetParameters;
        /// Extract a CircParameters from the NetParameters from a
        /// consensus.  We use a common function for both cases here
        /// to be sure that we look at the defaults from NetParameters
        /// code.
        fn from_netparams(inp: &NetParameters) -> CircParameters {
            let mut p = CircParameters::default();
            if let Err(e) = p.set_initial_send_window(inp.circuit_window.get() as u16) {
                warn!("Invalid parameter in directory: {}", e);
            }
            p.set_extend_by_ed25519_id(inp.extend_by_ed25519_id.into());
            p
        }

        match self {
            DirInfo::Fallbacks(_) => from_netparams(&NetParameters::default()),
            DirInfo::Directory(d) => from_netparams(d.params()),
        }
    }
}

/// A Circuit Manager (CircMgr) manages a set of circuits, returning them
/// when they're suitable, and launching them if they don't already exist.
///
/// Right now, its notion of "suitable" is quite rudimentary: it just
/// believes in two kinds of circuits: Exit circuits, and directory
/// circuits.  Exit circuits are ones that were created to connect to
/// a set of ports; directory circuits were made to talk to directory caches.
#[derive(Clone)]
pub struct CircMgr<R: Runtime> {
    /// The underlying circuit manager object that implements our behavior.
    mgr: Arc<mgr::AbstractCircMgr<build::CircuitBuilder<R>, R>>,

    /// A state manager for recording timeout history and guard information.
    ///
    /// (Right now there is only one implementation of CircStateMgr, but I
    /// think we'll want to have more before too much time is up. In any
    /// case I don't want to parameterize on this type.)
    storage: state::DynStateMgr,
}

impl<R: Runtime> CircMgr<R> {
    /// Construct a new circuit manager.
    pub fn new<SM>(
        config: CircMgrConfig,
        storage: SM,
        runtime: &R,
        chanmgr: Arc<ChanMgr<R>>,
    ) -> Result<Arc<Self>>
    where
        SM: tor_persist::StateMgr + Send + Sync + 'static,
    {
        let CircMgrConfig {
            path_config,
            request_timing,
            circuit_timing,
        } = config;

        let storage: state::DynStateMgr = Arc::new(storage);

        let builder =
            build::CircuitBuilder::new(runtime.clone(), chanmgr, path_config, Arc::clone(&storage));
        let mgr =
            mgr::AbstractCircMgr::new(builder, runtime.clone(), request_timing, circuit_timing);
        let circmgr = Arc::new(CircMgr {
            mgr: Arc::new(mgr),
            storage,
        });

        runtime.spawn(continually_expire_circuits(
            runtime.clone(),
            Arc::downgrade(&circmgr),
        ))?;

        Ok(circmgr)
    }

    /// Flush state to the state manager, if there is any unsaved state.
    pub fn update_persistent_state(&self) -> Result<()> {
        self.mgr.peek_builder().save_state()
    }

    /// Reconfigure this circuit manager using the latest set of
    /// network parameters.
    ///
    /// (NOTE: for now, this only affects circuit timeout estimation.)
    pub fn update_network_parameters(&self, p: &tor_netdir::params::NetParameters) {
        self.mgr.update_network_parameters(p);
        self.mgr.peek_builder().update_network_parameters(p);
    }

    /// Return a circuit suitable for sending one-hop BEGINDIR streams,
    /// launching it if necessary.
    pub async fn get_or_launch_dir(&self, netdir: DirInfo<'_>) -> Result<Arc<ClientCirc>> {
        self.expire_circuits();
        let usage = TargetCircUsage::Dir;
        self.mgr.get_or_launch(&usage, netdir).await
    }

    /// Return a circuit suitable for exiting to all of the provided
    /// `ports`, launching it if necessary.
    ///
    /// If the list of ports is empty, then the chosen circuit will
    /// still end at _some_ exit.
    pub async fn get_or_launch_exit(
        &self,
        netdir: DirInfo<'_>, // TODO: This has to be a NetDir.
        ports: &[TargetPort],
        isolation_group: IsolationToken,
    ) -> Result<Arc<ClientCirc>> {
        self.expire_circuits();
        let ports = ports.iter().map(Clone::clone).collect();
        let usage = TargetCircUsage::Exit {
            ports,
            isolation_group,
        };
        self.mgr.get_or_launch(&usage, netdir).await
    }

    /// If `circ_id` is the unique identifier for a circuit that we're
    /// keeping track of, don't give it out for any future requests.
    pub fn retire_circ(&self, circ_id: &UniqId) {
        let _ = self.mgr.take_circ(circ_id);
    }

    /// Expire every circuit that has been dirty for too long.
    ///
    /// Expired circuits are not closed while they still have users,
    /// but they are no longer given out for new requests.
    fn expire_circuits(&self) {
        // TODO: I would prefer not to call this at every request, but it
        // should be fine for now.
        let now = self.mgr.peek_runtime().now();
        self.mgr.expire_circs(now);
    }

    /// If we need to launch a testing circuit to judge our circuit
    /// build timeouts timeouts, do so.
    ///
    /// # Note
    ///
    /// This function is invoked periodically from the
    /// `arti-tor-client` crate, based on timings from the network
    /// parameters.  Please don't invoke it on your own; I hope we can
    /// have this API go away in the future.
    ///
    /// I would much prefer to have this _not_ be a public API, and
    /// instead have it be a daemon task.  The trouble is that it
    /// needs to get a NetDir as input, and that isn't possible with
    /// the current CircMgr design.  See
    /// [arti#161](https://gitlab.torproject.org/tpo/core/arti/-/issues/161).
    pub fn launch_timeout_testing_circuit_if_appropriate(&self, netdir: &NetDir) -> Result<()> {
        if !self.mgr.peek_builder().learning_timeouts() {
            return Ok(());
        }
        // We expire any too-old circuits here, so they don't get
        // counted towards max_circs.
        self.expire_circuits();
        let max_circs: u64 = netdir
            .params()
            .cbt_max_open_circuits_for_testing
            .try_into()
            .expect("Out-of-bounds result from BoundedInt32");
        if (self.mgr.n_circs() as u64) < max_circs {
            // Actually launch the circuit!
            let usage = TargetCircUsage::TimeoutTesting;
            let dirinfo = netdir.into();
            let mgr = Arc::clone(&self.mgr);
            debug!("Launching a circuit to test build times.");
            let _ = mgr.launch_by_usage(dirinfo, &usage)?;
        }

        Ok(())
    }
}

/// Periodically expire any circuits that should no longer be given
/// out for requests.
///
/// Exit when we find that `circmgr` is dropped.
///
/// This is a daemon task: it runs indefinitely in the background.
async fn continually_expire_circuits<R: Runtime>(runtime: R, circmgr: Weak<CircMgr<R>>) {
    // TODO: This is too long for accuracy and too short for
    // efficiency.  Instead we should have a more clever scheduling
    // algorithm somehow that gets updated when we have new or newly
    // dirty circuits only.
    let interval = Duration::from_secs(5);

    loop {
        runtime.sleep(interval).await;
        if let Some(cm) = Weak::upgrade(&circmgr) {
            cm.expire_circuits();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn get_params() {
        use tor_netdir::{MdReceiver, PartialNetDir};
        use tor_netdoc::doc::netstatus::NetParams;
        // If it's just fallbackdir, we get the default parameters.
        let di: DirInfo<'_> = (&[][..]).into();

        let p1 = di.circ_params();
        assert_eq!(p1.extend_by_ed25519_id(), false);
        assert_eq!(p1.initial_send_window(), 1000);

        // Now try with a directory and configured parameters.
        let (consensus, microdescs) = tor_netdir::testnet::construct_network();
        let mut params = NetParams::default();
        params.set("circwindow".into(), 100);
        params.set("ExtendByEd25519ID".into(), 1);
        let mut dir = PartialNetDir::new(consensus, Some(&params));
        for m in microdescs {
            dir.add_microdesc(m);
        }
        let netdir = dir.unwrap_if_sufficient().unwrap();
        let di: DirInfo<'_> = (&netdir).into();
        let p2 = di.circ_params();
        assert_eq!(p2.initial_send_window(), 100);
        assert_eq!(p2.extend_by_ed25519_id(), true);

        // Now try with a bogus circwindow value.
        let (consensus, microdescs) = tor_netdir::testnet::construct_network();
        let mut params = NetParams::default();
        params.set("circwindow".into(), 100_000);
        params.set("ExtendByEd25519ID".into(), 1);
        let mut dir = PartialNetDir::new(consensus, Some(&params));
        for m in microdescs {
            dir.add_microdesc(m);
        }
        let netdir = dir.unwrap_if_sufficient().unwrap();
        let di: DirInfo<'_> = (&netdir).into();
        let p2 = di.circ_params();
        assert_eq!(p2.initial_send_window(), 1000); // Not 100_000
        assert_eq!(p2.extend_by_ed25519_id(), true);
    }
}

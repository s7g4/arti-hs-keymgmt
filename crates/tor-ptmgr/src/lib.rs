#![cfg_attr(docsrs, feature(doc_auto_cfg, doc_cfg))]
#![doc = include_str!("../README.md")]
// @@ begin lint list maintained by maint/add_warning @@
#![cfg_attr(not(ci_arti_stable), allow(renamed_and_removed_lints))]
#![cfg_attr(not(ci_arti_nightly), allow(unknown_lints))]
#![deny(missing_docs)]
#![warn(noop_method_call)]
#![deny(unreachable_pub)]
#![warn(clippy::all)]
#![deny(clippy::await_holding_lock)]
#![deny(clippy::cargo_common_metadata)]
#![deny(clippy::cast_lossless)]
#![deny(clippy::checked_conversions)]
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
#![warn(clippy::semicolon_if_nothing_returned)]
#![warn(clippy::trait_duplication_in_bounds)]
#![deny(clippy::unnecessary_wraps)]
#![warn(clippy::unseparated_literal_suffix)]
#![deny(clippy::unwrap_used)]
#![allow(clippy::let_unit_value)] // This can reasonably be done for explicitness
#![allow(clippy::significant_drop_in_scrutinee)] // arti/-/merge_requests/588/#note_2812945
//! <!-- @@ end lint list maintained by maint/add_warning @@ -->

pub mod config;

use config::PtMgrConfig;

#[cfg(feature = "tor-channel-factory")]
use tor_chanmgr::factory::ChannelFactory;
use tor_linkspec::TransportId;
use tor_rtcompat::Runtime;

/// A pluggable transport manager knows how to make different
/// kinds of connections to the Tor network, for censorship avoidance.
///
/// Currently, we only support two kinds of pluggable transports: Those
/// configured in a PtConfig object, and those added with PtMgr::register.
//
// TODO: Will we need a <R:Runtime constraint> here? I don't know. -nickm
#[derive(Clone, Debug)]
pub struct PtMgr<R> {
    /// An underlying `Runtime`, used to spawn background tasks.
    runtime: R,
}

#[allow(clippy::missing_panics_doc, clippy::needless_pass_by_value)]
impl<R: Runtime> PtMgr<R> {
    /// Create a new PtMgr.
    pub fn new(cfg: PtMgrConfig, rt: R) -> Self {
        let _ = (cfg, rt);
        todo!("TODO pt-client: implement this.")
    }
    /// Reload the configuration
    pub fn reconfigure(&self, cfg: PtMgrConfig) -> Result<(), tor_config::ReconfigureError> {
        let _ = cfg;
        todo!("TODO pt-client: implement this.")
    }
    /// Manually add a new channel factory to this registry.
    #[cfg(feature = "tor-channel-factory")]
    pub fn register_factory(&self, ids: &[TransportId], factory: impl ChannelFactory) {
        let _ = (ids, factory);
        todo!("TODO pt-client: implement this.")
    }

    // TODO pt-client: Possibly, this should have a separate function to launch
    // its background tasks.
}

#[cfg(feature = "tor-channel-factory")]
#[allow(clippy::missing_panics_doc)]
impl<R: Runtime> tor_chanmgr::factory::TransportRegistry for PtMgr<R> {
    // There is going to be a lot happening "under the hood" here.
    //
    // When we are asked to get a ChannelFactory for a given
    // connection, we will need to:
    //    - launch the binary for that transport if it is not already running*.
    //    - If we launched the binary, talk to it and see which ports it
    //      is listening on.
    //    - Return a ChannelFactory that connects via one of those ports,
    //      using the appropriate version of SOCKS, passing K=V parameters
    //      encoded properly.
    //
    // * As in other managers, we'll need to avoid trying to launch the same
    //   transport twice if we get two concurrent requests.
    //
    // Later if the binary crashes, we should detect that.  We should relaunch
    // it on demand.
    //
    // On reconfigure, we should shut down any no-longer-used transports.
    //
    // Maybe, we should shut down transports that haven't been used
    // for a long time.

    fn get_factory(&self, transport: &TransportId) -> Option<&(dyn ChannelFactory + Sync)> {
        let _ = transport;
        let _ = &self.runtime;
        todo!("TODO pt-client")
    }
}

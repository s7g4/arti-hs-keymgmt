//! Types and functions to configure a Tor client.
//!
//! Some of these are re-exported from lower-level crates.

use crate::err::ErrorDetail;
use derive_builder::Builder;
use derive_more::AsRef;
use fs_mistrust::{Mistrust, MistrustBuilder};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::path::PathBuf;
use std::result::Result as StdResult;
use std::time::Duration;

pub use tor_chanmgr::{ChannelConfig, ChannelConfigBuilder};
pub use tor_config::convert_helper_via_multi_line_list_builder;
pub use tor_config::impl_standard_builder;
pub use tor_config::list_builder::{MultilineListBuilder, MultilineListBuilderError};
pub use tor_config::mistrust::BuilderExt as _;
pub use tor_config::{define_list_builder_accessors, define_list_builder_helper};
pub use tor_config::{BoolOrAuto, ConfigError};
pub use tor_config::{ConfigBuildError, ConfigurationSource, Reconfigure};
pub use tor_config_path::{CfgPath, CfgPathError, CfgPathResolver};
pub use tor_linkspec::{ChannelMethod, HasChanMethod, PtTransportName, TransportId};
use crate::config::SystemConfig as ConfigAlias;

pub use tor_guardmgr::bridge::BridgeConfigBuilder;

#[cfg(feature = "bridge-client")]
#[cfg_attr(docsrs, doc(cfg(feature = "bridge-client")))]
pub use tor_guardmgr::bridge::BridgeParseError;

use tor_guardmgr::bridge::BridgeConfig;
use tor_keymgr::config::{ArtiKeystoreConfig, ArtiKeystoreConfigBuilder};
use tor_memquota::{MemoryQuotaTracker, Config as MemConfig}; // Import MemoryQuotaTracker and Config
use tor_guardmgr::GuardMgr; // Import GuardMgr
use tor_dirmgr::DirMgrStore; // Import DirMgrStore

/// Types for configuring how Tor circuits are built.
pub mod circ {
    pub use tor_circmgr::{
        CircMgrConfig, CircuitTiming, CircuitTimingBuilder, PathConfig, PathConfigBuilder,
        PreemptiveCircuitConfig, PreemptiveCircuitConfigBuilder,
    };
    pub fn expand_cache_dir(&self, path_resolver: &PathResolver) -> PathBuf {
        // Example implementation
        path_resolver.resolve(&self.cache_dir);
        pub fn expand_cache_dir(&self, path_resolver: &PathResolver) -> PathBuf {
        // Example implementation
        path_resolver.resolve(&self.cache_dir);
        pub fn expand_state_dir(&self, path_resolver: &PathResolver) -> PathBuf {
        // Example implementation
        path_resolver.resolve(&self.state_dir);
    }
}}}
    
/// Types for configuring how Tor accesses its directory information.
pub mod dir {
    pub use tor_dirmgr::{
        Authority, AuthorityBuilder, DirMgrConfig, DirTolerance, DirToleranceBuilder,
        DownloadSchedule, DownloadScheduleConfig, DownloadScheduleConfigBuilder, FallbackDir,
        FallbackDirBuilder, NetworkConfig, NetworkConfigBuilder,
    };
}

/// Types for configuring pluggable transports.
#[cfg(feature = "pt-client")]
pub mod pt {
    pub use tor_ptmgr::config::{TransportConfig, TransportConfigBuilder};
}

/// Types for configuring onion services.
#[cfg(feature = "onion-service-service")]
pub mod onion_service {
    pub use tor_hsservice::config::{OnionServiceConfig, OnionServiceConfigBuilder};
}

/// Types for configuring vanguards.
pub mod vanguards {
    pub use tor_guardmgr::{VanguardConfig, VanguardConfigBuilder};
}

/// Configuration for client behavior relating to addresses.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
pub struct ClientAddrConfig {
    #[builder(default)]
    pub(crate) allow_local_addrs: bool,
    #[cfg(feature = "onion-service-client")]
    #[builder(default = "true")]
    pub(crate) allow_onion_addrs: bool,
}
impl_standard_builder! { ClientAddrConfig }

/// Configuration for client behavior relating to stream connection timeouts
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct StreamTimeoutConfig {
    #[builder(default = "default_connect_timeout()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) connect_timeout: Duration,
    #[builder(default = "default_dns_resolve_timeout()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) resolve_timeout: Duration,
    #[builder(default = "default_dns_resolve_ptr_timeout()")]
    #[builder_field_attr(serde(default, with = "humantime_serde::option"))]
    pub(crate) resolve_ptr_timeout: Duration,
}
impl_standard_builder! { StreamTimeoutConfig }

fn default_connect_timeout() -> Duration {
    Duration::new(10, 0)
}

fn default_dns_resolve_timeout() -> Duration {
    Duration::new(10, 0)
}

fn default_dns_resolve_ptr_timeout() -> Duration {
    Duration::new(10, 0)
}

/// Configuration for where information should be stored on disk.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct StorageConfig {
    #[builder(setter(into), default = "default_cache_dir()")]
    cache_dir: CfgPath,
    #[builder(setter(into), default = "default_state_dir()")]
    state_dir: CfgPath,
    #[cfg(feature = "keymgr")]
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    keystore: ArtiKeystoreConfig,
    #[builder(sub_builder(fn_name = "build_for_arti"))]
    #[builder_field_attr(serde(default))]
    permissions: Mistrust,
}
impl_standard_builder! { StorageConfig }

fn default_cache_dir() -> CfgPath {
    CfgPath::new("${ARTI_CACHE}".to_owned())
}

fn default_state_dir() -> CfgPath {
    CfgPath::new("${ARTI_LOCAL_DATA}".to_owned())
}

/// Configuration for anti-censorship features: bridges and pluggable transports.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(validate = "validate_bridges_config", error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
#[builder_struct_attr(non_exhaustive)]
pub struct BridgesConfig {
    #[builder(default)]
    pub(crate) enabled: BoolOrAuto,
    #[builder(sub_builder, setter(custom))]
    #[builder_field_attr(serde(default))]
    bridges: BridgeList,
    #[builder(sub_builder, setter(custom))]
    #[builder_field_attr(serde(default))]
    #[cfg(feature = "pt-client")]
    pub(crate) transports: TransportConfigList,
}

type TransportConfigList = Vec<pt::TransportConfig>;

#[cfg(feature = "pt-client")]
define_list_builder_helper! {
    pub struct TransportConfigListBuilder {
        transports: [pt::TransportConfigBuilder],
    }
    built: TransportConfigList = transports;
    default = vec![];
}

#[cfg(feature = "pt-client")]
define_list_builder_accessors! {
    struct BridgesConfigBuilder {
        pub transports: [pt::TransportConfigBuilder],
    }
}

impl_standard_builder! { BridgesConfig }

#[cfg(feature = "pt-client")]
fn validate_pt_config(bridges: &BridgesConfigBuilder) -> Result<(), ConfigBuildError> {
    use std::collections::HashSet;
    use std::str::FromStr;

    let mut protocols_defined: HashSet<PtTransportName> = HashSet::new();
    if let Some(transportlist) = bridges.opt_transports() {
        for protocols in transportlist.iter() {
            for protocol in protocols.get_protocols() {
                protocols_defined.insert(protocol.clone());
            }
        }
    }

    for maybe_protocol in bridges
        .bridges
        .bridges
        .as_deref()
        .unwrap_or_default()
        .iter()
    {
        match maybe_protocol.get_transport() {
            Some(raw_protocol) => {
                let protocol = TransportId::from_str(raw_protocol)
                    .unwrap_or_default()
                    .into_pluggable();
                match protocol {
                    Some(protocol_required) => {
                        if protocols_defined.contains(&protocol_required) {
                            return Ok(());
                        }
                    }
                    None => return Ok(()),
                }
            }
            None => {
                return Ok(());
            }
        }
    }

    Err(ConfigBuildError::Inconsistent {
        fields: ["bridges.bridges", "bridges.transports"].map(Into::into).into_iter().collect(),
        problem: "Bridges configured, but all bridges unusable due to lack of corresponding pluggable transport in `[bridges.transports]`".into(),
    })
}

#[allow(clippy::unnecessary_wraps)]
fn validate_bridges_config(bridges: &BridgesConfigBuilder) -> Result<(), ConfigBuildError> {
    let _ = bridges;

    use BoolOrAuto as BoA;

    match (
        bridges.enabled.unwrap_or_default(),
        bridges.bridges.bridges.as_deref().unwrap_or_default(),
    ) {
        (BoA::Auto, _) | (BoA::Explicit(false), _) | (BoA::Explicit(true), [_, ..]) => {}
        (BoA::Explicit(true), []) => {
            return Err(ConfigBuildError::Inconsistent {
                fields: ["enabled", "bridges"].map(Into::into).into_iter().collect(),
                problem: "bridges.enabled=true, but no bridges defined".into(),
            })
        }
    }
    #[cfg(feature = "pt-client")]
    {
        if bridges_enabled(
            bridges.enabled.unwrap_or_default(),
            bridges.bridges.bridges.as_deref().unwrap_or_default(),
        ) {
            validate_pt_config(bridges)?;
        }
    }

    Ok(())
}

fn bridges_enabled(enabled: BoolOrAuto, bridges: &[impl Sized]) -> bool {
    #[cfg(feature = "bridge-client")]
    {
        enabled.as_bool().unwrap_or(!bridges.is_empty())
    }

    #[cfg(not(feature = "bridge-client"))]
    {
        let _ = (enabled, bridges);
        false
    }
}

impl BridgesConfig {
    fn bridges_enabled(&self) -> bool {
        bridges_enabled(self.enabled, &self.bridges)
    }
}

pub type BridgeList = Vec<BridgeConfig>;

define_list_builder_helper! {
    struct BridgeListBuilder {
        bridges: [BridgeConfigBuilder],
    }
    built: BridgeList = bridges;
    default = vec![];
    #[serde(try_from="MultilineListBuilder<BridgeConfigBuilder>")]
    #[serde(into="MultilineListBuilder<BridgeConfigBuilder>")]
}

convert_helper_via_multi_line_list_builder! {
    struct BridgeListBuilder {
        bridges: [BridgeConfigBuilder],
    }
}

#[cfg(feature = "bridge-client")]
define_list_builder_accessors! {
    struct BridgesConfigBuilder {
        pub bridges: [BridgeConfigBuilder],
    }
}

/// A configuration used to bootstrap a [`TorClient`](crate::TorClient).
#[derive(Clone, Builder, Debug, AsRef, educe::Educe)]
#[educe(PartialEq, Eq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Serialize, Deserialize, Debug))]
#[non_exhaustive]
pub struct TorClientConfig {
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    tor_network: dir::NetworkConfig,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) storage: StorageConfig,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    download_schedule: dir::DownloadScheduleConfig,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    directory_tolerance: dir::DirTolerance,

    #[builder(
        sub_builder,
        field(
            type = "HashMap<String, i32>",
            build = "default_extend(self.override_net_params.clone())"
        )
    )]
    #[builder_field_attr(serde(default))]
    pub(crate) override_net_params: tor_netdoc::doc::netstatus::NetParams<i32>,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) bridges: BridgesConfig,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) channel: ChannelConfig,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) system: SystemConfig,

    #[as_ref]
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    path_rules: circ::PathConfig,

    #[as_ref]
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    preemptive_circuits: circ::PreemptiveCircuitConfig,

    #[as_ref]
    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    circuit_timing: circ::CircuitTiming,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) address_filter: ClientAddrConfig,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) stream_timeouts: StreamTimeoutConfig,

    #[builder(sub_builder)]
    #[builder_field_attr(serde(default))]
    pub(crate) vanguards: vanguards::VanguardConfig,

    #[as_ref]
    #[builder(setter(skip))]
    #[builder_field_attr(serde(skip))]
    #[educe(PartialEq(ignore), Eq(ignore))]
    #[builder(default = "tor_config_path::arti_client_base_resolver()")]
    pub(crate) path_resolver: CfgPathResolver,
}
impl_standard_builder! { TorClientConfig }

impl tor_config::load::TopLevel for TorClientConfig {
    type Builder = TorClientConfigBuilder;
}

/// Helper to add overrides to a default collection.
fn default_extend<T: Default + Extend<X>, X>(to_add: impl IntoIterator<Item = X>) -> T {
    let mut collection = T::default();
    collection.extend(to_add);
    collection
}

/// Configuration for system resources used by Tor.
#[derive(Debug, Clone, Builder, Eq, PartialEq)]
#[builder(build_fn(error = "ConfigBuildError"))]
#[builder(derive(Debug, Serialize, Deserialize))]
#[non_exhaustive]
pub struct SystemConfig {
    #[builder(sub_builder(fn_name = "build"))]
    #[builder_field_attr(serde(default))]
    pub(crate) memory: tor_memquota::Config,
}
impl_standard_builder! { SystemConfig }

impl tor_circmgr::CircMgrConfig for TorClientConfig {
    #[cfg(all(
        feature = "vanguards",
        any(feature = "onion-service-client", feature = "onion-service-service")
    ))]
    fn vanguard_config(&self) -> &tor_guardmgr::VanguardConfig {
        &self.vanguards
    }
}
#[cfg(feature = "onion-service-client")]
impl tor_hsclient::HsClientConnectorConfig for TorClientConfig {}

#[cfg(any(feature = "onion-service-client", feature = "onion-service-service"))]
impl tor_circmgr::hspool::HsCircPoolConfig for TorClientConfig {
    #[cfg(all(
        feature = "vanguards",
        any(feature = "onion-service-client", feature = "onion-service-service")
    ))]
    fn vanguard_config(&self) -> &tor_guardmgr::VanguardConfig {
        &self.vanguards
    }
}

impl AsRef<tor_guardmgr::fallback::FallbackList> for TorClientConfig {
    fn as_ref(&self) -> &tor_guardmgr::fallback::FallbackList {
        self.tor_network.fallback_caches()
    }
}
impl AsRef<[BridgeConfig]> for TorClientConfig {
    fn as_ref(&self) -> &[BridgeConfig] {
        #[cfg(feature = "bridge-client")]
        {
            &self.bridges.bridges
        }

        #[cfg(not(feature = "bridge-client"))]
        {
            &[]
        }
    }
}
impl AsRef<BridgesConfig> for TorClientConfig {
    fn as_ref(&self) -> &BridgesConfig {
        &self.bridges
    }
}
impl tor_guardmgr::GuardMgrConfig for TorClientConfig {
    fn bridges_enabled(&self) -> bool {
        self.bridges.bridges_enabled()
    }
}

impl TorClientConfig {
    /// Try to create a DirMgrConfig corresponding to this object.
    #[rustfmt::skip]
    pub fn dir_mgr_config(&self) -> Result<dir::DirMgrConfig, ConfigBuildError> {
        Ok(dir::DirMgrConfig {
            network:             self.tor_network        .clone(),
            schedule:            self.download_schedule  .clone(),
            tolerance:           self.directory_tolerance.clone(),
            cache_dir:           self.storage.expand_cache_dir(&self.path_resolver)?,
            cache_trust:         self.storage.permissions.clone(),
            override_net_params: self.override_net_params.clone(),
            extensions:          Default::default(),
        })
    }

    /// Return a reference to the [`fs_mistrust::Mistrust`] object that we'll
    /// use to check permissions on files and directories by default.
    pub fn fs_mistrust(&self) -> &Mistrust {
        self.storage.permissions()
    }

    /// Return the keystore config
    pub fn keystore(&self) -> ArtiKeystoreConfig {
        self.storage.keystore()
    }

    /// Get the state directory and its corresponding
    /// [`Mistrust`] configuration.
    pub(crate) fn state_dir(&self) -> StdResult<(PathBuf, &fs_mistrust::Mistrust), ErrorDetail> {
        let state_dir = self
            .storage
            .expand_state_dir(&self.path_resolver)
            .map_err(ErrorDetail::Configuration)?;
        let mistrust = self.storage.permissions();

        Ok((state_dir, mistrust))
    }

    /// Access the `tor_memquota` configuration
    #[cfg(feature = "testing")]
    pub fn system_memory(&self) -> &tor_memquota::Config {
        &self.system.memory
    }
}

impl TorClientConfigBuilder {
    /// Returns a `TorClientConfigBuilder` using the specified state and cache directories.
    pub fn from_directories<P, Q>(state_dir: P, cache_dir: Q) -> Self
    where
        P: AsRef<Path>,
        Q: AsRef<Path>,
    {
        let mut builder = Self::default();

        builder
            .storage()
            .cache_dir(CfgPath::new_literal(cache_dir.as_ref()))
            .state_dir(CfgPath::new_literal(state_dir.as_ref()));

        builder
    }
}

/// Return the filenames for the default user configuration files
pub fn default_config_files() -> Result<Vec<ConfigurationSource>, CfgPathError> {
    let path_resolver = tor_config_path::arti_client_base_resolver();

    ["${ARTI_CONFIG}/arti.toml", "${ARTI_CONFIG}/arti.d/"]
        .into_iter()
        .map(|f| {
            let path = CfgPath::new(f.into()).path(&path_resolver)?;
            Ok(ConfigurationSource::from_path(path))
        })
        .collect()
}

/// The environment variable we look at when deciding whether to disable FS permissions checking.
#[deprecated = "use tor-config::mistrust::ARTI_FS_DISABLE_PERMISSION_CHECKS instead"]
pub const FS_PERMISSIONS_CHECKS_DISABLE_VAR: &str = "ARTI_FS_DISABLE_PERMISSION_CHECKS";

/// Return true if the environment has been set up to disable FS permissions
/// checking.
#[deprecated(since = "0.5.0")]
#[allow(deprecated)]
pub fn fs_permissions_checks_disabled_via_env() -> bool {
    std::env::var_os(FS_PERMISSIONS_CHECKS_DISABLE_VAR).is_some()
}

#[cfg(test)]
mod test {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::mixed_attributes_style)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;

    #[test]
    fn defaults() {
        let dflt = TorClientConfig::default();
        let b2 = TorClientConfigBuilder::default();
        let dflt2 = b2.build().unwrap();
        assert_eq!(&dflt, &dflt2);
    }

    #[test]
    fn builder() {
        let sec = std::time::Duration::from_secs(1);

        let auth = dir::Authority::builder()
            .name("Fred")
            .v3ident([22; 20].into())
            .clone();
        let mut fallback = dir::FallbackDir::builder();
        fallback
            .rsa_identity([23; 20].into())
            .ed_identity([99; 32].into())
            .orports()
            .push("127.0.0.7:7".parse().unwrap());

        let mut bld = TorClientConfig::builder();
        bld.tor_network().set_authorities(vec![auth]);
        bld.tor_network().set_fallback_caches(vec![fallback]);
        bld.storage()
            .cache_dir(CfgPath::new("/var/tmp/foo".to_owned()))
            .state_dir(CfgPath::new("/var/tmp/bar".to_owned()));
        bld.download_schedule().retry_certs().attempts(10);
        bld.download_schedule().retry_certs().initial_delay(sec);
        bld.download_schedule().retry_certs().parallelism(3);
        bld.download_schedule().retry_microdescs().attempts(30);
        bld.download_schedule()
            .retry_microdescs()
            .initial_delay(10 * sec);
        bld.download_schedule().retry_microdescs().parallelism(9);
        bld.override_net_params()
            .insert("wombats-per-quokka".to_owned(), 7);
        bld.path_rules()
            .ipv4_subnet_family_prefix(20)
            .ipv6_subnet_family_prefix(48);
        bld.circuit_timing()
            .max_dirtiness(90 * sec)
            .request_timeout(10 * sec)
            .request_max_retries(22)
            .request_loyalty(3600 * sec);
        bld.address_filter().allow_local_addrs(true);

        let val = bld.build().unwrap();

        assert_ne!(val, TorClientConfig::default());
    }

    #[test]
    fn bridges_supported() {
        /// checks that when s is processed as TOML for a client config,
        /// the resulting number of bridges is according to `exp`
        fn chk(exp: Result<usize, ()>, s: &str) {
            eprintln!("----------\n{s}\n----------\n");
            let got = (|| {
                let cfg: toml::Value = toml::from_str(s).unwrap();
                let cfg: TorClientConfigBuilder = cfg.try_into()?;
                let cfg = cfg.build()?;
                let n_bridges = cfg.bridges.bridges.len();
                Ok::<_, anyhow::Error>(n_bridges) // anyhow is just something we can use for ?
            })()
            .map_err(|_| ());
            assert_eq!(got, exp);
        }

        let chk_enabled_or_auto = |exp, bridges_toml| {
            for enabled in [r#""#, r#"enabled = true"#, r#"enabled = "auto""#] {
                chk(exp, &format!("[bridges]\n{}\n{}", enabled, bridges_toml));
            }
        };

        let ok_1_if = |b: bool| b.then_some(1).ok_or(());

        chk(
            Err(()),
            r#"
                [bridges]
                enabled = true
            "#,
        );

        chk_enabled_or_auto(
            ok_1_if(cfg!(feature = "bridge-client")),
            r#"
                bridges = ["192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956"]
            "#,
        );

        chk_enabled_or_auto(
            ok_1_if(cfg!(feature = "pt-client")),
            r#"
                bridges = ["obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1"]
                [[bridges.transports]]
                protocols = ["obfs4"]
                path = "obfs4proxy"
            "#,
        );
    }

    #[test]
    fn check_default() {
        // We don't want to second-guess the directories crate too much
        // here, so we'll just make sure it does _something_ plausible.

        let dflt = default_config_files().unwrap();
        assert!(dflt[0].as_path().unwrap().ends_with("arti.toml"));
        assert!(dflt[1].as_path().unwrap().ends_with("arti.d"));
        assert_eq!(dflt.len(), 2);
    }

    #[test]
    #[cfg(feature = "pt-client")]
    fn check_bridge_pt() {
        let from_toml = |s: &str| -> TorClientConfigBuilder {
            let cfg: toml::Value = toml::from_str(dbg!(s)).unwrap();
            let cfg: TorClientConfigBuilder = cfg.try_into().unwrap();
            cfg
        };

        let chk = |cfg: &TorClientConfigBuilder, expected: Result<(), &str>| match (
            cfg.build(),
            expected,
        ) {
            (Ok(_), Ok(())) => {}
            (Err(e), Err(ex)) => {
                if !e.to_string().contains(ex) {
                    panic!("\"{e}\" did not contain {ex}");
                }
            }
            (Ok(_), Err(ex)) => {
                panic!("Expected {ex} but cfg succeeded");
            }
            (Err(e), Ok(())) => {
                panic!("Expected success but got error {e}")
            }
        };

        let test_cases = [
            ("# No bridges", Ok(())),
            (
                r#"
                    # No bridges but we still enabled bridges
                    [bridges]
                    enabled = true
                    bridges = []
                "#,
                Err("bridges.enabled=true, but no bridges defined"),
            ),
            (
                r#"
                    # One non-PT bridge
                    [bridges]
                    enabled = true
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                    ]
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 bridge
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfs4proxy"
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 bridge with unmanaged transport.
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    proxy_addr = "127.0.0.1:31337"
                "#,
                Ok(()),
            ),
            (
                r#"
                    # Transport is both managed and unmanaged.
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfsproxy"
                    proxy_addr = "127.0.0.1:9999"
                "#,
                Err("Cannot provide both path and proxy_addr"),
            ),
            (
                r#"
                    # One obfs4 bridge and non-PT bridge
                    [bridges]
                    enabled = false
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                    [[bridges.transports]]
                    protocols = ["obfs4"]
                    path = "obfs4proxy"
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 and non-PT bridge with no transport
                    [bridges]
                    enabled = true
                    bridges = [
                        "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
                Ok(()),
            ),
            (
                r#"
                    # One obfs4 bridge with no transport
                    [bridges]
                    enabled = true
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
                Err("all bridges unusable due to lack of corresponding pluggable transport"),
            ),
            (
                r#"
                    # One obfs4 bridge with no transport but bridges are disabled
                    [bridges]
                    enabled = false
                    bridges = [
                        "obfs4 bridge.example.net:80 $0bac39417268b69b9f514e7f63fa6fba1a788958 ed25519:dGhpcyBpcyBbpmNyZWRpYmx5IHNpbGx5ISEhISEhISA iat-mode=1",
                    ]
                "#,
                Ok(()),
            ),
            (
                r#"
                        # One non-PT bridge with a redundant transports section
                        [bridges]
                        enabled = false
                        bridges = [
                            "192.0.2.83:80 $0bac39417268b96b9f514ef763fa6fba1a788956",
                        ]
                        [[bridges.transports]]
                        protocols = ["obfs4"]
                        path = "obfs4proxy"
                "#,
                Ok(()),
            ),
        ];

        for (test_case, expected) in test_cases.iter() {
            chk(&from_toml(test_case), *expected);
        }
    }
}

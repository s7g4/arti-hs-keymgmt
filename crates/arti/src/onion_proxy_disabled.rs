//! Configuration logic for when onion service support is disabled.

use serde::{Deserialize, Serialize};
use tor_hsservice::OnionService as RawOnionService;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct OnionService(RawOnionService);
use tor_config::ConfigBuildError;
use std::collections::HashMap;
use std::iter::IntoIterator;

/// Dummy type for onion service configuration when no onion services are
/// configured.
///
/// This type exists so that we can have a builder for it that will
/// give an error when no onion services are configured.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct OnionServiceProxyConfigMap {
    services: HashMap<String, OnionService>,
}

/// A builder for onion service configuration, when no onion services are
/// configured.
///
/// Its only role is to detect whether options are provided, and reject the
/// configuration if so.
//
// TODO: If this is the right pattern, we should make it more general.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(transparent)]
pub(crate) struct OnionServiceProxyConfigMapBuilder(Option<toml::Value>);

impl OnionServiceProxyConfigMapBuilder {
    /// Attempt to "build" a dummy OnionServiceProxyConfigMap.
    pub(crate) fn build(&self) -> Result<OnionServiceProxyConfigMap, ConfigBuildError> {
        if self.0.is_some() {
            Err(ConfigBuildError::NoCompileTimeSupport {
                // This is within the context of the `onion_services` field, so
                // we just say "*" here.
                field: "*".to_string(),
                problem: "no support for running onion services; hint: recompile arti with onion-service-service".to_string(),
            })
        } else {
            Ok(OnionServiceProxyConfigMap {
                services: HashMap::new(),
            })
        }
    }
}

impl IntoIterator for OnionServiceProxyConfigMap {
    type Item = (String, OnionService);
    type IntoIter = std::collections::hash_map::IntoIter<String, OnionService>;

    fn into_iter(self) -> Self::IntoIter {
        self.services.into_iter()
    }
}

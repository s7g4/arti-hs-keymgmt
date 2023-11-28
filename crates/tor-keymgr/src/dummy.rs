#![allow(clippy::unnecessary_wraps, clippy::extra_unused_type_parameters)]

//! A dummy key manager implementation.
//!
//! This key manager implementation is only used when the `keymgr` feature is disabled.
//!
//! The implementations from this module ignore their arguments. The unused arguments can't be
//! removed, because the dummy implementations must have the same API as their fully-featured
//! counterparts.

use crate::{BoxedKeystore, KeystoreError, KeystoreSelector, Result};
use tor_error::HasKind;

use fs_mistrust::Mistrust;
use std::any::Any;
use std::path::Path;

/// A dummy key manager implementation.
///
/// This implementation has the same API as the key manager exposed when the `keymgr` feature is
/// enabled, except all its read operations return `None` and all its write operations will fail.
///
/// For operations that normally involve updating the state of the key manager and/or its
/// underlying storage, such as `insert` or `remove`, this `KeyMgr` always returns an error.
#[derive(derive_builder::Builder)]
#[builder(pattern = "owned")]
#[non_exhaustive]
pub struct KeyMgr {
    /// The default key store.
    default_store: BoxedKeystore,
    /// The secondary key stores.
    #[builder(default, setter(custom))]
    secondary_stores: Vec<BoxedKeystore>,
}

// TODO: auto-generate using define_list_builder_accessors/define_list_builder_helper
// when that becomes possible.
//
// See https://gitlab.torproject.org/tpo/core/arti/-/merge_requests/1760#note_2969841
impl KeyMgrBuilder {
    /// Access the being-built list of secondary stores (resolving default)
    ///
    /// If the field has not yet been set or accessed, the default list will be
    /// constructed and a mutable reference to the now-defaulted list of builders
    /// will be returned.
    pub fn secondary_stores(&mut self) -> &mut Vec<BoxedKeystore> {
        self.secondary_stores.get_or_insert(Default::default())
    }

    /// Set the whole list (overriding the default)
    pub fn set_secondary_stores(mut self, list: Vec<BoxedKeystore>) -> Self {
        self.secondary_stores = Some(list);
        self
    }

    /// Inspect the being-built list (with default unresolved)
    ///
    /// If the list has not yet been set, or accessed, `&None` is returned.
    pub fn opt_secondary_stores(&self) -> &Option<Vec<BoxedKeystore>> {
        &self.secondary_stores
    }

    /// Mutably access the being-built list (with default unresolved)
    ///
    /// If the list has not yet been set, or accessed, `&mut None` is returned.
    pub fn opt_secondary_stores_mut(&mut self) -> &mut Option<Vec<BoxedKeystore>> {
        &mut self.secondary_stores
    }
}

/// A dummy key store trait.
pub trait Keystore: Send + Sync + 'static {
    // TODO(gabi): Add the missing functions and impls
}

/// A dummy `ArtiNativeKeystore`.
#[non_exhaustive]
pub struct ArtiNativeKeystore;

/// A dummy `KeyType`.
#[non_exhaustive]
pub struct KeyType;

impl KeyType {
    /// The file extension for a key of this type.
    //
    // TODO HSS: maybe this function should return an error instead
    pub fn arti_extension(&self) -> &'static str {
        "dummy_extension"
    }
}

/// A dummy `Error` indicating that key manager support is disabled in cargo features.
#[non_exhaustive]
#[derive(Debug, Clone, thiserror::Error)]
#[error("Key manager support disabled in cargo features")]
struct Error;

impl KeystoreError for Error {}

impl HasKind for Error {
    fn kind(&self) -> tor_error::ErrorKind {
        tor_error::ErrorKind::Other
    }
}

impl ArtiNativeKeystore {
    /// Create a new [`ArtiNativeKeystore`].
    #[allow(clippy::unnecessary_wraps)]
    pub fn from_path_and_mistrust(_: impl AsRef<Path>, _: &Mistrust) -> Result<Self> {
        Ok(Self)
    }
}

impl Keystore for ArtiNativeKeystore {}

impl KeyMgr {
    /// A dummy `get` implementation that always behaves like the requested key is not found.
    ///
    /// This function always returns `Ok(None)`.
    pub fn get<K>(&self, _: &dyn Any) -> Result<Option<K>> {
        Ok(None)
    }

    /// A dummy `insert` implementation that always fails.
    ///
    /// This function always returns an error.
    pub fn insert<K>(&self, _: K, _: &dyn Any, _: KeystoreSelector) -> Result<()> {
        Err(Box::new(Error))
    }

    /// A dummy `remove` implementation that always fails.
    ///
    /// This function always returns an error.
    pub fn remove<K>(&self, _: &dyn Any) -> Result<Option<()>> {
        Err(Box::new(Error))
    }
}

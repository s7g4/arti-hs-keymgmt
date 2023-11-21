//! An error type for [`ArtiNativeKeystore`](crate::ArtiNativeKeystore).

use crate::key_type::ssh::SshKeyAlgorithm;
use crate::{ArtiPathError, KeyType, KeystoreError, UnknownKeyTypeError};
use tor_error::{ErrorKind, HasKind};

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

/// An error returned by [`ArtiNativeKeystore`](crate::ArtiNativeKeystore)'s
/// [`Keystore`](crate::Keystore) implementation.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum ArtiNativeKeystoreError {
    /// An error that occurred while accessing the filesystem.
    #[error("IO error on {path} while attempting to {action}")]
    Filesystem {
        /// The action we were trying to perform.
        action: FilesystemAction,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<io::Error>,
    },

    /// Encountered an invalid path or invalid permissions.
    #[error("Invalid path or permissions on {path} while attempting to {action}")]
    FsMistrust {
        /// The action we were trying to perform.
        action: FilesystemAction,
        /// The path of the key we were trying to fetch.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: Arc<fs_mistrust::Error>,
    },

    /// Found a key with an invalid path.
    #[error("Key has invalid path: {path}")]
    MalformedPath {
        /// The path of the key.
        path: PathBuf,
        /// The underlying error.
        #[source]
        err: MalformedPathError,
    },

    /// An error due to encountering an unsupported [`KeyType`].
    #[error("{0}")]
    UnknownKeyType(#[from] UnknownKeyTypeError),

    /// Failed to parse an OpenSSH key
    #[error("Failed to parse OpenSSH with type {key_type:?}")]
    SshKeyParse {
        /// The path of the malformed key.
        path: PathBuf,
        /// The type of key we were trying to fetch.
        key_type: KeyType,
        /// The underlying error.
        #[source]
        err: Arc<ssh_key::Error>,
    },

    /// Found an OpenSSH key that contains invalid key data,
    #[error("Invalid SSH key data: {0}")]
    InvalidSshKeyData(String),

    /// The OpenSSH key we retrieved is of the wrong type.
    #[error("Unexpected OpenSSH key type: wanted {wanted_key_algo}, found {found_key_algo}")]
    UnexpectedSshKeyType {
        /// The path of the malformed key.
        path: PathBuf,
        /// The algorithm we expected the key to use.
        wanted_key_algo: SshKeyAlgorithm,
        /// The algorithm of the key we got.
        found_key_algo: SshKeyAlgorithm,
    },

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// The action that caused an [`ArtiNativeKeystoreError::Filesystem`] or
/// [`ArtiNativeKeystoreError::FsMistrust`] error.
#[derive(Copy, Clone, Debug, derive_more::Display)]
pub(crate) enum FilesystemAction {
    /// Filesystem key store initialization.
    Init,
    /// Filesystem read
    Read,
    /// Filesystem write
    Write,
    /// Filesystem remove
    Remove,
}

/// An error caused by an invalid key path.
#[derive(thiserror::Error, Debug, Clone)]
pub(crate) enum MalformedPathError {
    /// Found a key with a non-UTF-8 path.
    #[error("the path is not valid UTF-8")]
    Utf8,

    /// Found a key with no extension.
    #[error("no extension")]
    NoExtension,

    /// The file path is not a valid [`ArtiPath`](crate::ArtiPath).
    #[error("not a valid ArtiPath")]
    InvalidArtiPath(ArtiPathError),
}

impl KeystoreError for ArtiNativeKeystoreError {}

impl HasKind for ArtiNativeKeystoreError {
    fn kind(&self) -> ErrorKind {
        use ArtiNativeKeystoreError as KE;

        match self {
            KE::Filesystem { .. } => ErrorKind::KeystoreAccessFailed,
            KE::FsMistrust { .. } => ErrorKind::FsPermissions,
            KE::MalformedPath { .. } => ErrorKind::KeystoreAccessFailed,
            KE::UnknownKeyType(_) => ErrorKind::KeystoreAccessFailed,
            KE::SshKeyParse { .. } | KE::UnexpectedSshKeyType { .. } => {
                ErrorKind::KeystoreCorrupted
            }
            KE::InvalidSshKeyData(_) => ErrorKind::KeystoreCorrupted,
            KE::Bug(e) => e.kind(),
        }
    }
}

impl From<ArtiNativeKeystoreError> for crate::Error {
    fn from(e: ArtiNativeKeystoreError) -> Self {
        crate::Error::Keystore(Arc::new(e))
    }
}

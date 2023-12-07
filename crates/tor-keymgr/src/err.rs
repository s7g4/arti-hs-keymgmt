//! An error type for the `tor-keymgr` crate.

use tor_error::HasKind;

use dyn_clone::DynClone;

use std::error::Error as StdError;
use std::fmt;
use std::sync::Arc;

use crate::KeyPathError;

/// An Error type for this crate.
#[derive(thiserror::Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Detected keustore corruption.
    #[error("{0}")]
    Corruption(#[from] KeystoreCorruptionError),

    /// An opaque error returned by a [`Keystore`](crate::Keystore).
    #[error("{0}")]
    Keystore(#[from] Arc<dyn KeystoreError>),

    /// An internal error.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

/// An error returned by a [`Keystore`](crate::Keystore).
pub trait KeystoreError:
    HasKind + StdError + DynClone + fmt::Debug + fmt::Display + Send + Sync + 'static
{
}

impl HasKind for Error {
    fn kind(&self) -> tor_error::ErrorKind {
        use tor_error::ErrorKind as EK;
        use Error as E;

        match self {
            E::Keystore(e) => e.kind(),
            E::Corruption(_) => EK::KeystoreCorrupted,
            E::Bug(e) => e.kind(),
        }
    }
}

/// An error caused by a syntactically invalid [`ArtiPath`](crate::ArtiPath).
///
/// The `ArtiPath` is not in the legal syntax: it contains bad characters,
/// or a syntactically invalid components.
///
/// (Does not include any errors arising from paths which are invalid
/// *for the particular key*.)
#[derive(thiserror::Error, Debug, Clone)]
#[error("Invalid ArtiPath")]
#[non_exhaustive]
pub enum ArtiPathError {
    /// Found an empty path component.
    #[error("Empty path component")]
    EmptyPathComponent,

    /// The path contains a disallowed char.
    #[error("Found disallowed char {0}")]
    DisallowedChar(char),

    /// The path contains the `..` pattern.
    #[error("Found `..` pattern")]
    PathTraversal,

    /// The path starts with a disallowed char.
    #[error("Path starts or ends with disallowed char {0}")]
    BadOuterChar(char),
}

/// An error caused by keystore corruption.
#[derive(thiserror::Error, Debug, Clone)]
#[error("Keystore corruption")]
#[non_exhaustive]
pub enum KeystoreCorruptionError {
    /// A keystore contains a key that has an invalid [`KeyPath`](crate::KeyPath).
    #[error("{0}")]
    KeyPath(#[from] KeyPathError),
}

#[cfg(test)]
mod tests {
    // @@ begin test lint list maintained by maint/add_warning @@
    #![allow(clippy::bool_assert_comparison)]
    #![allow(clippy::clone_on_copy)]
    #![allow(clippy::dbg_macro)]
    #![allow(clippy::print_stderr)]
    #![allow(clippy::print_stdout)]
    #![allow(clippy::single_char_pattern)]
    #![allow(clippy::unwrap_used)]
    #![allow(clippy::unchecked_duration_subtraction)]
    #![allow(clippy::useless_vec)]
    #![allow(clippy::needless_pass_by_value)]
    //! <!-- @@ end test lint list maintained by maint/add_warning @@ -->
    use super::*;
    use tor_error::ErrorKind;

    #[derive(Debug, Copy, Clone, PartialEq, thiserror::Error)]
    #[error("The source of a test error")]
    struct TestErrorSource;

    #[derive(Debug, Clone, thiserror::Error)]
    #[error("A test error")]
    struct TestError(#[from] TestErrorSource);

    impl KeystoreError for TestError {}

    impl HasKind for TestError {
        fn kind(&self) -> ErrorKind {
            ErrorKind::Other
        }
    }

    #[test]
    fn error_source() {
        let e: Error = (Arc::new(TestError(TestErrorSource)) as Arc<dyn KeystoreError>).into();

        assert_eq!(
            e.source().unwrap().to_string(),
            TestError(TestErrorSource).to_string()
        );
    }
}

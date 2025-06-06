//! Test helpers.

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

use std::fmt::Debug;

use crate::{ArtiPath, KeyPath, KeySpecifier};

/// Check that `spec` produces the [`ArtiPath`] from `path`, and that `path` parses to `spec`
///
/// # Panics
///
/// Panics if `path` isn't valid as an `ArtiPath` or any of the checks fail.
pub fn check_key_specifier<S, E>(spec: &S, path: &str)
where
    S: KeySpecifier + Debug + PartialEq,
    S: for<'p> TryFrom<&'p KeyPath, Error = E>,
    E: Debug,
{
    let apath = ArtiPath::new(path.to_string()).unwrap();
    assert_eq!(spec.arti_path().unwrap(), apath);
    assert_eq!(&S::try_from(&KeyPath::Arti(apath)).unwrap(), spec, "{path}");
}

/// OpenSSH keys used for testing.
#[cfg(test)]
pub(crate) mod ssh_keys {
    /// Helper macro for defining test key constants.
    ///
    /// Defines constants for the public and private key files
    /// specified in the `PUB` and `PRIV` lists, respectively.
    ///
    /// The entries from the `PUB` and `PRIV` lists must specify the documentation of the constant,
    /// and the basename of the file to include (`include_str`) from "../testdata".
    /// The path of each key file is built like so:
    ///
    ///   * `PUB` keys: `../testdata/<BASENAME>.public`
    ///   * `PRIV` keys: `../testdata/<BASENAME>.private`
    ///
    /// The names of the constants are derived from the basename:
    ///   * for `PUB` entries, the name is the uppercased basename, followed by `_PUB`
    ///   * for `PRIV` entries, the name is the uppercased basename
    macro_rules! define_key_consts {
        (
            PUB => { $($(#[ $docs_and_attrs:meta ])* $basename:literal,)* },
            PRIV => { $($(#[ $docs_and_attrs_priv:meta ])* $basename_priv:literal,)* }
        ) => {
            $(
                paste::paste! {
                    define_key_consts!(
                        @ $(#[ $docs_and_attrs ])*
                        [< $basename:upper _PUB >], $basename, ".public"
                    );
                }
            )*

            $(
                paste::paste! {
                    define_key_consts!(
                        @ $(#[ $docs_and_attrs_priv ])*
                        [< $basename_priv:upper >], $basename_priv, ".private"
                    );
                }
            )*
        };

        (
            @ $($(#[ $docs_and_attrs:meta ])*
            $const_name:ident, $basename:literal, $extension:literal)*
        ) => {
            $(
                $(#[ $docs_and_attrs ])*
                pub(crate) const $const_name: &str =
                    include_str!(concat!("../testdata/", $basename, $extension));
            )*
        }
    }

    define_key_consts! {
        // Public key constants
        PUB => {
            /// An Ed25519 public key.
            "ed25519_openssh",
            /// An Ed25519 public key that fails to parse.
            "ed25519_openssh_bad",
            /// A public key using the ed25519-expanded@spec.torproject.org algorithm.
            ///
            /// Not valid because Ed25519 public keys can't be "expanded".
            "ed25519_expanded_openssh",
            /// A X25519 public key.
            "x25519_openssh",
            /// An invalid public key using the armadillo@torproject.org algorithm.
            "x25519_openssh_unknown_algorithm",
        },
        // Keypair constants
        PRIV => {
            /// An Ed25519 keypair.
            "ed25519_openssh",
            /// An Ed25519 keypair that fails to parse.
            "ed25519_openssh_bad",
            /// An expanded Ed25519 keypair.
            "ed25519_expanded_openssh",
            /// An expanded Ed25519 keypair that fails to parse.
            "ed25519_expanded_openssh_bad",
            /// A DSA keypair.
            "dsa_openssh",
            /// A X25519 keypair.
            "x25519_openssh",
            /// An invalid keypair using the pangolin@torproject.org algorithm.
            "x25519_openssh_unknown_algorithm",
        }
    }
}

/// A module exporting a key specifier used for testing.
#[cfg(test)]
mod specifier {
    use crate::{
        ArtiPath, ArtiPathUnavailableError, CTorPath, KeyCertificateSpecifier, KeySpecifier,
        KeySpecifierComponent,
    };

    /// A key specifier path.
    pub(crate) const TEST_SPECIFIER_PATH: &str = "parent1/parent2/parent3/test-specifier";

    /// A [`KeySpecifier`] with a fixed [`ArtiPath`] prefix and custom suffix.
    ///
    /// The inner String is the suffix of its `ArtiPath`.
    #[derive(Default)]
    pub(crate) struct TestSpecifier(String);

    impl TestSpecifier {
        /// Create a new [`TestSpecifier`].
        pub(crate) fn new(prefix: impl AsRef<str>) -> Self {
            Self(prefix.as_ref().into())
        }

        /// Return the prefix of the [`ArtiPath`] of this specifier.
        pub(crate) fn path_prefix() -> &'static str {
            TEST_SPECIFIER_PATH
        }
    }

    impl KeySpecifier for TestSpecifier {
        fn arti_path(&self) -> Result<ArtiPath, ArtiPathUnavailableError> {
            Ok(ArtiPath::new(format!("{TEST_SPECIFIER_PATH}{}", self.0))
                .map_err(|e| tor_error::internal!("{e}"))?)
        }

        fn ctor_path(&self) -> Option<CTorPath> {
            None
        }

        fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>> {
            None
        }
    }

    /// A test client key specifiier
    #[derive(Debug, Clone)]
    pub(crate) struct TestCTorSpecifier(pub(crate) CTorPath);

    impl KeySpecifier for TestCTorSpecifier {
        fn arti_path(&self) -> Result<ArtiPath, ArtiPathUnavailableError> {
            unimplemented!()
        }

        fn ctor_path(&self) -> Option<CTorPath> {
            Some(self.0.clone())
        }

        fn keypair_specifier(&self) -> Option<Box<dyn KeySpecifier>> {
            unimplemented!()
        }
    }

    /// A test certificate specifier.
    pub(crate) struct TestCertSpecifier<SUBJ: KeySpecifier, SIGN: KeySpecifier> {
        /// The key specifier of the subject key.
        pub(crate) subject_key_spec: SUBJ,
        /// The key specifier of the signing key.
        pub(crate) signing_key_spec: SIGN,
        /// A list of denotators for distinguishing certs of this type.
        pub(crate) denotator: Vec<String>,
    }

    impl<SUBJ: KeySpecifier, SIGN: KeySpecifier> KeyCertificateSpecifier
        for TestCertSpecifier<SUBJ, SIGN>
    {
        fn cert_denotators(&self) -> Vec<&dyn KeySpecifierComponent> {
            self.denotator
                .iter()
                .map(|s| s as &dyn KeySpecifierComponent)
                .collect()
        }

        fn signing_key_specifier(&self) -> Option<&dyn KeySpecifier> {
            Some(&self.signing_key_spec)
        }

        /// The key specifier of the subject key.
        fn subject_key_specifier(&self) -> &dyn KeySpecifier {
            &self.subject_key_spec
        }
    }
}

/// A module exporting key implementations used for testing.
#[cfg(test)]
mod key {
    use crate::EncodableItem;
    use tor_key_forge::{ItemType, KeystoreItem, KeystoreItemType};

    /// A dummy key.
    ///
    /// Used as an argument placeholder for calling functions that require an [`EncodableItem`].
    ///
    /// Panics if its `EncodableItem` implementation is called.
    pub(crate) struct DummyKey;

    impl ItemType for DummyKey {
        fn item_type() -> KeystoreItemType
        where
            Self: Sized,
        {
            todo!()
        }
    }

    impl EncodableItem for DummyKey {
        fn as_keystore_item(&self) -> tor_key_forge::Result<KeystoreItem> {
            todo!()
        }
    }
}

#[cfg(test)]
pub(crate) use specifier::*;

#[cfg(test)]
pub(crate) use internal::assert_found;

/// Private module for reexporting test helper macros macro.
#[cfg(test)]
mod internal {
    /// Assert that the specified key can be found (or not) in `key_store`.
    macro_rules! assert_found {
        ($key_store:expr, $key_spec:expr, $key_type:expr, $found:expr) => {{
            let res = $key_store
                .get($key_spec, &$key_type.clone().into())
                .unwrap();
            if $found {
                assert!(res.is_some());
                // Ensure contains() agrees with get()
                assert!($key_store
                    .contains($key_spec, &$key_type.clone().into())
                    .unwrap());
            } else {
                assert!(res.is_none());
            }
        }};
    }

    pub(crate) use assert_found;
}

//! The Arti key store.
//!
//! See the [`ArtiNativeKeystore`] docs for more details.

pub(crate) mod certs;
pub(crate) mod err;
pub(crate) mod ssh;

use std::io::{self, ErrorKind};
use std::path::Path;
use std::result::Result as StdResult;
use std::str::FromStr;

use crate::keystore::fs_utils::{checked_op, FilesystemAction, FilesystemError, RelKeyPath};
use crate::keystore::{EncodableItem, ErasedKey, KeySpecifier, Keystore};
use crate::{
    arti_path, ArtiPath, ArtiPathUnavailableError, KeyPath, KeystoreId, Result, UnknownKeyTypeError,
};
use certs::UnparsedCert;
use err::ArtiNativeKeystoreError;
use ssh::UnparsedOpenSshKey;

use fs_mistrust::{CheckedDir, Mistrust};
use itertools::Itertools;
use tor_error::internal;
use walkdir::WalkDir;

use tor_basic_utils::PathExt as _;
use tor_key_forge::{CertData, KeystoreItem, KeystoreItemType};

/// The Arti key store.
///
/// This is a disk-based key store that encodes keys in OpenSSH format.
///
/// Some of the key types supported by the [`ArtiNativeKeystore`]
/// don't have a predefined SSH public key [algorithm name],
/// so we define several custom SSH algorithm names.
/// As per [RFC4251 § 6], our custom SSH algorithm names use the
/// `<something@subdomain.torproject.org>` format.
///
/// We have assigned the following custom algorithm names:
///   * `x25519@spec.torproject.org`, for x25519 keys
///   * `ed25519-expanded@spec.torproject.org`, for expanded ed25519 keys
///
/// See [SSH protocol extensions] for more details.
///
/// [algorithm name]: https://www.iana.org/assignments/ssh-parameters/ssh-parameters.xhtml#ssh-parameters-19
/// [RFC4251 § 6]: https://www.rfc-editor.org/rfc/rfc4251.html#section-6
/// [SSH protocol extensions]: https://spec.torproject.org/ssh-protocols.html
#[derive(Debug)]
pub struct ArtiNativeKeystore {
    /// The root of the key store.
    ///
    /// All the keys are stored within this directory.
    keystore_dir: CheckedDir,
    /// The unique identifier of this instance.
    id: KeystoreId,
}

impl ArtiNativeKeystore {
    /// Create a new [`ArtiNativeKeystore`] rooted at the specified `keystore_dir` directory.
    ///
    /// The `keystore_dir` directory is created if it doesn't exist.
    ///
    /// This function returns an error if `keystore_dir` is not a directory, if it does not conform
    /// to the requirements of the specified `Mistrust`, or if there was a problem creating the
    /// directory.
    pub fn from_path_and_mistrust(
        keystore_dir: impl AsRef<Path>,
        mistrust: &Mistrust,
    ) -> Result<Self> {
        let keystore_dir = mistrust
            .verifier()
            .check_content()
            .make_secure_dir(&keystore_dir)
            .map_err(|e| FilesystemError::FsMistrust {
                action: FilesystemAction::Init,
                path: keystore_dir.as_ref().into(),
                err: e.into(),
            })
            .map_err(ArtiNativeKeystoreError::Filesystem)?;

        // TODO: load the keystore ID from config.
        let id = KeystoreId::from_str("arti")?;
        Ok(Self { keystore_dir, id })
    }

    /// The path on disk of the key with the specified identity and type, relative to
    /// `keystore_dir`.
    fn rel_path(
        &self,
        key_spec: &dyn KeySpecifier,
        item_type: &KeystoreItemType,
    ) -> StdResult<RelKeyPath, ArtiPathUnavailableError> {
        RelKeyPath::arti(&self.keystore_dir, key_spec, item_type)
    }
}

/// Extract the key path (relative to the keystore root) from the specified result `res`,
/// or return an error.
///
/// If the underlying error is `ArtiPathUnavailable` (i.e. the `KeySpecifier` cannot provide
/// an `ArtiPath`), return `ret`.
macro_rules! rel_path_if_supported {
    ($res:expr, $ret:expr) => {{
        use ArtiPathUnavailableError::*;

        match $res {
            Ok(path) => path,
            Err(ArtiPathUnavailable) => return $ret,
            Err(e) => return Err(tor_error::internal!("invalid ArtiPath: {e}").into()),
        }
    }};
}

impl Keystore for ArtiNativeKeystore {
    fn id(&self) -> &KeystoreId {
        &self.id
    }

    fn contains(&self, key_spec: &dyn KeySpecifier, item_type: &KeystoreItemType) -> Result<bool> {
        let path = rel_path_if_supported!(self.rel_path(key_spec, item_type), Ok(false));

        let meta = match checked_op!(metadata, path) {
            Ok(meta) => meta,
            Err(fs_mistrust::Error::NotFound(_)) => return Ok(false),
            Err(e) => {
                return Err(FilesystemError::FsMistrust {
                    action: FilesystemAction::Read,
                    path: path.rel_path_unchecked().into(),
                    err: e.into(),
                })
                .map_err(|e| ArtiNativeKeystoreError::Filesystem(e).into());
            }
        };

        // The path exists, now check that it's actually a file and not a directory or symlink.
        if meta.is_file() {
            Ok(true)
        } else {
            Err(
                ArtiNativeKeystoreError::Filesystem(FilesystemError::NotARegularFile(
                    path.rel_path_unchecked().into(),
                ))
                .into(),
            )
        }
    }

    fn get(
        &self,
        key_spec: &dyn KeySpecifier,
        item_type: &KeystoreItemType,
    ) -> Result<Option<ErasedKey>> {
        let path = rel_path_if_supported!(self.rel_path(key_spec, item_type), Ok(None));

        let inner = match checked_op!(read, path) {
            Err(fs_mistrust::Error::NotFound(_)) => return Ok(None),
            res => res
                .map_err(|err| FilesystemError::FsMistrust {
                    action: FilesystemAction::Read,
                    path: path.rel_path_unchecked().into(),
                    err: err.into(),
                })
                .map_err(ArtiNativeKeystoreError::Filesystem)?,
        };

        let abs_path = path
            .checked_path()
            .map_err(ArtiNativeKeystoreError::Filesystem)?;

        match item_type {
            KeystoreItemType::Key(key_type) => {
                let inner = String::from_utf8(inner).map_err(|_| {
                    let err = io::Error::new(
                        io::ErrorKind::InvalidData,
                        "OpenSSH key is not valid UTF-8".to_string(),
                    );

                    ArtiNativeKeystoreError::Filesystem(FilesystemError::Io {
                        action: FilesystemAction::Read,
                        path: abs_path.clone(),
                        err: err.into(),
                    })
                })?;

                UnparsedOpenSshKey::new(inner, abs_path)
                    .parse_ssh_format_erased(key_type)
                    .map(Some)
            }
            KeystoreItemType::Cert(cert_type) => UnparsedCert::new(inner, abs_path)
                .parse_certificate_erased(cert_type)
                .map(Some),
            KeystoreItemType::Unknown { arti_extension } => Err(
                ArtiNativeKeystoreError::UnknownKeyType(UnknownKeyTypeError {
                    arti_extension: arti_extension.clone(),
                })
                .into(),
            ),
            _ => Err(internal!("unknown item type {item_type:?}").into()),
        }
    }

    fn insert(
        &self,
        key: &dyn EncodableItem,
        key_spec: &dyn KeySpecifier,
        item_type: &KeystoreItemType,
    ) -> Result<()> {
        let path = self
            .rel_path(key_spec, item_type)
            .map_err(|e| tor_error::internal!("{e}"))?;
        let unchecked_path = path.rel_path_unchecked();

        // Create the parent directories as needed
        if let Some(parent) = unchecked_path.parent() {
            self.keystore_dir
                .make_directory(parent)
                .map_err(|err| FilesystemError::FsMistrust {
                    action: FilesystemAction::Write,
                    path: parent.to_path_buf(),
                    err: err.into(),
                })
                .map_err(ArtiNativeKeystoreError::Filesystem)?;
        }

        let item_bytes: Vec<u8> = match key.as_keystore_item()? {
            KeystoreItem::Key(key) => {
                // TODO (#1095): decide what information, if any, to put in the comment
                let comment = "";
                key.to_openssh_string(comment)?.into_bytes()
            }
            KeystoreItem::Cert(cert) => match cert {
                CertData::TorEd25519Cert(cert) => cert.into(),
                _ => return Err(internal!("unknown cert type {item_type:?}").into()),
            },
            _ => return Err(internal!("unknown item type {item_type:?}").into()),
        };

        Ok(checked_op!(write_and_replace, path, item_bytes)
            .map_err(|err| FilesystemError::FsMistrust {
                action: FilesystemAction::Write,
                path: unchecked_path.into(),
                err: err.into(),
            })
            .map_err(ArtiNativeKeystoreError::Filesystem)?)
    }

    fn remove(
        &self,
        key_spec: &dyn KeySpecifier,
        item_type: &KeystoreItemType,
    ) -> Result<Option<()>> {
        let rel_path = self
            .rel_path(key_spec, item_type)
            .map_err(|e| tor_error::internal!("{e}"))?;

        match checked_op!(remove_file, rel_path) {
            Ok(()) => Ok(Some(())),
            Err(fs_mistrust::Error::NotFound(_)) => Ok(None),
            Err(e) => Err(ArtiNativeKeystoreError::Filesystem(
                FilesystemError::FsMistrust {
                    action: FilesystemAction::Remove,
                    path: rel_path.rel_path_unchecked().into(),
                    err: e.into(),
                },
            ))?,
        }
    }

    fn list(&self) -> Result<Vec<(KeyPath, KeystoreItemType)>> {
        WalkDir::new(self.keystore_dir.as_path())
            .into_iter()
            .map(|entry| {
                let entry = entry
                    .map_err(|e| {
                        let msg = e.to_string();
                        FilesystemError::Io {
                            action: FilesystemAction::Read,
                            path: self.keystore_dir.as_path().into(),
                            err: e
                                .into_io_error()
                                .unwrap_or_else(|| {
                                    io::Error::new(ErrorKind::Other, msg.to_string())
                                })
                                .into(),
                        }
                    })
                    .map_err(ArtiNativeKeystoreError::Filesystem)?;

                let path = entry.path();

                // Skip over directories as they won't be valid arti-paths
                //
                // TODO (#1118): provide a mechanism for warning about unrecognized keys?
                if entry.file_type().is_dir() {
                    return Ok(None);
                }

                let path = path
                    .strip_prefix(self.keystore_dir.as_path())
                    .map_err(|_| {
                        /* This error should be impossible. */
                        tor_error::internal!(
                            "found key {} outside of keystore_dir {}?!",
                            path.display_lossy(),
                            self.keystore_dir.as_path().display_lossy()
                        )
                    })?;

                if let Some(parent) = path.parent() {
                    // Check the properties of the parent directory by attempting to list its
                    // contents.
                    self.keystore_dir
                        .read_directory(parent)
                        .map_err(|e| FilesystemError::FsMistrust {
                            action: FilesystemAction::Read,
                            path: parent.into(),
                            err: e.into(),
                        })
                        .map_err(ArtiNativeKeystoreError::Filesystem)?;
                }

                let malformed_err = |path: &Path, err| ArtiNativeKeystoreError::MalformedPath {
                    path: path.into(),
                    err,
                };

                let extension = path
                    .extension()
                    .ok_or_else(|| malformed_err(path, err::MalformedPathError::NoExtension))?
                    .to_str()
                    .ok_or_else(|| malformed_err(path, err::MalformedPathError::Utf8))?;

                let item_type = KeystoreItemType::from(extension);
                // Strip away the file extension
                let path = path.with_extension("");
                // Construct slugs in platform-independent way
                let slugs = path
                    .components()
                    .map(|component| component.as_os_str().to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(&arti_path::PATH_SEP.to_string());
                ArtiPath::new(slugs)
                    .map(|path| Some((path.into(), item_type)))
                    .map_err(|e| {
                        malformed_err(&path, err::MalformedPathError::InvalidArtiPath(e)).into()
                    })
            })
            .flatten_ok()
            .collect()
    }
}

#[cfg(test)]
mod tests {
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
    use crate::test_utils::ssh_keys::*;
    use crate::test_utils::{assert_found, TestSpecifier};
    use crate::{ArtiPath, KeyPath};
    use std::cmp::Ordering;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{Duration, SystemTime};
    use tempfile::{tempdir, TempDir};
    use tor_cert::{CertifiedKey, Ed25519Cert};
    use tor_checkable::{SelfSigned, Timebound};
    use tor_key_forge::{CertType, KeyType, ParsedEd25519Cert};
    use tor_llcrypto::pk::ed25519::{self, Ed25519PublicKey as _};

    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    impl Ord for KeyPath {
        fn cmp(&self, other: &Self) -> Ordering {
            match (self, other) {
                (KeyPath::Arti(path1), KeyPath::Arti(path2)) => path1.cmp(path2),
                _ => unimplemented!("not supported"),
            }
        }
    }

    impl PartialOrd for KeyPath {
        fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
            Some(self.cmp(other))
        }
    }

    fn key_path(key_store: &ArtiNativeKeystore, key_type: &KeyType) -> PathBuf {
        let rel_key_path = key_store
            .rel_path(&TestSpecifier::default(), &key_type.clone().into())
            .unwrap();

        rel_key_path.checked_path().unwrap()
    }

    fn init_keystore(gen_keys: bool) -> (ArtiNativeKeystore, TempDir) {
        let keystore_dir = tempdir().unwrap();

        #[cfg(unix)]
        fs::set_permissions(&keystore_dir, fs::Permissions::from_mode(0o700)).unwrap();

        let key_store =
            ArtiNativeKeystore::from_path_and_mistrust(&keystore_dir, &Mistrust::default())
                .unwrap();

        if gen_keys {
            let key_path = key_path(&key_store, &KeyType::Ed25519Keypair);
            let parent = key_path.parent().unwrap();
            fs::create_dir_all(parent).unwrap();
            #[cfg(unix)]
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();

            fs::write(key_path, ED25519_OPENSSH).unwrap();
        }

        (key_store, keystore_dir)
    }

    macro_rules! assert_contains_arti_paths {
        ([$($arti_path:expr,)*], $list:expr) => {{
            let expected = vec![
                $(KeyPath::Arti(ArtiPath::new($arti_path.to_string()).unwrap())),*
            ];

            let mut sorted_list = $list.iter().map(|(path, _)| path.clone()).collect::<Vec<_>>();
            sorted_list.sort();

            assert_eq!(expected, sorted_list);
        }}
    }

    #[test]
    #[cfg(unix)]
    fn init_failure_perms() {
        use std::os::unix::fs::PermissionsExt;

        let keystore_dir = tempdir().unwrap();

        // Too permissive
        let mode = 0o777;

        fs::set_permissions(&keystore_dir, fs::Permissions::from_mode(mode)).unwrap();
        let err = ArtiNativeKeystore::from_path_and_mistrust(&keystore_dir, &Mistrust::default())
            .expect_err(&format!("expected failure (perms = {mode:o})"));

        assert_eq!(
            err.to_string(),
            format!(
                "Inaccessible path or bad permissions on {} while attempting to Init",
                keystore_dir.path().display_lossy()
            ),
            "expected keystore init failure (perms = {:o})",
            mode
        );
    }

    #[test]
    fn key_path_repr() {
        let (key_store, _) = init_keystore(false);

        assert_eq!(
            key_store
                .rel_path(&TestSpecifier::default(), &KeyType::Ed25519Keypair.into())
                .unwrap()
                .rel_path_unchecked(),
            PathBuf::from("parent1/parent2/parent3/test-specifier.ed25519_private")
        );

        assert_eq!(
            key_store
                .rel_path(
                    &TestSpecifier::default(),
                    &KeyType::X25519StaticKeypair.into()
                )
                .unwrap()
                .rel_path_unchecked(),
            PathBuf::from("parent1/parent2/parent3/test-specifier.x25519_private")
        );
    }

    #[cfg(unix)]
    #[test]
    fn get_and_rm_bad_perms() {
        use std::os::unix::fs::PermissionsExt;

        let (key_store, _keystore_dir) = init_keystore(true);

        let key_path = key_path(&key_store, &KeyType::Ed25519Keypair);

        // Make the permissions of the test key too permissive
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(key_store
            .get(&TestSpecifier::default(), &KeyType::Ed25519Keypair.into())
            .is_err());

        // Make the permissions of the parent directory too lax
        fs::set_permissions(
            key_path.parent().unwrap(),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();

        assert!(key_store.list().is_err());

        let key_spec = TestSpecifier::default();
        let ed_key_type = &KeyType::Ed25519Keypair.into();
        assert_eq!(
            key_store
                .remove(&key_spec, ed_key_type)
                .unwrap_err()
                .to_string(),
            format!(
                "Inaccessible path or bad permissions on {} while attempting to Remove",
                key_store
                    .rel_path(&key_spec, ed_key_type)
                    .unwrap()
                    .rel_path_unchecked()
                    .display_lossy()
            ),
        );
    }

    #[test]
    fn get() {
        // Initialize an empty key store
        let (key_store, _keystore_dir) = init_keystore(false);

        // Not found
        assert_found!(
            key_store,
            &TestSpecifier::default(),
            &KeyType::Ed25519Keypair,
            false
        );
        assert!(key_store.list().unwrap().is_empty());

        // Initialize a key store with some test keys
        let (key_store, _keystore_dir) = init_keystore(true);

        // Found!
        assert_found!(
            key_store,
            &TestSpecifier::default(),
            &KeyType::Ed25519Keypair,
            true
        );

        assert_contains_arti_paths!([TestSpecifier::path_prefix(),], key_store.list().unwrap());
    }

    #[test]
    fn insert() {
        // Initialize an empty key store
        let (key_store, keystore_dir) = init_keystore(false);

        // Not found
        assert_found!(
            key_store,
            &TestSpecifier::default(),
            &KeyType::Ed25519Keypair,
            false
        );
        assert!(key_store.list().unwrap().is_empty());

        // Insert the key
        let key = UnparsedOpenSshKey::new(ED25519_OPENSSH.into(), PathBuf::from("/test/path"));
        let erased_kp = key
            .parse_ssh_format_erased(&KeyType::Ed25519Keypair)
            .unwrap();

        let Ok(key) = erased_kp.downcast::<ed25519::Keypair>() else {
            panic!("failed to downcast key to ed25519::Keypair")
        };

        let key_spec = TestSpecifier::default();
        let ed_key_type = &KeyType::Ed25519Keypair.into();
        let path = keystore_dir.as_ref().join(
            key_store
                .rel_path(&key_spec, ed_key_type)
                .unwrap()
                .rel_path_unchecked(),
        );

        // The key and its parent directories don't exist yet.
        assert!(!path.parent().unwrap().try_exists().unwrap());
        assert!(key_store.insert(&*key, &key_spec, ed_key_type).is_ok());
        // insert() is supposed to create the missing directories
        assert!(path.parent().unwrap().try_exists().unwrap());

        // Found!
        assert_found!(
            key_store,
            &TestSpecifier::default(),
            &KeyType::Ed25519Keypair,
            true
        );
        assert_contains_arti_paths!([TestSpecifier::path_prefix(),], key_store.list().unwrap());
    }

    #[test]
    fn remove() {
        // Initialize the key store
        let (key_store, _keystore_dir) = init_keystore(true);

        assert_found!(
            key_store,
            &TestSpecifier::default(),
            &KeyType::Ed25519Keypair,
            true
        );

        // Now remove the key... remove() should indicate success by returning Ok(Some(()))
        assert_eq!(
            key_store
                .remove(&TestSpecifier::default(), &KeyType::Ed25519Keypair.into())
                .unwrap(),
            Some(())
        );
        assert!(key_store.list().unwrap().is_empty());

        // Can't find it anymore!
        assert_found!(
            key_store,
            &TestSpecifier::default(),
            &KeyType::Ed25519Keypair,
            false
        );

        // remove() returns Ok(None) now.
        assert!(key_store
            .remove(&TestSpecifier::default(), &KeyType::Ed25519Keypair.into())
            .unwrap()
            .is_none());
        assert!(key_store.list().unwrap().is_empty());
    }

    #[test]
    fn list() {
        // Initialize the key store
        let (key_store, _keystore_dir) = init_keystore(true);
        assert_contains_arti_paths!([TestSpecifier::path_prefix(),], key_store.list().unwrap());

        // Insert another key
        let key = UnparsedOpenSshKey::new(ED25519_OPENSSH.into(), PathBuf::from("/test/path"));
        let erased_kp = key
            .parse_ssh_format_erased(&KeyType::Ed25519Keypair)
            .unwrap();

        let Ok(key) = erased_kp.downcast::<ed25519::Keypair>() else {
            panic!("failed to downcast key to ed25519::Keypair")
        };

        let key_spec = TestSpecifier::new("-i-am-a-suffix");
        let ed_key_type = KeyType::Ed25519Keypair.into();

        assert!(key_store.insert(&*key, &key_spec, &ed_key_type).is_ok());

        assert_contains_arti_paths!(
            [
                TestSpecifier::path_prefix(),
                format!("{}-i-am-a-suffix", TestSpecifier::path_prefix()),
            ],
            key_store.list().unwrap()
        );
    }

    #[test]
    fn key_path_not_regular_file() {
        let (key_store, _keystore_dir) = init_keystore(false);

        let key_path = key_path(&key_store, &KeyType::Ed25519Keypair);
        // The key is a directory, not a regular file
        fs::create_dir_all(&key_path).unwrap();
        assert!(key_path.try_exists().unwrap());
        let parent = key_path.parent().unwrap();
        #[cfg(unix)]
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).unwrap();

        let err = key_store
            .contains(&TestSpecifier::default(), &KeyType::Ed25519Keypair.into())
            .unwrap_err();
        assert!(err.to_string().contains("not a regular file"), "{err}");
    }

    #[test]
    fn certs() {
        let (key_store, _keystore_dir) = init_keystore(false);

        let mut rng = rand::rng();
        let subject_key = ed25519::Keypair::generate(&mut rng);
        let signing_key = ed25519::Keypair::generate(&mut rng);

        // Note: the cert constructor rounds the expiration forward to the nearest hour
        // after the epoch.
        let cert_exp = SystemTime::UNIX_EPOCH + Duration::from_secs(60 * 60);

        let encoded_cert = Ed25519Cert::constructor()
            .cert_type(tor_cert::CertType::IDENTITY_V_SIGNING)
            .expiration(cert_exp)
            .signing_key(signing_key.public_key().into())
            .cert_key(CertifiedKey::Ed25519(subject_key.public_key().into()))
            .encode_and_sign(&signing_key)
            .unwrap();

        // The specifier doesn't really matter.
        let cert_spec = TestSpecifier::default();
        assert!(key_store
            .insert(&encoded_cert, &cert_spec, &CertType::Ed25519TorCert.into())
            .is_ok());

        let erased_cert = key_store
            .get(&cert_spec, &CertType::Ed25519TorCert.into())
            .unwrap()
            .unwrap();
        let Ok(found_cert) = erased_cert.downcast::<ParsedEd25519Cert>() else {
            panic!("failed to downcast cert to KewUnknownCert")
        };

        let found_cert = found_cert
            .should_be_signed_with(&signing_key.public_key().into())
            .unwrap()
            .dangerously_assume_wellsigned()
            .dangerously_assume_timely();

        assert_eq!(
            found_cert.as_ref().cert_type(),
            tor_cert::CertType::IDENTITY_V_SIGNING
        );
        assert_eq!(found_cert.as_ref().expiry(), cert_exp);
        assert_eq!(
            found_cert.as_ref().signing_key(),
            Some(&signing_key.public_key().into())
        );
        assert_eq!(
            found_cert.subject_key().unwrap(),
            &subject_key.public_key().into()
        );
    }
}

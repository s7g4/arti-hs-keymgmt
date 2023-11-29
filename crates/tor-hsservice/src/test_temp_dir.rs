//! Temp directories in tests
//!
//! Helpers for:
//!
//! This module improves on [`tempdir`] by adding several new features for testing:
//!
//!  * Allowing the user to cause the tests to use predictable paths
//!  * Allowing the user to cause the tests to leave their temporary directories behind
//!  * Helping ensure that test directories are not deleted
//!    before everything that uses them has been torn down
//!    (via Rust lifetimes)
//!
//! The principal entrypoint is [`test_temp_dir!`]
//! which returns a `TestTempDir`.
//!
//! # Environment variables
//!
//! The behaviour is influenced by `TEST_TEMP_RETAIN`:
//!
//!  * `0` (or unset): use a temporary directory in `TMPDIR` or `/tmp`
//!    and try to delete it after the test completes.
//!    (equivalent to using [`tempdir::TempDir`].
//!
//!  * `1`: use the directory `target/test/crate::module::function`.
//!    Delete and recreate it *on entry to the test*, but do not delete it afterwards.
//!    On Windows, `,` is used to replace `::` since `::` cannot appear in filenames.
//!
//!  * Pathname starting with `/` or `.`: like `1`,
//!    but the supplied path is used instead of `target/test`.
//!
//! # stdout printing
//!
//! This is a module for use in tests.
//! When invoked, it will print a message to stdout about the test directory.
//!
//! # Panics
//!
//! This is a module for use in tests.
//! Most error conditions will cause a panic.

#![allow(unreachable_pub)] // TODO make this into a pub module somewhere (where?)

// We have a nonstandard test lint block
#![allow(clippy::print_stdout)]

use std::env::{self, VarError};
use std::fs;
use std::io;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use derive_more::{Deref, DerefMut};
use educe::Educe;

/// The env var the user should set to control test temp dir handling
const RETAIN_VAR: &str = "TEST_TEMP_RETAIN";

/// Directory for a test to store temporary files
///
/// Automatically deleted (if appropriate) when dropped.
#[derive(Debug)]
pub enum TestTempDir {
    /// An ephemeral directory
    Ephemeral(tempfile::TempDir),
    /// A directory which should persist after the test completes
    Persistent(PathBuf),
}

/// A `T` which relies on some temporary directory with lifetime `d`
///
/// Obtained from `TestTempDir::in_obtain`.
///
/// Using this type means that the `T` won't outlive the temporary directory.
/// (Typically, if it were to, things would malfunction.
/// There might even be security hazards!)
#[derive(Clone, Copy, Deref, DerefMut, Educe)]
#[educe(Debug(bound))]
pub struct UsingTempDir<'d, T> {
    /// The thing
    #[deref]
    #[deref_mut]
    thing: T,

    /// Placate the compiler
    ///
    /// We use a notional `()` since we don't want the compiler to infer drop glue.
    #[educe(Debug(ignore))]
    tempdir: PhantomData<&'d ()>,
}

impl TestTempDir {
    /// Obtain a temp dir named after our thread, and the module path `mod_path`
    ///
    /// Expects that the current thread name is the module path within the crate,
    /// followed by the test function name.
    /// (This is how Rust's builtin `#[test]` names its threads.)
    // This is also used by some other crates.
    // If it turns out not to be true, we'll end up panicking.
    //
    /// And, expects that `mod_path` is the crate name,
    /// and then the module path within the crate.
    /// This is what Rust's builtin `module_path!` macro returns.
    ///
    /// The two instances of the module path within the crate must be the same!
    ///
    /// # Panics
    ///
    /// Panics if the thread name and `mod_path` do not correspond
    /// (see the [self](module-level documentation).)
    pub fn from_module_path_and_thread(mod_path: &str) -> TestTempDir {
        let path = (|| {
            let (crate_, m_mod) = mod_path
                .split_once("::")
                .ok_or_else(|| anyhow!("module path {:?} doesn't contain `::`", &mod_path))?;
            let thread = std::thread::current();
            let thread = thread.name().context("get current thread name")?;
            let (t_mod, fn_) = thread
                .rsplit_once("::")
                .ok_or_else(|| anyhow!("current thread name {:?} doesn't contain `::`", &thread))?;
            if m_mod != t_mod {
                return Err(anyhow!(
 "module path {:?} implies module name {:?} but thread name {:?} implies module name {:?}",
                    mod_path, m_mod, thread, t_mod
                ));
            }
            Ok::<_, anyhow::Error>(format!("{crate_}::{m_mod}::{fn_}"))
        })()
        .expect("unable to calculate complete test function path");

        Self::from_complete_item_path(&path)
    }

    /// Obtains a temp dir named after a complete item path
    ///
    /// The supplied `item_path` must be globally unique in the whole workspace,
    /// or it might collide with other tests from other crates.
    ///
    /// Handles the replacement of `::` with `:` on Windows.
    pub fn from_complete_item_path(item_path: &str) -> Self {
        let subdir = item_path;

        // Operating systems that can't have `::` in pathnames
        #[cfg(target_os = "windows")]
        let subdir = subdir.replace("::", ",");

        #[allow(clippy::needless_borrow)] // borrow not needed if we didn't rebind
        Self::from_stable_unique_subdir(&subdir)
    }

    /// Obtains a temp dir given a stable unique subdirectory name
    ///
    /// The supplied `subdir` must be globally unique
    /// across every test in the whole workspace,
    /// or it might collide with other tests.
    pub fn from_stable_unique_subdir(subdir: &str) -> Self {
        let retain = env::var(RETAIN_VAR);
        let retain = match &retain {
            Ok(y) => y,
            Err(VarError::NotPresent) => "0",
            Err(VarError::NotUnicode(_)) => panic!("{} not unicode", RETAIN_VAR),
        };
        let target: PathBuf = if retain == "0" {
            println!("test {subdir}: {RETAIN_VAR} not enabled, using ephemeral temp dir");
            let dir = tempfile::tempdir().expect("failed to create temp dir");
            return TestTempDir::Ephemeral(dir);
        } else if retain.starts_with('.') || retain.starts_with('/') {
            retain.into()
        } else if retain == "1" {
            let target = env::var_os("CARGO_TARGET_DIR").unwrap_or_else(|| "target".into());
            let mut dir = PathBuf::from(target);
            dir.push("test");
            dir
        } else {
            panic!("invalid value for {}: {:?}", RETAIN_VAR, retain)
        };

        let dir = {
            let mut dir = target;
            dir.push(subdir);
            dir
        };
        println!("test {subdir}, temp dir is {}", dir.display());
        match fs::remove_dir_all(&dir) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            other => other,
        }
        .expect("pre-remove temp dir");
        fs::create_dir_all(&dir).expect("create temp dir");
        TestTempDir::Persistent(dir)
    }

    /// Obtain a reference to the `Path` of this temp directory
    ///
    /// Prefer to use [`.in_obtain()`](TestTempDir::in_obtain) where possible.
    ///
    /// The lifetime of the temporary directory will not be properly represented
    /// by Rust lifetimes.  For example, calling
    /// `.to_owned()`[ToOwned::to_owned]
    /// will get a `'static` value,
    /// which doesn't represent the fact that the directory will go away
    /// when the `TestTempDir` is dropped.
    ///
    /// So the resulting value can be passed to functions which
    /// store the path for later use, and might later malfunction because
    /// the `TestTempDir` is dropped too earlier.
    pub fn as_path_untracked(&self) -> &Path {
        match self {
            TestTempDir::Ephemeral(t) => t.as_ref(),
            TestTempDir::Persistent(t) => t.as_ref(),
        }
    }

    /// Return a subdirectory, without lifetime tracking
    pub fn subdir_untracked(&self, subdir: &str) -> PathBuf {
        let mut r = self.as_path_untracked().to_owned();
        r.push(subdir);
        r
    }

    /// Obtain a `T` which uses paths in `self`
    ///
    /// Rust lifetime tracking ensures that the temporary directory
    /// won't be cleaned up until the `T` is destroyed.
    pub fn in_obtain<'d, T>(&'d self, subdir: &str, f: impl FnOnce(PathBuf) -> T) -> UsingTempDir<'d, T> {
        let dir = self.subdir_untracked(subdir);
        let thing = f(dir);
        UsingTempDir::with_path(thing, self.as_path_untracked())
    }
}

impl<'d, T> UsingTempDir<'d, T> {
    /// Obtain the inner `T`
    ///
    /// It is up to you to ensure that `T` doesn't outlive
    /// the temp directory used to create it.
    #[allow(dead_code)] // TODO HSS remove (this will in fact be used by ipt_mgr tests)
    pub fn into_untracked(self) -> T {
        self.thing
    }

    /// Create from a `T` and a `&Path` with the right lifetime
    pub fn with_path(thing: T, _path: &'d Path) -> Self {
        Self::new_untracked(thing)
    }

    /// Create from a raw `T`
    ///
    /// The returned lifetime is unfounded!
    /// It is up to you to ensure that the inferred lifetime is correct!
    pub fn new_untracked(thing: T) -> Self {
        Self {
            thing,
            tempdir: PhantomData,
        }
    }
}

/// Obtain a `TestTempDir` for the current test
///
/// Must be called in the same thread as the actual `#[test]` entrypoint!
///
/// **`fn test_temp_dir() -> TestTempDir;`**
#[macro_export]
macro_rules! test_temp_dir { {} => {
    TestTempDir::from_module_path_and_thread(module_path!())
} }

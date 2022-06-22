//! Internal: Declare an Error type for tor-bytes

use thiserror::Error;

/// Error type for decoding and encoding Tor objects from and to bytes.
//
// TODO(nickm): This error type could use a redesign: it doesn't do a good job
// of preserving context.  At the least it should say what kind of object it
// found any given problem in.
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Tried to read something, but we didn't find enough bytes.
    ///
    /// This can mean that the object is truncated, or that we need to
    /// read more and try again, depending on the context in which it
    /// was received.
    #[error("Object truncated (or not fully present)")]
    Truncated,
    /// Called Reader::should_be_exhausted(), but found bytes anyway.
    #[error("Extra bytes at end of object")]
    ExtraneousBytes,
    /// Invalid length value (eg, overflow)
    #[error("Object length out of bounds")]
    BadLengthValue,
    /// An attempt to parse an object failed for some reason related to its
    /// contents.
    #[error("Bad object: {0}")]
    BadMessage(&'static str),
    /// A parsing error that should never happen.
    ///
    /// We use this one in lieu of calling assert() and expect() and
    /// unwrap() from within parsing code.
    #[error("Internal error")]
    Bug(#[from] tor_error::Bug),
}

impl PartialEq for Error {
    fn eq(&self, other: &Self) -> bool {
        use Error::*;
        match (self, other) {
            (Truncated, Truncated) => true,
            (ExtraneousBytes, ExtraneousBytes) => true,
            (BadMessage(a), BadMessage(b)) => a == b,
            (BadLengthValue, BadLengthValue) => true,
            // notably, this means that an internal error is equal to nothing, not even itself.
            (_, _) => false,
        }
    }
}

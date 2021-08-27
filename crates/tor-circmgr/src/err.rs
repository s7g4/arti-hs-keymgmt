//! Declare an error type for tor-circmgr

use retry_error::RetryError;
use thiserror::Error;

/// An error returned while looking up or building a circuit
#[derive(Error, Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// No suitable relays for a request
    #[error("no relays for circuit: {0}")]
    NoRelays(String),

    /// We need to have a consensus directory to build this kind of
    /// circuits, and we only got a list of fallbacks.
    #[error("Consensus directory needed")]
    NeedConsensus,

    /// We were waiting on a pending circuit, but it didn't succeed.
    #[error("Pending circuit(s) failed to launch")]
    PendingFailed,

    /// A circuit build took too long to finish.
    #[error("Circuit took too long to build")]
    CircTimeout,

    /// Tried to take a circuit for a purpose it doesn't support.
    #[error("Circuit usage not supported: {0}")]
    UsageNotSupported(String),

    /// A request spent too long waiting for a circuit
    #[error("Spent too long waiting for a circuit to build")]
    RequestTimeout,

    /// Unable to get or build a circuit, despite retrying.
    #[error("{0}")]
    RequestFailed(RetryError<Box<Error>>),

    /// An error caused by a programming issue or a failure in another
    /// library that we can't work around.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Couldn't get a channel for a circuit.
    #[error("Couldn't get channel for circuit: {0}")]
    ChanFailed(#[from] tor_chanmgr::Error),

    /// Protocol issue while building a circuit.
    #[error("Problem building a circuit: {0}")]
    Protocol(#[from] tor_proto::Error),

    /// Problem loading or storing persistent state.
    #[error("Problem loading or storing state: {0}")]
    State(#[from] tor_persist::Error),
}

impl From<futures::channel::oneshot::Canceled> for Error {
    fn from(_: futures::channel::oneshot::Canceled) -> Error {
        Error::PendingFailed
    }
}

impl From<futures::task::SpawnError> for Error {
    fn from(_: futures::task::SpawnError) -> Error {
        Error::Internal("Unable to spawn new task in executor.".into())
    }
}

impl From<tor_rtcompat::TimeoutError> for Error {
    fn from(_: tor_rtcompat::TimeoutError) -> Error {
        Error::CircTimeout
    }
}

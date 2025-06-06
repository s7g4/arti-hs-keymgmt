//! Conflux-related functionality

use futures::StreamExt;
use futures::{select_biased, stream::FuturesUnordered, FutureExt as _, Stream};
use slotmap_careful::SlotMap;

use tor_async_utils::SinkPrepareExt as _;
use tor_error::{bad_api_usage, internal, into_bad_api_usage, Bug};

use crate::crypto::cell::HopNum;
use crate::util::err::ReactorError;

use super::{Circuit, CircuitAction, LegId, LegIdKey};

/// Type alias for the result of [`ConfluxSet::circuit_action`].
type CircuitActionResult = Result<Option<CircuitAction>, crate::Error>;

/// A set of linked conflux circuits.
pub(super) struct ConfluxSet {
    /// The circuits in this conflux set.
    legs: SlotMap<LegIdKey, Circuit>,
    /// The unique identifier of the primary leg
    pub(super) primary_id: LegIdKey,
}

impl ConfluxSet {
    /// Create a new conflux set, consisting of a single leg.
    pub(super) fn new(circuit_leg: Circuit) -> Self {
        let mut legs: SlotMap<LegIdKey, Circuit> = SlotMap::with_key();
        let primary_id = legs.insert(circuit_leg);

        Self { legs, primary_id }
    }

    /// Remove and return the only leg of this conflux set.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    ///
    /// Calling this function will empty the [`ConfluxSet`].
    pub(super) fn take_single_leg(&mut self) -> Result<Circuit, NotSingleLegError> {
        let circ = get_single(self.legs.remove(self.primary_id).into_iter())?;
        Ok(circ)
    }

    /// Return a reference to the only leg of this conflux set,
    /// along with the leg's ID.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg(&self) -> Result<(LegId, &Circuit), NotSingleLegError> {
        let (circ_id, circ) = get_single(self.legs.iter())?;
        Ok((LegId(circ_id), circ))
    }

    /// Return a mutable reference to the only leg of this conflux set,
    /// along with the leg's ID.
    ///
    /// Returns an error if there is more than one leg in the set,
    /// or if called before any circuit legs are available.
    pub(super) fn single_leg_mut(&mut self) -> Result<(LegId, &mut Circuit), NotSingleLegError> {
        let (circ_id, circ) = get_single(self.legs.iter_mut())?;
        Ok((LegId(circ_id), circ))
    }

    /// Return the primary leg of this conflux set.
    ///
    /// Returns an error if called before any circuit legs are available.
    pub(super) fn primary_leg_mut(&mut self) -> Result<&mut Circuit, Bug> {
        // TODO(conflux): support more than one leg,
        // and remove this check
        if self.legs.len() > 1 {
            return Err(internal!("multipath not currently supported"));
        }

        if self.legs.is_empty() {
            Err(bad_api_usage!(
                "tried to get circuit leg before creating it?!"
            ))
        } else {
            // TODO(conflux): implement primary leg selection
            let circ = self
                .legs
                .get_mut(self.primary_id)
                .ok_or_else(|| internal!("slotmap is empty?!"))?;

            Ok(circ)
        }
    }

    /// Return a mutable reference to the leg of this conflux set with the given id.
    pub(super) fn leg_mut(&mut self, leg_id: LegId) -> Option<&mut Circuit> {
        self.legs.get_mut(leg_id.0)
    }

    /// Return an iterator of all legs in the conflux set.
    pub(super) fn legs(&self) -> impl Iterator<Item = (LegId, &Circuit)> {
        self.legs.iter().map(|(id, leg)| (LegId(id), leg))
    }

    /// Return the number of legs in this conflux set.
    pub(super) fn len(&self) -> usize {
        self.legs.len()
    }

    /// Return whether this conflux set is empty.
    pub(super) fn is_empty(&self) -> bool {
        self.legs.len() == 0
    }

    /// Remove the specified leg from this conflux set.
    ///
    /// Returns an error if the given leg doesn't exist in the set,
    /// or if after removing the leg the set is depleted (empty).
    pub(super) fn remove(&mut self, leg: LegIdKey) -> Result<(), ReactorError> {
        let _ = self
            .legs
            .remove(leg)
            .ok_or_else(|| bad_api_usage!("leg {leg:?} not found in conflux set"))?;

        // TODO(conflux): if leg == primary_leg, reassign the next best leg to primary_leg

        if self.legs.is_empty() {
            // The last circuit in the set has just died, so the reactor should exit.
            return Err(ReactorError::Shutdown);
        }

        Ok(())
    }

    /// Returns a stream of [`CircuitAction`] messages,
    /// obtained from processing the incoming/outgoing messages on all the circuits in this set.
    ///
    /// This is cancellation-safe.
    pub(super) fn circuit_action<'a>(
        &'a mut self,
    ) -> impl Stream<Item = Result<CircuitActionResult, crate::Error>> + 'a {
        self.legs
            .iter_mut()
            .map(|(leg_id, leg)| {
                let mut ready_streams = leg.ready_streams_iterator(leg_id);
                let input = &mut leg.input;
                // TODO: we don't really need prepare_send_from here
                // because the inner select_biased! is cancel-safe.
                // We should replace this with a simple sink readiness check
                leg.chan_sender.prepare_send_from(async move {
                    // NOTE: the stream returned by this function is polled in the select_biased!
                    // from Reactor::run_once(), so each block from *this* select_biased! must be
                    // cancellation-safe
                    select_biased! {
                        // Check whether we've got an input message pending.
                        ret = input.next().fuse() => {
                            let Some(cell) = ret else {
                                return Ok(Some(CircuitAction::RemoveLeg(leg_id)));
                            };

                            Ok(Some(CircuitAction::HandleCell(cell)))
                        },
                        ret = ready_streams.next().fuse() => {
                            match ret {
                                Some(cmd) => {
                                    cmd.map(|cmd| Some(CircuitAction::Single(cmd)))
                                },
                                None => {
                                    // There are no ready streams (for example, they may all be
                                    // blocked due to congestion control), so there is nothing
                                    // to do.
                                    Ok(None)
                                }
                            }
                        }
                    }
                })
            })
            .collect::<FuturesUnordered<_>>()
            // Note: We don't actually use the returned SinkSendable,
            // and continue writing to the SometimesUboundedSink in the reactor :(
            .map(|res| res.map(|res| res.0))
    }

    /// The join point on the current primary leg.
    pub(super) fn primary_join_point(&self) -> Option<(LegId, HopNum)> {
        // TODO(conflux): we need a way to get the join point on the primary leg once this tunnel
        // has been converted from a "non-conflux tunnel" to a "conflux tunnel"
        None
    }
}

/// Get the only item from an iterator.
///
/// Returns an error if the iterator is empty or has more than one item.
fn get_single<T>(mut iterator: impl Iterator<Item = T>) -> Result<T, NotSingleError> {
    let Some(rv) = iterator.next() else {
        return Err(NotSingleError::None);
    };
    if iterator.next().is_some() {
        return Err(NotSingleError::Multiple);
    }
    Ok(rv)
}

/// An error returned from [`get_single`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum NotSingleError {
    /// The iterator had no items.
    #[error("the iterator had no items")]
    None,
    /// The iterator had more than one item.
    #[error("the iterator had more than one item")]
    Multiple,
}

/// An error returned when a method is expecting a single-leg conflux circuit,
/// but it is not single-leg.
#[derive(Copy, Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum NotSingleLegError {
    /// Conflux set has no legs.
    #[error("the conflux set has no legs")]
    EmptyConfluxSet,
    /// Conflux set is multi-path.
    #[error("the conflux set is multi-path")]
    IsMultipath,
}

impl From<NotSingleLegError> for Bug {
    fn from(e: NotSingleLegError) -> Self {
        into_bad_api_usage!("not a single leg conflux set")(e)
    }
}

impl From<NotSingleLegError> for crate::Error {
    fn from(e: NotSingleLegError) -> Self {
        Self::from(Bug::from(e))
    }
}

impl From<NotSingleLegError> for ReactorError {
    fn from(e: NotSingleLegError) -> Self {
        Self::from(Bug::from(e))
    }
}

impl From<NotSingleError> for NotSingleLegError {
    fn from(e: NotSingleError) -> Self {
        match e {
            NotSingleError::None => Self::EmptyConfluxSet,
            NotSingleError::Multiple => Self::IsMultipath,
        }
    }
}

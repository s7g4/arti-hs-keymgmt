//! Code for estimating good values for circuit timeouts.
//!
//! We need good circuit timeouts for two reasons: first, they help
//! user experience.  If user wait too long for their circuits, or if
//! they use exceptionally slow circuits, then Tor will feel really
//! slow.  Second, these timeouts are actually a security
//! property. (XXXX explain why!)

#![allow(dead_code)]

use std::time::Duration;

pub(crate) mod pareto;

/// An object that calculates circuit timeout thresholds from the history
/// of circuit build times.
pub(crate) trait TimeoutEstimator {
    /// Record that a given circuit hop has completed.
    ///
    /// The `hop` number is a zero-indexed value for which hop just completed.
    ///
    /// The `delay` value is the amount of time after we first launched the
    /// circuit.
    ///
    /// If this is the last hop of the circuit, then `is_last` is true.
    fn note_hop_completed(&self, hop: u8, delay: Duration, is_last: bool);

    /// Record that a circuit failed to complete because it took too long.
    ///
    /// The `hop` number is a the number of hops that were successfully
    /// completed.
    ///
    /// The `delay` number is the amount of time after we first launched the
    /// circuit.
    fn note_circ_timeout(&self, hop: u8, delay: Duration);

    /// Return the current estimation for how long we should wait for a given
    /// [`Action`] to complete.
    ///
    /// This function should return a 2-tuple of `(timeout, abandon)`
    /// durations.  After `timeout` has elapsed since circuit launch,
    /// the circuit should no longer be used, but we should still keep
    /// building it in order see how long it takes.  After `abandon`
    /// has elapsed since circuit launch, the circuit should be
    /// abandoned completely.
    fn timeouts(&self, action: &Action) -> (Duration, Duration);

    /// Return true if we're currently trying to learn more timeouts
    /// by launching testing circuits.
    fn learning_timeouts(&self) -> bool;
}

/// A possible action for which we can try to estimate a timeout.
#[non_exhaustive]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Action {
    /// Build a circuit of a given length.
    BuildCircuit {
        /// The length of the circuit to construct.
        ///
        /// (A 0-hop circuit takes no time.)
        length: usize,
    },
    /// Extend a given circuit from one length to another.
    ExtendCircuit {
        /// The current length of the circuit.
        initial_length: usize,
        /// The new length of the circuit.
        ///
        /// (Must be greater than `initial_length`.)
        final_length: usize,
    },
    /// Send a message to the last hop of a circuit and receive a response
    RoundTrip {
        /// The length of the circuit.
        length: usize,
    },
}

impl Action {
    /// Compute a scaling factor for a given `Action`
    ///
    /// These values are arbitrary numbers such that if the correct
    /// timeout for an Action `a1` is `t`, then the correct timeout
    /// for an action `a2` is `t * a2.timeout_scale() /
    /// a1.timeout_scale()`.
    ///
    /// This function can return garbage if the circuit length is larger
    /// than actually supported on the Tor network.
    fn timeout_scale(&self) -> usize {
        /// An arbitrary value to use to prevent overflow.
        const MAX_LEN: usize = 64;

        /// Return the scale value for building a `len`-hop circuit.
        fn build_scale(len: usize) -> usize {
            len * (len + 1) / 2
        }
        // This is based on an approximation from Tor's
        // `circuit_expire_building()` code.
        //
        // The general principle here is that when you're waiting for
        // a round-trip through a circuit through three relays
        // 'a--b--c', it takes three units of time.  Thus, building a
        // three hop circuit requires you to send a message through
        // "a", then through "a--b", then through "a--b--c", for a
        // total of 6.
        //
        // XXXX This should go into the specifications.
        match *self {
            Action::BuildCircuit { length } => {
                // We never down-scale our estimates for building a circuit
                // below a 3-hop length.
                //
                // TODO: This is undocumented.
                let length = length.clamp(3, MAX_LEN);
                build_scale(length)
            }
            Action::ExtendCircuit {
                initial_length,
                final_length,
            } => {
                let initial_length = initial_length.clamp(0, MAX_LEN);
                let final_length = final_length.clamp(initial_length, MAX_LEN);
                build_scale(final_length) - build_scale(initial_length)
            }
            Action::RoundTrip { length } => length.clamp(0, MAX_LEN),
        }
    }
}

#[cfg(test)]
mod test {
    use super::Action;

    #[test]
    fn action_scale_values() {
        assert_eq!(Action::BuildCircuit { length: 1 }.timeout_scale(), 6);
        assert_eq!(Action::BuildCircuit { length: 2 }.timeout_scale(), 6);
        assert_eq!(Action::BuildCircuit { length: 3 }.timeout_scale(), 6);
        assert_eq!(Action::BuildCircuit { length: 4 }.timeout_scale(), 10);
        assert_eq!(Action::BuildCircuit { length: 5 }.timeout_scale(), 15);

        assert_eq!(
            Action::ExtendCircuit {
                initial_length: 3,
                final_length: 4
            }
            .timeout_scale(),
            4
        );
        assert_eq!(
            Action::ExtendCircuit {
                initial_length: 99,
                final_length: 4
            }
            .timeout_scale(),
            0
        );

        assert_eq!(Action::RoundTrip { length: 3 }.timeout_scale(), 3);
    }
}

//! IPT set - the principal API between the IPT manager and publisher

use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use futures::channel::mpsc;
use futures::StreamExt as _;

use derive_more::{Deref, DerefMut};
use educe::Educe;
use itertools::chain;
use serde::{Deserialize, Serialize};

use crate::IptLocalId;
use crate::{IptStoreError, StartupError};

use tor_error::internal;
use tor_rtcompat::SleepProvider;

/// Handle for a suitable persistent storage manager
pub(crate) type IptSetStorageHandle = dyn tor_persist::StorageHandle<StateRecord> + Sync + Send;

/// Information shared between the IPT manager and the IPT publisher
///
/// The principal information is `ipts`, which is calculated by the IPT Manager.
/// See
/// [`IptManager::compute_iptsetstatus_publish`](crate::ipt_mgr::IptManager::compute_iptsetstatus_publish)
/// for more detailed information about how this is calculated.
#[derive(Educe)]
#[educe(Debug)]
pub(crate) struct PublishIptSet {
    /// Set of introduction points to be advertised in a descriptor (if we are to publish)
    ///
    /// If `Some`, the publisher will try to maintain a published descriptor,
    /// of lifetime `lifetime`, listing `ipts`.
    ///
    /// If `None`, the publisher will not try to publish.
    /// (Already-published descriptors will not be deleted.)
    ///
    /// These instructions ultimately come from
    /// [`IptManager::compute_iptsetstatus_publish`](crate::ipt_mgr::IptManager::compute_iptsetstatus_publish).
    pub(crate) ipts: Option<IptSet>,

    /// Record of publication attempts
    ///
    /// Time until which the manager ought we to try to maintain each ipt,
    /// even after we stop publishing it.
    ///
    /// This is a ceiling on:
    ///
    ///   * The last time we *finished* publishing the descriptor
    ///     (we can estimate this by taking the time we *started* to publish
    ///     plus our timeout on the publication attempt).
    ///
    ///   * Plus the `lifetime` that was used for publication.
    ///
    ///   * Plus the length of time between a client obtaining the descriptor
    ///     and its introduction request reaching us through the intro point
    ///     ([`IPT_PUBLISH_EXPIRY_SLOP`])
    ///
    /// This field is updated by the publisher, using
    /// [`note_publication_attempt`](PublishIptSet::note_publication_attempt),
    /// and read by the manager.
    ///
    /// A separate copy of the information is stored by the manager,
    /// in `ipt_mgr::Ipt::last_descriptor_expiry_including_slop`.
    ///
    /// There may be entries in this table that don't
    /// correspond to introduction points in `ipts`.
    /// The publisher mustn't create such entries
    /// (since that would imply publishing IPTs contrary to the manager's instructions)
    /// but it can occur, for example, on restart.
    ///
    /// It is the manager's job to remove expired entries.
    //
    // This is a separate field, rather than being part of IptSet, so that during startup,
    // we can load information about previously-published IPTs, even though we don't want,
    // at that stage, to publish anything.
    //
    // The publication information is stored in a separate on-disk file, so that the
    // IPT publisher can record publication attempts without having to interact with the
    // IPT manager's main data structure.
    //
    // (The publisher needs to update the on-disk state synchronously, before publication,
    // since otherwise there could be a bug scenario where we succeed in publishing,
    // but don't succeed in recording that we published, and then, on restart,
    // don't know that we need to (re)establish this IPT.)
    pub(crate) last_descriptor_expiry_including_slop: HashMap<IptLocalId, Instant>,

    /// The on-disk state storage handle.
    #[educe(Debug(ignore))]
    #[allow(dead_code)] // XXXX
    storage: Arc<IptSetStorageHandle>,
}

/// A set of introduction points for publication
///
/// This is shared between the manager and the publisher.
/// Each leaf field says who sets it.
///
/// This is not `Clone` and its contents should not be cloned.
/// When its contents are copied out into a descriptor by the publisher,
/// this should be accompanied by a call to
/// [`note_publication_attempt`](PublishIptSet::note_publication_attempt).
#[derive(Debug)]
pub(crate) struct IptSet {
    /// The actual introduction points
    pub(crate) ipts: Vec<IptInSet>,

    /// When to make the descriptor expire
    ///
    /// Set by the manager and read by the publisher.
    pub(crate) lifetime: Duration,
}

/// Introduction point as specified to publisher by manager
///
/// Convenience type alias.
#[derive(Debug)]
pub(crate) struct IptInSet {
    /// Details of the introduction point
    ///
    /// Set by the manager and read by the publisher.
    pub(crate) ipt: Ipt,

    /// Local identifier for this introduction point
    ///
    /// Set and used by the manager, to correlate this data structure with the manager's.
    /// May also be read by the publisher.
    pub(crate) lid: IptLocalId,
}

/// Actual introduction point details as specified to publisher by manager
///
/// Convenience type alias.
pub(crate) type Ipt = tor_netdoc::doc::hsdesc::IntroPointDesc;

/// Descriptor expiry time slop
///
/// How long after our descriptor expired should we continue to maintain an old IPT?
/// This is an allowance for:
///
///   - Various RTTs and delays in clients setting up circuits
///     (we can't really measure this ourselves properly,
///     since what matters is the client's latency)
///
///   - Clock skew
//
// TODO HSS IPT_PUBLISH_EXPIRY_SLOP configure?
pub(crate) const IPT_PUBLISH_EXPIRY_SLOP: Duration = Duration::from_secs(300); // 5 minutes

/// Shared view of introduction points - IPT manager's view
///
/// This is the manager's end of a bidirectional "channel",
/// containing a shared `PublishIptSet`, i.e. an `Option<IptSet>`.
#[derive(Debug)]
pub(crate) struct IptsManagerView {
    /// Actual shared data
    shared: Shared,

    /// Notification sender
    ///
    /// We don't wrap the state in a postage::watch,
    /// because the publisher needs to be able to mutably borrow the data
    /// without re-notifying itself when it drops the guard.
    notify: mpsc::Sender<()>,
}

/// Shared view of introduction points - IPT publisher's view
///
/// This is the publishers's end of a bidirectional "channel",
/// containing a shared `PublishIptSet`, i.e. an `Option<IptSet>`.
pub(crate) struct IptsPublisherView {
    /// Actual shared data
    shared: Shared,

    /// Notification receiver
    notify: mpsc::Receiver<()>,
}

/// Shared view of introduction points - IPT publisher's publication-only view
///
/// This is a restricted version of [`IptsPublisherView`]
/// which can only be used to:
///
///   - check that a publication attempt should still continue; and
///   - note publication attempts.
///
/// via the [`.borrow_for_publish()`](IptsPublisherUploadView::borrow_for_publish) method.
///
/// This is useful because multiple `IptsPublisherUploadView`
/// can exist (so, for example, it is `Clone`);
/// unlike `IptsPublisherView`, of which there is one per IPTs channel.
/// So the publisher's individual upload tasks can each have one.
///
/// Obtained from [`IptsPublisherView::upload_view`].
#[derive(Debug, Clone)]
pub(crate) struct IptsPublisherUploadView {
    /// Actual shared data
    shared: Shared,
}

/// Core shared state
type Shared = Arc<Mutex<PublishIptSet>>;

/// Mutex guard that will notify when dropped
///
/// Returned by [`IptsManagerView::borrow_for_update`]
#[derive(Deref, DerefMut)]
struct NotifyingBorrow<'v, R: SleepProvider> {
    /// Lock guard
    #[deref(forward)]
    #[deref_mut(forward)]
    guard: MutexGuard<'v, PublishIptSet>,

    /// To be notified on drop
    notify: &'v mut mpsc::Sender<()>,

    /// For saving!
    #[allow(dead_code)] // XXXX
    runtime: R,
}

/// Create a new shared state channel for the publication instructions
#[allow(clippy::unnecessary_wraps)] // XXXX
pub(crate) fn ipts_channel(
    #[allow(unused_variables)] // XXXX
    runtime: &impl SleepProvider,
    storage: Arc<IptSetStorageHandle>,
) -> Result<(IptsManagerView, IptsPublisherView), StartupError> {
    // TODO HSS-IPT-PERSIST load this from a file instead
    let last_descriptor_expiry_including_slop = HashMap::new();

    let initial_state = PublishIptSet {
        ipts: None,
        last_descriptor_expiry_including_slop,
        storage,
    };
    let shared = Arc::new(Mutex::new(initial_state));
    // Zero buffer is right.  Docs for `mpsc::channel` say:
    //   each sender gets a guaranteed slot in the channel capacity,
    //   and on top of that there are buffer “first come, first serve” slots
    // We only have one sender and only ever want one outstanding,
    // since we can (and would like to) coalesce notifications.
    let (tx, rx) = mpsc::channel(0);
    let r = (
        IptsManagerView {
            shared: shared.clone(),
            notify: tx,
        },
        IptsPublisherView { shared, notify: rx },
    );
    Ok(r)
}

/// Lock the shared state and obtain a lock guard
///
/// Does not do any notification.
fn lock_shared(shared: &Shared) -> MutexGuard<PublishIptSet> {
    // Propagating panics is fine since if either the manager or the publisher crashes,
    // the other one cannot survive.
    shared.lock().expect("IPT set shared state poisoned")
}

impl IptsManagerView {
    /// Arrange to be able to update the list of introduction points
    ///
    /// The manager may add new ipts, or delete old ones.
    ///
    /// The returned value is a lock guard.
    /// (It is not `Send` so cannot be held across await points.)
    /// The publisher will be notified when it is dropped.
    pub(crate) fn borrow_for_update(
        &mut self,
        runtime: impl SleepProvider,
    ) -> impl DerefMut<Target = PublishIptSet> + '_ {
        let guard = lock_shared(&self.shared);
        NotifyingBorrow {
            guard,
            notify: &mut self.notify,
            runtime,
        }
    }

    /// Peek at the list of introduction points we are providing to the publisher
    ///
    /// (Used for testing and during startup.)
    #[allow(dead_code)] // XXXX
    pub(crate) fn borrow_for_read(&mut self) -> impl Deref<Target = PublishIptSet> + '_ {
        lock_shared(&self.shared)
    }
}

impl<R: SleepProvider> Drop for NotifyingBorrow<'_, R> {
    fn drop(&mut self) {
        // Channel full?  Well, then the receiver is indeed going to wake up, so fine
        // Channel disconnected?  The publisher has crashed or terminated,
        // but we are not in a position to fail and shut down the establisher.
        // If our HS is shutting down, the manager will be shut down by other means.
        let _: Result<(), mpsc::TrySendError<_>> = self.notify.try_send(());

        // Now the fields will be dropped, includeing `guard`.
        // I.e. the mutex gets unlocked.  This means we notify the publisher
        // (which might make it wake up on another thread) just *before*
        // we release the lock, rather than just after.
        // This is slightly suboptimal but doesn't matter here.
        // To do better, we'd need to make the guard into an Option.
    }
}

impl IptsPublisherView {
    /// Wait until the IPT set has changed (or may have)
    ///
    /// After this returns, to find out what the new IPT set is,
    /// the publisher calls `borrow_for_publish`.
    ///
    /// Will complete immediately if the IPT set has
    /// changed since the last call to `await_update`.
    ///
    /// Returns:
    ///  * `Some(Ok(())` if the IPT set was (or may have been) updated
    ///  * `None` if the manager is shutting down and the publisher should shut down too
    ///  * `Some(Err(..))` if a fatal error occurred
    pub(crate) async fn await_update(&mut self) -> Option<Result<(), crate::FatalError>> {
        // Cancellation safety:
        //
        // We're using mpsc::Receiver's implementation of Stream, via StreamExt.
        // Stream::next() must be cancellation safe or it would be lossy everywhere.
        // So it is OK to create the future from next, here, and possibly discard it
        // before it becomes Ready.
        let () = self.notify.next().await?;
        Some(Ok(()))
    }

    /// Look at the list of introduction points to publish
    ///
    /// Whenever a a publication attempt is started
    /// [`note_publication_attempt`](PublishIptSet::note_publication_attempt)
    /// must be called on this same [`IptSet`].
    ///
    /// The returned value is a lock guard.
    /// (It is not `Send` so cannot be held across await points.)
    pub(crate) fn borrow_for_publish(&self) -> impl DerefMut<Target = PublishIptSet> + '_ {
        lock_shared(&self.shared)
    }

    /// Obtain an [`IptsPublisherUploadView`], for use just prior to a publication attempt
    pub(crate) fn upload_view(&self) -> IptsPublisherUploadView {
        let shared = self.shared.clone();
        IptsPublisherUploadView { shared }
    }
}

impl IptsPublisherUploadView {
    /// Look at the list of introduction points to publish
    ///
    /// See [`IptsPublisherView::borrow_for_publish`].
    pub(crate) fn borrow_for_publish(&self) -> impl DerefMut<Target = PublishIptSet> + '_ {
        lock_shared(&self.shared)
    }
}

impl PublishIptSet {
    /// Update all the `last_descriptor_expiry_including_slop` for a publication attempt
    ///
    /// Called by the publisher when it starts a publication attempt
    /// which will advertise this set of introduction points.
    ///
    /// When calling this, the publisher promises that the publication attempt
    /// will either complete, or be abandoned, before `worst_case_end`.
    pub(crate) fn note_publication_attempt(
        &mut self,
        #[allow(unused_variables)] // XXXX
        runtime: &impl SleepProvider,
        worst_case_end: Instant,
    ) -> Result<(), IptStoreError> {
        let ipts = self
            .ipts
            .as_ref()
            .ok_or_else(|| internal!("publishing None!"))?;

        let new_value = (|| {
            worst_case_end
                .checked_add(ipts.lifetime)?
                .checked_add(IPT_PUBLISH_EXPIRY_SLOP)
        })()
        .ok_or_else(
            // Clock overflow on the monotonic clock.  Everything is terrible.
            // We will have no idea when we can stop publishing the descriptor!
            // I guess we'll return an error and cause the publisher to bail out?
            // An ErrorKind of ClockSkew is wrong, since this is a purely local problem,
            // and should be impossible if we properly checked our parameters.
            || internal!("monotonic clock overflow"),
        )?;

        for ipt in &ipts.ipts {
            use std::collections::hash_map::Entry;
            let entry = self.last_descriptor_expiry_including_slop.entry(ipt.lid);

            // Open-coding a hypothetical Entry::value()
            let old_value = match &entry {
                Entry::Occupied(oe) => Some(*oe.get()),
                Entry::Vacant(_) => None,
            };

            let to_store = chain!(
                //
                old_value,
                [new_value],
            )
            .max()
            .expect("max of known-non-empty iterator was None");

            // Open-coding Entry::insert(); unstable insert_netry() would do
            match entry {
                Entry::Occupied(mut oe) => {
                    oe.insert(to_store);
                }
                Entry::Vacant(ve) => {
                    ve.insert(to_store);
                }
            };
        }

        // TODO HSS-IPT-PERSIST store last_descriptor_expiry_including_slop

        Ok(())
    }
}

/// Record of intro point publications
#[derive(Serialize, Deserialize, Debug)]
// XXXX populate this struct
pub(crate) struct StateRecord {
}

#[cfg(test)]
mod test {
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
    use crate::svc::test::create_storage_handles;
    use crate::FatalError;
    use futures::{pin_mut, poll};
    use std::task::Poll::{self, *};
    use tor_rtcompat::BlockOn as _;

    fn test_intro_point() -> Ipt {
        use tor_netdoc::doc::hsdesc::test_data;
        test_data::test_parsed_hsdesc().unwrap().intro_points()[0].clone()
    }

    async fn pv_poll_await_update(
        pv: &mut IptsPublisherView,
    ) -> Poll<Option<Result<(), FatalError>>> {
        let fut = pv.await_update();
        pin_mut!(fut);
        poll!(fut)
    }

    async fn pv_expect_one_await_update(pv: &mut IptsPublisherView) {
        assert!(matches!(
            pv_poll_await_update(pv).await,
            Ready(Some(Ok(())))
        ));
        assert!(matches!(pv_poll_await_update(pv).await, Pending));
    }

    fn pv_note_publication_attempt(
        runtime: &impl SleepProvider,
        pv: &IptsPublisherView,
        worst_case_end: Instant,
    ) {
        pv.borrow_for_publish()
            .note_publication_attempt(runtime, worst_case_end)
            .unwrap();
    }

    fn mv_get_0_expiry(mv: &mut IptsManagerView) -> Instant {
        let g = mv.borrow_for_read();
        let lid = g.ipts.as_ref().unwrap().ipts[0].lid;
        *g.last_descriptor_expiry_including_slop.get(&lid).unwrap()
    }

    #[test]
    fn test() {
        // We don't bother with MockRuntime::test_with_various
        // since this test case doesn't spawn tasks
        let runtime = tor_rtmock::MockRuntime::new();
        runtime.clone().block_on(async move {
            // make a channel; it should have no updates yet

            let (_state_mgr, iptpub_state_handle) = create_storage_handles();
            let (mut mv, mut pv) = ipts_channel(&runtime, iptpub_state_handle).unwrap();
            assert!(matches!(pv_poll_await_update(&mut pv).await, Pending));

            // borrowing publisher view for publish doesn't cause an update

            let pg = pv.borrow_for_publish();
            assert!(pg.ipts.is_none());
            drop(pg);

            let uv = pv.upload_view();
            let pg = uv.borrow_for_publish();
            assert!(pg.ipts.is_none());
            drop(pg);

            // borrowing manager view for update *does* cause one update

            let mut mg = mv.borrow_for_update(runtime.clone());
            mg.ipts = Some(IptSet {
                ipts: vec![],
                lifetime: Duration::ZERO,
            });
            drop(mg);

            pv_expect_one_await_update(&mut pv).await;

            // borrowing manager view for update twice cause one update

            const LIFETIME: Duration = Duration::from_secs(1800);
            const PUBLISH_END_TIMEOUT: Duration = Duration::from_secs(300);

            mv.borrow_for_update(runtime.clone())
                .ipts
                .as_mut()
                .unwrap()
                .lifetime = LIFETIME;
            mv.borrow_for_update(runtime.clone())
                .ipts
                .as_mut()
                .unwrap()
                .ipts
                .push(IptInSet {
                    ipt: test_intro_point(),
                    lid: IptLocalId([42; 32]),
                });

            pv_expect_one_await_update(&mut pv).await;

            // test setting lifetime

            pv_note_publication_attempt(&runtime, &pv, runtime.now() + PUBLISH_END_TIMEOUT);

            let expected_expiry =
                runtime.now() + PUBLISH_END_TIMEOUT + LIFETIME + IPT_PUBLISH_EXPIRY_SLOP;
            assert_eq!(mv_get_0_expiry(&mut mv), expected_expiry);

            // setting an *earlier* lifetime is ignored

            pv_note_publication_attempt(&runtime, &pv, runtime.now() - Duration::from_secs(10));
            assert_eq!(mv_get_0_expiry(&mut mv), expected_expiry);
        });
    }
}

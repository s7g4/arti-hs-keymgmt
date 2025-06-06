//! Define a [`CompoundRuntime`] part that can be built from several component
//! pieces.

use std::{net, sync::Arc, time::Duration};

use crate::traits::*;
use crate::{CoarseInstant, CoarseTimeProvider};
use async_trait::async_trait;
use educe::Educe;
use futures::{future::FutureObj, task::Spawn};
use std::future::Future;
use std::io::Result as IoResult;
use std::time::{Instant, SystemTime};
use tor_general_addr::unix;

/// A runtime made of several parts, each of which implements one trait-group.
///
/// The `TaskR` component should implement [`Spawn`], [`Blocking`] and maybe [`ToplevelBlockOn`];
/// the `SleepR` component should implement [`SleepProvider`];
/// the `CoarseTimeR` component should implement [`CoarseTimeProvider`];
/// the `TcpR` component should implement [`NetStreamProvider`] for [`net::SocketAddr`];
/// the `UnixR` component should implement [`NetStreamProvider`] for [`unix::SocketAddr`];
/// and
/// the `TlsR` component should implement [`TlsProvider`].
///
/// You can use this structure to create new runtimes in two ways: either by
/// overriding a single part of an existing runtime, or by building an entirely
/// new runtime from pieces.
#[derive(Educe)]
#[educe(Clone)] // #[derive(Clone)] wrongly infers Clone bounds on the generic parameters
pub struct CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> {
    /// The actual collection of Runtime objects.
    ///
    /// We wrap this in an Arc rather than requiring that each item implement
    /// Clone, though we could change our minds later on.
    inner: Arc<Inner<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>>,
}

/// A collection of objects implementing that traits that make up a [`Runtime`]
struct Inner<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> {
    /// A `Spawn` and `BlockOn` implementation.
    spawn: TaskR,
    /// A `SleepProvider` implementation.
    sleep: SleepR,
    /// A `CoarseTimeProvider`` implementation.
    coarse_time: CoarseTimeR,
    /// A `NetStreamProvider<net::SocketAddr>` implementation
    tcp: TcpR,
    /// A `NetStreamProvider<unix::SocketAddr>` implementation.
    unix: UnixR,
    /// A `TlsProvider<TcpR::TcpStream>` implementation.
    tls: TlsR,
    /// A `UdpProvider` implementation
    udp: UdpR,
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
    CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
{
    /// Construct a new CompoundRuntime from its components.
    pub fn new(
        spawn: TaskR,
        sleep: SleepR,
        coarse_time: CoarseTimeR,
        tcp: TcpR,
        unix: UnixR,
        tls: TlsR,
        udp: UdpR,
    ) -> Self {
        #[allow(clippy::arc_with_non_send_sync)]
        CompoundRuntime {
            inner: Arc::new(Inner {
                spawn,
                sleep,
                coarse_time,
                tcp,
                unix,
                tls,
                udp,
            }),
        }
    }
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> Spawn
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    TaskR: Spawn,
{
    #[inline]
    #[track_caller]
    fn spawn_obj(&self, future: FutureObj<'static, ()>) -> Result<(), futures::task::SpawnError> {
        self.inner.spawn.spawn_obj(future)
    }
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> Blocking
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    TaskR: Blocking,
    SleepR: Clone + Send + Sync + 'static,
    CoarseTimeR: Clone + Send + Sync + 'static,
    TcpR: Clone + Send + Sync + 'static,
    UnixR: Clone + Send + Sync + 'static,
    TlsR: Clone + Send + Sync + 'static,
    UdpR: Clone + Send + Sync + 'static,
{
    type ThreadHandle<T: Send + 'static> = TaskR::ThreadHandle<T>;

    #[inline]
    #[track_caller]
    fn spawn_blocking<F, T>(&self, f: F) -> TaskR::ThreadHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.inner.spawn.spawn_blocking(f)
    }

    #[inline]
    #[track_caller]
    fn reenter_block_on<F>(&self, future: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.inner.spawn.reenter_block_on(future)
    }

    #[track_caller]
    fn blocking_io<F, T>(&self, f: F) -> impl futures::Future<Output = T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.inner.spawn.blocking_io(f)
    }
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> ToplevelBlockOn
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    TaskR: ToplevelBlockOn,
    SleepR: Clone + Send + Sync + 'static,
    CoarseTimeR: Clone + Send + Sync + 'static,
    TcpR: Clone + Send + Sync + 'static,
    UnixR: Clone + Send + Sync + 'static,
    TlsR: Clone + Send + Sync + 'static,
    UdpR: Clone + Send + Sync + 'static,
{
    #[inline]
    #[track_caller]
    fn block_on<F: futures::Future>(&self, future: F) -> F::Output {
        self.inner.spawn.block_on(future)
    }
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> SleepProvider
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    SleepR: SleepProvider,
    TaskR: Clone + Send + Sync + 'static,
    CoarseTimeR: Clone + Send + Sync + 'static,
    TcpR: Clone + Send + Sync + 'static,
    UnixR: Clone + Send + Sync + 'static,
    TlsR: Clone + Send + Sync + 'static,
    UdpR: Clone + Send + Sync + 'static,
{
    type SleepFuture = SleepR::SleepFuture;

    #[inline]
    fn sleep(&self, duration: Duration) -> Self::SleepFuture {
        self.inner.sleep.sleep(duration)
    }

    #[inline]
    fn now(&self) -> Instant {
        self.inner.sleep.now()
    }

    #[inline]
    fn wallclock(&self) -> SystemTime {
        self.inner.sleep.wallclock()
    }
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> CoarseTimeProvider
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    CoarseTimeR: CoarseTimeProvider,
    SleepR: Clone + Send + Sync + 'static,
    TaskR: Clone + Send + Sync + 'static,
    CoarseTimeR: Clone + Send + Sync + 'static,
    TcpR: Clone + Send + Sync + 'static,
    UnixR: Clone + Send + Sync + 'static,
    TlsR: Clone + Send + Sync + 'static,
    UdpR: Clone + Send + Sync + 'static,
{
    #[inline]
    fn now_coarse(&self) -> CoarseInstant {
        self.inner.coarse_time.now_coarse()
    }
}

#[async_trait]
impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> NetStreamProvider<net::SocketAddr>
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    TcpR: NetStreamProvider<net::SocketAddr>,
    TaskR: Send + Sync + 'static,
    SleepR: Send + Sync + 'static,
    CoarseTimeR: Send + Sync + 'static,
    TcpR: Send + Sync + 'static,
    UnixR: Clone + Send + Sync + 'static,
    TlsR: Send + Sync + 'static,
    UdpR: Send + Sync + 'static,
{
    type Stream = TcpR::Stream;

    type Listener = TcpR::Listener;

    #[inline]
    async fn connect(&self, addr: &net::SocketAddr) -> IoResult<Self::Stream> {
        self.inner.tcp.connect(addr).await
    }

    #[inline]
    async fn listen(&self, addr: &net::SocketAddr) -> IoResult<Self::Listener> {
        self.inner.tcp.listen(addr).await
    }
}

#[async_trait]
impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> NetStreamProvider<unix::SocketAddr>
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    UnixR: NetStreamProvider<unix::SocketAddr>,
    TaskR: Send + Sync + 'static,
    SleepR: Send + Sync + 'static,
    CoarseTimeR: Send + Sync + 'static,
    TcpR: Send + Sync + 'static,
    UnixR: Clone + Send + Sync + 'static,
    TlsR: Send + Sync + 'static,
    UdpR: Send + Sync + 'static,
{
    type Stream = UnixR::Stream;

    type Listener = UnixR::Listener;

    #[inline]
    async fn connect(&self, addr: &unix::SocketAddr) -> IoResult<Self::Stream> {
        self.inner.unix.connect(addr).await
    }

    #[inline]
    async fn listen(&self, addr: &unix::SocketAddr) -> IoResult<Self::Listener> {
        self.inner.unix.listen(addr).await
    }
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR, S> TlsProvider<S>
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    TcpR: NetStreamProvider,
    TlsR: TlsProvider<S>,
    UnixR: Clone + Send + Sync + 'static,
    SleepR: Clone + Send + Sync + 'static,
    CoarseTimeR: Clone + Send + Sync + 'static,
    TaskR: Clone + Send + Sync + 'static,
    UdpR: Clone + Send + Sync + 'static,
    S: StreamOps,
{
    type Connector = TlsR::Connector;
    type TlsStream = TlsR::TlsStream;

    #[inline]
    fn tls_connector(&self) -> Self::Connector {
        self.inner.tls.tls_connector()
    }

    #[inline]
    fn supports_keying_material_export(&self) -> bool {
        self.inner.tls.supports_keying_material_export()
    }
}

impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> std::fmt::Debug
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompoundRuntime").finish_non_exhaustive()
    }
}

#[async_trait]
impl<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR> UdpProvider
    for CompoundRuntime<TaskR, SleepR, CoarseTimeR, TcpR, UnixR, TlsR, UdpR>
where
    UdpR: UdpProvider,
    TaskR: Send + Sync + 'static,
    SleepR: Send + Sync + 'static,
    CoarseTimeR: Send + Sync + 'static,
    TcpR: Send + Sync + 'static,
    UnixR: Clone + Send + Sync + 'static,
    TlsR: Send + Sync + 'static,
    UdpR: Send + Sync + 'static,
{
    type UdpSocket = UdpR::UdpSocket;

    #[inline]
    async fn bind(&self, addr: &net::SocketAddr) -> IoResult<Self::UdpSocket> {
        self.inner.udp.bind(addr).await
    }
}

/// Module to seal RuntimeSubstExt
mod sealed {
    /// Helper for sealing RuntimeSubstExt
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}
/// Extension trait on Runtime:
/// Construct new Runtimes that replace part of an original runtime.
///
/// (If you need to do more complicated versions of this, you should likely construct
/// CompoundRuntime directly.)
pub trait RuntimeSubstExt: sealed::Sealed + Sized {
    /// Return a new runtime wrapping this runtime, but replacing its TCP NetStreamProvider.
    fn with_tcp_provider<T>(
        &self,
        new_tcp: T,
    ) -> CompoundRuntime<Self, Self, Self, T, Self, Self, Self>;
    /// Return a new runtime wrapping this runtime, but replacing its SleepProvider.
    fn with_sleep_provider<T>(
        &self,
        new_sleep: T,
    ) -> CompoundRuntime<Self, T, Self, Self, Self, Self, Self>;
    /// Return a new runtime wrapping this runtime, but replacing its CoarseTimeProvider.
    fn with_coarse_time_provider<T>(
        &self,
        new_coarse_time: T,
    ) -> CompoundRuntime<Self, Self, T, Self, Self, Self, Self>;
}
impl<R: Runtime> sealed::Sealed for R {}
impl<R: Runtime + Sized> RuntimeSubstExt for R {
    fn with_tcp_provider<T>(
        &self,
        new_tcp: T,
    ) -> CompoundRuntime<Self, Self, Self, T, Self, Self, Self> {
        CompoundRuntime::new(
            self.clone(),
            self.clone(),
            self.clone(),
            new_tcp,
            self.clone(),
            self.clone(),
            self.clone(),
        )
    }

    fn with_sleep_provider<T>(
        &self,
        new_sleep: T,
    ) -> CompoundRuntime<Self, T, Self, Self, Self, Self, Self> {
        CompoundRuntime::new(
            self.clone(),
            new_sleep,
            self.clone(),
            self.clone(),
            self.clone(),
            self.clone(),
            self.clone(),
        )
    }

    fn with_coarse_time_provider<T>(
        &self,
        new_coarse_time: T,
    ) -> CompoundRuntime<Self, Self, T, Self, Self, Self, Self> {
        CompoundRuntime::new(
            self.clone(),
            self.clone(),
            new_coarse_time,
            self.clone(),
            self.clone(),
            self.clone(),
            self.clone(),
        )
    }
}

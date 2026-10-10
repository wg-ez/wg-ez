#![forbid(unsafe_code)]

//! In-process live-status watcher backing the topbar count + grid long-poll.
//!
//! One background loop polls [`Backend::status_signal`] and pushes a `watch`
//! generation on meaningful changes: connection-state changes (peer set,
//! endpoint, handshake, `connected`) fire on the tick that observes them,
//! while byte-counter churn is coalesced to at most one push per
//! [`TRAFFIC_REFRESH`]. Each tick caches the connected-peer count, read by the
//! long-poll to render the live topbar count even on timeout. Every open page
//! holds a [`Subscription`] while its request is parked; once the count drops
//! to zero the loop runs for [`IDLE_GRACE`] then stops, so no `wg` process is
//! spawned while no page is open.
//!
//! Probe cadence is adaptive: [`POLL_INTERVAL`] (5 s) while a change was seen
//! within [`ACTIVE_WINDOW`], backing off to [`IDLE_POLL_INTERVAL`] (30 s) once
//! the tunnel has been quiet that long; the first observed change snaps back
//! to 5 s.
//!
//! Design constraints:
//! - single-thread runtime: one future on the `current_thread` executor, no
//!   dedicated thread; blocking `wg` stays in the backend;
//! - no new dependency: `tokio::sync::watch` + `tokio::time::sleep`;
//! - one `wg` probe per tick shared by every subscriber, never one per page;
//! - concurrent parked requests are capped ([`MAX_STREAMS`] global,
//!   [`MAX_STREAMS_PER_IP`] per origin), slots released by a RAII
//!   [`Subscription`] guard, so a session bearer can neither exhaust fds nor
//!   starve the single worker.

use std::{
    collections::HashMap,
    net::IpAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use tokio::sync::watch;
use tokio::task::JoinHandle;

use super::ctx::Backend;

/// Active probe cadence. WireGuard exposes no change notification (no netlink
/// multicast group upstream), so `wg show … dump` is polled; 5 s matches the
/// historical v15 grid refresh and is used while the tunnel is changing.
pub const POLL_INTERVAL: Duration = Duration::from_secs(5);
/// Backed-off cadence once nothing has moved for [`ACTIVE_WINDOW`]: an idle
/// tunnel still gets its connected count refreshed, but the per-tick `wg`
/// process spawn drops from every 5 s to every 30 s. Any observed change
/// resets the cadence to [`POLL_INTERVAL`].
pub const IDLE_POLL_INTERVAL: Duration = Duration::from_secs(30);
/// How long the loop stays on the fast cadence after the last push. Longer
/// than the ~2 min WireGuard rekey keeps an active session live, while a
/// genuinely quiet page settles to the idle cadence.
pub const ACTIVE_WINDOW: Duration = Duration::from_secs(30);
/// Keep the loop alive this long after the last subscriber leaves, so the
/// htmx re-arm gap never misses an update (avoids the abort/respawn thrash).
pub const IDLE_GRACE: Duration = Duration::from_secs(30);
/// Traffic-counter-only changes are coalesced to at most one push per this
/// window. Byte counters move on every packet, so pushing them faster than
/// [`POLL_INTERVAL`] would turn the long-poll into a poll.
pub const TRAFFIC_REFRESH: Duration = Duration::from_secs(5);

/// Maximum concurrent long-poll subscriptions over the whole process. Never
/// let a session bearer park an unbounded number of `GET /api/status/stream`
/// requests: each parked request costs a socket + a `watch` receiver, and the
/// single-thread runtime would starve. At the cap the handler answers `429`
/// instead of holding the connection.
pub const MAX_STREAMS: usize = 64;

/// Maximum concurrent long-poll subscriptions from a single client IP, so one
/// origin cannot occupy every global slot. The slot table is bounded by
/// [`MAX_STREAMS`], so this adds no unbounded memory either.
pub const MAX_STREAMS_PER_IP: usize = 10;

/// Probe cadence for the next tick, from the time elapsed since the last push:
/// fast while changes are recent, backed off once the tunnel has been quiet for
/// [`ACTIVE_WINDOW`].
fn next_interval(since_last_push: Duration) -> Duration {
    if since_last_push >= ACTIVE_WINDOW {
        IDLE_POLL_INTERVAL
    } else {
        POLL_INTERVAL
    }
}

/// Decides when an observed [`super::ctx::StatusSignal`] deserves a push:
/// connection-state changes always fire at once; traffic-only changes fire at
/// most once per [`TRAFFIC_REFRESH`]. The first observation only seeds, since
/// the page that just subscribed already rendered a fresh grid.
struct PushGate {
    last_state: Option<u64>,
    last_traffic: Option<u64>,
    last_sent: Instant,
}

impl PushGate {
    fn new(now: Instant) -> Self {
        Self {
            last_state: None,
            last_traffic: None,
            last_sent: now,
        }
    }

    /// Record an observation; `true` when subscribers must be woken now.
    fn observe(&mut self, state: u64, traffic: u64, now: Instant) -> bool {
        let first = self.last_state.is_none();
        let state_changed = self.last_state.is_some_and(|prev| prev != state);
        let traffic_changed = self.last_traffic.is_some_and(|prev| prev != traffic);
        self.last_state = Some(state);
        self.last_traffic = Some(traffic);
        let traffic_due = traffic_changed && now.duration_since(self.last_sent) >= TRAFFIC_REFRESH;
        if state_changed || (!first && traffic_due) {
            self.last_sent = now;
            true
        } else {
            false
        }
    }
}

struct Inner<B: Backend> {
    backend: Arc<B>,
    /// Bumped generation; subscribers wake from `changed()`.
    tx: watch::Sender<u64>,
    /// Latest connected-peer count, refreshed on every loop tick (even when
    /// it does not warrant a push). The long-poll reads it to render the
    /// live topbar count without a second `wg` probe.
    connected: AtomicU64,
    /// Active long-poll requests.
    subs: AtomicUsize,
    /// Per-IP active subscription counts. Guarded so the global and per-IP
    /// caps are checked and their slots reserved/released atomically. It can
    /// never hold more than [`MAX_STREAMS`] entries.
    streams: Mutex<HashMap<IpAddr, usize>>,
    /// The single watcher task, if any.
    task: Mutex<Option<JoinHandle<()>>>,
}

impl<B: Backend> Inner<B> {
    fn lock_task(&self) -> std::sync::MutexGuard<'_, Option<JoinHandle<()>>> {
        // A poisoned lock only means a previous holder panicked; the guard
        // content is a `JoinHandle` with no invariant to protect.
        self.task.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn lock_streams(&self) -> std::sync::MutexGuard<'_, HashMap<IpAddr, usize>> {
        // A poisoned lock only means a previous holder panicked; the map is
        // rebuilt from scratch by the next subscribe/drop pair.
        self.streams.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Cloneable handle stored in [`super::ctx::AppState`].
pub struct StatusWatcher<B: Backend> {
    inner: Arc<Inner<B>>,
}

impl<B: Backend> Clone for StatusWatcher<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<B: Backend> StatusWatcher<B> {
    pub fn new(backend: Arc<B>) -> Self {
        let (tx, _rx) = watch::channel(0);
        Self {
            inner: Arc::new(Inner {
                backend,
                tx,
                connected: AtomicU64::new(0),
                subs: AtomicUsize::new(0),
                streams: Mutex::new(HashMap::new()),
                task: Mutex::new(None),
            }),
        }
    }

    /// Register a long-poll request from `ip`, starting the loop if it is not
    /// already running. Returns `None` when the global ([`MAX_STREAMS`]) or
    /// per-IP ([`MAX_STREAMS_PER_IP`]) cap is already reached, so the caller
    /// can answer `429` without parking the connection. Drop the guard
    /// (request ends) to release both slots; a failed subscribe reserves
    /// nothing.
    pub fn subscribe(&self, ip: IpAddr) -> Option<Subscription<B>> {
        {
            // Check + reserve under one lock so concurrent claims cannot both
            // pass a cap, and so the per-IP map can never outgrow the global
            // bound (`subs` is only mutated while this lock is held).
            let mut counts = self.inner.lock_streams();
            if self.inner.subs.load(Ordering::Relaxed) >= MAX_STREAMS {
                return None;
            }
            let held = counts.get(&ip).copied().unwrap_or(0);
            if held >= MAX_STREAMS_PER_IP {
                return None;
            }
            self.inner.subs.fetch_add(1, Ordering::Relaxed);
            *counts.entry(ip).or_insert(0) += 1;
        }
        self.ensure_running();
        Some(Subscription {
            inner: self.inner.clone(),
            rx: self.inner.tx.subscribe(),
            ip,
        })
    }

    fn ensure_running(&self) {
        let mut guard = self.inner.lock_task();
        let alive = guard.as_ref().is_some_and(|h| !h.is_finished());
        if !alive {
            let weak = Arc::downgrade(&self.inner);
            *guard = Some(tokio::spawn(run_loop(weak)));
        }
    }
}

/// RAII subscription: keeps the loop alive while a request is parked.
pub struct Subscription<B: Backend> {
    inner: Arc<Inner<B>>,
    rx: watch::Receiver<u64>,
    /// Owning client IP, released on Drop alongside the global slot.
    ip: IpAddr,
}

impl<B: Backend> Subscription<B> {
    /// Resolves at the next status change; `Err` only when the watcher drops.
    pub async fn changed(&mut self) -> Result<(), watch::error::RecvError> {
        self.rx.changed().await
    }

    /// Latest connected-peer count observed by the watcher loop. Read after
    /// [`Self::changed`] (or on timeout) to render the live topbar count.
    pub fn connected(&self) -> u64 {
        self.inner.connected.load(Ordering::Relaxed)
    }
}

impl<B: Backend> Drop for Subscription<B> {
    fn drop(&mut self) {
        let mut counts = self.inner.lock_streams();
        self.inner.subs.fetch_sub(1, Ordering::Relaxed);
        if let Some(held) = counts.get_mut(&self.ip) {
            *held = held.saturating_sub(1);
            if *held == 0 {
                // Do not leak an entry per closed stream: the map stays
                // bounded by the number of IPs actually parked.
                counts.remove(&self.ip);
            }
        }
    }
}

/// The single watcher loop. Holds a `Weak` so it never keeps the watcher
/// alive past its owner; exits [`IDLE_GRACE`] after the last subscriber.
async fn run_loop<B: Backend>(weak: Weak<Inner<B>>) {
    let mut generation: u64 = 0;
    let mut gate = PushGate::new(Instant::now());
    let mut idle_since: Option<Instant> = None;
    let mut last_push = Instant::now();
    let mut was_subscribed = false;
    loop {
        let Some(inner) = weak.upgrade() else {
            return;
        };
        let subscribed = inner.subs.load(Ordering::Relaxed) > 0;

        if subscribed {
            // A page that just re-armed must get a prompt probe even if the
            // tunnel had gone idle while another page held the loop.
            if !was_subscribed {
                last_push = Instant::now();
            }
            if let Ok(sig) = inner.backend.status_signal().await {
                // Cache the count on every probe, independently of the push
                // gate: the long-poll may answer on timeout without a state
                // change.
                inner.connected.store(sig.connected, Ordering::Relaxed);
                if gate.observe(sig.state, sig.traffic, Instant::now()) {
                    generation = generation.wrapping_add(1);
                    let _ = inner.tx.send(generation);
                    last_push = Instant::now();
                }
            }
            idle_since = None;
        } else {
            // No page parked: do not spawn `wg` at all, just watch the grace
            // timer (a re-arm within [`IDLE_GRACE`] wakes the probe again).
            match idle_since {
                None => idle_since = Some(Instant::now()),
                Some(t) if t.elapsed() >= IDLE_GRACE => return,
                Some(_) => {}
            }
        }

        was_subscribed = subscribed;
        let interval = if subscribed {
            next_interval(last_push.elapsed())
        } else {
            POLL_INTERVAL
        };
        tokio::time::sleep(interval).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::web::router::TestBackend;

    fn watcher() -> StatusWatcher<TestBackend> {
        StatusWatcher::new(Arc::new(TestBackend::default()))
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, last])
    }

    #[test]
    fn push_gate_coalesces_traffic_but_not_state() {
        let t0 = Instant::now();
        let mut gate = PushGate::new(t0);

        // First observation only seeds: the freshly rendered page is current.
        assert!(!gate.observe(1, 10, t0));

        // Traffic moved, but the refresh window (5 s) has not elapsed.
        assert!(!gate.observe(1, 11, t0 + Duration::from_secs(1)));
        // Traffic still moving; window elapsed -> one coalesced push.
        assert!(gate.observe(1, 12, t0 + Duration::from_secs(6)));
        // Right after a push, traffic churn is quiet again.
        assert!(!gate.observe(1, 13, t0 + Duration::from_secs(7)));

        // A connection-state change fires immediately, window or not.
        assert!(gate.observe(2, 13, t0 + Duration::from_secs(8)));

        // Stable state/traffic never wakes anyone.
        assert!(!gate.observe(2, 13, t0 + Duration::from_secs(60)));
        assert!(!gate.observe(2, 13, t0 + Duration::from_secs(120)));
    }

    #[test]
    fn interval_backs_off_when_quiet_and_snaps_back_on_activity() {
        // Recent push -> fast cadence.
        assert_eq!(next_interval(Duration::ZERO), POLL_INTERVAL);
        assert_eq!(
            next_interval(ACTIVE_WINDOW - Duration::from_secs(1)),
            POLL_INTERVAL
        );
        // Quiet for the whole window -> backed off.
        assert_eq!(next_interval(ACTIVE_WINDOW), IDLE_POLL_INTERVAL);
        assert_eq!(next_interval(ACTIVE_WINDOW * 10), IDLE_POLL_INTERVAL);
    }

    /// M5: the global cap refuses the slot past `MAX_STREAMS` and a Dropped
    /// subscription returns its slot so a later claim succeeds again.
    #[tokio::test]
    async fn subscribe_refuses_over_global_cap_and_frees_on_drop() {
        let w = watcher();
        let mut held = Vec::new();
        // Distinct IPs so the smaller per-IP cap never triggers first.
        for i in 0..MAX_STREAMS {
            held.push(
                w.subscribe(ip(i as u8 + 1))
                    .unwrap_or_else(|| panic!("global slot {i} must be granted")),
            );
        }
        assert!(
            w.subscribe(ip(200)).is_none(),
            "the (MAX_STREAMS+1)-th stream must be refused"
        );
        // Ending one stream frees exactly one global slot.
        held.pop();
        assert!(
            w.subscribe(ip(200)).is_some(),
            "a freed global slot must be reusable"
        );
    }

    /// M5: the per-IP cap is independent of the global one and of another IP.
    #[tokio::test]
    async fn subscribe_enforces_per_ip_cap_independently() {
        let w = watcher();
        let (a, b) = (ip(1), ip(2));
        let mut held = Vec::new();
        for _ in 0..MAX_STREAMS_PER_IP {
            held.push(
                w.subscribe(a)
                    .expect("per-IP slots must be granted up to the cap"),
            );
        }
        assert!(
            w.subscribe(a).is_none(),
            "one IP must not exceed the per-IP cap"
        );
        // A different origin still gets a slot: the cap is per-IP, not global.
        let other = w
            .subscribe(b)
            .expect("another IP must be unaffected by a saturating origin");
        drop(other);
        // Dropping one of `a`'s streams frees exactly one per-IP slot.
        held.pop();
        assert!(
            w.subscribe(a).is_some(),
            "freed per-IP slot must be reusable"
        );
    }

    /// M5: `MAX_STREAMS+1` strictly sequential claim/release cycles all
    /// succeed on one IP, proving every Drop returned both its global and its
    /// per-IP slot (no leak at the end of a flux).
    #[tokio::test]
    async fn sequential_subscriptions_never_leak_a_slot() {
        let w = watcher();
        let a = ip(7);
        for i in 0..=MAX_STREAMS {
            let sub = w
                .subscribe(a)
                .unwrap_or_else(|| panic!("sequential cycle {i} leaked a slot"));
            drop(sub);
        }
    }
}

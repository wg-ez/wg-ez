#![forbid(unsafe_code)]

//! Shared request state: pending 2FA logins, rate limits, `AppState`, and
//! trusted-proxy client-IP resolution.

use std::{
    collections::{HashMap, VecDeque},
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

use ipnet::IpNet;
use tokio::sync::Mutex;

use super::backend_trait::Backend;
use super::locales::Locales;
use crate::web::watcher::StatusWatcher;

/// Opaque pending-2FA login (5 min, server memory only, never in a cookie).
#[derive(Debug, Clone)]
pub struct PendingLogin {
    pub user_id: i64,
    pub username: String,
    pub expires_at: Instant,
    /// Wrong TOTP codes already submitted for this pending. The entry is
    /// **not** dropped on a failure unless this budget is exhausted, so a
    /// typo can be retried while a known pending id cannot be brute-forced
    /// past the threshold (M2).
    pub failed_attempts: u32,
}

impl PendingLogin {
    /// Wrong codes tolerated before the pending is invalidated. Chosen so
    /// the coarse login rate-limit is not the only bound and a
    /// legitimately mistyped code is retryable.
    pub const MAX_FAILED_ATTEMPTS: u32 = 5;

    /// Record one wrong TOTP code. Returns `true` once the attempt budget is
    /// exhausted, meaning the pending must now be dropped.
    pub fn register_failure(&mut self) -> bool {
        self.failed_attempts = self.failed_attempts.saturating_add(1);
        self.failed_attempts >= Self::MAX_FAILED_ATTEMPTS
    }
}

/// Strict upper bound on the in-memory pending-2FA map. Random 128-bit ids
/// cannot realistically collide, so without a cap a flood of `password`
/// requests on a 2FA account could grow the map (and RSS) until every entry's
/// 5-min TTL expires. Mirrors [`MAX_RATE_BUCKETS`] in spirit: the map never
/// grows past the bound.
pub const MAX_PENDING: usize = 4096;

/// Insert `entry` under `id`, first evicting the entry that expires soonest
/// when the map is already at [`MAX_PENDING`].
///
/// Callers must have pruned the expired entries first (`retain`), so evicting
/// the earliest `expires_at` drops the least-useful legitimate pending. Kept
/// as a free function (not a method) so the bound is unit-testable without a
/// live router.
pub fn insert_pending(map: &mut HashMap<String, PendingLogin>, id: String, entry: PendingLogin) {
    if map.len() >= MAX_PENDING && !map.contains_key(&id) {
        let victim = map
            .iter()
            .min_by_key(|(_, p)| p.expires_at)
            .map(|(k, _)| k.clone());
        if let Some(k) = victim {
            map.remove(&k);
        }
    }
    map.insert(id, entry);
}

/// In-memory rate limiter: sliding window of attempt instants per key.
///
/// The password login keeps **two** independent windows (M1): a fine one per
/// `(IP, username)` and a coarse one per IP. Without the per-account key, a
/// deployment behind an undeclared reverse proxy (empty `TRUSTED_PROXIES`)
/// would resolve every request to the proxy IP, so ten failures on any
/// account locked out **every** user of the instance. The coarse per-IP
/// bucket still bounds credential spraying across many usernames.
#[derive(Debug, Default)]
pub struct RateLimits {
    /// Coarse login bound, per IP (shared with `verify-2fa`, see the handler).
    login: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    /// Fine login bound, per `(IP, trimmed username)`.
    login_user: Mutex<HashMap<(IpAddr, String), VecDeque<Instant>>>,
    /// `GET /api/auth/pending` bound, per IP. Independent from `login` so a
    /// flood of pending-existence probes cannot exhaust the login budget (or
    /// vice versa); the route is a public oracle of pending-id validity, so it
    /// needs its own dedicated window.
    pending: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    cnf: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    /// `/metrics/*` **failed** Bearer checks only: successes are never
    /// recorded because a working scraper polls continuously and must never
    /// be throttled.
    metrics: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    setup: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    /// Bearer-credential **failures** only: successes are never recorded
    /// because the token is sent on every API request and a legitimate
    /// polling client must never be throttled.
    credential: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
    /// Authenticated tunnel **mutations** (client/admin POST|DELETE that run a
    /// full `Tunnel::apply`: `render` + conf write + `wg syncconf` + firewall
    /// rebuild). Independent from every other bucket.
    mutate: Mutex<HashMap<IpAddr, VecDeque<Instant>>>,
}

/// Above this many distinct buckets, each `check` prunes stale/empty ones
/// so a spoofed-IP (or spoofed-username) flood can never grow the maps
/// without bound.
const MAX_RATE_BUCKETS: usize = 4096;

/// Keep `map` strictly bounded by [`MAX_RATE_BUCKETS`].
///
/// First prune every expired window (and drop now-empty buckets) — the cheap
/// path that reclaims an ordinary burst spread over time. But a burst of more
/// than `MAX_RATE_BUCKETS` **distinct fresh keys inside a single window**
/// leaves nothing expired to reclaim, so the prune alone would let the map
/// grow until those windows age out. To make the bound strict we then evict
/// the least-recently-used buckets — `VecDeque` keeps instants in push order,
/// so its `back` is a bucket's most recent use — until we are back under the
/// bound.
///
/// Trade-off: an attacker holding a very large number of **real** IPs (the
/// `X-Forwarded-For` chain is not spoofable unless the request comes from a
/// declared `TRUSTED_PROXIES` hop) can evict *another* bucket by aging it out.
/// That is acceptable: per-IP limiting is weak against a botnet anyway, and the
/// bound is what protects process RSS from an unbounded map.
fn bound_buckets<K>(map: &mut HashMap<K, VecDeque<Instant>>, now: Instant, window: Duration)
where
    K: Eq + std::hash::Hash + Clone,
{
    if map.len() <= MAX_RATE_BUCKETS {
        return;
    }
    map.retain(|_, q| {
        while q.front().is_some_and(|t| now.duration_since(*t) > window) {
            q.pop_front();
        }
        !q.is_empty()
    });
    while map.len() > MAX_RATE_BUCKETS {
        let victim = map
            .iter()
            .min_by_key(|(_, q)| q.back().copied())
            .map(|(k, _)| k.clone());
        match victim {
            Some(k) => {
                map.remove(&k);
            }
            // Every remaining bucket is non-empty (`retain` above), so this is
            // unreachable; bail rather than loop forever if it ever is not.
            None => break,
        }
    }
}

/// Fine password-login bound: attempts per `(IP, username)` per minute.
const LOGIN_USER_MAX: usize = 10;
/// Coarse password-login bound: attempts per IP per minute, all usernames
/// confounded, to bound credential spraying from one origin.
const LOGIN_IP_MAX: usize = 50;
/// `GET /api/auth/pending` bound: 60/min/IP. Independent from the login
/// buckets so probing pending-id validity (a public oracle) can neither lock
/// a user out of login nor be masked by an unrelated login budget.
const PENDING_MAX: usize = 60;
/// Authenticated tunnel-mutation bound: 120/min/IP (2/s). Deliberately
/// generous so legitimate bulk editing and the 270-check parity audit are
/// never throttled, yet tight enough to bound a valid principal looping the
/// full `Tunnel::apply` path on the single-threaded runtime.
const MUTATE_MAX: usize = 120;

impl RateLimits {
    /// Allow up to `max` attempts per `window`. Returns false on excess.
    /// Generic over the bucket key so the same memory-hardened sliding window
    /// serves both per-IP and per-`(IP, username)` maps.
    async fn check<K>(
        bucket: &Mutex<HashMap<K, VecDeque<Instant>>>,
        key: K,
        max: usize,
        window: Duration,
    ) -> bool
    where
        K: Eq + std::hash::Hash + Clone,
    {
        let mut map = bucket.lock().await;
        let now = Instant::now();
        // Memory guard (strict): bound the map before and after the insert, so
        // a flood of >MAX distinct fresh keys cannot outgrow the bound.
        bound_buckets(&mut map, now, window);
        let q = map.entry(key).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) > window) {
            q.pop_front();
        }
        if q.len() >= max {
            return false;
        }
        q.push_back(now);
        bound_buckets(&mut map, now, window);
        true
    }

    /// Pure read, **without recording**: is `ip` already at/over `max` attempts
    /// in the window? Prunes stale entries and drops the bucket once empty, so
    /// a flood of one-shot IPs cannot grow the map without bound. Never inserts
    /// an entry, so a caller that pre-checks before an expensive verification
    /// pays nothing and does not consume quota.
    async fn saturated<K>(
        bucket: &Mutex<HashMap<K, VecDeque<Instant>>>,
        key: &K,
        max: usize,
        window: Duration,
    ) -> bool
    where
        K: Eq + std::hash::Hash + Clone,
    {
        let mut map = bucket.lock().await;
        let now = Instant::now();
        bound_buckets(&mut map, now, window);
        let Some(q) = map.get_mut(key) else {
            return false;
        };
        while q.front().is_some_and(|t| now.duration_since(*t) > window) {
            q.pop_front();
        }
        if q.is_empty() {
            map.remove(key);
            return false;
        }
        q.len() >= max
    }

    /// Record a single attempt (only used for failures). Prunes the window and
    /// applies the same anti-DoS pruning as [`Self::check`].
    async fn record<K>(bucket: &Mutex<HashMap<K, VecDeque<Instant>>>, key: K, window: Duration)
    where
        K: Eq + std::hash::Hash + Clone,
    {
        let mut map = bucket.lock().await;
        let now = Instant::now();
        bound_buckets(&mut map, now, window);
        let q = map.entry(key).or_default();
        while q.front().is_some_and(|t| now.duration_since(*t) > window) {
            q.pop_front();
        }
        q.push_back(now);
        bound_buckets(&mut map, now, window);
    }

    /// Coarse login bound: [`LOGIN_IP_MAX`] attempts/min/IP, all usernames
    /// confounded. The password handler runs it together with
    /// [`Self::check_login_user`]; `verify-2fa` runs it alone because the
    /// account is only resolved after the code format check (M1).
    pub async fn check_login_ip(&self, ip: IpAddr) -> bool {
        Self::check(&self.login, ip, LOGIN_IP_MAX, Duration::from_secs(60)).await
    }

    /// Fine login bound: [`LOGIN_USER_MAX`] attempts/min for the couple
    /// `(IP, username)`. The username is normalized exactly like the
    /// credential lookup (`trim`, case-sensitive — see
    /// `store::user::get_by_username`), so the limiter key can never diverge
    /// from the account it protects.
    pub async fn check_login_user(&self, ip: IpAddr, username: &str) -> bool {
        let key = (ip, normalize_username(username));
        Self::check(
            &self.login_user,
            key,
            LOGIN_USER_MAX,
            Duration::from_secs(60),
        )
        .await
    }

    /// `/cnf/*`: 20/min/IP -> 429.
    pub async fn check_cnf(&self, ip: IpAddr) -> bool {
        Self::check(&self.cnf, ip, 20, Duration::from_secs(60)).await
    }

    /// `GET /api/auth/pending`: [`PENDING_MAX`] attempts/min/IP -> 429.
    ///
    /// Deliberately **not** [`Self::check_login_ip`]: the pending route is a
    /// public validity oracle and must not share (and therefore perturb) the
    /// login budget. Independent bucket, same memory hardening as the rest.
    pub async fn check_pending(&self, ip: IpAddr) -> bool {
        Self::check(&self.pending, ip, PENDING_MAX, Duration::from_secs(60)).await
    }

    /// `/metrics/*` failed Bearer pre-check: `true` when `ip` already hit
    /// 30 failures/min, `false` otherwise. **Records nothing**, so a
    /// successful scrape (the Bearer is re-checked on every poll) can never
    /// saturate the bucket; call it before the expensive Argon2 verification
    /// to refuse early with 429, then call [`Self::record_metrics_failure`]
    /// only on a wrong Bearer.
    pub async fn metrics_saturated(&self, ip: IpAddr) -> bool {
        Self::saturated(&self.metrics, &ip, 30, Duration::from_secs(60)).await
    }

    /// Record one `/metrics/*` Bearer failure (30/min/IP, same policy as the
    /// login bucket but **independent** from it).
    pub async fn record_metrics_failure(&self, ip: IpAddr) {
        Self::record(&self.metrics, ip, Duration::from_secs(60)).await;
    }

    /// `/api/setup/*`: 20/min/IP -> 429 (bounds the open bootstrap route and
    /// the admin-gated endpoint step).
    pub async fn check_setup(&self, ip: IpAddr) -> bool {
        Self::check(&self.setup, ip, 20, Duration::from_secs(60)).await
    }

    /// Bearer-credential **failure** pre-check: `false` when the IP already
    /// hit 10 failures/min, `true` otherwise. **Records nothing**, so
    /// successes (every API request from a legitimate client) can never
    /// saturate it; call it before the token lookup to refuse early with
    /// 429, then call [`Self::record_credential_failure`] only when the
    /// credential is wrong.
    pub async fn check_credential(&self, ip: IpAddr) -> bool {
        !Self::saturated(&self.credential, &ip, 10, Duration::from_secs(60)).await
    }

    /// Record one Bearer-credential failure (10/min/IP, same policy as the
    /// login bucket but **independent** from it).
    pub async fn record_credential_failure(&self, ip: IpAddr) {
        Self::record(&self.credential, ip, Duration::from_secs(60)).await;
    }

    /// Authenticated tunnel-mutation bound: [`MUTATE_MAX`] (120/min/IP).
    ///
    /// Guards every route whose effect runs a full `Tunnel::apply` (client and
    /// admin POST|DELETE), so a valid principal can never loop the expensive
    /// render + conf write + `wg syncconf` + firewall rebuild path on the
    /// single-threaded runtime. The OTL generation is the single mutation
    /// deliberately **not** covered (it has no kernel effect). The bucket is
    /// independent from `login`, `cnf`, `metrics`, `setup` and `credential`.
    pub async fn check_mutation(&self, ip: IpAddr) -> bool {
        Self::check(&self.mutate, ip, MUTATE_MAX, Duration::from_secs(60)).await
    }
}

/// Shared state for every handler + the router.
pub struct AppState<B: Backend> {
    pub backend: Arc<B>,
    pub locales: Arc<Locales>,
    pub pending: Arc<Mutex<HashMap<String, PendingLogin>>>,
    pub limits: Arc<RateLimits>,
    /// Push watcher for the live topbar count + grid long-poll
    /// (`GET /api/status/stream`).
    pub watcher: StatusWatcher<B>,
    /// Trusted proxies for `X-Forwarded-For` (CSV IP/CIDR at boot).
    /// `X-Forwarded-Host` is never honored (no virtual-host routing) and
    /// `X-Forwarded-Proto` is never honored (protocol comes from INSECURE).
    pub trusted_proxies: Arc<Vec<IpNet>>,
}

impl<B: Backend> Clone for AppState<B> {
    fn clone(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            locales: self.locales.clone(),
            pending: self.pending.clone(),
            limits: self.limits.clone(),
            watcher: self.watcher.clone(),
            trusted_proxies: self.trusted_proxies.clone(),
        }
    }
}

impl<B: Backend> AppState<B> {
    pub fn new(backend: Arc<B>, locales: Locales, trusted_proxies: Vec<IpNet>) -> Self {
        let watcher = StatusWatcher::new(backend.clone());
        Self {
            backend,
            locales: Arc::new(locales),
            pending: Arc::new(Mutex::new(HashMap::new())),
            limits: Arc::new(RateLimits::default()),
            watcher,
            trusted_proxies: Arc::new(trusted_proxies),
        }
    }

    /// Client IP: direct peer unless it is a trusted proxy. When it is, walk
    /// `X-Forwarded-For` from the right and return the first non-trusted hop,
    /// so a client-supplied leftmost prefix (typical `$proxy_add_x_forwarded_for`
    /// append) can never spoof the rate-limit identity. Invalid/untrustworthy
    /// chains fail closed to the direct peer.
    pub fn client_ip(&self, direct: Option<IpAddr>, forwarded_for: Option<&str>) -> Option<IpAddr> {
        let direct = direct?;
        if !proxy_trusted(&self.trusted_proxies, direct) {
            return Some(direct);
        }
        let Some(ff) = forwarded_for else {
            return Some(direct);
        };
        for hop in ff.rsplit(',').map(str::trim).filter(|s| !s.is_empty()) {
            match hop.parse::<IpAddr>() {
                Ok(ip) if !proxy_trusted(&self.trusted_proxies, ip) => return Some(ip),
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        Some(direct)
    }
}

/// Username normalization for the per-account login bucket. Mirrors the
/// credential lookup exactly (`store::user::get_by_username` matches on the
/// trimmed, case-sensitive value), so the limiter key cannot diverge from the
/// account it protects.
///
/// Clamped to the handler's accepted username length (256): a request body is
/// up to 1 MiB, and without the bound an attacker could store megabyte-sized
/// strings as map keys and blow up RSS before the map-wide pruning kicks in.
/// Truncation is safe because any username longer than 256 bytes is already
/// rejected by the handler (401), so the fine bucket can only over-throttle a
/// user, never let an attacker bypass it.
fn normalize_username(username: &str) -> String {
    username.trim().chars().take(256).collect()
}

fn proxy_trusted(proxies: &[IpNet], peer: IpAddr) -> bool {
    proxies.iter().any(|net| net.contains(&peer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forwarded_headers_only_from_trusted_proxies() {
        let proxies = vec![
            "10.0.0.1/32".parse().unwrap(),
            "192.168.0.0/24".parse().unwrap(),
        ];
        assert!(proxy_trusted(&proxies, "10.0.0.1".parse().unwrap()));
        assert!(proxy_trusted(&proxies, "192.168.0.55".parse().unwrap()));
        assert!(!proxy_trusted(&proxies, "192.168.1.1".parse().unwrap()));
        assert!(!proxy_trusted(&[], "10.0.0.1".parse().unwrap()));
    }

    /// M2: a wrong TOTP code must count against the pending's attempt budget
    /// without dropping it until the cap is reached; the 5th failure reports
    /// exhaustion so the handler can invalidate the entry.
    #[test]
    fn pending_failure_budget_is_reported_on_fifth_try() {
        let mut p = PendingLogin {
            user_id: 1,
            username: "admin".into(),
            expires_at: Instant::now() + Duration::from_secs(300),
            failed_attempts: 0,
        };
        for i in 1..PendingLogin::MAX_FAILED_ATTEMPTS {
            assert!(!p.register_failure(), "failure #{i} must stay retryable");
        }
        assert!(
            p.register_failure(),
            "the 5th failure must exhaust the budget"
        );
        assert_eq!(p.failed_attempts, PendingLogin::MAX_FAILED_ATTEMPTS);
        // Further failures never panic and keep reporting exhaustion.
        assert!(p.register_failure());
    }

    #[tokio::test]
    async fn rate_limit_blocks_after_max_and_buckets_are_independent() {
        let rl = RateLimits::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        // M1: the fine bucket is scoped to `(IP, username)`.
        for _ in 0..10 {
            assert!(rl.check_login_user(ip, "alice").await);
        }
        assert!(
            !rl.check_login_user(ip, "alice").await,
            "11th (ip, alice) attempt must be denied"
        );
        // The same IP may still try another account, and another IP may still
        // try the same account.
        assert!(rl.check_login_user(ip, "bob").await);
        let ip2: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.check_login_user(ip2, "alice").await);
        // Usernames are normalized like the credential lookup (trim).
        assert!(
            !rl.check_login_user(ip, "  alice  ").await,
            "trimmed username must share the bucket"
        );
        // The metrics failure bucket is independent from the login buckets:
        // read-only pre-checks never record, so it stays unsaturated.
        assert!(!rl.metrics_saturated(ip).await);
        // The setup bucket is independent too, and throttles at 20/min.
        for _ in 0..20 {
            assert!(rl.check_setup(ip).await);
        }
        assert!(
            !rl.check_setup(ip).await,
            "21st setup attempt must be denied"
        );
    }

    /// M1 coarse bucket: [`LOGIN_IP_MAX`] attempts/min/IP across **all**
    /// usernames, so credential spraying is still bounded even though each
    /// account has its own fine budget.
    #[tokio::test]
    async fn login_ip_bucket_is_coarse_and_shared_across_usernames() {
        let rl = RateLimits::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..LOGIN_IP_MAX {
            assert!(rl.check_login_ip(ip).await);
        }
        assert!(
            !rl.check_login_ip(ip).await,
            "51st coarse attempt must be denied"
        );
        // Independent from the fine bucket and from other IPs.
        assert!(rl.check_login_user(ip, "alice").await);
        let other: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.check_login_ip(other).await);
    }

    /// FAIBLE: the memory guard must be a **strict** bound, not only a prune of
    /// expired windows. A burst of more than `MAX_RATE_BUCKETS` distinct fresh
    /// keys inside one window has nothing expired to reclaim, so without
    /// eviction the map would grow past the bound until those windows age out.
    /// After `MAX+1` fresh keys the map must already be back at the bound, and
    /// further fresh inserts must not grow it either.
    #[tokio::test]
    async fn rate_buckets_stay_bounded_under_a_burst_of_fresh_keys() {
        let rl = RateLimits::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for i in 0..=MAX_RATE_BUCKETS {
            assert!(rl.check_login_user(ip, &format!("user{i}")).await);
        }
        let len = rl.login_user.lock().await.len();
        assert!(len <= MAX_RATE_BUCKETS, "len={len} > {MAX_RATE_BUCKETS}");
        for i in 0..64 {
            assert!(rl.check_login_user(ip, &format!("later{i}")).await);
        }
        let len = rl.login_user.lock().await.len();
        assert!(len <= MAX_RATE_BUCKETS, "len={len} > {MAX_RATE_BUCKETS}");
    }

    /// The fine bucket key is clamped to 256 chars so an attacker cannot store
    /// megabyte-sized usernames (accepted up to the 1 MiB body limit) as map
    /// keys; an over-long name shares the bucket of its 256-char prefix.
    #[tokio::test]
    async fn login_user_key_is_length_clamped() {
        let rl = RateLimits::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let long = "a".repeat(300);
        let prefix = "a".repeat(256);
        for _ in 0..LOGIN_USER_MAX {
            assert!(rl.check_login_user(ip, &long).await);
        }
        assert!(
            !rl.check_login_user(ip, &prefix).await,
            "the 256-char prefix must share the clamped bucket"
        );
    }

    /// The credential bucket counts **failures only**: the pre-check never
    /// records, so a legitimate API client (repeated pre-checks) is never
    /// throttled, while ten recorded failures deny the 11th pre-check. It
    /// is independent from `login` and `metrics`.
    #[tokio::test]
    async fn credential_failures_throttle_successes_do_not() {
        let rl = RateLimits::default();
        let ip: IpAddr = "9.9.9.9".parse().unwrap();
        // Pre-checks alone never fill the bucket (successes are not recorded).
        for _ in 0..50 {
            assert!(rl.check_credential(ip).await);
        }
        // Ten failures saturate the bucket: the 11th pre-check is denied.
        for _ in 0..10 {
            rl.record_credential_failure(ip).await;
        }
        assert!(
            !rl.check_credential(ip).await,
            "11th credential failure must be denied"
        );
        // Independent from the login / metrics buckets and from other IPs.
        assert!(rl.check_login_ip(ip).await);
        assert!(rl.check_login_user(ip, "alice").await);
        assert!(!rl.metrics_saturated(ip).await);
        let other: IpAddr = "9.9.9.10".parse().unwrap();
        assert!(rl.check_credential(other).await);
    }

    /// The metrics bucket counts **failed** Bearer checks only: the pre-check
    /// never records, so a working scraper (repeated pre-checks with the right
    /// token) is never throttled, while thirty recorded failures saturate the
    /// bucket and deny the next pre-check. It is independent from `login`
    /// and `credential`. This is the CPU-DoS guard: the pre-check runs BEFORE the
    /// expensive Argon2 verification.
    #[tokio::test]
    async fn metrics_failures_throttle_successes_do_not() {
        let rl = RateLimits::default();
        let ip: IpAddr = "9.9.9.8".parse().unwrap();
        // Pre-checks alone never fill the bucket (successes are not recorded).
        for _ in 0..50 {
            assert!(!rl.metrics_saturated(ip).await);
        }
        // Thirty failures saturate the bucket.
        for _ in 0..30 {
            rl.record_metrics_failure(ip).await;
        }
        assert!(
            rl.metrics_saturated(ip).await,
            "31st metrics auth attempt must be refused"
        );
        // Independent from the login / credential buckets and from other IPs.
        assert!(rl.check_login_ip(ip).await);
        assert!(rl.check_login_user(ip, "alice").await);
        assert!(rl.check_credential(ip).await);
        let other: IpAddr = "9.9.9.7".parse().unwrap();
        assert!(!rl.metrics_saturated(other).await);
    }

    /// The authenticated-mutation bucket is bounded at [`MUTATE_MAX`]/min/IP:
    /// the first 120 mutations pass, the 121st is denied. It is independent
    /// from every other bucket (a mutation burst must never lock the principal
    /// out of login / cnf / setup) and per-IP (another origin is unaffected).
    #[tokio::test]
    async fn mutations_are_bounded_and_bucket_is_independent() {
        let rl = RateLimits::default();
        let ip: IpAddr = "7.7.7.7".parse().unwrap();
        for _ in 0..MUTATE_MAX {
            assert!(rl.check_mutation(ip).await);
        }
        assert!(
            !rl.check_mutation(ip).await,
            "121st mutation must be denied"
        );
        // Independent from the other buckets and from other IPs.
        assert!(rl.check_login_ip(ip).await);
        assert!(rl.check_login_user(ip, "alice").await);
        assert!(rl.check_setup(ip).await);
        assert!(rl.check_cnf(ip).await);
        assert!(rl.check_credential(ip).await);
        let other: IpAddr = "7.7.7.8".parse().unwrap();
        assert!(rl.check_mutation(other).await);
    }

    /// `GET /api/auth/pending` is a public validity oracle: its dedicated
    /// bucket throttles at [`PENDING_MAX`]/min/IP and, crucially, does **not**
    /// consume the login budget (a probe flood must never lock a user out of
    /// logging in).
    #[tokio::test]
    async fn pending_probes_are_bounded_and_independent_from_login() {
        let rl = RateLimits::default();
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        for _ in 0..PENDING_MAX {
            assert!(rl.check_pending(ip).await);
        }
        assert!(
            !rl.check_pending(ip).await,
            "the 61st pending probe must be denied"
        );
        // The login buckets are untouched by pending probes, and vice versa.
        assert!(rl.check_login_ip(ip).await);
        assert!(rl.check_login_user(ip, "alice").await);
        let other: IpAddr = "5.6.7.8".parse().unwrap();
        assert!(rl.check_pending(other).await);
    }

    /// The pending map is strictly bounded: once [`MAX_PENDING`] entries exist,
    /// inserting one more evicts the earliest-expiring entry instead of
    /// growing the map, and later inserts keep it at the bound.
    #[tokio::test]
    async fn pending_map_is_strictly_bounded() {
        let mut map: HashMap<String, PendingLogin> = HashMap::new();
        let base = Instant::now();
        for i in 0..MAX_PENDING {
            insert_pending(
                &mut map,
                format!("id{i:08}"),
                PendingLogin {
                    user_id: 1,
                    username: "admin".into(),
                    expires_at: base + Duration::from_secs(i as u64 + 1),
                    failed_attempts: 0,
                },
            );
        }
        assert_eq!(map.len(), MAX_PENDING);
        // `id00000000` expires first, so it is the eviction victim.
        let victim = "id00000000".to_string();
        assert!(map.contains_key(&victim));
        insert_pending(
            &mut map,
            "fresh".into(),
            PendingLogin {
                user_id: 1,
                username: "admin".into(),
                expires_at: base + Duration::from_secs(999_999),
                failed_attempts: 0,
            },
        );
        assert_eq!(
            map.len(),
            MAX_PENDING,
            "the map must not grow past the bound"
        );
        assert!(
            !map.contains_key(&victim),
            "the earliest-expiring entry must be evicted"
        );
        assert!(map.contains_key("fresh"));
        // Further fresh inserts stay bounded too.
        for i in 0..64 {
            insert_pending(
                &mut map,
                format!("more{i:04}"),
                PendingLogin {
                    user_id: 1,
                    username: "admin".into(),
                    expires_at: base + Duration::from_secs(100_000 + i as u64),
                    failed_attempts: 0,
                },
            );
        }
        assert_eq!(map.len(), MAX_PENDING);
    }
}

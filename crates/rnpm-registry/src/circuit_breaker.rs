use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// State of a circuit breaker for a remote registry host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Normal operation: requests are permitted to flow through.
    Closed,
    /// Failing fast: registry has failed consecutively beyond threshold.
    /// Inbound requests fail fast without incurring network delay or load.
    Open,
    /// Probe state: cooldown timeout has elapsed. A single request is permitted
    /// to probe whether the remote registry has recovered.
    HalfOpen,
}

#[derive(Debug, Clone)]
struct HostCircuit {
    consecutive_failures: usize,
    state: CircuitBreakerState,
    last_state_change: Instant,
    dirty: bool,
    half_open_probe_in_flight: bool,
}

impl Default for HostCircuit {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: CircuitBreakerState::Closed,
            last_state_change: Instant::now(),
            dirty: false,
            half_open_probe_in_flight: false,
        }
    }
}

/// RAII guard for an active single probe in `CircuitBreakerState::HalfOpen`.
/// Releases the probe slot if dropped before `record_success`/`record_failure` completes.
#[derive(Debug)]
pub struct HalfOpenProbeGuard {
    host: String,
    hosts: Arc<RwLock<HashMap<String, HostCircuit>>>,
    disarmed: bool,
}

impl HalfOpenProbeGuard {
    /// Marks the probe as completed so `Drop` will not clear `half_open_probe_in_flight`.
    pub fn disarm(&mut self) {
        self.disarmed = true;
    }
}

impl Drop for HalfOpenProbeGuard {
    fn drop(&mut self) {
        if !self.disarmed {
            let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = hosts.get_mut(&self.host) {
                if entry.state == CircuitBreakerState::HalfOpen {
                    entry.half_open_probe_in_flight = false;
                }
            }
        }
    }
}

/// Thread-safe circuit breaker tracking registry host failures and enforcing fail-fast behavior.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_threshold: usize,
    reset_timeout: Duration,
    hosts: Arc<RwLock<HashMap<String, HostCircuit>>>,
    /// Count of host entries with non-zero failures or non-Closed state.
    /// When 0, all hosts are Closed and healthy fast-paths avoid locking entirely.
    dirty_hosts: Arc<AtomicUsize>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: usize, reset_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            reset_timeout,
            hosts: Arc::new(RwLock::new(HashMap::new())),
            dirty_hosts: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Check the circuit state for a host.
    /// If Open and the reset timeout has elapsed, transitions automatically to HalfOpen.
    pub async fn check_state(&self, host: &str) -> CircuitBreakerState {
        if self.failure_threshold == 0 || self.dirty_hosts.load(Ordering::Acquire) == 0 {
            return CircuitBreakerState::Closed;
        }

        {
            let hosts = self.hosts.read().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = hosts.get(host) else {
                return CircuitBreakerState::Closed;
            };
            if entry.state != CircuitBreakerState::Open
                || entry.last_state_change.elapsed() < self.reset_timeout
            {
                return entry.state;
            }
        }

        let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = hosts.get_mut(host) else {
            return CircuitBreakerState::Closed;
        };
        if entry.state == CircuitBreakerState::Open
            && entry.last_state_change.elapsed() >= self.reset_timeout
        {
            entry.state = CircuitBreakerState::HalfOpen;
            entry.last_state_change = Instant::now();
        }
        entry.state
    }

    /// Acquire permission to dispatch a request for `host`, enforcing the single-probe
    /// guard when the circuit is in `HalfOpen` state.
    pub async fn try_acquire_request(
        &self,
        host: &str,
    ) -> Result<Option<HalfOpenProbeGuard>, CircuitBreakerState> {
        if self.failure_threshold == 0 || self.dirty_hosts.load(Ordering::Acquire) == 0 {
            return Ok(None);
        }

        {
            let hosts = self.hosts.read().unwrap_or_else(|e| e.into_inner());
            let Some(entry) = hosts.get(host) else {
                return Ok(None);
            };
            match entry.state {
                CircuitBreakerState::Closed => return Ok(None),
                CircuitBreakerState::Open => {
                    if entry.last_state_change.elapsed() < self.reset_timeout {
                        return Err(CircuitBreakerState::Open);
                    }
                }
                CircuitBreakerState::HalfOpen => {
                    if entry.half_open_probe_in_flight {
                        return Err(CircuitBreakerState::HalfOpen);
                    }
                }
            }
        }

        let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
        let Some(entry) = hosts.get_mut(host) else {
            return Ok(None);
        };
        match entry.state {
            CircuitBreakerState::Closed => Ok(None),
            CircuitBreakerState::Open => {
                if entry.last_state_change.elapsed() >= self.reset_timeout {
                    entry.state = CircuitBreakerState::HalfOpen;
                    entry.last_state_change = Instant::now();
                    entry.half_open_probe_in_flight = true;
                    Ok(Some(HalfOpenProbeGuard {
                        host: host.to_string(),
                        hosts: Arc::clone(&self.hosts),
                        disarmed: false,
                    }))
                } else {
                    Err(CircuitBreakerState::Open)
                }
            }
            CircuitBreakerState::HalfOpen => {
                if entry.half_open_probe_in_flight {
                    Err(CircuitBreakerState::HalfOpen)
                } else {
                    entry.half_open_probe_in_flight = true;
                    Ok(Some(HalfOpenProbeGuard {
                        host: host.to_string(),
                        hosts: Arc::clone(&self.hosts),
                        disarmed: false,
                    }))
                }
            }
        }
    }

    /// Record a successful request to a host, closing the circuit and resetting failure counts.
    pub async fn record_success(&self, host: &str) {
        if self.failure_threshold == 0 || self.dirty_hosts.load(Ordering::Acquire) == 0 {
            return;
        }

        {
            let hosts = self.hosts.read().unwrap_or_else(|e| e.into_inner());
            match hosts.get(host) {
                None => return,
                Some(entry)
                    if entry.state == CircuitBreakerState::Closed
                        && entry.consecutive_failures == 0 =>
                {
                    return;
                }
                _ => {}
            }
        }

        let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = hosts.get_mut(host) {
            if entry.dirty {
                entry.dirty = false;
                self.dirty_hosts.fetch_sub(1, Ordering::Release);
            }
            entry.consecutive_failures = 0;
            entry.state = CircuitBreakerState::Closed;
            entry.half_open_probe_in_flight = false;
            entry.last_state_change = Instant::now();
        }
    }

    /// Record a failure (such as HTTP 5xx, HTTP 429, or network disconnect).
    /// If consecutive failures reach `failure_threshold` or if probe in HalfOpen fails,
    /// trips the circuit to Open.
    pub async fn record_failure(&self, host: &str) -> CircuitBreakerState {
        if self.failure_threshold == 0 {
            return CircuitBreakerState::Closed;
        }

        let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
        let entry = hosts.entry(host.to_string()).or_default();

        if !entry.dirty {
            entry.dirty = true;
            self.dirty_hosts.fetch_add(1, Ordering::Release);
        }

        entry.consecutive_failures += 1;
        if entry.consecutive_failures >= self.failure_threshold
            || entry.state == CircuitBreakerState::HalfOpen
        {
            entry.state = CircuitBreakerState::Open;
            entry.half_open_probe_in_flight = false;
            entry.last_state_change = Instant::now();
        }

        entry.state
    }

    /// Explicitly reset the circuit for a host to Closed.
    pub async fn reset(&self, host: &str) {
        let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = hosts.get_mut(host) {
            if entry.dirty {
                entry.dirty = false;
                self.dirty_hosts.fetch_sub(1, Ordering::Release);
            }
            entry.consecutive_failures = 0;
            entry.state = CircuitBreakerState::Closed;
            entry.half_open_probe_in_flight = false;
            entry.last_state_change = Instant::now();
        }
    }

    /// Explicitly trip the circuit for a host to Open.
    pub async fn trip(&self, host: &str) {
        let mut hosts = self.hosts.write().unwrap_or_else(|e| e.into_inner());
        let entry = hosts.entry(host.to_string()).or_default();
        if !entry.dirty {
            entry.dirty = true;
            self.dirty_hosts.fetch_add(1, Ordering::Release);
        }
        entry.state = CircuitBreakerState::Open;
        entry.half_open_probe_in_flight = false;
        entry.consecutive_failures = self.failure_threshold;
        entry.last_state_change = Instant::now();
    }
}

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

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
}

impl Default for HostCircuit {
    fn default() -> Self {
        Self {
            consecutive_failures: 0,
            state: CircuitBreakerState::Closed,
            last_state_change: Instant::now(),
        }
    }
}

/// Thread-safe circuit breaker tracking registry host failures and enforcing fail-fast behavior.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    failure_threshold: usize,
    reset_timeout: Duration,
    hosts: Arc<RwLock<HashMap<String, HostCircuit>>>,
}

impl CircuitBreaker {
    pub fn new(failure_threshold: usize, reset_timeout: Duration) -> Self {
        Self {
            failure_threshold,
            reset_timeout,
            hosts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Check the circuit state for a host.
    /// If Open and the reset timeout has elapsed, transitions automatically to HalfOpen.
    pub async fn check_state(&self, host: &str) -> CircuitBreakerState {
        if self.failure_threshold == 0 {
            return CircuitBreakerState::Closed;
        }

        let mut hosts = self.hosts.write().await;
        let entry = hosts.entry(host.to_string()).or_default();

        if entry.state == CircuitBreakerState::Open {
            if entry.last_state_change.elapsed() >= self.reset_timeout {
                entry.state = CircuitBreakerState::HalfOpen;
                entry.last_state_change = Instant::now();
            }
        }

        entry.state
    }

    /// Record a successful request to a host, closing the circuit and resetting failure counts.
    pub async fn record_success(&self, host: &str) {
        if self.failure_threshold == 0 {
            return;
        }

        let mut hosts = self.hosts.write().await;
        if let Some(entry) = hosts.get_mut(host) {
            entry.consecutive_failures = 0;
            entry.state = CircuitBreakerState::Closed;
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

        let mut hosts = self.hosts.write().await;
        let entry = hosts.entry(host.to_string()).or_default();

        entry.consecutive_failures += 1;
        if entry.consecutive_failures >= self.failure_threshold
            || entry.state == CircuitBreakerState::HalfOpen
        {
            entry.state = CircuitBreakerState::Open;
            entry.last_state_change = Instant::now();
        }

        entry.state
    }

    /// Explicitly reset the circuit for a host to Closed.
    pub async fn reset(&self, host: &str) {
        let mut hosts = self.hosts.write().await;
        if let Some(entry) = hosts.get_mut(host) {
            entry.consecutive_failures = 0;
            entry.state = CircuitBreakerState::Closed;
            entry.last_state_change = Instant::now();
        }
    }

    /// Explicitly trip the circuit for a host to Open.
    pub async fn trip(&self, host: &str) {
        let mut hosts = self.hosts.write().await;
        let entry = hosts.entry(host.to_string()).or_default();
        entry.state = CircuitBreakerState::Open;
        entry.consecutive_failures = self.failure_threshold;
        entry.last_state_change = Instant::now();
    }
}

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// High-resolution phases of the installation workflow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    Plan,
    Metadata,
    Fetch,
    Verify,
    Inflate,
    StoreWrite,
    Materialize,
    Bins,
    Lifecycle,
    Lockfile,
}

impl Phase {
    /// Canonical phase name matching npm timing logs and specification.
    pub fn name(&self) -> &'static str {
        match self {
            Phase::Plan => "plan",
            Phase::Metadata => "metadata",
            Phase::Fetch => "fetch",
            Phase::Verify => "verify",
            Phase::Inflate => "inflate",
            Phase::StoreWrite => "store-write",
            Phase::Materialize => "materialize",
            Phase::Bins => "bins",
            Phase::Lifecycle => "lifecycle",
            Phase::Lockfile => "lockfile",
        }
    }

    /// List of all phases in chronological lifecycle order.
    pub fn all() -> &'static [Phase] {
        &[
            Phase::Plan,
            Phase::Metadata,
            Phase::Fetch,
            Phase::Verify,
            Phase::Inflate,
            Phase::StoreWrite,
            Phase::Materialize,
            Phase::Bins,
            Phase::Lifecycle,
            Phase::Lockfile,
        ]
    }
}

/// Recorded timing data for a single phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingPhase {
    pub phase: String,
    pub duration_ms: f64,
    pub percentage: f64,
}

/// Summary of timing and filesystem metrics for an installation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimingMetrics {
    pub total_duration_ms: f64,
    pub phases: Vec<TimingPhase>,
    pub files_created: u64,
    pub junctions_created: u64,
    pub bytes_written: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl TimingMetrics {
    /// Formats the per-phase timing table.
    pub fn format_table(&self) -> String {
        let mut out = String::new();
        out.push_str("\nTiming Summary:\n");
        out.push_str("┌─────────────────┬──────────────────┬────────────┐\n");
        out.push_str("│ Phase           │ Duration (ms)    │ % of Total │\n");
        out.push_str("├─────────────────┼──────────────────┼────────────┤\n");
        for p in &self.phases {
            out.push_str(&format!(
                "│ {:<15} │ {:>13.2} ms │ {:>8.1} % │\n",
                p.phase, p.duration_ms, p.percentage
            ));
        }
        out.push_str("├─────────────────┼──────────────────┼────────────┤\n");
        out.push_str(&format!(
            "│ {:<15} │ {:>13.2} ms │ {:>8.1} % │\n",
            "Total", self.total_duration_ms, 100.0
        ));
        out.push_str("└─────────────────┴──────────────────┴────────────┘\n");
        out
    }

    /// Formats the summary counters.
    pub fn format_counters(&self) -> String {
        let mut out = String::new();
        out.push_str("Counters & Metrics:\n");
        out.push_str(&format!("  Files created:      {}\n", self.files_created));
        out.push_str(&format!(
            "  Junctions created:  {}\n",
            self.junctions_created
        ));
        out.push_str(&format!(
            "  Bytes written:      {} ({})\n",
            self.bytes_written,
            format_bytes_human(self.bytes_written)
        ));
        out.push_str(&format!("  Cache hits:         {}\n", self.cache_hits));
        out.push_str(&format!("  Cache misses:       {}\n", self.cache_misses));
        out
    }

    /// Formats npm-style timing log entries.
    pub fn format_npm_logs(&self) -> String {
        let mut out = String::new();
        for p in &self.phases {
            out.push_str(&format!(
                "npm timing phase:{} {:.2}ms ({:.1}%)\n",
                p.phase, p.duration_ms, p.percentage
            ));
        }
        out.push_str(&format!(
            "npm timing total {:.2}ms\n",
            self.total_duration_ms
        ));
        out
    }

    /// Dumps timing and counters to `timing.json` at the given directory or file path.
    pub fn dump_timing_json(&self, dir_or_file: &Path) -> std::io::Result<()> {
        let file_path = if dir_or_file.is_dir() {
            dir_or_file.join("timing.json")
        } else {
            dir_or_file.to_path_buf()
        };
        let json_str = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(file_path, json_str)?;
        Ok(())
    }
}

fn format_bytes_human(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GiB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}

/// Thread-safe accumulator for timing across parallel and sequential phases.
#[derive(Debug, Clone)]
pub struct TimingCollector {
    start_time: Instant,
    phase_nanos: Arc<[AtomicU64; 10]>,
    cache_hits: Arc<AtomicU64>,
    cache_misses: Arc<AtomicU64>,
    initial_files_created: u64,
    initial_junctions_created: u64,
    initial_bytes_written: u64,
}

impl TimingCollector {
    /// Creates a new timing collector, snapshotting initial filesystem counters for this run.
    pub fn new() -> Self {
        Self {
            start_time: Instant::now(),
            phase_nanos: Arc::new(std::array::from_fn(|_| AtomicU64::new(0))),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            initial_files_created: rnpm_fs::files_created(),
            initial_junctions_created: rnpm_fs::junctions_created(),
            initial_bytes_written: rnpm_fs::bytes_written(),
        }
    }

    /// Record a duration for a specific phase.
    pub fn record_phase(&self, phase: Phase, duration: Duration) {
        self.phase_nanos[phase as usize].fetch_add(duration.as_nanos() as u64, Ordering::Relaxed);
    }

    /// Increment cache hit count.
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Increment cache miss count.
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Add multiple cache hits.
    pub fn add_cache_hits(&self, count: u64) {
        self.cache_hits.fetch_add(count, Ordering::Relaxed);
    }

    /// Add multiple cache misses.
    pub fn add_cache_misses(&self, count: u64) {
        self.cache_misses.fetch_add(count, Ordering::Relaxed);
    }

    /// Enters a tracing span and starts timing for the specified phase.
    pub fn enter_phase(&self, phase: Phase) -> PhaseGuard {
        let span = match phase {
            Phase::Plan => tracing::info_span!("plan"),
            Phase::Metadata => tracing::info_span!("metadata"),
            Phase::Fetch => tracing::info_span!("fetch"),
            Phase::Verify => tracing::info_span!("verify"),
            Phase::Inflate => tracing::info_span!("inflate"),
            Phase::StoreWrite => tracing::info_span!("store-write"),
            Phase::Materialize => tracing::info_span!("materialize"),
            Phase::Bins => tracing::info_span!("bins"),
            Phase::Lifecycle => tracing::info_span!("lifecycle"),
            Phase::Lockfile => tracing::info_span!("lockfile"),
        };
        PhaseGuard {
            collector: self.clone(),
            phase,
            start: Instant::now(),
            _span: span.entered(),
        }
    }

    /// Finishes collection, aggregating phase durations and filesystem metrics.
    pub fn finish(&self) -> TimingMetrics {
        let total_elapsed = self.start_time.elapsed();
        let total_wall_ms = total_elapsed.as_secs_f64() * 1000.0;

        let mut sum_phase_ms = 0.0;
        let mut raw_ms: Vec<(Phase, f64)> = Vec::with_capacity(10);
        for &phase in Phase::all() {
            let nanos = self.phase_nanos[phase as usize].load(Ordering::Acquire);
            let ms = (nanos as f64) / 1_000_000.0;
            sum_phase_ms += ms;
            raw_ms.push((phase, ms));
        }

        // Scale per-worker phase durations if parallel aggregation exceeds total wall-clock elapsed time
        let scale_factor = if sum_phase_ms > total_wall_ms && total_wall_ms > 0.0 {
            total_wall_ms / sum_phase_ms
        } else {
            1.0
        };

        let denominator = if total_wall_ms > 0.0 {
            total_wall_ms
        } else {
            sum_phase_ms.max(0.001)
        };

        let phases = raw_ms
            .into_iter()
            .map(|(phase, ms)| {
                let scaled_ms = ms * scale_factor;
                let percentage = if denominator > 0.0 {
                    (scaled_ms / denominator) * 100.0
                } else {
                    0.0
                };
                TimingPhase {
                    phase: phase.name().to_string(),
                    duration_ms: (scaled_ms * 100.0).round() / 100.0,
                    percentage: (percentage * 10.0).round() / 10.0,
                }
            })
            .collect();

        TimingMetrics {
            total_duration_ms: (total_wall_ms * 100.0).round() / 100.0,
            phases,
            files_created: rnpm_fs::files_created().saturating_sub(self.initial_files_created),
            junctions_created: rnpm_fs::junctions_created()
                .saturating_sub(self.initial_junctions_created),
            bytes_written: rnpm_fs::bytes_written().saturating_sub(self.initial_bytes_written),
            cache_hits: self.cache_hits.load(Ordering::Acquire),
            cache_misses: self.cache_misses.load(Ordering::Acquire),
        }
    }
}

impl Default for TimingCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// RAII guard that exits tracing span and accumulates phase duration upon drop.
pub struct PhaseGuard {
    collector: TimingCollector,
    phase: Phase,
    start: Instant,
    _span: tracing::span::EnteredSpan,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let elapsed = self.start.elapsed();
        self.collector.record_phase(self.phase, elapsed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_timing_wall_clock_and_parallel_scaling() {
        let collector = TimingCollector::new();
        std::thread::sleep(Duration::from_millis(10));

        // Simulate 4 concurrent workers recording 20ms each (total 80ms worker time, while wall time ~10-15ms)
        collector.record_phase(Phase::Fetch, Duration::from_millis(40));
        collector.record_phase(Phase::Materialize, Duration::from_millis(40));

        let metrics = collector.finish();
        assert!(
            metrics.total_duration_ms >= 9.0,
            "Total duration must reflect wall-clock elapsed time, got {}",
            metrics.total_duration_ms
        );

        // Sum of scaled phases should not exceed total wall-clock duration
        let total_phase_ms: f64 = metrics.phases.iter().map(|p| p.duration_ms).sum();
        assert!(
            total_phase_ms <= metrics.total_duration_ms + 0.1,
            "Scaled phases sum ({total_phase_ms}) must not exceed wall clock ({})",
            metrics.total_duration_ms
        );

        // Sum of percentages should not exceed 100.1%
        let total_pct: f64 = metrics.phases.iter().map(|p| p.percentage).sum();
        assert!(
            total_pct <= 100.1,
            "Percentages sum ({total_pct}) must not exceed 100%"
        );
    }

    #[test]
    fn test_timing_counters_isolated_without_global_resets() {
        // Record something in fs
        rnpm_fs::record_files_created_batch(5, 1000);
        let c1 = TimingCollector::new();
        rnpm_fs::record_files_created_batch(2, 500);
        let m1 = c1.finish();

        assert_eq!(
            m1.files_created, 2,
            "m1 should only reflect deltas created after its initialization"
        );
        assert_eq!(
            m1.bytes_written, 500,
            "m1 should only reflect deltas created after its initialization"
        );
    }
}

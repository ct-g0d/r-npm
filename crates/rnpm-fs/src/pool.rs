use std::collections::VecDeque;
use std::panic::{catch_unwind, resume_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

const CLOSED_BIT: u64 = 1u64 << 63;
const SLOTS_SHIFT: u32 = 32;
const SLOTS_MASK: u64 = ((1u64 << 31) - 1) << SLOTS_SHIFT;
const ACTIVE_MASK: u64 = u32::MAX as u64;

struct Batch {
    call: unsafe fn(*const ()),
    ctx: *const (),
    state: AtomicU64,
    panic: Mutex<Option<Box<dyn std::any::Any + Send>>>,
    done_lock: Mutex<()>,
    done_cvar: Condvar,
}

// Safety: `ctx` points to a `Sync` closure `F` whose lifetime covers the caller's
// `BatchFinishGuard`, which blocks until `CLOSED_BIT` is set and `active_workers == 0`.
unsafe impl Send for Batch {}
unsafe impl Sync for Batch {}

impl Batch {
    #[inline]
    fn try_enter(&self) -> bool {
        let mut cur = self.state.load(Ordering::Acquire);
        loop {
            if (cur & CLOSED_BIT) != 0 || (cur & SLOTS_MASK) == 0 {
                return false;
            }
            let next = cur - (1u64 << SLOTS_SHIFT) + 1;
            match self
                .state
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => return true,
                Err(actual) => cur = actual,
            }
        }
    }

    #[inline]
    fn has_open_slots(&self) -> bool {
        let cur = self.state.load(Ordering::Acquire);
        (cur & CLOSED_BIT) == 0 && (cur & SLOTS_MASK) != 0
    }

    fn execute_as_helper(&self) {
        // SAFETY: `self.call` is `call_closure::<F>` and `self.ctx` points to the caller's `&F`
        // (`F: Fn() + Sync`), which remains live and immutable until `BatchFinishGuard::drop`
        // closes the batch and waits for `ACTIVE_MASK == 0`.
        let res = catch_unwind(AssertUnwindSafe(|| unsafe { (self.call)(self.ctx) }));
        if let Err(payload) = res {
            let mut guard = self.panic.lock().unwrap_or_else(|e| e.into_inner());
            if guard.is_none() {
                *guard = Some(payload);
            }
        }
        let prev = self.state.fetch_sub(1, Ordering::AcqRel);
        if (prev & CLOSED_BIT) != 0 && (prev & ACTIVE_MASK) == 1 {
            let _done = self.done_lock.lock().unwrap_or_else(|e| e.into_inner());
            self.done_cvar.notify_one();
        }
    }
}

struct BatchFinishGuard<'a> {
    batch: &'a Batch,
}

impl Drop for BatchFinishGuard<'_> {
    fn drop(&mut self) {
        let mut cur = self.batch.state.load(Ordering::Acquire);
        loop {
            let active = cur & ACTIVE_MASK;
            let next = CLOSED_BIT | active;
            match self.batch.state.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }

        if (self.batch.state.load(Ordering::Acquire) & ACTIVE_MASK) > 0 {
            let mut done = self
                .batch
                .done_lock
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            while (self.batch.state.load(Ordering::Acquire) & ACTIVE_MASK) > 0 {
                done = self
                    .batch
                    .done_cvar
                    .wait(done)
                    .unwrap_or_else(|e| e.into_inner());
            }
        }
    }
}

struct PoolState {
    queue: VecDeque<Arc<Batch>>,
    idle_workers: usize,
    spawned_workers: usize,
}

struct IoPool {
    state: Mutex<PoolState>,
    cvar: Condvar,
    max_workers: usize,
}

impl IoPool {
    fn global() -> &'static Arc<Self> {
        static POOL: OnceLock<Arc<IoPool>> = OnceLock::new();
        POOL.get_or_init(|| {
            let max_workers = std::thread::available_parallelism()
                .map(|n| (n.get() * 4).clamp(16, 32))
                .unwrap_or(24)
                .saturating_sub(1);
            Arc::new(Self {
                state: Mutex::new(PoolState {
                    queue: VecDeque::with_capacity(16),
                    idle_workers: 0,
                    spawned_workers: 0,
                }),
                cvar: Condvar::new(),
                max_workers,
            })
        })
    }

    fn worker_loop(self: Arc<Self>) {
        loop {
            let batch = {
                let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
                loop {
                    let mut picked = None;
                    while let Some(front) = guard.queue.front() {
                        if front.try_enter() {
                            let b = Arc::clone(front);
                            if !b.has_open_slots() {
                                guard.queue.pop_front();
                            }
                            picked = Some(b);
                            break;
                        }
                        guard.queue.pop_front();
                    }
                    if let Some(b) = picked {
                        break b;
                    }
                    guard.idle_workers += 1;
                    guard = self.cvar.wait(guard).unwrap_or_else(|e| e.into_inner());
                    guard.idle_workers = guard.idle_workers.saturating_sub(1);
                }
            };
            batch.execute_as_helper();
        }
    }
}

/// SAFETY: Caller must guarantee `ctx` points to a valid, initialized `F` that outlives the call.
unsafe fn call_closure<F: Fn() + Sync>(ctx: *const ()) {
    let f = &*(ctx as *const F);
    f();
}

/// Runs `f` across up to `requested_threads` workers concurrently (including the caller thread)
/// using a persistent worker pool, avoiding per-call OS thread creation overhead.
///
/// Panic-safe and deadlock-free even under nested invocations.
pub fn run_parallel<F: Fn() + Sync>(requested_threads: usize, f: &F) {
    if requested_threads <= 1 {
        f();
        return;
    }

    let pool = IoPool::global();
    let total_threads = requested_threads.min(pool.max_workers + 1);
    if total_threads <= 1 {
        f();
        return;
    }

    let helper_slots = total_threads - 1;
    debug_assert!(helper_slots < (1usize << 31));
    let batch = Arc::new(Batch {
        call: call_closure::<F>,
        ctx: (f as *const F).cast(),
        state: AtomicU64::new((helper_slots as u64) << SLOTS_SHIFT),
        panic: Mutex::new(None),
        done_lock: Mutex::new(()),
        done_cvar: Condvar::new(),
    });

    let (spawn_start, spawn_end) = {
        let mut guard = pool.state.lock().unwrap_or_else(|e| e.into_inner());
        while guard.queue.front().is_some_and(|b| !b.has_open_slots()) {
            guard.queue.pop_front();
        }
        guard.queue.push_back(Arc::clone(&batch));

        // Lazily grow the persistent pool only up to the concurrency actually needed.
        let desired_workers = helper_slots.min(pool.max_workers);
        let needed = desired_workers
            .saturating_sub(guard.idle_workers)
            .min(pool.max_workers.saturating_sub(guard.spawned_workers));
        let start = guard.spawned_workers;
        guard.spawned_workers += needed;

        let to_wake = helper_slots.min(guard.idle_workers);
        if to_wake >= guard.idle_workers && to_wake > 1 {
            pool.cvar.notify_all();
        } else {
            for _ in 0..to_wake {
                pool.cvar.notify_one();
            }
        }
        (start, start + needed)
    };

    for idx in spawn_start..spawn_end {
        let p = Arc::clone(pool);
        if std::thread::Builder::new()
            .name(format!("rnpm-fs-io-{idx}"))
            .spawn(move || p.worker_loop())
            .is_err()
        {
            let mut guard = pool.state.lock().unwrap_or_else(|e| e.into_inner());
            guard.spawned_workers = guard.spawned_workers.saturating_sub(1);
        }
    }

    let caller_res = {
        let _finish_guard = BatchFinishGuard { batch: &batch };
        catch_unwind(AssertUnwindSafe(f))
    };

    if let Err(payload) = caller_res {
        resume_unwind(payload);
    }
    let panic_payload = batch.panic.lock().unwrap_or_else(|e| e.into_inner()).take();
    if let Some(payload) = panic_payload {
        resume_unwind(payload);
    }
}

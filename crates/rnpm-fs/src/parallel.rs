use crate::atomic::extract_and_replace;
use crate::error::FsError;
use crate::tarball::{ExtractionSummary, TarLimits};
use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// A single extraction task for parallel batch extraction.
pub struct BatchExtractionItem<R> {
    pub reader: R,
    pub destination: PathBuf,
    pub limits: Option<TarLimits>,
}

impl<R> BatchExtractionItem<R> {
    pub fn new(reader: R, destination: PathBuf, limits: Option<TarLimits>) -> Self {
        Self {
            reader,
            destination,
            limits,
        }
    }
}

/// Executes a batch of extraction tasks in parallel using a bounded thread pool.
/// Bounded concurrency saturates multi-core CPUs without overwhelming disk queues.
/// Work dispatch uses guided batch pulling to minimize queue mutex contention,
/// and worker threads collect local results to avoid locking during extraction.
pub fn extract_batch_parallel<R: Read + Send>(
    items: Vec<BatchExtractionItem<R>>,
    concurrency_limit: usize,
) -> Vec<Result<ExtractionSummary, FsError>> {
    let num_items = items.len();
    if num_items == 0 {
        return Vec::new();
    }

    let concurrency = if concurrency_limit == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(4)
            .clamp(2, 16)
    } else {
        concurrency_limit
    };

    let actual_threads = concurrency.min(num_items);
    let items_queue = Arc::new(Mutex::new(
        items.into_iter().enumerate().collect::<Vec<_>>(),
    ));

    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(actual_threads);

        for _ in 0..actual_threads {
            let queue_clone = Arc::clone(&items_queue);

            let handle = scope.spawn(move || {
                let mut local_results = Vec::new();
                let mut local_batch = Vec::new();

                loop {
                    // Guided batch extraction: take a proportional chunk of tasks to minimize mutex contention
                    {
                        let mut guard = queue_clone.lock().unwrap();
                        let remaining = guard.len();
                        if remaining == 0 {
                            break;
                        }
                        let chunk_size = (remaining / (actual_threads * 2)).clamp(1, 8);
                        let start_idx = remaining.saturating_sub(chunk_size);
                        local_batch.extend(guard.split_off(start_idx));
                    }

                    // Process local batch without holding any lock
                    while let Some((index, item)) = local_batch.pop() {
                        let res = extract_and_replace(item.reader, &item.destination, item.limits);
                        local_results.push((index, res));
                    }
                }

                local_results
            });

            handles.push(handle);
        }

        let mut final_results: Vec<Option<Result<ExtractionSummary, FsError>>> =
            (0..num_items).map(|_| None).collect();

        for handle in handles {
            if let Ok(worker_results) = handle.join() {
                for (index, res) in worker_results {
                    if index < num_items {
                        final_results[index] = Some(res);
                    }
                }
            }
        }

        final_results
            .into_iter()
            .map(|opt| {
                opt.unwrap_or_else(|| {
                    Err(FsError::Io(std::io::Error::other(
                        "Extraction worker terminated unexpectedly",
                    )))
                })
            })
            .collect()
    })
}

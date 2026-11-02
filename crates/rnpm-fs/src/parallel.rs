use std::io::Read;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use crate::atomic::extract_and_replace;
use crate::error::FsError;
use crate::tarball::{ExtractionSummary, TarLimits};

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

    let items_queue = Arc::new(Mutex::new(items.into_iter().enumerate().collect::<Vec<_>>()));
    let results = Arc::new(Mutex::new(Vec::with_capacity(num_items)));
    {
        let mut guard = results.lock().unwrap();
        for _ in 0..num_items {
            guard.push(None);
        }
    }

    let actual_threads = concurrency.min(num_items);
    std::thread::scope(|scope| {
        for _ in 0..actual_threads {
            let queue_clone = Arc::clone(&items_queue);
            let results_clone = Arc::clone(&results);

            scope.spawn(move || loop {
                let next_item = {
                    let mut guard = queue_clone.lock().unwrap();
                    guard.pop()
                };

                match next_item {
                    Some((index, item)) => {
                        let res = extract_and_replace(item.reader, &item.destination, item.limits);
                        let mut res_guard = results_clone.lock().unwrap();
                        res_guard[index] = Some(res);
                    }
                    None => break,
                }
            });
        }
    });

    let mut guard = results.lock().unwrap();
    guard
        .drain(..)
        .map(|opt| {
            opt.unwrap_or_else(|| {
                Err(FsError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    "Extraction worker terminated unexpectedly",
                )))
            })
        })
        .collect()
}

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::Arc;
use std::thread::{self, JoinHandle};

const NODE_WRITER_SCRIPT: &str = r#"
const fs = require('fs');
const path = require('path');
const dirs = new Set();
const q = [];
let head = 0;
let inflight = 0;
let stdinEnded = false;
let failed = false;
const concurrency = parseInt(process.env.RNPM_NODE_WRITER_CONCURRENCY || '96', 10);

const timing = !!process.env.RNPM_TIMING_DEBUG;
const tStart = Date.now();
let tFirstItem = 0;
let tStdinEnd = 0;
let totalEnqueued = 0;
let totalBytes = 0;
let writesCompleted = 0;
let writtenAtStdinEnd = 0;
let mkdirCount = 0;
let mkdirTimeMs = 0;

function pump() {
  while (inflight < concurrency && head < q.length) {
    const item = q[head];
    q[head] = null;
    head++;
    inflight++;
    const onWriteDone = (err) => {
      if (err) {
        if (err.code === 'ENOENT') {
          mkdirCount++;
          const tMkdirStart = timing ? Date.now() : 0;
          try {
            fs.mkdirSync(path.dirname(item.p), { recursive: true });
          } catch (e) {}
          if (timing) {
            mkdirTimeMs += Date.now() - tMkdirStart;
          }
          const onRetryDone = (retryErr) => {
            if (retryErr) {
              console.error('NodeWriter error after mkdir:', item.p, retryErr);
              failed = true;
            }
            writesCompleted++;
            inflight--;
            pump();
          };
          if (item.m === 0o644) {
            fs.writeFile(item.p, item.b, onRetryDone);
          } else {
            fs.writeFile(item.p, item.b, { mode: item.m }, onRetryDone);
          }
          return;
        }
        console.error('NodeWriter error:', item.p, err);
        failed = true;
      }
      writesCompleted++;
      inflight--;
      pump();
    };

    if (item.m === 0o644) {
      fs.writeFile(item.p, item.b, onWriteDone);
    } else {
      fs.writeFile(item.p, item.b, { mode: item.m }, onWriteDone);
    }
  }
  if (head > 1024) {
    q.splice(0, head);
    head = 0;
  }
  if (stdinEnded && inflight === 0 && head === q.length) {
    if (timing) {
      const tEnd = Date.now();
      const mem = process.memoryUsage();
      console.error(`[TIMING_PROFILE] node_writer stats:`);
      console.error(`  first item received at: ${tFirstItem ? tFirstItem - tStart : 0} ms`);
      console.error(`  stdin ended at: ${tStdinEnd ? tStdinEnd - tStart : 0} ms (written so far: ${writtenAtStdinEnd}/${totalEnqueued})`);
      console.error(`  all writes finished at: ${tEnd - tStart} ms (${writesCompleted} files, ${(totalBytes / 1024 / 1024).toFixed(1)} MiB)`);
      console.error(`  mkdirSync calls: ${mkdirCount}, total mkdir time: ${mkdirTimeMs.toFixed(1)} ms`);
      console.error(`  node_writer peak rss: ${(mem.rss / 1024 / 1024).toFixed(1)} MiB, heap: ${(mem.heapUsed / 1024 / 1024).toFixed(1)} MiB`);
    }
    process.exit(failed ? 1 : 0);
  }
}

let hdr = null;

process.stdin.on('readable', () => {
  let count = 0;
  while (true) {
    if (!hdr) {
      const h = process.stdin.read(12);
      if (!h) break;
      hdr = {
        pLen: h.readUInt32LE(0),
        mode: h.readUInt32LE(4),
        dLen: h.readUInt32LE(8)
      };
    }
    const body = process.stdin.read(hdr.pLen + hdr.dLen);
    if (!body) break;
    if (timing && tFirstItem === 0) tFirstItem = Date.now();
    const p = body.toString('utf8', 0, hdr.pLen);
    const b = body.subarray(hdr.pLen);
    totalEnqueued++;
    totalBytes += hdr.dLen;
    q.push({ p, b, m: hdr.mode });
    hdr = null;
    count++;
    if (count >= 32) {
      pump();
      count = 0;
    }
  }
  pump();
});

process.stdin.on('end', () => {
  stdinEnded = true;
  tStdinEnd = Date.now();
  writtenAtStdinEnd = writesCompleted;
  pump();
});
"#;

pub enum NodeWriterMsg {
    File {
        path: String,
        data: Arc<Vec<u8>>,
        mode: u32,
    },
    Close,
}

struct NodeWriterWorker {
    child: Child,
    sender: SyncSender<NodeWriterMsg>,
    thread_handle: Option<JoinHandle<std::io::Result<()>>>,
}

impl NodeWriterWorker {
    fn spawn(uv_size: &str, concurrency: &str) -> Result<Self, std::io::Error> {
        let mut child = Command::new("node")
            .env("UV_THREADPOOL_SIZE", uv_size)
            .env("RNPM_NODE_WRITER_CONCURRENCY", concurrency)
            .arg("-e")
            .arg(NODE_WRITER_SCRIPT)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let mut stdin = std::io::BufWriter::with_capacity(64 * 1024, child.stdin.take().unwrap());
        let (tx, rx): (SyncSender<NodeWriterMsg>, Receiver<NodeWriterMsg>) = sync_channel(256);

        let handle = thread::spawn(move || -> std::io::Result<()> {
            use std::io::Write;
            let mut hdr = [0u8; 12];
            while let Ok(msg) = rx.recv() {
                match msg {
                    NodeWriterMsg::File { path, data, mode } => {
                        let path_bytes = path.as_bytes();
                        hdr[0..4].copy_from_slice(&(path_bytes.len() as u32).to_le_bytes());
                        hdr[4..8].copy_from_slice(&mode.to_le_bytes());
                        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
                        if let Err(e) = stdin.write_all(&hdr) {
                            eprintln!("[NODE_WRITER_ERR] write hdr: {e}");
                            return Err(e);
                        }
                        if let Err(e) = stdin.write_all(path_bytes) {
                            eprintln!("[NODE_WRITER_ERR] write path: {e}");
                            return Err(e);
                        }
                        for chunk in data.chunks(64 * 1024) {
                            if let Err(e) = stdin.write_all(chunk) {
                                eprintln!("[NODE_WRITER_ERR] write data: {e}");
                                return Err(e);
                            }
                        }
                    }
                    NodeWriterMsg::Close => break,
                }
            }
            if let Err(e) = stdin.flush() {
                eprintln!("[NODE_WRITER_ERR] flush: {e}");
                return Err(e);
            }
            drop(stdin);
            Ok(())
        });

        Ok(Self {
            child,
            sender: tx,
            thread_handle: Some(handle),
        })
    }

    fn close_input(&mut self) {
        let _ = self.sender.send(NodeWriterMsg::Close);
    }

    fn wait(mut self) -> Result<(), std::io::Error> {
        if let Some(h) = self.thread_handle.take() {
            h.join()
                .map_err(|_| std::io::Error::other("NodeWriter thread panicked"))??;
        }
        let status = self.child.wait()?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "NodeWriter process exited with error status: {status:?}"
            )));
        }
        Ok(())
    }
}

/// A background Node.js worker pool that writes files concurrently using libuv/fs.writeFile.
pub struct NodeWriter {
    workers: Vec<NodeWriterWorker>,
    senders: Arc<Vec<SyncSender<NodeWriterMsg>>>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl NodeWriter {
    /// Spawns background Node.js worker process(es) and begins listening for file write commands.
    pub fn spawn() -> Result<Self, std::io::Error> {
        let num_workers: usize = std::env::var("RNPM_NODE_WRITER_WORKERS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(1);

        let uv_size = std::env::var("UV_THREADPOOL_SIZE")
            .or_else(|_| std::env::var("RNPM_UV_THREADPOOL_SIZE"))
            .unwrap_or_else(|_| "128".to_string());

        let concurrency = std::env::var("RNPM_NODE_WRITER_CONCURRENCY")
            .unwrap_or_else(|_| "128".to_string());

        let mut workers = Vec::with_capacity(num_workers);
        let mut senders = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let worker = NodeWriterWorker::spawn(&uv_size, &concurrency)?;
            senders.push(worker.sender.clone());
            workers.push(worker);
        }

        Ok(Self {
            workers,
            senders: Arc::new(senders),
            counter: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
    }

    /// Obtains a cloned channel sender for worker threads.
    pub fn sender(&self) -> NodeWriterSender {
        NodeWriterSender {
            senders: Arc::clone(&self.senders),
            counter: Arc::clone(&self.counter),
        }
    }

    /// Signals that no more files will be sent, closing the input stream to Node.js.
    pub fn close_input(&mut self) {
        for worker in &mut self.workers {
            worker.close_input();
        }
    }

    /// Waits for Node.js worker(s) to finish writing all files to disk and exit.
    pub fn wait(self) -> Result<(), std::io::Error> {
        for worker in self.workers {
            worker.wait()?;
        }
        Ok(())
    }

    /// Flushes all pending writes, waits for Node.js to finish writing all files to disk, and exits.
    pub fn finish(mut self) -> Result<(), std::io::Error> {
        self.close_input();
        self.wait()
    }
}

/// Cloneable sender that distributes write tasks round-robin across NodeWriter worker processes.
#[derive(Clone)]
pub struct NodeWriterSender {
    senders: Arc<Vec<SyncSender<NodeWriterMsg>>>,
    counter: Arc<std::sync::atomic::AtomicUsize>,
}

impl NodeWriterSender {
    pub fn send(&self, msg: NodeWriterMsg) -> Result<(), std::io::Error> {
        let idx = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed) % self.senders.len();
        self.senders[idx]
            .send(msg)
            .map_err(|e| std::io::Error::other(format!("NodeWriter disconnected: {e}")))
    }
}

/// A task for the pure Rust writer thread pool.
pub enum WriteTask {
    File {
        path: PathBuf,
        data: Arc<Vec<u8>>,
        mode: u32,
    },
    Close,
}

/// A dedicated pool of OS threads that drain a bounded channel and write files via `write_file_fast`.
pub struct RustWriterPool {
    sender: Option<SyncSender<WriteTask>>,
    handles: Vec<JoinHandle<std::io::Result<()>>>,
}

impl RustWriterPool {
    /// Spawns `num_threads` OS worker threads draining `capacity` bounded channel.
    pub fn spawn(num_threads: usize, capacity: usize) -> Result<Self, std::io::Error> {
        let (tx, rx) = sync_channel::<WriteTask>(capacity);
        let rx = Arc::new(std::sync::Mutex::new(rx));
        let mut handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let rx = Arc::clone(&rx);
            handles.push(thread::spawn(move || -> std::io::Result<()> {
                let mut batch = Vec::with_capacity(16);
                loop {
                    batch.clear();
                    {
                        let Ok(guard) = rx.lock() else { break; };
                        match guard.recv() {
                            Ok(task) => {
                                let is_close = matches!(task, WriteTask::Close);
                                batch.push(task);
                                if !is_close {
                                    while batch.len() < 16 {
                                        match guard.try_recv() {
                                            Ok(t) => {
                                                let close = matches!(t, WriteTask::Close);
                                                batch.push(t);
                                                if close {
                                                    break;
                                                }
                                            }
                                            Err(_) => break,
                                        }
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    let mut should_exit = false;
                    for task in &batch {
                        match task {
                            WriteTask::File { path, data, mode } => {
                                crate::writer::write_file_fast(path, data, *mode, 65536)?;
                            }
                            WriteTask::Close => {
                                should_exit = true;
                                break;
                            }
                        }
                    }
                    if should_exit {
                        break;
                    }
                }
                Ok(())
            }));
        }

        Ok(Self {
            sender: Some(tx),
            handles,
        })
    }

    /// Obtains a cloned sender for worker threads.
    pub fn sender(&self) -> SyncSender<WriteTask> {
        self.sender.as_ref().unwrap().clone()
    }

    /// Signals workers that no more tasks will be enqueued.
    pub fn close_input(&mut self) {
        if let Some(s) = self.sender.take() {
            for _ in 0..self.handles.len() {
                let _ = s.send(WriteTask::Close);
            }
        }
    }

    /// Waits for all worker threads to finish.
    pub fn wait(mut self) -> Result<(), std::io::Error> {
        for h in self.handles.drain(..) {
            h.join()
                .map_err(|_| std::io::Error::other("RustWriterPool worker panicked"))??;
        }
        Ok(())
    }

    /// Sends close sentinels to all worker threads and joins them.
    pub fn finish(mut self) -> Result<(), std::io::Error> {
        self.close_input();
        self.wait()
    }
}

/// Cloneable sender for async file writes across worker threads.
#[derive(Clone)]
pub enum AsyncFileWriterSender {
    Node(NodeWriterSender),
    Rust(SyncSender<WriteTask>),
}

impl AsyncFileWriterSender {
    /// Sends a file write task to the background writer pool/helper.
    /// Fails fast if the background writer has disconnected or encountered an error.
    pub fn send(&self, path: PathBuf, data: Vec<u8>, mode: u32) -> Result<(), std::io::Error> {
        self.send_arc(path, Arc::new(data), mode)
    }

    /// Sends a file write task with pre-shared Arc<Vec<u8>> to avoid buffer copies.
    pub fn send_arc(&self, path: PathBuf, data: Arc<Vec<u8>>, mode: u32) -> Result<(), std::io::Error> {
        match self {
            Self::Node(s) => {
                let path_str = path.to_string_lossy().to_string();
                s.send(NodeWriterMsg::File {
                    path: path_str,
                    data,
                    mode,
                })
            }
            Self::Rust(s) => s
                .send(WriteTask::File { path, data, mode })
                .map_err(|e| std::io::Error::other(format!("RustWriterPool disconnected: {e}"))),
        }
    }
}

/// Unified async file writer that dispatches to either `NodeWriter` or `RustWriterPool`.
pub enum AsyncFileWriter {
    Node(NodeWriter),
    Rust(RustWriterPool),
}

impl AsyncFileWriter {
    /// Spawns the async file writer. Respects `RNPM_WRITER=rust` or `RNPM_WRITER=node` overrides.
    /// Defaults to `NodeWriter` if available, falling back to `RustWriterPool`.
    pub fn spawn() -> Result<Self, std::io::Error> {
        let pref = std::env::var("RNPM_WRITER").unwrap_or_default();
        if pref.eq_ignore_ascii_case("rust") {
            return Ok(Self::Rust(RustWriterPool::spawn(16, 4096)?));
        }

        // Try NodeWriter first
        match NodeWriter::spawn() {
            Ok(nw) => Ok(Self::Node(nw)),
            Err(e) => {
                if pref.eq_ignore_ascii_case("node") {
                    return Err(e);
                }
                // Fall back to dedicated Rust thread pool
                Ok(Self::Rust(RustWriterPool::spawn(16, 4096)?))
            }
        }
    }

    /// Obtains a cloned sender for distributing write tasks.
    pub fn sender(&self) -> AsyncFileWriterSender {
        match self {
            Self::Node(nw) => AsyncFileWriterSender::Node(nw.sender()),
            Self::Rust(rw) => AsyncFileWriterSender::Rust(rw.sender()),
        }
    }

    /// Signals that no more files will be sent, closing input to background worker(s).
    pub fn close_input(&mut self) {
        match self {
            Self::Node(nw) => nw.close_input(),
            Self::Rust(rw) => rw.close_input(),
        }
    }

    /// Waits for all pending writes to complete on disk and worker(s) to exit.
    pub fn wait(self) -> Result<(), std::io::Error> {
        match self {
            Self::Node(nw) => nw.wait(),
            Self::Rust(rw) => rw.wait(),
        }
    }

    /// Flushes all pending writes and waits for completion.
    pub fn finish(mut self) -> Result<(), std::io::Error> {
        self.close_input();
        self.wait()
    }
}

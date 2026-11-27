use std::collections::VecDeque;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{sync_channel, Receiver, SendError, SyncSender};
use std::sync::{Arc, Condvar, Mutex};
use std::thread::{self, JoinHandle};

const NODE_WRITER_SCRIPT: &str = r#"
const fs = require('fs');
const path = require('path');
const q = [];
let head = 0;
let inflight = 0;
let stdinEnded = false;
let failed = false;
let completed = false;
const concurrency = parseInt(process.env.RNPM_NODE_WRITER_CONCURRENCY || '96', 10);
const maxQueue = concurrency * 2;

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
let peakQueue = 0;
let sumQueueDelayMs = 0;
let sumServiceTimeMs = 0;
let maxServiceTimeMs = 0;

let paused = false;
const hdrBuf = Buffer.allocUnsafe(12);
let hdrLen = 0;
let activeFrame = null;

// Exclusive creation avoids truncating a pre-existing hardlink or following a
// symlink. Fresh installations pay no additional stat/unlink syscall.
function writeItem(item, done) {
  const options = { flag: 'wx', mode: item.m };
  fs.writeFile(item.p, item.b, options, (err) => {
    if (!err || err.code !== 'EEXIST') return done(err);
    fs.unlink(item.p, (unlinkErr) => {
      if (unlinkErr && unlinkErr.code !== 'ENOENT') return done(unlinkErr);
      fs.writeFile(item.p, item.b, options, done);
    });
  });
}

function finishWrite(item, err, tWriteStart) {
  if (timing) {
    const sTime = Date.now() - tWriteStart;
    sumServiceTimeMs += sTime;
    if (sTime > maxServiceTimeMs) maxServiceTimeMs = sTime;
  }
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
      writeItem(item, (retryErr) => {
        if (retryErr) {
          console.error('NodeWriter error after mkdir:', item.p, retryErr);
          failed = true;
        }
        writesCompleted++;
        inflight--;
        pump();
        checkResume();
      });
      return;
    }
    console.error('NodeWriter error:', item.p, err);
    failed = true;
  }
  writesCompleted++;
  inflight--;
  pump();
  checkResume();
}

function pump() {
  while (inflight < concurrency && head < q.length) {
    const item = q[head];
    q[head] = null;
    head++;
    inflight++;
    if (timing) {
      sumQueueDelayMs += Date.now() - item.t;
    }
    const tWriteStart = timing ? Date.now() : 0;
    writeItem(item, (err) => finishWrite(item, err, tWriteStart));
  }
  if (head === q.length) {
    q.length = 0;
    head = 0;
  } else if (head > 4096) {
    q.splice(0, head);
    head = 0;
  }
  if (stdinEnded && inflight === 0 && head === q.length && !completed) {
    completed = true;
    if (timing) {
      const tEnd = Date.now();
      const mem = process.memoryUsage();
      const avgQDelay = writesCompleted ? (sumQueueDelayMs / writesCompleted).toFixed(1) : 0;
      const avgService = writesCompleted ? (sumServiceTimeMs / writesCompleted).toFixed(1) : 0;
      console.error(`[TIMING_PROFILE] node_writer stats:`);
      console.error(`[TIMING_PROFILE]   first item received at: ${tFirstItem ? tFirstItem - tStart : 0} ms`);
      console.error(`[TIMING_PROFILE]   stdin ended at: ${tStdinEnd ? tStdinEnd - tStart : 0} ms (written so far: ${writtenAtStdinEnd}/${totalEnqueued})`);
      console.error(`[TIMING_PROFILE]   all writes finished at: ${tEnd - tStart} ms (${writesCompleted} files, ${(totalBytes / 1024 / 1024).toFixed(1)} MiB)`);
      console.error(`[TIMING_PROFILE]   peak queue depth: ${peakQueue}, avg queue delay: ${avgQDelay} ms`);
      console.error(`[TIMING_PROFILE]   avg write service time: ${avgService} ms, max service time: ${maxServiceTimeMs} ms`);
      console.error(`[TIMING_PROFILE]   mkdirSync calls: ${mkdirCount}, total mkdir time: ${mkdirTimeMs.toFixed(1)} ms`);
      console.error(`[TIMING_PROFILE]   node_writer peak rss: ${(mem.rss / 1024 / 1024).toFixed(1)} MiB, heap: ${(mem.heapUsed / 1024 / 1024).toFixed(1)} MiB`);
    }
    // Let the stdin end/close callbacks unwind before Node tears down libuv.
    // Forcing exit inside a Windows pipe callback can stall process shutdown
    // even after every file callback and the final timing banner completed.
    process.exitCode = failed ? 1 : 0;
  }
}

function checkResume() {
  if (paused && (q.length - head) < concurrency) {
    paused = false;
    process.stdin.resume();
  }
}

function enqueueFrame(p, b, m) {
  if (timing && tFirstItem === 0) tFirstItem = Date.now();
  totalEnqueued++;
  totalBytes += b.length;
  q.push({ p, b, m, t: timing ? Date.now() : 0 });
}

function startOrEmitFrame(pLen, mode, dLen, chunk, bodyStart, len) {
  const bodyLen = pLen + dLen;
  if (bodyStart + bodyLen <= len) {
    const dStart = bodyStart + pLen;
    enqueueFrame(
      chunk.toString('utf8', bodyStart, dStart),
      chunk.subarray(dStart, bodyStart + bodyLen),
      mode
    );
    return bodyStart + bodyLen;
  }
  const buf = Buffer.allocUnsafe(bodyLen);
  const avail = len - bodyStart;
  if (avail > 0) chunk.copy(buf, 0, bodyStart, len);
  activeFrame = { pLen, mode, bodyLen, buf, pos: avail };
  return len;
}

process.stdin.on('data', (chunk) => {
  const len = chunk.length;
  let pos = 0;
  while (pos < len) {
    if (activeFrame !== null) {
      const take = Math.min(activeFrame.bodyLen - activeFrame.pos, len - pos);
      chunk.copy(activeFrame.buf, activeFrame.pos, pos, pos + take);
      activeFrame.pos += take;
      pos += take;
      if (activeFrame.pos === activeFrame.bodyLen) {
        const f = activeFrame;
        activeFrame = null;
        enqueueFrame(f.buf.toString('utf8', 0, f.pLen), f.buf.subarray(f.pLen), f.mode);
      }
      continue;
    }
    if (hdrLen > 0) {
      const take = Math.min(12 - hdrLen, len - pos);
      chunk.copy(hdrBuf, hdrLen, pos, pos + take);
      hdrLen += take;
      pos += take;
      if (hdrLen < 12) break;
      hdrLen = 0;
      pos = startOrEmitFrame(
        hdrBuf.readUInt32LE(0),
        hdrBuf.readUInt32LE(4),
        hdrBuf.readUInt32LE(8),
        chunk,
        pos,
        len
      );
      continue;
    }
    if (len - pos < 12) {
      chunk.copy(hdrBuf, 0, pos, len);
      hdrLen = len - pos;
      break;
    }
    pos = startOrEmitFrame(
      chunk.readUInt32LE(pos),
      chunk.readUInt32LE(pos + 4),
      chunk.readUInt32LE(pos + 8),
      chunk,
      pos + 12,
      len
    );
  }
  pump();
  const curQueued = q.length - head;
  if (curQueued > peakQueue) peakQueue = curQueued;
  if (!paused && curQueued >= maxQueue) {
    paused = true;
    process.stdin.pause();
  }
});

process.stdin.on('end', () => {
  stdinEnded = true;
  tStdinEnd = Date.now();
  writtenAtStdinEnd = writesCompleted;
  if (hdrLen > 0 || activeFrame !== null) {
    console.error('NodeWriter truncated frame at EOF');
    failed = true;
  }
  pump();
});
"#;

#[cfg(test)]
mod worker_tests {
    use super::*;

    #[test]
    fn bounded_writer_drains_and_replaces_hardlink_without_touching_source() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("original");
        let linked = dir.path().join("linked");
        std::fs::write(&original, b"keep me").unwrap();
        std::fs::hard_link(&original, &linked).unwrap();
        let mut writer = NodeWriterWorker::spawn("4", "4").unwrap();
        for i in 0..700 {
            let path = if i == 0 {
                linked.clone()
            } else {
                dir.path().join(format!("{i}.txt"))
            };
            writer
                .sender
                .send(NodeWriterMsg::File {
                    path: path.to_string_lossy().into_owned(),
                    data: Arc::new(i.to_string().into_bytes()),
                    mode: 0o644,
                })
                .unwrap();
        }
        writer.close_input();
        writer.wait().unwrap();
        assert_eq!(std::fs::read(original).unwrap(), b"keep me");
        assert_eq!(std::fs::read(linked).unwrap(), b"0");
        for i in 1..700 {
            assert_eq!(
                std::fs::read(dir.path().join(format!("{i}.txt"))).unwrap(),
                i.to_string().as_bytes()
            );
        }
    }

    #[test]
    fn pipe_error_still_waits_for_child_exit() {
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("finished");
        let child = Command::new("node")
            .args([
                "-e",
                "setTimeout(() => require('fs').writeFileSync(process.argv[1], 'done'), 40)",
            ])
            .arg(&marker)
            .stdin(Stdio::null())
            .spawn()
            .unwrap();
        let (sender, _receiver) = sync_channel(1);
        let worker = NodeWriterWorker {
            child,
            sender,
            thread_handle: Some(thread::spawn(|| {
                Err(std::io::Error::other("injected pipe error"))
            })),
        };
        assert!(worker
            .wait()
            .unwrap_err()
            .to_string()
            .contains("injected pipe error"));
        assert_eq!(std::fs::read(marker).unwrap(), b"done");
    }

    #[test]
    fn writer_exits_after_eof_under_default_parallelism() {
        for round in 0..8 {
            let dir = tempfile::tempdir().unwrap();
            let mut writer = NodeWriterWorker::spawn("128", "128").unwrap();
            let payload = Arc::new(vec![round; 8192]);
            for file in 0..2048 {
                writer
                    .sender
                    .send(NodeWriterMsg::File {
                        path: dir
                            .path()
                            .join(format!("{file}.js"))
                            .to_string_lossy()
                            .into_owned(),
                        data: payload.clone(),
                        mode: 0o644,
                    })
                    .unwrap();
            }
            writer.close_input();
            writer
                .thread_handle
                .take()
                .unwrap()
                .join()
                .unwrap()
                .unwrap();
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            loop {
                if let Some(status) = writer.child.try_wait().unwrap() {
                    assert!(status.success());
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    writer.child.kill().unwrap();
                    writer.child.wait().unwrap();
                    panic!("Node writer did not exit after EOF in round {round}");
                }
                thread::sleep(std::time::Duration::from_millis(10));
            }
            assert_eq!(std::fs::read(dir.path().join("2047.js")).unwrap(), *payload);
        }
    }

    #[test]
    fn writer_handles_large_spanning_and_mixed_frames() {
        let dir = tempfile::tempdir().unwrap();
        let mut writer = NodeWriterWorker::spawn("8", "8").unwrap();
        let small: Arc<Vec<u8>> = Arc::new(b"small".to_vec());
        let empty: Arc<Vec<u8>> = Arc::new(Vec::new());
        let large_a: Arc<Vec<u8>> = Arc::new((0..(600 * 1024 + 17)).map(|i| (i % 251) as u8).collect());
        let large_b: Arc<Vec<u8>> = Arc::new((0..(512 * 1024 + 3)).map(|i| ((i * 7) % 241) as u8).collect());

        let items = [
            ("empty.txt", Arc::clone(&empty)),
            ("large_a.bin", Arc::clone(&large_a)),
            ("tiny_1.txt", Arc::clone(&small)),
            ("large_b.bin", Arc::clone(&large_b)),
            ("tiny_2.txt", Arc::clone(&small)),
        ];
        for (name, data) in &items {
            writer
                .sender
                .send(NodeWriterMsg::File {
                    path: dir.path().join(name).to_string_lossy().into_owned(),
                    data: Arc::clone(data),
                    mode: 0o644,
                })
                .unwrap();
        }
        writer.close_input();
        writer.wait().unwrap();

        for (name, expected) in &items {
            assert_eq!(std::fs::read(dir.path().join(name)).unwrap(), **expected, "mismatch for {name}");
        }
    }
}

#[cfg(test)]
mod spawn_for_hint_tests {
    use super::*;

    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    struct EnvGuard {
        key: &'static str,
        prev: Option<String>,
    }

    impl EnvGuard {
        fn set(key: &'static str, val: &str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::set_var(key, val);
            Self { key, prev }
        }

        fn remove(key: &'static str) -> Self {
            let prev = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, prev }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            if let Some(ref prev) = self.prev {
                std::env::set_var(self.key, prev);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    #[test]
    fn spawn_for_hint_small_selects_rust() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::remove("RNPM_WRITER");
        let writer = AsyncFileWriter::spawn_for_hint(3).expect("spawn_for_hint(3) failed");
        assert!(matches!(writer, AsyncFileWriter::Rust(_)));
        writer.finish().expect("finish failed");
    }

    #[test]
    fn spawn_for_hint_large_selects_rust() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::remove("RNPM_WRITER");
        let writer = AsyncFileWriter::spawn_for_hint(50).expect("spawn_for_hint(50) failed");
        assert!(matches!(writer, AsyncFileWriter::Rust(_)));
        writer.finish().expect("finish failed");
    }

    #[test]
    fn spawn_for_hint_node_env_overrides_small_hint() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::set("RNPM_WRITER", "node");
        let node_available = Command::new("node")
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if node_available {
            let writer = AsyncFileWriter::spawn_for_hint(3)
                .expect("spawn_for_hint(3) with RNPM_WRITER=node failed");
            assert!(matches!(writer, AsyncFileWriter::Node(_)));
            writer.finish().expect("finish failed");
        }
    }

    #[test]
    fn spawn_for_hint_rust_env_overrides_large_hint() {
        let _lock = ENV_MUTEX.lock().unwrap();
        let _guard = EnvGuard::set("RNPM_WRITER", "rust");
        let writer = AsyncFileWriter::spawn_for_hint(50)
            .expect("spawn_for_hint(50) with RNPM_WRITER=rust failed");
        assert!(matches!(writer, AsyncFileWriter::Rust(_)));
        writer.finish().expect("finish failed");
    }

}

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
    thread_handle: Option<JoinHandle<std::io::Result<(u64, u64)>>>,
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

        let mut stdin = std::io::BufWriter::with_capacity(512 * 1024, child.stdin.take().unwrap());
        let (tx, rx): (SyncSender<NodeWriterMsg>, Receiver<NodeWriterMsg>) = sync_channel(1024);

        let handle = thread::spawn(move || -> std::io::Result<(u64, u64)> {
            use std::io::Write;
            let mut hdr = [0u8; 12];
            let mut files = 0;
            let mut bytes = 0;
            let write_frame = |stdin: &mut std::io::BufWriter<std::process::ChildStdin>,
                               hdr: &mut [u8; 12],
                               path: &str,
                               data: &[u8],
                               mode: u32|
             -> std::io::Result<u64> {
                let path_bytes = path.as_bytes();
                let Ok(path_len) = u32::try_from(path_bytes.len()) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "NodeWriter path exceeds u32::MAX bytes",
                    ));
                };
                let Ok(data_len) = u32::try_from(data.len()) else {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "NodeWriter file payload exceeds u32::MAX bytes",
                    ));
                };
                hdr[0..4].copy_from_slice(&path_len.to_le_bytes());
                hdr[4..8].copy_from_slice(&mode.to_le_bytes());
                hdr[8..12].copy_from_slice(&data_len.to_le_bytes());
                if let Err(e) = stdin.write_all(hdr) {
                    eprintln!("[NODE_WRITER_ERR] write hdr: {e}");
                    return Err(e);
                }
                if let Err(e) = stdin.write_all(path_bytes) {
                    eprintln!("[NODE_WRITER_ERR] write path: {e}");
                    return Err(e);
                }
                if let Err(e) = stdin.write_all(data) {
                    eprintln!("[NODE_WRITER_ERR] write data: {e}");
                    return Err(e);
                }
                Ok(u64::from(data_len))
            };

            while let Ok(msg) = rx.recv() {
                match msg {
                    NodeWriterMsg::File { path, data, mode } => {
                        let written = write_frame(&mut stdin, &mut hdr, &path, &data, mode)?;
                        files += 1;
                        bytes += written;
                    }
                    NodeWriterMsg::Close => {
                        while let Ok(rem) = rx.try_recv() {
                            if let NodeWriterMsg::File { path, data, mode } = rem {
                                let written = write_frame(&mut stdin, &mut hdr, &path, &data, mode)?;
                                files += 1;
                                bytes += written;
                            }
                        }
                        break;
                    }
                }
            }
            if let Err(e) = stdin.flush() {
                eprintln!("[NODE_WRITER_ERR] flush: {e}");
                return Err(e);
            }
            drop(stdin);
            Ok((files, bytes))
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
        // A pipe failure must not skip reaping the child process.
        let input_result = self.thread_handle.take().map_or(Ok((0, 0)), |h| {
            h.join()
                .map_err(|_| std::io::Error::other("NodeWriter thread panicked"))?
        });
        let status_result = self.child.wait();
        let (files, bytes) = input_result?;
        let status = status_result?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "NodeWriter process exited with error status: {status:?}"
            )));
        }
        crate::tarball::record_files_created_batch(files, bytes);
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
        let num_workers: usize = match std::env::var("RNPM_NODE_WRITER_WORKERS") {
            Ok(v) => match v.parse::<usize>() {
                Ok(0) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "RNPM_NODE_WRITER_WORKERS must be greater than 0",
                    ));
                }
                Ok(n) => n,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Invalid RNPM_NODE_WRITER_WORKERS value: {v}"),
                    ));
                }
            },
            Err(_) => 1,
        };

        let uv_size = std::env::var("UV_THREADPOOL_SIZE")
            .or_else(|_| std::env::var("RNPM_UV_THREADPOOL_SIZE"))
            .unwrap_or_else(|_| "128".to_string());

        let concurrency =
            std::env::var("RNPM_NODE_WRITER_CONCURRENCY").unwrap_or_else(|_| "128".to_string());
        for (name, value) in [
            ("UV_THREADPOOL_SIZE", &uv_size),
            ("RNPM_NODE_WRITER_CONCURRENCY", &concurrency),
        ] {
            if !matches!(value.parse::<usize>(), Ok(n) if n > 0) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("{name} must be a positive integer, got {value:?}"),
                ));
            }
        }

        let mut workers: Vec<NodeWriterWorker> = Vec::with_capacity(num_workers);
        let mut senders = Vec::with_capacity(num_workers);

        for _ in 0..num_workers {
            let worker = match NodeWriterWorker::spawn(&uv_size, &concurrency) {
                Ok(w) => w,
                Err(e) => {
                    // Clean up any already spawned workers before returning
                    for mut w in workers {
                        w.close_input();
                        let _ = w.wait();
                    }
                    return Err(e);
                }
            };
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
    /// Ensures that all workers are waited/joined even if one fails.
    pub fn wait(self) -> Result<(), std::io::Error> {
        let mut first_err = None;
        for worker in self.workers {
            if let Err(e) = worker.wait() {
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }
        if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(())
        }
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
        let idx = self
            .counter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            % self.senders.len();
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

struct RustWriterQueueState {
    queue: VecDeque<WriteTask>,
    closed: bool,
    sender_count: usize,
    capacity: usize,
}

struct RustWriterQueue {
    state: Mutex<RustWriterQueueState>,
    not_empty: Condvar,
    not_full: Condvar,
}

impl RustWriterQueue {
    fn new(capacity: usize) -> Arc<Self> {
        let cap = capacity.max(1);
        Arc::new(Self {
            state: Mutex::new(RustWriterQueueState {
                queue: VecDeque::with_capacity(cap.min(4096)),
                closed: false,
                sender_count: 1,
                capacity: cap,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
        })
    }

    fn close(&self) {
        if let Ok(mut guard) = self.state.lock() {
            guard.closed = true;
            self.not_empty.notify_all();
            self.not_full.notify_all();
        }
    }
}

/// Cloneable bounded sender for `RustWriterPool` without blocking-wait mutex convoy.
pub struct RustWriterSender {
    inner: Arc<RustWriterQueue>,
}

impl Clone for RustWriterSender {
    fn clone(&self) -> Self {
        if let Ok(mut guard) = self.inner.state.lock() {
            guard.sender_count = guard.sender_count.saturating_add(1);
        }
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Drop for RustWriterSender {
    fn drop(&mut self) {
        if let Ok(mut guard) = self.inner.state.lock() {
            guard.sender_count = guard.sender_count.saturating_sub(1);
            if guard.sender_count == 0 {
                guard.closed = true;
                self.inner.not_empty.notify_all();
            }
        }
    }
}

impl RustWriterSender {
    /// Sends a write task to the worker queue, blocking if at capacity until space frees or the queue closes.
    pub fn send(&self, task: WriteTask) -> Result<(), SendError<WriteTask>> {
        let Ok(mut guard) = self.inner.state.lock() else {
            return Err(SendError(task));
        };
        while guard.queue.len() >= guard.capacity && !guard.closed {
            guard = match self.inner.not_full.wait(guard) {
                Ok(g) => g,
                Err(_) => return Err(SendError(task)),
            };
        }
        if guard.closed {
            return Err(SendError(task));
        }
        let was_empty = guard.queue.is_empty();
        guard.queue.push_back(task);
        drop(guard);
        if was_empty {
            self.inner.not_empty.notify_one();
        }
        Ok(())
    }
}

/// A dedicated pool of OS threads that drain a bounded queue without lock-held blocking waits.
pub struct RustWriterPool {
    queue: Arc<RustWriterQueue>,
    sender: Option<RustWriterSender>,
    handles: Vec<JoinHandle<std::io::Result<()>>>,
}

impl RustWriterPool {
    /// Spawns `num_threads` OS worker threads draining a bounded queue of `capacity` slots.
    pub fn spawn(num_threads: usize, capacity: usize) -> Result<Self, std::io::Error> {
        let queue = RustWriterQueue::new(capacity);
        let sender = RustWriterSender {
            inner: Arc::clone(&queue),
        };
        let mut handles = Vec::with_capacity(num_threads);

        for _ in 0..num_threads {
            let q = Arc::clone(&queue);
            handles.push(thread::spawn(move || -> std::io::Result<()> {
                let mut batch = Vec::with_capacity(32);
                let mut wide_buf: Vec<u16> = Vec::with_capacity(260);
                let mut first_err: Option<std::io::Error> = None;
                loop {
                    batch.clear();
                    {
                        let Ok(mut guard) = q.state.lock() else {
                            break;
                        };
                        while guard.queue.is_empty() && !guard.closed {
                            guard = match q.not_empty.wait(guard) {
                                Ok(g) => g,
                                Err(_) => {
                                    return first_err.map_or(Ok(()), Err);
                                }
                            };
                        }
                        if guard.queue.is_empty() && guard.closed {
                            break;
                        }
                        while batch.len() < 32 {
                            match guard.queue.pop_front() {
                                Some(task) => {
                                    let is_close = matches!(task, WriteTask::Close);
                                    batch.push(task);
                                    if is_close {
                                        break;
                                    }
                                }
                                None => break,
                            }
                        }
                        let still_pending = !guard.queue.is_empty();
                        drop(guard);
                        if !batch.is_empty() {
                            q.not_full.notify_all();
                        }
                        if still_pending {
                            q.not_empty.notify_one();
                        }
                    }
                    let mut should_exit = false;
                    for task in batch.drain(..) {
                        match task {
                            WriteTask::File { path, data, mode } => {
                                if let Err(err) = crate::writer::write_file_fast_buf(
                                    &path,
                                    &data,
                                    mode,
                                    65536,
                                    &mut wide_buf,
                                    true,
                                ) {
                                    if first_err.is_none() {
                                        first_err = Some(err);
                                    }
                                }
                            }
                            WriteTask::Close => {
                                should_exit = true;
                            }
                        }
                    }
                    if should_exit {
                        break;
                    }
                }
                first_err.map_or(Ok(()), Err)
            }));
        }

        Ok(Self {
            queue,
            sender: Some(sender),
            handles,
        })
    }

    /// Obtains a cloned sender for worker threads.
    pub fn sender(&self) -> RustWriterSender {
        self.sender
            .as_ref()
            .expect("RustWriterPool sender already closed")
            .clone()
    }

    /// Signals workers that no more tasks will be enqueued, allowing all queued tasks to drain.
    pub fn close_input(&mut self) {
        self.sender.take();
        self.queue.close();
    }

    /// Waits for all worker threads to finish.
    pub fn wait(mut self) -> Result<(), std::io::Error> {
        let mut first_err = None;
        for h in self.handles.drain(..) {
            match h.join() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    if first_err.is_none() {
                        first_err = Some(e);
                    }
                }
                Err(_) => {
                    if first_err.is_none() {
                        first_err = Some(std::io::Error::other("RustWriterPool worker panicked"));
                    }
                }
            }
        }
        if let Some(err) = first_err {
            Err(err)
        } else {
            Ok(())
        }
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
    Rust(RustWriterSender),
}

impl AsyncFileWriterSender {
    /// Sends a file write task to the background writer pool/helper.
    /// Fails fast if the background writer has disconnected or encountered an error.
    pub fn send(&self, path: PathBuf, data: Vec<u8>, mode: u32) -> Result<(), std::io::Error> {
        self.send_arc(path, Arc::new(data), mode)
    }

    /// Sends a file write task with pre-shared Arc<Vec<u8>> to avoid buffer copies.
    pub fn send_arc(
        &self,
        path: PathBuf,
        data: Arc<Vec<u8>>,
        mode: u32,
    ) -> Result<(), std::io::Error> {
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
    /// Spawns the configured writer. Package counts no longer select a backend.
    pub fn spawn_for_hint(_estimated_packages: usize) -> Result<Self, std::io::Error> {
        Self::spawn()
    }

    /// Uses the Rust writer unless `RNPM_WRITER=node` explicitly selects Node.js.
    pub fn spawn() -> Result<Self, std::io::Error> {
        if std::env::var("RNPM_WRITER").is_ok_and(|pref| pref.eq_ignore_ascii_case("node")) {
            return NodeWriter::spawn().map(Self::Node);
        }
        RustWriterPool::spawn(16, 4096).map(Self::Rust)
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

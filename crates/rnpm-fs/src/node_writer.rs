use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
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
const concurrency = 16;

function pump() {
  while (inflight < concurrency && head < q.length) {
    const item = q[head++];
    inflight++;
    const dir = path.dirname(item.p);
    let cur = dir;
    let needMkdir = false;
    while (cur && !dirs.has(cur)) {
      dirs.add(cur);
      needMkdir = true;
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
    if (needMkdir) {
      try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
    }
    const writePromise = (item.m === 0o644)
      ? fs.promises.writeFile(item.p, item.b)
      : fs.promises.writeFile(item.p, item.b, { mode: item.m });
    writePromise
      .then(() => {
        inflight--;
        pump();
      })
      .catch(err => {
        console.error('NodeWriter error:', item.p, err);
        failed = true;
        inflight--;
        pump();
      });
  }
  if (head > 1000 && head === q.length) {
    q.length = 0;
    head = 0;
  }
  if (stdinEnded && inflight === 0 && head === q.length) {
    process.exit(failed ? 1 : 0);
  }
}

let hdr = null;

process.stdin.on('readable', () => {
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
    const p = body.toString('utf8', 0, hdr.pLen);
    const b = body.subarray(hdr.pLen);
    q.push({ p, b, m: hdr.mode });
    hdr = null;
  }
  pump();
});

process.stdin.on('end', () => {
  stdinEnded = true;
  pump();
});
"#;

pub enum NodeWriterMsg {
    File {
        path: String,
        data: Vec<u8>,
        mode: u32,
    },
    Close,
}

/// A background Node.js worker that writes files concurrently using libuv/fs.promises.
pub struct NodeWriter {
    child: Child,
    sender: Sender<NodeWriterMsg>,
    thread_handle: Option<JoinHandle<std::io::Result<()>>>,
}

impl NodeWriter {
    /// Spawns a background Node.js process and begins listening for file write commands.
    pub fn spawn() -> Result<Self, std::io::Error> {
        let mut child = Command::new("node")
            .env("UV_THREADPOOL_SIZE", "32")
            .arg("-e")
            .arg(NODE_WRITER_SCRIPT)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let mut stdin = std::io::BufWriter::with_capacity(1024 * 1024, child.stdin.take().unwrap());
        let (tx, rx): (Sender<NodeWriterMsg>, Receiver<NodeWriterMsg>) = channel();

        let handle = thread::spawn(move || -> std::io::Result<()> {
            while let Ok(msg) = rx.recv() {
                match msg {
                    NodeWriterMsg::File { path, data, mode } => {
                        let path_bytes = path.as_bytes();
                        stdin.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
                        stdin.write_all(&mode.to_le_bytes())?;
                        stdin.write_all(&(data.len() as u32).to_le_bytes())?;
                        stdin.write_all(path_bytes)?;
                        stdin.write_all(&data)?;
                    }
                    NodeWriterMsg::Close => break,
                }
            }
            stdin.flush()?;
            drop(stdin);
            Ok(())
        });

        Ok(Self {
            child,
            sender: tx,
            thread_handle: Some(handle),
        })
    }

    /// Obtains a cloned channel sender for worker threads.
    pub fn sender(&self) -> Sender<NodeWriterMsg> {
        self.sender.clone()
    }

    /// Flushes all pending writes, waits for Node.js to finish writing all files to disk, and exits.
    pub fn finish(mut self) -> Result<(), std::io::Error> {
        let _ = self.sender.send(NodeWriterMsg::Close);
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

/// A task for the pure Rust writer thread pool.
pub enum WriteTask {
    File {
        path: PathBuf,
        data: Vec<u8>,
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

    /// Sends close sentinels to all worker threads and joins them.
    pub fn finish(mut self) -> Result<(), std::io::Error> {
        if let Some(s) = self.sender.take() {
            for _ in 0..self.handles.len() {
                let _ = s.send(WriteTask::Close);
            }
        }
        for h in self.handles {
            h.join()
                .map_err(|_| std::io::Error::other("RustWriterPool worker panicked"))??;
        }
        Ok(())
    }
}

/// Cloneable sender for async file writes across worker threads.
#[derive(Clone)]
pub enum AsyncFileWriterSender {
    Node(Sender<NodeWriterMsg>),
    Rust(SyncSender<WriteTask>),
}

impl AsyncFileWriterSender {
    /// Sends a file write task to the background writer pool/helper.
    /// Fails fast if the background writer has disconnected or encountered an error.
    pub fn send(&self, path: PathBuf, data: Vec<u8>, mode: u32) -> Result<(), std::io::Error> {
        match self {
            Self::Node(s) => {
                let path_str = path.to_string_lossy().to_string();
                s.send(NodeWriterMsg::File {
                    path: path_str,
                    data,
                    mode,
                })
                .map_err(|e| std::io::Error::other(format!("NodeWriter disconnected: {e}")))
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

    /// Flushes all pending writes and waits for completion.
    pub fn finish(self) -> Result<(), std::io::Error> {
        match self {
            Self::Node(nw) => nw.finish(),
            Self::Rust(rw) => rw.finish(),
        }
    }
}

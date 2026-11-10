use std::io::Write;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::thread::{self, JoinHandle};

const NODE_WRITER_SCRIPT: &str = r#"
const fs = require('fs');
const path = require('path');
const dirs = new Set();
const q = [];
let inflight = 0;
let stdinEnded = false;
let failed = false;
const concurrency = 16;

function pump() {
  while (inflight < concurrency && q.length > 0) {
    const item = q.shift();
    inflight++;
    const dir = path.dirname(item.p);
    if (!dirs.has(dir)) {
      try { fs.mkdirSync(dir, { recursive: true }); } catch (e) {}
      dirs.add(dir);
    }
    fs.promises.writeFile(item.p, item.b)
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
  if (stdinEnded && inflight === 0 && q.length === 0) {
    process.exit(failed ? 1 : 0);
  }
}

let buf = Buffer.alloc(0);

process.stdin.on('data', chunk => {
  buf = Buffer.concat([buf, chunk]);
  while (buf.length >= 8) {
    const pathLen = buf.readUInt32LE(0);
    const dataLen = buf.readUInt32LE(4);
    const frameLen = 8 + pathLen + dataLen;
    if (buf.length < frameLen) break;

    const pStr = buf.toString('utf8', 8, 8 + pathLen);
    const bSlice = buf.subarray(8 + pathLen, frameLen);

    q.push({ p: pStr, b: Buffer.from(bSlice) });
    buf = buf.subarray(frameLen);
  }
  pump();
});

process.stdin.on('end', () => {
  stdinEnded = true;
  pump();
});
"#;

pub enum NodeWriterMsg {
    File { path: String, data: Vec<u8> },
    Close,
}

/// A background Node.js worker that writes files concurrently using libuv/fs.promises
/// to avoid Windows Defender file-scan lock contention on CloseHandle.
pub struct NodeWriter {
    child: Child,
    sender: SyncSender<NodeWriterMsg>,
    thread_handle: Option<JoinHandle<std::io::Result<()>>>,
}

impl NodeWriter {
    /// Checks if `node` is available on the system.
    pub fn is_available() -> bool {
        Command::new("node")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    /// Spawns a background Node.js process and begins listening for file write commands.
    pub fn spawn() -> Result<Self, std::io::Error> {
        let mut child = Command::new("node")
            .env("UV_THREADPOOL_SIZE", "16")
            .arg("-e")
            .arg(NODE_WRITER_SCRIPT)
            .stdin(Stdio::piped())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()?;

        let mut stdin = std::io::BufWriter::with_capacity(1024 * 1024, child.stdin.take().unwrap());
        let (tx, rx): (SyncSender<NodeWriterMsg>, Receiver<NodeWriterMsg>) = sync_channel(4096);

        let handle = thread::spawn(move || -> std::io::Result<()> {
            while let Ok(msg) = rx.recv() {
                match msg {
                    NodeWriterMsg::File { path, data } => {
                        let path_bytes = path.as_bytes();
                        stdin.write_all(&(path_bytes.len() as u32).to_le_bytes())?;
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
    pub fn sender(&self) -> SyncSender<NodeWriterMsg> {
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

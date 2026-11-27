use crate::error::{HttpTransportError, RegistryError};
use crate::network_errors::format_io_error;
use flate2::read::{DeflateDecoder, GzDecoder};
use reqwest::header::HeaderMap;
use reqwest::{Method, StatusCode};
use std::collections::HashMap;
use std::future::Future;
use std::io::{ErrorKind, Read, Write as _};
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use url::{Host, Url};

const MAX_HEADER_BYTES: usize = 64 * 1024;
const STACK_HEAD_BUF: usize = 4096;
const MAX_ERROR_BODY_BYTES: usize = 64 * 1024;
const DNS_CACHE_TTL: Duration = Duration::from_secs(30);
const POOL_SHARDS: usize = 16;
const HOT_CHECKOUT_PROBE_AGE: Duration = Duration::from_millis(50);

struct IdleConn {
    stream: TcpStream,
    last_used: Instant,
}

struct DnsCacheEntry {
    addrs: Arc<[SocketAddr]>,
    expires_at: Instant,
}

pub(crate) struct Http1Pool {
    shards: [Mutex<HashMap<String, Vec<IdleConn>>>; POOL_SHARDS],
    dns_cache: Mutex<HashMap<String, DnsCacheEntry>>,
}

impl Http1Pool {
    pub(crate) fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            dns_cache: Mutex::new(HashMap::new()),
        }
    }

    #[inline]
    fn shard_for(&self, key: &str) -> &Mutex<HashMap<String, Vec<IdleConn>>> {
        let mut h: u64 = 0xcbf29ce484222325;
        for &b in key.as_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x100000001b3);
        }
        &self.shards[(h as usize) & (POOL_SHARDS - 1)]
    }

    fn checkout(&self, key: &str, idle_timeout: Duration) -> Option<TcpStream> {
        if idle_timeout.is_zero() {
            return None;
        }
        let shard = self.shard_for(key);
        let now = Instant::now();
        loop {
            let candidate = {
                let mut guard = shard.lock().unwrap_or_else(|e| e.into_inner());
                let list = guard.get_mut(key)?;
                list.pop()?
            };
            let age = now.saturating_duration_since(candidate.last_used);
            if age >= idle_timeout {
                continue;
            }
            if age < HOT_CHECKOUT_PROBE_AGE {
                return Some(candidate.stream);
            }
            let mut probe = [0u8; 1];
            match candidate.stream.try_read(&mut probe) {
                Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                    return Some(candidate.stream);
                }
                _ => {
                    continue;
                }
            }
        }
    }

    fn checkin(
        &self,
        key: &str,
        stream: TcpStream,
        max_idle_per_host: usize,
        idle_timeout: Duration,
    ) {
        if max_idle_per_host == 0 || idle_timeout.is_zero() {
            return;
        }
        let shard = self.shard_for(key);
        let mut guard = shard.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(list) = guard.get_mut(key) {
            if list.len() < max_idle_per_host {
                list.push(IdleConn {
                    stream,
                    last_used: Instant::now(),
                });
            }
        } else {
            if guard.len() >= 256 {
                if let Some(evict) = guard
                    .iter()
                    .find(|(_, v)| v.is_empty())
                    .map(|(k, _)| k.clone())
                {
                    guard.remove(&evict);
                }
            }
            let mut list = Vec::with_capacity(max_idle_per_host.min(16));
            list.push(IdleConn {
                stream,
                last_used: Instant::now(),
            });
            guard.insert(key.to_owned(), list);
        }
    }

    fn get_cached_dns(&self, key: &str) -> Option<Arc<[SocketAddr]>> {
        let mut guard = self.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(entry) = guard.get(key) {
            if Instant::now() < entry.expires_at {
                return Some(Arc::clone(&entry.addrs));
            }
            guard.remove(key);
        }
        None
    }

    fn put_cached_dns(&self, key: &str, addrs: Arc<[SocketAddr]>) {
        if addrs.is_empty() {
            return;
        }
        let mut guard = self.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
        if guard.len() >= 256 && !guard.contains_key(key) {
            if let Some(first) = guard.keys().next().cloned() {
                guard.remove(&first);
            }
        }
        guard.insert(
            key.to_owned(),
            DnsCacheEntry {
                addrs,
                expires_at: Instant::now() + DNS_CACHE_TTL,
            },
        );
    }

    fn invalidate_dns(&self, key: &str) {
        let mut guard = self.dns_cache.lock().unwrap_or_else(|e| e.into_inner());
        guard.remove(key);
    }
}

#[inline]
fn format_pool_key<'a>(buf: &'a mut [u8; 272], raw_host: &str, port: u16) -> Option<&'a str> {
    let host_bytes = raw_host.as_bytes();
    if host_bytes.len() + 7 > buf.len() {
        return None;
    }
    for (dst, &b) in buf[..host_bytes.len()].iter_mut().zip(host_bytes) {
        *dst = b.to_ascii_lowercase();
    }
    let mut cursor = std::io::Cursor::new(&mut buf[host_bytes.len()..]);
    write!(&mut cursor, ":{port}").ok()?;
    let len = host_bytes.len() + cursor.position() as usize;
    std::str::from_utf8(&buf[..len]).ok()
}

pub(crate) enum BodyTarget<'a> {
    Metadata {
        max_size: usize,
    },
    TarballBytes {
        max_size: usize,
        compute_sha512: bool,
    },
    TarballFile {
        max_size: usize,
        disk_threshold: usize,
        temp_path: &'a Path,
        dest_path: &'a Path,
    },
}

pub(crate) enum BodyPayload {
    Bytes {
        bytes: Vec<u8>,
        sha512: Option<String>,
        cache_metadata: serde_json::Value,
    },
    File {
        written: u64,
    },
}

pub(crate) enum HopOutcome {
    Success {
        etag: Option<String>,
        payload: BodyPayload,
    },
    NotModified {
        etag: Option<String>,
        cache_metadata: serde_json::Value,
    },
    Redirect {
        status: StatusCode,
        location: Option<Result<String, ()>>,
    },
    ErrorStatus {
        status: StatusCode,
        retry_after: Option<String>,
        www_authenticate: Option<String>,
        body: String,
    },
    FallbackToReqwest,
}

struct ParsedHeaders {
    status: StatusCode,
    keep_alive: bool,
    content_length: Option<u64>,
    is_chunked: bool,
    unsupported_te: bool,
    content_encoding: ContentEncoding,
    etag: Option<String>,
    location: Option<Result<String, ()>>,
    retry_after: Option<String>,
    www_authenticate: Option<String>,
    cache_metadata: serde_json::Value,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ContentEncoding {
    Identity,
    Gzip,
    Deflate,
    Unsupported,
}

#[inline]
fn has_crlf_bytes(bytes: &[u8]) -> bool {
    bytes.iter().any(|&b| b == b'\r' || b == b'\n')
}

#[inline]
fn is_valid_header_str(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == b'\t' || (0x20..0x7f).contains(&b))
}

#[inline]
fn trim_ascii_ws(mut b: &[u8]) -> &[u8] {
    while let Some(&first) = b.first() {
        if first == b' ' || first == b'\t' {
            b = &b[1..];
        } else {
            break;
        }
    }
    while let Some(&last) = b.last() {
        if last == b' ' || last == b'\t' {
            b = &b[..b.len() - 1];
        } else {
            break;
        }
    }
    b
}

#[inline]
fn contains_token_ascii_ci(val: &str, token: &str) -> bool {
    val.split(',')
        .any(|part| part.trim().eq_ignore_ascii_case(token))
}

fn parse_headers(raw: &[u8], collect_cache_metadata: bool) -> Result<ParsedHeaders, RegistryError> {
    let text = std::str::from_utf8(raw).map_err(|_| {
        RegistryError::Transport(HttpTransportError {
            message: "HTTP response headers contain invalid UTF-8".into(),
            is_connect: false,
            is_timeout: false,
            is_decode: true,
            is_transient: false,
        })
    })?;

    let mut lines = text.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let (is_http_11, status_rest) = if let Some(rest) = status_line.strip_prefix("HTTP/1.1 ") {
        (true, rest)
    } else if let Some(rest) = status_line.strip_prefix("HTTP/1.0 ") {
        (false, rest)
    } else {
        return Err(RegistryError::Transport(HttpTransportError {
            message: format!("Invalid HTTP status line: {status_line}"),
            is_connect: false,
            is_timeout: false,
            is_decode: true,
            is_transient: false,
        }));
    };

    if status_rest.len() < 3 || !status_rest.as_bytes()[..3].iter().all(|b| b.is_ascii_digit()) {
        return Err(RegistryError::Transport(HttpTransportError {
            message: format!("Invalid HTTP status code in: {status_line}"),
            is_connect: false,
            is_timeout: false,
            is_decode: true,
            is_transient: false,
        }));
    }
    let code: u16 = status_rest[..3].parse().map_err(|_| {
        RegistryError::Transport(HttpTransportError {
            message: format!("Invalid HTTP status code in: {status_line}"),
            is_connect: false,
            is_timeout: false,
            is_decode: true,
            is_transient: false,
        })
    })?;
    let status = StatusCode::from_u16(code).map_err(|_| {
        RegistryError::Transport(HttpTransportError {
            message: format!("Invalid HTTP status code: {code}"),
            is_connect: false,
            is_timeout: false,
            is_decode: true,
            is_transient: false,
        })
    })?;

    let mut conn_close = false;
    let mut conn_keep_alive = false;
    let mut content_length: Option<u64> = None;
    let mut is_chunked = false;
    let mut unsupported_te = false;
    let mut content_encoding = ContentEncoding::Identity;
    let mut etag: Option<String> = None;
    let mut location: Option<Result<String, ()>> = None;
    let mut retry_after: Option<String> = None;
    let mut www_auth_parts: Vec<String> = Vec::new();
    let mut cache_map: Option<serde_json::Map<String, serde_json::Value>> = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name_raw, val_raw)) = line.split_once(':') else {
            return Err(RegistryError::Transport(HttpTransportError {
                message: format!("Malformed HTTP header line: {line}"),
                is_connect: false,
                is_timeout: false,
                is_decode: true,
                is_transient: false,
            }));
        };
        let name = name_raw.trim();
        let val = val_raw.trim();

        if name.eq_ignore_ascii_case("content-length") {
            let parsed = val.parse::<u64>().map_err(|_| {
                RegistryError::Transport(HttpTransportError {
                    message: format!("Invalid Content-Length header: {val}"),
                    is_connect: false,
                    is_timeout: false,
                    is_decode: true,
                    is_transient: false,
                })
            })?;
            if let Some(prev) = content_length {
                if prev != parsed {
                    return Err(RegistryError::Transport(HttpTransportError {
                        message: "Conflicting Content-Length headers".into(),
                        is_connect: false,
                        is_timeout: false,
                        is_decode: true,
                        is_transient: false,
                    }));
                }
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            for tok in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                if tok.eq_ignore_ascii_case("chunked") {
                    is_chunked = true;
                } else if !tok.eq_ignore_ascii_case("identity") {
                    unsupported_te = true;
                }
            }
        } else if name.eq_ignore_ascii_case("connection") {
            if contains_token_ascii_ci(val, "close") {
                conn_close = true;
            }
            if contains_token_ascii_ci(val, "keep-alive") {
                conn_keep_alive = true;
            }
        } else if name.eq_ignore_ascii_case("content-encoding") {
            let enc = val.trim();
            if enc.eq_ignore_ascii_case("gzip") || enc.eq_ignore_ascii_case("x-gzip") {
                content_encoding = ContentEncoding::Gzip;
            } else if enc.eq_ignore_ascii_case("deflate") {
                content_encoding = ContentEncoding::Deflate;
            } else if !enc.is_empty() && !enc.eq_ignore_ascii_case("identity") {
                content_encoding = ContentEncoding::Unsupported;
            }
        } else if name.eq_ignore_ascii_case("etag") {
            if etag.is_none() {
                etag = Some(val.to_string());
            }
        } else if name.eq_ignore_ascii_case("location") {
            if location.is_none() {
                if is_valid_header_str(val.as_bytes()) {
                    location = Some(Ok(val.to_string()));
                } else {
                    location = Some(Err(()));
                }
            }
        } else if name.eq_ignore_ascii_case("retry-after") {
            if retry_after.is_none() {
                retry_after = Some(val.to_string());
            }
        } else if name.eq_ignore_ascii_case("www-authenticate") {
            if !val.is_empty() {
                www_auth_parts.push(val.to_string());
            }
        } else if collect_cache_metadata {
            let cache_key = if name.eq_ignore_ascii_case("cache-control") {
                Some("cache-control")
            } else if name.eq_ignore_ascii_case("date") {
                Some("date")
            } else if name.eq_ignore_ascii_case("age") {
                Some("age")
            } else if name.eq_ignore_ascii_case("content-type") {
                Some("content-type")
            } else if name.eq_ignore_ascii_case("vary") {
                Some("vary")
            } else {
                None
            };
            if let Some(k) = cache_key {
                let m = cache_map.get_or_insert_with(|| serde_json::Map::with_capacity(4));
                m.insert(k.into(), serde_json::Value::String(val.to_owned()));
            }
        }
    }

    if is_chunked {
        content_length = None;
    }

    let keep_alive = if conn_close {
        false
    } else if is_http_11 {
        true
    } else {
        conn_keep_alive
    };

    let www_authenticate = if www_auth_parts.is_empty() {
        None
    } else {
        Some(www_auth_parts.join(", "))
    };

    let cache_metadata = if collect_cache_metadata {
        let mut outer = serde_json::Map::with_capacity(1);
        let mut resp_map = serde_json::Map::with_capacity(1);
        resp_map.insert(
            "headers".into(),
            serde_json::Value::Object(cache_map.unwrap_or_default()),
        );
        outer.insert("response".into(), serde_json::Value::Object(resp_map));
        serde_json::Value::Object(outer)
    } else {
        serde_json::Value::Null
    };

    Ok(ParsedHeaders {
        status,
        keep_alive,
        content_length,
        is_chunked,
        unsupported_te,
        content_encoding,
        etag,
        location,
        retry_after,
        www_authenticate,
        cache_metadata,
    })
}

fn parse_headers_raw_location(raw: &[u8], parsed: &mut ParsedHeaders) {
    for line in raw.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(pos) = line.iter().position(|&b| b == b':') {
            let name = trim_ascii_ws(&line[..pos]);
            if name.eq_ignore_ascii_case(b"location") {
                let val = trim_ascii_ws(&line[pos + 1..]);
                if !is_valid_header_str(val) {
                    parsed.location = Some(Err(()));
                }
                break;
            }
        }
    }
}

#[inline]
async fn write_all_fast(
    stream: &mut TcpStream,
    mut data: &[u8],
    url: &Url,
    total_deadline: tokio::time::Instant,
) -> Result<(), std::io::Error> {
    while !data.is_empty() {
        match stream.try_write(data) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    ErrorKind::WriteZero,
                    "failed to write request bytes",
                ));
            }
            Ok(n) => {
                data = &data[n..];
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => {
                let now = tokio::time::Instant::now();
                if now >= total_deadline {
                    return Err(std::io::Error::new(ErrorKind::TimedOut, "write timeout"));
                }
                match tokio::time::timeout_at(total_deadline, stream.write_all(data)).await {
                    Ok(res) => return res,
                    Err(_) => {
                        let _ = url;
                        return Err(std::io::Error::new(ErrorKind::TimedOut, "write timeout"));
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

#[inline]
async fn read_with_timeouts<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
    url: &Url,
    idle_timeout: Duration,
    total_deadline: tokio::time::Instant,
    idle_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<usize, RegistryError> {
    let now = tokio::time::Instant::now();
    if now >= total_deadline {
        return Err(RegistryError::Transport(HttpTransportError {
            message: format_io_error(
                url,
                &std::io::Error::new(ErrorKind::TimedOut, "request timeout"),
                false,
                true,
            ),
            is_connect: false,
            is_timeout: true,
            is_decode: false,
            is_transient: true,
        }));
    }
    let remaining = total_deadline - now;
    let is_idle_bound = idle_timeout <= remaining;
    let wait_dur = if is_idle_bound { idle_timeout } else { remaining };

    let mut deadline_set = false;
    let mut fut = std::pin::pin!(reader.read(buf));
    std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
        Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
        Poll::Ready(Err(err)) => {
            let is_to = err.kind() == ErrorKind::TimedOut;
            let msg = format_io_error(url, &err, false, is_to);
            Poll::Ready(Err(RegistryError::Transport(HttpTransportError {
                message: msg,
                is_connect: false,
                is_timeout: is_to,
                is_decode: false,
                is_transient: is_transient_io(&err),
            })))
        }
        Poll::Pending => {
            let sleep = match idle_sleep {
                Some(s) => {
                    if !deadline_set {
                        s.as_mut().reset(tokio::time::Instant::now() + wait_dur);
                        deadline_set = true;
                    }
                    s
                }
                None => {
                    deadline_set = true;
                    idle_sleep.insert(Box::pin(tokio::time::sleep(wait_dur)))
                }
            };
            match sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    if is_idle_bound {
                        Poll::Ready(Err(RegistryError::SlowlorisTimeout(idle_timeout)))
                    } else {
                        Poll::Ready(Err(RegistryError::Transport(HttpTransportError {
                            message: format_io_error(
                                url,
                                &std::io::Error::new(ErrorKind::TimedOut, "request timeout"),
                                false,
                                true,
                            ),
                            is_connect: false,
                            is_timeout: true,
                            is_decode: false,
                            is_transient: true,
                        })))
                    }
                }
                Poll::Pending => Poll::Pending,
            }
        }
    })
    .await
}

#[inline]
async fn read_buf_with_timeouts<R: tokio::io::AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut Vec<u8>,
    url: &Url,
    idle_timeout: Duration,
    total_deadline: tokio::time::Instant,
    idle_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<usize, RegistryError> {
    let now = tokio::time::Instant::now();
    if now >= total_deadline {
        return Err(RegistryError::Transport(HttpTransportError {
            message: format_io_error(
                url,
                &std::io::Error::new(ErrorKind::TimedOut, "request timeout"),
                false,
                true,
            ),
            is_connect: false,
            is_timeout: true,
            is_decode: false,
            is_transient: true,
        }));
    }
    let remaining = total_deadline - now;
    let is_idle_bound = idle_timeout <= remaining;
    let wait_dur = if is_idle_bound { idle_timeout } else { remaining };

    let mut deadline_set = false;
    let mut fut = std::pin::pin!(reader.read_buf(buf));
    std::future::poll_fn(|cx| match fut.as_mut().poll(cx) {
        Poll::Ready(Ok(n)) => Poll::Ready(Ok(n)),
        Poll::Ready(Err(err)) => {
            let is_to = err.kind() == ErrorKind::TimedOut;
            let msg = format_io_error(url, &err, false, is_to);
            Poll::Ready(Err(RegistryError::Transport(HttpTransportError {
                message: msg,
                is_connect: false,
                is_timeout: is_to,
                is_decode: false,
                is_transient: is_transient_io(&err),
            })))
        }
        Poll::Pending => {
            let sleep = match idle_sleep {
                Some(s) => {
                    if !deadline_set {
                        s.as_mut().reset(tokio::time::Instant::now() + wait_dur);
                        deadline_set = true;
                    }
                    s
                }
                None => {
                    deadline_set = true;
                    idle_sleep.insert(Box::pin(tokio::time::sleep(wait_dur)))
                }
            };
            match sleep.as_mut().poll(cx) {
                Poll::Ready(()) => {
                    if is_idle_bound {
                        Poll::Ready(Err(RegistryError::SlowlorisTimeout(idle_timeout)))
                    } else {
                        Poll::Ready(Err(RegistryError::Transport(HttpTransportError {
                            message: format_io_error(
                                url,
                                &std::io::Error::new(ErrorKind::TimedOut, "request timeout"),
                                false,
                                true,
                            ),
                            is_connect: false,
                            is_timeout: true,
                            is_decode: false,
                            is_transient: true,
                        })))
                    }
                }
                Poll::Pending => Poll::Pending,
            }
        }
    })
    .await
}

#[inline]
fn is_transient_io(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::TimedOut
            | ErrorKind::Interrupted
            | ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionRefused
            | ErrorKind::WouldBlock
    )
}

#[inline]
fn is_stale_reused_io(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
    )
}

async fn connect_addrs(addrs: &[SocketAddr]) -> std::io::Result<TcpStream> {
    let mut last_err = None;
    for &addr in addrs {
        match TcpStream::connect(addr).await {
            Ok(s) => return Ok(s),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| std::io::Error::new(ErrorKind::AddrNotAvailable, "no addresses")))
}

struct BodySink<'a> {
    mem: Option<Vec<u8>>,
    file: Option<BufWriter<tokio::fs::File>>,
    disk_threshold: Option<usize>,
    temp_path: Option<&'a Path>,
    hasher: Option<ring::digest::Context>,
    written: u64,
    max_size: u64,
}

impl<'a> BodySink<'a> {
    fn new_memory(max_size: usize, expected_len: Option<u64>, compute_sha512: bool) -> Self {
        let cap = expected_len
            .map(|l| (l as usize).min(max_size))
            .unwrap_or(0);
        Self {
            mem: Some(Vec::with_capacity(cap)),
            file: None,
            disk_threshold: None,
            temp_path: None,
            hasher: compute_sha512.then(|| ring::digest::Context::new(&ring::digest::SHA512)),
            written: 0,
            max_size: max_size as u64,
        }
    }

    async fn new_file_or_mem(
        max_size: u64,
        disk_threshold: usize,
        temp_path: &'a Path,
        expected_len: Option<u64>,
    ) -> Result<Self, RegistryError> {
        if expected_len.is_some_and(|l| l > disk_threshold as u64) {
            let raw = tokio::fs::File::create(temp_path).await.map_err(|e| {
                RegistryError::Other(format!("Failed to create {}: {e}", temp_path.display()))
            })?;
            Ok(Self {
                mem: None,
                file: Some(BufWriter::with_capacity(256 * 1024, raw)),
                disk_threshold: Some(disk_threshold),
                temp_path: Some(temp_path),
                hasher: None,
                written: 0,
                max_size,
            })
        } else {
            let cap = expected_len.map(|l| l as usize).unwrap_or(0);
            Ok(Self {
                mem: Some(Vec::with_capacity(cap)),
                file: None,
                disk_threshold: Some(disk_threshold),
                temp_path: Some(temp_path),
                hasher: None,
                written: 0,
                max_size,
            })
        }
    }

    #[inline]
    fn check_limit(&self, add: u64) -> Result<(), RegistryError> {
        if self.written + add > self.max_size {
            return Err(RegistryError::SizeLimitExceeded {
                limit: self.max_size,
                actual: self.written + add,
                message: "Payload exceeds maximum allowed size".into(),
            });
        }
        Ok(())
    }

    async fn push(&mut self, data: &[u8]) -> Result<(), RegistryError> {
        if data.is_empty() {
            return Ok(());
        }
        self.check_limit(data.len() as u64)?;
        if let Some(ref mut ctx) = self.hasher {
            ctx.update(data);
        }
        if let Some(ref mut mem) = self.mem {
            let spill = self
                .disk_threshold
                .is_some_and(|t| mem.len() + data.len() > t);
            if !spill {
                mem.extend_from_slice(data);
                self.written += data.len() as u64;
                return Ok(());
            }
            let tp = self.temp_path.expect("temp_path required when disk_threshold is set");
            let raw = tokio::fs::File::create(tp).await.map_err(|e| {
                RegistryError::Other(format!("Failed to create {}: {e}", tp.display()))
            })?;
            let mut bw = BufWriter::with_capacity(256 * 1024, raw);
            if !mem.is_empty() {
                bw.write_all(mem).await.map_err(|e| {
                    RegistryError::Other(format!("Failed to write {}: {e}", tp.display()))
                })?;
            }
            bw.write_all(data).await.map_err(|e| {
                RegistryError::Other(format!("Failed to write {}: {e}", tp.display()))
            })?;
            self.mem = None;
            self.file = Some(bw);
            self.written += data.len() as u64;
            return Ok(());
        }
        if let Some(ref mut bw) = self.file {
            let tp = self.temp_path.expect("temp_path required for file sink");
            bw.write_all(data).await.map_err(|e| {
                RegistryError::Other(format!("Failed to write {}: {e}", tp.display()))
            })?;
            self.written += data.len() as u64;
        }
        Ok(())
    }

    async fn cleanup_on_err(&mut self) {
        if let Some(bw) = self.file.take() {
            drop(bw);
            if let Some(tp) = self.temp_path {
                let _ = tokio::fs::remove_file(tp).await;
            }
        }
    }
}

pub(crate) fn format_static_headers(default_headers: &HeaderMap) -> Box<[u8]> {
    let mut buf = Vec::with_capacity(192);
    for (name, value) in default_headers {
        let name_str = name.as_str();
        if name_str.eq_ignore_ascii_case("connection") || name_str.eq_ignore_ascii_case("host") {
            continue;
        }
        if let Ok(val_str) = value.to_str() {
            if !has_crlf_bytes(name_str.as_bytes()) && !has_crlf_bytes(val_str.as_bytes()) {
                buf.extend_from_slice(name_str.as_bytes());
                buf.extend_from_slice(b": ");
                buf.extend_from_slice(val_str.as_bytes());
                buf.extend_from_slice(b"\r\n");
            }
        }
    }
    buf.into_boxed_slice()
}

pub(crate) struct Http1RequestParams<'a> {
    pub method: &'a Method,
    pub url: &'a Url,
    pub static_headers: &'a [u8],
    pub accept: Option<&'a str>,
    pub accept_gzip: bool,
    pub if_none_match: Option<&'a str>,
    pub auth_header: Option<&'a str>,
    pub collect_cache_metadata: bool,
    pub connect_timeout: Duration,
    pub request_timeout: Duration,
    pub chunk_idle_timeout: Duration,
    pub pool_idle_timeout: Duration,
    pub max_idle_per_host: usize,
}

#[inline]
fn append_request_bytes(buf: &mut Vec<u8>, params: &Http1RequestParams<'_>, raw_host: &str, path_str: &str) {
    buf.extend_from_slice(params.method.as_str().as_bytes());
    buf.push(b' ');
    buf.extend_from_slice(path_str.as_bytes());
    if let Some(q) = params.url.query() {
        buf.push(b'?');
        buf.extend_from_slice(q.as_bytes());
    }
    buf.extend_from_slice(b" HTTP/1.1\r\nhost: ");
    buf.extend_from_slice(raw_host.as_bytes());
    if let Some(explicit_port) = params.url.port() {
        let _ = write!(buf, ":{explicit_port}");
    }
    buf.extend_from_slice(b"\r\n");
    buf.extend_from_slice(params.static_headers);
    if let Some(accept) = params.accept {
        buf.extend_from_slice(b"accept: ");
        buf.extend_from_slice(accept.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    if params.accept_gzip {
        buf.extend_from_slice(b"accept-encoding: gzip, deflate\r\n");
    }
    if let Some(inm) = params.if_none_match {
        buf.extend_from_slice(b"if-none-match: ");
        buf.extend_from_slice(inm.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    if let Some(auth) = params.auth_header {
        buf.extend_from_slice(b"authorization: ");
        buf.extend_from_slice(auth.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"connection: keep-alive\r\n\r\n");
}

#[inline]
fn format_request_to_stack<'a>(
    stack_buf: &'a mut [u8; 512],
    params: &Http1RequestParams<'_>,
    raw_host: &str,
    path_str: &str,
) -> Option<&'a [u8]> {
    let mut est = params.method.as_str().len()
        + path_str.len()
        + params.url.query().map_or(0, |q| q.len() + 1)
        + raw_host.len()
        + 12
        + params.static_headers.len()
        + params.accept.map_or(0, |a| a.len() + 10)
        + if params.accept_gzip { 32 } else { 0 }
        + params.if_none_match.map_or(0, |i| i.len() + 17)
        + params.auth_header.map_or(0, |a| a.len() + 17)
        + 26;
    if est > stack_buf.len() {
        return None;
    }
    let mut pos = 0usize;
    let mut push = |bytes: &[u8]| {
        stack_buf[pos..pos + bytes.len()].copy_from_slice(bytes);
        pos += bytes.len();
    };
    push(params.method.as_str().as_bytes());
    push(b" ");
    push(path_str.as_bytes());
    if let Some(q) = params.url.query() {
        push(b"?");
        push(q.as_bytes());
    }
    push(b" HTTP/1.1\r\nhost: ");
    push(raw_host.as_bytes());
    if let Some(explicit_port) = params.url.port() {
        let mut port_buf = [0u8; 8];
        let mut c = std::io::Cursor::new(&mut port_buf[..]);
        let _ = write!(&mut c, ":{explicit_port}");
        let plen = c.position() as usize;
        push(&port_buf[..plen]);
    }
    push(b"\r\n");
    push(params.static_headers);
    if let Some(accept) = params.accept {
        push(b"accept: ");
        push(accept.as_bytes());
        push(b"\r\n");
    }
    if params.accept_gzip {
        push(b"accept-encoding: gzip, deflate\r\n");
    }
    if let Some(inm) = params.if_none_match {
        push(b"if-none-match: ");
        push(inm.as_bytes());
        push(b"\r\n");
    }
    if let Some(auth) = params.auth_header {
        push(b"authorization: ");
        push(auth.as_bytes());
        push(b"\r\n");
    }
    push(b"connection: keep-alive\r\n\r\n");
    let _ = &mut est;
    Some(&stack_buf[..pos])
}

pub(crate) async fn execute_hop(
    pool: &Http1Pool,
    params: Http1RequestParams<'_>,
    target: BodyTarget<'_>,
) -> Result<HopOutcome, RegistryError> {
    let Some(raw_host) = params.url.host_str() else {
        return Err(RegistryError::Other("URL has no host".into()));
    };
    let port = params.url.port_or_known_default().unwrap_or(80);
    let mut pool_key_buf = [0u8; 272];
    let pool_key_owned: String;
    let pool_key: &str = match format_pool_key(&mut pool_key_buf, raw_host, port) {
        Some(k) => k,
        None => {
            pool_key_owned = format!("{}:{port}", raw_host.to_ascii_lowercase());
            &pool_key_owned
        }
    };

    let path = params.url.path();
    let path_str = if path.is_empty() { "/" } else { path };
    if has_crlf_bytes(path_str.as_bytes()) {
        return Err(RegistryError::SecurityViolation(
            "Request path contains forbidden CR/LF characters".into(),
        ));
    }
    if let Some(q) = params.url.query() {
        if has_crlf_bytes(q.as_bytes()) {
            return Err(RegistryError::SecurityViolation(
                "Request query contains forbidden CR/LF characters".into(),
            ));
        }
    }
    if let Some(a) = params.accept {
        if has_crlf_bytes(a.as_bytes()) {
            return Err(RegistryError::SecurityViolation(
                "Accept header contains forbidden CR/LF characters".into(),
            ));
        }
    }
    if let Some(inm) = params.if_none_match {
        if has_crlf_bytes(inm.as_bytes()) {
            return Err(RegistryError::SecurityViolation(
                "If-None-Match header contains forbidden CR/LF characters".into(),
            ));
        }
    }
    if let Some(auth) = params.auth_header {
        if has_crlf_bytes(auth.as_bytes()) {
            return Err(RegistryError::SecurityViolation(
                "Authorization header contains forbidden CR/LF characters".into(),
            ));
        }
    }

    let mut stack_req = [0u8; 512];
    let mut heap_req: Vec<u8> = Vec::new();
    let req_bytes: &[u8] = if let Some(slice) =
        format_request_to_stack(&mut stack_req, &params, raw_host, path_str)
    {
        slice
    } else {
        heap_req.reserve(512);
        append_request_bytes(&mut heap_req, &params, raw_host, path_str);
        &heap_req
    };

    let mut allow_pooled = true;
    let mut idle_sleep: Option<Pin<Box<tokio::time::Sleep>>> = None;

    loop {
        let total_deadline = tokio::time::Instant::now() + params.request_timeout;

        let (mut stream, reused) = if allow_pooled {
            if let Some(s) = pool.checkout(pool_key, params.pool_idle_timeout) {
                (s, true)
            } else {
                (
                    open_fresh_connection(
                        pool,
                        pool_key,
                        params.url,
                        port,
                        params.connect_timeout,
                        total_deadline,
                    )
                    .await?,
                    false,
                )
            }
        } else {
            (
                open_fresh_connection(
                    pool,
                    pool_key,
                    params.url,
                    port,
                    params.connect_timeout,
                    total_deadline,
                )
                .await?,
                false,
            )
        };

        // Fast synchronous try_write first; only arms Tokio timer on WouldBlock.
        if let Err(err) = write_all_fast(&mut stream, req_bytes, params.url, total_deadline).await {
            if reused && is_stale_reused_io(&err) {
                allow_pooled = false;
                continue;
            }
            let is_to = err.kind() == ErrorKind::TimedOut;
            return Err(RegistryError::Transport(HttpTransportError {
                message: format_io_error(params.url, &err, false, is_to),
                is_connect: false,
                is_timeout: is_to,
                is_decode: false,
                is_transient: is_transient_io(&err),
            }));
        }

        // Read response headers into a 4 KB stack buffer first (zero heap alloc for 99.9% of responses).
        let mut stack_head = [0u8; STACK_HEAD_BUF];
        let mut overflow_head: Option<Vec<u8>> = None;
        let mut filled = 0usize;
        let header_end = loop {
            let active_slice = match overflow_head {
                Some(ref v) => &v[..filled],
                None => &stack_head[..filled],
            };
            if let Some(pos) = active_slice.windows(4).position(|w| w == b"\r\n\r\n") {
                break pos + 4;
            }
            let n = if let Some(ref mut v) = overflow_head {
                if filled == v.len() {
                    if v.len() >= MAX_HEADER_BYTES {
                        return Ok(HopOutcome::FallbackToReqwest);
                    }
                    v.resize((v.len() * 2).min(MAX_HEADER_BYTES), 0);
                }
                match read_with_timeouts(
                    &mut stream,
                    &mut v[filled..],
                    params.url,
                    params.chunk_idle_timeout,
                    total_deadline,
                    &mut idle_sleep,
                )
                .await
                {
                    Ok(n) => n,
                    Err(e) => return Err(e),
                }
            } else if filled == stack_head.len() {
                let mut v = Vec::with_capacity(STACK_HEAD_BUF * 2);
                v.extend_from_slice(&stack_head);
                v.resize(STACK_HEAD_BUF * 2, 0);
                let n = match read_with_timeouts(
                    &mut stream,
                    &mut v[filled..],
                    params.url,
                    params.chunk_idle_timeout,
                    total_deadline,
                    &mut idle_sleep,
                )
                .await
                {
                    Ok(n) => n,
                    Err(e) => return Err(e),
                };
                overflow_head = Some(v);
                n
            } else {
                match read_with_timeouts(
                    &mut stream,
                    &mut stack_head[filled..],
                    params.url,
                    params.chunk_idle_timeout,
                    total_deadline,
                    &mut idle_sleep,
                )
                .await
                {
                    Ok(n) => n,
                    Err(RegistryError::Transport(ref te))
                        if reused && filled == 0 && te.is_transient =>
                    {
                        allow_pooled = false;
                        break 0;
                    }
                    Err(e) => return Err(e),
                }
            };

            if n == 0 {
                if reused && filled == 0 {
                    allow_pooled = false;
                    break 0;
                }
                let eof_err = std::io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "connection closed before response headers",
                );
                return Err(RegistryError::Transport(HttpTransportError {
                    message: format_io_error(params.url, &eof_err, false, false),
                    is_connect: false,
                    is_timeout: false,
                    is_decode: false,
                    is_transient: true,
                }));
            }
            filled += n;
        };

        if header_end == 0 {
            continue;
        }

        let head_all: &[u8] = match overflow_head {
            Some(ref v) => &v[..filled],
            None => &stack_head[..filled],
        };
        let raw_header_block = &head_all[..header_end - 4];
        let mut parsed = parse_headers(raw_header_block, params.collect_cache_metadata)?;
        if parsed.location.is_some() {
            parse_headers_raw_location(raw_header_block, &mut parsed);
        }

        if (100..200).contains(&parsed.status.as_u16()) || parsed.unsupported_te {
            return Ok(HopOutcome::FallbackToReqwest);
        }
        if matches!(parsed.content_encoding, ContentEncoding::Unsupported) {
            return Ok(HopOutcome::FallbackToReqwest);
        }
        if !params.accept_gzip
            && !matches!(parsed.content_encoding, ContentEncoding::Identity)
        {
            return Ok(HopOutcome::FallbackToReqwest);
        }

        let body_rem = &head_all[header_end..filled];

        // 304 Not Modified: zero-length body
        if parsed.status == StatusCode::NOT_MODIFIED {
            if parsed.keep_alive && body_rem.is_empty() {
                pool.checkin(
                    pool_key,
                    stream,
                    params.max_idle_per_host,
                    params.pool_idle_timeout,
                );
            }
            return Ok(HopOutcome::NotModified {
                etag: parsed.etag,
                cache_metadata: parsed.cache_metadata,
            });
        }

        // 3xx Redirect
        if parsed.status.is_redirection() {
            if parsed.keep_alive
                && parsed.content_length == Some(0)
                && body_rem.is_empty()
            {
                pool.checkin(
                    pool_key,
                    stream,
                    params.max_idle_per_host,
                    params.pool_idle_timeout,
                );
            }
            return Ok(HopOutcome::Redirect {
                status: parsed.status,
                location: parsed.location,
            });
        }

        // Non-success status (401, 403, 404, 429, 5xx, etc.)
        if !parsed.status.is_success() {
            let body_bytes = read_error_body(
                &mut stream,
                body_rem,
                &parsed,
                params.method,
                params.url,
                params.chunk_idle_timeout,
                total_deadline,
                &mut idle_sleep,
            )
            .await;
            let (body_text, clean_eof) = match body_bytes {
                Ok((bytes, clean)) => (String::from_utf8_lossy(&bytes).into_owned(), clean),
                Err(_) => (String::new(), false),
            };
            if clean_eof && parsed.keep_alive {
                pool.checkin(
                    pool_key,
                    stream,
                    params.max_idle_per_host,
                    params.pool_idle_timeout,
                );
            }
            return Ok(HopOutcome::ErrorStatus {
                status: parsed.status,
                retry_after: parsed.retry_after,
                www_authenticate: parsed.www_authenticate,
                body: body_text,
            });
        }

        // 2xx Success
        let max_size = match &target {
            BodyTarget::Metadata { max_size } => *max_size as u64,
            BodyTarget::TarballBytes { max_size, .. } => *max_size as u64,
            BodyTarget::TarballFile { max_size, .. } => *max_size as u64,
        };

        if let Some(cl) = parsed.content_length {
            if cl > max_size {
                return Err(RegistryError::SizeLimitExceeded {
                    limit: max_size,
                    actual: cl,
                    message: format!("Content-Length for '{}' exceeds maximum size", params.url),
                });
            }
        }

        let is_head_or_204 = *params.method == Method::HEAD || parsed.status == StatusCode::NO_CONTENT;
        let compute_sha512 = matches!(
            target,
            BodyTarget::TarballBytes {
                compute_sha512: true,
                ..
            }
        );

        let mut sink = match target {
            BodyTarget::Metadata { max_size } => {
                BodySink::new_memory(max_size, parsed.content_length, false)
            }
            BodyTarget::TarballBytes {
                max_size,
                compute_sha512,
            } => BodySink::new_memory(max_size, parsed.content_length, compute_sha512),
            BodyTarget::TarballFile {
                max_size,
                disk_threshold,
                temp_path,
                ..
            } => BodySink::new_file_or_mem(
                max_size as u64,
                disk_threshold,
                temp_path,
                parsed.content_length,
            )
            .await?,
        };

        let read_res = if is_head_or_204 {
            Ok(body_rem.is_empty())
        } else if parsed.is_chunked {
            read_chunked_body(
                &mut stream,
                head_all,
                header_end,
                &mut sink,
                params.url,
                params.chunk_idle_timeout,
                total_deadline,
                &mut idle_sleep,
            )
            .await
        } else if let Some(cl) = parsed.content_length {
            read_content_length_body(
                &mut stream,
                body_rem,
                cl,
                &mut sink,
                params.url,
                params.chunk_idle_timeout,
                total_deadline,
                &mut idle_sleep,
            )
            .await
        } else {
            read_eof_body(
                &mut stream,
                body_rem,
                &mut sink,
                params.url,
                params.chunk_idle_timeout,
                total_deadline,
                &mut idle_sleep,
            )
            .await
            .map(|()| false)
        };

        let clean_for_pool = match read_res {
            Ok(clean) => clean,
            Err(err) => {
                sink.cleanup_on_err().await;
                return Err(err);
            }
        };

        if clean_for_pool && parsed.keep_alive {
            pool.checkin(
                pool_key,
                stream,
                params.max_idle_per_host,
                params.pool_idle_timeout,
            );
        }

        match target {
            BodyTarget::Metadata { max_size } => {
                let raw_bytes = sink.mem.take().unwrap_or_default();
                let final_bytes = match parsed.content_encoding {
                    ContentEncoding::Identity => raw_bytes,
                    ContentEncoding::Gzip => {
                        decompress_bounded(GzDecoder::new(&raw_bytes[..]), max_size)?
                    }
                    ContentEncoding::Deflate => {
                        decompress_bounded(DeflateDecoder::new(&raw_bytes[..]), max_size)?
                    }
                    ContentEncoding::Unsupported => unreachable!(),
                };
                return Ok(HopOutcome::Success {
                    etag: parsed.etag,
                    payload: BodyPayload::Bytes {
                        bytes: final_bytes,
                        sha512: None,
                        cache_metadata: parsed.cache_metadata,
                    },
                });
            }
            BodyTarget::TarballBytes { .. } => {
                let bytes = sink.mem.take().unwrap_or_default();
                let sha512 = if compute_sha512 {
                    sink.hasher.take().map(|ctx| {
                        let digest = ctx.finish();
                        format!("sha512-{}", data_encoding::BASE64.encode(digest.as_ref()))
                    })
                } else {
                    None
                };
                return Ok(HopOutcome::Success {
                    etag: parsed.etag,
                    payload: BodyPayload::Bytes {
                        bytes,
                        sha512,
                        cache_metadata: serde_json::Value::Null,
                    },
                });
            }
            BodyTarget::TarballFile {
                temp_path,
                dest_path,
                ..
            } => {
                let written = sink.written;
                if let Some(buf) = sink.mem.take() {
                    let tp = temp_path.to_path_buf();
                    let dp = dest_path.to_path_buf();
                    let dest_buf_res = tokio::task::spawn_blocking(move || {
                        let mut f = std::fs::File::create(&tp).map_err(|e| {
                            RegistryError::Other(format!("Failed to create {}: {e}", tp.display()))
                        })?;
                        if let Err(e) = f.write_all(&buf) {
                            drop(f);
                            let _ = std::fs::remove_file(&tp);
                            return Err(RegistryError::Other(format!(
                                "Failed to write {}: {e}",
                                tp.display()
                            )));
                        }
                        drop(f);
                        if let Err(e) = std::fs::rename(&tp, &dp) {
                            let _ = std::fs::remove_file(&tp);
                            return Err(RegistryError::Other(format!(
                                "Failed to rename {} to {}: {e}",
                                tp.display(),
                                dp.display()
                            )));
                        }
                        Ok(())
                    })
                    .await
                    .map_err(|e| {
                        RegistryError::Other(format!("Failed to join tarball write task: {e}"))
                    })?;
                    dest_buf_res?;
                } else if let Some(mut bw) = sink.file.take() {
                    if let Err(e) = bw.flush().await {
                        drop(bw);
                        let _ = tokio::fs::remove_file(temp_path).await;
                        return Err(RegistryError::Other(format!(
                            "Failed to flush {}: {e}",
                            temp_path.display()
                        )));
                    }
                    drop(bw);
                    if let Err(e) = tokio::fs::rename(temp_path, dest_path).await {
                        let _ = tokio::fs::remove_file(temp_path).await;
                        return Err(RegistryError::Other(format!(
                            "Failed to rename {} to {}: {e}",
                            temp_path.display(),
                            dest_path.display()
                        )));
                    }
                }
                return Ok(HopOutcome::Success {
                    etag: parsed.etag,
                    payload: BodyPayload::File { written },
                });
            }
        }
    }
}

async fn open_fresh_connection(
    pool: &Http1Pool,
    key: &str,
    url: &Url,
    port: u16,
    connect_timeout: Duration,
    total_deadline: tokio::time::Instant,
) -> Result<TcpStream, RegistryError> {
    let now = tokio::time::Instant::now();
    if now >= total_deadline {
        return Err(RegistryError::Transport(HttpTransportError {
            message: format_io_error(
                url,
                &std::io::Error::new(ErrorKind::TimedOut, "connect timeout"),
                true,
                true,
            ),
            is_connect: true,
            is_timeout: true,
            is_decode: false,
            is_transient: true,
        }));
    }
    let deadline = (now + connect_timeout).min(total_deadline);

    let single_addr = match url.host() {
        Some(Host::Ipv4(ip)) => Some(SocketAddr::new(IpAddr::V4(ip), port)),
        Some(Host::Ipv6(ip)) => Some(SocketAddr::new(IpAddr::V6(ip), port)),
        Some(Host::Domain(_)) => None,
        None => {
            return Err(RegistryError::Other("URL has no host".into()));
        }
    };

    let connect_result = if let Some(addr) = single_addr {
        tokio::time::timeout_at(deadline, TcpStream::connect(addr)).await
    } else {
        let Some(Host::Domain(dom)) = url.host() else {
            unreachable!()
        };
        let addrs: Arc<[SocketAddr]> = if let Some(cached) = pool.get_cached_dns(key) {
            cached
        } else {
            let res = tokio::time::timeout_at(deadline, tokio::net::lookup_host((dom, port)))
                .await
                .map_err(|_| {
                    RegistryError::Transport(HttpTransportError {
                        message: format_io_error(
                            url,
                            &std::io::Error::new(ErrorKind::TimedOut, "DNS lookup timed out"),
                            true,
                            true,
                        ),
                        is_connect: true,
                        is_timeout: true,
                        is_decode: false,
                        is_transient: true,
                    })
                })?
                .map_err(|err| {
                    RegistryError::Transport(HttpTransportError {
                        message: format_io_error(url, &err, true, false),
                        is_connect: true,
                        is_timeout: false,
                        is_decode: false,
                        is_transient: true,
                    })
                })?;
            let resolved: Arc<[SocketAddr]> = res.collect::<Vec<_>>().into();
            if resolved.is_empty() {
                let err = std::io::Error::new(
                    ErrorKind::AddrNotAvailable,
                    "failed to lookup address information",
                );
                return Err(RegistryError::Transport(HttpTransportError {
                    message: format_io_error(url, &err, true, false),
                    is_connect: true,
                    is_timeout: false,
                    is_decode: false,
                    is_transient: true,
                }));
            }
            pool.put_cached_dns(key, Arc::clone(&resolved));
            resolved
        };
        tokio::time::timeout_at(deadline, connect_addrs(&addrs)).await
    };

    match connect_result {
        Ok(Ok(stream)) => {
            let _ = stream.set_nodelay(true);
            Ok(stream)
        }
        Ok(Err(err)) => {
            pool.invalidate_dns(key);
            let is_to = err.kind() == ErrorKind::TimedOut;
            Err(RegistryError::Transport(HttpTransportError {
                message: format_io_error(url, &err, true, is_to),
                is_connect: true,
                is_timeout: is_to,
                is_decode: false,
                is_transient: is_transient_io(&err),
            }))
        }
        Err(_) => {
            pool.invalidate_dns(key);
            Err(RegistryError::Transport(HttpTransportError {
                message: format_io_error(
                    url,
                    &std::io::Error::new(ErrorKind::TimedOut, "connect timed out"),
                    true,
                    true,
                ),
                is_connect: true,
                is_timeout: true,
                is_decode: false,
                is_transient: true,
            }))
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn read_content_length_body(
    stream: &mut TcpStream,
    initial_rem: &[u8],
    content_length: u64,
    sink: &mut BodySink<'_>,
    url: &Url,
    idle_timeout: Duration,
    total_deadline: tokio::time::Instant,
    idle_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<bool, RegistryError> {
    let take_initial = (initial_rem.len() as u64).min(content_length) as usize;
    let trailing_extra = (initial_rem.len() as u64) > content_length;
    if take_initial > 0 {
        sink.push(&initial_rem[..take_initial]).await?;
    }

    if sink.disk_threshold.is_none() {
        if let Some(ref mut mem) = sink.mem {
            while sink.written < content_length {
                let remaining = content_length - sink.written;
                let old_len = mem.len();
                let mut limited = (&mut *stream).take(remaining);
                let n = read_buf_with_timeouts(
                    &mut limited,
                    mem,
                    url,
                    idle_timeout,
                    total_deadline,
                    idle_sleep,
                )
                .await?;
                if n == 0 {
                    return Err(RegistryError::ContentLengthMismatch {
                        expected: content_length,
                        actual: sink.written,
                    });
                }
                if let Some(ref mut ctx) = sink.hasher {
                    ctx.update(&mem[old_len..]);
                }
                sink.written += n as u64;
            }
            return Ok(!trailing_extra);
        }
    }

    if sink.written >= content_length {
        return Ok(!trailing_extra);
    }

    let scratch_len = (content_length - sink.written).min(64 * 1024) as usize;
    let mut scratch = vec![0u8; scratch_len];
    while sink.written < content_length {
        let remaining = (content_length - sink.written) as usize;
        let to_read = remaining.min(scratch.len());
        let n = read_with_timeouts(
            stream,
            &mut scratch[..to_read],
            url,
            idle_timeout,
            total_deadline,
            idle_sleep,
        )
        .await?;
        if n == 0 {
            return Err(RegistryError::ContentLengthMismatch {
                expected: content_length,
                actual: sink.written,
            });
        }
        sink.push(&scratch[..n]).await?;
    }
    Ok(!trailing_extra)
}

#[allow(clippy::too_many_arguments)]
async fn read_chunked_body(
    stream: &mut TcpStream,
    head_buf: &[u8],
    body_start: usize,
    sink: &mut BodySink<'_>,
    url: &Url,
    idle_timeout: Duration,
    total_deadline: tokio::time::Instant,
    idle_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<bool, RegistryError> {
    let mut buf = Vec::with_capacity(STACK_HEAD_BUF);
    buf.extend_from_slice(&head_buf[body_start..]);
    let mut pos = 0usize;

    loop {
        let line_end = loop {
            if let Some(rel) = buf[pos..].windows(2).position(|w| w == b"\r\n") {
                break pos + rel;
            }
            if pos > 0 {
                buf.copy_within(pos.., 0);
                buf.truncate(buf.len() - pos);
                pos = 0;
            }
            if buf.len() > 4096 {
                return Err(RegistryError::Transport(HttpTransportError {
                    message: "Chunked size line exceeded 4096 bytes".into(),
                    is_connect: false,
                    is_timeout: false,
                    is_decode: true,
                    is_transient: false,
                }));
            }
            let old_len = buf.len();
            buf.resize(old_len + 4096, 0);
            let n = read_with_timeouts(
                stream,
                &mut buf[old_len..],
                url,
                idle_timeout,
                total_deadline,
                idle_sleep,
            )
            .await?;
            buf.truncate(old_len + n);
            if n == 0 {
                return Err(RegistryError::Transport(HttpTransportError {
                    message: format_io_error(
                        url,
                        &std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "premature EOF in chunked stream",
                        ),
                        false,
                        false,
                    ),
                    is_connect: false,
                    is_timeout: false,
                    is_decode: true,
                    is_transient: true,
                }));
            }
        };

        let line = &buf[pos..line_end];
        let size_bytes = match line.iter().position(|&b| b == b';') {
            Some(semi) => trim_ascii_ws(&line[..semi]),
            None => trim_ascii_ws(line),
        };
        let size_str = std::str::from_utf8(size_bytes).map_err(|_| {
            RegistryError::Transport(HttpTransportError {
                message: "Invalid UTF-8 in chunk size".into(),
                is_connect: false,
                is_timeout: false,
                is_decode: true,
                is_transient: false,
            })
        })?;
        if size_str.is_empty() || !size_str.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(RegistryError::Transport(HttpTransportError {
                message: format!("Invalid hex chunk size '{size_str}'"),
                is_connect: false,
                is_timeout: false,
                is_decode: true,
                is_transient: false,
            }));
        }
        let chunk_size = u64::from_str_radix(size_str, 16).map_err(|_| {
            RegistryError::Transport(HttpTransportError {
                message: format!("Chunk size overflow '{size_str}'"),
                is_connect: false,
                is_timeout: false,
                is_decode: true,
                is_transient: false,
            })
        })?;
        pos = line_end + 2;

        if chunk_size == 0 {
            loop {
                if buf.len() - pos >= 2 && &buf[pos..pos + 2] == b"\r\n" {
                    pos += 2;
                    return Ok(pos == buf.len());
                }
                if let Some(rel) = buf[pos..].windows(4).position(|w| w == b"\r\n\r\n") {
                    pos += rel + 4;
                    return Ok(pos == buf.len());
                }
                if pos > 0 {
                    buf.copy_within(pos.., 0);
                    buf.truncate(buf.len() - pos);
                    pos = 0;
                }
                if buf.len() > MAX_HEADER_BYTES {
                    return Ok(false);
                }
                let old_len = buf.len();
                buf.resize(old_len + 4096, 0);
                let n = read_with_timeouts(
                    stream,
                    &mut buf[old_len..],
                    url,
                    idle_timeout,
                    total_deadline,
                    idle_sleep,
                )
                .await?;
                buf.truncate(old_len + n);
                if n == 0 {
                    return Err(RegistryError::Transport(HttpTransportError {
                        message: format_io_error(
                            url,
                            &std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "premature EOF in chunked trailers",
                            ),
                            false,
                            false,
                        ),
                        is_connect: false,
                        is_timeout: false,
                        is_decode: true,
                        is_transient: true,
                    }));
                }
            }
        }

        sink.check_limit(chunk_size)?;

        let mut remaining = chunk_size as usize;
        if pos < buf.len() {
            let take = remaining.min(buf.len() - pos);
            sink.push(&buf[pos..pos + take]).await?;
            pos += take;
            remaining -= take;
        }
        if remaining > 0 {
            buf.clear();
            pos = 0;
            let mut scratch = vec![0u8; remaining.min(64 * 1024)];
            while remaining > 0 {
                let want = remaining.min(scratch.len());
                let n = read_with_timeouts(
                    stream,
                    &mut scratch[..want],
                    url,
                    idle_timeout,
                    total_deadline,
                    idle_sleep,
                )
                .await?;
                if n == 0 {
                    return Err(RegistryError::Transport(HttpTransportError {
                        message: format_io_error(
                            url,
                            &std::io::Error::new(
                                ErrorKind::UnexpectedEof,
                                "premature EOF in chunk data",
                            ),
                            false,
                            false,
                        ),
                        is_connect: false,
                        is_timeout: false,
                        is_decode: true,
                        is_transient: true,
                    }));
                }
                sink.push(&scratch[..n]).await?;
                remaining -= n;
            }
        }

        while buf.len() - pos < 2 {
            if pos > 0 {
                buf.copy_within(pos.., 0);
                buf.truncate(buf.len() - pos);
                pos = 0;
            }
            let old_len = buf.len();
            buf.resize(old_len + 4096, 0);
            let n = read_with_timeouts(
                stream,
                &mut buf[old_len..],
                url,
                idle_timeout,
                total_deadline,
                idle_sleep,
            )
            .await?;
            buf.truncate(old_len + n);
            if n == 0 {
                return Err(RegistryError::Transport(HttpTransportError {
                    message: format_io_error(
                        url,
                        &std::io::Error::new(
                            ErrorKind::UnexpectedEof,
                            "premature EOF expecting chunk CRLF",
                        ),
                        false,
                        false,
                    ),
                    is_connect: false,
                    is_timeout: false,
                    is_decode: true,
                    is_transient: true,
                }));
            }
        }
        if &buf[pos..pos + 2] != b"\r\n" {
            return Err(RegistryError::Transport(HttpTransportError {
                message: "Malformed chunk terminator (expected CRLF)".into(),
                is_connect: false,
                is_timeout: false,
                is_decode: true,
                is_transient: false,
            }));
        }
        pos += 2;
    }
}

async fn read_eof_body(
    stream: &mut TcpStream,
    initial_rem: &[u8],
    sink: &mut BodySink<'_>,
    url: &Url,
    idle_timeout: Duration,
    total_deadline: tokio::time::Instant,
    idle_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<(), RegistryError> {
    if !initial_rem.is_empty() {
        sink.push(initial_rem).await?;
    }
    let mut scratch = vec![0u8; 64 * 1024];
    loop {
        let n = read_with_timeouts(
            stream,
            &mut scratch,
            url,
            idle_timeout,
            total_deadline,
            idle_sleep,
        )
        .await?;
        if n == 0 {
            return Ok(());
        }
        sink.push(&scratch[..n]).await?;
    }
}

#[allow(clippy::too_many_arguments)]
async fn read_error_body(
    stream: &mut TcpStream,
    initial_rem: &[u8],
    parsed: &ParsedHeaders,
    method: &Method,
    url: &Url,
    idle_timeout: Duration,
    total_deadline: tokio::time::Instant,
    idle_sleep: &mut Option<Pin<Box<tokio::time::Sleep>>>,
) -> Result<(Vec<u8>, bool), RegistryError> {
    if *method == Method::HEAD {
        return Ok((Vec::new(), initial_rem.is_empty()));
    }
    if parsed.is_chunked {
        let mut sink = BodySink::new_memory(MAX_ERROR_BODY_BYTES, None, false);
        let clean = read_chunked_body(
            stream,
            initial_rem,
            0,
            &mut sink,
            url,
            idle_timeout,
            total_deadline,
            idle_sleep,
        )
        .await?;
        return Ok((sink.mem.unwrap_or_default(), clean));
    }
    if let Some(cl) = parsed.content_length {
        if cl > MAX_ERROR_BODY_BYTES as u64 {
            return Ok((Vec::new(), false));
        }
        let mut sink = BodySink::new_memory(MAX_ERROR_BODY_BYTES, Some(cl), false);
        let clean = read_content_length_body(
            stream,
            initial_rem,
            cl,
            &mut sink,
            url,
            idle_timeout,
            total_deadline,
            idle_sleep,
        )
        .await?;
        return Ok((sink.mem.unwrap_or_default(), clean));
    }
    let capped = initial_rem.len().min(MAX_ERROR_BODY_BYTES);
    Ok((initial_rem[..capped].to_vec(), false))
}

fn decompress_bounded<R: Read>(decoder: R, max_size: usize) -> Result<Vec<u8>, RegistryError> {
    let mut out = Vec::new();
    let mut limited = decoder.take((max_size as u64) + 1);
    limited.read_to_end(&mut out).map_err(|err| {
        RegistryError::Transport(HttpTransportError {
            message: format!("Failed to decompress HTTP response body: {err}"),
            is_connect: false,
            is_timeout: false,
            is_decode: true,
            is_transient: false,
        })
    })?;
    if out.len() > max_size {
        return Err(RegistryError::SizeLimitExceeded {
            limit: max_size as u64,
            actual: out.len() as u64,
            message: "Decompressed response payload exceeds maximum size".into(),
        });
    }
    Ok(out)
}

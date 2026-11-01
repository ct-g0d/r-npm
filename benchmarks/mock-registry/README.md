# Mock Registry for Differential Benchmarks

Lightweight local loopback mock npm registry designed for reproducible, offline performance benchmarks and correctness tests.

## Features

- **Abbreviated Metadata:** Serves `application/vnd.npm.install-v1+json` and standard `application/json` packuments.
- **Dynamic URL Rewriting:** Automatically rewrites tarball URLs in packuments to match the host and port of incoming requests.
- **Deterministic Tarballs:** Immutable `.tgz` archives with fixed timestamps and verified SHA-512 SSRI integrity.
- **Request Logging:** Logs every HTTP request with duration and bytes transferred, queryable via `/api/requests`.
- **Status Simulation:** Supports `/ __status/<code >` (e.g. 401, 403, 404, 429, 302) for fault-injection testing.
- **Zero Dependencies:** Pure Node.js built with built-in `http`, `crypto`, `fs`, `path`, and `zlib` modules.

## Usage

### Build packages
```powershell
node benchmarks/mock-registry/build-packages.js
```

### Start server
```powershell
node benchmarks/mock-registry/mock-server.js --port 4873 --storage benchmarks/mock-registry/storage
```

### API Endpoints
- `GET /api/health` - Health check and uptime.
- `GET /api/requests` - Query recorded requests.
- `POST /api/reset` - Clear request history.
- `GET /api/shutdown` - Gracefully shut down the server.

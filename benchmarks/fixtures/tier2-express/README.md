# Tier 2: Express HTTP Backend Fixture (`tier2-express`)

Synthetic benchmark fixture representing a Node.js Express HTTP microservice / API backend.

## Manifest Characteristics
- `dependencies`:
  - `express`: Minimalist web framework, depending transitively on `accepts`, `mime-types`, `debug`, `depd`.
  - `body-parser`: Parsing middleware, depending transitively on `bytes`, `raw-body`.
  - `cors`: Cross-origin resource sharing middleware.
  - `cookie-parser`: Cookie header parser.
- Transitive dependencies:
  - `mime-types` -> `mime-db`
  - `raw-body` -> `bytes`
  - `accepts` -> `mime-types`
- Demonstrates transitive deduplication and hoisting of shared sub-dependencies (`bytes`, `mime-types`).

## Purpose
Validates:
1. Multi-level dependency tree resolution and hoisting.
2. Deduplication of shared transitive packages (`bytes`, `mime-types`).
3. Reification and deterministic lockfile generation for typical backend services.

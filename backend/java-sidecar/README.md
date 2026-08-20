# OpenScience Java Sidecar

This module is the Java 21 boundary of OpenScience's incremental hybrid-backend migration. The existing Bun/TypeScript CLI still owns the agent loop, tools, model streams, and every permission decision.

The sidecar currently provides three loopback-only endpoints:

- `GET /v1/health`
- `GET /v1/capabilities`
- `POST /v1/policy/evaluate`

Policy evaluation is shadow-only. Java evaluates the same effective rules as TypeScript and the CLI logs parity, but the Java response never changes allow, deny, or ask behavior.

## Requirements

- Java 21 (the Maven Enforcer rule rejects other major versions)
- Maven 3.9 or newer
- Bun 1.3.14 for the TypeScript CLI

## Test

From the repository root:

```bash
bun run java:test
```

This boots the real WebFlux application on a random port for its HTTP integration tests.

## Run locally

Start the sidecar in one terminal:

```bash
bun run java:run
```

It binds to `127.0.0.1:8088` by default. Override only the port when needed:

```bash
OPENSCIENCE_JAVA_SIDECAR_PORT=8090 bun run java:run
```

Then opt the CLI into shadow mode in another terminal:

```bash
OPENSCIENCE_JAVA_SIDECAR_URL=http://127.0.0.1:8088 bun run dev
```

PowerShell equivalents:

```powershell
$env:OPENSCIENCE_JAVA_SIDECAR_PORT = "8090"
bun run java:run

$env:OPENSCIENCE_JAVA_SIDECAR_URL = "http://127.0.0.1:8090"
bun run dev
```

The CLI accepts only plain HTTP loopback root URLs (`localhost`, `127.0.0.1`, or `::1`) without credentials, query strings, fragments, or path prefixes. It connects directly to loopback, ignores proxy environment variables, and never follows redirects. Each shadow request times out after 500 ms and contains only the permission name, requested pattern, and effective policy rules.

## Policy contract

Request:

```json
{
  "protocolVersion": "1",
  "permission": "bash",
  "pattern": "ls -la",
  "rules": [{ "permission": "bash", "pattern": "ls *", "action": "allow" }]
}
```

Response:

```json
{
  "protocolVersion": "1",
  "decision": { "permission": "bash", "pattern": "ls *", "action": "allow" }
}
```

Rules use last-match-wins precedence and the same `*`, `?`, and optional trailing ` *` semantics as `backend/cli/src/util/wildcard.ts`. An unmatched request defaults to `ask`.

To keep shadow evaluation bounded, the HTTP contract accepts at most 128 rules, 256 UTF-16 code units per permission, and 4096 code units per pattern. A single evaluation also shares a 100,000-step matching budget. Oversized HTTP requests return 400; exhausting the work budget produces the safe default `ask` shadow result. TypeScript remains authoritative in either case.

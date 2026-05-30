# @synthegria/client

Official JavaScript / Node.js SDK for the **Synthegria SIEM** log ingestion API.

Zero dependencies. Works in Node.js 18+ and modern browsers.
Full TypeScript definitions included.

## Installation

```bash
npm install @synthegria/client
# or:
yarn add @synthegria/client
```

## Quick Start

```javascript
const { SynthegriaClient } = require("@synthegria/client");

const client = new SynthegriaClient({
  apiKey:  "synthegria_<tenant>_<token>",
  baseUrl: "https://your-app.onrender.com",
});

// ── Synchronous ingestion ─────────────────────────────────────────────────
const logs = [
  { timestamp: "2026-01-01T00:00:00Z", source_ip: "1.2.3.4",
    message: "normal login", severity: "LOW" },
];

const result = await client.ingest(logs);
console.log(result.anomaly_count);            // 0
console.log(result.meter_event_id);           // "mtr_evt_..."
console.log(result.ai_analysis);              // null (clean batch)

// ── Bulk async ingestion ──────────────────────────────────────────────────
const largeBatch = Array.from({ length: 5_000 }, (_, i) => ({
  message: `event ${i}`, source_ip: "10.0.0.1",
}));

const job = await client.ingestBulk(largeBatch);
console.log(job.jobId);                       // UUID

const done = await job.wait({ timeout: 60_000 });
console.log(done.anomaly_count);
console.log(done.ai_analysis?.summary);       // AI threat summary
```

## TypeScript

```typescript
import { SynthegriaClient, IngestResult, AIAnalysis } from "@synthegria/client";

const client = new SynthegriaClient({
  apiKey: "synthegria_acme_abc123",
  baseUrl: "https://siem.acme.io",
});

const result: IngestResult = await client.ingest(logs);
const ai: AIAnalysis | null = result.ai_analysis;
```

## Error Handling

```javascript
const { AuthError, RateLimitError, SynthegriaError } = require("@synthegria/client");

try {
  await client.ingest(logs);
} catch (err) {
  if (err instanceof AuthError) {
    console.error("Check your API key");
  } else if (err instanceof RateLimitError) {
    console.warn(`Retry after ${err.retryAfter}s`);
  } else if (err instanceof SynthegriaError) {
    console.error(`API error ${err.statusCode}:`, err.message);
  }
}
```

## API Reference

### `new SynthegriaClient({ apiKey, baseUrl, timeout })`

| Method | Returns | Description |
|---|---|---|
| `ingest(logs)` | `Promise<IngestResult>` | Sync JSON ingestion |
| `ingestBulk(logs)` | `Promise<BulkJob>` | Async gzip ingestion |
| `getJob(jobId)` | `Promise<JobRecord>` | Poll job status |
| `getAudit(limit?)` | `Promise<AuditEntry[]>` | Fetch audit entries |
| `healthz()` | `Promise<{status:"ok"}>` | Liveness probe |

### `BulkJob`

| Member | Type | Description |
|---|---|---|
| `jobId` | `string` | UUID |
| `linesReceived` | `number` | Lines accepted |
| `wait(opts?)` | `Promise<IngestResult>` | Block until done |

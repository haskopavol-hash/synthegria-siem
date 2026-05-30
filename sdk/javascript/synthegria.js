/**
 * Synthegria SIEM JavaScript / Node.js SDK  v1.0.0
 * =================================================
 * Zero-dependency client for the Synthegria log ingestion API.
 * Works in Node.js 18+ (native fetch + zlib) and modern browsers
 * (fetch + CompressionStream).
 *
 * @example
 * // Node.js
 * const { SynthegriaClient } = require("./synthegria");
 *
 * const client = new SynthegriaClient({
 *   apiKey:  "synthegria_acme_abc123",
 *   baseUrl: "https://siem.acme.io",
 * });
 *
 * // Synchronous ingestion
 * const result = await client.ingest(logs);
 * console.log(result.anomaly_count);
 * console.log(result.ai_analysis?.summary);
 *
 * // Async bulk ingestion
 * const job = await client.ingestBulk(logs);
 * const done = await job.wait({ timeout: 60_000 });
 * console.log(done.meter_event_id);
 */

"use strict";

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

class SynthegriaError extends Error {
  /**
   * @param {string} message
   * @param {number|null} statusCode
   */
  constructor(message, statusCode = null) {
    super(message);
    this.name = "SynthegriaError";
    this.statusCode = statusCode;
  }
}

class AuthError extends SynthegriaError {
  constructor(message = "Invalid or missing API key.") {
    super(message, 401);
    this.name = "AuthError";
  }
}

class RateLimitError extends SynthegriaError {
  /**
   * @param {string} message
   * @param {number|null} retryAfter  seconds until the limit resets
   */
  constructor(message, retryAfter = null) {
    super(message, 429);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

class BulkJobError extends SynthegriaError {
  /**
   * @param {string} jobId
   * @param {string} reason
   */
  constructor(jobId, reason) {
    super(`Bulk job '${jobId}' failed: ${reason}`);
    this.name = "BulkJobError";
    this.jobId = jobId;
    this.reason = reason;
  }
}

// ---------------------------------------------------------------------------
// BulkJob
// ---------------------------------------------------------------------------

class BulkJob {
  /**
   * @param {string} jobId
   * @param {number} linesReceived
   * @param {string} pollUrl
   * @param {SynthegriaClient} client
   */
  constructor(jobId, linesReceived, pollUrl, client) {
    this.jobId = jobId;
    this.linesReceived = linesReceived;
    this.pollUrl = pollUrl;
    this._client = client;
  }

  /**
   * Wait until the job reaches "done" and return the result envelope.
   *
   * @param {object}  opts
   * @param {number}  opts.timeout       Maximum wait in milliseconds (default 60 000).
   * @param {number}  opts.pollInterval  Time between polls in milliseconds (default 500).
   * @returns {Promise<object>} The result envelope (same shape as ingest()).
   * @throws {BulkJobError}  The job finished with status="failed".
   * @throws {Error}         Timed out waiting for completion.
   */
  async wait({ timeout = 60_000, pollInterval = 500 } = {}) {
    const deadline = Date.now() + timeout;
    while (Date.now() < deadline) {
      const status = await this._client.getJob(this.jobId);
      if (status.status === "done") return status.result;
      if (status.status === "failed") {
        throw new BulkJobError(this.jobId, status.error ?? "unknown");
      }
      await _sleep(pollInterval);
    }
    throw new Error(
      `Bulk job '${this.jobId}' did not complete within ${timeout}ms.`
    );
  }
}

// ---------------------------------------------------------------------------
// SynthegriaClient
// ---------------------------------------------------------------------------

class SynthegriaClient {
  /**
   * @param {object} opts
   * @param {string} opts.apiKey   Tenant API key.
   * @param {string} [opts.baseUrl="https://your-app.onrender.com"]
   * @param {number} [opts.timeout=30000]  Request timeout in ms.
   */
  constructor({ apiKey, baseUrl = "https://your-app.onrender.com", timeout = 30_000 } = {}) {
    if (!apiKey) throw new Error("apiKey is required.");
    this.apiKey   = apiKey;
    this.baseUrl  = baseUrl.replace(/\/$/, "");
    this.timeout  = timeout;
  }

  // -------------------------------------------------------------------------
  // Internal helpers
  // -------------------------------------------------------------------------

  /**
   * @private
   * @param {string} method
   * @param {string} path
   * @param {BodyInit|null} body
   * @param {Record<string,string>} extraHeaders
   * @returns {Promise<object|Array>}
   */
  async _request(method, path, body = null, extraHeaders = {}) {
    const url = `${this.baseUrl}${path}`;
    const headers = {
      "X-API-Key":    this.apiKey,
      "Content-Type": "application/json",
      ...extraHeaders,
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeout);

    let response;
    try {
      response = await fetch(url, {
        method,
        headers,
        body,
        signal: controller.signal,
      });
    } catch (err) {
      clearTimeout(timer);
      throw new SynthegriaError(`Network error: ${err.message}`);
    }
    clearTimeout(timer);

    let data;
    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok) {
      const detail = data?.detail ?? JSON.stringify(data);
      const retryAfter = response.headers.get("Retry-After");
      if (response.status === 401) throw new AuthError(detail);
      if (response.status === 429) {
        throw new RateLimitError(detail, retryAfter ? parseInt(retryAfter, 10) : null);
      }
      throw new SynthegriaError(detail, response.status);
    }

    return data;
  }

  /**
   * Gzip-compress a string.  Works in Node.js 18+ and modern browsers.
   * @private
   * @param {string} str
   * @returns {Promise<Uint8Array|Buffer>}
   */
  async _gzip(str) {
    // Node.js — use the native zlib module
    if (typeof process !== "undefined" && process.versions?.node) {
      const { gzipSync } = await import("node:zlib");
      return gzipSync(Buffer.from(str, "utf-8"));
    }
    // Browser — use CompressionStream
    const cs     = new CompressionStream("gzip");
    const writer = cs.writable.getWriter();
    writer.write(new TextEncoder().encode(str));
    writer.close();
    const chunks = [];
    const reader = cs.readable.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const len   = chunks.reduce((s, c) => s + c.length, 0);
    const out   = new Uint8Array(len);
    let offset  = 0;
    for (const chunk of chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }

  // -------------------------------------------------------------------------
  // Public API
  // -------------------------------------------------------------------------

  /**
   * Ingest a plain JSON batch synchronously.
   *
   * The server runs anomaly detection and AI analysis inline and returns
   * the full result envelope immediately.
   *
   * @param {object[]} logs  Array of log-line objects.
   * @returns {Promise<object>} Result envelope with anomaly_count, ai_analysis, etc.
   * @throws {AuthError}       Invalid or missing API key.
   * @throws {RateLimitError}  Rate limit exceeded.
   * @throws {SynthegriaError} Any other API error.
   */
  async ingest(logs) {
    return this._request("POST", "/v1/logs", JSON.stringify(logs));
  }

  /**
   * Submit a gzip-compressed batch for asynchronous background processing.
   *
   * Returns a BulkJob handle immediately (HTTP 202 Accepted).
   * Call job.wait() to block until done, or poll getJob() manually.
   *
   * @param {object[]} logs  Array of log-line objects.
   * @returns {Promise<BulkJob>}
   * @throws {AuthError}       Invalid or missing API key.
   * @throws {RateLimitError}  Rate limit exceeded.
   * @throws {SynthegriaError} Queue full (503) or other API error.
   */
  async ingestBulk(logs) {
    const compressed = await this._gzip(JSON.stringify(logs));
    const result = await this._request(
      "POST", "/v1/logs/bulk",
      compressed,
      { "Content-Encoding": "gzip" },
    );
    return new BulkJob(result.job_id, result.lines_received, result.poll_url, this);
  }

  /**
   * Poll the status and result of a bulk ingestion job.
   *
   * @param {string} jobId  UUID returned by ingestBulk().
   * @returns {Promise<object>} Job status object.
   * @throws {SynthegriaError(statusCode=404)} Job not found or expired (1 h TTL).
   */
  async getJob(jobId) {
    return this._request("GET", `/v1/jobs/${jobId}`);
  }

  /**
   * Fetch structured audit log entries.
   *
   * @param {number} [limit=20]  Number of entries to return (max 100).
   * @returns {Promise<object[]>}
   */
  async getAudit(limit = 20) {
    return this._request("GET", `/v1/audit?limit=${limit}`);
  }

  /**
   * Check the API liveness.
   *
   * @returns {Promise<{status: "ok"}>}
   */
  async healthz() {
    return this._request("GET", "/healthz");
  }
}

// ---------------------------------------------------------------------------
// Internal utility
// ---------------------------------------------------------------------------

function _sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ---------------------------------------------------------------------------
// Exports  (CommonJS + ESM-compatible)
// ---------------------------------------------------------------------------

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    SynthegriaClient,
    BulkJob,
    SynthegriaError,
    AuthError,
    RateLimitError,
    BulkJobError,
  };
}

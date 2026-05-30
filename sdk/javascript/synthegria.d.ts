/**
 * Synthegria SIEM JavaScript SDK — TypeScript Definitions  v1.0.0
 */

// ---------------------------------------------------------------------------
// Exceptions
// ---------------------------------------------------------------------------

export class SynthegriaError extends Error {
  readonly statusCode: number | null;
  constructor(message: string, statusCode?: number | null);
}

export class AuthError extends SynthegriaError {
  readonly statusCode: 401;
  constructor(message?: string);
}

export class RateLimitError extends SynthegriaError {
  readonly statusCode: 429;
  readonly retryAfter: number | null;
  constructor(message: string, retryAfter?: number | null);
}

export class BulkJobError extends SynthegriaError {
  readonly jobId: string;
  readonly reason: string;
  constructor(jobId: string, reason: string);
}

// ---------------------------------------------------------------------------
// Anomaly + AI analysis shapes
// ---------------------------------------------------------------------------

export type AnomalySeverity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
export type AnomalyType = "brute_force" | "sql_injection" | "xss" | "auth_anomaly";
export type JobStatus    = "pending" | "processing" | "done" | "failed";
export type AIMode       = "live" | "mock";

export interface Anomaly {
  type:     AnomalyType;
  severity: AnomalySeverity;
  [key: string]: unknown;
}

export interface AIAnalysis {
  mode:           AIMode;
  model:          string;
  threat_level:   AnomalySeverity;
  attack_types:   AnomalyType[];
  summary:        string;
  disclaimer?:    string;
  tokens_used?:   number | null;
  fallback_reason?: string;
}

// ---------------------------------------------------------------------------
// Ingestion result
// ---------------------------------------------------------------------------

export interface IngestResult {
  status:         "ok";
  customer_id:    string;
  lines_received: number;
  meter_event_id: string | null;
  anomaly_count:  number;
  anomalies:      Anomaly[];
  ai_analysis:    AIAnalysis | null;
  message?:       string;
  compressed_bytes?:   number;
  uncompressed_bytes?: number;
  compression_ratio?:  string;
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

export interface AuditEntry {
  ts:             string;
  method:         string;
  path:           string;
  status_code:    number;
  duration_ms:    number;
  api_key:        string | null;
  customer_id:    string | null;
  lines_received: number | null;
  anomaly_count:  number | null;
  ip:             string | null;
}

// ---------------------------------------------------------------------------
// Job
// ---------------------------------------------------------------------------

export interface JobRecord {
  job_id:         string;
  status:         JobStatus;
  customer_id:    string;
  lines_received: number;
  created_at:     string;
  completed_at?:  string;
  result?:        IngestResult;
  error?:         string;
}

// ---------------------------------------------------------------------------
// BulkJob
// ---------------------------------------------------------------------------

export interface WaitOptions {
  /** Maximum wait time in milliseconds. Default: 60 000. */
  timeout?:      number;
  /** Poll interval in milliseconds. Default: 500. */
  pollInterval?: number;
}

export declare class BulkJob {
  readonly jobId:         string;
  readonly linesReceived: number;
  readonly pollUrl:       string;

  /**
   * Block until the job is done and return the ingestion result.
   * @throws {BulkJobError} The job finished with status="failed".
   * @throws {Error}        Timed out.
   */
  wait(opts?: WaitOptions): Promise<IngestResult>;
}

// ---------------------------------------------------------------------------
// Client options
// ---------------------------------------------------------------------------

export interface SynthegriaClientOptions {
  /** Tenant API key sent as X-API-Key header. */
  apiKey: string;
  /** Base URL of the deployed Synthegria instance. */
  baseUrl?: string;
  /** Request timeout in milliseconds. Default: 30 000. */
  timeout?: number;
}

// ---------------------------------------------------------------------------
// SynthegriaClient
// ---------------------------------------------------------------------------

export declare class SynthegriaClient {
  readonly apiKey:   string;
  readonly baseUrl:  string;
  readonly timeout:  number;

  constructor(opts: SynthegriaClientOptions);

  /**
   * Ingest a plain JSON batch synchronously.
   * Returns the full result including anomaly detection and AI analysis.
   */
  ingest(logs: Record<string, unknown>[]): Promise<IngestResult>;

  /**
   * Submit a gzip-compressed batch for async background processing.
   * Returns a BulkJob handle immediately (HTTP 202 Accepted).
   */
  ingestBulk(logs: Record<string, unknown>[]): Promise<BulkJob>;

  /**
   * Poll the status and result of a bulk ingestion job.
   * @throws {SynthegriaError} (statusCode=404) Job not found or expired.
   */
  getJob(jobId: string): Promise<JobRecord>;

  /**
   * Fetch the last N structured audit log entries.
   */
  getAudit(limit?: number): Promise<AuditEntry[]>;

  /**
   * Check the API liveness.
   */
  healthz(): Promise<{ status: "ok" }>;
}

// Client for the OSV.dev API (https://google.github.io/osv.dev/api/). OSV aggregates
// the GitHub Advisory Database, npm advisories, OpenSSF malicious-package reports and more,
// so DepCheck never maintains its own vulnerability data. The API allows CORS, so this
// works from a browser as well as Node.
import type { Dependency } from './lockfiles.js';

export interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

export interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  withdrawn?: string;
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { name: string; ecosystem: string };
    ranges?: Array<{ type: string; events: OsvEvent[] }>;
    versions?: string[];
    database_specific?: Record<string, unknown>;
  }>;
  references?: Array<{ type: string; url: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] } & Record<string, unknown>;
}

export type FetchLike = (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
}>;

export interface OsvClientOptions {
  baseUrl?: string;
  fetch?: FetchLike;
  /** Parallel requests when fetching vulnerability details. Default 8. */
  concurrency?: number;
  /** Shared cache of vulnerability details by id. */
  cache?: Map<string, OsvVulnerability>;
  /** Give up on a request after this long. Default 30 000 ms. */
  timeoutMs?: number;
  /** Extra attempts after a network error, a timeout, HTTP 429 or a 5xx response. Default 2. */
  retries?: number;
  /** Wait before the first retry; doubles for each later one. Default 500 ms. */
  retryDelayMs?: number;
}

interface BatchResponse {
  results: Array<{ vulns?: Array<{ id: string }>; next_page_token?: string }>;
}

const BATCH_SIZE = 1000;

export class OsvClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly concurrency: number;
  private readonly cache: Map<string, OsvVulnerability>;
  private readonly timeoutMs: number;
  private readonly retries: number;
  private readonly retryDelayMs: number;

  constructor(options: OsvClientOptions = {}) {
    this.baseUrl = (options.baseUrl ?? 'https://api.osv.dev').replace(/\/$/, '');
    // Bind: calling window.fetch detached from window throws "Illegal invocation" in browsers.
    const f = options.fetch ?? (globalThis.fetch?.bind(globalThis) as unknown as FetchLike | undefined);
    if (!f) throw new Error('No fetch implementation available; pass options.fetch');
    this.fetchImpl = f;
    this.concurrency = options.concurrency ?? 8;
    this.cache = options.cache ?? new Map();
    this.timeoutMs = options.timeoutMs ?? 30_000;
    this.retries = options.retries ?? 2;
    this.retryDelayMs = options.retryDelayMs ?? 500;
  }

  /** One request with a timeout, retried when the failure is likely to be temporary. */
  private async request<T>(path: string, body?: unknown): Promise<T> {
    let failure = new Error(`OSV request ${path} failed`);
    for (let attempt = 0; attempt <= this.retries; attempt++) {
      if (attempt) await new Promise((resolve) => setTimeout(resolve, this.retryDelayMs * 2 ** (attempt - 1)));
      const signal = typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function' ? AbortSignal.timeout(this.timeoutMs) : undefined;
      try {
        const res = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method: body ? 'POST' : 'GET',
          headers: body ? { 'content-type': 'application/json' } : undefined,
          body: body ? JSON.stringify(body) : undefined,
          signal,
        });
        if (res.ok) return (await res.json()) as T;
        failure = new Error(`OSV request ${path} failed with HTTP ${res.status}`);
        if (res.status !== 429 && res.status < 500) break; // a client error will not improve on retry
      } catch (err) {
        const reason = signal?.aborted ? `no response within ${this.timeoutMs} ms` : (err as Error).message;
        failure = new Error(`OSV request ${path} failed: ${reason}`);
      }
    }
    throw failure;
  }

  /** Returns the vulnerability ids affecting each dependency, in input order. */
  async queryIds(deps: Dependency[]): Promise<string[][]> {
    const out: string[][] = deps.map(() => []);
    for (let start = 0; start < deps.length; start += BATCH_SIZE) {
      const slice = deps.slice(start, start + BATCH_SIZE);
      let pending = slice.map((d, i) => ({ index: start + i, dep: d, token: undefined as string | undefined }));
      while (pending.length) {
        const res = await this.request<BatchResponse>('/v1/querybatch', {
          queries: pending.map((p) => ({
            package: { name: p.dep.name, ecosystem: 'npm' },
            version: p.dep.version,
            ...(p.token ? { page_token: p.token } : {}),
          })),
        });
        const next: typeof pending = [];
        pending.forEach((p, i) => {
          const r = res.results[i];
          for (const v of r?.vulns ?? []) out[p.index]!.push(v.id);
          if (r?.next_page_token) next.push({ ...p, token: r.next_page_token });
        });
        pending = next;
      }
    }
    return out;
  }

  async getVulnerability(id: string): Promise<OsvVulnerability> {
    const cached = this.cache.get(id);
    if (cached) return cached;
    const vuln = await this.request<OsvVulnerability>(`/v1/vulns/${encodeURIComponent(id)}`);
    this.cache.set(id, vuln);
    return vuln;
  }

  async getVulnerabilities(ids: Iterable<string>): Promise<Map<string, OsvVulnerability>> {
    const queue = [...new Set(ids)];
    const result = new Map<string, OsvVulnerability>();
    const worker = async () => {
      for (let id = queue.shift(); id !== undefined; id = queue.shift()) {
        result.set(id, await this.getVulnerability(id));
      }
    };
    await Promise.all(Array.from({ length: Math.min(this.concurrency, queue.length) }, worker));
    return result;
  }
}

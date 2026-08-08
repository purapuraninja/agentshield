import { sha256 } from '@agentshield/core';
import {
  MEMORY_ADAPTER_CONTRACT_VERSION, type MemoryAdapter, type MemoryAdapterOptions,
  type MemoryConnectionResult, type MemoryInventoryPage, type MemoryInventoryRequest
} from './index.js';
import { normalizeRecord } from './normalize.js';

/**
 * Read-only PostgreSQL memory adapter.
 *
 * The adapter talks to a `PostgresDriver` instead of importing node-postgres directly. That keeps the
 * Community edition self-contained (no database driver is bundled) while still providing the real
 * `pg` integration through {@link createPgDriver}, which lazy-imports the driver only when used.
 *
 * Read-only enforcement lives in the contract, not the hope: every operation opens a `READ ONLY`
 * transaction with a bounded `statement_timeout`, and the driver is free to reject any write
 * statement. The conformance suite in `postgres.test.ts` proves an audit-mode adapter cannot issue
 * mutation queries.
 */

export interface PostgresDriver {
  readonly name: string;
  /** Opens a read-only transaction (optionally with a statement timeout) before queries. */
  beginReadOnly(timeoutMs?: number): Promise<void>;
  /** Ends the read-only transaction (rollback); safe to call after `beginReadOnly`. */
  finish(): Promise<void>;
  /** Closes the underlying connection. */
  close(): Promise<void>;
  /** Returns the column names of a table. */
  columns(table: string): Promise<string[]>;
  /** Runs a parameterized query and returns the result rows. */
  query(sql: string, params?: unknown[]): Promise<Array<Record<string, unknown>>>;
}

/** Lazily imports node-postgres; throws an actionable message when the driver is not installed. */
export async function createPgDriver(options: MemoryAdapterOptions = {}): Promise<PostgresDriver> {
  let pg: typeof import('pg');
  try {
    pg = await import('pg');
  } catch {
    throw new Error(
      'The PostgreSQL adapter requires the optional `pg` package. Install it with ' +
      '`corepack pnpm add pg` in the consuming project and try again. The Community edition does not bundle a database driver.'
    );
  }
  const client = new pg.Client({
    connectionString: options.connectionString,
    host: options.host,
    port: options.port,
    database: options.database,
    user: options.user,
    password: options.password,
    ssl: options.ssl
  });
  let connected = false;
  let transactionOpen = false;
  async function ensureConnected(): Promise<void> {
    if (connected) return; // node-postgres rejects a second connect() on the same client
    await client.connect();
    connected = true;
  }
  return {
    name: 'postgres',
    async beginReadOnly(timeoutMs) {
      await ensureConnected();
      await client.query('BEGIN TRANSACTION READ ONLY');
      if (timeoutMs && Number.isInteger(timeoutMs) && timeoutMs > 0) {
        await client.query('SET statement_timeout = $1', [timeoutMs]);
      }
      transactionOpen = true;
    },
    async finish() {
      if (!transactionOpen) return;
      try { await client.query('ROLLBACK'); } finally { transactionOpen = false; }
    },
    async close() {
      try { if (transactionOpen) await client.query('ROLLBACK'); } finally { transactionOpen = false; }
      await client.end().catch(() => undefined);
      connected = false;
    },
    async columns(table) {
      const rows = await client.query(
        'SELECT column_name FROM information_schema.columns WHERE table_name = $1 ORDER BY ordinal_position',
        [table]
      );
      return rows.rows.map((row) => String(row.column_name));
    },
    async query(sql, params) {
      const result = await client.query(sql, params ?? []);
      return result.rows;
    }
  };
}

function assertIdentifier(value: string, label: string): string {
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(value)) throw new Error(`${label} must be a simple SQL identifier`);
  return value;
}

function boundedPageSize(value: number | undefined): number {
  if (value === undefined) return 500;
  if (!Number.isInteger(value) || value < 1 || value > 5_000) throw new Error('Memory page size must be an integer between 1 and 5000');
  return value;
}

function isValidCursor(value: string | undefined): boolean {
  if (value === undefined) return true;
  if (value.length === 0 || value.length > 256) return false;
  return !value.includes('\u0000') && !value.includes('\r') && !value.includes('\n');
}

/**
 * Creates an audit-only memory adapter over a PostgreSQL table. The adapter never calls `planMutation`,
 * `applyMutation`, or `restoreSnapshot`, so {@link validateMemoryAdapter} rejects it for remediation
 * mode and proves that audit mode cannot issue write queries.
 */
export function createPostgresAdapter(driver: PostgresDriver, options: MemoryAdapterOptions = {}): MemoryAdapter {
  const table = options.table ? assertIdentifier(options.table, 'table') : undefined;
  const statementTimeoutMs = options.statementTimeoutMs;
  const adapterIdentity = sha256(`${driver.name ?? 'postgres'}\0${table ?? ''}\0${options.database ?? ''}`);
  const adapter: MemoryAdapter = {
    contractVersion: MEMORY_ADAPTER_CONTRACT_VERSION,
    id: `postgres:${adapterIdentity.replace('sha256:', '').slice(0, 24)}`,
    target: `postgres://${options.database ?? ''}/${table ?? ''}`,
    mode: 'audit',
    capabilities: { readOnlyAudit: true, pagination: true, checkpoints: true, sourceMutation: false, snapshotRestore: false },
    async testConnection(): Promise<MemoryConnectionResult> {
      try {
        await driver.beginReadOnly(statementTimeoutMs);
        const rows = await driver.query('SELECT 1 AS ok');
        await driver.finish();
        return { ok: rows.length === 1, adapter: 'postgres', message: rows.length === 1 ? 'PostgreSQL connection and read-only transaction verified' : 'PostgreSQL returned no rows for SELECT 1' };
      } catch (error) {
        await driver.finish().catch(() => undefined);
        return { ok: false, adapter: 'postgres', message: redact(error) };
      }
    },
    async inventoryPage(request: MemoryInventoryRequest = {}): Promise<MemoryInventoryPage> {
      if (!table) throw new Error('PostgreSQL audit requires --table');
      if (!isValidCursor(request.cursor)) throw new Error('Invalid memory inventory cursor');
      const pageSize = boundedPageSize(request.pageSize ?? options.pageSize);
      await driver.beginReadOnly(statementTimeoutMs);
      try {
        let columns = await driver.columns(table);
        if (!columns.length) throw new Error(`Table ${table} does not exist or has no columns`);
        columns = columns.map(String);
        const names = new Set(columns);
        const idColumn = options.idColumn ?? (names.has('id') ? 'id' : columns[0]!);
        const contentColumn = options.contentColumn ?? ['content', 'text', 'value', 'memory'].find((name) => names.has(name));
        if (!contentColumn) throw new Error('Could not infer content column; pass --content-column');
        assertIdentifier(idColumn, 'id-column');
        assertIdentifier(contentColumn, 'content-column');
        // Fetch one extra row so the last page does not produce an empty trailing page.
        const rows = request.cursor === undefined
          ? await driver.query(`SELECT * FROM "${table}" ORDER BY "${idColumn}" LIMIT $1`, [pageSize + 1])
          : await driver.query(`SELECT * FROM "${table}" WHERE "${idColumn}" > $1::text ORDER BY "${idColumn}" LIMIT $2`, [request.cursor, pageSize + 1]);
        const hasMore = rows.length > pageSize;
        const pageRows = hasMore ? rows.slice(0, pageSize) : rows;
        const records = pageRows.map((row, index) => normalizeRecord({
          ...row,
          content: row[contentColumn],
          created_at: options.createdAtColumn ? row[assertIdentifier(options.createdAtColumn, 'created-at-column')] : row.created_at,
          source: options.sourceColumn ? row[assertIdentifier(options.sourceColumn, 'source-column')] : row.source
        }, 'postgres', adapter.target, String(row[idColumn] ?? `${request.cursor ?? ''}:${index}`), `postgres://${options.database ?? ''}/${table}`));
        const last = records.at(-1);
        return { records, errors: [], nextCursor: hasMore && last ? String(last.externalId) : undefined };
      } finally {
        await driver.finish();
      }
    },
    async checkpoint(): Promise<string> {
      if (!table) throw new Error('PostgreSQL audit requires --table');
      await driver.beginReadOnly(statementTimeoutMs);
      try {
        const columns = (await driver.columns(table)).map(String);
        const names = new Set(columns);
        const idColumn = options.idColumn ?? (names.has('id') ? 'id' : columns[0]!);
        const contentColumn = options.contentColumn ?? ['content', 'text', 'value', 'memory'].find((name) => names.has(name));
        if (!contentColumn) throw new Error('Could not infer content column; pass --content-column');
        assertIdentifier(idColumn, 'id-column');
        assertIdentifier(contentColumn, 'content-column');
        const rows = await driver.query(`SELECT "${idColumn}", "${contentColumn}" FROM "${table}" ORDER BY "${idColumn}"`);
        return sha256(rows
          .map((row) => `${String(row[idColumn])}\0${String(row[contentColumn] ?? '')}`)
          .sort()
          .join('\n'));
      } finally {
        await driver.finish();
      }
    }
  };
  return adapter;
}

function redact(error: unknown): string {
  const message = error instanceof Error ? error.message : String(error);
  return message
    .replace(/(?:password|passwd|pwd)\s*[=:]\s*[^\s,;]+/gi, '$1=[REDACTED]')
    .replace(/(postgres(?:ql)?:\/\/)[^/@\s]+@/i, '$1[REDACTED]@');
}

export type { MemoryAdapterOptions };

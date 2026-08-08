import { describe, expect, it } from 'vitest';
import { validateMemoryAdapter } from './index.js';
import { createPgDriver, createPostgresAdapter, type PostgresDriver } from './postgres.js';

const ROWS: Array<Record<string, unknown>> = [
  { id: 'a1', content: 'The deployment region is us-east-1.', type: 'semantic', created_at: '2026-07-01T00:00:00Z' },
  { id: 'b2', content: 'Run the release script before every deploy.', type: 'procedural', created_at: '2026-07-02T00:00:00Z' },
  { id: 'c3', content: 'The release happened on Friday and was rolled back.', type: 'episodic', created_at: '2026-07-03T00:00:00Z' },
  { id: 'd4', content: 'Draft notes for the incident review.', type: 'working', created_at: '2026-07-04T00:00:00Z' },
  { id: 'e5', content: 'The deployment region is us-east-1.', type: 'semantic', created_at: '2026-07-05T00:00:00Z' }
];

/**
 * Minimal driver that simulates a PostgreSQL table and enforces the audit contract: statements other
 * than SELECT/transaction control are rejected, and every query must run inside a READ ONLY
 * transaction. It records every statement so tests can prove no write query was ever issued.
 */
class InMemoryPostgresDriver implements PostgresDriver {
  readonly name = 'in-memory-postgres';
  readonly statements: string[] = [];
  private transactionOpen = false;
  constructor(private readonly rows: Array<Record<string, unknown>>) {}

  async beginReadOnly(timeoutMs?: number): Promise<void> {
    this.transactionOpen = true;
    this.statements.push('BEGIN TRANSACTION READ ONLY');
    if (timeoutMs) this.statements.push(`SET statement_timeout = ${timeoutMs}`);
  }
  async finish(): Promise<void> {
    this.transactionOpen = false;
    this.statements.push('ROLLBACK');
  }
  async close(): Promise<void> { this.transactionOpen = false; }
  async columns(): Promise<string[]> {
    return ['id', 'content', 'created_at', 'source'];
  }
  async query(sql: string, params: unknown[] = []): Promise<Array<Record<string, unknown>>> {
    if (!this.transactionOpen) throw new Error('query issued outside a read-only transaction');
    const keyword = sql.trim().split(/\s+/)[0]?.toUpperCase() ?? '';
    if (!['SELECT', 'SET', 'BEGIN', 'COMMIT', 'ROLLBACK'].includes(keyword)) {
      throw new Error(`write statement rejected in audit mode: ${sql}`);
    }
    this.statements.push(sql);
    if (/SELECT 1 AS ok/.test(sql)) return [{ ok: 1 }];
    const cursorMatch = /WHERE "(\w+)" > \$1::text ORDER BY "\w+" LIMIT \$2/.exec(sql);
    if (cursorMatch) {
      const cursor = String(params[0] ?? '');
      const limit = Number(params[1]);
      return this.rows.filter((row) => String(row[cursorMatch[1]!]) > cursor).slice(0, limit);
    }
    const firstPage = /ORDER BY "(\w+)" LIMIT \$1/.exec(sql);
    if (firstPage) {
      const limit = Number(params[0]);
      return [...this.rows].sort((a, b) => String(a[firstPage[1]!]).localeCompare(String(b[firstPage[1]!]))).slice(0, limit);
    }
    if (/ORDER BY "\w+"$/.test(sql.trim())) {
      return [...this.rows].sort((a, b) => String(a.id).localeCompare(String(b.id)));
    }
    return this.rows;
  }
}

describe('postgres read-only memory adapter', () => {
  it('passes the memory adapter conformance suite', async () => {
    const adapter = createPostgresAdapter(new InMemoryPostgresDriver(ROWS), { table: 'memories' });
    const result = await validateMemoryAdapter(adapter);
    expect(result.records).toBe(5);
    expect(result.pages).toBe(3);
    expect(result.checkpoint).toMatch(/^sha256:[a-f0-9]{64}$/);
  });

  it('never exposes mutation methods in audit mode', () => {
    const adapter = createPostgresAdapter(new InMemoryPostgresDriver(ROWS), { table: 'memories' });
    expect(adapter.mode).toBe('audit');
    expect(adapter.capabilities.sourceMutation).toBe(false);
    expect(adapter.capabilities.snapshotRestore).toBe(false);
    expect(adapter.planMutation).toBeUndefined();
    expect(adapter.applyMutation).toBeUndefined();
    expect(adapter.restoreSnapshot).toBeUndefined();
  });

  it('issues only read-only statements while conformance runs', async () => {
    const driver = new InMemoryPostgresDriver(ROWS);
    await validateMemoryAdapter(createPostgresAdapter(driver, { table: 'memories' }));
    expect(driver.statements.some((sql) => /BEGIN TRANSACTION READ ONLY/i.test(sql))).toBe(true);
    expect(driver.statements.some((sql) => /ROLLBACK/i.test(sql))).toBe(true);
    const writes = driver.statements.filter((sql) => !/^(SELECT|SET|BEGIN|COMMIT|ROLLBACK)\b/i.test(sql.trim()));
    expect(writes).toEqual([]);
  });

  it('rejects write queries inside the audit driver', async () => {
    const driver = new InMemoryPostgresDriver(ROWS);
    await driver.beginReadOnly();
    await expect(driver.query('DELETE FROM memories')).rejects.toThrow('write statement rejected in audit mode');
    await expect(driver.query('UPDATE memories SET content = $1', ['x'])).rejects.toThrow('write statement rejected in audit mode');
  });

  it('rejects invalid cursors and page sizes', async () => {
    const adapter = createPostgresAdapter(new InMemoryPostgresDriver(ROWS), { table: 'memories' });
    await expect(adapter.inventoryPage({ cursor: 'bad\ncursor' })).rejects.toThrow('Invalid memory inventory cursor');
    await expect(adapter.inventoryPage({ pageSize: 999_999 })).rejects.toThrow('page size');
  });

  it('normalizes rows into canonical memory records with column inference', async () => {
    const adapter = createPostgresAdapter(new InMemoryPostgresDriver(ROWS), { table: 'memories' });
    const page = await adapter.inventoryPage({});
    expect(page.records).toHaveLength(5);
    expect(page.records[0]).toMatchObject({ externalId: 'a1', type: 'semantic' });
    expect(page.records[0]?.source.uri).toContain('postgres://');
    expect(page.records[0]?.createdAt).toBe('2026-07-01T00:00:00Z');
  });

  it('supports explicit column overrides', async () => {
    const adapter = createPostgresAdapter(new InMemoryPostgresDriver(ROWS), {
      table: 'memories', contentColumn: 'content', createdAtColumn: 'created_at'
    });
    const page = await adapter.inventoryPage({});
    expect(page.records[0]?.createdAt).toBe('2026-07-01T00:00:00Z');
  });

  it('fails with actionable guidance when pg is not installed', async () => {
    await expect(createPgDriver({ connectionString: 'postgres://localhost/example' }))
      .rejects.toThrow(/optional `pg` package/);
  });
});

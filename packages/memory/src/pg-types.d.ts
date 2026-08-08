/**
 * Ambient declarations for the optional `pg` package. The Community edition does not bundle a
 * database driver; these declarations keep typecheck working without installing node-postgres while
 * `createPgDriver` lazy-imports the real driver at runtime with actionable guidance when absent.
 */
declare module 'pg' {
  export class Client {
    constructor(config?: Record<string, unknown>);
    connect(): Promise<void>;
    query(text: string, values?: unknown[]): Promise<{ rows: Array<Record<string, unknown>> }>;
    end(): Promise<void>;
  }
}

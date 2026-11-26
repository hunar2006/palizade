declare module "node:sqlite" {
  export class DatabaseSync {
    constructor(path: string);
    exec(sql: string): void;
    prepare(sql: string): {
      run(...args: unknown[]): void;
      all(...args: unknown[]): unknown[];
      get(...args: unknown[]): unknown;
      iterate(): Iterable<unknown>;
    };
    close(): void;
  }
}

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { runAuthMigrations, MigrationDB } from '@/database/auth-migration-runner';
import * as fs from 'fs';
import * as path from 'path';

// Mock the logger to suppress output during tests
vi.mock('@/utils/logger', () => ({
  logger: {
    info: vi.fn(),
    warn: vi.fn(),
    error: vi.fn(),
    debug: vi.fn()
  }
}));

// Mock fs so we can control migration file discovery without process.chdir
vi.mock('fs', async (importOriginal) => {
  const actual = await importOriginal<typeof fs>();
  return {
    ...actual,
    existsSync: vi.fn(),
    readdirSync: vi.fn(),
    readFileSync: vi.fn()
  };
});

const mockedFs = vi.mocked(fs);

/**
 * In-memory database mock that tracks executed SQL.
 */
class InMemoryMigrationDB implements MigrationDB {
  private migrations: Array<{ version: number; name: string }> = [];
  private executedSQL: string[] = [];

  exec(sql: string): void {
    this.executedSQL.push(sql);
  }

  prepare(sql: string) {
    const db = this;
    return {
      run(...params: any[]): { changes: number } {
        db.executedSQL.push(sql);
        if (sql.includes('INSERT INTO _auth_migrations')) {
          db.migrations.push({ version: params[0], name: params[1] });
          return { changes: 1 };
        }
        return { changes: 0 };
      },
      get(..._params: any[]): any {
        return undefined;
      },
      all(..._params: any[]): any[] {
        if (sql.includes('SELECT version FROM _auth_migrations')) {
          return db.migrations.map(r => ({ version: r.version }));
        }
        return [];
      }
    };
  }

  getExecutedSQL(): string[] {
    return this.executedSQL;
  }

  getMigrations(): Array<{ version: number; name: string }> {
    return this.migrations;
  }
}

/**
 * Set up fs mocks to simulate a migrations directory with given files.
 */
function setupFsMocks(files: Record<string, string>) {
  const filenames = Object.keys(files);

  // existsSync: return true for the dist migrations path
  mockedFs.existsSync.mockImplementation((p: fs.PathLike) => {
    const ps = p.toString();
    if (ps.includes(path.join('dist', 'database', 'migrations', 'auth'))) return true;
    return false;
  });

  mockedFs.readdirSync.mockReturnValue(filenames.sort() as any);

  mockedFs.readFileSync.mockImplementation((p: fs.PathOrFileDescriptor, _opts?: any) => {
    const basename = path.basename(p.toString());
    if (files[basename] !== undefined) return files[basename];
    throw new Error(`File not found: ${p}`);
  });
}

describe('runAuthMigrations', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should create _auth_migrations tracking table', () => {
    setupFsMocks({
      '001_create_table.sql': 'CREATE TABLE IF NOT EXISTS user_instances (id TEXT PRIMARY KEY);'
    });

    const db = new InMemoryMigrationDB();
    runAuthMigrations(db);

    const createTableSQL = db.getExecutedSQL().find(
      s => s.includes('CREATE TABLE IF NOT EXISTS _auth_migrations')
    );
    expect(createTableSQL).toBeDefined();
  });

  it('should apply all migrations on fresh database', () => {
    setupFsMocks({
      '001_create_table.sql': 'CREATE TABLE IF NOT EXISTS user_instances (id TEXT PRIMARY KEY);',
      '002_drop_legacy.sql': 'DROP TABLE IF EXISTS users;'
    });

    const db = new InMemoryMigrationDB();
    runAuthMigrations(db);

    const migrations = db.getMigrations();
    expect(migrations).toHaveLength(2);
    expect(migrations[0].version).toBe(1);
    expect(migrations[0].name).toBe('001_create_table.sql');
    expect(migrations[1].version).toBe(2);
    expect(migrations[1].name).toBe('002_drop_legacy.sql');
  });

  it('should skip already applied migrations (idempotent)', () => {
    setupFsMocks({
      '001_create_table.sql': 'CREATE TABLE IF NOT EXISTS user_instances (id TEXT PRIMARY KEY);',
      '002_drop_legacy.sql': 'DROP TABLE IF EXISTS users;'
    });

    const db = new InMemoryMigrationDB();

    // Run once
    runAuthMigrations(db);
    expect(db.getMigrations()).toHaveLength(2);

    // Run again - should not add duplicates
    runAuthMigrations(db);
    expect(db.getMigrations()).toHaveLength(2);
  });

  it('should apply only pending migrations (partial state)', () => {
    setupFsMocks({
      '001_create_table.sql': 'CREATE TABLE IF NOT EXISTS user_instances (id TEXT PRIMARY KEY);',
      '002_drop_legacy.sql': 'DROP TABLE IF EXISTS users;'
    });

    const db = new InMemoryMigrationDB();

    // Pre-seed migration 001 as already applied
    db.prepare('INSERT INTO _auth_migrations (version, name) VALUES (?, ?)').run(1, '001_create_table.sql');

    // Run migrations - should only apply 002
    runAuthMigrations(db);

    const migrations = db.getMigrations();
    expect(migrations).toHaveLength(2);
    expect(migrations[0].version).toBe(1);
    expect(migrations[1].version).toBe(2);
    expect(migrations[1].name).toBe('002_drop_legacy.sql');
  });

  it('should skip files with invalid naming', () => {
    setupFsMocks({
      '001_create_table.sql': 'CREATE TABLE IF NOT EXISTS user_instances (id TEXT PRIMARY KEY);',
      '002_drop_legacy.sql': 'DROP TABLE IF EXISTS users;',
      'invalid.sql': 'SELECT 1;'
    });

    const db = new InMemoryMigrationDB();
    runAuthMigrations(db);

    // Should only apply the 2 valid migrations
    const migrations = db.getMigrations();
    expect(migrations).toHaveLength(2);
  });

  it('should execute migration SQL on the database', () => {
    const migrationSQL = 'CREATE TABLE IF NOT EXISTS user_instances (id TEXT PRIMARY KEY);';
    setupFsMocks({
      '001_create_table.sql': migrationSQL
    });

    const db = new InMemoryMigrationDB();
    runAuthMigrations(db);

    // The migration SQL should appear in executed statements
    const executed = db.getExecutedSQL();
    expect(executed.some(s => s === migrationSQL)).toBe(true);
  });
});

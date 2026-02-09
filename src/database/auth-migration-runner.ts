/**
 * Auth database migration runner.
 *
 * Applies numbered SQL migrations from the migrations/auth/ directory
 * to an auth.db database. Tracks applied migrations in an
 * `_auth_migrations` table so each migration runs at most once.
 */

import * as fs from 'fs';
import * as path from 'path';
import { logger } from '../utils/logger';

/**
 * Minimal database interface matching better-sqlite3's synchronous API.
 */
export interface MigrationDB {
  prepare(sql: string): {
    run(...params: any[]): { changes: number };
    get(...params: any[]): any;
    all(...params: any[]): any[];
  };
  exec(sql: string): void;
}

/**
 * Resolve the migrations directory.
 * Works from both dist/ (compiled) and src/ (development) roots.
 */
function resolveMigrationsDir(): string {
  // Try dist path first (production / post-build)
  const distPath = path.join(process.cwd(), 'dist', 'database', 'migrations', 'auth');
  if (fs.existsSync(distPath)) {
    return distPath;
  }

  // Fall back to src path (development)
  const srcPath = path.join(process.cwd(), 'src', 'database', 'migrations', 'auth');
  if (fs.existsSync(srcPath)) {
    return srcPath;
  }

  // Try relative to this file (for bundled / monorepo setups)
  const relativePath = path.join(__dirname, 'migrations', 'auth');
  if (fs.existsSync(relativePath)) {
    return relativePath;
  }

  throw new Error(
    `Auth migrations directory not found. Checked: ${distPath}, ${srcPath}, ${relativePath}`
  );
}

/**
 * Parse a migration filename into its version number.
 * Expected format: NNN_description.sql (e.g. 001_create_user_instances.sql).
 * Returns null for filenames that don't match.
 */
function parseMigrationVersion(filename: string): number | null {
  const match = filename.match(/^(\d{3})_.*\.sql$/);
  if (!match) return null;
  return parseInt(match[1], 10);
}

/**
 * Run all pending auth migrations on the given database.
 *
 * - Creates `_auth_migrations` tracking table if it doesn't exist
 * - Reads .sql files from migrations/auth/ sorted by version number
 * - Applies each migration not yet recorded in the tracking table
 *
 * @param db - A better-sqlite3-compatible database handle
 */
export function runAuthMigrations(db: MigrationDB): void {
  // Create tracking table
  db.exec(`
    CREATE TABLE IF NOT EXISTS _auth_migrations (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Discover migration files
  const migrationsDir = resolveMigrationsDir();
  const files = fs.readdirSync(migrationsDir)
    .filter(f => f.endsWith('.sql'))
    .sort();

  // Determine already-applied versions
  const applied = new Set<number>(
    db.prepare('SELECT version FROM _auth_migrations').all()
      .map((row: any) => row.version as number)
  );

  for (const file of files) {
    const version = parseMigrationVersion(file);
    if (version === null) {
      logger.warn(`Skipping invalid migration filename: ${file}`);
      continue;
    }

    if (applied.has(version)) {
      continue;
    }

    const sql = fs.readFileSync(path.join(migrationsDir, file), 'utf-8');
    logger.info(`Applying auth migration ${file}...`);

    db.exec(sql);

    db.prepare(
      'INSERT INTO _auth_migrations (version, name) VALUES (?, ?)'
    ).run(version, file);

    logger.info(`Applied auth migration ${file}`);
  }
}

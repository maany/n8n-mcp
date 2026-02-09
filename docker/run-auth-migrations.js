#!/usr/bin/env node

/**
 * Run auth database migrations (user_instances table) programmatically.
 * This script is used in Docker containers to initialize custom tables
 * in auth.db at startup, before the Node.js server starts.
 */

const path = require('path');
const fs = require('fs');

function runMigrations() {
  try {
    const dataDir = path.join(process.cwd(), 'data');

    // Ensure data directory exists
    if (!fs.existsSync(dataDir)) {
      fs.mkdirSync(dataDir, { recursive: true });
    }

    const dbPath = path.join(dataDir, 'auth.db');

    // Open (or create) auth.db
    const Database = require('better-sqlite3');
    const db = new Database(dbPath);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');

    // Import and run the migration runner
    const { runAuthMigrations } = require('../dist/database/auth-migration-runner.js');
    runAuthMigrations(db);

    db.close();
    console.log('Auth custom table migrations completed successfully');
  } catch (error) {
    console.error('ERROR: Auth migration failed:', error.message);
    console.error(error.stack);
    process.exit(1);
  }
}

runMigrations();

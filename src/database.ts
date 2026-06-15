import { mkdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';

await mkdir('./storage').catch(() => null);

export const database = new DatabaseSync('./storage/database.db');

database.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT NOT NULL,
      avatar TEXT,

      access_token BLOB,
      access_token_iv BLOB,
      refresh_token BLOB,
      refresh_token_iv BLOB,
      expires_at INTEGER,

      banned INTEGER
    ) STRICT;

    CREATE TABLE IF NOT EXISTS gwell (
      id INTEGER PRIMARY KEY,
      name TEXT,
      text TEXT,
      color TEXT
    ) STRICT;

    INSERT OR IGNORE INTO gwell (id) VALUES (0);
  `);

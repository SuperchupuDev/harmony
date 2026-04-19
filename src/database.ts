import { mkdir } from 'node:fs/promises';
import { DatabaseSync } from 'node:sqlite';

await mkdir('./storage').catch(() => null);

export const database = new DatabaseSync('./storage/database.db');

database
  .prepare(`
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
  `)
  .run();

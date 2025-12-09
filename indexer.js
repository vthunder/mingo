// Simple SBO indexer via WebSocket and SQLite
import WebSocket from 'ws';
import { Buffer } from 'buffer';
import fs from 'fs';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import yaml from 'js-yaml';

// Get WebSocket URL and verbosity from command line
const wsUrl = process.argv[2];
const verbosity = process.argv[3] || 'info';
if (!wsUrl) {
  console.error('Usage: node indexer.js <ws-url> [verbosity]');
  process.exit(1);
}

// Connect to WebSocket
const ws = new WebSocket(wsUrl);

// Open SQLite DB
const db = await open({
  filename: './sbo_index.db',
  driver: sqlite3.Database
});

// Ensure table exists
await db.exec(`
  CREATE TABLE IF NOT EXISTS sbo_objects (
    id TEXT,
    path TEXT,
    action TEXT,
    schema TEXT,
    content_schema TEXT,
    content_type TEXT,
    block_number INTEGER,
    data TEXT,
    PRIMARY KEY (path, id)
  )
`);

// Parse SBO message from base64-encoded blob
function parseSBOBlob(base64Data) {
  const raw = Buffer.from(base64Data, 'base64').toString('utf-8');
  const parts = raw.split(/^---\n/m);
  if (parts.length < 2) throw new Error('Missing YAML frontmatter delimiter');
  const metadata = yaml.load(parts[1]);
  if (!metadata?.schema?.startsWith('SBO')) throw new Error('Not a valid SBO message');
  const content = parts.slice(2).join('---\n');
  return { metadata, content };
}

ws.on('message', async (raw) => {
  try {
    const parsed = JSON.parse(raw);
    if (parsed.topic !== 'data-verified') return;

    const txs = parsed.message?.data_transactions || [];

    for (const tx of txs) {
      if (verbosity === 'info') console.log('Received transaction');
      try {
        const { metadata, content } = parseSBOBlob(tx.data);
        const { path, id, action, schema, content_schema, content_type } = metadata;

        if (verbosity === 'debug') {
          console.debug('Parsed SBO message:', metadata);
        } else if (verbosity === 'info') {
          console.log(`Valid SBO: path=${path}, id=${id}`);
        }

        await db.run(
          `INSERT OR REPLACE INTO sbo_objects (id, path, action, schema, content_schema, content_type, block_number, data)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
          [id || null, path, action, schema, content_schema || null, content_type || null, parsed.message.block_number, content]
        );
      } catch (e) {
        console.error('Failed to parse or validate SBO message:', e.message);
      }
    }
  } catch (err) {
    console.error('Failed to process message:', err.message);
  }
});

ws.on('open', () => console.log('Connected to WebSocket stream'));
ws.on('close', () => console.log('WebSocket closed'));
ws.on('error', (err) => console.error('WebSocket error:', err));

import { Pool } from 'pg';
import { config } from '../config/env.js';

export const pool = new Pool({
  connectionString: config.databaseUrl,
  ssl: config.nodeEnv === 'production' ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  console.error('Unexpected database client error', err);
});

export const query = async (text: string, params?: unknown[]) => {
  return pool.query(text, params);
};

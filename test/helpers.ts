import { readFileSync, readdirSync } from 'node:fs';
import pg from 'pg';

const base = {
  host: process.env.PGHOST ?? 'localhost',
  port: Number(process.env.PGPORT ?? 5432),
  user: process.env.PGUSER ?? 'postgres',
  password: process.env.PGPASSWORD,
};

/** Fresh database with the Supabase shim + all migrations; returns a service_role pool. */
export async function freshDb(name: string): Promise<pg.Pool> {
  const admin = new pg.Client({ ...base, database: 'postgres' });
  await admin.connect();
  await admin.query(`drop database if exists ${name}`);
  await admin.query(`create database ${name}`);
  await admin.end();

  const setup = new pg.Client({ ...base, database: name });
  await setup.connect();
  const files = ['supabase/tests/00_supabase_shim.sql',
    ...readdirSync('supabase/migrations').sort().map((f) => `supabase/migrations/${f}`)];
  for (const f of files) await setup.query(readFileSync(f, 'utf8'));
  await setup.end();

  const pool = new pg.Pool({ ...base, database: name, max: 4 });
  pool.on('connect', (c) => { c.query('set role service_role'); });
  return pool;
}

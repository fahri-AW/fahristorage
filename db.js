import pg from "pg";

const { Pool } = pg;
if (!process.env.DATABASE_URL) {
  throw new Error("DATABASE_URL belum diatur. Tambahkan connection string PostgreSQL di Vercel.");
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost")
    ? false
    : { rejectUnauthorized: false },
  max: 5,
  idleTimeoutMillis: 10000,
  connectionTimeoutMillis: 10000
});

export async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGSERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin','user')),
      active SMALLINT NOT NULL DEFAULT 1,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS settings (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS files (
      id BIGSERIAL PRIMARY KEY,
      drive_id TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      mime_type TEXT NOT NULL,
      size BIGINT NOT NULL DEFAULT 0,
      category TEXT NOT NULL,
      uploaded_by BIGINT NOT NULL REFERENCES users(id),
      drive_url TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS upload_history (
      id BIGSERIAL PRIMARY KEY,
      file_name TEXT NOT NULL,
      category TEXT NOT NULL,
      action TEXT NOT NULL,
      user_id BIGINT NOT NULL REFERENCES users(id),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_files_uploaded_by ON files(uploaded_by);
    CREATE INDEX IF NOT EXISTS idx_files_created_at ON files(created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_history_user_created ON upload_history(user_id, created_at DESC);
  `);
}

function toPostgres(sql) {
  let index = 0;
  return sql.replace(/\?/g, () => `$${++index}`);
}

export async function run(sql, params = []) {
  return pool.query(toPostgres(sql), params);
}
export async function get(sql, params = []) {
  const result = await pool.query(toPostgres(sql), params);
  return result.rows[0];
}
export async function all(sql, params = []) {
  const result = await pool.query(toPostgres(sql), params);
  return result.rows;
}

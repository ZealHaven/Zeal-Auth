import { spawn, execSync } from 'child_process';
import { existsSync, writeFileSync, readFileSync, unlinkSync } from 'fs';
import { resolve } from 'path';

const PORT = '9876';
const BIN = resolve(__dirname, '..', 'bin', 'auth-server-e2e');
const PID_FILE = resolve(__dirname, '..', 'bin', '.e2e-pid');
const DB_URL = 'postgres://auth:auth@localhost:5435/auth?sslmode=disable';

export default async function globalSetup() {
  // Kill any stale server on this port
  try { execSync(`fuser -k ${PORT}/tcp`, { stdio: 'pipe' }); } catch {}
  await new Promise((r) => setTimeout(r, 500));

  // Build binary
  if (!existsSync(BIN)) {
    execSync(`go build -o ${BIN} ./cmd/server`, {
      cwd: resolve(__dirname, '..'),
      stdio: 'inherit',
    });
  }

  // Run migrations
  const migrationFile = resolve(__dirname, '..', 'migrations', '000001_init.up.sql');
  if (existsSync(migrationFile)) {
    try {
      execSync(`psql "${DB_URL}" -c "CREATE SCHEMA IF NOT EXISTS auth"`, { stdio: 'pipe' });
      execSync(`psql "${DB_URL}" -f "${migrationFile}"`, { stdio: 'pipe' });
    } catch {
      // Tables may already exist
    }
  }

  // Start server detached so it survives after this function returns
  const proc = spawn(BIN, [], {
    env: {
      ...process.env,
      SERVER_PORT: PORT,
      DATABASE_URL: DB_URL,
      REDIS_URL: 'redis://localhost:6379/0',
      COOKIE_DOMAIN: 'localhost',
      FOSITE_GLOBAL_SECRET: 'e2e-test-secret-32-bytes-long!!!!',
      KEY_ENCRYPTION_KEY: '0000000000000000000000000000000000000000000000000000000000000001',
    },
    detached: true,
    stdio: 'ignore',
  });

  proc.unref();

  // Write PID for teardown
  writeFileSync(PID_FILE, String(proc.pid));

  // Wait for server to be ready
  const maxWait = 15_000;
  const start = Date.now();
  while (Date.now() - start < maxWait) {
    try {
      const res = await fetch(`http://localhost:${PORT}/health`);
      if (res.ok) break;
    } catch {
      // not ready
    }
    await new Promise((r) => setTimeout(r, 200));
  }

  // Write port for test files to read
  writeFileSync(resolve(__dirname, '..', 'bin', '.e2e-port'), PORT);
}

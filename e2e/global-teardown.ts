import { execSync } from 'child_process';
import { existsSync, readFileSync, unlinkSync } from 'fs';
import { resolve } from 'path';

const PID_FILE = resolve(__dirname, '..', 'bin', '.e2e-pid');

export default async function globalTeardown() {
  if (existsSync(PID_FILE)) {
    const pid = readFileSync(PID_FILE, 'utf-8').trim();
    try {
      process.kill(Number(pid), 'SIGTERM');
    } catch {
      // already dead
    }
    try { unlinkSync(PID_FILE); } catch {}
  }

  // Also kill anything on the port
  try { execSync('fuser -k 9876/tcp', { stdio: 'pipe' }); } catch {}
}

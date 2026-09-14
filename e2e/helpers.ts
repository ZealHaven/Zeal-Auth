import { readFileSync } from 'fs';
import { resolve } from 'path';

const PORT_FILE = resolve(__dirname, '..', 'bin', '.e2e-port');

export function baseURL(): string {
  const port = readFileSync(PORT_FILE, 'utf-8').trim();
  return `http://localhost:${port}`;
}

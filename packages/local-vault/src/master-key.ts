import { randomBytes } from 'node:crypto';
import { readFile, writeFile, mkdir, access, chmod } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

const VAULT_DIR = join(homedir(), '.blindkey');
const KEY_FILE = join(VAULT_DIR, 'master.key');

export function getVaultDir(): string {
  return VAULT_DIR;
}

export function getDbPath(): string {
  return join(VAULT_DIR, 'vault.db');
}

/**
 * Load the master encryption key. Priority:
 * 1. VAULT_MASTER_KEY env var
 * 2. ~/.blindkey/master.key file
 * 3. Generate new key and save to file
 *
 * Sets process.env.VAULT_MASTER_KEY so core crypto functions work.
 */
export async function loadMasterKey(): Promise<string> {
  if (process.env.VAULT_MASTER_KEY) {
    return process.env.VAULT_MASTER_KEY;
  }

  let key: string;

  try {
    await access(KEY_FILE);
    key = (await readFile(KEY_FILE, 'utf-8')).trim();
  } catch {
    // First run — generate a new key
    await mkdir(VAULT_DIR, { recursive: true });
    key = randomBytes(32).toString('hex');
    await writeFile(KEY_FILE, key + '\n', 'utf-8');
    try {
      await chmod(KEY_FILE, 0o600);
    } catch {
      // chmod may not work on Windows — non-fatal
    }
  }

  process.env.VAULT_MASTER_KEY = key;
  return key;
}

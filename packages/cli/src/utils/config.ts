import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

const BLINDKEY_DIR = join(homedir(), '.blindkey');
const CONFIG_FILE = join(BLINDKEY_DIR, 'config.json');

export interface BlindKeyConfig {
  mode: 'local' | 'docker';
  version: number;
  api_url?: string;
  created_at: string;
}

export async function readConfig(): Promise<BlindKeyConfig | null> {
  try {
    const raw = await readFile(CONFIG_FILE, 'utf-8');
    return JSON.parse(raw) as BlindKeyConfig;
  } catch {
    return null;
  }
}

export async function writeConfig(config: BlindKeyConfig): Promise<void> {
  await mkdir(BLINDKEY_DIR, { recursive: true });
  await writeFile(CONFIG_FILE, JSON.stringify(config, null, 2) + '\n', 'utf-8');
}

export function getConfigPath(): string {
  return CONFIG_FILE;
}

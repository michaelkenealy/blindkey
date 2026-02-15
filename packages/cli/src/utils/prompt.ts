import { createInterface } from 'node:readline';
import { access } from 'node:fs/promises';

// ── ANSI Colors ──

export const GREEN = '\x1b[32m';
export const YELLOW = '\x1b[33m';
export const RED = '\x1b[31m';
export const CYAN = '\x1b[36m';
export const BOLD = '\x1b[1m';
export const DIM = '\x1b[2m';
export const RESET = '\x1b[0m';

// ── Interactive Prompt ──

export function createPrompt(): {
  question: (q: string) => Promise<string>;
  questionHidden: (q: string) => Promise<string>;
  close: () => void;
} {
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  return {
    question: (q: string) =>
      new Promise((resolve) => {
        rl.question(q, resolve);
      }),
    questionHidden: (q: string) =>
      new Promise((resolve) => {
        process.stdout.write(q);
        const stdin = process.stdin;
        const wasRaw = stdin.isRaw;
        stdin.setRawMode?.(true);
        let input = '';
        const onData = (char: Buffer) => {
          const c = char.toString();
          if (c === '\n' || c === '\r') {
            stdin.removeListener('data', onData);
            stdin.setRawMode?.(wasRaw);
            process.stdout.write('\n');
            resolve(input);
          } else if (c === '\u0003') {
            process.exit(0);
          } else if (c === '\u007F' || c === '\b') {
            if (input.length > 0) {
              input = input.slice(0, -1);
              process.stdout.write('\b \b');
            }
          } else {
            input += c;
            process.stdout.write('*');
          }
        };
        stdin.on('data', onData);
      }),
    close: () => rl.close(),
  };
}

// ── File Helpers ──

export async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

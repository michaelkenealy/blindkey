import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

export function registerPolicyCommand(program: Command, _getVault: () => Promise<LocalVault>) {
  const policy = program
    .command('policy')
    .description('Policy management');

  policy
    .command('list')
    .description('List active policy templates')
    .action(async () => {
      console.log('\x1b[1mActive Policies\x1b[0m\n');
      console.log('  \x1b[32m●\x1b[0m default     Built-in block patterns, size limits, content scanning');
      console.log('  \x1b[2m○\x1b[0m developer   Development workflow defaults (policies/developer.yaml)');
      console.log('  \x1b[2m○\x1b[0m paranoid    Maximum lockdown (policies/paranoid.yaml)');
      console.log('  \x1b[2m○\x1b[0m productivity Calendar, email, notes (policies/productivity.yaml)');
      console.log('\n\x1b[2mUse bk policy validate <file> to check a custom policy.\x1b[0m');
    });

  policy
    .command('validate <file>')
    .description('Validate a policy YAML file')
    .action(async (file: string) => {
      const fullPath = resolve(file);
      try {
        const content = await readFile(fullPath, 'utf-8');

        // Basic structural validation
        const errors: string[] = [];

        if (!content.includes('filesystem:') && !content.includes('proxy:')) {
          errors.push('Missing top-level "filesystem:" or "proxy:" section');
        }

        if (content.includes('block_patterns:')) {
          const patterns = content.match(/- "([^"]+)"/g);
          if (!patterns || patterns.length === 0) {
            errors.push('block_patterns section is empty');
          }
        }

        if (content.includes('content_scan:')) {
          if (!content.includes('pattern:')) {
            errors.push('content_scan section missing "pattern:" entries');
          }
          if (!content.includes('message:')) {
            errors.push('content_scan entries missing "message:" field');
          }
        }

        if (errors.length > 0) {
          console.error(`\x1b[31m✕\x1b[0m Validation failed for ${file}:`);
          for (const e of errors) {
            console.error(`  - ${e}`);
          }
          process.exit(1);
        }

        console.log(`\x1b[32m✓\x1b[0m Policy file valid: ${file}`);
      } catch (err) {
        console.error(`\x1b[31m✕\x1b[0m Cannot read ${file}: ${(err as Error).message}`);
        process.exit(1);
      }
    });
}

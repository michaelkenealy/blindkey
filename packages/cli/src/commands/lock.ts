import { resolve } from 'node:path';
import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerLockCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('lock <path>')
    .description('Revoke agent access to a filesystem path')
    .action(async (rawPath: string) => {
      const vault = await getVault();
      const fullPath = resolve(rawPath);
      const removed = vault.grants.remove(fullPath);

      if (removed) {
        vault.audit.log({
          action: 'path_locked',
          path: fullPath,
          granted: false,
        });
        console.log(`\x1b[32m\u2713\x1b[0m Locked: ${fullPath}`);
      } else {
        console.error(`\x1b[31m\u2715\x1b[0m No grant found for: ${fullPath}`);
        process.exit(1);
      }
    });
}

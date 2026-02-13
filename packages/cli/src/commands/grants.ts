import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerGrantsCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('grants')
    .alias('paths')
    .description('List all filesystem grants')
    .action(async () => {
      const vault = await getVault();
      const grants = vault.grants.getAll();

      if (grants.length === 0) {
        console.log('No filesystem grants. Unlock a path with: vault unlock <path>');
        return;
      }

      console.log(
        `\x1b[2m${'PATH'.padEnd(40)}${'PERMISSIONS'.padEnd(30)}${'FLAGS'}\x1b[0m`
      );
      console.log('\x1b[2m' + '\u2500'.repeat(80) + '\x1b[0m');

      for (const g of grants) {
        const perms = g.permissions.join(', ');
        const flags = [
          g.recursive ? 'recursive' : '',
          g.requires_approval ? '\x1b[33mapproval\x1b[0m' : '',
        ].filter(Boolean).join(', ');

        console.log(
          `\x1b[32m\u2713\x1b[0m ${g.path.padEnd(38)}${perms.padEnd(30)}${flags}`
        );
      }

      console.log(`\n\x1b[2m${grants.length} grant${grants.length === 1 ? '' : 's'}\x1b[0m`);
    });
}

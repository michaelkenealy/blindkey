import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerListCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('list')
    .alias('ls')
    .description('List all secrets in the vault')
    .action(async () => {
      const vault = await getVault();
      const secrets = await vault.store.listSecrets([]);

      if (secrets.length === 0) {
        console.log('No secrets stored. Add one with: vault add <name> <value>');
        return;
      }

      // Header
      console.log(
        `\x1b[2m${'NAME'.padEnd(24)}${'SERVICE'.padEnd(14)}${'DOMAINS'.padEnd(28)}${'VAULT REF'}\x1b[0m`
      );
      console.log('\x1b[2m' + '─'.repeat(90) + '\x1b[0m');

      for (const s of secrets) {
        const domains = s.allowed_domains ? s.allowed_domains.join(', ') : '(any)';
        console.log(
          `${s.name.padEnd(24)}${s.service.padEnd(14)}${domains.padEnd(28)}\x1b[2m${s.vault_ref}\x1b[0m`
        );
      }

      console.log(`\n\x1b[2m${secrets.length} secret${secrets.length === 1 ? '' : 's'}\x1b[0m`);
    });
}

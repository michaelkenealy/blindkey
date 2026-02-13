import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerRmCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('rm <name>')
    .description('Remove a secret from the vault')
    .action(async (name: string) => {
      const vault = await getVault();
      const deleted = vault.store.deleteSecretByName(name.toUpperCase());

      if (deleted) {
        vault.audit.log({
          action: 'secret_removed',
          detail: JSON.stringify({ name: name.toUpperCase() }),
        });
        console.log(`\x1b[32m✓\x1b[0m Secret removed: ${name.toUpperCase()}`);
      } else {
        console.error(`\x1b[31m✕\x1b[0m Secret "${name.toUpperCase()}" not found`);
        process.exit(1);
      }
    });
}

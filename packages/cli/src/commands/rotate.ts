import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerRotateCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('rotate <name> <new-value>')
    .description('Rotate a secret (replace with a new value)')
    .action(async (name: string, newValue: string) => {
      const vault = await getVault();
      const existing = vault.store.getSecretByName(name.toUpperCase());

      if (!existing) {
        console.error(`\x1b[31m✕\x1b[0m Secret "${name.toUpperCase()}" not found`);
        process.exit(1);
      }

      try {
        await vault.store.rotateSecret(existing.secret.vault_ref, newValue);

        vault.audit.log({
          action: 'secret_rotated',
          vault_ref: existing.secret.vault_ref,
          detail: JSON.stringify({ name: name.toUpperCase() }),
        });

        console.log(`\x1b[32m✓\x1b[0m Secret rotated: ${name.toUpperCase()}`);
        console.log(`  ref: \x1b[2m${existing.secret.vault_ref}\x1b[0m`);
      } catch (err) {
        console.error(`\x1b[31m✕\x1b[0m ${(err as Error).message}`);
        process.exit(1);
      }
    });
}

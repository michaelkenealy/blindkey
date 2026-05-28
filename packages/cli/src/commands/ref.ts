import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerRefCommand(program: Command, getVault: () => Promise<LocalVault>) {
  const ref = program
    .command('ref')
    .description('Manage named references (bk://<name> → vault_ref)');

  ref
    .command('list')
    .alias('ls')
    .description('List all named refs')
    .action(async () => {
      const vault = await getVault();
      const refs = await vault.store.listRefs();

      if (refs.length === 0) {
        console.log('No named refs. Add one with: bk ref add <name> <vault-ref> <provider>');
        return;
      }

      console.log(
        `\x1b[2m${'NAME'.padEnd(24)}${'PROVIDER'.padEnd(16)}${'VAULT REF'}\x1b[0m`
      );
      console.log('\x1b[2m' + '─'.repeat(72) + '\x1b[0m');

      for (const r of refs) {
        console.log(
          `${r.name.padEnd(24)}${r.provider.padEnd(16)}\x1b[2m${r.vault_ref}\x1b[0m`
        );
      }

      console.log(`\n\x1b[2m${refs.length} ref${refs.length === 1 ? '' : 's'}\x1b[0m`);
    });

  ref
    .command('add <name> <vault-ref> <provider>')
    .description('Add or update a named ref (e.g. bk ref add openai-prod bk://openai-abc123 openai)')
    .action(async (name: string, vaultRef: string, provider: string) => {
      const vault = await getVault();
      await vault.store.setRef(name, vaultRef, provider);
      console.log(`\x1b[32m✓\x1b[0m Ref "${name}" → ${vaultRef} (${provider})`);
    });

  ref
    .command('rm <name>')
    .description('Remove a named ref')
    .action(async (name: string) => {
      const vault = await getVault();
      const removed = await vault.store.deleteRef(name);
      if (removed) {
        console.log(`\x1b[32m✓\x1b[0m Removed ref "${name}"`);
      } else {
        console.error(`\x1b[31m✗\x1b[0m Ref "${name}" not found`);
        process.exit(1);
      }
    });

  // Default action: list
  ref.action(async () => {
    const vault = await getVault();
    const refs = await vault.store.listRefs();

    if (refs.length === 0) {
      console.log('No named refs. Add one with: bk ref add <name> <vault-ref> <provider>');
      return;
    }

    console.log(
      `\x1b[2m${'NAME'.padEnd(24)}${'PROVIDER'.padEnd(16)}${'VAULT REF'}\x1b[0m`
    );
    console.log('\x1b[2m' + '─'.repeat(72) + '\x1b[0m');

    for (const r of refs) {
      console.log(
        `${r.name.padEnd(24)}${r.provider.padEnd(16)}\x1b[2m${r.vault_ref}\x1b[0m`
      );
    }

    console.log(`\n\x1b[2m${refs.length} ref${refs.length === 1 ? '' : 's'}\x1b[0m`);
  });
}

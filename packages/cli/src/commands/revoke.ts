import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerRevokeCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('revoke [session-id]')
    .description('Revoke a session or lock all filesystem grants')
    .option('-a, --all', 'Revoke all — remove all filesystem grants')
    .action(async (_sessionId: string | undefined, opts: { all?: boolean }) => {
      const vault = await getVault();

      if (opts.all) {
        const grants = vault.grants.getAll();
        for (const grant of grants) {
          vault.grants.remove(grant.path);
        }

        vault.audit.log({
          action: 'grants_revoked_all',
          detail: JSON.stringify({ count: grants.length }),
        });

        console.log(`\x1b[32m✓\x1b[0m All filesystem grants revoked (${grants.length} removed)`);
        return;
      }

      // In local mode, session revocation = lock all grants.
      console.log('\x1b[2mLocal mode: use \x1b[0m\x1b[1mbk revoke --all\x1b[0m\x1b[2m to remove all filesystem grants.\x1b[0m');
      console.log('Use \x1b[1mbk lock <path>\x1b[0m to revoke a specific path.');
    });
}

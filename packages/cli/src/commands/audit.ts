import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerAuditCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('audit')
    .description('Show recent audit log entries')
    .option('-n, --tail <count>', 'Number of entries to show', '20')
    .action(async (opts: { tail: string }) => {
      const vault = await getVault();
      const limit = parseInt(opts.tail, 10);
      const entries = vault.audit.recent(limit);
      const total = vault.audit.count();

      if (entries.length === 0) {
        console.log('No audit entries yet.');
        return;
      }

      console.log(
        `\x1b[2m${'TIME'.padEnd(22)}${'ACTION'.padEnd(18)}${'STATUS'.padEnd(10)}${'DETAIL'}\x1b[0m`
      );
      console.log('\x1b[2m' + '\u2500'.repeat(80) + '\x1b[0m');

      // Reverse so oldest is first (entries come DESC from query)
      for (const e of entries.reverse()) {
        const time = e.created_at.padEnd(22);
        const action = e.action.padEnd(18);
        const granted = e.granted === null ? '\x1b[2m\u2014\x1b[0m'.padEnd(10)
          : e.granted === 1 ? '\x1b[32mallowed\x1b[0m'.padEnd(19) // +9 for ANSI codes
          : '\x1b[31mblocked\x1b[0m'.padEnd(19);

        let detail = '';
        if (e.vault_ref) detail += e.vault_ref + ' ';
        if (e.path) detail += e.path + ' ';
        if (e.blocking_rule) detail += `[${e.blocking_rule}] `;
        if (e.detail) {
          try {
            const parsed = JSON.parse(e.detail);
            detail += typeof parsed === 'string' ? parsed : JSON.stringify(parsed);
          } catch {
            detail += e.detail;
          }
        }

        console.log(`${time}${action}${granted}${detail.trim()}`);
      }

      console.log(`\n\x1b[2mShowing ${entries.length} of ${total} entries\x1b[0m`);
    });
}

import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';

export function registerSessionsCommand(program: Command, _getVault: () => Promise<LocalVault>) {
  program
    .command('sessions')
    .description('List active agent sessions')
    .action(async () => {
      // In local mode, sessions are managed by the agent runtime (OpenClaw, MCP host).
      // BlindKey local vault doesn't track sessions — it's stateless.
      console.log('\x1b[2mSessions are managed by the agent runtime.\x1b[0m');
      console.log('Use \x1b[1mbk audit\x1b[0m to see recent agent activity.');
      console.log('Use \x1b[1mbk revoke --all\x1b[0m to lock all filesystem grants.');
    });
}

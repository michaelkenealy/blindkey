import { resolve } from 'node:path';
import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import type { FsPermission } from '@blindkey/core';

export function registerUnlockCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('unlock <path>')
    .description('Grant agent access to a filesystem path')
    .option('-p, --permission <perm>', 'Permission level: read, write, create, delete, list', 'read')
    .option('--no-recursive', 'Do not apply recursively to subdirectories')
    .option('--approval', 'Require human approval for each access')
    .action(async (rawPath: string, opts: {
      permission: string;
      recursive: boolean;
      approval: boolean;
    }) => {
      const vault = await getVault();
      const fullPath = resolve(rawPath);

      const permMap: Record<string, FsPermission[]> = {
        read: ['read', 'list'],
        write: ['read', 'write', 'list'],
        create: ['read', 'write', 'create', 'list'],
        delete: ['read', 'write', 'create', 'delete', 'list'],
        list: ['list'],
      };

      const permissions = permMap[opts.permission];
      if (!permissions) {
        console.error(`\x1b[31m✕\x1b[0m Invalid permission: ${opts.permission}. Use: read, write, create, delete, list`);
        process.exit(1);
      }

      const grant = vault.grants.add({
        path: fullPath,
        permissions,
        recursive: opts.recursive,
        requires_approval: opts.approval,
      });

      vault.audit.log({
        action: 'path_unlocked',
        path: fullPath,
        detail: JSON.stringify({ permissions, recursive: opts.recursive }),
        granted: true,
      });

      const icon = opts.approval ? '\u26a0' : '\u2713';
      const color = opts.approval ? '33' : '32';
      console.log(`\x1b[${color}m${icon}\x1b[0m Unlocked: ${fullPath}`);
      console.log(`  permissions: ${permissions.join(', ')}`);
      console.log(`  recursive: ${opts.recursive}`);
      if (opts.approval) {
        console.log(`  \x1b[33mrequires approval for each access\x1b[0m`);
      }
    });
}

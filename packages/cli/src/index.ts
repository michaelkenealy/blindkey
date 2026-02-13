#!/usr/bin/env node

import { Command } from 'commander';
import { createLocalVault, type LocalVault } from '@blindkey/local-vault';
import { registerAddCommand } from './commands/add.js';
import { registerRmCommand } from './commands/rm.js';
import { registerListCommand } from './commands/list.js';
import { registerUnlockCommand } from './commands/unlock.js';
import { registerLockCommand } from './commands/lock.js';
import { registerAuditCommand } from './commands/audit.js';
import { registerGrantsCommand } from './commands/grants.js';
import { registerRotateCommand } from './commands/rotate.js';
import { registerSessionsCommand } from './commands/sessions.js';
import { registerRevokeCommand } from './commands/revoke.js';
import { registerPolicyCommand } from './commands/policy.js';
import { registerServeCommand } from './commands/serve.js';
import { registerDoctorCommand } from './commands/doctor.js';
import { registerMigrateCommand } from './commands/migrate.js';

const program = new Command();

program
  .name('bk')
  .description('BlindKey — The agent is blind to the key.')
  .version('0.1.0');

// Lazy-init the vault (only when a command actually runs)
let vaultInstance: LocalVault | null = null;
async function getVault(): Promise<LocalVault> {
  if (!vaultInstance) {
    vaultInstance = await createLocalVault();
  }
  return vaultInstance;
}

// Register commands
registerAddCommand(program, getVault);
registerRmCommand(program, getVault);
registerListCommand(program, getVault);
registerUnlockCommand(program, getVault);
registerLockCommand(program, getVault);
registerAuditCommand(program, getVault);
registerGrantsCommand(program, getVault);
registerRotateCommand(program, getVault);
registerSessionsCommand(program, getVault);
registerRevokeCommand(program, getVault);
registerPolicyCommand(program, getVault);
registerServeCommand(program, getVault);
registerDoctorCommand(program, getVault);
registerMigrateCommand(program, getVault);

program.parse();

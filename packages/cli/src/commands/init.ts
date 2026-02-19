import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { readFile, writeFile, copyFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import type { SecretType } from '@blindkey/core';
import {
  GREEN, YELLOW, RED, CYAN, BOLD, DIM, RESET,
  createPrompt, fileExists,
} from '../utils/prompt.js';

const BLINDKEY_DIR = join(homedir(), '.blindkey');
const KEY_FILE = join(BLINDKEY_DIR, 'master.key');
const BACKUP_FILE = join(BLINDKEY_DIR, 'master.key.backup');

const SERVICES: Record<string, { domain: string; type: SecretType }> = {
  stripe: { domain: 'api.stripe.com', type: 'api_key' },
  openai: { domain: 'api.openai.com', type: 'api_key' },
  anthropic: { domain: 'api.anthropic.com', type: 'api_key' },
  github: { domain: 'api.github.com', type: 'oauth_token' },
  aws: { domain: '*.amazonaws.com', type: 'api_key' },
  sendgrid: { domain: 'api.sendgrid.com', type: 'api_key' },
  twilio: { domain: 'api.twilio.com', type: 'basic_auth' },
  slack: { domain: 'slack.com', type: 'oauth_token' },
  custom: { domain: '', type: 'api_key' },
};

export function registerInitCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('init')
    .description('Interactive setup wizard for BlindKey')
    .option('--skip-backup', 'Skip master key backup prompt')
    .option('--mcp', 'Generate MCP configuration for Claude')
    .action(async (opts: { skipBackup?: boolean; mcp?: boolean }) => {
      const prompt = createPrompt();

      console.log(`
${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                             ║
║   ${RESET}${BOLD}BlindKey Setup Wizard${CYAN}                                   ║
║   ${RESET}${DIM}Secure credential management for AI agents${CYAN}               ║
║                                                             ║
╚═══════════════════════════════════════════════════════════╝${RESET}
`);

      // Step 1: Initialize vault
      console.log(`${BOLD}Step 1: Initialize Vault${RESET}\n`);

      let vault: LocalVault;
      try {
        vault = await getVault();
        console.log(`${GREEN}✓${RESET} Vault initialized at ${DIM}${BLINDKEY_DIR}${RESET}\n`);
      } catch (err) {
        console.error(`${RED}✕${RESET} Failed to initialize vault: ${(err as Error).message}`);
        prompt.close();
        process.exit(1);
      }

      // Step 2: Master key backup
      console.log(`${BOLD}Step 2: Backup Master Key${RESET}\n`);

      if (!opts.skipBackup && (await fileExists(KEY_FILE))) {
        const masterKey = (await readFile(KEY_FILE, 'utf-8')).trim();

        console.log(`${YELLOW}!${RESET} ${BOLD}IMPORTANT:${RESET} Your master key encrypts all secrets.`);
        console.log(`  If lost, ${RED}ALL SECRETS ARE UNRECOVERABLE${RESET}.\n`);

        const backup = await prompt.question(
          `  Would you like to:\n` +
            `    [1] Display key to copy manually\n` +
            `    [2] Save backup to ${DIM}${BACKUP_FILE}${RESET}\n` +
            `    [3] Skip (I've already backed it up)\n\n` +
            `  Choice [1/2/3]: `
        );

        if (backup === '1') {
          console.log(`\n  ${BOLD}Master Key:${RESET} ${CYAN}${masterKey}${RESET}`);
          console.log(`  ${DIM}Store this in a password manager or secure location.${RESET}\n`);
          await prompt.question('  Press Enter when you have saved it...');
        } else if (backup === '2') {
          await copyFile(KEY_FILE, BACKUP_FILE);
          console.log(`\n${GREEN}✓${RESET} Backup saved to ${DIM}${BACKUP_FILE}${RESET}`);
          console.log(`  ${DIM}Move this file to a secure location (USB drive, password manager).${RESET}\n`);
        }
        console.log('');
      } else {
        console.log(`${GREEN}✓${RESET} Master key backup skipped\n`);
      }

      // Step 3: Add first secret
      console.log(`${BOLD}Step 3: Add Your First Secret${RESET}\n`);

      const addSecret = await prompt.question(
        `  Would you like to add a secret now? [Y/n]: `
      );

      if (addSecret.toLowerCase() !== 'n') {
        console.log(`\n  Available services:`);
        const serviceList = Object.keys(SERVICES);
        serviceList.forEach((s, i) => {
          const info = SERVICES[s];
          const domain = info.domain || 'you specify';
          console.log(`    [${i + 1}] ${s} (${DIM}${domain}${RESET})`);
        });

        const serviceChoice = await prompt.question(`\n  Service [1-${serviceList.length}]: `);
        const serviceIndex = parseInt(serviceChoice, 10) - 1;
        const serviceName =
          serviceIndex >= 0 && serviceIndex < serviceList.length
            ? serviceList[serviceIndex]
            : 'custom';

        const service = SERVICES[serviceName];

        let name = serviceName.toUpperCase() + '_API_KEY';
        const customName = await prompt.question(
          `  Secret name [${name}]: `
        );
        if (customName.trim()) {
          name = customName.trim().toUpperCase();
        }

        let domain = service.domain;
        if (!domain || serviceName === 'custom') {
          domain = await prompt.question(`  Allowed domain (e.g., api.example.com): `);
        }

        console.log(`\n  Enter your secret value (hidden):`);
        const value = await prompt.questionHidden('  > ');

        if (!value.trim()) {
          console.log(`\n${YELLOW}!${RESET} No secret value provided. Skipping.\n`);
        } else {
          try {
            const { vaultRef } = await vault.store.storeSecret({
              user_id: 'local',
              name,
              service: serviceName,
              secret_type: service.type,
              plaintext_value: value,
              allowed_domains: domain ? [domain] : undefined,
              injection_ttl_seconds: 1800,
            });

            vault.audit.log({
              action: 'secret_added',
              vault_ref: vaultRef,
              detail: JSON.stringify({ name, service: serviceName, via: 'init_wizard' }),
            });

            console.log(`\n${GREEN}✓${RESET} Secret added: ${BOLD}${name}${RESET}`);
            console.log(`  ref: ${DIM}${vaultRef}${RESET}`);
            if (domain) {
              console.log(`  domain: ${domain}\n`);
            }
          } catch (err) {
            console.error(`\n${RED}✕${RESET} ${(err as Error).message}\n`);
          }
        }
      }

      // Step 4: MCP Configuration
      if (opts.mcp) {
        console.log(`${BOLD}Step 4: Claude MCP Configuration${RESET}\n`);

        const mcpConfig = {
          mcpServers: {
            blindkey: {
              command: 'bk',
              args: ['serve', '--mcp'],
              env: {},
            },
          },
        };

        console.log(`  Add this to your Claude Desktop config:\n`);
        console.log(`${DIM}${JSON.stringify(mcpConfig, null, 2)}${RESET}\n`);

        const saveMcp = await prompt.question(
          `  Save to ${DIM}blindkey-mcp-config.json${RESET}? [Y/n]: `
        );

        if (saveMcp.toLowerCase() !== 'n') {
          await writeFile('blindkey-mcp-config.json', JSON.stringify(mcpConfig, null, 2));
          console.log(`\n${GREEN}✓${RESET} Config saved to ${DIM}blindkey-mcp-config.json${RESET}\n`);
        }
      }

      // Summary
      console.log(`${BOLD}Setup Complete!${RESET}\n`);

      console.log(`  ${CYAN}Quick commands:${RESET}`);
      console.log(`    ${DIM}bk list${RESET}          - View all secrets`);
      console.log(`    ${DIM}bk add NAME VALUE${RESET} - Add a new secret`);
      console.log(`    ${DIM}bk unlock ./path${RESET}  - Grant filesystem access`);
      console.log(`    ${DIM}bk doctor${RESET}        - Check setup health`);
      console.log(`    ${DIM}bk serve${RESET}         - Start local API server`);
      console.log(`    ${DIM}bk serve --mcp${RESET}   - Start MCP server for Claude\n`);

      console.log(`  ${CYAN}Documentation:${RESET}`);
      console.log(`    ${DIM}https://github.com/michaelkenealy/blindkey${RESET}\n`);

      prompt.close();
    });
}

import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { readFile, writeFile, copyFile } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';
import { randomBytes } from 'node:crypto';
import type { SecretType } from '@blindkey/core';
import {
  GREEN, YELLOW, RED, CYAN, BOLD, DIM, RESET,
  createPrompt, fileExists,
} from '../utils/prompt.js';
import { writeConfig } from '../utils/config.js';

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

export function registerSetupCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('setup')
    .description('Guided setup wizard — choose Docker or Local mode')
    .action(async () => {
      const prompt = createPrompt();

      console.log(`
${BOLD}${CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                             ║
║   ${RESET}${BOLD}BlindKey Setup${CYAN}                                          ║
║   ${RESET}${DIM}Secure credential management for AI agents${CYAN}               ║
║                                                             ║
╚═══════════════════════════════════════════════════════════╝${RESET}
`);

      // ── Step 1: Mode Selection ──

      console.log(`${BOLD}Step 1: Choose Your Mode${RESET}\n`);
      console.log(`  ${CYAN}[1]${RESET} ${BOLD}Local${RESET}  — SQLite, single-user, no Docker required`);
      console.log(`      ${DIM}Best for personal use and development.${RESET}`);
      console.log(`  ${CYAN}[2]${RESET} ${BOLD}Docker${RESET} — PostgreSQL, multi-user, Docker required`);
      console.log(`      ${DIM}Best for teams and production deployments.${RESET}\n`);

      const modeChoice = await prompt.question('  Mode [1/2]: ');
      const mode = modeChoice === '2' ? 'docker' : 'local';

      console.log(`\n${GREEN}✓${RESET} Selected: ${BOLD}${mode}${RESET} mode\n`);

      if (mode === 'local') {
        await localSetup(prompt, getVault);
      } else {
        await dockerSetup(prompt);
      }

      // ── Write config ──

      await writeConfig({
        mode,
        version: 1,
        created_at: new Date().toISOString(),
      });
      console.log(`${GREEN}✓${RESET} Config saved to ${DIM}${join(BLINDKEY_DIR, 'config.json')}${RESET}\n`);

      // ── Summary ──

      console.log(`${BOLD}Setup Complete!${RESET}\n`);

      if (mode === 'local') {
        console.log(`  ${CYAN}Quick start:${RESET}`);
        console.log(`    ${DIM}bk list${RESET}          - View all secrets`);
        console.log(`    ${DIM}bk add NAME VALUE${RESET} - Add a new secret`);
        console.log(`    ${DIM}bk unlock ./path${RESET}  - Grant filesystem access`);
        console.log(`    ${DIM}bk doctor${RESET}        - Check setup health`);
        console.log(`    ${DIM}bk serve${RESET}         - Start MCP server\n`);
      } else {
        console.log(`  ${CYAN}Quick start:${RESET}`);
        console.log(`    ${DIM}docker compose up -d${RESET}  - Start services`);
        console.log(`    ${DIM}npm run dev${RESET}           - Start API server`);
        console.log(`    ${DIM}npm run dev${RESET}           - Start dashboard (in packages/dashboard)\n`);
      }

      console.log(`  ${CYAN}Documentation:${RESET}`);
      console.log(`    ${DIM}https://github.com/michaelkenealy/blindkey${RESET}\n`);

      prompt.close();
    });
}

// ═══════════════════════════════════════════════════════════════
// LOCAL MODE SETUP
// ═══════════════════════════════════════════════════════════════

async function localSetup(
  prompt: ReturnType<typeof createPrompt>,
  getVault: () => Promise<LocalVault>,
) {
  // Initialize vault
  console.log(`${BOLD}Step 2: Initialize Vault${RESET}\n`);

  let vault: LocalVault;
  try {
    vault = await getVault();
    console.log(`${GREEN}✓${RESET} Vault initialized at ${DIM}${BLINDKEY_DIR}${RESET}\n`);
  } catch (err) {
    console.error(`${RED}✕${RESET} Failed to initialize vault: ${(err as Error).message}`);
    prompt.close();
    process.exit(1);
  }

  // Master key backup
  console.log(`${BOLD}Step 3: Backup Master Key${RESET}\n`);

  if (await fileExists(KEY_FILE)) {
    const masterKey = (await readFile(KEY_FILE, 'utf-8')).trim();

    console.log(`${YELLOW}!${RESET} ${BOLD}IMPORTANT:${RESET} Your master key encrypts all secrets.`);
    console.log(`  If lost, ${RED}ALL SECRETS ARE UNRECOVERABLE${RESET}.\n`);

    const backup = await prompt.question(
      `  Would you like to:\n` +
        `    [1] Display key to copy manually\n` +
        `    [2] Save backup to ${DIM}${BACKUP_FILE}${RESET}\n` +
        `    [3] Skip (I've already backed it up)\n\n` +
        `  Choice [1/2/3]: `,
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

  // Add first secret
  console.log(`${BOLD}Step 4: Add Your First Secret${RESET}\n`);

  const addSecret = await prompt.question(
    `  Would you like to add a secret now? [Y/n]: `,
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
    const customName = await prompt.question(`  Secret name [${name}]: `);
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
          detail: JSON.stringify({ name, service: serviceName, via: 'setup_wizard' }),
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
}

// ═══════════════════════════════════════════════════════════════
// DOCKER MODE SETUP
// ═══════════════════════════════════════════════════════════════

async function dockerSetup(prompt: ReturnType<typeof createPrompt>) {
  console.log(`${BOLD}Step 2: Database Configuration${RESET}\n`);

  const defaultUrl = 'postgresql://agentvault:agentvault_dev@localhost:5432/agentvault';
  const dbInput = await prompt.question(
    `  DATABASE_URL [${DIM}${defaultUrl}${RESET}]: `,
  );
  const databaseUrl = dbInput.trim() || defaultUrl;
  console.log(`${GREEN}✓${RESET} Database: ${DIM}${databaseUrl}${RESET}\n`);

  // JWT Secret
  console.log(`${BOLD}Step 3: JWT Secret${RESET}\n`);

  let jwtSecret = '';
  while (jwtSecret.length < 32) {
    const genDefault = randomBytes(48).toString('base64url');
    const jwtInput = await prompt.question(
      `  JWT_SECRET (min 32 chars) [${DIM}auto-generate${RESET}]: `,
    );
    jwtSecret = jwtInput.trim() || genDefault;
    if (jwtSecret.length < 32) {
      console.log(`  ${RED}✕${RESET} Must be at least 32 characters. Try again.\n`);
    }
  }
  console.log(`${GREEN}✓${RESET} JWT secret configured\n`);

  // Vault Master Key
  console.log(`${BOLD}Step 4: Vault Master Key${RESET}\n`);
  console.log(`  ${DIM}This 32-byte hex key encrypts all secrets at rest.${RESET}`);

  const genKey = randomBytes(32).toString('hex');
  const keyInput = await prompt.question(
    `  VAULT_MASTER_KEY [${DIM}auto-generate${RESET}]: `,
  );
  const masterKey = keyInput.trim() || genKey;
  console.log(`${GREEN}✓${RESET} Master key configured\n`);

  if (!keyInput.trim()) {
    console.log(`${YELLOW}!${RESET} ${BOLD}IMPORTANT:${RESET} Your auto-generated master key:`);
    console.log(`  ${CYAN}${masterKey}${RESET}`);
    console.log(`  ${DIM}Store this in a password manager. If lost, ALL SECRETS ARE UNRECOVERABLE.${RESET}\n`);
    await prompt.question('  Press Enter when you have saved it...');
    console.log('');
  }

  // Write .env
  console.log(`${BOLD}Step 5: Write Configuration${RESET}\n`);

  const envContent = `# BlindKey Environment Configuration (generated by bk setup)

# Master encryption key for secrets (32 bytes, hex-encoded)
VAULT_MASTER_KEY=${masterKey}

# PostgreSQL
DATABASE_URL=${databaseUrl}

# Redis (required for proxy)
REDIS_URL=redis://localhost:6379

# Server ports
PROXY_PORT=3100
API_PORT=3200
FS_PROXY_PORT=3300

# JWT secret for user auth
JWT_SECRET=${jwtSecret}

# CORS controls
CORS_ALLOWED_ORIGINS=http://localhost:3400
CORS_ALLOW_ALL=false

# Egress hardening
BLINDKEY_ALLOW_INSECURE_HTTP=false
BLINDKEY_ALLOW_PRIVATE_EGRESS=false
`;

  const envPath = join(process.cwd(), '.env');
  if (await fileExists(envPath)) {
    const overwrite = await prompt.question(
      `  ${YELLOW}!${RESET} .env already exists. Overwrite? [y/N]: `,
    );
    if (overwrite.toLowerCase() !== 'y') {
      console.log(`  ${DIM}Skipped .env — keeping existing file.${RESET}\n`);
      return;
    }
  }

  await writeFile(envPath, envContent);
  console.log(`${GREEN}✓${RESET} .env written to ${DIM}${envPath}${RESET}\n`);

  // Docker compose
  const runDocker = await prompt.question(
    `  Run ${DIM}docker compose up -d${RESET} now? [Y/n]: `,
  );
  if (runDocker.toLowerCase() !== 'n') {
    console.log(`\n  ${DIM}Starting Docker services...${RESET}`);
    const { execSync } = await import('node:child_process');
    try {
      execSync('docker compose up -d', { stdio: 'inherit', cwd: process.cwd() });
      console.log(`\n${GREEN}✓${RESET} Docker services started\n`);
    } catch {
      console.log(`\n${YELLOW}!${RESET} Docker compose failed. Start manually with: ${DIM}docker compose up -d${RESET}\n`);
    }
  }
}

import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import type { SecretType } from '@blindkey/core';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';

interface EnvSecret {
  name: string;
  value: string;
  service: string;
  domains: string[];
}

// Well-known API key patterns and their service/domain mappings
const SERVICE_PATTERNS: Array<{
  pattern: RegExp;
  service: string;
  domains: string[];
}> = [
  { pattern: /^sk_(live|test)_/i, service: 'stripe', domains: ['api.stripe.com'] },
  { pattern: /^pk_(live|test)_/i, service: 'stripe', domains: ['api.stripe.com'] },
  { pattern: /^ghp_/i, service: 'github', domains: ['api.github.com'] },
  { pattern: /^gho_/i, service: 'github', domains: ['api.github.com'] },
  { pattern: /^github_pat_/i, service: 'github', domains: ['api.github.com'] },
  { pattern: /^sk-/i, service: 'openai', domains: ['api.openai.com'] },
  { pattern: /^sk-proj-/i, service: 'openai', domains: ['api.openai.com'] },
  { pattern: /^xoxb-/i, service: 'slack', domains: ['slack.com', 'api.slack.com'] },
  { pattern: /^xoxp-/i, service: 'slack', domains: ['slack.com', 'api.slack.com'] },
  { pattern: /^SG\./i, service: 'sendgrid', domains: ['api.sendgrid.com'] },
  { pattern: /^AKIA/i, service: 'aws', domains: ['*.amazonaws.com'] },
  { pattern: /^ya29\./i, service: 'google', domains: ['*.googleapis.com'] },
  { pattern: /^AIza/i, service: 'google', domains: ['*.googleapis.com'] },
  { pattern: /^whsec_/i, service: 'stripe', domains: ['api.stripe.com'] },
  { pattern: /^sk-ant-/i, service: 'anthropic', domains: ['api.anthropic.com'] },
];

function detectService(name: string, value: string): { service: string; domains: string[] } {
  // Check value against known patterns
  for (const { pattern, service, domains } of SERVICE_PATTERNS) {
    if (pattern.test(value)) {
      return { service, domains };
    }
  }

  // Check name for hints
  const lower = name.toLowerCase();
  if (lower.includes('stripe')) return { service: 'stripe', domains: ['api.stripe.com'] };
  if (lower.includes('github')) return { service: 'github', domains: ['api.github.com'] };
  if (lower.includes('openai')) return { service: 'openai', domains: ['api.openai.com'] };
  if (lower.includes('slack')) return { service: 'slack', domains: ['slack.com', 'api.slack.com'] };
  if (lower.includes('aws')) return { service: 'aws', domains: ['*.amazonaws.com'] };
  if (lower.includes('anthropic')) return { service: 'anthropic', domains: ['api.anthropic.com'] };

  return { service: 'custom', domains: [] };
}

function parseEnvFile(content: string): EnvSecret[] {
  const secrets: EnvSecret[] = [];
  const lines = content.split('\n');

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comments and empty lines
    if (!trimmed || trimmed.startsWith('#')) continue;

    const match = trimmed.match(/^([A-Za-z_][A-Za-z0-9_]*)=(.+)$/);
    if (!match) continue;

    const [, name, rawValue] = match;
    // Strip surrounding quotes
    const value = rawValue.replace(/^["']|["']$/g, '');

    // Only include values that look like secrets (long enough, not a boolean/number)
    if (value.length < 8) continue;
    if (/^(true|false|yes|no|\d+)$/i.test(value)) continue;

    // Skip common non-secret env vars
    const skipNames = ['NODE_ENV', 'PORT', 'HOST', 'DATABASE_URL', 'DB_HOST', 'DB_PORT',
      'DB_NAME', 'DB_USER', 'LOG_LEVEL', 'DEBUG', 'HOME', 'PATH', 'SHELL'];
    if (skipNames.includes(name.toUpperCase())) continue;

    const { service, domains } = detectService(name, value);
    secrets.push({ name: name.toUpperCase(), value, service, domains });
  }

  return secrets;
}

export function registerMigrateCommand(program: Command, getVault: () => Promise<LocalVault>) {
  const migrate = program
    .command('migrate')
    .description('Migrate secrets from other sources into BlindKey');

  migrate
    .command('openclaw')
    .description('Migrate secrets from .env file into BlindKey vault')
    .option('--auto', 'Auto-detect services and domains from key patterns')
    .option('--env <path>', 'Path to .env file', '.env')
    .option('--dry-run', 'Show what would be imported without importing')
    .action(async (opts: { auto?: boolean; env: string; dryRun?: boolean }) => {
      const envPath = resolve(opts.env);

      let content: string;
      try {
        content = await readFile(envPath, 'utf-8');
      } catch {
        console.error(`\x1b[31m✕\x1b[0m Cannot read ${envPath}`);
        console.error('  Make sure the .env file exists at the specified path.');
        process.exit(1);
      }

      const secrets = parseEnvFile(content);

      if (secrets.length === 0) {
        console.log('\x1b[2mNo importable secrets found in .env file.\x1b[0m');
        return;
      }

      console.log(`\x1b[1mFound ${secrets.length} secret(s) in ${opts.env}:\x1b[0m\n`);

      for (const s of secrets) {
        const domainStr = s.domains.length > 0
          ? `\x1b[32m${s.domains.join(', ')}\x1b[0m`
          : '\x1b[33mno domain restriction\x1b[0m';
        console.log(`  ${s.name}`);
        console.log(`    service: ${s.service}  domains: ${domainStr}`);
        console.log(`    value: ${s.value.slice(0, 8)}${'*'.repeat(Math.min(s.value.length - 8, 20))}`);
        console.log('');
      }

      if (opts.dryRun) {
        console.log('\x1b[2m(dry run — no secrets imported)\x1b[0m');
        return;
      }

      const vault = await getVault();
      let imported = 0;
      let skipped = 0;

      for (const s of secrets) {
        try {
          const { vaultRef } = await vault.store.storeSecret({
            user_id: 'local',
            name: s.name,
            service: s.service,
            secret_type: 'api_key' as SecretType,
            plaintext_value: s.value,
            allowed_domains: s.domains.length > 0 ? s.domains : undefined,
            injection_ttl_seconds: 3600,
          });

          vault.audit.log({
            action: 'secret_added',
            vault_ref: vaultRef,
            detail: JSON.stringify({ name: s.name, source: 'env_migration' }),
          });

          console.log(`  \x1b[32m✓\x1b[0m ${s.name} → ${vaultRef}`);
          imported++;
        } catch (err) {
          const msg = (err as Error).message;
          if (msg.includes('UNIQUE constraint')) {
            console.log(`  \x1b[33m⊘\x1b[0m ${s.name} — already exists, skipping`);
            skipped++;
          } else {
            console.error(`  \x1b[31m✕\x1b[0m ${s.name} — ${msg}`);
          }
        }
      }

      console.log(`\n\x1b[32m${imported} imported\x1b[0m, ${skipped} skipped`);

      if (imported > 0) {
        console.log('\nNext steps:');
        console.log('  1. Verify with: \x1b[1mbk list\x1b[0m');
        console.log('  2. Remove secrets from .env (they\'re now in the vault)');
        console.log('  3. Update your agent to use bk:// references instead');
      }
    });
}

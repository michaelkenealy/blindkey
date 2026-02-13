import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { resolveTTL, type SecretType } from '@blindkey/core';

export function registerAddCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('add <name> <value>')
    .description('Add a secret to the vault')
    .option('-s, --service <service>', 'Service name (e.g., stripe, github)', 'custom')
    .option('-t, --type <type>', 'Secret type: api_key, oauth_token, basic_auth, custom_header, query_param', 'api_key')
    .option('-d, --domain <domains...>', 'Allowed domains (e.g., api.stripe.com *.github.com)')
    .option('--ttl <tier>', 'Injection TTL: high (15m), medium (60m), low (4h), or seconds', 'medium')
    .action(async (name: string, value: string, opts: {
      service: string;
      type: string;
      domain?: string[];
      ttl: string;
    }) => {
      const vault = await getVault();
      const ttlSeconds = resolveTTL(opts.ttl);

      try {
        const { vaultRef } = await vault.store.storeSecret({
          user_id: 'local',
          name: name.toUpperCase(),
          service: opts.service,
          secret_type: opts.type as SecretType,
          plaintext_value: value,
          allowed_domains: opts.domain,
          injection_ttl_seconds: ttlSeconds,
        });

        vault.audit.log({
          action: 'secret_added',
          vault_ref: vaultRef,
          detail: JSON.stringify({ name, service: opts.service }),
        });

        console.log(`\x1b[32m✓\x1b[0m Secret added: ${name.toUpperCase()}`);
        console.log(`  ref: \x1b[2m${vaultRef}\x1b[0m`);
        if (opts.domain) {
          console.log(`  domains: ${opts.domain.join(', ')}`);
        }
      } catch (err) {
        const msg = (err as Error).message;
        if (msg.includes('UNIQUE constraint')) {
          console.error(`\x1b[31m✕\x1b[0m Secret "${name.toUpperCase()}" already exists. Remove it first with: bk rm ${name}`);
        } else {
          console.error(`\x1b[31m✕\x1b[0m ${msg}`);
        }
        process.exit(1);
      }
    });
}

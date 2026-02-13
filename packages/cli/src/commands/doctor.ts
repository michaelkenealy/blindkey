import type { Command } from 'commander';
import type { LocalVault } from '@blindkey/local-vault';
import { access, stat } from 'node:fs/promises';
import { join } from 'node:path';
import { homedir } from 'node:os';

const BLINDKEY_DIR = join(homedir(), '.blindkey');

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

export function registerDoctorCommand(program: Command, getVault: () => Promise<LocalVault>) {
  program
    .command('doctor')
    .description('Check BlindKey setup and diagnose issues')
    .action(async () => {
      console.log('\x1b[1mBlindKey Doctor\x1b[0m\n');
      let issues = 0;

      // 1. Check ~/.blindkey directory
      const dirExists = await fileExists(BLINDKEY_DIR);
      if (dirExists) {
        console.log(`  \x1b[32m✓\x1b[0m Config directory: ${BLINDKEY_DIR}`);
      } else {
        console.log(`  \x1b[33m!\x1b[0m Config directory not found (will be created on first use)`);
      }

      // 2. Check master key
      const keyPath = join(BLINDKEY_DIR, 'master.key');
      const keyExists = await fileExists(keyPath);
      if (keyExists) {
        const keyStat = await stat(keyPath);
        const mode = (keyStat.mode & 0o777).toString(8);
        console.log(`  \x1b[32m✓\x1b[0m Master key: ${keyPath} (mode: ${mode})`);
        if (process.platform !== 'win32' && mode !== '600') {
          console.log(`    \x1b[33m!\x1b[0m Permissions should be 600 (owner read/write only)`);
          issues++;
        }
      } else if (dirExists) {
        console.log(`  \x1b[33m!\x1b[0m Master key not found (will be generated on first use)`);
      }

      // 3. Check database
      const dbPath = join(BLINDKEY_DIR, 'vault.db');
      const dbExists = await fileExists(dbPath);
      if (dbExists) {
        const dbStat = await stat(dbPath);
        const sizeKB = (dbStat.size / 1024).toFixed(1);
        console.log(`  \x1b[32m✓\x1b[0m Database: ${dbPath} (${sizeKB} KB)`);
      } else if (dirExists) {
        console.log(`  \x1b[33m!\x1b[0m Database not found (will be created on first use)`);
      }

      // 4. Try to initialize vault
      try {
        const vault = await getVault();
        console.log(`  \x1b[32m✓\x1b[0m Vault initialization: OK`);

        // 5. Count secrets and grants
        const secrets = await vault.store.listSecrets([]);
        console.log(`  \x1b[32m✓\x1b[0m Secrets stored: ${secrets.length}`);

        const grants = vault.grants.getAll();
        console.log(`  \x1b[32m✓\x1b[0m Filesystem grants: ${grants.length}`);

        // 6. Check for secrets without domain allowlists
        const noDomains = secrets.filter(s => !s.allowed_domains || s.allowed_domains.length === 0);
        if (noDomains.length > 0) {
          console.log(`\n  \x1b[33m!\x1b[0m ${noDomains.length} secret(s) have no domain allowlist:`);
          for (const s of noDomains) {
            console.log(`    - ${s.name} (any domain allowed)`);
          }
          console.log(`    Consider adding domains: bk add --domain api.example.com`);
          issues++;
        }

        // 7. Check audit log
        const recentAudit = vault.audit.recent(1);
        if (recentAudit.length > 0) {
          console.log(`  \x1b[32m✓\x1b[0m Audit log: active`);
        } else {
          console.log(`  \x1b[2m○\x1b[0m Audit log: empty (no activity yet)`);
        }
      } catch (err) {
        console.log(`  \x1b[31m✕\x1b[0m Vault initialization failed: ${(err as Error).message}`);
        issues++;
      }

      // 8. Check Node.js version
      const nodeVersion = process.version;
      const major = parseInt(nodeVersion.slice(1).split('.')[0], 10);
      if (major >= 18) {
        console.log(`  \x1b[32m✓\x1b[0m Node.js: ${nodeVersion}`);
      } else {
        console.log(`  \x1b[31m✕\x1b[0m Node.js ${nodeVersion} — BlindKey requires Node.js 18+`);
        issues++;
      }

      // Summary
      console.log('');
      if (issues === 0) {
        console.log('\x1b[32mAll checks passed.\x1b[0m Ready to use BlindKey.');
      } else {
        console.log(`\x1b[33m${issues} issue(s) found.\x1b[0m See above for details.`);
      }
    });
}

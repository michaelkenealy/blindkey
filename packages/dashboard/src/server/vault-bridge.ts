#!/usr/bin/env node

/**
 * BlindKey Vault Bridge — lightweight Express server that exposes
 * the local SQLite vault (secrets, grants, audit, policies) to the
 * React dashboard via HTTP endpoints on port 3401.
 *
 * No authentication — runs locally for single-user mode.
 */

import express from 'express';
import { createLocalVault, type LocalVault } from '@blindkey/local-vault';
import type { FilesystemGrantInput, FsPolicyRule } from '@blindkey/core';

const app = express();
app.use(express.json());

let vault: LocalVault;

// ── Secrets ──

app.get('/api/secrets', async (_req, res) => {
  try {
    const secrets = await vault.store.listSecrets([]);
    res.json({ secrets });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.post('/api/secrets', async (req, res) => {
  try {
    const { name, value, service, secret_type, domain } = req.body;
    const result = await vault.store.storeSecret({
      user_id: 'local',
      name,
      service: service ?? 'Custom',
      secret_type: secret_type ?? 'api_key',
      plaintext_value: value,
      allowed_domains: domain ? [domain] : undefined,
    });
    res.json({ vault_ref: result.vaultRef });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.delete('/api/secrets/:vaultRef', async (req, res) => {
  try {
    await vault.store.deleteSecret(req.params.vaultRef);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ── Filesystem Grants ──

app.get('/api/grants', (_req, res) => {
  try {
    const grants = vault.grants.getAll();
    res.json({ grants });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.post('/api/grants', (req, res) => {
  try {
    const { path, permissions, recursive, requires_approval } = req.body;
    const input: FilesystemGrantInput = {
      path,
      permissions: permissions ?? ['read'],
      recursive: recursive !== false,
      requires_approval: requires_approval ?? false,
    };
    const grant = vault.grants.add(input);
    res.json({ grant });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.delete('/api/grants/:path(*)', (req, res) => {
  try {
    const removed = vault.grants.remove(req.params.path);
    res.json({ success: removed });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ── Audit Log ──

app.get('/api/audit', (req, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 100;
    const entries = vault.audit.recent(limit);
    res.json({ entries });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.get('/api/audit/count', (_req, res) => {
  try {
    const count = vault.audit.count();
    res.json({ count });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ── Content Policies ──

app.get('/api/policies', (_req, res) => {
  try {
    const policies = vault.policies.getAll();
    res.json({ policies });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.post('/api/policies', (req, res) => {
  try {
    const rule = req.body as FsPolicyRule;
    const policy = vault.policies.add(rule);
    res.json({ policy });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.delete('/api/policies/:id', (req, res) => {
  try {
    const removed = vault.policies.remove(req.params.id);
    res.json({ success: removed });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

app.patch('/api/policies/:id', (req, res) => {
  try {
    const { enabled } = req.body;
    vault.policies.toggle(req.params.id, enabled);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: (err as Error).message });
  }
});

// ── Start ──

async function main() {
  vault = await createLocalVault();

  const port = parseInt(process.env.BRIDGE_PORT ?? '3401');
  app.listen(port, () => {
    console.log(`BlindKey vault bridge running on http://localhost:${port}`);
    console.log(`Vault: ~/.blindkey/vault.db`);
  });
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});

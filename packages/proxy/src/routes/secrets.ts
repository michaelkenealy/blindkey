import type { FastifyInstance } from 'fastify';
import type { VaultBackend } from '@blindkey/core';

export function registerSecretsRoutes(app: FastifyInstance, vaultBackend: VaultBackend) {
  // List available vault refs for current session
  app.get('/v1/proxy/secrets', async (request, reply) => {
    const session = request.session!;
    const secrets = await vaultBackend.listSecrets(session.allowed_secrets);

    return reply.send({
      secrets: secrets.map((s) => ({
        vault_ref: s.vault_ref,
        name: s.name,
        service: s.service,
        secret_type: s.secret_type,
        allowed_domains: s.allowed_domains,
      })),
    });
  });
}

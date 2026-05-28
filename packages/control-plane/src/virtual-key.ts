import { randomBytes } from 'node:crypto';
import type { PrincipalType, VirtualKey } from './types.js';

export function generateVirtualKeyPrefix(environment: string): string {
  const env = environment.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '') || 'default';
  return `bk_${env}_${randomBytes(8).toString('base64url')}`;
}

export interface VirtualKeyInput {
  id: string;
  workspaceId: string;
  name: string;
  providerCredentialId: string;
  subjectType: PrincipalType;
  subjectId: string;
  environment: string;
  allowedModels?: string[];
  allowedDomains?: string[];
  policySetIds?: string[];
  budgetIds?: string[];
  createdAt?: Date;
}

export function createVirtualKey(input: VirtualKeyInput): VirtualKey {
  return {
    id: input.id,
    workspaceId: input.workspaceId,
    keyPrefix: generateVirtualKeyPrefix(input.environment),
    name: input.name,
    providerCredentialId: input.providerCredentialId,
    subjectType: input.subjectType,
    subjectId: input.subjectId,
    environment: input.environment,
    allowedModels: input.allowedModels ?? [],
    allowedDomains: input.allowedDomains ?? [],
    policySetIds: input.policySetIds ?? [],
    budgetIds: input.budgetIds ?? [],
    revokedAt: null,
    createdAt: input.createdAt ?? new Date(),
  };
}

export function revokeVirtualKey(virtualKey: VirtualKey, revokedAt: Date = new Date()): VirtualKey {
  return { ...virtualKey, revokedAt };
}

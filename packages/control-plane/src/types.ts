export type WorkspaceTier = 'solo' | 'team' | 'control_centre' | 'enterprise';

export type EnvironmentName = 'local' | 'development' | 'staging' | 'production' | string;

export type PrincipalType = 'user' | 'team' | 'agent' | 'app' | 'service_account';

export type SecretBindingType = 'provider_credential' | 'oauth_token' | 'api_key' | 'custom';

export type BudgetWindow = 'day' | 'week' | 'month' | 'quarter' | 'year';

export type BudgetSubjectType = 'workspace' | 'team' | 'user' | 'agent' | 'app' | 'virtual_key';

export type UsageStatus = 'allowed' | 'denied' | 'error';

export type WorkspaceRole = 'owner' | 'admin' | 'developer' | 'security' | 'billing' | 'viewer' | 'agent';

export type WorkspacePermission =
  | 'workspace.manage'
  | 'members.manage'
  | 'secrets.read_metadata'
  | 'secrets.create'
  | 'secrets.rotate'
  | 'secrets.delete'
  | 'virtual_keys.create'
  | 'virtual_keys.revoke'
  | 'virtual_keys.use'
  | 'budgets.manage'
  | 'usage.view'
  | 'audit.view'
  | 'incidents.manage'
  | 'policies.manage'
  | 'rotations.manage'
  | 'billing.manage';

export interface Workspace {
  id: string;
  name: string;
  tier: WorkspaceTier;
  createdAt: Date;
}

export interface Team {
  id: string;
  workspaceId: string;
  name: string;
  ownerUserId: string;
  createdAt: Date;
}

export interface WorkspaceMember {
  id: string;
  workspaceId: string;
  userId: string;
  email: string;
  roles: WorkspaceRole[];
  teamIds: string[];
  createdAt: Date;
  disabledAt: Date | null;
}

export interface AgentIdentity {
  id: string;
  workspaceId: string;
  name: string;
  ownerUserId: string;
  purpose: string;
  environment: EnvironmentName;
  createdAt: Date;
}

export interface AppIdentity {
  id: string;
  workspaceId: string;
  name: string;
  environment: EnvironmentName;
  ownerUserId: string;
  createdAt: Date;
}

export interface ProviderCredential {
  id: string;
  workspaceId: string;
  vaultRef: string;
  provider: string;
  environment: EnvironmentName;
  bindingType: SecretBindingType;
  allowedDomains: string[];
  createdAt: Date;
  rotatedAt: Date;
}

export interface VirtualKey {
  id: string;
  workspaceId: string;
  keyPrefix: string;
  name: string;
  providerCredentialId: string;
  subjectType: PrincipalType;
  subjectId: string;
  environment: EnvironmentName;
  allowedModels: string[];
  allowedDomains: string[];
  policySetIds: string[];
  budgetIds: string[];
  revokedAt: Date | null;
  createdAt: Date;
}

export interface Budget {
  id: string;
  workspaceId: string;
  subjectType: BudgetSubjectType;
  subjectId: string;
  window: BudgetWindow;
  amountCents: number;
  currency: string;
  hardLimit: boolean;
  createdAt: Date;
}

export interface UsageEvent {
  id: string;
  workspaceId: string;
  virtualKeyId: string;
  provider: string;
  model: string | null;
  costCents: number;
  status: UsageStatus;
  occurredAt: Date;
  metadata?: Record<string, unknown>;
}

export interface BudgetUsageSnapshot {
  budget: Budget;
  spentCents: number;
  remainingCents: number;
  percentUsed: number;
}

export interface ProxyAccessRequest {
  workspaceId: string;
  virtualKey: VirtualKey;
  providerCredential: ProviderCredential;
  url: string;
  method: string;
  model?: string | null;
  projectedCostCents?: number;
  now?: Date;
}

export interface ProxyAccessDecision {
  allowed: boolean;
  reason: string | null;
  checks: string[];
}

export interface RotationPlan {
  id: string;
  workspaceId: string;
  providerCredentialId: string;
  environment: EnvironmentName;
  status: RotationStatus;
  createdByUserId: string;
  createdAt: Date;
  completedAt: Date | null;
}

export type RotationStatus =
  | 'draft'
  | 'new_key_created'
  | 'testing'
  | 'deploying'
  | 'monitoring'
  | 'revoking_old'
  | 'completed'
  | 'failed'
  | 'rolled_back';

export type RotationEvent =
  | 'create_new_key'
  | 'start_test'
  | 'test_passed'
  | 'deploy'
  | 'healthcheck_passed'
  | 'revoke_old'
  | 'complete'
  | 'fail'
  | 'rollback';

export interface RotationTransitionResult {
  plan: RotationPlan;
  allowed: boolean;
  reason: string | null;
}

export interface Incident {
  id: string;
  workspaceId: string;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  status: 'open' | 'contained' | 'resolved';
  createdAt: Date;
  resolvedAt: Date | null;
}

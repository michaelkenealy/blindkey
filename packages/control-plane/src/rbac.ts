import type { WorkspaceMember, WorkspacePermission, WorkspaceRole } from './types.js';

export const ROLE_PERMISSIONS: Record<WorkspaceRole, WorkspacePermission[]> = {
  owner: [
    'workspace.manage',
    'members.manage',
    'secrets.read_metadata',
    'secrets.create',
    'secrets.rotate',
    'secrets.delete',
    'virtual_keys.create',
    'virtual_keys.revoke',
    'virtual_keys.use',
    'budgets.manage',
    'usage.view',
    'audit.view',
    'incidents.manage',
    'policies.manage',
    'rotations.manage',
    'billing.manage',
  ],
  admin: [
    'members.manage',
    'secrets.read_metadata',
    'secrets.create',
    'secrets.rotate',
    'secrets.delete',
    'virtual_keys.create',
    'virtual_keys.revoke',
    'virtual_keys.use',
    'budgets.manage',
    'usage.view',
    'audit.view',
    'incidents.manage',
    'policies.manage',
    'rotations.manage',
  ],
  developer: [
    'secrets.read_metadata',
    'virtual_keys.use',
    'usage.view',
  ],
  security: [
    'secrets.read_metadata',
    'secrets.rotate',
    'virtual_keys.revoke',
    'usage.view',
    'audit.view',
    'incidents.manage',
    'policies.manage',
    'rotations.manage',
  ],
  billing: [
    'budgets.manage',
    'usage.view',
    'billing.manage',
  ],
  viewer: [
    'secrets.read_metadata',
    'usage.view',
    'audit.view',
  ],
  agent: [
    'virtual_keys.use',
  ],
};

export function permissionsForRoles(roles: WorkspaceRole[]): Set<WorkspacePermission> {
  const permissions = new Set<WorkspacePermission>();
  for (const role of roles) {
    for (const permission of ROLE_PERMISSIONS[role]) {
      permissions.add(permission);
    }
  }
  return permissions;
}

export function memberHasPermission(
  member: WorkspaceMember,
  permission: WorkspacePermission,
  workspaceId?: string,
): boolean {
  if (member.disabledAt) return false;
  if (workspaceId && member.workspaceId !== workspaceId) return false;
  return permissionsForRoles(member.roles).has(permission);
}

export function assertMemberPermission(
  member: WorkspaceMember,
  permission: WorkspacePermission,
  workspaceId?: string,
): void {
  if (!memberHasPermission(member, permission, workspaceId)) {
    throw new Error(`Permission denied: ${permission}`);
  }
}

export function canManageMember(actor: WorkspaceMember, target: WorkspaceMember): boolean {
  if (actor.workspaceId !== target.workspaceId) return false;
  if (actor.disabledAt || target.disabledAt) return false;
  if (actor.userId === target.userId) return false;
  return memberHasPermission(actor, 'members.manage', actor.workspaceId);
}

import { describe, expect, it } from 'vitest';
import { assertMemberPermission, canManageMember, memberHasPermission, permissionsForRoles } from './rbac.js';
import type { WorkspaceMember } from './types.js';

function member(roles: WorkspaceMember['roles'], userId = 'user_1'): WorkspaceMember {
  return {
    id: `member_${userId}`,
    workspaceId: 'workspace_1',
    userId,
    email: `${userId}@example.com`,
    roles,
    teamIds: [],
    createdAt: new Date('2026-05-01T00:00:00Z'),
    disabledAt: null,
  };
}

describe('workspace RBAC', () => {
  it('grants owners full commercial control-plane permissions', () => {
    const permissions = permissionsForRoles(['owner']);
    expect(permissions.has('workspace.manage')).toBe(true);
    expect(permissions.has('billing.manage')).toBe(true);
    expect(permissions.has('rotations.manage')).toBe(true);
  });

  it('keeps developers away from secret rotation and billing controls', () => {
    const developer = member(['developer']);
    expect(memberHasPermission(developer, 'virtual_keys.use', 'workspace_1')).toBe(true);
    expect(memberHasPermission(developer, 'secrets.rotate', 'workspace_1')).toBe(false);
    expect(memberHasPermission(developer, 'billing.manage', 'workspace_1')).toBe(false);
    expect(() => assertMemberPermission(developer, 'secrets.rotate', 'workspace_1')).toThrow(/Permission denied/);
  });

  it('blocks disabled members even if they still have roles assigned', () => {
    const disabled = { ...member(['admin']), disabledAt: new Date('2026-05-03T00:00:00Z') };
    expect(memberHasPermission(disabled, 'members.manage', 'workspace_1')).toBe(false);
  });

  it('allows admins to manage other members in the same workspace only', () => {
    const admin = member(['admin'], 'admin_1');
    const target = member(['developer'], 'dev_1');
    const external = { ...member(['developer'], 'dev_2'), workspaceId: 'workspace_2' };

    expect(canManageMember(admin, target)).toBe(true);
    expect(canManageMember(admin, external)).toBe(false);
    expect(canManageMember(admin, admin)).toBe(false);
  });
});

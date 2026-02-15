/**
 * @blindkey/fs-gate
 *
 * Standalone filesystem gating library. Provides path-based permission
 * checking, grant management, and filesystem policy evaluation.
 *
 * Designed for use by Blindkey, Aquaman, OpenClaw-Secure, or any tool
 * that needs to control filesystem access per-session or per-agent.
 */

import { resolve, extname } from 'node:path';

// ── Types ──

export type FsPermission = 'read' | 'write' | 'create' | 'delete' | 'list';
export type FsOperation = 'read' | 'write' | 'create' | 'delete' | 'list' | 'info';

export interface FsGrant {
  /** Unique identifier */
  id: string;
  /** Directory or file path this grant covers */
  path: string;
  /** Allowed permissions on this path */
  permissions: FsPermission[];
  /** Whether grant applies to subdirectories */
  recursive: boolean;
  /** Whether the operation requires human approval */
  requires_approval: boolean;
}

export interface FsGrantInput {
  path: string;
  permissions: FsPermission[];
  recursive?: boolean;
  requires_approval?: boolean;
}

export interface FsAccessCheck {
  granted: boolean;
  grant: FsGrant | null;
  reason: string | null;
}

// ── Policy Types ──

export interface FsBlockPatternsRule {
  type: 'fs_block_patterns';
  patterns: string[];
}

export interface FsSizeLimitRule {
  type: 'fs_size_limit';
  max_read_bytes: number;
  max_write_bytes: number;
}

export interface FsExtensionAllowlistRule {
  type: 'fs_extension_allowlist';
  extensions: string[];
}

export interface FsContentScanRule {
  type: 'fs_content_scan';
  on: 'write';
  block_if_contains: Array<{ pattern: string; message: string }>;
}

export type FsPolicyRule =
  | FsBlockPatternsRule
  | FsSizeLimitRule
  | FsExtensionAllowlistRule
  | FsContentScanRule;

export interface FsPolicyResult {
  allowed: boolean;
  blocking_rule: string | null;
  message: string | null;
}

// ── Default Blocked Paths ──

export const DEFAULT_BLOCK_PATTERNS: string[] = [
  '**/.env',
  '**/.env.*',
  '**/*.pem',
  '**/*.key',
  '**/id_rsa*',
  '**/id_ed25519*',
  '**/credentials*',
  '**/.git/config',
  '**/.aws/**',
  '**/.ssh/**',
  '**/.gnupg/**',
  '**/.npmrc',
  '**/.pypirc',
  '**/.docker/config.json',
  '**/.kube/config',
];

// ── Permission Mapping ──

const OPERATION_TO_PERMISSION: Record<FsOperation, FsPermission> = {
  read: 'read',
  write: 'write',
  create: 'create',
  delete: 'delete',
  list: 'list',
  info: 'read',
};

// ── Path Utilities ──

function normalizePath(p: string): string {
  return resolve(p).replace(/\\/g, '/');
}

function matchPattern(pattern: string, filePath: string): boolean {
  const normalized = normalizePath(filePath);
  const regexStr = pattern
    .replace(/\\/g, '/')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*')
    .replace(/\./g, '\\.');
  return new RegExp(`(^|/)${regexStr}$`).test(normalized);
}

// ── Grant Checking ──

/**
 * Check if the requested operation on the given path is permitted
 * by any of the provided grants.
 */
export function checkAccess(
  grants: FsGrant[],
  operation: FsOperation,
  requestedPath: string,
): FsAccessCheck {
  const normalizedReq = normalizePath(requestedPath);
  const neededPermission = OPERATION_TO_PERMISSION[operation];

  for (const grant of grants) {
    const normalizedGrant = normalizePath(grant.path);

    let pathMatch = false;
    if (normalizedReq === normalizedGrant) {
      pathMatch = true;
    } else if (grant.recursive && normalizedReq.startsWith(normalizedGrant + '/')) {
      pathMatch = true;
    }

    if (pathMatch && grant.permissions.includes(neededPermission)) {
      return { granted: true, grant, reason: null };
    }
  }

  return {
    granted: false,
    grant: null,
    reason: `No filesystem grant covers ${operation} on "${requestedPath}"`,
  };
}

// ── Policy Evaluation ──

/**
 * Evaluate filesystem policy rules against a request.
 */
export function evaluatePolicy(
  rules: FsPolicyRule[],
  request: { operation: FsOperation; path: string; content?: string },
  contentSize?: number,
): FsPolicyResult {
  for (const rule of rules) {
    switch (rule.type) {
      case 'fs_block_patterns': {
        for (const pattern of rule.patterns) {
          if (matchPattern(pattern, request.path)) {
            return {
              allowed: false,
              blocking_rule: 'fs_block_patterns',
              message: `Path matches blocked pattern: ${pattern}`,
            };
          }
        }
        break;
      }

      case 'fs_size_limit': {
        if (contentSize !== undefined) {
          if (request.operation === 'read' && contentSize > rule.max_read_bytes) {
            return {
              allowed: false,
              blocking_rule: 'fs_size_limit',
              message: `File size ${contentSize} exceeds read limit ${rule.max_read_bytes}`,
            };
          }
          if (
            (request.operation === 'write' || request.operation === 'create') &&
            contentSize > rule.max_write_bytes
          ) {
            return {
              allowed: false,
              blocking_rule: 'fs_size_limit',
              message: `Content size ${contentSize} exceeds write limit ${rule.max_write_bytes}`,
            };
          }
        }
        break;
      }

      case 'fs_extension_allowlist': {
        if (request.operation === 'write' || request.operation === 'create') {
          const ext = extname(request.path).toLowerCase();
          if (ext && !rule.extensions.map(e => e.toLowerCase()).includes(ext)) {
            return {
              allowed: false,
              blocking_rule: 'fs_extension_allowlist',
              message: `Extension "${ext}" is not in the allowed list`,
            };
          }
        }
        break;
      }

      case 'fs_content_scan': {
        if (
          (request.operation === 'write' || request.operation === 'create') &&
          request.content
        ) {
          for (const check of rule.block_if_contains) {
            try {
              if (new RegExp(check.pattern).test(request.content)) {
                return {
                  allowed: false,
                  blocking_rule: 'fs_content_scan',
                  message: check.message,
                };
              }
            } catch {
              // Skip invalid patterns
              continue;
            }
          }
        }
        break;
      }
    }
  }

  return { allowed: true, blocking_rule: null, message: null };
}

// ── In-Memory Grant Manager ──

let grantCounter = 0;

/**
 * In-memory grant manager for standalone use. For persistent storage,
 * use @blindkey/local-vault's LocalGrantService instead.
 */
export class GrantManager {
  private grants: Map<string, FsGrant> = new Map();

  grant(input: FsGrantInput): FsGrant {
    // Check if a grant already exists for this path (upsert)
    for (const [id, existing] of this.grants) {
      if (normalizePath(existing.path) === normalizePath(input.path)) {
        const updated: FsGrant = {
          ...existing,
          permissions: input.permissions,
          recursive: input.recursive !== false,
          requires_approval: input.requires_approval ?? false,
        };
        this.grants.set(id, updated);
        return updated;
      }
    }

    const id = `grant-${++grantCounter}`;
    const grant: FsGrant = {
      id,
      path: input.path,
      permissions: input.permissions,
      recursive: input.recursive !== false,
      requires_approval: input.requires_approval ?? false,
    };
    this.grants.set(id, grant);
    return grant;
  }

  revoke(path: string): boolean {
    const normalized = normalizePath(path);
    for (const [id, grant] of this.grants) {
      if (normalizePath(grant.path) === normalized) {
        this.grants.delete(id);
        return true;
      }
    }
    return false;
  }

  listGrants(): FsGrant[] {
    return Array.from(this.grants.values());
  }

  checkAccess(operation: FsOperation, path: string): FsAccessCheck {
    return checkAccess(this.listGrants(), operation, path);
  }

  clear(): void {
    this.grants.clear();
  }
}

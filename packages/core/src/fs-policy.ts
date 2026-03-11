import { resolve, extname } from 'node:path';
import type {
  FilesystemGrant,
  FsRequest,
  FsPolicyRule,
  FsBlockPatternsRule,
  FsSizeLimitRule,
  FsExtensionAllowlistRule,
  FsContentScanRule,
  FsPermission,
  FsOperation,
} from './types.js';
import { safeRegexTest, SafeRegexError } from './safe-regex.js';

export interface FsGrantCheckResult {
  granted: boolean;
  grant: FilesystemGrant | null;
  reason: string | null;
}

const OPERATION_TO_PERMISSION: Record<FsOperation, FsPermission> = {
  read: 'read',
  write: 'write',
  create: 'create',
  delete: 'delete',
  list: 'list',
  info: 'read',
};

function normalizePath(p: string): string {
  return resolve(p).replace(/\\/g, '/');
}

/**
 * Check if the requested path falls within any grant and the operation is permitted.
 */
export function checkGrant(
  grants: FilesystemGrant[],
  operation: FsOperation,
  requestedPath: string
): FsGrantCheckResult {
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

/**
 * Match a path against glob-like patterns (supports ** and *).
 */
function matchPattern(pattern: string, filePath: string): boolean {
  const normalized = normalizePath(filePath);
  // Convert glob to regex — escape dots BEFORE converting globstar to .*
  const regexStr = pattern
    .replace(/\\/g, '/')
    .replace(/\./g, '\\.')
    .replace(/\*\*/g, '{{GLOBSTAR}}')
    .replace(/\*/g, '[^/]*')
    .replace(/\{\{GLOBSTAR\}\}/g, '.*');
  return new RegExp(`(^|/)${regexStr}$`).test(normalized);
}

export interface FsPolicyCheckResult {
  allowed: boolean;
  blocking_rule: string | null;
  message: string | null;
}

/**
 * Evaluate filesystem policy rules against a request.
 */
export function evaluateFsPolicy(
  rules: FsPolicyRule[],
  request: FsRequest,
  contentSize?: number
): FsPolicyCheckResult {
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
          if (ext && !rule.extensions.map((e) => e.toLowerCase()).includes(ext)) {
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
              // Use safe regex evaluation to prevent ReDoS attacks
              if (safeRegexTest(check.pattern, request.content)) {
                return {
                  allowed: false,
                  blocking_rule: 'fs_content_scan',
                  message: check.message,
                };
              }
            } catch (e) {
              if (e instanceof SafeRegexError) {
                // Unsafe pattern - log and skip (fail-open for content scan)
                console.warn(`[SECURITY] Blocked unsafe regex pattern in fs_content_scan: ${e.message}`);
                continue;
              }
              throw e;
            }
          }
        }
        break;
      }
    }
  }

  return { allowed: true, blocking_rule: null, message: null };
}

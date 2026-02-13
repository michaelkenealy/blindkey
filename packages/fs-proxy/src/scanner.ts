import { createHash } from 'node:crypto';
import type { FsRequest, FsPolicyRule } from '@blindkey/core';
import { evaluateFsPolicy, type FsPolicyCheckResult } from '@blindkey/core';
import { DEFAULT_FS_POLICIES } from './patterns.js';

/**
 * Run filesystem policy checks against a request.
 * Merges default policies with any session-specific policies.
 */
export function scanRequest(
  request: FsRequest,
  additionalRules: FsPolicyRule[] = [],
  contentSize?: number
): FsPolicyCheckResult {
  const allRules = [...DEFAULT_FS_POLICIES, ...additionalRules];
  return evaluateFsPolicy(allRules, request, contentSize);
}

/**
 * Compute SHA-256 hash of file content.
 */
export function hashContent(content: string): string {
  return createHash('sha256').update(content).digest('hex');
}

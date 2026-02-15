export class BlindKeyError extends Error {
  public readonly statusCode: number;
  public readonly code: string;

  constructor(message: string, code: string, statusCode: number) {
    super(message);
    this.name = 'BlindKeyError';
    this.code = code;
    this.statusCode = statusCode;
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
    };
  }
}

export class AuthenticationError extends BlindKeyError {
  constructor(message = 'Invalid or expired session token') {
    super(message, 'authentication_error', 401);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends BlindKeyError {
  constructor(message = 'Access denied') {
    super(message, 'authorization_error', 403);
    this.name = 'AuthorizationError';
  }
}

export class PolicyDeniedError extends BlindKeyError {
  public readonly policy: string;

  constructor(policy: string, message?: string) {
    super(message ?? `Request denied by policy: ${policy}`, 'policy_denied', 403);
    this.name = 'PolicyDeniedError';
    this.policy = policy;
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
      policy: this.policy,
    };
  }
}

export class NotFoundError extends BlindKeyError {
  constructor(resource: string) {
    super(`${resource} not found`, 'not_found', 404);
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends BlindKeyError {
  public readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super(`Rate limit exceeded. Retry after ${retryAfterSeconds} seconds.`, 'rate_limited', 429);
    this.name = 'RateLimitError';
    this.retryAfterSeconds = retryAfterSeconds;
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
      retry_after_seconds: this.retryAfterSeconds,
    };
  }
}

export class ValidationError extends BlindKeyError {
  constructor(message: string) {
    super(message, 'validation_error', 400);
    this.name = 'ValidationError';
  }
}

export class DomainNotAllowedError extends BlindKeyError {
  public readonly domain: string;
  public readonly vaultRef: string;

  constructor(domain: string, vaultRef: string) {
    super(
      `Domain "${domain}" is not in the allowed_domains list for secret ${vaultRef}`,
      'domain_not_allowed',
      403
    );
    this.name = 'DomainNotAllowedError';
    this.domain = domain;
    this.vaultRef = vaultRef;
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
      domain: this.domain,
    };
  }
}

export class EgressDeniedError extends BlindKeyError {
  public readonly target: string;

  constructor(target: string, reason: string) {
    super(`Egress target denied for "${target}": ${reason}`, 'egress_denied', 403);
    this.name = 'EgressDeniedError';
    this.target = target;
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
      target: this.target,
    };
  }
}

export class FsAccessDeniedError extends BlindKeyError {
  public readonly path: string;
  public readonly operation: string;
  public readonly rule: string | null;

  constructor(path: string, operation: string, rule?: string) {
    super(
      `Filesystem access denied: ${operation} on "${path}"${rule ? ` (blocked by ${rule})` : ''}`,
      'fs_access_denied',
      403
    );
    this.name = 'FsAccessDeniedError';
    this.path = path;
    this.operation = operation;
    this.rule = rule ?? null;
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
      path: this.path,
      operation: this.operation,
      rule: this.rule,
    };
  }
}

export class ApprovalRequiredError extends BlindKeyError {
  public readonly approvalId: string;

  constructor(approvalId: string) {
    super('Request requires human approval. Waiting for user decision.', 'approval_required', 202);
    this.name = 'ApprovalRequiredError';
    this.approvalId = approvalId;
  }

  toJSON() {
    return {
      error: this.code,
      message: this.message,
      approval_id: this.approvalId,
    };
  }
}

/**
 * Response sanitization: strips any secret values that might be echoed back
 * in API responses, preventing accidental leakage to the agent.
 */
export function sanitizeResponse(
  responseBody: unknown,
  secretValue: string
): unknown {
  if (!secretValue || secretValue.length < 8) {
    // Don't sanitize very short secrets — too many false positives
    return responseBody;
  }

  if (typeof responseBody === 'string') {
    return responseBody.replaceAll(secretValue, '[REDACTED]');
  }

  if (typeof responseBody !== 'object' || responseBody === null) {
    return responseBody;
  }

  // Deep-clone and sanitize
  const json = JSON.stringify(responseBody);
  if (json.includes(secretValue)) {
    return JSON.parse(json.replaceAll(secretValue, '[REDACTED]'));
  }

  return responseBody;
}

/**
 * Sanitize response headers — remove any that might contain secrets.
 */
export function sanitizeHeaders(
  headers: Record<string, string>,
  secretValue: string
): Record<string, string> {
  const cleaned: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (typeof value === 'string' && value.includes(secretValue)) {
      cleaned[key] = '[REDACTED]';
    } else {
      cleaned[key] = value;
    }
  }
  return cleaned;
}

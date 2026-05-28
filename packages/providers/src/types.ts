export interface ProviderAdapter {
  /** Hostnames this provider is permitted to reach. */
  allowedDomains: string[];
  /**
   * Mutate `headers` to inject the credential.
   * `secretType` mirrors the vault's secret_type field.
   */
  injectAuth(headers: Record<string, string>, plaintext: string, secretType: string): void;
  /** Pull the model name from the request body, or null if not applicable. */
  extractModel(body: unknown): string | null;
  /** Rough cost estimate in cents from a parsed response body. Return 0 when unknown. */
  estimateCostCents(response: unknown): number;
}

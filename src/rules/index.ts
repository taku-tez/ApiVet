/**
 * ApiVet Security Rules - Main Export
 * 
 * Rules are organized by category:
 * - owasp.ts: OWASP API Top 10 2023 core rules (APIVET001-015, 084-089)
 *   - APIVET001-015: Core OWASP API security rules
 *   - APIVET084-086: API6:2023 - Unrestricted Access to Sensitive Business Flows
 *   - APIVET087-089: API10:2023 - Unsafe Consumption of APIs
 * - auth.ts: JWT and OAuth2 authentication rules (APIVET016-025)
 * - aws.ts: AWS API Gateway and related services (APIVET026-029, 034, 036-038, 048-049)
 * - azure.ts: Azure API Management and services (APIVET030, 039-040, 056-065)
 * - gcp.ts: GCP Cloud Endpoints, Cloud Run, Firebase, API Gateway (APIVET031, 041-042, 066-075)
 * - platforms.ts: CDN, PaaS, and other platforms (APIVET043-047, 050-055)
 * - general.ts: General cloud security rules (APIVET032-033, 035)
 * - graphql.ts: GraphQL-specific security rules (APIVET076-083)
 */

import type { OpenApiSpec, Finding } from '../types.js';
import { Rule } from './utils.js';
import { owaspRules } from './owasp.js';
import { authRules } from './auth.js';
import { awsRules } from './aws.js';
import { azureRules } from './azure.js';
import { gcpRules } from './gcp.js';
import { platformRules } from './platforms.js';
import { generalRules } from './general.js';
import { graphqlRules } from './graphql.js';

// Re-export types
export type { Rule } from './utils.js';

// Combine all rules
export const rules: Rule[] = [
  ...owaspRules,      // APIVET001-015
  ...authRules,       // APIVET016-025
  ...awsRules,        // APIVET026-029, 034, 036-038, 048-049
  ...azureRules,      // APIVET030, 039-040, 056-065
  ...gcpRules,        // APIVET031, 041-042, 066-075
  ...generalRules,    // APIVET032-033, 035
  ...platformRules,   // APIVET043-047, 050-055
  ...graphqlRules     // APIVET076-083
];

/**
 * Run all security rules against an OpenAPI specification
 */
export function runRules(spec: OpenApiSpec, filePath: string): Finding[] {
  const findings: Finding[] = [];

  for (const rule of rules) {
    try {
      const ruleFindings = rule.check(spec, filePath);
      findings.push(...ruleFindings);
    } catch (error) {
      // Rule execution failed, skip this rule
      console.error(`Rule ${rule.id} failed:`, error);
    }
  }

  return findings;
}

// Export individual rule sets for selective use
export { owaspRules } from './owasp.js';
export { authRules } from './auth.js';
export { awsRules } from './aws.js';
export { azureRules } from './azure.js';
export { gcpRules } from './gcp.js';
export { platformRules } from './platforms.js';
export { generalRules } from './general.js';
export { graphqlRules } from './graphql.js';

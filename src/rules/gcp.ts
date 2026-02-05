/**
 * GCP Cloud Endpoints, Cloud Run, and Firebase Rules
 * APIVET031, APIVET041-042
 */

import type { OpenApiSpec, Finding } from '../types.js';
import { Rule, isGcpService, hasGoogleExtensions, hasGlobalSecurity, hasSecuritySchemes, createFinding } from './utils.js';

export const gcpRules: Rule[] = [
  // GCP Cloud Endpoints
  {
    id: 'APIVET031',
    title: 'GCP Cloud Endpoints detected',
    description: 'Ensure GCP API security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      const isGcp = hasGoogleExtensions(spec) || isGcpService(servers) ||
                   servers.some(s => s.url.includes('.endpoints.'));

      if (isGcp) {
        findings.push(createFinding(
          'APIVET031',
          'GCP Cloud Endpoints/API Gateway detected',
          'This API uses GCP Cloud Endpoints or API Gateway. Ensure authentication and quotas are configured.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Configure x-google-endpoints for DNS and auth. Use API keys or OAuth2. Set x-google-quota.'
          }
        ));

        // Check for CORS in Google endpoints
        const extSpec = spec as Record<string, unknown>;
        const googleEndpoints = extSpec['x-google-endpoints'] as Array<Record<string, unknown>> | undefined;
        if (googleEndpoints) {
          for (const endpoint of googleEndpoints) {
            if (endpoint.allowCors && !endpoint.name) {
              findings.push(createFinding(
                'APIVET031',
                'GCP endpoint allows CORS without explicit configuration',
                'A GCP endpoint has allowCors enabled. Ensure CORS is intentional.',
                'low',
                {
                  owaspCategory: 'API8:2023',
                  filePath,
                  remediation: 'Review CORS settings and restrict allowed origins.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // GCP Cloud Run authentication
  {
    id: 'APIVET041',
    title: 'GCP Cloud Run without authentication indication',
    description: 'Cloud Run services should have authentication',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (!servers.some(s => s.url.includes('.run.app'))) return findings;

      if (!hasGlobalSecurity(spec) && !hasSecuritySchemes(spec)) {
        findings.push(createFinding(
          'APIVET041',
          'GCP Cloud Run service without authentication defined',
          'This Cloud Run service has no authentication in the OpenAPI spec.',
          'medium',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Configure Cloud Run auth (IAM invoker or custom). Use Firebase Auth or custom JWT for public APIs.'
          }
        ));
      }

      return findings;
    }
  },

  // Firebase / Identity Platform
  {
    id: 'APIVET042',
    title: 'Firebase / Identity Platform detected',
    description: 'Ensure Firebase security rules are configured',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const specStr = JSON.stringify(spec).toLowerCase();

      const isFirebase = specStr.includes('firebase') ||
                        specStr.includes('identitytoolkit.googleapis.com') ||
                        specStr.includes('securetoken.googleapis.com');

      if (isFirebase) {
        findings.push(createFinding(
          'APIVET042',
          'Firebase / Identity Platform authentication detected',
          'This API uses Firebase Auth or Identity Platform. Ensure proper token validation.',
          'info',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Validate Firebase ID tokens server-side. Check expiration. Implement security rules. Enable App Check.'
          }
        ));
      }

      return findings;
    }
  }
];

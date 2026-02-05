/**
 * GCP Cloud Endpoints, Cloud Run, Firebase, and API Gateway Rules
 * APIVET031, APIVET041-042, APIVET066-075
 */

import type { OpenApiSpec, Finding } from '../types.js';
import {
  Rule,
  HTTP_METHODS,
  isGcpService,
  hasGoogleExtensions,
  hasGlobalSecurity,
  hasSecuritySchemes,
  createFinding,
  getResponseHeaderNames
} from './utils.js';

// Helper: Check if spec is GCP API (Cloud Endpoints, API Gateway, or services)
function isGcpApi(spec: OpenApiSpec): boolean {
  const servers = spec.servers || [];
  return hasGoogleExtensions(spec) ||
         isGcpService(servers) ||
         servers.some(s =>
           s.url.includes('.endpoints.') ||
           s.url.includes('.run.app') ||
           s.url.includes('.cloudfunctions.net') ||
           s.url.includes('apigateway.') ||
           s.url.includes('.googleapis.com')
         );
}

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
  },

  // ============================================
  // GCP Deep Security Checks (APIVET066-075)
  // ============================================

  // GCP API without API key requirement
  {
    id: 'APIVET066',
    title: 'GCP API without API key requirement',
    description: 'GCP APIs should require API keys for usage tracking and quota enforcement',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const extSpec = spec as Record<string, unknown>;
      const schemes = spec.components?.securitySchemes || {};

      // Check x-google-management for API key setting
      const googleMgmt = extSpec['x-google-management'] as Record<string, unknown> | undefined;
      if (googleMgmt) {
        const metrics = googleMgmt.metrics as Record<string, unknown>[] | undefined;
        // If management is defined but no API key required
        if (!metrics || metrics.length === 0) {
          // Check if any security scheme is API key
          const hasApiKey = Object.values(schemes).some(s => s.type === 'apiKey');
          if (!hasApiKey) {
            findings.push(createFinding(
              'APIVET066',
              'GCP API without API key requirement',
              'This GCP API does not require API keys. API keys enable usage tracking, quota enforcement, and billing.',
              'medium',
              {
                owaspCategory: 'API2:2023',
                filePath,
                remediation: 'Enable API key requirement in Cloud Endpoints/API Gateway config. Add x-google-management with metrics. Create API key credentials in Cloud Console.'
              }
            ));
          }
        }
      } else {
        // No x-google-management at all
        const hasApiKey = Object.values(schemes).some(s => s.type === 'apiKey');
        if (!hasApiKey && Object.keys(spec.paths || {}).length > 0) {
          findings.push(createFinding(
            'APIVET066',
            'GCP API without API key configuration',
            'This GCP API has no x-google-management or API key security scheme. API keys enable usage tracking and quota enforcement.',
            'medium',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Add x-google-management configuration or define apiKey security scheme. Enable API key validation in ESP/ESPv2.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // GCP API allowing all callers (unauthenticated)
  {
    id: 'APIVET067',
    title: 'GCP API allows unauthenticated access',
    description: 'GCP APIs with x-google-allow: all permit unauthenticated requests',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          // Check x-google-allow on operation
          const googleAllow = operation['x-google-allow'] as string | undefined;
          if (googleAllow === 'all') {
            findings.push(createFinding(
              'APIVET067',
              'GCP API endpoint allows unauthenticated access',
              `${method.toUpperCase()} ${path} has x-google-allow: all, permitting unauthenticated requests.`,
              'high',
              {
                owaspCategory: 'API2:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Change x-google-allow to "configured" and define proper security requirements. Use IAM roles for service-to-service auth.'
              }
            ));
          }
        }
      }

      // Also check spec-level x-google-allow
      const extSpec = spec as Record<string, unknown>;
      if (extSpec['x-google-allow'] === 'all') {
        findings.push(createFinding(
          'APIVET067',
          'GCP API globally allows unauthenticated access',
          'The API has x-google-allow: all at spec level, permitting unauthenticated requests to all endpoints.',
          'high',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Remove global x-google-allow: all. Configure authentication per endpoint or use security schemes.'
          }
        ));
      }

      return findings;
    }
  },

  // GCP Cloud Functions without authentication
  {
    id: 'APIVET068',
    title: 'GCP Cloud Functions without authentication',
    description: 'Cloud Functions should have authentication unless intentionally public',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (!servers.some(s => s.url.includes('.cloudfunctions.net'))) return findings;

      if (!hasGlobalSecurity(spec) && !hasSecuritySchemes(spec)) {
        findings.push(createFinding(
          'APIVET068',
          'GCP Cloud Functions without authentication defined',
          'This Cloud Functions API has no authentication in the OpenAPI spec. Functions may be publicly accessible.',
          'medium',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Configure IAM invoker role (allUsers for public, specific principals for private). Use Firebase Auth or custom JWT validation.'
          }
        ));
      }

      return findings;
    }
  },

  // GCP API without quota
  {
    id: 'APIVET069',
    title: 'GCP API without quota configuration',
    description: 'GCP APIs should have quota limits to prevent abuse',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const extSpec = spec as Record<string, unknown>;
      const paths = spec.paths || {};

      // Check for x-google-quota
      const hasGoogleQuota = JSON.stringify(spec).includes('x-google-quota');

      // Also check for rate limit response headers
      let hasRateLimitHeaders = false;
      for (const pathItem of Object.values(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation?.responses) continue;

          for (const response of Object.values(operation.responses)) {
            const headerNames = getResponseHeaderNames(
              response as { headers?: Record<string, unknown>; $ref?: string },
              spec
            );

            if (headerNames.some(h =>
              h.includes('ratelimit') ||
              h.includes('x-ratelimit') ||
              h.includes('retry-after')
            )) {
              hasRateLimitHeaders = true;
              break;
            }
          }
          if (hasRateLimitHeaders) break;
        }
        if (hasRateLimitHeaders) break;
      }

      // Check for 429 responses
      let has429 = false;
      for (const pathItem of Object.values(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (operation?.responses?.['429']) {
            has429 = true;
            break;
          }
        }
        if (has429) break;
      }

      if (!hasGoogleQuota && !hasRateLimitHeaders && !has429 && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET069',
          'GCP API without quota configuration',
          'This GCP API has no x-google-quota, rate limit headers, or 429 responses defined. Consider adding quota limits.',
          'medium',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Add x-google-quota in Cloud Endpoints config. Define quota metrics in x-google-management. Configure quota limits per API key or project.'
          }
        ));
      }

      return findings;
    }
  },

  // GCP without Cloud Armor (WAF)
  {
    id: 'APIVET070',
    title: 'GCP API without Cloud Armor indication',
    description: 'GCP APIs should be protected by Cloud Armor for DDoS and WAF protection',
    severity: 'low',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const specStr = JSON.stringify(spec).toLowerCase();
      const servers = spec.servers || [];

      // Check for Cloud Armor or load balancer indication
      const hasWafIndication = specStr.includes('cloud armor') ||
        specStr.includes('cloudarmor') ||
        specStr.includes('x-google-armor') ||
        specStr.includes('waf') ||
        servers.some(s =>
          s.url.includes('.a.run.app') || // Internal Cloud Run URL
          s.description?.toLowerCase().includes('load balancer')
        );

      if (!hasWafIndication && Object.keys(spec.paths || {}).length > 0) {
        findings.push(createFinding(
          'APIVET070',
          'GCP API without Cloud Armor protection indicated',
          'This GCP API does not indicate Cloud Armor protection. Cloud Armor provides DDoS protection and WAF capabilities.',
          'low',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Deploy Cloud Load Balancing with Cloud Armor security policy. Enable preconfigured WAF rules (OWASP Top 10). Configure rate limiting and IP allowlists.'
          }
        ));
      }

      return findings;
    }
  },

  // GCP backend over HTTP
  {
    id: 'APIVET071',
    title: 'GCP API with HTTP backend',
    description: 'GCP API backends should use HTTPS',
    severity: 'high',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const paths = spec.paths || {};

      // Check x-google-backend for HTTP URLs
      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          const googleBackend = operation['x-google-backend'] as Record<string, unknown> | undefined;
          if (googleBackend) {
            const address = googleBackend.address as string | undefined;
            if (address && address.startsWith('http://') &&
                !address.includes('localhost') &&
                !address.includes('127.0.0.1')) {
              findings.push(createFinding(
                'APIVET071',
                `GCP API backend using HTTP: ${address}`,
                `${method.toUpperCase()} ${path} has x-google-backend with HTTP URL. Data between ESP and backend is not encrypted.`,
                'high',
                {
                  owaspCategory: 'API8:2023',
                  filePath,
                  endpoint: path,
                  method: method.toUpperCase(),
                  remediation: 'Change backend address to HTTPS. Use internal networking (VPC) for backends. Configure backend authentication.'
                }
              ));
            }
          }
        }
      }

      // Check spec-level x-google-backend
      const extSpec = spec as Record<string, unknown>;
      const globalBackend = extSpec['x-google-backend'] as Record<string, unknown> | undefined;
      if (globalBackend) {
        const address = globalBackend.address as string | undefined;
        if (address && address.startsWith('http://') &&
            !address.includes('localhost') &&
            !address.includes('127.0.0.1')) {
          findings.push(createFinding(
            'APIVET071',
            `GCP API global backend using HTTP: ${address}`,
            'The API has x-google-backend with HTTP URL at spec level. All backend traffic is unencrypted.',
            'high',
            {
              owaspCategory: 'API8:2023',
              filePath,
              remediation: 'Change backend address to HTTPS. For Cloud Run/Functions, use the HTTPS URL. Use VPC Serverless Connector for private backends.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // GCP API without versioning
  {
    id: 'APIVET072',
    title: 'GCP API without versioning',
    description: 'GCP APIs should use versioning for lifecycle management',
    severity: 'low',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const paths = spec.paths || {};
      const servers = spec.servers || [];

      // Check for version in URL path
      const hasVersionInPath = Object.keys(paths).some(p =>
        /\/v\d+/i.test(p) || /\/api\/\d+\.\d+/i.test(p)
      );

      // Check for version in server URL
      const hasVersionInServer = servers.some(s =>
        /\/v\d+/i.test(s.url)
      );

      // Check for version query parameter
      let hasVersionParam = false;
      for (const pathItem of Object.values(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation?.parameters) continue;

          if (operation.parameters.some((p: any) =>
            p.name?.toLowerCase() === 'version' ||
            p.name?.toLowerCase() === 'api-version' ||
            p.name?.toLowerCase() === 'v'
          )) {
            hasVersionParam = true;
            break;
          }
        }
        if (hasVersionParam) break;
      }

      if (!hasVersionInPath && !hasVersionInServer && !hasVersionParam && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET072',
          'GCP API without versioning',
          'This GCP API does not use versioning. Google Cloud APIs typically use /v1, /v2, etc. for lifecycle management.',
          'low',
          {
            owaspCategory: 'API9:2023',
            filePath,
            remediation: 'Add version prefix to paths (e.g., /v1/resource). Use Cloud Endpoints revisions. Follow Google API Design Guide versioning conventions.'
          }
        ));
      }

      return findings;
    }
  },

  // Apigee detection
  {
    id: 'APIVET073',
    title: 'Google Cloud Apigee detected',
    description: 'Ensure Apigee security policies are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();

      const isApigee = servers.some(s =>
        s.url.includes('.apigee.net') ||
        s.url.includes('.apigee.io') ||
        s.url.includes('apigee.')
      ) || specStr.includes('x-apigee') || specStr.includes('apigee');

      if (isApigee) {
        findings.push(createFinding(
          'APIVET073',
          'Google Cloud Apigee detected',
          'This API uses Apigee. Ensure OAuth2, API key validation, spike arrest, and threat protection policies are configured.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Configure VerifyAPIKey/OAuthV2 policies. Add SpikeArrest and Quota. Enable JSONThreatProtection and XMLThreatProtection. Use shared flows for security.'
          }
        ));
      }

      return findings;
    }
  },

  // GCP Google OAuth2 without scopes
  {
    id: 'APIVET074',
    title: 'GCP OAuth2 without scope validation',
    description: 'GCP OAuth2 schemes should define and validate scopes',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const schemes = spec.components?.securitySchemes || {};
      const paths = spec.paths || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'oauth2') continue;

        // Check OAuth2 flows for Google patterns
        const flows = scheme.flows || {};
        const flowsStr = JSON.stringify(flows).toLowerCase();
        const isGoogleOAuth = flowsStr.includes('accounts.google.com') ||
                              flowsStr.includes('oauth2.googleapis.com') ||
                              flowsStr.includes('googleapis.com/auth');

        if (!isGoogleOAuth) continue;

        // Check if endpoints use this scheme without scopes
        for (const [path, pathItem] of Object.entries(paths)) {
          for (const method of HTTP_METHODS) {
            const operation = pathItem[method];
            if (!operation?.security) continue;

            for (const secReq of operation.security) {
              if (name in secReq && (!secReq[name] || secReq[name].length === 0)) {
                findings.push(createFinding(
                  'APIVET074',
                  `Google OAuth2 "${name}" used without scopes`,
                  `${method.toUpperCase()} ${path} uses Google OAuth2 "${name}" without specific scopes. This allows any valid Google token to access the endpoint.`,
                  'medium',
                  {
                    owaspCategory: 'API5:2023',
                    filePath,
                    endpoint: path,
                    method: method.toUpperCase(),
                    remediation: 'Define required scopes (e.g., https://www.googleapis.com/auth/cloud-platform). Use fine-grained scopes. Validate scopes in ESP/backend.'
                  }
                ));
              }
            }
          }
        }
      }

      return findings;
    }
  },

  // GCP API key in query string
  {
    id: 'APIVET075',
    title: 'GCP API key in query string',
    description: 'API keys in query strings can be leaked in logs and referer headers',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isGcpApi(spec)) return findings;

      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'apiKey') continue;

        const keyName = (scheme.name || '').toLowerCase();
        const isGcpKey = keyName === 'key' ||
                         keyName === 'api_key' ||
                         keyName === 'apikey' ||
                         keyName.includes('google');

        if (isGcpKey && scheme.in === 'query') {
          findings.push(createFinding(
            'APIVET075',
            `GCP API key "${name}" sent via query string`,
            `Security scheme "${name}" sends the API key in the query string. Keys in URLs can be leaked via browser history, proxy logs, and Referer headers.`,
            'medium',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Send API key in X-API-Key header instead. Configure ESP to accept header-based API keys. Note: some Google APIs still require query param for legacy compatibility.'
            }
          ));
        }
      }

      return findings;
    }
  }
];

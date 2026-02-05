/**
 * Azure API Management and Related Services Rules
 * APIVET030, APIVET039-040, APIVET056-065, APIVET090-098 (Policy-based)
 */

import type { Finding } from '../types.js';
import {
  Rule,
  HTTP_METHODS,
  isAzureApim,
  hasGlobalSecurity,
  createFinding,
  getResponseHeaderNames
} from './utils.js';

// Helper: Extract policy metadata from spec (embedded by cloud scanner)
interface PolicyMeta {
  hasValidateJwt?: boolean;
  hasRateLimit?: boolean;
  hasIpFilter?: boolean;
  hasCors?: boolean;
  corsAllowAll?: boolean;
  hasCache?: boolean;
  hasLog?: boolean;
  hasAuthenticationManaged?: boolean;
  jwtValidation?: {
    hasRequiredClaims?: boolean;
    hasAudiences?: boolean;
    hasIssuers?: boolean;
    hasOpenIdConfig?: boolean;
  };
  ipFilter?: {
    action?: string;
    addressCount?: number;
  };
  corsConfig?: {
    allowedOrigins?: string[];
    allowCredentials?: boolean;
  };
  rateLimitConfig?: {
    callsPerPeriod?: number;
    renewalPeriod?: number;
  };
}

interface PolicyData {
  global?: PolicyMeta;
  api?: PolicyMeta;
}

function getPolicyData(spec: Record<string, unknown>): PolicyData | undefined {
  return spec['x-azure-apim-policies'] as PolicyData | undefined;
}

/**
 * Check if a policy capability exists at either global or API level
 */
function hasPolicyCapability(
  policies: PolicyData | undefined,
  key: keyof PolicyMeta
): boolean {
  if (!policies) return false;
  return !!(policies.global?.[key] || policies.api?.[key]);
}

export const azureRules: Rule[] = [
  // Azure APIM detection
  {
    id: 'APIVET030',
    title: 'Azure APIM integration detected',
    description: 'Ensure Azure API Management policies are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];

      if (isAzureApim(spec.servers)) {
        findings.push(createFinding(
          'APIVET030',
          'Azure API Management detected',
          'This API uses Azure APIM. Ensure inbound/outbound policies are configured for security.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Review APIM policies: validate-jwt, rate-limit-by-key, ip-filter, cors.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure Functions / App Service
  {
    id: 'APIVET039',
    title: 'Azure Functions / App Service detected',
    description: 'Ensure Azure authentication is properly configured',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      const isAzureFunc = servers.some(s =>
        s.url.includes('.azurewebsites.net') ||
        s.url.includes('.azure-mobile.net')
      );

      if (isAzureFunc) {
        findings.push(createFinding(
          'APIVET039',
          'Azure Functions / App Service detected',
          'This API is hosted on Azure Functions or App Service. Configure built-in or custom authentication.',
          'info',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Enable Azure App Service Authentication (Easy Auth) or implement custom JWT validation.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure Front Door
  {
    id: 'APIVET040',
    title: 'Azure Front Door detected',
    description: 'Ensure Azure Front Door security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      const isFrontDoor = servers.some(s =>
        s.url.includes('.azurefd.net') ||
        s.url.includes('.afd.') ||
        s.url.includes('frontdoor')
      );

      if (isFrontDoor) {
        findings.push(createFinding(
          'APIVET040',
          'Azure Front Door detected',
          'This API uses Azure Front Door. Ensure WAF policies and DDoS protection are configured.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Enable Azure WAF policy with OWASP rule sets. Configure rate limiting. Use Private Link.'
          }
        ));
      }

      return findings;
    }
  },

  // ============================================
  // Azure APIM Deep Security Checks (APIVET056-065)
  // ============================================

  // Azure APIM without subscription key
  {
    id: 'APIVET056',
    title: 'Azure APIM without subscription key requirement',
    description: 'Azure APIM APIs should require subscription keys for access control and usage tracking',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const schemes = spec.components?.securitySchemes || {};
      const schemeValues = Object.values(schemes);

      // Check for Ocp-Apim-Subscription-Key or subscription-key pattern
      const hasSubscriptionKey = schemeValues.some(scheme => {
        if (scheme.type !== 'apiKey') return false;
        const name = (scheme.name || '').toLowerCase();
        return name.includes('ocp-apim-subscription') ||
               name.includes('subscription-key') ||
               name.includes('ocp-apim-trace');
      });

      if (!hasSubscriptionKey) {
        findings.push(createFinding(
          'APIVET056',
          'Azure APIM without subscription key requirement',
          'This Azure APIM API does not define a subscription key security scheme. Subscription keys enable usage tracking, rate limiting per product, and access control.',
          'medium',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Add an apiKey security scheme for Ocp-Apim-Subscription-Key header. Configure APIM products with subscription required.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure APIM management endpoint exposed
  {
    id: 'APIVET057',
    title: 'Azure APIM management endpoint exposed in spec',
    description: 'Azure Resource Manager (ARM) endpoints should not appear in public API specs',
    severity: 'high',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      for (const server of servers) {
        const url = server.url.toLowerCase();
        if (url.includes('management.azure.com') ||
            url.includes('.management.core.windows.net')) {
          findings.push(createFinding(
            'APIVET057',
            `Azure management endpoint exposed: ${server.url}`,
            'Azure Resource Manager (ARM) endpoint found in API spec. This is an administrative endpoint that should not be in public API specs.',
            'high',
            {
              owaspCategory: 'API9:2023',
              filePath,
              remediation: 'Remove ARM/management endpoints from public API specs. Use separate specs for management APIs. Restrict access with Azure RBAC and Conditional Access.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // Azure APIM endpoint without authentication
  {
    id: 'APIVET058',
    title: 'Azure APIM endpoint without authentication',
    description: 'Azure APIM endpoints should have authentication configured',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const paths = spec.paths || {};
      const globalSec = hasGlobalSecurity(spec);

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation) continue;

          // Skip if global security exists
          if (globalSec) continue;

          // Skip if operation has its own security
          if (operation.security && operation.security.length > 0) continue;

          findings.push(createFinding(
            'APIVET058',
            'Azure APIM endpoint without authentication',
            `${method.toUpperCase()} ${path} in Azure APIM has no authentication. Configure validate-jwt policy or security scheme.`,
            'high',
            {
              owaspCategory: 'API2:2023',
              filePath,
              endpoint: path,
              method: method.toUpperCase(),
              remediation: 'Add validate-jwt inbound policy, configure OAuth2 with Azure Entra ID, or require subscription keys. Use APIM named values for secrets.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // Azure APIM without rate limiting
  {
    id: 'APIVET059',
    title: 'Azure APIM without rate limiting indication',
    description: 'Azure APIM APIs should indicate rate limiting configuration',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const paths = spec.paths || {};
      let hasAnyRateLimit = false;

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
              h.includes('rate-limit') ||
              h.includes('retry-after') ||
              h.includes('x-ms-ratelimit')
            )) {
              hasAnyRateLimit = true;
              break;
            }
          }
          if (hasAnyRateLimit) break;
        }
        if (hasAnyRateLimit) break;
      }

      // Also check for 429 responses
      if (!hasAnyRateLimit) {
        for (const pathItem of Object.values(paths)) {
          for (const method of HTTP_METHODS) {
            const operation = pathItem[method];
            if (operation?.responses?.['429']) {
              hasAnyRateLimit = true;
              break;
            }
          }
          if (hasAnyRateLimit) break;
        }
      }

      if (!hasAnyRateLimit && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET059',
          'Azure APIM without rate limiting indication',
          'This Azure APIM API does not indicate rate limiting (no rate-limit headers or 429 responses). Configure rate-limit-by-key or rate-limit policies.',
          'medium',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Add rate-limit-by-key inbound policy in APIM. Define 429 response with Retry-After header. Use APIM products for tiered rate limits.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure APIM without API versioning
  {
    id: 'APIVET060',
    title: 'Azure APIM without API versioning',
    description: 'Azure APIM APIs should use versioning for lifecycle management',
    severity: 'low',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const paths = spec.paths || {};
      const servers = spec.servers || [];

      // Check for version in URL path
      const hasVersionInPath = Object.keys(paths).some(p =>
        /\/v\d+/i.test(p) || /\/api\/\d+\.\d+/i.test(p)
      );

      // Check for version in server URL
      const hasVersionInServer = servers.some(s =>
        /\/v\d+/i.test(s.url) || /api-version=/i.test(s.url)
      );

      // Check for api-version query parameter
      let hasVersionParam = false;
      for (const pathItem of Object.values(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation?.parameters) continue;

          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Parameter type varies
          if (operation.parameters.some((p: any) =>
            p.name?.toLowerCase() === 'api-version' ||
            p.name?.toLowerCase() === 'x-api-version'
          )) {
            hasVersionParam = true;
            break;
          }
        }
        if (hasVersionParam) break;
      }

      // Check for version header
      let hasVersionHeader = false;
      for (const pathItem of Object.values(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation?.parameters) continue;

          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Parameter type varies
          if (operation.parameters.some((p: any) =>
            p.in === 'header' && (
              p.name?.toLowerCase() === 'api-version' ||
              p.name?.toLowerCase() === 'x-api-version' ||
              p.name?.toLowerCase() === 'x-ms-version'
            )
          )) {
            hasVersionHeader = true;
            break;
          }
        }
        if (hasVersionHeader) break;
      }

      if (!hasVersionInPath && !hasVersionInServer && !hasVersionParam && !hasVersionHeader && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET060',
          'Azure APIM without API versioning',
          'This Azure APIM API does not use versioning. Azure APIM supports URL path, query string, and header-based versioning.',
          'low',
          {
            owaspCategory: 'API9:2023',
            filePath,
            remediation: 'Configure API versioning in APIM (URL path /v1, query ?api-version=, or header). Use APIM revisions for non-breaking changes.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure APIM subscription key in query string
  {
    id: 'APIVET061',
    title: 'Azure APIM subscription key in query string',
    description: 'Subscription keys in query strings can be leaked in logs and referer headers',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'apiKey') continue;

        const schemeName = (scheme.name || '').toLowerCase();
        const isSubscriptionKey = schemeName.includes('subscription') ||
                                  schemeName.includes('ocp-apim');

        if (isSubscriptionKey && scheme.in === 'query') {
          findings.push(createFinding(
            'APIVET061',
            `Azure APIM subscription key "${name}" sent via query string`,
            `Security scheme "${name}" sends the subscription key in the query string. Keys in URLs can be leaked via browser history, proxy logs, and Referer headers.`,
            'medium',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Configure subscription key delivery via header (Ocp-Apim-Subscription-Key) instead of query string. Update APIM subscription settings.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // Azure APIM backend over HTTP
  {
    id: 'APIVET062',
    title: 'Azure APIM with non-HTTPS backend',
    description: 'APIM backend services should use HTTPS',
    severity: 'high',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      // Check x-ms-paths and any backend URL references
      const extSpec = spec as Record<string, unknown>;

      // Check for Azure-specific backend annotations
      const xMsApi = extSpec['x-ms-api-annotation'] as Record<string, unknown> | undefined;
      if (xMsApi) {
        const backend = xMsApi.backend as string | undefined;
        if (backend && backend.startsWith('http://') && !backend.includes('localhost') && !backend.includes('127.0.0.1')) {
          findings.push(createFinding(
            'APIVET062',
            'Azure APIM backend using HTTP',
            `Backend URL "${backend}" uses HTTP instead of HTTPS. Data between APIM and backend is not encrypted.`,
            'high',
            {
              owaspCategory: 'API8:2023',
              filePath,
              remediation: 'Use HTTPS for all backend services. Configure client certificates for backend authentication. Use APIM VNet integration for private backends.'
            }
          ));
        }
      }

      // Check for HTTP backend URLs in x-servers or x-ms-parameterized-host
      const paramHost = extSpec['x-ms-parameterized-host'] as Record<string, unknown> | undefined;
      if (paramHost) {
        const hostTemplate = paramHost.hostTemplate as string | undefined;
        if (hostTemplate && hostTemplate.startsWith('http://')) {
          findings.push(createFinding(
            'APIVET062',
            'Azure APIM parameterized host using HTTP',
            `Parameterized host template "${hostTemplate}" uses HTTP. All API traffic should use HTTPS.`,
            'high',
            {
              owaspCategory: 'API8:2023',
              filePath,
              remediation: 'Change hostTemplate to use HTTPS. Enforce HTTPS-only in APIM inbound policies with redirect.'
            }
          ));
        }
      }

      // Check servers for HTTP (non-localhost)
      const servers = spec.servers || [];
      for (const server of servers) {
        if (server.url.startsWith('http://') &&
            !server.url.includes('localhost') &&
            !server.url.includes('127.0.0.1') &&
            (server.url.includes('.azure-api.net') || server.url.includes('management.azure.com'))) {
          findings.push(createFinding(
            'APIVET062',
            `Azure APIM endpoint using HTTP: ${server.url}`,
            'Azure APIM endpoint is configured with HTTP. All APIM traffic should use HTTPS.',
            'high',
            {
              owaspCategory: 'API8:2023',
              filePath,
              remediation: 'Use HTTPS URL for Azure APIM. Enable "Require HTTPS" in APIM custom domain settings.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // Azure Entra ID / B2C detection
  {
    id: 'APIVET063',
    title: 'Azure Entra ID / B2C authentication detected',
    description: 'Ensure Azure Entra ID integration is properly configured',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const specStr = JSON.stringify(spec).toLowerCase();
      const schemes = spec.components?.securitySchemes || {};

      let isEntraId = false;
      let isB2C = false;

      // Check OAuth2 URLs for Entra ID patterns
      for (const scheme of Object.values(schemes)) {
        if (scheme.type !== 'oauth2') continue;

        const flows = scheme.flows || {};
        for (const flow of Object.values(flows)) {
          const flowObj = flow as Record<string, unknown>;
          const urls = [
            flowObj.authorizationUrl as string,
            flowObj.tokenUrl as string,
            flowObj.refreshUrl as string
          ].filter(Boolean);

          for (const url of urls) {
            const lower = url.toLowerCase();
            if (lower.includes('login.microsoftonline.com') ||
                lower.includes('sts.windows.net') ||
                lower.includes('login.microsoft.com')) {
              isEntraId = true;
            }
            if (lower.includes('.b2clogin.com') ||
                lower.includes('b2c_')) {
              isB2C = true;
            }
          }
        }

        // Check openIdConnectUrl
        // eslint-disable-next-line @typescript-eslint/no-explicit-any -- OpenAPI 3.0 type
        if (scheme.type === 'openIdConnect' as any) {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any -- OpenAPI 3.0 openIdConnectUrl
          const oidcUrl = ((scheme as any).openIdConnectUrl || '').toLowerCase();
          if (oidcUrl.includes('login.microsoftonline.com') || oidcUrl.includes('login.microsoft.com')) {
            isEntraId = true;
          }
          if (oidcUrl.includes('.b2clogin.com')) {
            isB2C = true;
          }
        }
      }

      // Fallback: check spec-wide patterns
      if (!isEntraId && !isB2C) {
        if (specStr.includes('login.microsoftonline.com') || specStr.includes('graph.microsoft.com')) {
          isEntraId = true;
        }
        if (specStr.includes('.b2clogin.com')) {
          isB2C = true;
        }
      }

      if (isB2C) {
        findings.push(createFinding(
          'APIVET063',
          'Azure Entra ID B2C authentication detected',
          'This API uses Azure Entra ID B2C for consumer-facing authentication. Ensure custom policies and user flows are properly configured.',
          'info',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Validate B2C tokens with correct issuer and audience. Configure MFA in user flows. Use custom policies for advanced scenarios. Enable Identity Protection.'
          }
        ));
      } else if (isEntraId) {
        findings.push(createFinding(
          'APIVET063',
          'Azure Entra ID authentication detected',
          'This API uses Azure Entra ID (formerly Azure AD) for authentication. Ensure proper token validation and Conditional Access.',
          'info',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Validate tokens with correct tenant, audience, and issuer. Configure Conditional Access policies. Use app roles for authorization. Enable Continuous Access Evaluation (CAE).'
          }
        ));
      }

      return findings;
    }
  },

  // Azure APIM without WAF
  {
    id: 'APIVET064',
    title: 'Azure APIM without WAF indication',
    description: 'Azure APIM APIs should be protected by Azure WAF via Application Gateway or Front Door',
    severity: 'low',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();

      // Check if there's a Front Door or Application Gateway in front
      const hasWafIndication = specStr.includes('waf') ||
        specStr.includes('x-azure-waf') ||
        servers.some(s =>
          s.url.includes('.azurefd.net') ||
          s.url.includes('.afd.') ||
          s.url.includes('appgw') ||
          s.url.includes('applicationgateway')
        );

      if (!hasWafIndication) {
        findings.push(createFinding(
          'APIVET064',
          'Azure APIM without WAF protection indicated',
          'This Azure APIM API does not indicate WAF protection. Azure WAF via Application Gateway or Front Door provides OWASP protection.',
          'low',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Deploy Azure Application Gateway or Front Door with WAF policy in front of APIM. Use OWASP 3.2 managed rule sets. Configure custom rules for API-specific threats.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure APIM OAuth2 without scopes
  {
    id: 'APIVET065',
    title: 'Azure APIM OAuth2 without scope validation',
    description: 'Azure APIM OAuth2 schemes should define and validate scopes',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const schemes = spec.components?.securitySchemes || {};
      const paths = spec.paths || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'oauth2') continue;

        // Check OAuth2 flows for Entra ID patterns
        const flows = scheme.flows || {};
        const isAzureOAuth = JSON.stringify(flows).toLowerCase().includes('microsoftonline') ||
                             JSON.stringify(flows).toLowerCase().includes('login.microsoft');

        if (!isAzureOAuth) continue;

        // Check if endpoints use this scheme without scopes
        for (const [path, pathItem] of Object.entries(paths)) {
          for (const method of HTTP_METHODS) {
            const operation = pathItem[method];
            if (!operation?.security) continue;

            for (const secReq of operation.security) {
              if (name in secReq && (!secReq[name] || secReq[name].length === 0)) {
                findings.push(createFinding(
                  'APIVET065',
                  `Azure Entra ID OAuth2 "${name}" used without scopes`,
                  `${method.toUpperCase()} ${path} uses Entra ID OAuth2 "${name}" without specific scopes. This allows any valid token to access the endpoint.`,
                  'medium',
                  {
                    owaspCategory: 'API5:2023',
                    filePath,
                    endpoint: path,
                    method: method.toUpperCase(),
                    remediation: 'Define required scopes (e.g., api://<app-id>/read, api://<app-id>/write). Validate scopes in APIM validate-jwt policy with required-claims.'
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

  // ============================================
  // Azure APIM Policy-Based Checks (APIVET090-098)
  // These rules analyze actual APIM policies fetched via SDK
  // ============================================

  // APIM without validate-jwt policy
  {
    id: 'APIVET090',
    title: 'Azure APIM missing validate-jwt policy',
    description: 'Azure APIM should have validate-jwt policy for token validation',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings; // No policy data available (static scan only)

      if (!hasPolicyCapability(policies, 'hasValidateJwt')) {
        findings.push(createFinding(
          'APIVET090',
          'Azure APIM missing validate-jwt policy',
          'No validate-jwt policy found at global or API level. Without JWT validation, APIM cannot verify bearer tokens, allowing unauthorized access.',
          'high',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Add <validate-jwt> inbound policy with header-name="Authorization". Configure required-claims, audiences, and issuers for Entra ID tokens.'
          }
        ));
      }

      return findings;
    }
  },

  // validate-jwt without audience/issuer validation
  {
    id: 'APIVET091',
    title: 'Azure APIM validate-jwt missing audience or issuer',
    description: 'validate-jwt should validate both audience and issuer claims',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      // Check at both levels
      for (const [level, policy] of Object.entries(policies)) {
        if (!policy?.jwtValidation) continue; // No JWT validation at this level

        const jwt = policy.jwtValidation;

        if (!jwt.hasAudiences) {
          findings.push(createFinding(
            'APIVET091',
            `Azure APIM validate-jwt at ${level} level missing audience validation`,
            `The validate-jwt policy at ${level} level does not validate the token audience (aud claim). Tokens issued for other applications could be accepted.`,
            'high',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Add <audiences><audience>your-app-id</audience></audiences> to the validate-jwt policy. Use the Application ID URI or Client ID.'
            }
          ));
        }

        if (!jwt.hasIssuers) {
          findings.push(createFinding(
            'APIVET091',
            `Azure APIM validate-jwt at ${level} level missing issuer validation`,
            `The validate-jwt policy at ${level} level does not validate the token issuer (iss claim). Tokens from any Entra ID tenant could be accepted.`,
            'high',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Add <issuers><issuer>https://sts.windows.net/{tenant-id}/</issuer></issuers> to the validate-jwt policy.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // APIM without rate limiting policy
  {
    id: 'APIVET092',
    title: 'Azure APIM missing rate limiting policy',
    description: 'Azure APIM should have rate-limit or rate-limit-by-key policy to prevent abuse',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      if (!hasPolicyCapability(policies, 'hasRateLimit')) {
        findings.push(createFinding(
          'APIVET092',
          'Azure APIM missing rate limiting policy',
          'No rate-limit or rate-limit-by-key policy found. Without rate limiting, APIs are vulnerable to brute force, DDoS, and resource exhaustion attacks.',
          'medium',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Add <rate-limit-by-key> inbound policy. Use counter-key="@(context.Subscription?.Key ?? context.Request.IpAddress)" for per-client limiting. Set appropriate calls and renewal-period values.'
          }
        ));
      }

      return findings;
    }
  },

  // APIM CORS wildcard origin
  {
    id: 'APIVET093',
    title: 'Azure APIM CORS policy allows all origins',
    description: 'CORS wildcard origin (*) allows any website to make API requests',
    severity: 'high',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      for (const [level, policy] of Object.entries(policies)) {
        if (!policy?.corsAllowAll) continue;

        const withCredentials = policy.corsConfig?.allowCredentials;

        findings.push(createFinding(
          'APIVET093',
          `Azure APIM CORS wildcard origin at ${level} level`,
          `The CORS policy at ${level} level allows all origins (*).${withCredentials ? ' Combined with allow-credentials="true", this is especially dangerous as it allows credential theft from any website.' : ' Any website can make cross-origin requests to this API.'}`,
          withCredentials ? 'critical' : 'high',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Replace wildcard origin with specific allowed origins. Example: <allowed-origins><origin>https://your-app.com</origin></allowed-origins>. Never use * with allow-credentials="true".'
          }
        ));
      }

      return findings;
    }
  },

  // APIM without IP filtering
  {
    id: 'APIVET094',
    title: 'Azure APIM without IP filtering policy',
    description: 'Consider restricting API access by IP address for internal/admin APIs',
    severity: 'low',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      // Only flag if there are paths that look like admin/internal endpoints
      const paths = Object.keys(spec.paths || {});
      const hasAdminPaths = paths.some(p => {
        const lower = p.toLowerCase();
        return lower.includes('/admin') || lower.includes('/internal') ||
               lower.includes('/management') || lower.includes('/config');
      });

      if (hasAdminPaths && !hasPolicyCapability(policies, 'hasIpFilter')) {
        findings.push(createFinding(
          'APIVET094',
          'Azure APIM admin/internal paths without IP filtering',
          'This API has admin/internal paths but no ip-filter policy. Sensitive endpoints should be restricted by IP address.',
          'low',
          {
            owaspCategory: 'API5:2023',
            filePath,
            remediation: 'Add <ip-filter action="allow"> inbound policy for admin paths. Specify allowed IP ranges for your organization. Combine with VNet integration for network-level isolation.'
          }
        ));
      }

      return findings;
    }
  },

  // APIM without backend authentication
  {
    id: 'APIVET095',
    title: 'Azure APIM without backend authentication',
    description: 'APIM should authenticate to backend services to prevent direct backend access bypass',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      // Check for any form of backend authentication
      const hasBackendAuth = (p: PolicyMeta | undefined) =>
        p?.hasAuthenticationManaged ||
        (spec as Record<string, unknown>)['x-azure-apim-authentication-certificate'] ||
        (spec as Record<string, unknown>)['x-azure-apim-authentication-basic'];

      const globalHasAuth = hasBackendAuth(policies.global);
      const apiHasAuth = hasBackendAuth(policies.api);

      if (!globalHasAuth && !apiHasAuth) {
        findings.push(createFinding(
          'APIVET095',
          'Azure APIM without backend authentication policy',
          'No authentication-managed-identity, authentication-certificate, or authentication-basic policy found. Backend services can be accessed directly bypassing APIM.',
          'medium',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Add <authentication-managed-identity> to authenticate to backends using Managed Identity. Alternatively, use client certificates or restrict backend to APIM VNet only.'
          }
        ));
      }

      return findings;
    }
  },

  // APIM without logging/monitoring
  {
    id: 'APIVET096',
    title: 'Azure APIM without logging policy',
    description: 'APIM should log API activity for security monitoring and forensics',
    severity: 'low',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      if (!hasPolicyCapability(policies, 'hasLog')) {
        findings.push(createFinding(
          'APIVET096',
          'Azure APIM without logging policy',
          'No log-to-eventhub or trace policy found. Without logging, security incidents cannot be detected or investigated.',
          'low',
          {
            owaspCategory: 'API9:2023',
            filePath,
            remediation: 'Enable Application Insights integration in APIM. Add <trace> policy for detailed request/response logging. Use <log-to-eventhub> for streaming to SIEM.'
          }
        ));
      }

      return findings;
    }
  },

  // APIM CORS with credentials
  {
    id: 'APIVET097',
    title: 'Azure APIM CORS allows credentials with broad origins',
    description: 'CORS with allow-credentials and non-restrictive origins enables credential theft',
    severity: 'high',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      for (const [level, policy] of Object.entries(policies)) {
        if (!policy?.corsConfig?.allowCredentials) continue;
        if (policy.corsAllowAll) continue; // Already caught by APIVET093

        // Check for overly broad origins (e.g., many origins or patterns)
        const origins = policy.corsConfig.allowedOrigins || [];
        const hasBroadOrigin = origins.some((o: string) =>
          o.includes('localhost') || o.includes('127.0.0.1') ||
          o.includes('.example.') || o.endsWith('.test')
        );

        if (hasBroadOrigin) {
          findings.push(createFinding(
            'APIVET097',
            `Azure APIM CORS at ${level} level allows credentials with development origins`,
            `The CORS policy at ${level} level has allow-credentials="true" with development/test origins (localhost, .example, .test). These should be removed in production.`,
            'high',
            {
              owaspCategory: 'API8:2023',
              filePath,
              remediation: 'Remove localhost and test origins from production CORS policy. Use environment-specific APIM configurations for dev/staging/prod.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // APIM JWT without required claims
  {
    id: 'APIVET098',
    title: 'Azure APIM validate-jwt without required claims',
    description: 'validate-jwt should check required claims for proper authorization',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAzureApim(spec.servers)) return findings;

      const policies = getPolicyData(spec as Record<string, unknown>);
      if (!policies) return findings;

      for (const [level, policy] of Object.entries(policies)) {
        if (!policy?.jwtValidation) continue;

        if (!policy.jwtValidation.hasRequiredClaims) {
          findings.push(createFinding(
            'APIVET098',
            `Azure APIM validate-jwt at ${level} level without required claims`,
            `The validate-jwt policy at ${level} level does not enforce required claims (e.g., roles, scp, groups). Without claim validation, any authenticated user can access any endpoint regardless of permissions.`,
            'medium',
            {
              owaspCategory: 'API5:2023',
              filePath,
              remediation: 'Add <required-claims> to validate-jwt. Example: <claim name="scp" match="any"><value>api.read</value></claim>. Use app roles for RBAC.'
            }
          ));
        }
      }

      return findings;
    }
  }
];

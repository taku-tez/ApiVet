/**
 * Azure API Management and Related Services Rules
 * APIVET030, APIVET039-040, APIVET056-065
 */

import type { OpenApiSpec, Finding } from '../types.js';
import {
  Rule,
  HTTP_METHODS,
  isAzureApim,
  isAzureService,
  hasGlobalSecurity,
  hasSecuritySchemes,
  createFinding,
  getResponseHeaderNames
} from './utils.js';

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

      const specStr = JSON.stringify(spec);

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
        if (scheme.type === 'openIdConnect' as any) {
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
  }
];

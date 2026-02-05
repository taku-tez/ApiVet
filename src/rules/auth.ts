/**
 * JWT and OAuth2 Authentication Rules
 * APIVET016 - APIVET025
 */

import type { Finding } from '../types.js';
import {
  Rule,
  HTTP_METHODS,
  SENSITIVE_ENDPOINT_PATTERNS,
  hasGlobalSecurity,
  isHttpUrl,
  isLocalhostUrl,
  createFinding
} from './utils.js';

export const authRules: Rule[] = [
  // OAuth2 Implicit Flow (deprecated)
  {
    id: 'APIVET016',
    title: 'OAuth2 Implicit Flow is deprecated',
    description: 'Implicit flow is deprecated per OAuth 2.0 Security Best Practice',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type === 'oauth2' && scheme.flows?.implicit) {
          findings.push(createFinding(
            'APIVET016',
            `OAuth2 Implicit Flow detected in "${name}"`,
            `Security scheme "${name}" uses deprecated Implicit flow. Access tokens are exposed in URL.`,
            'high',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Migrate to Authorization Code flow with PKCE for SPAs.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // OAuth2 Password Flow
  {
    id: 'APIVET017',
    title: 'OAuth2 Password Flow is discouraged',
    description: 'Password flow exposes credentials to the client',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type === 'oauth2' && scheme.flows?.password) {
          findings.push(createFinding(
            'APIVET017',
            `OAuth2 Password Flow detected in "${name}"`,
            `Security scheme "${name}" uses Password flow which requires sharing credentials with the client.`,
            'high',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Use Authorization Code flow with PKCE instead.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // OAuth2 HTTP endpoint
  {
    id: 'APIVET018',
    title: 'OAuth2 endpoint uses HTTP',
    description: 'OAuth2 endpoints must use HTTPS',
    severity: 'critical',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'oauth2' || !scheme.flows) continue;

        const urls: Array<{ type: string; url?: string }> = [
          { type: 'authorizationUrl', url: scheme.flows.implicit?.authorizationUrl },
          { type: 'authorizationUrl', url: scheme.flows.authorizationCode?.authorizationUrl },
          { type: 'tokenUrl', url: scheme.flows.authorizationCode?.tokenUrl },
          { type: 'tokenUrl', url: scheme.flows.password?.tokenUrl },
          { type: 'tokenUrl', url: scheme.flows.clientCredentials?.tokenUrl },
          { type: 'refreshUrl', url: scheme.flows.authorizationCode?.refreshUrl },
          { type: 'refreshUrl', url: scheme.flows.password?.refreshUrl },
          { type: 'refreshUrl', url: scheme.flows.clientCredentials?.refreshUrl }
        ];

        for (const { type, url } of urls) {
          if (url && isHttpUrl(url) && !isLocalhostUrl(url)) {
            findings.push(createFinding(
              'APIVET018',
              `OAuth2 ${type} uses HTTP in "${name}"`,
              `The OAuth2 ${type} "${url}" uses HTTP. Tokens are exposed to interception.`,
              'critical',
              {
                owaspCategory: 'API2:2023',
                filePath,
                remediation: 'Always use HTTPS for OAuth2 endpoints.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API Key in query
  {
    id: 'APIVET019',
    title: 'API Key in URL query parameter',
    description: 'API keys in query parameters may be logged insecurely',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type === 'apiKey' && scheme.in === 'query') {
          findings.push(createFinding(
            'APIVET019',
            `API Key in query parameter "${name}"`,
            `Security scheme "${name}" transmits API key in URL query "${scheme.name}". May be logged.`,
            'medium',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Transmit API keys in HTTP headers instead.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // OAuth2 broad scopes
  {
    id: 'APIVET020',
    title: 'OAuth2 potentially overly broad scopes',
    description: 'OAuth2 scopes should follow least privilege',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};
      const broadPatterns = ['admin', 'root', 'superuser', 'all', '*', 'full_access', 'full-access'];

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'oauth2' || !scheme.flows) continue;

        const allScopes: string[] = [];
        for (const flow of Object.values(scheme.flows)) {
          if (flow?.scopes) {
            allScopes.push(...Object.keys(flow.scopes));
          }
        }

        for (const scope of allScopes) {
          if (broadPatterns.some(p => scope.toLowerCase().includes(p))) {
            findings.push(createFinding(
              'APIVET020',
              `Potentially overly broad OAuth2 scope "${scope}"`,
              `Scope "${scope}" in "${name}" may grant excessive permissions.`,
              'medium',
              {
                owaspCategory: 'API5:2023',
                filePath,
                remediation: 'Define granular scopes with minimum permissions.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // OpenID Connect HTTP
  {
    id: 'APIVET021',
    title: 'OpenID Connect URL uses HTTP',
    description: 'OIDC discovery endpoints must use HTTPS',
    severity: 'critical',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type === 'openIdConnect' && scheme.openIdConnectUrl) {
          if (isHttpUrl(scheme.openIdConnectUrl) && !isLocalhostUrl(scheme.openIdConnectUrl)) {
            findings.push(createFinding(
              'APIVET021',
              `OpenID Connect URL uses HTTP in "${name}"`,
              `OIDC discovery URL "${scheme.openIdConnectUrl}" uses HTTP. Attackers can redirect auth.`,
              'critical',
              {
                owaspCategory: 'API2:2023',
                filePath,
                remediation: 'Always use HTTPS for OpenID Connect URLs.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // JWT weak algorithm
  {
    id: 'APIVET022',
    title: 'JWT weak algorithm indication',
    description: 'JWT should use strong signing algorithms',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};
      const weakAlgs = ['none', 'hs256', 'hs384', 'hs512'];

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'http' || scheme.scheme?.toLowerCase() !== 'bearer') continue;

        const description = (scheme.description || '').toLowerCase();
        const bearerFormat = (scheme.bearerFormat || '').toLowerCase();

        if (!description.includes('jwt') && !bearerFormat.includes('jwt')) continue;

        for (const alg of weakAlgs) {
          if (description.includes(alg) || bearerFormat.includes(alg)) {
            const isNone = alg === 'none';
            findings.push(createFinding(
              'APIVET022',
              isNone
                ? `JWT "none" algorithm mentioned in "${name}"`
                : `JWT symmetric algorithm ${alg.toUpperCase()} mentioned in "${name}"`,
              isNone
                ? `Security scheme "${name}" mentions JWT "none" algorithm. No signature verification.`
                : `Security scheme "${name}" mentions ${alg.toUpperCase()}. Symmetric algorithms share secrets.`,
              isNone ? 'critical' : 'medium',
              {
                owaspCategory: 'API2:2023',
                filePath,
                remediation: isNone
                  ? 'Never accept JWTs with "alg": "none".'
                  : 'Consider asymmetric algorithms like RS256 or ES256.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // OAuth2 missing refresh URL
  {
    id: 'APIVET023',
    title: 'OAuth2 flow without refresh URL',
    description: 'OAuth2 flows should define refresh endpoints',
    severity: 'low',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type !== 'oauth2' || !scheme.flows) continue;

        const flowsNeedingRefresh = [
          { name: 'authorizationCode', flow: scheme.flows.authorizationCode },
          { name: 'password', flow: scheme.flows.password }
        ];

        for (const { name: flowName, flow } of flowsNeedingRefresh) {
          if (flow && !flow.refreshUrl) {
            findings.push(createFinding(
              'APIVET023',
              `OAuth2 ${flowName} flow missing refresh URL in "${name}"`,
              `The ${flowName} flow in "${name}" has no refreshUrl. Tokens may have long lifetimes.`,
              'low',
              {
                owaspCategory: 'API2:2023',
                filePath,
                remediation: 'Define refreshUrl and use short-lived access tokens with rotation.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // Sensitive endpoint without explicit security
  {
    id: 'APIVET024',
    title: 'Sensitive endpoint relies on global security only',
    description: 'High-risk endpoints should have explicit security',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        const isSensitive = SENSITIVE_ENDPOINT_PATTERNS.some(p => path.toLowerCase().includes(p));
        if (!isSensitive) continue;

        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation) continue;

          const hasGlobal = hasGlobalSecurity(spec);
          const hasOp = operation.security && operation.security.length > 0;

          if (hasGlobal && !hasOp) {
            findings.push(createFinding(
              'APIVET024',
              `Sensitive endpoint ${method.toUpperCase()} ${path} uses implicit global security`,
              `${method.toUpperCase()} ${path} handles sensitive operations but relies on global security only.`,
              'medium',
              {
                owaspCategory: 'API5:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Add explicit security requirements for clarity and defense in depth.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // Cookie auth
  {
    id: 'APIVET025',
    title: 'API Key in cookie',
    description: 'Cookie authentication requires proper security attributes',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type === 'apiKey' && scheme.in === 'cookie') {
          findings.push(createFinding(
            'APIVET025',
            `Cookie-based authentication in "${name}"`,
            `Security scheme "${name}" uses cookies. Ensure Secure, HttpOnly, SameSite attributes.`,
            'medium',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Set Secure, HttpOnly, SameSite=Strict/Lax. Consider token-based auth for APIs.'
            }
          ));
        }
      }

      return findings;
    }
  }
];

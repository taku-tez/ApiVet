/**
 * OWASP API Security Top 10 2023 - Core Rules
 * APIVET001 - APIVET015
 */

import type { OpenApiSpec, Finding } from '../types.js';
import {
  Rule,
  HTTP_METHODS,
  SENSITIVE_PROPERTY_PATTERNS,
  ADMIN_ENDPOINT_PATTERNS,
  URL_PARAM_PATTERNS,
  QUERY_INJECTION_PATTERNS,
  hasGlobalSecurity,
  isHttpUrl,
  isLocalhostUrl,
  createFinding,
  getJsonSchemasFromContent,
  collectSchemaProperties
} from './utils.js';

export const owaspRules: Rule[] = [
  // API1:2023 - Broken Object Level Authorization
  {
    id: 'APIVET001',
    title: 'Missing object-level authorization check',
    description: 'Endpoints with path parameters should implement object-level authorization',
    severity: 'high',
    owaspCategory: 'API1:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        if (!/{[^}]+}/.test(path)) continue;

        for (const method of ['get', 'put', 'delete', 'patch'] as const) {
          const operation = pathItem[method];
          if (!operation) continue;

          const hasOpSecurity = operation.security && operation.security.length > 0;
          if (!hasOpSecurity && !hasGlobalSecurity(spec)) {
            findings.push(createFinding(
              'APIVET001',
              'Endpoint with object reference lacks security definition',
              `The endpoint ${method.toUpperCase()} ${path} uses path parameters but has no security defined. This may lead to BOLA vulnerabilities.`,
              'high',
              {
                owaspCategory: 'API1:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Add security requirements and implement proper authorization checks.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API2:2023 - Broken Authentication (Basic Auth)
  {
    id: 'APIVET002',
    title: 'Weak authentication scheme',
    description: 'API uses basic authentication which is easily decodable',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type === 'http' && scheme.scheme?.toLowerCase() === 'basic') {
          findings.push(createFinding(
            'APIVET002',
            'Basic authentication detected',
            `Security scheme "${name}" uses HTTP Basic authentication which transmits credentials in Base64.`,
            'high',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Use OAuth 2.0 with JWT tokens or API keys in secure headers.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // API2:2023 - No authentication
  {
    id: 'APIVET003',
    title: 'No authentication defined',
    description: 'API specification has no security schemes defined',
    severity: 'critical',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes;
      const paths = spec.paths || {};

      if ((!schemes || Object.keys(schemes).length === 0) && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET003',
          'No security schemes defined',
          'The API specification does not define any security schemes. All endpoints are effectively public.',
          'critical',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Define security schemes in components.securitySchemes and apply them to endpoints.'
          }
        ));
      }

      return findings;
    }
  },

  // API3:2023 - Sensitive data exposure
  {
    id: 'APIVET004',
    title: 'Sensitive data in response',
    description: 'Response may expose sensitive properties',
    severity: 'medium',
    owaspCategory: 'API3:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const reportedProps = new Set<string>(); // Avoid duplicate findings for same property

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post', 'put', 'patch'] as const) {
          const operation = pathItem[method];
          if (!operation?.responses) continue;

          for (const response of Object.values(operation.responses)) {
            // FB5 & FB6: Get all JSON schemas (application/json, application/*+json, etc.)
            const schemas = getJsonSchemasFromContent(response.content);
            
            for (const schema of schemas) {
              // FB5: Collect all properties including $ref resolved and nested
              const allProps = collectSchemaProperties(schema, spec);
              
              for (const propName of allProps) {
                const lower = propName.toLowerCase();
                const findingKey = `${path}:${method}:${propName}`;
                
                if (SENSITIVE_PROPERTY_PATTERNS.some(p => lower.includes(p)) && !reportedProps.has(findingKey)) {
                  reportedProps.add(findingKey);
                  findings.push(createFinding(
                    'APIVET004',
                    `Potentially sensitive property "${propName}" in response`,
                    `Response includes "${propName}" which may contain sensitive data.`,
                    'medium',
                    {
                      owaspCategory: 'API3:2023',
                      filePath,
                      endpoint: path,
                      method: method.toUpperCase(),
                      remediation: 'Implement response filtering based on user authorization level.'
                    }
                  ));
                }
              }
            }
          }
        }
      }

      return findings;
    }
  },

  // API4:2023 - Rate limiting
  {
    id: 'APIVET005',
    title: 'No rate limiting indication',
    description: 'API does not indicate rate limiting',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      let hasRateLimit = false;

      for (const pathItem of Object.values(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          const responses = operation?.responses;
          if (!responses) continue;

          for (const response of Object.values(responses)) {
            if (response.headers) {
              const headerNames = Object.keys(response.headers).map(h => h.toLowerCase());
              if (headerNames.some(h => h.includes('ratelimit') || h.includes('rate-limit') || h.includes('retry-after'))) {
                hasRateLimit = true;
              }
            }
          }
        }
      }

      if (!hasRateLimit && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET005',
          'No rate limiting headers documented',
          'The API does not document rate limiting headers.',
          'medium',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Implement rate limiting with X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After headers.'
          }
        ));
      }

      return findings;
    }
  },

  // API4:2023 - Pagination
  {
    id: 'APIVET006',
    title: 'List endpoint without pagination',
    description: 'Collection endpoints should implement pagination',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const collectionPattern = /\/(users|items|products|orders|posts|comments|articles|resources|records|entries|data)$/i;
      const paginationParams = ['page', 'limit', 'offset', 'cursor', 'per_page', 'page_size', 'pagesize', 'skip', 'take'];

      for (const [path, pathItem] of Object.entries(paths)) {
        const operation = pathItem.get;
        if (!operation || !collectionPattern.test(path)) continue;

        const params = [...(pathItem.parameters || []), ...(operation.parameters || [])];
        const paramNames = params.map(p => p.name.toLowerCase());
        const hasPagination = paramNames.some(n => paginationParams.includes(n));

        if (!hasPagination) {
          findings.push(createFinding(
            'APIVET006',
            'Collection endpoint without pagination parameters',
            `GET ${path} appears to return a collection but lacks pagination.`,
            'medium',
            {
              owaspCategory: 'API4:2023',
              filePath,
              endpoint: path,
              method: 'GET',
              remediation: 'Implement pagination with page, limit, offset, or cursor parameters.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // API5:2023 - Admin endpoint
  {
    id: 'APIVET007',
    title: 'Admin endpoint potentially exposed',
    description: 'Administrative endpoints should have strict access controls',
    severity: 'high',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        if (!ADMIN_ENDPOINT_PATTERNS.some(p => path.toLowerCase().includes(p))) continue;

        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation) continue;

          const hasSecurity = (operation.security && operation.security.length > 0) || hasGlobalSecurity(spec);
          if (!hasSecurity) {
            findings.push(createFinding(
              'APIVET007',
              'Administrative endpoint without security',
              `${method.toUpperCase()} ${path} appears to be administrative but has no security.`,
              'high',
              {
                owaspCategory: 'API5:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Apply strict access controls and require elevated privileges.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API7:2023 - SSRF
  {
    id: 'APIVET008',
    title: 'URL parameter may enable SSRF',
    description: 'Parameters accepting URLs could be exploited for SSRF',
    severity: 'high',
    owaspCategory: 'API7:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post', 'put', 'patch'] as const) {
          const operation = pathItem[method];
          if (!operation) continue;

          const allParams = [...(pathItem.parameters || []), ...(operation.parameters || [])];
          for (const param of allParams) {
            const lower = param.name.toLowerCase();
            if (URL_PARAM_PATTERNS.some(p => lower.includes(p))) {
              if (param.schema?.format === 'uri' || param.schema?.type === 'string') {
                findings.push(createFinding(
                  'APIVET008',
                  `URL parameter "${param.name}" may enable SSRF`,
                  `Parameter "${param.name}" in ${method.toUpperCase()} ${path} accepts URLs.`,
                  'high',
                  {
                    owaspCategory: 'API7:2023',
                    filePath,
                    endpoint: path,
                    method: method.toUpperCase(),
                    remediation: 'Validate URLs, use allowlists, disable redirects, restrict internal network access.'
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

  // API8:2023 - HTTP instead of HTTPS
  {
    id: 'APIVET009',
    title: 'Server URL uses HTTP',
    description: 'API servers should use HTTPS',
    severity: 'high',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      for (const server of servers) {
        if (isHttpUrl(server.url) && !isLocalhostUrl(server.url)) {
          findings.push(createFinding(
            'APIVET009',
            'Non-HTTPS server URL',
            `Server URL "${server.url}" uses HTTP. Data is not encrypted.`,
            'high',
            {
              owaspCategory: 'API8:2023',
              filePath,
              remediation: 'Configure HTTPS and update the server URL.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // API8:2023 - CORS
  {
    id: 'APIVET010',
    title: 'CORS configuration detected',
    description: 'Verify CORS is not overly permissive',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        if (!pathItem.options?.responses) continue;

        for (const response of Object.values(pathItem.options.responses)) {
          if (response.headers) {
            const headerNames = Object.keys(response.headers).map(h => h.toLowerCase());
            if (headerNames.includes('access-control-allow-origin')) {
              findings.push(createFinding(
                'APIVET010',
                'CORS configuration detected - verify not overly permissive',
                `OPTIONS ${path} includes CORS headers. Ensure not set to "*" for sensitive endpoints.`,
                'info',
                {
                  owaspCategory: 'API8:2023',
                  filePath,
                  endpoint: path,
                  method: 'OPTIONS',
                  remediation: 'Restrict Access-Control-Allow-Origin to specific trusted domains.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // API9:2023 - Deprecated endpoints
  {
    id: 'APIVET011',
    title: 'Deprecated endpoint',
    description: 'Deprecated endpoints should be removed',
    severity: 'low',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (operation?.deprecated) {
            findings.push(createFinding(
              'APIVET011',
              'Deprecated endpoint in specification',
              `${method.toUpperCase()} ${path} is deprecated. Consider removal.`,
              'low',
              {
                owaspCategory: 'API9:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Create deprecation timeline and remove deprecated endpoints.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API9:2023 - Multiple versions
  {
    id: 'APIVET012',
    title: 'Multiple API versions',
    description: 'Multiple versions may indicate improper version management',
    severity: 'info',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = Object.keys(spec.paths || {});
      const versions = new Set<string>();

      for (const path of paths) {
        const match = path.match(/\/v(\d+)/i);
        if (match) versions.add(match[1]);
      }

      if (versions.size > 1) {
        findings.push(createFinding(
          'APIVET012',
          'Multiple API versions in specification',
          `Found ${versions.size} versions (${[...versions].map(v => 'v' + v).join(', ')}).`,
          'info',
          {
            owaspCategory: 'API9:2023',
            filePath,
            remediation: 'Maintain clear version strategy. Deprecate and remove old versions.'
          }
        ));
      }

      return findings;
    }
  },

  // API8:2023 - Query injection
  {
    id: 'APIVET013',
    title: 'Query parameter may be vulnerable to injection',
    description: 'Parameters for filtering/searching should be validated',
    severity: 'medium',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        const operation = pathItem.get;
        if (!operation) continue;

        const allParams = [...(pathItem.parameters || []), ...(operation.parameters || [])];
        for (const param of allParams) {
          const lower = param.name.toLowerCase();
          if (QUERY_INJECTION_PATTERNS.some(p => lower.includes(p))) {
            if (!param.schema?.pattern && !param.schema?.enum && param.schema?.type === 'string') {
              findings.push(createFinding(
                'APIVET013',
                `Query parameter "${param.name}" lacks input validation`,
                `Parameter "${param.name}" in GET ${path} has no pattern or enum constraint.`,
                'medium',
                {
                  owaspCategory: 'API8:2023',
                  filePath,
                  endpoint: path,
                  method: 'GET',
                  remediation: 'Add pattern (regex), enum, or maxLength constraints. Use parameterized queries.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // API3:2023 - Mass assignment
  {
    id: 'APIVET014',
    title: 'Request body without schema',
    description: 'Request bodies should have explicit schemas',
    severity: 'medium',
    owaspCategory: 'API3:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['post', 'put', 'patch'] as const) {
          const operation = pathItem[method];
          if (!operation?.requestBody) continue;

          const content = operation.requestBody.content?.['application/json'];
          if (content && !content.schema) {
            findings.push(createFinding(
              'APIVET014',
              'Request body without schema definition',
              `${method.toUpperCase()} ${path} accepts JSON but has no schema. May allow mass assignment.`,
              'medium',
              {
                owaspCategory: 'API3:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Define explicit schemas listing only accepted properties.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API2:2023 - Bearer token
  {
    id: 'APIVET015',
    title: 'Bearer token security considerations',
    description: 'APIs using Bearer tokens should implement proper token management',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        if (scheme.type === 'http' && scheme.scheme?.toLowerCase() === 'bearer') {
          findings.push(createFinding(
            'APIVET015',
            'Bearer token authentication - ensure proper token management',
            `Security scheme "${name}" uses Bearer tokens. Ensure proper expiration and refresh.`,
            'info',
            {
              owaspCategory: 'API2:2023',
              filePath,
              remediation: 'Implement short-lived access tokens with refresh token rotation.'
            }
          ));
        }
      }

      return findings;
    }
  }
];

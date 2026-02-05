/**
 * OWASP API Security Top 10 2023 - Core Rules
 * APIVET001 - APIVET015
 */

import type { Finding } from '../types.js';
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
  collectSchemaProperties,
  getResponseHeaderNames,
  hasJsonContentWithoutSchema
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
            // FB4: Use helper to resolve $ref in headers
            const headerNames = getResponseHeaderNames(response, spec);
            if (headerNames.some(h => h.includes('ratelimit') || h.includes('rate-limit') || h.includes('retry-after'))) {
              hasRateLimit = true;
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
          // FB4: Use helper to resolve $ref in headers
          const headerNames = getResponseHeaderNames(response, spec);
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

          // FB3: Check all JSON-compatible content types, resolve $ref
          if (hasJsonContentWithoutSchema(operation.requestBody, spec)) {
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
  },

  // ============================================
  // API6:2023 - Unrestricted Access to Sensitive Business Flows
  // ============================================

  // API6:2023 - Sensitive business flow without rate limiting
  {
    id: 'APIVET084',
    title: 'Sensitive business flow without rate limiting',
    description: 'Sensitive business endpoints should implement rate limiting to prevent abuse',
    severity: 'high',
    owaspCategory: 'API6:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      const sensitivePatterns = [
        'signup', 'register', 'login', 'signin', 'checkout', 'purchase',
        'payment', 'transfer', 'withdraw', 'vote', 'verify', 'confirm',
        'reset-password', 'forgot-password', 'reset_password', 'forgot_password',
        'otp', 'mfa', 'totp', '2fa'
      ];

      for (const [path, pathItem] of Object.entries(paths)) {
        const pathLower = path.toLowerCase();
        const isSensitive = sensitivePatterns.some(p => pathLower.includes(p));
        if (!isSensitive) continue;

        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation) continue;

          const responses = operation.responses || {};
          const has429 = '429' in responses;
          
          // Check for rate limit headers in any response
          let hasRateLimitHeader = false;
          for (const response of Object.values(responses)) {
            // eslint-disable-next-line @typescript-eslint/no-explicit-any -- Response type varies
            const headerNames = getResponseHeaderNames(response as any, spec);
            if (headerNames.some(h => 
              h.includes('ratelimit') || 
              h.includes('rate-limit') || 
              h.includes('retry-after') ||
              h.includes('x-rate-limit')
            )) {
              hasRateLimitHeader = true;
              break;
            }
          }

          if (!has429 && !hasRateLimitHeader) {
            findings.push(createFinding(
              'APIVET084',
              'Sensitive business flow without rate limiting',
              `${method.toUpperCase()} ${path} is a sensitive business endpoint but lacks rate limiting (no 429 response or rate-limit headers).`,
              'high',
              {
                owaspCategory: 'API6:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Implement rate limiting with 429 responses and X-RateLimit-* headers to prevent automated abuse.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API6:2023 - No CAPTCHA/bot protection indication
  {
    id: 'APIVET085',
    title: 'No CAPTCHA/bot protection indication',
    description: 'Sensitive business endpoints should indicate bot protection mechanisms',
    severity: 'medium',
    owaspCategory: 'API6:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      const sensitivePatterns = [
        'signup', 'register', 'login', 'signin', 'checkout', 'purchase',
        'payment', 'transfer', 'vote', 'reset-password', 'forgot-password',
        'reset_password', 'forgot_password'
      ];
      
      const botProtectionKeywords = [
        'captcha', 'recaptcha', 'hcaptcha', 'turnstile', 'bot-protection',
        'bot_protection', 'challenge', 'human-verification', 'human_verification'
      ];

      for (const [path, pathItem] of Object.entries(paths)) {
        const pathLower = path.toLowerCase();
        const isSensitive = sensitivePatterns.some(p => pathLower.includes(p));
        if (!isSensitive) continue;

        for (const method of ['post'] as const) {
          const operation = pathItem[method];
          if (!operation) continue;

          // Check description
          const opDescription = (operation.description || '').toLowerCase();
          const opSummary = (operation.summary || '').toLowerCase();
          
          // Check parameters
          const params = [...(pathItem.parameters || []), ...(operation.parameters || [])];
          const paramText = params.map(p => `${p.name} ${p.description || ''}`).join(' ').toLowerCase();
          
          // Check for x-* extensions
          const extSpec = operation as Record<string, unknown>;
          const extensionText = Object.entries(extSpec)
            .filter(([k]) => k.startsWith('x-'))
            .map(([_, v]) => JSON.stringify(v))
            .join(' ')
            .toLowerCase();
          
          const allText = `${opDescription} ${opSummary} ${paramText} ${extensionText}`;
          const hasBotProtection = botProtectionKeywords.some(k => allText.includes(k));

          if (!hasBotProtection) {
            findings.push(createFinding(
              'APIVET085',
              'No CAPTCHA/bot protection indication',
              `${method.toUpperCase()} ${path} is a sensitive business endpoint but does not indicate bot protection (CAPTCHA, reCAPTCHA, hCaptcha, Turnstile).`,
              'medium',
              {
                owaspCategory: 'API6:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Implement CAPTCHA or bot protection to prevent automated abuse of sensitive business flows.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API6:2023 - Signup/registration without duplicate check
  {
    id: 'APIVET086',
    title: 'Signup/registration without duplicate check',
    description: 'Registration endpoints should define 409 Conflict response for duplicate accounts',
    severity: 'low',
    owaspCategory: 'API6:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      const signupPatterns = ['signup', 'register', 'registration', 'create-account', 'create_account'];

      for (const [path, pathItem] of Object.entries(paths)) {
        const pathLower = path.toLowerCase();
        const isSignup = signupPatterns.some(p => pathLower.includes(p));
        if (!isSignup) continue;

        const operation = pathItem.post;
        if (!operation) continue;

        const responses = operation.responses || {};
        const has409 = '409' in responses;

        if (!has409) {
          findings.push(createFinding(
            'APIVET086',
            'Signup/registration without duplicate check',
            `POST ${path} is a registration endpoint but does not define 409 Conflict response for duplicate accounts.`,
            'low',
            {
              owaspCategory: 'API6:2023',
              filePath,
              endpoint: path,
              method: 'POST',
              remediation: 'Add 409 Conflict response to indicate duplicate account handling.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // ============================================
  // API10:2023 - Unsafe Consumption of APIs
  // ============================================

  // API10:2023 - External API call without timeout indication
  {
    id: 'APIVET087',
    title: 'External API call without timeout indication',
    description: 'Endpoints calling external APIs via callbacks/webhooks should indicate timeout handling',
    severity: 'medium',
    owaspCategory: 'API10:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      const callbackParamPatterns = [
        'callback_url', 'callbackurl', 'webhook_url', 'webhookurl',
        'redirect_uri', 'redirecturi', 'notify_url', 'notifyurl',
        'callback', 'webhook', 'notification_url', 'notificationurl'
      ];
      
      const timeoutKeywords = ['timeout', 'time-out', 'time_out', 'retry', 'retries', 'max-wait', 'max_wait'];

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method];
          if (!operation) continue;

          // Check parameters for callback/webhook URL fields
          const params = [...(pathItem.parameters || []), ...(operation.parameters || [])];
          const hasCallbackParam = params.some(p => 
            callbackParamPatterns.some(pattern => p.name.toLowerCase().includes(pattern))
          );

          // Check request body for callback/webhook URL fields
          let hasCallbackInBody = false;
          const requestBody = operation.requestBody as { content?: Record<string, { schema?: unknown }> } | undefined;
          if (requestBody?.content) {
            for (const mediaType of Object.values(requestBody.content)) {
              if (mediaType.schema) {
                const props = collectSchemaProperties(mediaType.schema, spec);
                hasCallbackInBody = props.some(prop => 
                  callbackParamPatterns.some(pattern => prop.toLowerCase().includes(pattern))
                );
                if (hasCallbackInBody) break;
              }
            }
          }

          if (!hasCallbackParam && !hasCallbackInBody) continue;

          // Check if timeout is mentioned anywhere
          const opDescription = (operation.description || '').toLowerCase();
          const opSummary = (operation.summary || '').toLowerCase();
          const extSpec = operation as Record<string, unknown>;
          const extensionText = Object.entries(extSpec)
            .filter(([k]) => k.startsWith('x-'))
            .map(([_, v]) => JSON.stringify(v))
            .join(' ')
            .toLowerCase();
          
          const allText = `${opDescription} ${opSummary} ${extensionText}`;
          const hasTimeout = timeoutKeywords.some(k => allText.includes(k));

          if (!hasTimeout) {
            findings.push(createFinding(
              'APIVET087',
              'External API call without timeout indication',
              `${method.toUpperCase()} ${path} accepts callback/webhook URLs but does not indicate timeout handling for external calls.`,
              'medium',
              {
                owaspCategory: 'API10:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Document timeout and retry policies for external API calls. Implement proper timeout handling.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API10:2023 - Webhook/callback without signature verification
  {
    id: 'APIVET088',
    title: 'Webhook/callback without signature verification',
    description: 'Webhook/callback endpoints should implement signature verification',
    severity: 'high',
    owaspCategory: 'API10:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      const webhookPathPatterns = ['webhook', 'callback', 'hook', 'notify', 'notification'];
      const signatureKeywords = [
        'signature', 'hmac', 'sha256', 'sha-256', 'verify', 'validation',
        'x-signature', 'x-hub-signature', 'x-webhook-signature', 'x-hook-signature'
      ];

      for (const [path, pathItem] of Object.entries(paths)) {
        const pathLower = path.toLowerCase();
        const isWebhook = webhookPathPatterns.some(p => pathLower.includes(p));
        if (!isWebhook) continue;

        for (const method of ['post', 'put'] as const) {
          const operation = pathItem[method];
          if (!operation) continue;

          // Check description and summary
          const opDescription = (operation.description || '').toLowerCase();
          const opSummary = (operation.summary || '').toLowerCase();
          
          // Check parameters for signature headers
          const params = [...(pathItem.parameters || []), ...(operation.parameters || [])];
          const hasSignatureParam = params.some(p => 
            signatureKeywords.some(k => p.name.toLowerCase().includes(k))
          );
          
          // Check extensions
          const extSpec = operation as Record<string, unknown>;
          const extensionText = Object.entries(extSpec)
            .filter(([k]) => k.startsWith('x-'))
            .map(([_, v]) => JSON.stringify(v))
            .join(' ')
            .toLowerCase();
          
          const allText = `${opDescription} ${opSummary} ${extensionText}`;
          const hasSignatureMention = signatureKeywords.some(k => allText.includes(k));

          if (!hasSignatureParam && !hasSignatureMention) {
            findings.push(createFinding(
              'APIVET088',
              'Webhook/callback without signature verification',
              `${method.toUpperCase()} ${path} appears to be a webhook endpoint but does not indicate signature verification.`,
              'high',
              {
                owaspCategory: 'API10:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Implement HMAC signature verification (X-Hub-Signature, X-Webhook-Signature) to validate webhook requests.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // API10:2023 - Third-party API integration without TLS
  {
    id: 'APIVET089',
    title: 'Third-party API integration without TLS',
    description: 'External API integrations should use HTTPS',
    severity: 'high',
    owaspCategory: 'API10:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      // Patterns suggesting third-party/external API
      const externalPatterns = [
        /\.api\./i,  // anything.api.something
        /api\./i,    // api.something
        /webhook/i,
        /callback/i,
        /integration/i,
        /third-party/i,
        /thirdparty/i,
        /external/i
      ];

      for (const server of servers) {
        const url = server.url;
        
        // Skip if not HTTP
        if (!isHttpUrl(url)) continue;
        
        // Skip localhost
        if (isLocalhostUrl(url)) continue;
        
        // Check if URL suggests external/third-party API
        const isExternal = externalPatterns.some(p => p.test(url)) ||
          (server.description && externalPatterns.some(p => p.test(server.description || '')));

        if (isExternal) {
          findings.push(createFinding(
            'APIVET089',
            'Third-party API integration without TLS',
            `Server "${url}" appears to be an external API integration using HTTP instead of HTTPS.`,
            'high',
            {
              owaspCategory: 'API10:2023',
              filePath,
              remediation: 'Use HTTPS for all third-party API integrations to ensure data is encrypted in transit.'
            }
          ));
        }
      }

      return findings;
    }
  }
];

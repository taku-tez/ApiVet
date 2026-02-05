import type { Finding, OpenApiSpec, Severity } from '../types.js';

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  owaspCategory?: string;
  check: (spec: OpenApiSpec, filePath: string) => Finding[];
}

export const rules: Rule[] = [
  // API1:2023 - Broken Object Level Authorization
  {
    id: 'APIVET001',
    title: 'Missing object-level authorization check',
    description: 'Endpoints with path parameters (e.g., /users/{id}) should implement object-level authorization',
    severity: 'high',
    owaspCategory: 'API1:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        // Check for path parameters like {id}, {userId}, etc.
        if (/{[^}]+}/.test(path)) {
          const methods = ['get', 'put', 'delete', 'patch'] as const;
          for (const method of methods) {
            const operation = pathItem[method];
            if (operation && (!operation.security || operation.security.length === 0)) {
              // Check if global security is defined
              if (!spec.security || spec.security.length === 0) {
                findings.push({
                  ruleId: 'APIVET001',
                  title: 'Endpoint with object reference lacks security definition',
                  description: `The endpoint ${method.toUpperCase()} ${path} uses path parameters but has no security defined. This may lead to Broken Object Level Authorization (BOLA) vulnerabilities.`,
                  severity: 'high',
                  owaspCategory: 'API1:2023',
                  location: {
                    path: filePath,
                    endpoint: path,
                    method: method.toUpperCase()
                  },
                  remediation: 'Add security requirements and implement proper authorization checks to verify the user has access to the requested object.'
                });
              }
            }
          }
        }
      }
      
      return findings;
    }
  },

  // API2:2023 - Broken Authentication
  {
    id: 'APIVET002',
    title: 'Weak authentication scheme',
    description: 'API uses basic authentication which transmits credentials in easily decodable format',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'http' && scheme.scheme?.toLowerCase() === 'basic') {
          findings.push({
            ruleId: 'APIVET002',
            title: 'Basic authentication detected',
            description: `Security scheme "${name}" uses HTTP Basic authentication. Basic auth transmits credentials in Base64 encoding which is easily decoded.`,
            severity: 'high',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Consider using more secure authentication methods such as OAuth 2.0 with JWT tokens, or API keys transmitted via secure headers.'
          });
        }
      }
      
      return findings;
    }
  },

  // API2:2023 - No authentication defined
  {
    id: 'APIVET003',
    title: 'No authentication defined',
    description: 'API specification has no security schemes defined',
    severity: 'critical',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes;
      
      if (!securitySchemes || Object.keys(securitySchemes).length === 0) {
        // Check if there are any paths that might need auth
        const paths = spec.paths || {};
        if (Object.keys(paths).length > 0) {
          findings.push({
            ruleId: 'APIVET003',
            title: 'No security schemes defined',
            description: 'The API specification does not define any security schemes. All endpoints are effectively public.',
            severity: 'critical',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Define appropriate security schemes in components.securitySchemes and apply them to endpoints that require authentication.'
          });
        }
      }
      
      return findings;
    }
  },

  // API3:2023 - Broken Object Property Level Authorization
  {
    id: 'APIVET004',
    title: 'Sensitive data in response without filtering',
    description: 'Response may expose sensitive properties that should be filtered based on user role',
    severity: 'medium',
    owaspCategory: 'API3:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const sensitivePatterns = [
        'password', 'secret', 'token', 'apikey', 'api_key', 
        'private', 'ssn', 'social_security', 'credit_card',
        'creditcard', 'cvv', 'pin', 'salary', 'income'
      ];
      
      const checkSchema = (schema: any, endpoint: string, method: string): void => {
        if (!schema?.properties) return;
        
        for (const [propName, propSchema] of Object.entries(schema.properties)) {
          const lowerName = propName.toLowerCase();
          if (sensitivePatterns.some(p => lowerName.includes(p))) {
            findings.push({
              ruleId: 'APIVET004',
              title: `Potentially sensitive property "${propName}" in response`,
              description: `The response schema includes a property "${propName}" that may contain sensitive data. Ensure proper filtering based on user authorization level.`,
              severity: 'medium',
              owaspCategory: 'API3:2023',
              location: {
                path: filePath,
                endpoint,
                method
              },
              remediation: 'Implement response filtering to exclude sensitive properties based on the requesting user\'s authorization level.'
            });
          }
        }
      };
      
      const paths = spec.paths || {};
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['get', 'post', 'put', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method];
          if (operation?.responses) {
            for (const [code, response] of Object.entries(operation.responses)) {
              if (response.content?.['application/json']?.schema) {
                checkSchema(response.content['application/json'].schema, path, method.toUpperCase());
              }
            }
          }
        }
      }
      
      return findings;
    }
  },

  // API4:2023 - Unrestricted Resource Consumption
  {
    id: 'APIVET005',
    title: 'No rate limiting indication',
    description: 'API does not indicate rate limiting in responses',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      let hasRateLimitHeader = false;
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method];
          if (operation?.responses) {
            for (const response of Object.values(operation.responses)) {
              if (response.headers) {
                const headerNames = Object.keys(response.headers).map(h => h.toLowerCase());
                if (headerNames.some(h => 
                  h.includes('ratelimit') || 
                  h.includes('rate-limit') || 
                  h.includes('x-rate-limit') ||
                  h.includes('retry-after')
                )) {
                  hasRateLimitHeader = true;
                }
              }
            }
          }
        }
      }
      
      if (!hasRateLimitHeader && Object.keys(paths).length > 0) {
        findings.push({
          ruleId: 'APIVET005',
          title: 'No rate limiting headers documented',
          description: 'The API specification does not document rate limiting headers. This may indicate missing rate limiting protection.',
          severity: 'medium',
          owaspCategory: 'API4:2023',
          location: { path: filePath },
          remediation: 'Implement and document rate limiting using standard headers like X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After.'
        });
      }
      
      return findings;
    }
  },

  // API4:2023 - Pagination issues
  {
    id: 'APIVET006',
    title: 'List endpoint without pagination',
    description: 'Collection endpoints should implement pagination to prevent resource exhaustion',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const operation = pathItem.get;
        if (!operation) continue;
        
        // Check if this looks like a collection endpoint
        const isCollection = path.match(/\/(users|items|products|orders|posts|comments|articles|resources|records|entries|data)$/i);
        
        if (isCollection) {
          const params = [...(pathItem.parameters || []), ...(operation.parameters || [])];
          const paramNames = params.map(p => p.name.toLowerCase());
          
          const hasPagination = paramNames.some(n => 
            ['page', 'limit', 'offset', 'cursor', 'per_page', 'page_size', 'pagesize', 'skip', 'take'].includes(n)
          );
          
          if (!hasPagination) {
            findings.push({
              ruleId: 'APIVET006',
              title: 'Collection endpoint without pagination parameters',
              description: `The endpoint GET ${path} appears to return a collection but does not define pagination parameters. This could lead to resource exhaustion.`,
              severity: 'medium',
              owaspCategory: 'API4:2023',
              location: {
                path: filePath,
                endpoint: path,
                method: 'GET'
              },
              remediation: 'Implement pagination using parameters like "page", "limit", "offset", or cursor-based pagination.'
            });
          }
        }
      }
      
      return findings;
    }
  },

  // API5:2023 - Broken Function Level Authorization
  {
    id: 'APIVET007',
    title: 'Admin endpoint potentially exposed',
    description: 'Administrative endpoints should have strict access controls',
    severity: 'high',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const adminPatterns = ['/admin', '/management', '/internal', '/system', '/config', '/settings'];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        if (adminPatterns.some(p => path.toLowerCase().includes(p))) {
          const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
          for (const method of methods) {
            const operation = pathItem[method];
            if (operation) {
              // Check if operation has specific security or if global security applies
              const hasSecurity = (operation.security && operation.security.length > 0) ||
                                  (spec.security && spec.security.length > 0);
              
              if (!hasSecurity) {
                findings.push({
                  ruleId: 'APIVET007',
                  title: 'Administrative endpoint without security',
                  description: `The endpoint ${method.toUpperCase()} ${path} appears to be an administrative function but has no security defined.`,
                  severity: 'high',
                  owaspCategory: 'API5:2023',
                  location: {
                    path: filePath,
                    endpoint: path,
                    method: method.toUpperCase()
                  },
                  remediation: 'Apply strict access controls to administrative endpoints and require elevated privileges.'
                });
              }
            }
          }
        }
      }
      
      return findings;
    }
  },

  // API7:2023 - Server Side Request Forgery
  {
    id: 'APIVET008',
    title: 'URL parameter may enable SSRF',
    description: 'Parameters accepting URLs could be exploited for Server-Side Request Forgery',
    severity: 'high',
    owaspCategory: 'API7:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const urlParamPatterns = ['url', 'uri', 'link', 'href', 'src', 'source', 'target', 'redirect', 'callback', 'webhook'];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['get', 'post', 'put', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method];
          if (!operation) continue;
          
          const allParams = [...(pathItem.parameters || []), ...(operation.parameters || [])];
          
          for (const param of allParams) {
            const lowerName = param.name.toLowerCase();
            if (urlParamPatterns.some(p => lowerName.includes(p))) {
              if (param.schema?.format === 'uri' || param.schema?.type === 'string') {
                findings.push({
                  ruleId: 'APIVET008',
                  title: `URL parameter "${param.name}" may enable SSRF`,
                  description: `The parameter "${param.name}" in ${method.toUpperCase()} ${path} accepts URLs which could be exploited for Server-Side Request Forgery attacks.`,
                  severity: 'high',
                  owaspCategory: 'API7:2023',
                  location: {
                    path: filePath,
                    endpoint: path,
                    method: method.toUpperCase()
                  },
                  remediation: 'Validate and sanitize URL inputs. Use allowlists for permitted domains. Disable redirects and restrict access to internal networks.'
                });
              }
            }
          }
        }
      }
      
      return findings;
    }
  },

  // API8:2023 - Security Misconfiguration
  {
    id: 'APIVET009',
    title: 'Server URL uses HTTP instead of HTTPS',
    description: 'API servers should use HTTPS to encrypt data in transit',
    severity: 'high',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      for (const server of servers) {
        if (server.url.startsWith('http://') && !server.url.includes('localhost') && !server.url.includes('127.0.0.1')) {
          findings.push({
            ruleId: 'APIVET009',
            title: 'Non-HTTPS server URL',
            description: `Server URL "${server.url}" uses HTTP instead of HTTPS. Data transmitted to this endpoint is not encrypted.`,
            severity: 'high',
            owaspCategory: 'API8:2023',
            location: { path: filePath },
            remediation: 'Configure the API server to use HTTPS and update the server URL in the specification.'
          });
        }
      }
      
      return findings;
    }
  },

  // API8:2023 - CORS misconfiguration indicators
  {
    id: 'APIVET010',
    title: 'Wildcard CORS potential',
    description: 'OPTIONS responses should be checked for overly permissive CORS',
    severity: 'medium',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        if (pathItem.options) {
          const responses = pathItem.options.responses || {};
          for (const [code, response] of Object.entries(responses)) {
            if (response.headers) {
              const headerNames = Object.keys(response.headers).map(h => h.toLowerCase());
              if (headerNames.includes('access-control-allow-origin')) {
                findings.push({
                  ruleId: 'APIVET010',
                  title: 'CORS configuration detected - verify it\'s not overly permissive',
                  description: `The endpoint OPTIONS ${path} includes CORS headers. Ensure Access-Control-Allow-Origin is not set to "*" for sensitive endpoints.`,
                  severity: 'info',
                  owaspCategory: 'API8:2023',
                  location: {
                    path: filePath,
                    endpoint: path,
                    method: 'OPTIONS'
                  },
                  remediation: 'Restrict Access-Control-Allow-Origin to specific trusted domains. Avoid using wildcards for endpoints that handle sensitive data.'
                });
              }
            }
          }
        }
      }
      
      return findings;
    }
  },

  // API9:2023 - Improper Inventory Management
  {
    id: 'APIVET011',
    title: 'Deprecated endpoint still defined',
    description: 'Deprecated endpoints should be removed or have clear sunset dates',
    severity: 'low',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method];
          if (operation?.deprecated) {
            findings.push({
              ruleId: 'APIVET011',
              title: 'Deprecated endpoint in specification',
              description: `The endpoint ${method.toUpperCase()} ${path} is marked as deprecated. Deprecated endpoints increase the attack surface and should have a clear sunset plan.`,
              severity: 'low',
              owaspCategory: 'API9:2023',
              location: {
                path: filePath,
                endpoint: path,
                method: method.toUpperCase()
              },
              remediation: 'Create a deprecation timeline and eventually remove deprecated endpoints. Ensure clients are notified of deprecation status.'
            });
          }
        }
      }
      
      return findings;
    }
  },

  // API9:2023 - Version in path
  {
    id: 'APIVET012',
    title: 'Multiple API versions detected',
    description: 'Multiple API versions may indicate improper version management',
    severity: 'info',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = Object.keys(spec.paths || {});
      const versionPattern = /\/v(\d+)/i;
      const versions = new Set<string>();
      
      for (const path of paths) {
        const match = path.match(versionPattern);
        if (match) {
          versions.add(match[1]);
        }
      }
      
      if (versions.size > 1) {
        findings.push({
          ruleId: 'APIVET012',
          title: 'Multiple API versions in specification',
          description: `Found ${versions.size} different API versions (${[...versions].map(v => 'v' + v).join(', ')}). Ensure older versions are properly maintained or deprecated.`,
          severity: 'info',
          owaspCategory: 'API9:2023',
          location: { path: filePath },
          remediation: 'Maintain a clear version strategy. Deprecate and eventually remove old API versions to reduce attack surface.'
        });
      }
      
      return findings;
    }
  },

  // SQL Injection potential
  {
    id: 'APIVET013',
    title: 'Query parameter may be vulnerable to injection',
    description: 'Parameters used for filtering/searching should be validated to prevent injection attacks',
    severity: 'medium',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const dangerousParams = ['query', 'search', 'filter', 'sort', 'order', 'where', 'select', 'fields'];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const operation = pathItem.get;
        if (!operation) continue;
        
        const allParams = [...(pathItem.parameters || []), ...(operation.parameters || [])];
        
        for (const param of allParams) {
          const lowerName = param.name.toLowerCase();
          if (dangerousParams.some(p => lowerName.includes(p))) {
            if (!param.schema?.pattern && !param.schema?.enum && param.schema?.type === 'string') {
              findings.push({
                ruleId: 'APIVET013',
                title: `Query parameter "${param.name}" lacks input validation`,
                description: `The parameter "${param.name}" in GET ${path} is used for querying/filtering but has no pattern or enum constraint defined.`,
                severity: 'medium',
                owaspCategory: 'API8:2023',
                location: {
                  path: filePath,
                  endpoint: path,
                  method: 'GET'
                },
                remediation: 'Add input validation using pattern (regex), enum constraints, or maxLength limits. Use parameterized queries on the backend.'
              });
            }
          }
        }
      }
      
      return findings;
    }
  },

  // Mass assignment potential
  {
    id: 'APIVET014',
    title: 'Request body without defined schema',
    description: 'Request bodies should have explicit schemas to prevent mass assignment',
    severity: 'medium',
    owaspCategory: 'API3:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['post', 'put', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method];
          if (!operation?.requestBody) continue;
          
          const content = operation.requestBody.content?.['application/json'];
          if (content && !content.schema) {
            findings.push({
              ruleId: 'APIVET014',
              title: 'Request body without schema definition',
              description: `The endpoint ${method.toUpperCase()} ${path} accepts a JSON body but has no schema defined. This may allow mass assignment attacks.`,
              severity: 'medium',
              owaspCategory: 'API3:2023',
              location: {
                path: filePath,
                endpoint: path,
                method: method.toUpperCase()
              },
              remediation: 'Define explicit schemas for request bodies listing only the properties that should be accepted.'
            });
          }
        }
      }
      
      return findings;
    }
  },

  // JWT without expiry
  {
    id: 'APIVET015',
    title: 'Bearer token security considerations',
    description: 'APIs using Bearer tokens should implement token expiration and refresh mechanisms',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'http' && scheme.scheme?.toLowerCase() === 'bearer') {
          findings.push({
            ruleId: 'APIVET015',
            title: 'Bearer token authentication - ensure proper token management',
            description: `Security scheme "${name}" uses Bearer token authentication. Ensure tokens have appropriate expiration times and refresh mechanisms are in place.`,
            severity: 'info',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Implement short-lived access tokens with refresh token rotation. Validate token expiration on every request.'
          });
        }
      }
      
      return findings;
    }
  },

  // OAuth2 Implicit Flow (deprecated)
  {
    id: 'APIVET016',
    title: 'OAuth2 Implicit Flow is deprecated',
    description: 'The OAuth2 Implicit flow is deprecated and should not be used for new applications',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'oauth2' && scheme.flows?.implicit) {
          findings.push({
            ruleId: 'APIVET016',
            title: `OAuth2 Implicit Flow detected in "${name}"`,
            description: `Security scheme "${name}" uses the OAuth2 Implicit flow which is deprecated per OAuth 2.0 Security Best Current Practice (RFC 9700). Access tokens are exposed in the URL fragment.`,
            severity: 'high',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Migrate to Authorization Code flow with PKCE. For SPAs, use the Authorization Code flow with PKCE instead of Implicit flow.'
          });
        }
      }
      
      return findings;
    }
  },

  // OAuth2 Password Flow (Resource Owner Password Credentials)
  {
    id: 'APIVET017',
    title: 'OAuth2 Password Flow is discouraged',
    description: 'The Resource Owner Password Credentials flow exposes user credentials to the client',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'oauth2' && scheme.flows?.password) {
          findings.push({
            ruleId: 'APIVET017',
            title: `OAuth2 Password Flow detected in "${name}"`,
            description: `Security scheme "${name}" uses the Resource Owner Password Credentials flow. This flow requires users to share their credentials with the client application, which is a security anti-pattern.`,
            severity: 'high',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Use Authorization Code flow with PKCE instead. The Password flow should only be used for legacy applications during migration.'
          });
        }
      }
      
      return findings;
    }
  },

  // OAuth2 Token/Authorization URL uses HTTP
  {
    id: 'APIVET018',
    title: 'OAuth2 endpoint uses HTTP',
    description: 'OAuth2 authorization and token endpoints must use HTTPS',
    severity: 'critical',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'oauth2' && scheme.flows) {
          const flows = scheme.flows;
          const urlsToCheck: Array<{ type: string; url?: string }> = [
            { type: 'authorizationUrl', url: flows.implicit?.authorizationUrl },
            { type: 'authorizationUrl', url: flows.authorizationCode?.authorizationUrl },
            { type: 'tokenUrl', url: flows.authorizationCode?.tokenUrl },
            { type: 'tokenUrl', url: flows.password?.tokenUrl },
            { type: 'tokenUrl', url: flows.clientCredentials?.tokenUrl },
            { type: 'refreshUrl', url: flows.authorizationCode?.refreshUrl },
            { type: 'refreshUrl', url: flows.password?.refreshUrl },
            { type: 'refreshUrl', url: flows.clientCredentials?.refreshUrl }
          ];
          
          for (const { type, url } of urlsToCheck) {
            if (url && url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
              findings.push({
                ruleId: 'APIVET018',
                title: `OAuth2 ${type} uses HTTP in "${name}"`,
                description: `The OAuth2 ${type} "${url}" uses HTTP instead of HTTPS. This exposes tokens and authorization codes to interception.`,
                severity: 'critical',
                owaspCategory: 'API2:2023',
                location: { path: filePath },
                remediation: 'Always use HTTPS for OAuth2 endpoints. Never transmit tokens or authorization codes over unencrypted connections.'
              });
            }
          }
        }
      }
      
      return findings;
    }
  },

  // API Key in query parameter
  {
    id: 'APIVET019',
    title: 'API Key transmitted in URL query parameter',
    description: 'API keys in query parameters may be logged and cached insecurely',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'apiKey' && scheme.in === 'query') {
          findings.push({
            ruleId: 'APIVET019',
            title: `API Key in query parameter "${name}"`,
            description: `Security scheme "${name}" transmits the API key in the URL query parameter "${scheme.name}". Query parameters may be logged in server logs, browser history, and proxy caches.`,
            severity: 'medium',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Transmit API keys in HTTP headers instead of query parameters. Use a custom header like X-API-Key or the Authorization header.'
          });
        }
      }
      
      return findings;
    }
  },

  // OAuth2 overly broad scopes
  {
    id: 'APIVET020',
    title: 'OAuth2 potentially overly broad scopes',
    description: 'OAuth2 scopes should follow the principle of least privilege',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      const broadScopePatterns = ['admin', 'root', 'superuser', 'all', '*', 'full_access', 'full-access'];
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'oauth2' && scheme.flows) {
          const allScopes: string[] = [];
          
          // Collect all scopes from all flows
          for (const flow of Object.values(scheme.flows)) {
            if (flow?.scopes) {
              allScopes.push(...Object.keys(flow.scopes));
            }
          }
          
          for (const scope of allScopes) {
            const lowerScope = scope.toLowerCase();
            if (broadScopePatterns.some(p => lowerScope.includes(p))) {
              findings.push({
                ruleId: 'APIVET020',
                title: `Potentially overly broad OAuth2 scope "${scope}"`,
                description: `The scope "${scope}" in security scheme "${name}" may grant excessive permissions. Broad scopes violate the principle of least privilege.`,
                severity: 'medium',
                owaspCategory: 'API5:2023',
                location: { path: filePath },
                remediation: 'Define granular scopes that provide only the minimum permissions needed. Break down broad scopes into specific resource:action pairs.'
              });
            }
          }
        }
      }
      
      return findings;
    }
  },

  // OpenID Connect URL uses HTTP
  {
    id: 'APIVET021',
    title: 'OpenID Connect discovery URL uses HTTP',
    description: 'OpenID Connect discovery endpoints must use HTTPS',
    severity: 'critical',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'openIdConnect' && scheme.openIdConnectUrl) {
          const url = scheme.openIdConnectUrl;
          if (url.startsWith('http://') && !url.includes('localhost') && !url.includes('127.0.0.1')) {
            findings.push({
              ruleId: 'APIVET021',
              title: `OpenID Connect URL uses HTTP in "${name}"`,
              description: `The OpenID Connect discovery URL "${url}" uses HTTP. This allows attackers to intercept the discovery document and redirect authentication to malicious endpoints.`,
              severity: 'critical',
              owaspCategory: 'API2:2023',
              location: { path: filePath },
              remediation: 'Always use HTTPS for OpenID Connect discovery URLs.'
            });
          }
        }
      }
      
      return findings;
    }
  },

  // JWT Algorithm concerns in description
  {
    id: 'APIVET022',
    title: 'JWT weak algorithm indication',
    description: 'JWT implementations should use strong signing algorithms',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      const weakAlgorithms = ['none', 'hs256', 'hs384', 'hs512'];
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'http' && scheme.scheme?.toLowerCase() === 'bearer') {
          const description = (scheme.description || '').toLowerCase();
          const bearerFormat = (scheme.bearerFormat || '').toLowerCase();
          
          // Check if JWT is mentioned
          if (description.includes('jwt') || bearerFormat.includes('jwt')) {
            // Check for weak algorithm mentions
            for (const alg of weakAlgorithms) {
              if (description.includes(alg) || bearerFormat.includes(alg)) {
                const isNone = alg === 'none';
                findings.push({
                  ruleId: 'APIVET022',
                  title: isNone 
                    ? `JWT "none" algorithm mentioned in "${name}"`
                    : `JWT symmetric algorithm ${alg.toUpperCase()} mentioned in "${name}"`,
                  description: isNone
                    ? `Security scheme "${name}" mentions the JWT "none" algorithm. This algorithm provides no signature verification and should never be accepted.`
                    : `Security scheme "${name}" mentions the symmetric ${alg.toUpperCase()} algorithm. Symmetric algorithms require sharing the secret with all parties that need to verify tokens.`,
                  severity: isNone ? 'critical' : 'medium',
                  owaspCategory: 'API2:2023',
                  location: { path: filePath },
                  remediation: isNone
                    ? 'Never accept JWTs with "alg": "none". Always require a valid signature.'
                    : 'Consider using asymmetric algorithms like RS256 or ES256 which use public/private key pairs. This allows verification without exposing the signing key.'
                });
              }
            }
          }
        }
      }
      
      return findings;
    }
  },

  // Missing refresh token endpoint
  {
    id: 'APIVET023',
    title: 'OAuth2 flow without refresh URL',
    description: 'OAuth2 flows should define refresh token endpoints for token rotation',
    severity: 'low',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'oauth2' && scheme.flows) {
          // Check flows that should have refresh URLs
          const flowsNeedingRefresh = [
            { name: 'authorizationCode', flow: scheme.flows.authorizationCode },
            { name: 'password', flow: scheme.flows.password }
          ];
          
          for (const { name: flowName, flow } of flowsNeedingRefresh) {
            if (flow && !flow.refreshUrl) {
              findings.push({
                ruleId: 'APIVET023',
                title: `OAuth2 ${flowName} flow missing refresh URL in "${name}"`,
                description: `The ${flowName} flow in security scheme "${name}" does not define a refreshUrl. Without token refresh, users may need to re-authenticate frequently, or tokens may have excessively long lifetimes.`,
                severity: 'low',
                owaspCategory: 'API2:2023',
                location: { path: filePath },
                remediation: 'Define a refreshUrl for token refresh. Use short-lived access tokens with refresh token rotation for better security.'
              });
            }
          }
        }
      }
      
      return findings;
    }
  },

  // Sensitive endpoints without explicit security
  {
    id: 'APIVET024',
    title: 'Sensitive endpoint relies on global security only',
    description: 'High-risk endpoints should have explicit security requirements',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const sensitivePatterns = [
        '/password', '/credentials', '/tokens', '/keys', '/secrets',
        '/payment', '/billing', '/charge', '/subscription',
        '/pii', '/personal', '/private'
      ];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const isSensitive = sensitivePatterns.some(p => path.toLowerCase().includes(p));
        if (!isSensitive) continue;
        
        const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method];
          if (!operation) continue;
          
          // Has global security but no explicit operation security
          if (spec.security && spec.security.length > 0 && 
              (!operation.security || operation.security.length === 0)) {
            findings.push({
              ruleId: 'APIVET024',
              title: `Sensitive endpoint ${method.toUpperCase()} ${path} uses implicit global security`,
              description: `The endpoint ${method.toUpperCase()} ${path} handles sensitive operations but relies on global security definitions. Sensitive endpoints should have explicit security requirements for clarity and defense in depth.`,
              severity: 'medium',
              owaspCategory: 'API5:2023',
              location: {
                path: filePath,
                endpoint: path,
                method: method.toUpperCase()
              },
              remediation: 'Add explicit security requirements to sensitive endpoints, even if they match global settings. This provides documentation clarity and prevents accidental exposure if global settings change.'
            });
          }
        }
      }
      
      return findings;
    }
  },

  // Cookie-based auth without security attributes
  {
    id: 'APIVET025',
    title: 'API Key in cookie may lack security attributes',
    description: 'Cookie-based authentication requires proper security attributes',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        if (scheme.type === 'apiKey' && scheme.in === 'cookie') {
          findings.push({
            ruleId: 'APIVET025',
            title: `Cookie-based authentication in "${name}"`,
            description: `Security scheme "${name}" uses cookie-based authentication. Ensure cookies are set with Secure, HttpOnly, and SameSite attributes to prevent interception and CSRF attacks.`,
            severity: 'medium',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Set cookies with Secure (HTTPS only), HttpOnly (no JavaScript access), and SameSite=Strict or Lax attributes. Consider using token-based authentication for APIs.'
          });
        }
      }
      
      return findings;
    }
  },

  // ============================================
  // Cloud Provider Security Rules
  // ============================================

  // AWS API Gateway: Missing authorizer
  {
    id: 'APIVET026',
    title: 'AWS API Gateway endpoint without authorizer',
    description: 'AWS API Gateway endpoints should have authorization configured',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const extSpec = spec as Record<string, unknown>;
      
      // Check if this is an AWS API Gateway spec
      const isAwsSpec = JSON.stringify(spec).includes('x-amazon-apigateway');
      if (!isAwsSpec) return findings;
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;
          
          // Check for x-amazon-apigateway-auth or security
          const hasAwsAuth = operation['x-amazon-apigateway-auth'];
          const hasSecurity = operation.security || spec.security;
          const integration = operation['x-amazon-apigateway-integration'] as Record<string, unknown> | undefined;
          
          // Skip if it's a mock integration (often used for OPTIONS/CORS)
          if (integration?.type === 'mock') continue;
          
          if (!hasAwsAuth && !hasSecurity) {
            findings.push({
              ruleId: 'APIVET026',
              title: `AWS API Gateway endpoint without authorization`,
              description: `The endpoint ${method.toUpperCase()} ${path} in AWS API Gateway has no authorizer configured. Consider adding a Lambda authorizer, Cognito user pool, or IAM authorization.`,
              severity: 'high',
              owaspCategory: 'API2:2023',
              location: {
                path: filePath,
                endpoint: path,
                method: method.toUpperCase()
              },
              remediation: 'Configure x-amazon-apigateway-auth or add a security requirement. Use Cognito user pools, Lambda authorizers, or IAM authorization for API Gateway.'
            });
          }
        }
      }
      
      return findings;
    }
  },

  // AWS API Gateway: Missing request validation
  {
    id: 'APIVET027',
    title: 'AWS API Gateway without request validation',
    description: 'AWS API Gateway should validate request parameters and body',
    severity: 'medium',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const extSpec = spec as Record<string, unknown>;
      
      // Check if this is an AWS API Gateway spec
      const isAwsSpec = JSON.stringify(spec).includes('x-amazon-apigateway');
      if (!isAwsSpec) return findings;
      
      // Check for request validators at spec level
      const validators = extSpec['x-amazon-apigateway-request-validators'] as Record<string, unknown> | undefined;
      const defaultValidator = extSpec['x-amazon-apigateway-request-validator'] as string | undefined;
      
      if (!validators && !defaultValidator) {
        findings.push({
          ruleId: 'APIVET027',
          title: 'AWS API Gateway missing request validation configuration',
          description: 'The API Gateway specification does not define request validators. Request validation helps prevent malformed requests from reaching backend services.',
          severity: 'medium',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Add x-amazon-apigateway-request-validators to define validators (e.g., "validate-body", "validate-params", "validate-body-and-params") and set x-amazon-apigateway-request-validator to enable validation.'
        });
      } else if (validators && !defaultValidator) {
        // Validators defined but none set as default
        findings.push({
          ruleId: 'APIVET027',
          title: 'AWS API Gateway request validators defined but not enabled',
          description: 'Request validators are defined but no default validator is set. Validation will not occur unless explicitly enabled per operation.',
          severity: 'low',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Set x-amazon-apigateway-request-validator at the API level or per operation to enable request validation.'
        });
      }
      
      return findings;
    }
  },

  // AWS API Gateway: API Key requirement
  {
    id: 'APIVET028',
    title: 'AWS API Gateway endpoint without API key requirement',
    description: 'Consider requiring API keys for usage tracking and throttling',
    severity: 'info',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      // Check if this is an AWS API Gateway spec
      const isAwsSpec = JSON.stringify(spec).includes('x-amazon-apigateway');
      if (!isAwsSpec) return findings;
      
      let hasAnyApiKey = false;
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;
          
          const integration = operation['x-amazon-apigateway-integration'] as Record<string, unknown> | undefined;
          if (integration?.type === 'mock') continue;
          
          // Check for API key requirement
          const apiKeyRequired = (operation['x-amazon-apigateway-api-key-source'] as string) ||
                                  (operation.security as Array<Record<string, string[]>> | undefined)?.some(s => 'api_key' in s);
          
          if (apiKeyRequired) {
            hasAnyApiKey = true;
          }
        }
      }
      
      if (!hasAnyApiKey) {
        findings.push({
          ruleId: 'APIVET028',
          title: 'AWS API Gateway without API key requirements',
          description: 'No endpoints require API keys. API keys enable usage plans, throttling, and tracking of API consumers.',
          severity: 'info',
          owaspCategory: 'API4:2023',
          location: { path: filePath },
          remediation: 'Consider adding API key requirements with usage plans to track and throttle API consumers. Configure x-amazon-apigateway-api-key-source and create usage plans.'
        });
      }
      
      return findings;
    }
  },

  // AWS: Cognito authorizer without scopes
  {
    id: 'APIVET029',
    title: 'AWS Cognito authorizer without scope validation',
    description: 'Cognito authorizers should validate OAuth2 scopes',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const securitySchemes = spec.components?.securitySchemes || {};
      
      for (const [name, scheme] of Object.entries(securitySchemes)) {
        const extScheme = scheme as unknown as Record<string, unknown>;
        const authorizer = extScheme['x-amazon-apigateway-authorizer'] as Record<string, unknown> | undefined;
        
        if (authorizer?.type === 'cognito_user_pools') {
          const scopes = authorizer.providerARNs as string[] | undefined;
          
          // Check if any operations use this scheme without scopes
          const paths = spec.paths || {};
          for (const [path, pathItem] of Object.entries(paths)) {
            const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
            for (const method of methods) {
              const operation = pathItem[method];
              if (!operation?.security) continue;
              
              for (const secReq of operation.security) {
                if (name in secReq && (!secReq[name] || secReq[name].length === 0)) {
                  findings.push({
                    ruleId: 'APIVET029',
                    title: `Cognito authorizer "${name}" used without scopes`,
                    description: `The endpoint ${method.toUpperCase()} ${path} uses Cognito authorizer "${name}" but doesn't require any OAuth2 scopes. This may allow broader access than intended.`,
                    severity: 'medium',
                    owaspCategory: 'API5:2023',
                    location: {
                      path: filePath,
                      endpoint: path,
                      method: method.toUpperCase()
                    },
                    remediation: 'Specify required OAuth2 scopes in the security requirement to enforce fine-grained access control.'
                  });
                }
              }
            }
          }
        }
      }
      
      return findings;
    }
  },

  // Azure API Management: Missing policies hint
  {
    id: 'APIVET030',
    title: 'Azure APIM integration detected',
    description: 'Ensure Azure API Management policies are properly configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      // Check for Azure APIM URLs
      const isAzureApim = servers.some(s => 
        s.url.includes('.azure-api.net') || 
        s.url.includes('management.azure.com')
      );
      
      if (isAzureApim) {
        findings.push({
          ruleId: 'APIVET030',
          title: 'Azure API Management detected',
          description: 'This API appears to use Azure API Management. Ensure inbound/outbound policies are configured for security (JWT validation, rate limiting, IP filtering, CORS).',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Review Azure APIM policies: validate-jwt for token validation, rate-limit-by-key for throttling, ip-filter for access control, and cors for cross-origin requests.'
        });
      }
      
      return findings;
    }
  },

  // GCP: Cloud Endpoints / API Gateway detection
  {
    id: 'APIVET031',
    title: 'GCP Cloud Endpoints detected',
    description: 'Ensure GCP API security features are properly configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const extSpec = spec as Record<string, unknown>;
      
      // Check for GCP-specific extensions
      const hasGoogleEndpoints = extSpec['x-google-endpoints'] !== undefined;
      const hasGoogleBackend = JSON.stringify(spec).includes('x-google-backend');
      const servers = spec.servers || [];
      const isGcpUrl = servers.some(s => 
        s.url.includes('.endpoints.') || 
        s.url.includes('.run.app') ||
        s.url.includes('.cloudfunctions.net')
      );
      
      if (hasGoogleEndpoints || hasGoogleBackend || isGcpUrl) {
        findings.push({
          ruleId: 'APIVET031',
          title: 'GCP Cloud Endpoints/API Gateway detected',
          description: 'This API appears to use GCP Cloud Endpoints or API Gateway. Ensure authentication (API keys, Firebase Auth, or service accounts) and quotas are properly configured.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Configure x-google-endpoints for DNS and authentication. Use securityDefinitions with API keys or OAuth2. Set x-google-quota for rate limiting.'
        });
        
        // Check for missing authentication in GCP
        const googleEndpoints = extSpec['x-google-endpoints'] as Array<Record<string, unknown>> | undefined;
        if (googleEndpoints) {
          for (const endpoint of googleEndpoints) {
            if (endpoint.allowCors && !endpoint.name) {
              findings.push({
                ruleId: 'APIVET031',
                title: 'GCP endpoint allows CORS without explicit configuration',
                description: 'A GCP endpoint has allowCors enabled. Ensure CORS is intentional and properly restricted.',
                severity: 'low',
                owaspCategory: 'API8:2023',
                location: { path: filePath },
                remediation: 'Review CORS settings and restrict allowed origins in GCP Cloud Endpoints configuration.'
              });
            }
          }
        }
      }
      
      return findings;
    }
  },

  // Cloud: Staging/Development URL in production spec
  {
    id: 'APIVET032',
    title: 'Non-production environment URL detected',
    description: 'API specification contains staging or development URLs',
    severity: 'medium',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const devPatterns = [
        'staging', 'stage', 'dev', 'development', 'test', 'sandbox', 
        'qa', 'uat', 'preprod', 'pre-prod', 'demo', 'preview'
      ];
      
      for (const server of servers) {
        const url = server.url.toLowerCase();
        const description = (server.description || '').toLowerCase();
        
        for (const pattern of devPatterns) {
          if (url.includes(pattern) || description.includes(pattern)) {
            findings.push({
              ruleId: 'APIVET032',
              title: `Non-production URL detected: ${server.url}`,
              description: `Server URL "${server.url}" appears to be a ${pattern} environment. Ensure production specifications don't expose development endpoints.`,
              severity: 'medium',
              owaspCategory: 'API9:2023',
              location: { path: filePath },
              remediation: 'Remove non-production URLs from production API specifications. Use environment variables or separate spec files for different environments.'
            });
            break;
          }
        }
      }
      
      return findings;
    }
  },

  // Cloud: Internal/Private API exposure
  {
    id: 'APIVET033',
    title: 'Internal API URL potentially exposed',
    description: 'API specification contains internal or private network URLs',
    severity: 'high',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const internalPatterns = [
        /^https?:\/\/10\.\d+\.\d+\.\d+/,
        /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
        /^https?:\/\/192\.168\.\d+\.\d+/,
        /^https?:\/\/[^/]*\.internal[./]/,
        /^https?:\/\/[^/]*\.local[./]/,
        /^https?:\/\/[^/]*\.corp[./]/,
        /^https?:\/\/[^/]*\.private[./]/
      ];
      
      for (const server of servers) {
        for (const pattern of internalPatterns) {
          if (pattern.test(server.url)) {
            findings.push({
              ruleId: 'APIVET033',
              title: `Internal network URL exposed: ${server.url}`,
              description: `Server URL "${server.url}" appears to be an internal/private network address. Exposing internal URLs in API specifications may leak infrastructure details.`,
              severity: 'high',
              owaspCategory: 'API9:2023',
              location: { path: filePath },
              remediation: 'Remove internal URLs from public API specifications. Use relative paths or environment-specific configuration for internal APIs.'
            });
            break;
          }
        }
      }
      
      return findings;
    }
  },

  // AWS Lambda: Proxy integration without input validation
  {
    id: 'APIVET034',
    title: 'AWS Lambda proxy integration bypasses API Gateway validation',
    description: 'Lambda proxy integrations pass raw requests to Lambda',
    severity: 'medium',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      
      for (const [path, pathItem] of Object.entries(paths)) {
        const methods = ['get', 'post', 'put', 'delete', 'patch'] as const;
        for (const method of methods) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;
          
          const integration = operation['x-amazon-apigateway-integration'] as Record<string, unknown> | undefined;
          
          if (integration?.type === 'aws_proxy' || integration?.type === 'AWS_PROXY') {
            // Check if there's request validation
            const hasValidator = operation['x-amazon-apigateway-request-validator'] !== undefined;
            const hasRequestBody = operation.requestBody !== undefined;
            
            if (!hasValidator && hasRequestBody) {
              findings.push({
                ruleId: 'APIVET034',
                title: `Lambda proxy integration without request validation`,
                description: `The endpoint ${method.toUpperCase()} ${path} uses AWS Lambda proxy integration with a request body but no request validator. Raw requests are passed directly to Lambda without API Gateway validation.`,
                severity: 'medium',
                owaspCategory: 'API8:2023',
                location: {
                  path: filePath,
                  endpoint: path,
                  method: method.toUpperCase()
                },
                remediation: 'Add x-amazon-apigateway-request-validator to validate request body and parameters before passing to Lambda. Alternatively, implement validation in the Lambda function.'
              });
            }
          }
        }
      }
      
      return findings;
    }
  },

  // Cloud: Missing CORS configuration for browser access
  {
    id: 'APIVET035',
    title: 'Cloud API without CORS configuration',
    description: 'APIs accessed from browsers need CORS configuration',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const servers = spec.servers || [];
      
      // Only check for cloud-hosted APIs
      const isCloudHosted = servers.some(s => 
        s.url.includes('.amazonaws.com') ||
        s.url.includes('.azure-api.net') ||
        s.url.includes('.run.app') ||
        s.url.includes('.cloudfunctions.net') ||
        s.url.includes('.execute-api.')
      );
      
      if (!isCloudHosted) return findings;
      
      // Check if OPTIONS method is defined for any path
      let hasOptionsMethod = false;
      
      for (const [path, pathItem] of Object.entries(paths)) {
        if (pathItem.options) {
          hasOptionsMethod = true;
          break;
        }
      }
      
      if (!hasOptionsMethod && Object.keys(paths).length > 0) {
        findings.push({
          ruleId: 'APIVET035',
          title: 'Cloud API without CORS preflight handlers',
          description: 'This cloud-hosted API does not define OPTIONS methods for CORS preflight requests. If this API is accessed from web browsers, CORS must be configured.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'If browser access is needed, configure CORS at the API gateway level (AWS API Gateway CORS, Azure APIM cors policy, or GCP allowCors). For server-to-server APIs, CORS may not be needed.'
        });
      }
      
      return findings;
    }
  },

  // ============================================
  // Extended Cloud Provider Rules
  // ============================================

  // AWS: AppSync GraphQL detection
  {
    id: 'APIVET036',
    title: 'AWS AppSync GraphQL API detected',
    description: 'GraphQL APIs require specific security considerations',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isAppSync = servers.some(s => 
        s.url.includes('.appsync-api.') ||
        s.url.includes('appsync.')
      );
      
      if (isAppSync) {
        findings.push({
          ruleId: 'APIVET036',
          title: 'AWS AppSync GraphQL API detected',
          description: 'This API uses AWS AppSync. Ensure proper authorization (API key, Cognito, IAM, or Lambda) and implement field-level resolvers with appropriate permissions.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Configure AppSync authorization modes. Use @auth directives in GraphQL schema. Implement resolver-level authorization for sensitive fields. Enable logging and monitoring.'
        });
      }
      
      return findings;
    }
  },

  // AWS: CloudFront with API Gateway
  {
    id: 'APIVET037',
    title: 'AWS API Gateway without CloudFront',
    description: 'Consider using CloudFront for DDoS protection and caching',
    severity: 'info',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      // Check for direct API Gateway URL without CloudFront
      const hasDirectApiGateway = servers.some(s => 
        s.url.includes('.execute-api.') && 
        !s.url.includes('.cloudfront.net')
      );
      
      const hasCloudFront = servers.some(s => 
        s.url.includes('.cloudfront.net')
      );
      
      if (hasDirectApiGateway && !hasCloudFront) {
        findings.push({
          ruleId: 'APIVET037',
          title: 'AWS API Gateway exposed without CloudFront',
          description: 'The API Gateway endpoint is directly exposed. Consider placing CloudFront in front for DDoS protection, caching, and geographic restrictions.',
          severity: 'info',
          owaspCategory: 'API4:2023',
          location: { path: filePath },
          remediation: 'Configure Amazon CloudFront distribution with API Gateway as origin. Enable AWS WAF for additional protection. Use custom domain with CloudFront for production.'
        });
      }
      
      return findings;
    }
  },

  // AWS: WAF recommendation
  {
    id: 'APIVET038',
    title: 'AWS API without WAF indication',
    description: 'AWS APIs should consider WAF protection',
    severity: 'low',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec);
      
      const isAws = servers.some(s => 
        s.url.includes('.amazonaws.com') ||
        s.url.includes('.execute-api.')
      );
      
      // Check for any WAF-related mentions
      const hasWafMention = specStr.toLowerCase().includes('waf') ||
                           specStr.includes('x-waf') ||
                           specStr.includes('x-amazon-waf');
      
      if (isAws && !hasWafMention) {
        findings.push({
          ruleId: 'APIVET038',
          title: 'AWS API without WAF configuration indicated',
          description: 'This AWS API does not mention WAF protection. AWS WAF provides protection against common web exploits and bots.',
          severity: 'low',
          owaspCategory: 'API4:2023',
          location: { path: filePath },
          remediation: 'Consider enabling AWS WAF with managed rule groups (AWSManagedRulesCommonRuleSet, AWSManagedRulesKnownBadInputsRuleSet) for API Gateway or CloudFront.'
        });
      }
      
      return findings;
    }
  },

  // Azure: Function App / App Service detection
  {
    id: 'APIVET039',
    title: 'Azure Functions / App Service detected',
    description: 'Ensure Azure-specific authentication is properly configured',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isAzureFunction = servers.some(s => 
        s.url.includes('.azurewebsites.net') ||
        s.url.includes('.azure-mobile.net')
      );
      
      if (isAzureFunction) {
        findings.push({
          ruleId: 'APIVET039',
          title: 'Azure Functions / App Service detected',
          description: 'This API appears to be hosted on Azure Functions or App Service. Ensure built-in authentication (Easy Auth) or custom authentication is properly configured.',
          severity: 'info',
          owaspCategory: 'API2:2023',
          location: { path: filePath },
          remediation: 'Enable Azure App Service Authentication (Easy Auth) with Microsoft Entra ID, or implement custom JWT validation. Configure CORS settings in Azure portal.'
        });
      }
      
      return findings;
    }
  },

  // Azure: Front Door detection
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
        findings.push({
          ruleId: 'APIVET040',
          title: 'Azure Front Door detected',
          description: 'This API uses Azure Front Door. Ensure WAF policies and DDoS protection are properly configured.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Enable Azure WAF policy on Front Door with OWASP rule sets. Configure rate limiting rules. Enable DDoS protection. Use Private Link for backend connections.'
        });
      }
      
      return findings;
    }
  },

  // GCP: Cloud Run authentication
  {
    id: 'APIVET041',
    title: 'GCP Cloud Run without authentication indication',
    description: 'Cloud Run services should have authentication configured',
    severity: 'medium',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isCloudRun = servers.some(s => s.url.includes('.run.app'));
      
      if (isCloudRun) {
        // Check if any authentication is defined
        const hasAuth = spec.security && spec.security.length > 0;
        const hasSecuritySchemes = spec.components?.securitySchemes && 
                                   Object.keys(spec.components.securitySchemes).length > 0;
        
        if (!hasAuth && !hasSecuritySchemes) {
          findings.push({
            ruleId: 'APIVET041',
            title: 'GCP Cloud Run service without authentication defined',
            description: 'This Cloud Run service does not define authentication in the OpenAPI spec. Ensure the service is configured to require authentication (IAM invoker permission or custom auth).',
            severity: 'medium',
            owaspCategory: 'API2:2023',
            location: { path: filePath },
            remediation: 'Configure Cloud Run to require authentication (allUsers vs allAuthenticatedUsers vs specific IAM members). For public APIs, implement custom authentication (Firebase Auth, Identity Platform, or custom JWT).'
          });
        }
      }
      
      return findings;
    }
  },

  // GCP: Firebase integration
  {
    id: 'APIVET042',
    title: 'Firebase / Identity Platform authentication detected',
    description: 'Ensure Firebase security rules are properly configured',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const specStr = JSON.stringify(spec).toLowerCase();
      
      const isFirebase = specStr.includes('firebase') ||
                        specStr.includes('identitytoolkit.googleapis.com') ||
                        specStr.includes('securetoken.googleapis.com');
      
      if (isFirebase) {
        findings.push({
          ruleId: 'APIVET042',
          title: 'Firebase / Identity Platform authentication detected',
          description: 'This API uses Firebase Authentication or Identity Platform. Ensure proper token validation and security rules.',
          severity: 'info',
          owaspCategory: 'API2:2023',
          location: { path: filePath },
          remediation: 'Validate Firebase ID tokens server-side. Check token expiration and issuer. Implement proper Firestore/RTDB security rules. Enable App Check for additional security.'
        });
      }
      
      return findings;
    }
  },

  // Cloudflare: Workers / API Shield detection
  {
    id: 'APIVET043',
    title: 'Cloudflare Workers / Pages detected',
    description: 'Ensure Cloudflare security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isCloudflare = servers.some(s => 
        s.url.includes('.workers.dev') ||
        s.url.includes('.pages.dev') ||
        s.url.includes('cloudflare')
      );
      
      if (isCloudflare) {
        findings.push({
          ruleId: 'APIVET043',
          title: 'Cloudflare Workers / Pages detected',
          description: 'This API uses Cloudflare Workers or Pages. Consider enabling API Shield for schema validation and anomaly detection.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Enable Cloudflare API Shield for schema validation. Configure rate limiting rules. Use Access for authentication. Enable Bot Management for additional protection.'
        });
      }
      
      return findings;
    }
  },

  // Vercel: Edge Functions detection
  {
    id: 'APIVET044',
    title: 'Vercel deployment detected',
    description: 'Ensure Vercel security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isVercel = servers.some(s => 
        s.url.includes('.vercel.app') ||
        s.url.includes('.now.sh')
      );
      
      if (isVercel) {
        findings.push({
          ruleId: 'APIVET044',
          title: 'Vercel deployment detected',
          description: 'This API is deployed on Vercel. Ensure proper authentication and consider Vercel Firewall for additional protection.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Configure environment variables securely. Use Vercel Authentication for protected routes. Enable Vercel Firewall for DDoS protection. Consider Edge Middleware for request validation.'
        });
      }
      
      return findings;
    }
  },

  // Netlify detection
  {
    id: 'APIVET045',
    title: 'Netlify deployment detected',
    description: 'Ensure Netlify security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isNetlify = servers.some(s => 
        s.url.includes('.netlify.app') ||
        s.url.includes('.netlify.com') ||
        s.url.includes('netlify')
      );
      
      if (isNetlify) {
        findings.push({
          ruleId: 'APIVET045',
          title: 'Netlify deployment detected',
          description: 'This API is deployed on Netlify. Ensure proper function authentication and consider Netlify security headers.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Configure security headers in netlify.toml. Use Netlify Identity for authentication. Secure environment variables. Enable branch protection for production.'
        });
      }
      
      return findings;
    }
  },

  // Kubernetes Ingress detection
  {
    id: 'APIVET046',
    title: 'Kubernetes Ingress pattern detected',
    description: 'Ensure Kubernetes Ingress security is properly configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const specStr = JSON.stringify(spec).toLowerCase();
      const servers = spec.servers || [];
      
      const isK8sIngress = specStr.includes('kubernetes') ||
                          specStr.includes('nginx.ingress') ||
                          specStr.includes('traefik') ||
                          specStr.includes('istio') ||
                          servers.some(s => s.url.includes('.svc.cluster.local'));
      
      if (isK8sIngress) {
        findings.push({
          ruleId: 'APIVET046',
          title: 'Kubernetes / Service Mesh pattern detected',
          description: 'This API appears to use Kubernetes Ingress or Service Mesh. Ensure proper network policies and authentication.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Configure TLS termination at Ingress. Use network policies for pod-to-pod communication. Enable mTLS with service mesh (Istio/Linkerd). Implement rate limiting at Ingress level.'
        });
      }
      
      return findings;
    }
  },

  // Kong Gateway detection
  {
    id: 'APIVET047',
    title: 'Kong Gateway pattern detected',
    description: 'Ensure Kong security plugins are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const specStr = JSON.stringify(spec).toLowerCase();
      
      const isKong = specStr.includes('x-kong') ||
                    specStr.includes('konghq') ||
                    specStr.includes('kong-admin');
      
      if (isKong) {
        findings.push({
          ruleId: 'APIVET047',
          title: 'Kong Gateway detected',
          description: 'This API uses Kong Gateway. Ensure security plugins (key-auth, jwt, oauth2, rate-limiting) are properly configured.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Enable Kong security plugins: key-auth/jwt/oauth2 for authentication, rate-limiting for throttling, ip-restriction for access control, bot-detection for protection.'
        });
      }
      
      return findings;
    }
  },

  // AWS: HTTP API vs REST API
  {
    id: 'APIVET048',
    title: 'AWS HTTP API detected',
    description: 'HTTP APIs have different security features than REST APIs',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec);
      
      // HTTP API uses different URL pattern and lacks some REST API features
      const hasHttpApiMarkers = specStr.includes('x-amazon-apigateway-cors') ||
                               specStr.includes('payloadFormatVersion');
      
      const isApiGateway = servers.some(s => s.url.includes('.execute-api.'));
      
      if (isApiGateway && hasHttpApiMarkers) {
        findings.push({
          ruleId: 'APIVET048',
          title: 'AWS API Gateway HTTP API detected',
          description: 'This appears to be an HTTP API (not REST API). HTTP APIs have limited features: no WAF integration, limited request validation, and different authorizer options.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'For HTTP APIs: use JWT authorizers (not IAM/Cognito authorizers), implement request validation in Lambda, consider REST API if WAF integration is needed.'
        });
      }
      
      return findings;
    }
  },

  // AWS: Private API detection
  {
    id: 'APIVET049',
    title: 'AWS Private API Gateway consideration',
    description: 'Consider using private API endpoints for internal services',
    severity: 'info',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();
      
      const isAwsApi = servers.some(s => s.url.includes('.execute-api.'));
      const isInternalApi = specStr.includes('internal') || 
                           specStr.includes('private') ||
                           specStr.includes('backend');
      const hasVpcEndpoint = specStr.includes('vpce-') || 
                            specStr.includes('x-amazon-apigateway-endpoint-configuration');
      
      if (isAwsApi && isInternalApi && !hasVpcEndpoint) {
        findings.push({
          ruleId: 'APIVET049',
          title: 'Consider AWS Private API for internal service',
          description: 'This API appears to be for internal use but may be publicly accessible. Consider using a private API Gateway endpoint with VPC endpoint.',
          severity: 'info',
          owaspCategory: 'API9:2023',
          location: { path: filePath },
          remediation: 'Configure API Gateway as PRIVATE endpoint type. Create VPC endpoint for API Gateway. Use resource policies to restrict access to specific VPCs.'
        });
      }
      
      return findings;
    }
  },

  // Supabase detection
  {
    id: 'APIVET050',
    title: 'Supabase API detected',
    description: 'Ensure Supabase Row Level Security is properly configured',
    severity: 'medium',
    owaspCategory: 'API1:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isSupabase = servers.some(s => 
        s.url.includes('.supabase.co') ||
        s.url.includes('supabase')
      );
      
      if (isSupabase) {
        findings.push({
          ruleId: 'APIVET050',
          title: 'Supabase API detected',
          description: 'This API uses Supabase. Ensure Row Level Security (RLS) policies are enabled on all tables and proper JWT validation is in place.',
          severity: 'medium',
          owaspCategory: 'API1:2023',
          location: { path: filePath },
          remediation: 'Enable RLS on all Supabase tables. Create appropriate policies for select/insert/update/delete. Never expose the service_role key to clients. Use anon key with proper RLS.'
        });
      }
      
      return findings;
    }
  },

  // Railway / Render detection
  {
    id: 'APIVET051',
    title: 'PaaS deployment detected (Railway/Render)',
    description: 'Ensure PaaS security settings are properly configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isPaaS = servers.some(s => 
        s.url.includes('.railway.app') ||
        s.url.includes('.onrender.com') ||
        s.url.includes('.fly.dev') ||
        s.url.includes('.up.railway.app')
      );
      
      if (isPaaS) {
        findings.push({
          ruleId: 'APIVET051',
          title: 'PaaS deployment detected',
          description: 'This API is deployed on a PaaS platform. Ensure environment variables are properly secured and consider using custom domains with proper TLS.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Secure environment variables in platform settings. Use custom domains with proper TLS certificates. Enable health checks. Configure auto-scaling policies.'
        });
      }
      
      return findings;
    }
  },

  // Heroku detection
  {
    id: 'APIVET052',
    title: 'Heroku deployment detected',
    description: 'Ensure Heroku security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isHeroku = servers.some(s => 
        s.url.includes('.herokuapp.com') ||
        s.url.includes('heroku')
      );
      
      if (isHeroku) {
        findings.push({
          ruleId: 'APIVET052',
          title: 'Heroku deployment detected',
          description: 'This API is deployed on Heroku. Note that *.herokuapp.com domains share SSL certificates. Consider using custom domains for production.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Use custom domains with ACM certificates for production. Enable Heroku Private Spaces for sensitive workloads. Configure proper Config Vars security. Enable runtime metrics.'
        });
      }
      
      return findings;
    }
  },

  // DigitalOcean App Platform detection
  {
    id: 'APIVET053',
    title: 'DigitalOcean App Platform detected',
    description: 'Ensure DigitalOcean security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      
      const isDigitalOcean = servers.some(s => 
        s.url.includes('.ondigitalocean.app') ||
        s.url.includes('digitalocean')
      );
      
      if (isDigitalOcean) {
        findings.push({
          ruleId: 'APIVET053',
          title: 'DigitalOcean App Platform detected',
          description: 'This API is deployed on DigitalOcean App Platform. Ensure proper environment variable encryption and consider using managed databases with VPC.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Use encrypted environment variables. Configure custom domains. Enable App Platform firewall rules. Use managed databases within VPC for database connections.'
        });
      }
      
      return findings;
    }
  },

  // Akamai API Gateway detection
  {
    id: 'APIVET054',
    title: 'Akamai API Gateway detected',
    description: 'Ensure Akamai API security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();
      
      const isAkamai = servers.some(s => 
        s.url.includes('.akamaized.net') ||
        s.url.includes('.akamaiapis.net') ||
        s.url.includes('.akamai.com')
      ) || specStr.includes('akamai');
      
      if (isAkamai) {
        findings.push({
          ruleId: 'APIVET054',
          title: 'Akamai API Gateway detected',
          description: 'This API uses Akamai. Ensure Kona Site Defender, Bot Manager, and API Gateway security features are properly configured.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Enable Kona Site Defender for WAF protection. Configure Bot Manager for bot detection. Use API Gateway for schema validation and rate limiting. Enable API Security features.'
        });
      }
      
      return findings;
    }
  },

  // Fastly detection
  {
    id: 'APIVET055',
    title: 'Fastly CDN detected',
    description: 'Ensure Fastly security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();
      
      const isFastly = servers.some(s => 
        s.url.includes('.fastly.net') ||
        s.url.includes('.global.ssl.fastly.net')
      ) || specStr.includes('fastly');
      
      if (isFastly) {
        findings.push({
          ruleId: 'APIVET055',
          title: 'Fastly CDN detected',
          description: 'This API uses Fastly. Ensure Next-Gen WAF and rate limiting are properly configured.',
          severity: 'info',
          owaspCategory: 'API8:2023',
          location: { path: filePath },
          remediation: 'Enable Fastly Next-Gen WAF (Signal Sciences). Configure rate limiting with Edge Rate Limiting. Use VCL for custom security logic. Enable request logging for monitoring.'
        });
      }
      
      return findings;
    }
  }
];

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

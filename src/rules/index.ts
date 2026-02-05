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

import { describe, it, expect } from 'vitest';
import { runRules, rules } from '../src/rules/index.js';
import type { OpenApiSpec } from '../src/types.js';

describe('ApiVet Rules', () => {
  describe('APIVET001 - Broken Object Level Authorization', () => {
    it('should detect endpoint with path param but no security', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/users/{id}': {
            get: {
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const bolaFinding = findings.find(f => f.ruleId === 'APIVET001');
      
      expect(bolaFinding).toBeDefined();
      expect(bolaFinding?.severity).toBe('high');
      expect(bolaFinding?.owaspCategory).toBe('API1:2023');
    });

    it('should not flag when global security is defined', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        security: [{ bearerAuth: [] }],
        components: {
          securitySchemes: {
            bearerAuth: { type: 'http', scheme: 'bearer' }
          }
        },
        paths: {
          '/users/{id}': {
            get: {
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const bolaFinding = findings.find(f => f.ruleId === 'APIVET001');
      
      expect(bolaFinding).toBeUndefined();
    });
  });

  describe('APIVET002 - Weak Authentication', () => {
    it('should detect basic auth', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            basicAuth: { type: 'http', scheme: 'basic' }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const basicAuthFinding = findings.find(f => f.ruleId === 'APIVET002');
      
      expect(basicAuthFinding).toBeDefined();
      expect(basicAuthFinding?.severity).toBe('high');
    });
  });

  describe('APIVET003 - No Authentication', () => {
    it('should detect missing security schemes', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/data': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const noAuthFinding = findings.find(f => f.ruleId === 'APIVET003');
      
      expect(noAuthFinding).toBeDefined();
      expect(noAuthFinding?.severity).toBe('critical');
    });
  });

  describe('APIVET004 - Sensitive Data Exposure', () => {
    it('should detect sensitive properties in response', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/users': {
            get: {
              responses: {
                '200': {
                  description: 'OK',
                  content: {
                    'application/json': {
                      schema: {
                        type: 'object',
                        properties: {
                          id: { type: 'integer' },
                          password: { type: 'string' },
                          ssn: { type: 'string' }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const sensitiveFindings = findings.filter(f => f.ruleId === 'APIVET004');
      
      expect(sensitiveFindings.length).toBe(2);
      expect(sensitiveFindings.some(f => f.title.includes('password'))).toBe(true);
      expect(sensitiveFindings.some(f => f.title.includes('ssn'))).toBe(true);
    });
  });

  describe('APIVET006 - Pagination', () => {
    it('should detect collection endpoint without pagination', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/users': {
            get: {
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const paginationFinding = findings.find(f => f.ruleId === 'APIVET006');
      
      expect(paginationFinding).toBeDefined();
      expect(paginationFinding?.severity).toBe('medium');
    });

    it('should not flag when pagination params exist', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/users': {
            get: {
              parameters: [
                { name: 'page', in: 'query', schema: { type: 'integer' } },
                { name: 'limit', in: 'query', schema: { type: 'integer' } }
              ],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const paginationFinding = findings.find(f => f.ruleId === 'APIVET006');
      
      expect(paginationFinding).toBeUndefined();
    });
  });

  describe('APIVET007 - Admin Endpoint', () => {
    it('should detect admin endpoint without security', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/admin/users': {
            delete: {
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const adminFinding = findings.find(f => f.ruleId === 'APIVET007');
      
      expect(adminFinding).toBeDefined();
      expect(adminFinding?.severity).toBe('high');
    });
  });

  describe('APIVET008 - SSRF', () => {
    it('should detect URL parameters', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/fetch': {
            post: {
              parameters: [
                { name: 'targetUrl', in: 'query', schema: { type: 'string', format: 'uri' } }
              ],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const ssrfFinding = findings.find(f => f.ruleId === 'APIVET008');
      
      expect(ssrfFinding).toBeDefined();
      expect(ssrfFinding?.severity).toBe('high');
    });
  });

  describe('APIVET009 - HTTP Server', () => {
    it('should detect non-HTTPS server URL', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'http://api.example.com' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const httpFinding = findings.find(f => f.ruleId === 'APIVET009');
      
      expect(httpFinding).toBeDefined();
      expect(httpFinding?.severity).toBe('high');
    });

    it('should allow localhost HTTP', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'http://localhost:3000' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const httpFinding = findings.find(f => f.ruleId === 'APIVET009');
      
      expect(httpFinding).toBeUndefined();
    });
  });

  describe('APIVET011 - Deprecated Endpoints', () => {
    it('should detect deprecated endpoints', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/old-api': {
            get: {
              deprecated: true,
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const deprecatedFinding = findings.find(f => f.ruleId === 'APIVET011');
      
      expect(deprecatedFinding).toBeDefined();
      expect(deprecatedFinding?.severity).toBe('low');
    });
  });

  describe('APIVET016 - OAuth2 Implicit Flow', () => {
    it('should detect OAuth2 implicit flow', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            oauth: {
              type: 'oauth2',
              flows: {
                implicit: {
                  authorizationUrl: 'https://auth.example.com/authorize',
                  scopes: { read: 'Read access' }
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const implicitFinding = findings.find(f => f.ruleId === 'APIVET016');
      
      expect(implicitFinding).toBeDefined();
      expect(implicitFinding?.severity).toBe('high');
    });
  });

  describe('APIVET017 - OAuth2 Password Flow', () => {
    it('should detect OAuth2 password flow', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            oauth: {
              type: 'oauth2',
              flows: {
                password: {
                  tokenUrl: 'https://auth.example.com/token',
                  scopes: { read: 'Read access' }
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const passwordFinding = findings.find(f => f.ruleId === 'APIVET017');
      
      expect(passwordFinding).toBeDefined();
      expect(passwordFinding?.severity).toBe('high');
    });
  });

  describe('APIVET018 - OAuth2 HTTP Endpoint', () => {
    it('should detect OAuth2 token URL using HTTP', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            oauth: {
              type: 'oauth2',
              flows: {
                clientCredentials: {
                  tokenUrl: 'http://auth.example.com/token',
                  scopes: { read: 'Read access' }
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const httpFinding = findings.find(f => f.ruleId === 'APIVET018');
      
      expect(httpFinding).toBeDefined();
      expect(httpFinding?.severity).toBe('critical');
    });

    it('should allow localhost HTTP for development', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            oauth: {
              type: 'oauth2',
              flows: {
                clientCredentials: {
                  tokenUrl: 'http://localhost:8080/token',
                  scopes: {}
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const httpFinding = findings.find(f => f.ruleId === 'APIVET018');
      
      expect(httpFinding).toBeUndefined();
    });
  });

  describe('APIVET019 - API Key in Query', () => {
    it('should detect API key in query parameter', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            apiKey: {
              type: 'apiKey',
              in: 'query',
              name: 'api_key'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const queryKeyFinding = findings.find(f => f.ruleId === 'APIVET019');
      
      expect(queryKeyFinding).toBeDefined();
      expect(queryKeyFinding?.severity).toBe('medium');
    });

    it('should not flag API key in header', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            apiKey: {
              type: 'apiKey',
              in: 'header',
              name: 'X-API-Key'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const queryKeyFinding = findings.find(f => f.ruleId === 'APIVET019');
      
      expect(queryKeyFinding).toBeUndefined();
    });
  });

  describe('APIVET020 - OAuth2 Broad Scopes', () => {
    it('should detect overly broad OAuth2 scopes', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            oauth: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://auth.example.com/authorize',
                  tokenUrl: 'https://auth.example.com/token',
                  scopes: {
                    'admin': 'Full admin access',
                    'read': 'Read only'
                  }
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const scopeFinding = findings.find(f => f.ruleId === 'APIVET020');
      
      expect(scopeFinding).toBeDefined();
      expect(scopeFinding?.title).toContain('admin');
    });
  });

  describe('APIVET021 - OpenID Connect HTTP', () => {
    it('should detect OpenID Connect URL using HTTP', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            oidc: {
              type: 'openIdConnect',
              openIdConnectUrl: 'http://auth.example.com/.well-known/openid-configuration'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const oidcFinding = findings.find(f => f.ruleId === 'APIVET021');
      
      expect(oidcFinding).toBeDefined();
      expect(oidcFinding?.severity).toBe('critical');
    });
  });

  describe('APIVET022 - JWT Weak Algorithm', () => {
    it('should detect JWT none algorithm mention', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            bearer: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT',
              description: 'Accepts JWT tokens. Supports alg: none for testing.'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const jwtFinding = findings.find(f => f.ruleId === 'APIVET022' && f.title.includes('none'));
      
      expect(jwtFinding).toBeDefined();
      expect(jwtFinding?.severity).toBe('critical');
    });

    it('should detect symmetric JWT algorithm mention', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            bearer: {
              type: 'http',
              scheme: 'bearer',
              bearerFormat: 'JWT',
              description: 'JWT tokens signed with HS256'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const jwtFinding = findings.find(f => f.ruleId === 'APIVET022' && f.title.includes('HS256'));
      
      expect(jwtFinding).toBeDefined();
      expect(jwtFinding?.severity).toBe('medium');
    });
  });

  describe('APIVET023 - OAuth2 Missing Refresh URL', () => {
    it('should detect missing refresh URL in authorization code flow', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            oauth: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://auth.example.com/authorize',
                  tokenUrl: 'https://auth.example.com/token',
                  scopes: { read: 'Read' }
                  // No refreshUrl
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const refreshFinding = findings.find(f => f.ruleId === 'APIVET023');
      
      expect(refreshFinding).toBeDefined();
      expect(refreshFinding?.severity).toBe('low');
    });
  });

  describe('APIVET025 - Cookie Auth', () => {
    it('should flag cookie-based API key authentication', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            cookieAuth: {
              type: 'apiKey',
              in: 'cookie',
              name: 'session_id'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const cookieFinding = findings.find(f => f.ruleId === 'APIVET025');
      
      expect(cookieFinding).toBeDefined();
      expect(cookieFinding?.severity).toBe('medium');
    });
  });

  // ============================================
  // Cloud Provider Rules
  // ============================================

  describe('APIVET026 - AWS API Gateway Authorization', () => {
    it('should detect AWS API Gateway endpoint without authorizer', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/items': {
            get: {
              responses: { '200': { description: 'OK' } },
              'x-amazon-apigateway-integration': {
                type: 'aws_proxy',
                uri: 'arn:aws:lambda:...'
              }
            } as any
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const awsFinding = findings.find(f => f.ruleId === 'APIVET026');
      
      expect(awsFinding).toBeDefined();
      expect(awsFinding?.severity).toBe('high');
    });
  });

  describe('APIVET027 - AWS Request Validation', () => {
    it('should detect missing request validators', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        'x-amazon-apigateway-integration': {} as any,
        paths: {
          '/items': {
            get: {
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const validatorFinding = findings.find(f => f.ruleId === 'APIVET027');
      
      expect(validatorFinding).toBeDefined();
    });
  });

  describe('APIVET032 - Non-Production URL', () => {
    it('should detect staging URLs', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://api-staging.example.com' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const stagingFinding = findings.find(f => f.ruleId === 'APIVET032');
      
      expect(stagingFinding).toBeDefined();
      expect(stagingFinding?.severity).toBe('medium');
    });

    it('should detect dev URLs', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://dev.api.example.com', description: 'Development server' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const devFinding = findings.find(f => f.ruleId === 'APIVET032');
      
      expect(devFinding).toBeDefined();
    });
  });

  describe('APIVET033 - Internal URL Exposure', () => {
    it('should detect private IP addresses', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'http://192.168.1.100:8080' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const internalFinding = findings.find(f => f.ruleId === 'APIVET033');
      
      expect(internalFinding).toBeDefined();
      expect(internalFinding?.severity).toBe('high');
    });

    it('should detect 10.x.x.x addresses', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://10.0.0.50/api' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const internalFinding = findings.find(f => f.ruleId === 'APIVET033');
      
      expect(internalFinding).toBeDefined();
    });

    it('should detect .internal domains', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://api.internal.company.com' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const internalFinding = findings.find(f => f.ruleId === 'APIVET033');
      
      expect(internalFinding).toBeDefined();
    });
  });

  describe('APIVET034 - Lambda Proxy Validation', () => {
    it('should detect Lambda proxy without validation', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/items': {
            post: {
              requestBody: {
                content: { 'application/json': { schema: { type: 'object' } } }
              },
              responses: { '200': { description: 'OK' } },
              'x-amazon-apigateway-integration': {
                type: 'aws_proxy',
                uri: 'arn:aws:lambda:...'
              }
            } as any
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const proxyFinding = findings.find(f => f.ruleId === 'APIVET034');
      
      expect(proxyFinding).toBeDefined();
      expect(proxyFinding?.severity).toBe('medium');
    });
  });

  describe('APIVET030 - Azure APIM Detection', () => {
    it('should detect Azure APIM URLs', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://myapi.azure-api.net' }
        ],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const azureFinding = findings.find(f => f.ruleId === 'APIVET030');
      
      expect(azureFinding).toBeDefined();
    });
  });

  describe('APIVET031 - GCP Detection', () => {
    it('should detect GCP Cloud Run URLs', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://myservice-abc123.run.app' }
        ],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const gcpFinding = findings.find(f => f.ruleId === 'APIVET031');
      
      expect(gcpFinding).toBeDefined();
    });
  });

  // ============================================
  // Extended Cloud Provider Rules
  // ============================================

  describe('APIVET041 - GCP Cloud Run Auth', () => {
    it('should detect Cloud Run without auth', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://my-service-abc123.run.app' }
        ],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const cloudRunFinding = findings.find(f => f.ruleId === 'APIVET041');
      
      expect(cloudRunFinding).toBeDefined();
      expect(cloudRunFinding?.severity).toBe('medium');
    });
  });

  describe('APIVET043 - Cloudflare Workers', () => {
    it('should detect Cloudflare Workers', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://my-api.workers.dev' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const cfFinding = findings.find(f => f.ruleId === 'APIVET043');
      
      expect(cfFinding).toBeDefined();
    });
  });

  describe('APIVET044 - Vercel', () => {
    it('should detect Vercel deployment', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://my-app.vercel.app' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const vercelFinding = findings.find(f => f.ruleId === 'APIVET044');
      
      expect(vercelFinding).toBeDefined();
    });
  });

  describe('APIVET050 - Supabase', () => {
    it('should detect Supabase API', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://abc123.supabase.co' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const supabaseFinding = findings.find(f => f.ruleId === 'APIVET050');
      
      expect(supabaseFinding).toBeDefined();
      expect(supabaseFinding?.severity).toBe('medium');
    });
  });

  describe('APIVET051 - PaaS Detection', () => {
    it('should detect Railway deployment', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://my-app.railway.app' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const paasFinding = findings.find(f => f.ruleId === 'APIVET051');
      
      expect(paasFinding).toBeDefined();
    });

    it('should detect Render deployment', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://my-api.onrender.com' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const paasFinding = findings.find(f => f.ruleId === 'APIVET051');
      
      expect(paasFinding).toBeDefined();
    });

    it('should detect Fly.io deployment', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://my-app.fly.dev' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const paasFinding = findings.find(f => f.ruleId === 'APIVET051');
      
      expect(paasFinding).toBeDefined();
    });
  });

  describe('APIVET052 - Heroku', () => {
    it('should detect Heroku deployment', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://my-app.herokuapp.com' }
        ],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const herokuFinding = findings.find(f => f.ruleId === 'APIVET052');
      
      expect(herokuFinding).toBeDefined();
    });
  });

  describe('Rule count', () => {
    it('should have at least 55 rules', () => {
      expect(rules.length).toBeGreaterThanOrEqual(55);
    });
  });
});

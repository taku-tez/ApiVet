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

    // FB5: $ref resolution
    it('should detect sensitive properties via $ref', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          schemas: {
            User: {
              type: 'object',
              properties: {
                id: { type: 'integer' },
                password: { type: 'string' },
                email: { type: 'string' }
              }
            }
          }
        },
        paths: {
          '/users': {
            get: {
              responses: {
                '200': {
                  description: 'OK',
                  content: {
                    'application/json': {
                      schema: {
                        $ref: '#/components/schemas/User'
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
      
      expect(sensitiveFindings.some(f => f.title.includes('password'))).toBe(true);
    });

    // FB5: Nested schema traversal
    it('should detect sensitive properties in nested schemas', () => {
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
                          data: {
                            type: 'object',
                            properties: {
                              credentials: {
                                type: 'object',
                                properties: {
                                  secret_key: { type: 'string' }
                                }
                              }
                            }
                          }
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
      
      expect(sensitiveFindings.some(f => f.title.includes('secret_key'))).toBe(true);
    });

    // FB6: JSON-compatible content types
    it('should detect sensitive properties in application/hal+json', () => {
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
                    'application/hal+json': {
                      schema: {
                        type: 'object',
                        properties: {
                          api_key: { type: 'string' }
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
      
      expect(sensitiveFindings.some(f => f.title.includes('api_key'))).toBe(true);
    });

    // FB5: $ref resolution with allOf/oneOf
    it('should detect sensitive properties via allOf', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          schemas: {
            BaseUser: {
              type: 'object',
              properties: {
                id: { type: 'integer' }
              }
            },
            UserCredentials: {
              type: 'object',
              properties: {
                password: { type: 'string' }
              }
            }
          }
        },
        paths: {
          '/users': {
            get: {
              responses: {
                '200': {
                  description: 'OK',
                  content: {
                    'application/json': {
                      schema: {
                        allOf: [
                          { $ref: '#/components/schemas/BaseUser' },
                          { $ref: '#/components/schemas/UserCredentials' }
                        ]
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
      
      expect(sensitiveFindings.some(f => f.title.includes('password'))).toBe(true);
    });

    it('should detect sensitive properties in application/vnd.api+json', () => {
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
                    'application/vnd.api+json': {
                      schema: {
                        type: 'object',
                        properties: {
                          credit_card: { type: 'string' }
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
      
      expect(sensitiveFindings.some(f => f.title.includes('credit_card'))).toBe(true);
    });
  });

  describe('APIVET005 - Rate Limiting', () => {
    it('should detect missing rate limit headers', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/users': {
            get: {
              responses: {
                '200': { description: 'OK' }
              }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const rateLimitFinding = findings.find(f => f.ruleId === 'APIVET005');
      
      expect(rateLimitFinding).toBeDefined();
    });

    it('should not flag when rate limit headers are defined', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        paths: {
          '/users': {
            get: {
              responses: {
                '200': {
                  description: 'OK',
                  headers: {
                    'X-RateLimit-Limit': { schema: { type: 'integer' } }
                  }
                }
              }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const rateLimitFinding = findings.find(f => f.ruleId === 'APIVET005');
      
      expect(rateLimitFinding).toBeUndefined();
    });

    // FB4: $ref resolution for headers
    it('should detect rate limit headers via $ref', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          headers: {
            RateLimitHeader: {
              schema: { type: 'integer' },
              description: 'Rate limit'
            }
          }
        },
        paths: {
          '/users': {
            get: {
              responses: {
                '200': {
                  description: 'OK',
                  headers: {
                    'X-RateLimit-Limit': { $ref: '#/components/headers/RateLimitHeader' }
                  }
                }
              }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const rateLimitFinding = findings.find(f => f.ruleId === 'APIVET005');
      
      // Should NOT flag because rate limit header is defined (via $ref)
      expect(rateLimitFinding).toBeUndefined();
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

  // ============================================
  // Azure APIM Deep Security Rules (APIVET056-065)
  // ============================================

  describe('APIVET056 - Azure APIM Subscription Key', () => {
    it('should detect APIM without subscription key scheme', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET056');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag when subscription key is defined', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        components: {
          securitySchemes: {
            subscriptionKey: {
              type: 'apiKey',
              in: 'header',
              name: 'Ocp-Apim-Subscription-Key'
            }
          }
        },
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET056');
      expect(finding).toBeUndefined();
    });

    it('should not flag non-APIM APIs', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://api.example.com' }],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET056');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET057 - Azure Management Endpoint', () => {
    it('should detect management.azure.com in servers', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://management.azure.com/subscriptions/xxx' }],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET057');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
    });

    it('should not flag APIM gateway URLs', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET057');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET058 - Azure APIM Auth', () => {
    it('should detect APIM endpoint without auth', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET058');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
    });

    it('should not flag when global security is defined', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        security: [{ apiKey: [] }],
        components: {
          securitySchemes: {
            apiKey: { type: 'apiKey', in: 'header', name: 'Ocp-Apim-Subscription-Key' }
          }
        },
        paths: {
          '/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET058');
      expect(finding).toBeUndefined();
    });

    it('should not flag when operation has security', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/users': {
            get: {
              security: [{ bearerAuth: [] }],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET058');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET059 - Azure APIM Rate Limiting', () => {
    it('should detect APIM without rate limiting', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET059');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag when rate limit headers exist', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/users': {
            get: {
              responses: {
                '200': {
                  description: 'OK',
                  headers: {
                    'X-RateLimit-Limit': { schema: { type: 'integer' } }
                  }
                }
              }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET059');
      expect(finding).toBeUndefined();
    });

    it('should not flag when 429 response is defined', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/users': {
            get: {
              responses: {
                '200': { description: 'OK' },
                '429': { description: 'Too Many Requests' }
              }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET059');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET060 - Azure APIM Versioning', () => {
    it('should detect APIM without versioning', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET060');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('low');
    });

    it('should not flag when version in path', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/v1/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET060');
      expect(finding).toBeUndefined();
    });

    it('should not flag when api-version query param exists', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {
          '/users': {
            get: {
              parameters: [
                { name: 'api-version', in: 'query', schema: { type: 'string' } }
              ],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET060');
      expect(finding).toBeUndefined();
    });

    it('should not flag when version in server URL', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net/v2' }],
        paths: {
          '/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET060');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET061 - Azure APIM Subscription Key in Query', () => {
    it('should detect subscription key in query string', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        components: {
          securitySchemes: {
            subKey: {
              type: 'apiKey',
              in: 'query',
              name: 'subscription-key'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET061');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag subscription key in header', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        components: {
          securitySchemes: {
            subKey: {
              type: 'apiKey',
              in: 'header',
              name: 'Ocp-Apim-Subscription-Key'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET061');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET062 - Azure APIM Backend HTTPS', () => {
    it('should detect APIM HTTP server URL', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'http://myapi.azure-api.net' }],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET062');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
    });

    it('should not flag HTTPS APIM URL', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET062');
      expect(finding).toBeUndefined();
    });

    it('should detect HTTP parameterized host', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        'x-ms-parameterized-host': {
          hostTemplate: 'http://{region}.azure-api.net',
          parameters: [{ name: 'region' }]
        },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: {}
      } as any;

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET062');
      expect(finding).toBeDefined();
    });
  });

  describe('APIVET063 - Azure Entra ID Detection', () => {
    it('should detect Entra ID OAuth2', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            entra: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize',
                  tokenUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
                  scopes: { read: 'Read' }
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET063');
      expect(finding).toBeDefined();
      expect(finding?.title).toContain('Entra ID');
    });

    it('should detect Azure B2C', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        components: {
          securitySchemes: {
            b2c: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://contoso.b2clogin.com/contoso.onmicrosoft.com/oauth2/v2.0/authorize',
                  tokenUrl: 'https://contoso.b2clogin.com/contoso.onmicrosoft.com/oauth2/v2.0/token',
                  scopes: { read: 'Read' }
                }
              }
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET063');
      expect(finding).toBeDefined();
      expect(finding?.title).toContain('B2C');
    });
  });

  describe('APIVET064 - Azure APIM WAF', () => {
    it('should detect APIM without WAF indication', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET064');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('low');
    });

    it('should not flag when Front Door is present', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [
          { url: 'https://myapi.azure-api.net' },
          { url: 'https://myapi.azurefd.net' }
        ],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET064');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET065 - Azure APIM OAuth2 Scopes', () => {
    it('should detect Entra ID OAuth2 without scopes on endpoint', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        components: {
          securitySchemes: {
            entra: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize',
                  tokenUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
                  scopes: { 'api://app/read': 'Read', 'api://app/write': 'Write' }
                }
              }
            }
          }
        },
        paths: {
          '/data': {
            get: {
              security: [{ entra: [] }],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET065');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag when scopes are specified', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        components: {
          securitySchemes: {
            entra: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/authorize',
                  tokenUrl: 'https://login.microsoftonline.com/tenant/oauth2/v2.0/token',
                  scopes: { 'api://app/read': 'Read' }
                }
              }
            }
          }
        },
        paths: {
          '/data': {
            get: {
              security: [{ entra: ['api://app/read'] }],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET065');
      expect(finding).toBeUndefined();
    });

    it('should not flag non-Azure OAuth2', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.azure-api.net' }],
        components: {
          securitySchemes: {
            auth0: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://example.auth0.com/authorize',
                  tokenUrl: 'https://example.auth0.com/oauth/token',
                  scopes: { read: 'Read' }
                }
              }
            }
          }
        },
        paths: {
          '/data': {
            get: {
              security: [{ auth0: [] }],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET065');
      expect(finding).toBeUndefined();
    });
  });

  // ============================================
  // GCP Deep Security Rules (APIVET066-075)
  // ============================================

  describe('APIVET066 - GCP API Key Requirement', () => {
    it('should detect GCP API without API key scheme', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET066');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag when API key is defined', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        components: {
          securitySchemes: {
            apiKey: { type: 'apiKey', in: 'query', name: 'key' }
          }
        },
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET066');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET067 - GCP Unauthenticated Access', () => {
    it('should detect x-google-allow: all on endpoint', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.run.app' }],
        paths: {
          '/public': {
            get: {
              'x-google-allow': 'all',
              responses: { '200': { description: 'OK' } }
            } as any
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET067');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
    });

    it('should detect x-google-allow: all at spec level', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        'x-google-allow': 'all',
        servers: [{ url: 'https://myapi.cloudfunctions.net' }],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      } as any;

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET067');
      expect(finding).toBeDefined();
    });
  });

  describe('APIVET068 - GCP Cloud Functions Auth', () => {
    it('should detect Cloud Functions without auth', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://region-project.cloudfunctions.net' }],
        paths: { '/func': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET068');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag when security is defined', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://region-project.cloudfunctions.net' }],
        security: [{ bearerAuth: [] }],
        components: {
          securitySchemes: {
            bearerAuth: { type: 'http', scheme: 'bearer' }
          }
        },
        paths: { '/func': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET068');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET069 - GCP API Quota', () => {
    it('should detect GCP API without quota', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET069');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag when 429 response exists', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: {
          '/test': {
            get: {
              responses: {
                '200': { description: 'OK' },
                '429': { description: 'Quota exceeded' }
              }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET069');
      expect(finding).toBeUndefined();
    });

    it('should not flag when x-google-quota exists', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: {
          '/test': {
            get: {
              'x-google-quota': { metricCosts: { 'read-requests': 1 } },
              responses: { '200': { description: 'OK' } }
            } as any
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET069');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET070 - GCP Cloud Armor', () => {
    it('should detect GCP API without Cloud Armor', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.run.app' }],
        paths: { '/test': { get: { responses: { '200': { description: 'OK' } } } } }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET070');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('low');
    });
  });

  describe('APIVET071 - GCP Backend HTTPS', () => {
    it('should detect HTTP in x-google-backend', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: {
          '/test': {
            get: {
              'x-google-backend': {
                address: 'http://backend.internal:8080'
              },
              responses: { '200': { description: 'OK' } }
            } as any
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET071');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
    });

    it('should not flag HTTPS backend', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: {
          '/test': {
            get: {
              'x-google-backend': {
                address: 'https://backend.run.app'
              },
              responses: { '200': { description: 'OK' } }
            } as any
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET071');
      expect(finding).toBeUndefined();
    });

    it('should allow localhost HTTP', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: {
          '/test': {
            get: {
              'x-google-backend': {
                address: 'http://localhost:8080'
              },
              responses: { '200': { description: 'OK' } }
            } as any
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET071');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET072 - GCP API Versioning', () => {
    it('should detect GCP API without versioning', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: {
          '/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET072');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('low');
    });

    it('should not flag when version in path', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        paths: {
          '/v1/users': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET072');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET073 - Apigee Detection', () => {
    it('should detect Apigee URLs', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://org-env.apigee.net/v1' }],
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET073');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('info');
    });
  });

  describe('APIVET074 - GCP OAuth2 Scopes', () => {
    it('should detect Google OAuth2 without scopes', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.run.app' }],
        components: {
          securitySchemes: {
            google: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
                  tokenUrl: 'https://oauth2.googleapis.com/token',
                  scopes: { 'https://www.googleapis.com/auth/cloud-platform': 'Cloud Platform' }
                }
              }
            }
          }
        },
        paths: {
          '/data': {
            get: {
              security: [{ google: [] }],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET074');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag when scopes are specified', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.run.app' }],
        components: {
          securitySchemes: {
            google: {
              type: 'oauth2',
              flows: {
                authorizationCode: {
                  authorizationUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
                  tokenUrl: 'https://oauth2.googleapis.com/token',
                  scopes: { 'https://www.googleapis.com/auth/cloud-platform': 'Cloud Platform' }
                }
              }
            }
          }
        },
        paths: {
          '/data': {
            get: {
              security: [{ google: ['https://www.googleapis.com/auth/cloud-platform'] }],
              responses: { '200': { description: 'OK' } }
            }
          }
        }
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET074');
      expect(finding).toBeUndefined();
    });
  });

  describe('APIVET075 - GCP API Key in Query', () => {
    it('should detect API key in query string', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
        components: {
          securitySchemes: {
            apiKey: {
              type: 'apiKey',
              in: 'query',
              name: 'key'
            }
          }
        },
        paths: {}
      };

      const findings = runRules(spec, 'test.yaml');
      const finding = findings.find(f => f.ruleId === 'APIVET075');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('medium');
    });

    it('should not flag API key in header', () => {
      const spec: OpenApiSpec = {
        openapi: '3.0.0',
        info: { title: 'Test', version: '1.0.0' },
        servers: [{ url: 'https://myapi.endpoints.project.cloud.goog' }],
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
      const finding = findings.find(f => f.ruleId === 'APIVET075');
      expect(finding).toBeUndefined();
    });
  });

  describe('Rule count', () => {
    it('should have at least 75 rules', () => {
      expect(rules.length).toBeGreaterThanOrEqual(75);
    });
  });
});

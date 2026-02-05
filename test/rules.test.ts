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

  describe('Rule count', () => {
    it('should have at least 15 rules', () => {
      expect(rules.length).toBeGreaterThanOrEqual(15);
    });
  });
});

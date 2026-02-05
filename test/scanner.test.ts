import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { scanOpenApiSpec, scanFile } from '../src/scanner/index.js';

// FB5: Use os.tmpdir() for cross-platform compatibility
const TEST_DIR = path.join(os.tmpdir(), 'apivet-test-specs');

beforeAll(() => {
  fs.mkdirSync(TEST_DIR, { recursive: true });
  
  // Create test OpenAPI spec
  const validSpec = {
    openapi: '3.0.0',
    info: { title: 'Test API', version: '1.0.0' },
    paths: {
      '/health': {
        get: { responses: { '200': { description: 'OK' } } }
      }
    }
  };
  
  fs.writeFileSync(
    path.join(TEST_DIR, 'valid.yaml'),
    `openapi: "3.0.0"
info:
  title: Test API
  version: "1.0.0"
paths:
  /health:
    get:
      responses:
        "200":
          description: OK
`
  );
  
  fs.writeFileSync(
    path.join(TEST_DIR, 'valid.json'),
    JSON.stringify(validSpec, null, 2)
  );
  
  fs.writeFileSync(
    path.join(TEST_DIR, 'invalid.yaml'),
    'this is not a valid spec'
  );
  
  // Create Swagger 2.0 spec
  fs.writeFileSync(
    path.join(TEST_DIR, 'swagger.json'),
    JSON.stringify({
      swagger: '2.0',
      info: { title: 'Legacy API', version: '1.0.0' },
      paths: {
        '/legacy': {
          get: { responses: { '200': { description: 'OK' } } }
        }
      }
    }, null, 2)
  );
});

afterAll(() => {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
});

describe('Scanner', () => {
  describe('scanFile', () => {
    it('should parse YAML spec', async () => {
      const result = await scanFile(path.join(TEST_DIR, 'valid.yaml'));
      
      expect(result.error).toBeUndefined();
      expect(result.spec).toBeDefined();
      expect(result.spec?.title).toBe('Test API');
      expect(result.spec?.openApiVersion).toBe('3.0.0');
    });

    it('should parse JSON spec', async () => {
      const result = await scanFile(path.join(TEST_DIR, 'valid.json'));
      
      expect(result.error).toBeUndefined();
      expect(result.spec).toBeDefined();
      expect(result.spec?.title).toBe('Test API');
    });

    it('should parse Swagger 2.0 spec', async () => {
      const result = await scanFile(path.join(TEST_DIR, 'swagger.json'));
      
      expect(result.error).toBeUndefined();
      expect(result.spec).toBeDefined();
      expect(result.spec?.title).toBe('Legacy API');
      expect(result.spec?.openApiVersion).toBe('2.0');
    });

    it('should handle invalid spec gracefully', async () => {
      const result = await scanFile(path.join(TEST_DIR, 'invalid.yaml'));
      
      expect(result.error).toBe('Not a valid OpenAPI/Swagger specification');
    });

    it('should handle non-existent file', async () => {
      const result = await scanFile(path.join(TEST_DIR, 'nonexistent.yaml'));
      
      expect(result.error).toBeDefined();
    });
  });

  describe('scanOpenApiSpec', () => {
    it('should scan single file', async () => {
      const results = await scanOpenApiSpec(path.join(TEST_DIR, 'valid.yaml'));
      
      expect(results.length).toBe(1);
      expect(results[0].spec).toBeDefined();
    });

    it('should scan directory', async () => {
      const results = await scanOpenApiSpec(TEST_DIR);
      
      // Should find valid.yaml, valid.json, swagger.json, invalid.yaml
      expect(results.length).toBeGreaterThanOrEqual(3);
    });

    // FB3: scanOpenApiSpec should handle non-existent paths gracefully
    it('should return error result for non-existent path instead of throwing', async () => {
      const results = await scanOpenApiSpec('/nonexistent/path/to/spec.yaml');
      
      expect(results.length).toBe(1);
      expect(results[0].error).toBeDefined();
      expect(results[0].error).toContain('not found');
      expect(results[0].findings).toEqual([]);
    });

    it('should filter by severity', async () => {
      // Create a spec with known findings
      const specWithIssues = {
        openapi: '3.0.0',
        info: { title: 'Insecure API', version: '1.0.0' },
        servers: [{ url: 'http://api.example.com' }], // APIVET009 - high
        paths: {
          '/users/{id}': {
            get: { responses: { '200': { description: 'OK' } } }
          }
        }
      };
      
      const testFile = path.join(TEST_DIR, 'insecure.json');
      fs.writeFileSync(testFile, JSON.stringify(specWithIssues, null, 2));
      
      const allResults = await scanOpenApiSpec(testFile);
      const highResults = await scanOpenApiSpec(testFile, { severity: 'high' });
      const criticalResults = await scanOpenApiSpec(testFile, { severity: 'critical' });
      
      expect(highResults[0].findings.length).toBeLessThanOrEqual(allResults[0].findings.length);
      expect(criticalResults[0].findings.length).toBeLessThanOrEqual(highResults[0].findings.length);
    });
  });
});

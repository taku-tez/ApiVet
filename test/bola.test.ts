import { describe, it, expect } from 'vitest';
import {
  extractIdEndpoints,
  isIdParameter,
  isUuidV1,
  generateSequentialIds,
  generateUuidV1Predictions,
  generateTestCases,
  isAdminEndpoint,
  runBolaTests,
} from '../src/bola/index.js';
import type { OpenApiSpec } from '../src/types.js';

// ── Sample Specs ───────────────────────────────────────────────────────

const sampleSpec: OpenApiSpec = {
  openapi: '3.0.0',
  info: { title: 'Test API', version: '1.0.0' },
  paths: {
    '/users/{userId}': {
      get: {
        operationId: 'getUser',
        parameters: [
          { name: 'userId', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: { '200': { description: 'OK' } },
      },
      put: {
        operationId: 'updateUser',
        parameters: [
          { name: 'userId', in: 'path', required: true, schema: { type: 'string' } },
        ],
        responses: { '200': { description: 'OK' } },
      },
    },
    '/orders/{id}': {
      get: {
        operationId: 'getOrder',
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { '200': { description: 'OK' } },
      },
      delete: {
        operationId: 'deleteOrder',
        parameters: [
          { name: 'id', in: 'path', required: true, schema: { type: 'integer' } },
        ],
        responses: { '204': { description: 'Deleted' } },
      },
    },
    '/products': {
      get: {
        operationId: 'listProducts',
        parameters: [
          { name: 'category', in: 'query', schema: { type: 'string' } },
        ],
        responses: { '200': { description: 'OK' } },
      },
    },
    '/admin/settings': {
      get: {
        operationId: 'getSettings',
        responses: { '200': { description: 'OK' } },
      },
    },
  },
};

// ── isIdParameter ──────────────────────────────────────────────────────

describe('isIdParameter', () => {
  it('matches common id patterns', () => {
    expect(isIdParameter('id')).toBe(true);
    expect(isIdParameter('userId')).toBe(true);
    expect(isIdParameter('user_id')).toBe(true);
    expect(isIdParameter('orderId')).toBe(true);
    expect(isIdParameter('uuid')).toBe(true);
    expect(isIdParameter('slug')).toBe(true);
    expect(isIdParameter('username')).toBe(true);
    expect(isIdParameter('email')).toBe(true);
  });

  it('rejects non-id patterns', () => {
    expect(isIdParameter('category')).toBe(false);
    expect(isIdParameter('page')).toBe(false);
    expect(isIdParameter('limit')).toBe(false);
    expect(isIdParameter('format')).toBe(false);
  });
});

// ── extractIdEndpoints ─────────────────────────────────────────────────

describe('extractIdEndpoints', () => {
  it('extracts endpoints with id parameters', () => {
    const endpoints = extractIdEndpoints(sampleSpec);
    expect(endpoints.length).toBe(4); // getUser, updateUser, getOrder, deleteOrder
    expect(endpoints.map(e => e.path)).toContain('/users/{userId}');
    expect(endpoints.map(e => e.path)).toContain('/orders/{id}');
  });

  it('skips endpoints without id params', () => {
    const endpoints = extractIdEndpoints(sampleSpec);
    const paths = endpoints.map(e => e.path);
    expect(paths).not.toContain('/products');
  });

  it('handles empty spec', () => {
    expect(extractIdEndpoints({})).toEqual([]);
    expect(extractIdEndpoints({ paths: {} })).toEqual([]);
  });
});

// ── Sequential ID Generation ───────────────────────────────────────────

describe('generateSequentialIds', () => {
  it('generates adjacent ids', () => {
    const ids = generateSequentialIds('100', 2);
    expect(ids).toContain('101');
    expect(ids).toContain('102');
    expect(ids).toContain('99');
    expect(ids).toContain('98');
  });

  it('returns empty for non-numeric', () => {
    expect(generateSequentialIds('abc')).toEqual([]);
  });
});

// ── UUID v1 ────────────────────────────────────────────────────────────

describe('UUID v1 detection', () => {
  it('detects UUIDv1', () => {
    expect(isUuidV1('6ba7b810-9dad-11d1-80b4-00c04fd430c8')).toBe(true);
  });

  it('rejects UUIDv4', () => {
    expect(isUuidV1('550e8400-e29b-41d4-a716-446655440000')).toBe(false);
  });

  it('generates predictions for v1', () => {
    const preds = generateUuidV1Predictions('6ba7b810-9dad-11d1-80b4-00c04fd430c8', 1);
    expect(preds.length).toBe(2);
    // Should have same suffix but different time_low
    expect(preds[0]).toContain('-9dad-11d1-80b4-00c04fd430c8');
  });
});

// ── Test Case Generation ───────────────────────────────────────────────

describe('generateTestCases', () => {
  it('generates horizontal test cases', () => {
    const endpoints = extractIdEndpoints(sampleSpec);
    const cases = generateTestCases(endpoints, '1', '2');
    const horizontal = cases.filter(c => c.testType === 'horizontal');
    expect(horizontal.length).toBeGreaterThan(0);
    expect(horizontal[0].originalValue).toBe('1');
    expect(horizontal[0].replacedValue).toBe('2');
  });

  it('generates sequential id cases for numeric ids', () => {
    const endpoints = extractIdEndpoints(sampleSpec);
    const cases = generateTestCases(endpoints, '100', '200');
    const sequential = cases.filter(c => c.testType === 'sequential-id');
    expect(sequential.length).toBeGreaterThan(0);
  });
});

// ── Admin Endpoint Detection ───────────────────────────────────────────

describe('isAdminEndpoint', () => {
  it('detects admin paths', () => {
    expect(isAdminEndpoint('/admin/settings')).toBe(true);
    expect(isAdminEndpoint('/api/manage/users')).toBe(true);
    expect(isAdminEndpoint('/internal/health')).toBe(true);
    expect(isAdminEndpoint('/api/v1/users')).toBe(true);
    expect(isAdminEndpoint('/system/config')).toBe(true);
  });

  it('rejects normal paths', () => {
    expect(isAdminEndpoint('/api/products')).toBe(false);
    expect(isAdminEndpoint('/api/orders/123')).toBe(false);
  });
});

// ── runBolaTests (dry-run) ─────────────────────────────────────────────

describe('runBolaTests', () => {
  it('dry-run generates test cases without sending requests', async () => {
    const result = await runBolaTests(sampleSpec, {
      specPath: 'test.yaml',
      baseUrl: 'http://localhost:3000',
      tokenA: 'token-a',
      tokenB: 'token-b',
      dryRun: true,
    });

    expect(result.totalEndpoints).toBe(4);
    expect(result.testCases.length).toBeGreaterThan(0);
    expect(result.testCases.every(tc => tc.status === 'skipped')).toBe(true);
    expect(result.findings).toEqual([]);
    expect(result.summary.skipped).toBe(result.testCases.length);
  });

  it('handles spec with no vulnerable endpoints', async () => {
    const emptySpec: OpenApiSpec = {
      openapi: '3.0.0',
      info: { title: 'Empty', version: '1.0.0' },
      paths: {
        '/health': {
          get: { responses: { '200': { description: 'OK' } } },
        },
      },
    };

    const result = await runBolaTests(emptySpec, {
      specPath: 'test.yaml',
      baseUrl: 'http://localhost:3000',
      tokenA: 'a',
      tokenB: 'b',
      dryRun: true,
    });

    expect(result.totalEndpoints).toBe(0);
    expect(result.testCases).toEqual([]);
  });
});

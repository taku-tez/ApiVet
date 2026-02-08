import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { scanGraphQL } from '../src/graphql/index.js';

// Mock fetch globally
const mockFetch = vi.fn();
vi.stubGlobal('fetch', mockFetch);

function jsonResponse(body: unknown, status = 200): Response {
  return {
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    text: async () => JSON.stringify(body),
  } as unknown as Response;
}

describe('GraphQL Scanner', () => {
  beforeEach(() => {
    mockFetch.mockReset();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('scanGraphQL', () => {
    it('should return error for invalid URL', async () => {
      const result = await scanGraphQL('not-a-url');
      expect(result.status).toBe('error');
      expect(result.error).toContain('Invalid URL');
    });

    it('should return error for unsupported protocol', async () => {
      const result = await scanGraphQL('ftp://example.com/graphql');
      expect(result.status).toBe('error');
      expect(result.error).toContain('Unsupported protocol');
    });

    it('should return error when endpoint is unreachable', async () => {
      mockFetch.mockRejectedValue(new Error('ECONNREFUSED'));
      const result = await scanGraphQL('http://localhost:9999/graphql');
      expect(result.status).toBe('error');
      expect(result.error).toContain('Cannot reach endpoint');
    });

    it('should detect enabled introspection', async () => {
      // Ping
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      // Introspection check
      mockFetch.mockResolvedValueOnce(jsonResponse({
        data: { __schema: { queryType: { name: 'Query' }, types: [{ name: 'Query', kind: 'OBJECT' }, { name: 'User', kind: 'OBJECT' }] } }
      }));
      // Remaining checks return generic responses
      for (let i = 0; i < 10; i++) {
        mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      }

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['depth-limit', 'batch-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass', 'injection'] });
      expect(result.status).toBe('success');
      
      const introDetail = result.details.find(d => d.check === 'introspection');
      expect(introDetail?.status).toBe('fail');
      expect(introDetail?.severity).toBe('high');
      
      const finding = result.findings.find(f => f.ruleId === 'APIVET-GQL-001');
      expect(finding).toBeDefined();
      expect(finding?.severity).toBe('high');
    });

    it('should pass when introspection is disabled', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      mockFetch.mockResolvedValueOnce(jsonResponse({
        errors: [{ message: 'GraphQL introspection is not allowed' }]
      }));
      for (let i = 0; i < 10; i++) {
        mockFetch.mockResolvedValueOnce(jsonResponse({ errors: [{ message: 'Not allowed' }] }));
      }

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['depth-limit', 'batch-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass', 'injection'] });
      const introDetail = result.details.find(d => d.check === 'introspection');
      expect(introDetail?.status).toBe('pass');
    });

    it('should detect lack of depth limiting', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      // Depth check - returns data without errors
      mockFetch.mockResolvedValueOnce(jsonResponse({
        data: { __type: { fields: [{ name: 'test', type: { name: 'String', ofType: null } }] } }
      }));

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['introspection', 'batch-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass', 'injection'] });
      const detail = result.details.find(d => d.check === 'depth-limit');
      expect(detail?.status).toBe('fail');
    });

    it('should pass when depth limiting is enforced', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      mockFetch.mockResolvedValueOnce(jsonResponse({
        errors: [{ message: 'Query depth limit of 5 exceeded, found depth of 12' }]
      }));

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['introspection', 'batch-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass', 'injection'] });
      const detail = result.details.find(d => d.check === 'depth-limit');
      expect(detail?.status).toBe('pass');
    });

    it('should detect unlimited batch queries', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      // Batch response - array of 10 results
      mockFetch.mockResolvedValueOnce(jsonResponse(
        Array.from({ length: 10 }, () => ({ data: { __typename: 'Query' } }))
      ));

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['introspection', 'depth-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass', 'injection'] });
      const detail = result.details.find(d => d.check === 'batch-limit');
      expect(detail?.status).toBe('fail');
    });

    it('should detect field suggestions', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      mockFetch.mockResolvedValueOnce(jsonResponse({
        errors: [{ message: 'Cannot query field "__typenaem" on type "Query". Did you mean "__typename"?' }]
      }));

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['introspection', 'depth-limit', 'batch-limit', 'cost-analysis', 'auth-bypass', 'injection'] });
      const detail = result.details.find(d => d.check === 'field-suggestions');
      expect(detail?.status).toBe('fail');
      expect(detail?.severity).toBe('low');
    });

    it('should detect lack of cost analysis', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      // 50 aliases all resolved
      const data: Record<string, string> = {};
      for (let i = 0; i < 50; i++) data[`a${i}`] = 'Query';
      mockFetch.mockResolvedValueOnce(jsonResponse({ data }));

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['introspection', 'depth-limit', 'batch-limit', 'field-suggestions', 'auth-bypass', 'injection'] });
      const detail = result.details.find(d => d.check === 'cost-analysis');
      expect(detail?.status).toBe('fail');
    });

    it('should detect auth bypass on introspection', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      // Unauthenticated introspection succeeds
      mockFetch.mockResolvedValueOnce(jsonResponse({
        data: { __schema: { queryType: { name: 'Query' } } }
      }));
      // Mutation check
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Mutation' } }));

      const result = await scanGraphQL('http://localhost:4000/graphql', {
        authToken: 'secret-token',
        skipChecks: ['introspection', 'depth-limit', 'batch-limit', 'field-suggestions', 'cost-analysis', 'injection'],
      });
      const detail = result.details.find(d => d.check === 'auth-bypass');
      expect(detail?.status).toBe('fail');
      expect(detail?.severity).toBe('high');
    });

    it('should detect injection info leakage', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      // SQL injection leaks info
      mockFetch.mockResolvedValueOnce(jsonResponse({
        errors: [{ message: 'syntax error at or near "OR" in PostgreSQL query' }]
      }));
      // Other injection tests
      mockFetch.mockResolvedValueOnce(jsonResponse({ errors: [{ message: 'Invalid' }] }));
      mockFetch.mockResolvedValueOnce(jsonResponse({ errors: [{ message: 'Invalid' }] }));

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['introspection', 'depth-limit', 'batch-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass'] });
      const detail = result.details.find(d => d.check === 'injection');
      expect(detail?.status).toBe('fail');
    });

    it('should skip checks when specified', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));

      const result = await scanGraphQL('http://localhost:4000/graphql', {
        skipChecks: ['introspection', 'depth-limit', 'batch-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass', 'injection'],
      });
      expect(result.status).toBe('success');
      expect(result.details.every(d => d.status === 'skip')).toBe(true);
      expect(result.findings).toHaveLength(0);
    });

    it('should include OWASP categories and remediation in findings', async () => {
      mockFetch.mockResolvedValueOnce(jsonResponse({ data: { __typename: 'Query' } }));
      mockFetch.mockResolvedValueOnce(jsonResponse({
        data: { __schema: { queryType: { name: 'Query' }, types: [] } }
      }));

      const result = await scanGraphQL('http://localhost:4000/graphql', { skipChecks: ['depth-limit', 'batch-limit', 'field-suggestions', 'cost-analysis', 'auth-bypass', 'injection'] });
      const finding = result.findings.find(f => f.ruleId === 'APIVET-GQL-001');
      expect(finding?.owaspCategory).toContain('API9:2023');
      expect(finding?.remediation).toBeTruthy();
    });
  });
});

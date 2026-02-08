/**
 * GraphQL Security Scanner
 * Runtime security checks against live GraphQL endpoints
 */

import type { Finding, Severity } from '../types.js';

export interface GraphQLScanResult {
  endpoint: string;
  status: 'success' | 'error';
  totalChecks: number;
  findings: Finding[];
  details: GraphQLCheckDetail[];
  error?: string;
}

export interface GraphQLCheckDetail {
  check: string;
  status: 'pass' | 'fail' | 'warn' | 'error' | 'skip';
  message: string;
  severity?: Severity;
  ruleId?: string;
}

export interface GraphQLScanOptions {
  timeout?: number;
  headers?: Record<string, string>;
  /** Auth token for authenticated checks */
  authToken?: string;
  /** Checks to skip */
  skipChecks?: string[];
}

async function gqlRequest(
  endpoint: string,
  query: string,
  options: GraphQLScanOptions,
  variables?: Record<string, unknown>,
  operationName?: string
): Promise<{ status: number; body: unknown; headers: Headers; error?: string }> {
  const timeout = options.timeout || 10000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const body: Record<string, unknown> = { query };
    if (variables) body.variables = variables;
    if (operationName) body.operationName = operationName;

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'ApiVet/1.0 GraphQL Security Scanner',
      ...options.headers,
    };
    if (options.authToken) {
      headers['Authorization'] = `Bearer ${options.authToken}`;
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: controller.signal,
    });

    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }

    return { status: res.status, body: parsed, headers: res.headers };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('abort')) {
      return { status: 0, body: null, headers: new Headers(), error: `Request timed out after ${timeout}ms` };
    }
    return { status: 0, body: null, headers: new Headers(), error: msg };
  } finally {
    clearTimeout(timeoutId);
  }
}

async function gqlBatchRequest(
  endpoint: string,
  queries: Array<{ query: string }>,
  options: GraphQLScanOptions
): Promise<{ status: number; body: unknown; headers: Headers; error?: string }> {
  const timeout = options.timeout || 10000;
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'ApiVet/1.0 GraphQL Security Scanner',
      ...options.headers,
    };
    if (options.authToken) {
      headers['Authorization'] = `Bearer ${options.authToken}`;
    }

    const res = await fetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify(queries),
      signal: controller.signal,
    });

    const text = await res.text();
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      parsed = text;
    }

    return { status: res.status, body: parsed, headers: res.headers };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('abort')) {
      return { status: 0, body: null, headers: new Headers(), error: `Request timed out after ${timeout}ms` };
    }
    return { status: 0, body: null, headers: new Headers(), error: msg };
  } finally {
    clearTimeout(timeoutId);
  }
}

// ---- Check 1: Introspection ----
async function checkIntrospection(
  endpoint: string,
  options: GraphQLScanOptions
): Promise<GraphQLCheckDetail> {
  const introspectionQuery = `query IntrospectionQuery { __schema { queryType { name } types { name kind } } }`;
  const res = await gqlRequest(endpoint, introspectionQuery, options);

  if (res.error) {
    return { check: 'introspection', status: 'error', message: `Request failed: ${res.error}` };
  }

  const body = res.body as Record<string, unknown> | null;
  const data = body?.data as Record<string, unknown> | undefined;

  if (data?.__schema) {
    const schema = data.__schema as Record<string, unknown>;
    const types = schema.types as Array<Record<string, string>> | undefined;
    const typeCount = types?.length || 0;
    return {
      check: 'introspection',
      status: 'fail',
      message: `Introspection is ENABLED. Schema exposes ${typeCount} types. Attackers can map the entire API.`,
      severity: 'high',
      ruleId: 'APIVET-GQL-001',
    };
  }

  // Check if errors indicate introspection is disabled
  const errors = (body?.errors as Array<Record<string, string>>) || [];
  if (errors.length > 0) {
    return {
      check: 'introspection',
      status: 'pass',
      message: 'Introspection is disabled or restricted.',
    };
  }

  return { check: 'introspection', status: 'pass', message: 'Introspection appears to be disabled.' };
}

// ---- Check 2: Query Depth ----
async function checkDepthLimit(
  endpoint: string,
  options: GraphQLScanOptions
): Promise<GraphQLCheckDetail> {
  // Build a deeply nested query (depth 15)
  let deepQuery = '{ __typename ';
  const depth = 15;
  for (let i = 0; i < depth; i++) {
    deepQuery = `{ __type(name: "Query") { fields { type { ofType ${deepQuery} } } } }`;
  }
  // Simplified deep introspection query
  deepQuery = `query DeepTest { __type(name: "Query") { fields { name type { name ofType { name ofType { name ofType { name ofType { name ofType { name ofType { name ofType { name ofType { name ofType { name ofType { name } } } } } } } } } } } } } }`;

  const res = await gqlRequest(endpoint, deepQuery, options);
  if (res.error) {
    return { check: 'depth-limit', status: 'error', message: `Request failed: ${res.error}` };
  }

  const body = res.body as Record<string, unknown> | null;
  const errors = (body?.errors as Array<Record<string, string>>) || [];
  const data = body?.data;

  // If we got data back without errors, depth limiting is likely not enforced
  if (data && !errors.length) {
    return {
      check: 'depth-limit',
      status: 'fail',
      message: 'No query depth limiting detected. Deeply nested queries (10+ levels) are accepted.',
      severity: 'medium',
      ruleId: 'APIVET-GQL-002',
    };
  }

  // Check if error message mentions depth
  const depthError = errors.find(
    (e) => {
      const msg = (e.message || '').toLowerCase();
      return msg.includes('depth') || msg.includes('nested') || msg.includes('complexity');
    }
  );

  if (depthError) {
    return {
      check: 'depth-limit',
      status: 'pass',
      message: `Query depth limiting is enforced: "${depthError.message}"`,
    };
  }

  // Other errors (might be introspection disabled which blocks our test)
  if (errors.length > 0) {
    return {
      check: 'depth-limit',
      status: 'warn',
      message: `Query returned errors but unclear if depth limiting is enforced. Error: "${errors[0].message}"`,
    };
  }

  return { check: 'depth-limit', status: 'warn', message: 'Could not determine if depth limiting is enforced.' };
}

// ---- Check 3: Batch Query Limit ----
async function checkBatchLimit(
  endpoint: string,
  options: GraphQLScanOptions
): Promise<GraphQLCheckDetail> {
  // Send 10 queries in a batch
  const queries = Array.from({ length: 10 }, (_, i) => ({
    query: `query Batch${i} { __typename }`,
  }));

  const res = await gqlBatchRequest(endpoint, queries, options);
  if (res.error) {
    return { check: 'batch-limit', status: 'error', message: `Request failed: ${res.error}` };
  }

  const body = res.body;

  // If response is an array with all results, batching is allowed
  if (Array.isArray(body)) {
    if (body.length >= 10) {
      return {
        check: 'batch-limit',
        status: 'fail',
        message: `Batch queries accepted without limit. ${body.length} queries executed simultaneously. Attackers can amplify attacks.`,
        severity: 'medium',
        ruleId: 'APIVET-GQL-003',
      };
    }
    return {
      check: 'batch-limit',
      status: 'warn',
      message: `Batch queries partially accepted (${body.length}/10). Consider stricter limits.`,
    };
  }

  // Non-array response means batching is blocked or not supported
  const bodyObj = body as Record<string, unknown> | null;
  const errors = (bodyObj?.errors as Array<Record<string, string>>) || [];
  if (errors.length > 0) {
    return {
      check: 'batch-limit',
      status: 'pass',
      message: 'Batch queries are rejected or limited.',
    };
  }

  return { check: 'batch-limit', status: 'pass', message: 'Batch queries do not appear to be supported.' };
}

// ---- Check 4: Field Suggestions ----
async function checkFieldSuggestions(
  endpoint: string,
  options: GraphQLScanOptions
): Promise<GraphQLCheckDetail> {
  // Send a query with a misspelled field to trigger suggestions
  const query = `{ __typenaem }`;

  const res = await gqlRequest(endpoint, query, options);
  if (res.error) {
    return { check: 'field-suggestions', status: 'error', message: `Request failed: ${res.error}` };
  }

  const body = res.body as Record<string, unknown> | null;
  const errors = (body?.errors as Array<Record<string, string>>) || [];

  for (const err of errors) {
    const msg = (err.message || '').toLowerCase();
    if (msg.includes('did you mean') || msg.includes('suggestion')) {
      return {
        check: 'field-suggestions',
        status: 'fail',
        message: `Field suggestions are enabled. Error messages leak schema info: "${err.message}"`,
        severity: 'low',
        ruleId: 'APIVET-GQL-004',
      };
    }
  }

  if (errors.length > 0) {
    return {
      check: 'field-suggestions',
      status: 'pass',
      message: 'Error messages do not include field suggestions.',
    };
  }

  return { check: 'field-suggestions', status: 'warn', message: 'Could not trigger an error to test field suggestions.' };
}

// ---- Check 5: Cost Analysis (high-cost query) ----
async function checkCostAnalysis(
  endpoint: string,
  options: GraphQLScanOptions
): Promise<GraphQLCheckDetail> {
  // Try an alias-based amplification attack
  const aliases = Array.from({ length: 50 }, (_, i) => `a${i}: __typename`).join(' ');
  const query = `{ ${aliases} }`;

  const res = await gqlRequest(endpoint, query, options);
  if (res.error) {
    return { check: 'cost-analysis', status: 'error', message: `Request failed: ${res.error}` };
  }

  const body = res.body as Record<string, unknown> | null;
  const errors = (body?.errors as Array<Record<string, string>>) || [];
  const data = body?.data as Record<string, unknown> | undefined;

  // Check if cost/complexity error was returned
  const costError = errors.find((e) => {
    const msg = (e.message || '').toLowerCase();
    return msg.includes('cost') || msg.includes('complexity') || msg.includes('too many') || msg.includes('limit');
  });

  if (costError) {
    return {
      check: 'cost-analysis',
      status: 'pass',
      message: `Query cost analysis is enforced: "${costError.message}"`,
    };
  }

  // If all 50 aliases resolved, no cost limiting
  if (data && Object.keys(data).length >= 50) {
    return {
      check: 'cost-analysis',
      status: 'fail',
      message: 'No query cost analysis detected. 50 alias fields executed without limits. Vulnerable to alias-based DoS.',
      severity: 'medium',
      ruleId: 'APIVET-GQL-005',
    };
  }

  if (errors.length > 0) {
    return {
      check: 'cost-analysis',
      status: 'warn',
      message: `Query returned errors: "${errors[0].message}". Unable to determine cost analysis status.`,
    };
  }

  return { check: 'cost-analysis', status: 'warn', message: 'Could not determine if cost analysis is enforced.' };
}

// ---- Check 6: Auth Bypass ----
async function checkAuthBypass(
  endpoint: string,
  options: GraphQLScanOptions
): Promise<GraphQLCheckDetail> {
  // Try introspection without auth headers
  const noAuthOptions = { ...options, authToken: undefined, headers: {} };
  const introspectionQuery = `{ __schema { queryType { name } } }`;

  const res = await gqlRequest(endpoint, introspectionQuery, noAuthOptions);
  if (res.error) {
    return { check: 'auth-bypass', status: 'error', message: `Request failed: ${res.error}` };
  }

  const body = res.body as Record<string, unknown> | null;
  const data = body?.data as Record<string, unknown> | undefined;

  if (data?.__schema) {
    // If we also have auth configured, this is a bypass
    if (options.authToken || (options.headers && Object.keys(options.headers).some(h => h.toLowerCase() === 'authorization'))) {
      return {
        check: 'auth-bypass',
        status: 'fail',
        message: 'Introspection accessible WITHOUT authentication. Schema is publicly exposed even though auth is configured.',
        severity: 'high',
        ruleId: 'APIVET-GQL-006',
      };
    }
    return {
      check: 'auth-bypass',
      status: 'fail',
      message: 'GraphQL endpoint accessible without authentication. Introspection returns schema data.',
      severity: 'high',
      ruleId: 'APIVET-GQL-006',
    };
  }

  // Try a mutation without auth
  const mutationQuery = `mutation { __typename }`;
  const mutRes = await gqlRequest(endpoint, mutationQuery, noAuthOptions);
  const mutBody = mutRes.body as Record<string, unknown> | null;
  const mutErrors = (mutBody?.errors as Array<Record<string, string>>) || [];

  // If no 401/403 in status or error messages, might be an issue
  if (mutRes.status === 200 && mutErrors.length === 0) {
    return {
      check: 'auth-bypass',
      status: 'warn',
      message: 'Mutation endpoint responds 200 without authentication. Verify mutation authorization is enforced.',
    };
  }

  if (mutRes.status === 401 || mutRes.status === 403) {
    return {
      check: 'auth-bypass',
      status: 'pass',
      message: 'Unauthenticated requests are properly rejected.',
    };
  }

  return {
    check: 'auth-bypass',
    status: 'pass',
    message: 'Authentication appears to be enforced on introspection and mutations.',
  };
}

// ---- Check 7: Injection ----
async function checkInjection(
  endpoint: string,
  options: GraphQLScanOptions
): Promise<GraphQLCheckDetail> {
  const injectionPayloads = [
    { name: 'SQL injection in variable', query: `query($id: String) { __typename }`, variables: { id: "' OR '1'='1" } },
    { name: 'NoSQL injection', query: `query($id: String) { __typename }`, variables: { id: '{"$gt": ""}' } },
    { name: 'Directive overloading', query: `query { __typename @skip(if: true) @skip(if: false) @include(if: true) @include(if: false) }`, variables: undefined },
  ];

  const issues: string[] = [];

  for (const payload of injectionPayloads) {
    const res = await gqlRequest(endpoint, payload.query, options, payload.variables);
    if (res.error) continue;

    const body = res.body as Record<string, unknown> | null;
    const errors = (body?.errors as Array<Record<string, string>>) || [];

    // Check if error messages leak internal details
    for (const err of errors) {
      const msg = (err.message || '').toLowerCase();
      if (
        msg.includes('sql') ||
        msg.includes('syntax error') ||
        msg.includes('table') ||
        msg.includes('column') ||
        msg.includes('mongodb') ||
        msg.includes('postgres') ||
        msg.includes('mysql') ||
        msg.includes('stack trace') ||
        msg.includes('internal server error')
      ) {
        issues.push(`${payload.name}: Error leaks internal info - "${err.message}"`);
      }
    }

    // Directive overloading: check if multiple conflicting directives are accepted
    if (payload.name.includes('Directive') && !errors.length) {
      issues.push('Directive overloading accepted - multiple conflicting directives not rejected');
    }
  }

  if (issues.length > 0) {
    return {
      check: 'injection',
      status: 'fail',
      message: `Injection/info-leak issues found: ${issues.join('; ')}`,
      severity: 'high',
      ruleId: 'APIVET-GQL-007',
    };
  }

  return {
    check: 'injection',
    status: 'pass',
    message: 'No injection vulnerabilities or information leakage detected in tested patterns.',
  };
}

// ---- Main Scanner ----
const ALL_CHECKS: Record<string, (endpoint: string, options: GraphQLScanOptions) => Promise<GraphQLCheckDetail>> = {
  introspection: checkIntrospection,
  'depth-limit': checkDepthLimit,
  'batch-limit': checkBatchLimit,
  'field-suggestions': checkFieldSuggestions,
  'cost-analysis': checkCostAnalysis,
  'auth-bypass': checkAuthBypass,
  injection: checkInjection,
};

export async function scanGraphQL(
  endpoint: string,
  options: GraphQLScanOptions = {}
): Promise<GraphQLScanResult> {
  const findings: Finding[] = [];
  const details: GraphQLCheckDetail[] = [];
  const skipSet = new Set(options.skipChecks || []);

  // Validate endpoint
  try {
    const url = new URL(endpoint);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return { endpoint, status: 'error', totalChecks: 0, findings, details, error: `Unsupported protocol: ${url.protocol}` };
    }
  } catch {
    return { endpoint, status: 'error', totalChecks: 0, findings, details, error: `Invalid URL: ${endpoint}` };
  }

  // Connectivity check
  const pingRes = await gqlRequest(endpoint, '{ __typename }', options);
  if (pingRes.error) {
    return { endpoint, status: 'error', totalChecks: 0, findings, details, error: `Cannot reach endpoint: ${pingRes.error}` };
  }

  for (const [name, checkFn] of Object.entries(ALL_CHECKS)) {
    if (skipSet.has(name)) {
      details.push({ check: name, status: 'skip', message: 'Skipped by user' });
      continue;
    }

    try {
      const detail = await checkFn(endpoint, options);
      details.push(detail);

      if (detail.status === 'fail' && detail.ruleId && detail.severity) {
        findings.push({
          ruleId: detail.ruleId,
          title: `GraphQL: ${detail.check}`,
          description: detail.message,
          severity: detail.severity,
          location: { endpoint },
          owaspCategory: getOwaspCategory(detail.ruleId),
          remediation: getRemediation(detail.check),
        });
      }
    } catch (err) {
      details.push({
        check: name,
        status: 'error',
        message: `Check failed: ${err instanceof Error ? err.message : String(err)}`,
      });
    }
  }

  return {
    endpoint,
    status: 'success',
    totalChecks: details.length,
    findings,
    details,
  };
}

function getOwaspCategory(ruleId: string): string {
  const map: Record<string, string> = {
    'APIVET-GQL-001': 'API9:2023 Improper Inventory Management',
    'APIVET-GQL-002': 'API4:2023 Unrestricted Resource Consumption',
    'APIVET-GQL-003': 'API4:2023 Unrestricted Resource Consumption',
    'APIVET-GQL-004': 'API9:2023 Improper Inventory Management',
    'APIVET-GQL-005': 'API4:2023 Unrestricted Resource Consumption',
    'APIVET-GQL-006': 'API2:2023 Broken Authentication',
    'APIVET-GQL-007': 'API8:2023 Security Misconfiguration',
  };
  return map[ruleId] || '';
}

function getRemediation(check: string): string {
  const map: Record<string, string> = {
    introspection: 'Disable introspection in production. Use graphql-disable-introspection or configure your server (Apollo: introspection: false).',
    'depth-limit': 'Implement query depth validation (e.g., graphql-depth-limit). Set max depth to 5-10 levels.',
    'batch-limit': 'Limit or disable batch queries. Set max operations per request (e.g., 5-10).',
    'field-suggestions': 'Disable field suggestions in production (Apollo: fieldSuggestion: false). Return generic error messages.',
    'cost-analysis': 'Implement query cost/complexity analysis (e.g., graphql-cost-analysis). Set cost limits per query.',
    'auth-bypass': 'Require authentication for all GraphQL operations. Implement field-level authorization. Use persisted queries for public access.',
    injection: 'Validate and sanitize all input variables. Use parameterized queries. Limit directive usage. Suppress internal error details in production.',
  };
  return map[check] || '';
}

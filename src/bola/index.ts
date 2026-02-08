/**
 * BOLA/IDOR (Broken Object Level Authorization) Auto-Detection Module
 *
 * OWASP API Security Top 10 #1 - API1:2023
 * Tests for unauthorized access to resources by manipulating object identifiers.
 */

import type { OpenApiSpec, PathItem, Operation, Parameter } from '../types.js';
import type { Finding, Severity } from '../types.js';

// ── Types ──────────────────────────────────────────────────────────────

export interface BolaConfig {
  specPath: string;
  baseUrl: string;
  tokenA: string;         // User A (authorized owner)
  tokenB: string;         // User B (attacker / different user)
  adminToken?: string;    // Admin token for vertical escalation tests
  authHeader?: string;    // Default: Authorization
  authScheme?: string;    // Default: Bearer
  timeout?: number;       // ms, default: 10000
  concurrency?: number;   // parallel requests, default: 5
  skipPaths?: string[];   // glob patterns to skip
  dryRun?: boolean;       // don't actually send requests
  verbose?: boolean;
}

export interface BolaTestCase {
  path: string;
  method: string;
  paramName: string;
  paramLocation: 'path' | 'query' | 'header' | 'cookie';
  originalValue: string;
  replacedValue: string;
  testType: BolaTestType;
}

export type BolaTestType =
  | 'horizontal'     // same role, different user's resource
  | 'vertical'       // low-priv user accessing admin endpoint
  | 'sequential-id'  // predictable sequential IDs
  | 'uuid-v1'        // timestamp-based UUID prediction
  | 'param-swap';    // generic parameter substitution

export interface BolaResult {
  totalEndpoints: number;
  testedEndpoints: number;
  testCases: BolaTestCaseResult[];
  findings: Finding[];
  summary: BolaSummary;
}

export interface BolaTestCaseResult extends BolaTestCase {
  status: 'vulnerable' | 'protected' | 'error' | 'skipped';
  authorizedResponse?: ResponseSummary;
  unauthorizedResponse?: ResponseSummary;
  diff?: ResponseDiff;
  error?: string;
}

export interface ResponseSummary {
  statusCode: number;
  bodyLength: number;
  bodyHash: string;
  contentType?: string;
  headers: Record<string, string>;
}

export interface ResponseDiff {
  statusCodeMatch: boolean;
  bodyMatch: boolean;
  bodyLengthDelta: number;
  similarityPercent: number;
}

export interface BolaSummary {
  vulnerable: number;
  protected: number;
  errors: number;
  skipped: number;
}

// ── Parameter Extraction ───────────────────────────────────────────────

/** Patterns that indicate object-level identifiers */
const ID_PARAM_PATTERNS = [
  /^id$/i,
  /Id$/,                    // userId, orderId, etc.
  /^uuid$/i,
  /Uuid$/i,
  /^slug$/i,
  /^key$/i,
  /^token$/i,
  /^handle$/i,
  /^username$/i,
  /^email$/i,
  /_id$/i,                  // user_id, order_id
  /^pk$/i,
];

/** Methods that typically access specific resources */
const RESOURCE_METHODS = ['get', 'put', 'patch', 'delete'];

export function isIdParameter(name: string): boolean {
  return ID_PARAM_PATTERNS.some(p => p.test(name));
}

export interface ExtractedEndpoint {
  path: string;
  method: string;
  params: Parameter[];
  operation: Operation;
}

/**
 * Extract endpoints with path/query parameters that look like object identifiers
 */
export function extractIdEndpoints(spec: OpenApiSpec): ExtractedEndpoint[] {
  const endpoints: ExtractedEndpoint[] = [];
  const paths = spec.paths ?? {};

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!pathItem) continue;
    const pi = pathItem as PathItem;
    const pathParams = pi.parameters ?? [];

    for (const method of RESOURCE_METHODS) {
      const op = pi[method] as Operation | undefined;
      if (!op) continue;

      // Merge path-level and operation-level parameters
      const allParams = [...pathParams, ...(op.parameters ?? [])];
      const idParams = allParams.filter(p =>
        (p.in === 'path' || p.in === 'query') && isIdParameter(p.name)
      );

      if (idParams.length > 0) {
        endpoints.push({ path, method, params: idParams, operation: op });
      }
    }
  }

  return endpoints;
}

// ── ID Generation / Prediction ─────────────────────────────────────────

export function generateSequentialIds(baseId: string, count: number = 5): string[] {
  const num = parseInt(baseId, 10);
  if (isNaN(num)) return [];
  const ids: string[] = [];
  for (let i = 1; i <= count; i++) {
    ids.push(String(num + i));
    if (num - i > 0) ids.push(String(num - i));
  }
  return ids;
}

/**
 * Detect UUIDv1 and generate adjacent timestamps
 */
export function isUuidV1(uuid: string): boolean {
  // UUIDv1 format: xxxxxxxx-xxxx-1xxx-yxxx-xxxxxxxxxxxx (version nibble = 1)
  return /^[0-9a-f]{8}-[0-9a-f]{4}-1[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(uuid);
}

export function generateUuidV1Predictions(uuid: string, count: number = 3): string[] {
  if (!isUuidV1(uuid)) return [];
  // UUIDv1 time is in the first 3 groups (time_low-time_mid-time_hi_and_version)
  const parts = uuid.split('-');
  const timeLow = parseInt(parts[0], 16);
  const predictions: string[] = [];

  for (let i = 1; i <= count; i++) {
    // Increment/decrement the time_low portion
    const incHex = (timeLow + i * 0x10000).toString(16).padStart(8, '0');
    const decHex = Math.max(0, timeLow - i * 0x10000).toString(16).padStart(8, '0');
    predictions.push(`${incHex}-${parts[1]}-${parts[2]}-${parts[3]}-${parts[4]}`);
    predictions.push(`${decHex}-${parts[1]}-${parts[2]}-${parts[3]}-${parts[4]}`);
  }

  return predictions;
}

// ── Test Case Generation ───────────────────────────────────────────────

export function generateTestCases(
  endpoints: ExtractedEndpoint[],
  sampleIdA: string = '1',
  sampleIdB: string = '2'
): BolaTestCase[] {
  const cases: BolaTestCase[] = [];

  for (const ep of endpoints) {
    for (const param of ep.params) {
      // Horizontal: swap user A's ID with user B's
      cases.push({
        path: ep.path,
        method: ep.method,
        paramName: param.name,
        paramLocation: param.in as BolaTestCase['paramLocation'],
        originalValue: sampleIdA,
        replacedValue: sampleIdB,
        testType: 'horizontal',
      });

      // Sequential ID prediction
      if (/^\d+$/.test(sampleIdA)) {
        for (const seqId of generateSequentialIds(sampleIdA, 2)) {
          cases.push({
            path: ep.path,
            method: ep.method,
            paramName: param.name,
            paramLocation: param.in as BolaTestCase['paramLocation'],
            originalValue: sampleIdA,
            replacedValue: seqId,
            testType: 'sequential-id',
          });
        }
      }

      // UUID v1 prediction
      if (isUuidV1(sampleIdA)) {
        for (const predicted of generateUuidV1Predictions(sampleIdA, 1)) {
          cases.push({
            path: ep.path,
            method: ep.method,
            paramName: param.name,
            paramLocation: param.in as BolaTestCase['paramLocation'],
            originalValue: sampleIdA,
            replacedValue: predicted,
            testType: 'uuid-v1',
          });
        }
      }
    }
  }

  return cases;
}

// ── HTTP Request Helpers ───────────────────────────────────────────────

function buildUrl(baseUrl: string, path: string, paramName: string, paramValue: string, paramLocation: string): string {
  let resolvedPath = path;
  if (paramLocation === 'path') {
    resolvedPath = path.replace(`{${paramName}}`, encodeURIComponent(paramValue));
  }
  const url = new URL(resolvedPath, baseUrl);
  if (paramLocation === 'query') {
    url.searchParams.set(paramName, paramValue);
  }
  return url.toString();
}

function hashBody(body: string): string {
  // Simple hash for comparison (not crypto)
  let hash = 0;
  for (let i = 0; i < body.length; i++) {
    const chr = body.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return hash.toString(16);
}

function computeSimilarity(a: string, b: string): number {
  if (a === b) return 100;
  if (a.length === 0 && b.length === 0) return 100;
  if (a.length === 0 || b.length === 0) return 0;
  // Simple length-based similarity + prefix match
  const minLen = Math.min(a.length, b.length);
  const maxLen = Math.max(a.length, b.length);
  let matchChars = 0;
  for (let i = 0; i < minLen; i++) {
    if (a[i] === b[i]) matchChars++;
    else break;
  }
  return Math.round((matchChars / maxLen) * 100);
}

function compareResponses(authorized: ResponseSummary, unauthorized: ResponseSummary): ResponseDiff {
  return {
    statusCodeMatch: authorized.statusCode === unauthorized.statusCode,
    bodyMatch: authorized.bodyHash === unauthorized.bodyHash,
    bodyLengthDelta: Math.abs(authorized.bodyLength - unauthorized.bodyLength),
    similarityPercent: 0, // set below when we have bodies
  };
}

interface FetchOptions {
  url: string;
  method: string;
  token: string;
  authHeader: string;
  authScheme: string;
  timeout: number;
}

async function fetchWithAuth(opts: FetchOptions): Promise<{ summary: ResponseSummary; body: string }> {
  const headers: Record<string, string> = {};
  if (opts.authScheme.toLowerCase() === 'bearer') {
    headers[opts.authHeader] = `Bearer ${opts.token}`;
  } else {
    headers[opts.authHeader] = opts.token;
  }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), opts.timeout);

  try {
    const res = await fetch(opts.url, {
      method: opts.method.toUpperCase(),
      headers,
      signal: controller.signal,
    });
    const body = await res.text();
    return {
      summary: {
        statusCode: res.status,
        bodyLength: body.length,
        bodyHash: hashBody(body),
        contentType: res.headers.get('content-type') ?? undefined,
        headers: Object.fromEntries(res.headers.entries()),
      },
      body,
    };
  } finally {
    clearTimeout(timer);
  }
}

// ── Vulnerability Detection Logic ──────────────────────────────────────

function isVulnerable(authorizedRes: ResponseSummary, unauthorizedRes: ResponseSummary, diff: ResponseDiff): boolean {
  // If unauthorized request gets same 200 response as authorized → BOLA
  if (unauthorizedRes.statusCode >= 200 && unauthorizedRes.statusCode < 300) {
    if (diff.statusCodeMatch && diff.bodyMatch) return true;
    if (diff.statusCodeMatch && diff.similarityPercent > 80) return true;
    // Even if body differs slightly, 200 with similar length is suspicious
    if (diff.statusCodeMatch && diff.bodyLengthDelta < 50) return true;
  }
  return false;
}

// ── Main Runner ────────────────────────────────────────────────────────

export async function runBolaTests(
  spec: OpenApiSpec,
  config: BolaConfig
): Promise<BolaResult> {
  const authHeader = config.authHeader ?? 'Authorization';
  const authScheme = config.authScheme ?? 'Bearer';
  const timeout = config.timeout ?? 10000;

  const endpoints = extractIdEndpoints(spec);
  const testCases = generateTestCases(endpoints);
  const results: BolaTestCaseResult[] = [];
  const findings: Finding[] = [];

  // Process test cases (simplified sequential for now)
  for (const tc of testCases) {
    if (config.dryRun) {
      results.push({ ...tc, status: 'skipped' });
      continue;
    }

    try {
      // 1) Request with token A (authorized owner) using original value
      const authorizedUrl = buildUrl(config.baseUrl, tc.path, tc.paramName, tc.originalValue, tc.paramLocation);
      const authRes = await fetchWithAuth({
        url: authorizedUrl, method: tc.method, token: config.tokenA,
        authHeader, authScheme, timeout,
      });

      // 2) Request with token B (attacker) using replaced value (another user's ID)
      const unauthorizedUrl = buildUrl(config.baseUrl, tc.path, tc.paramName, tc.replacedValue, tc.paramLocation);
      const unauthRes = await fetchWithAuth({
        url: unauthorizedUrl, method: tc.method, token: config.tokenB,
        authHeader, authScheme, timeout,
      });

      const diff = compareResponses(authRes.summary, unauthRes.summary);
      diff.similarityPercent = computeSimilarity(authRes.body, unauthRes.body);

      const vuln = isVulnerable(authRes.summary, unauthRes.summary, diff);

      const result: BolaTestCaseResult = {
        ...tc,
        status: vuln ? 'vulnerable' : 'protected',
        authorizedResponse: authRes.summary,
        unauthorizedResponse: unauthRes.summary,
        diff,
      };
      results.push(result);

      if (vuln) {
        findings.push(createFinding(tc, authRes.summary, unauthRes.summary, diff));
      }
    } catch (err) {
      results.push({
        ...tc,
        status: 'error',
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // Vertical escalation tests (if admin token provided)
  if (config.adminToken) {
    const verticalFindings = await runVerticalEscalationTests(spec, config, authHeader, authScheme, timeout);
    findings.push(...verticalFindings);
  }

  const summary: BolaSummary = {
    vulnerable: results.filter(r => r.status === 'vulnerable').length,
    protected: results.filter(r => r.status === 'protected').length,
    errors: results.filter(r => r.status === 'error').length,
    skipped: results.filter(r => r.status === 'skipped').length,
  };

  return {
    totalEndpoints: endpoints.length,
    testedEndpoints: endpoints.length,
    testCases: results,
    findings,
    summary,
  };
}

// ── Vertical Escalation ────────────────────────────────────────────────

/** Detect admin-like paths and test with low-priv token */
const ADMIN_PATH_PATTERNS = [
  /\/admin\//i,
  /\/manage\//i,
  /\/internal\//i,
  /\/system\//i,
  /\/settings/i,
  /\/config/i,
  /\/users$/i,       // listing all users
  /\/roles/i,
  /\/permissions/i,
];

export function isAdminEndpoint(path: string): boolean {
  return ADMIN_PATH_PATTERNS.some(p => p.test(path));
}

async function runVerticalEscalationTests(
  spec: OpenApiSpec,
  config: BolaConfig,
  authHeader: string,
  authScheme: string,
  timeout: number,
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const paths = spec.paths ?? {};

  for (const [path, pathItem] of Object.entries(paths)) {
    if (!pathItem || !isAdminEndpoint(path)) continue;
    const pi = pathItem as PathItem;

    for (const method of ['get', 'post', 'put', 'delete', 'patch']) {
      const op = pi[method] as Operation | undefined;
      if (!op) continue;

      if (config.dryRun) continue;

      try {
        // Try accessing admin endpoint with low-priv token (tokenB)
        const url = buildUrl(config.baseUrl, path.replace(/\{[^}]+\}/g, '1'), '', '', 'path');
        const res = await fetchWithAuth({
          url, method, token: config.tokenB,
          authHeader, authScheme, timeout,
        });

        if (res.summary.statusCode >= 200 && res.summary.statusCode < 300) {
          findings.push({
            ruleId: 'BOLA-VERTICAL-001',
            title: `Vertical privilege escalation: ${method.toUpperCase()} ${path}`,
            description: `Low-privilege user can access admin endpoint. Response: ${res.summary.statusCode}. ` +
              `This indicates missing role-based access control.`,
            severity: 'critical' as Severity,
            location: { endpoint: path, method: method.toUpperCase() },
            owaspCategory: 'API1:2023 Broken Object Level Authorization',
            remediation: 'Implement role-based access control (RBAC). Verify user roles server-side before granting access to administrative endpoints.',
          });
        }
      } catch {
        // Skip on error
      }
    }
  }

  return findings;
}

// ── Finding Creation ───────────────────────────────────────────────────

function createFinding(
  tc: BolaTestCase,
  authRes: ResponseSummary,
  unauthRes: ResponseSummary,
  diff: ResponseDiff,
): Finding {
  const typeLabels: Record<BolaTestType, string> = {
    'horizontal': 'Horizontal privilege escalation (IDOR)',
    'vertical': 'Vertical privilege escalation',
    'sequential-id': 'Sequential ID enumeration',
    'uuid-v1': 'UUIDv1 timestamp prediction',
    'param-swap': 'Parameter substitution',
  };

  const severityMap: Record<BolaTestType, Severity> = {
    'horizontal': 'critical',
    'vertical': 'critical',
    'sequential-id': 'high',
    'uuid-v1': 'high',
    'param-swap': 'high',
  };

  return {
    ruleId: `BOLA-${tc.testType.toUpperCase()}-001`,
    title: `${typeLabels[tc.testType]}: ${tc.method.toUpperCase()} ${tc.path} [${tc.paramName}]`,
    description:
      `User B accessed User A's resource by replacing ${tc.paramName}=${tc.originalValue} with ${tc.replacedValue}. ` +
      `Authorized response: ${authRes.statusCode} (${authRes.bodyLength}B), ` +
      `Unauthorized response: ${unauthRes.statusCode} (${unauthRes.bodyLength}B). ` +
      `Body similarity: ${diff.similarityPercent}%.`,
    severity: severityMap[tc.testType],
    location: {
      endpoint: tc.path,
      method: tc.method.toUpperCase(),
    },
    owaspCategory: 'API1:2023 Broken Object Level Authorization',
    remediation:
      'Implement object-level authorization checks. Verify that the authenticated user owns or has permission to access the requested resource. ' +
      'Use non-guessable identifiers (UUIDv4) and validate ownership in every handler.',
  };
}

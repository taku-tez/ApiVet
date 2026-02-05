import type { Finding, Severity } from '../types.js';

export interface CheckResult {
  url: string;
  status: 'success' | 'error';
  responseTime?: number;
  statusCode?: number;
  findings: Finding[];
  headers?: Record<string, string>;
  error?: string;
}

export interface CheckOptions {
  headers?: boolean;
  auth?: 'basic' | 'bearer' | 'apikey';
  authToken?: string;
  authHeader?: string;
  customHeaders?: string[];
  body?: string;
  timeout?: number;
  method?: string;
}

const SECURITY_HEADERS: Array<{
  name: string;
  required: boolean;
  severity: Severity;
  description: string;
  remediation: string;
}> = [
  {
    name: 'strict-transport-security',
    required: true,
    severity: 'high',
    description: 'HTTP Strict Transport Security (HSTS) header is missing',
    remediation: 'Add Strict-Transport-Security header with appropriate max-age value'
  },
  {
    name: 'x-content-type-options',
    required: true,
    severity: 'medium',
    description: 'X-Content-Type-Options header is missing',
    remediation: 'Add X-Content-Type-Options: nosniff header'
  },
  {
    name: 'x-frame-options',
    required: false,
    severity: 'low',
    description: 'X-Frame-Options header is missing (consider Content-Security-Policy frame-ancestors instead)',
    remediation: 'Add X-Frame-Options: DENY or SAMEORIGIN header'
  },
  {
    name: 'content-security-policy',
    required: false,
    severity: 'medium',
    description: 'Content-Security-Policy header is missing',
    remediation: 'Implement a Content-Security-Policy header appropriate for your API'
  },
  {
    name: 'x-xss-protection',
    required: false,
    severity: 'low',
    description: 'X-XSS-Protection header is missing (deprecated but still useful for older browsers)',
    remediation: 'Add X-XSS-Protection: 1; mode=block header'
  },
  {
    name: 'cache-control',
    required: true,
    severity: 'medium',
    description: 'Cache-Control header is missing - API responses may be cached inappropriately',
    remediation: 'Add Cache-Control: no-store, no-cache for sensitive API endpoints'
  },
  {
    name: 'permissions-policy',
    required: false,
    severity: 'low',
    description: 'Permissions-Policy header is missing - browser features may be unrestricted',
    remediation: 'Add Permissions-Policy header to restrict access to browser features (camera, microphone, geolocation, etc.)'
  },
  {
    name: 'referrer-policy',
    required: false,
    severity: 'low',
    description: 'Referrer-Policy header is missing - full URL may be sent in Referer header',
    remediation: 'Add Referrer-Policy: strict-origin-when-cross-origin or no-referrer header'
  },
  {
    name: 'cross-origin-opener-policy',
    required: false,
    severity: 'low',
    description: 'Cross-Origin-Opener-Policy header is missing',
    remediation: 'Add Cross-Origin-Opener-Policy: same-origin header to isolate browsing context'
  },
  {
    name: 'cross-origin-resource-policy',
    required: false,
    severity: 'low',
    description: 'Cross-Origin-Resource-Policy header is missing',
    remediation: 'Add Cross-Origin-Resource-Policy: same-origin header to prevent cross-origin reads'
  }
];

const DANGEROUS_HEADERS = [
  {
    name: 'server',
    pattern: /.+/,
    severity: 'low' as Severity,
    description: 'Server header exposes server software information',
    remediation: 'Remove or obfuscate the Server header to prevent information disclosure'
  },
  {
    name: 'x-powered-by',
    pattern: /.+/,
    severity: 'low' as Severity,
    description: 'X-Powered-By header exposes technology stack',
    remediation: 'Remove the X-Powered-By header to prevent information disclosure'
  },
  {
    name: 'access-control-allow-origin',
    pattern: /^\*$/,
    severity: 'high' as Severity,
    description: 'CORS allows all origins (*) - this may expose the API to cross-origin attacks',
    remediation: 'Restrict Access-Control-Allow-Origin to specific trusted domains'
  },
  {
    name: 'access-control-allow-credentials',
    pattern: /^true$/i,
    severity: 'medium' as Severity,
    description: 'CORS allows credentials - ensure this is intentional and origin is restricted',
    remediation: 'Verify that allowing credentials is necessary and that origin is properly restricted'
  },
  {
    name: 'x-aspnet-version',
    pattern: /.+/,
    severity: 'low' as Severity,
    description: 'X-AspNet-Version header exposes ASP.NET version',
    remediation: 'Remove the X-AspNet-Version header'
  },
  {
    name: 'x-debug-token',
    pattern: /.+/,
    severity: 'medium' as Severity,
    description: 'Debug token header detected - may expose debugging information',
    remediation: 'Remove debug headers in production'
  }
];

/**
 * Build authentication headers based on auth type and token
 */
function buildAuthHeaders(
  auth: CheckOptions['auth'],
  authToken?: string,
  authHeader?: string
): Record<string, string> {
  if (!auth || !authToken) return {};

  const headerName = authHeader || 'Authorization';

  switch (auth) {
    case 'basic':
      // For basic auth, token should be base64-encoded "username:password"
      // If not already encoded, encode it
      const base64Token = authToken.includes(':')
        ? Buffer.from(authToken).toString('base64')
        : authToken;
      return { [headerName]: `Basic ${base64Token}` };

    case 'bearer':
      return { [headerName]: `Bearer ${authToken}` };

    case 'apikey':
      // For API key, use custom header name (default X-API-Key if no Authorization)
      const apiKeyHeader = authHeader || 'X-API-Key';
      return { [apiKeyHeader]: authToken };

    default:
      return {};
  }
}

/**
 * Parse custom headers from "Name: Value" or "Name:Value" format
 */
function parseCustomHeaders(customHeaders?: string[]): Record<string, string> {
  if (!customHeaders || customHeaders.length === 0) return {};
  
  const parsed: Record<string, string> = {};
  for (const header of customHeaders) {
    const colonIndex = header.indexOf(':');
    if (colonIndex > 0) {
      const name = header.substring(0, colonIndex).trim();
      const value = header.substring(colonIndex + 1).trim();
      if (name) {
        parsed[name] = value;
      }
    }
  }
  return parsed;
}

export async function checkEndpoint(
  url: string,
  options: CheckOptions = {}
): Promise<CheckResult> {
  const {
    headers: checkHeaders = false,
    auth,
    authToken,
    authHeader,
    customHeaders,
    body,
    timeout = 10000,
    method = 'GET'
  } = options;

  const findings: Finding[] = [];

  // Validate URL first
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    return {
      url,
      status: 'error',
      findings,
      error: `Invalid URL: ${url}`
    };
  }

  // FB2: Reject non-HTTP/HTTPS protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    return {
      url,
      status: 'error',
      findings,
      error: `Unsupported protocol: ${parsedUrl.protocol} (only http: and https: are supported)`
    };
  }

  // Check for HTTP vs HTTPS (warning, not error)
  if (parsedUrl.protocol === 'http:' &&
      !parsedUrl.hostname.includes('localhost') &&
      !parsedUrl.hostname.includes('127.0.0.1')) {
    findings.push({
      ruleId: 'APIVET-LIVE-001',
      title: 'Non-HTTPS endpoint',
      description: `The endpoint ${url} uses HTTP instead of HTTPS. Data transmitted is not encrypted.`,
      severity: 'high',
      remediation: 'Use HTTPS for all API endpoints to encrypt data in transit.'
    });
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), timeout);

  try {
    // Build request headers including authentication and custom headers
    const requestHeaders: Record<string, string> = {
      'User-Agent': 'ApiVet/1.0 Security Scanner',
      ...buildAuthHeaders(auth, authToken, authHeader),
      ...parseCustomHeaders(customHeaders)
    };

    // Build fetch options
    const fetchOptions: RequestInit = {
      method,
      signal: controller.signal,
      headers: requestHeaders
    };

    // Include body for methods that support it
    if (body && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method.toUpperCase())) {
      fetchOptions.body = body;
      // Set Content-Type if not already set
      if (!requestHeaders['Content-Type'] && !requestHeaders['content-type']) {
        requestHeaders['Content-Type'] = 'application/json';
      }
    }

    const startTime = Date.now();
    const response = await fetch(url, fetchOptions);
    const responseTime = Date.now() - startTime;

    const responseHeaders: Record<string, string> = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key.toLowerCase()] = value;
    });

    if (checkHeaders) {
      const isHttps = parsedUrl.protocol === 'https:';
      
      // Check for missing security headers (both required and optional)
      for (const header of SECURITY_HEADERS) {
        // FB4: Skip HSTS check for HTTP endpoints (HSTS only applies to HTTPS)
        if (header.name === 'strict-transport-security' && !isHttps) {
          continue;
        }
        
        if (!responseHeaders[header.name]) {
          // Report all missing security headers with their defined severity
          findings.push({
            ruleId: `APIVET-LIVE-HDR-${header.name.toUpperCase().replace(/-/g, '_')}`,
            title: `Missing security header: ${header.name}`,
            description: header.description,
            severity: header.severity,
            remediation: header.remediation
          });
        }
      }

      // Check for dangerous headers
      for (const header of DANGEROUS_HEADERS) {
        const value = responseHeaders[header.name];
        if (value && header.pattern.test(value)) {
          findings.push({
            ruleId: `APIVET-LIVE-HDR-${header.name.toUpperCase().replace(/-/g, '_')}`,
            title: `Potentially dangerous header: ${header.name}`,
            description: header.description,
            severity: header.severity,
            remediation: header.remediation
          });
        }
      }
    }

    return {
      url,
      status: 'success',
      responseTime,
      statusCode: response.status,
      findings,
      headers: checkHeaders ? responseHeaders : undefined
    };
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : 'Unknown error';

    // Provide more helpful error messages
    let friendlyError = errorMessage;
    if (errorMessage.includes('abort')) {
      friendlyError = `Request timed out after ${timeout}ms`;
    } else if (errorMessage.includes('ECONNREFUSED')) {
      friendlyError = 'Connection refused - server may be down or unreachable';
    } else if (errorMessage.includes('ENOTFOUND')) {
      friendlyError = 'DNS lookup failed - hostname could not be resolved';
    }

    return {
      url,
      status: 'error',
      findings,
      error: friendlyError
    };
  } finally {
    // FB1: Always clear timeout to prevent resource leak
    clearTimeout(timeoutId);
  }
}

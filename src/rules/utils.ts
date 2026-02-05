import type { OpenApiSpec, Finding, Severity } from '../types.js';

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  owaspCategory?: string;
  check: (spec: OpenApiSpec, filePath: string) => Finding[];
}

// Spec detection utilities
export function isAwsSpec(spec: OpenApiSpec): boolean {
  return JSON.stringify(spec).includes('x-amazon-apigateway');
}

export function isAwsApiGateway(servers: OpenApiSpec['servers']): boolean {
  return (servers || []).some(s => 
    s.url.includes('.execute-api.') ||
    s.url.includes('.amazonaws.com')
  );
}

export function isAzureApim(servers: OpenApiSpec['servers']): boolean {
  return (servers || []).some(s => 
    s.url.includes('.azure-api.net') ||
    s.url.includes('management.azure.com')
  );
}

export function isAzureService(servers: OpenApiSpec['servers']): boolean {
  return (servers || []).some(s => 
    s.url.includes('.azurewebsites.net') ||
    s.url.includes('.azure-mobile.net') ||
    s.url.includes('.azurefd.net')
  );
}

export function isGcpService(servers: OpenApiSpec['servers']): boolean {
  return (servers || []).some(s => 
    s.url.includes('.run.app') ||
    s.url.includes('.cloudfunctions.net') ||
    s.url.includes('.endpoints.')
  );
}

export function hasGoogleExtensions(spec: OpenApiSpec): boolean {
  const extSpec = spec as Record<string, unknown>;
  return extSpec['x-google-endpoints'] !== undefined ||
         JSON.stringify(spec).includes('x-google-backend');
}

// Security utilities
export function hasGlobalSecurity(spec: OpenApiSpec): boolean {
  return (spec.security && spec.security.length > 0) || false;
}

export function hasSecuritySchemes(spec: OpenApiSpec): boolean {
  return spec.components?.securitySchemes !== undefined &&
         Object.keys(spec.components.securitySchemes).length > 0;
}

export function hasOperationSecurity(operation: unknown): boolean {
  const op = operation as { security?: unknown[] } | undefined;
  return op?.security !== undefined && Array.isArray(op.security) && op.security.length > 0;
}

// URL pattern utilities
export const PRIVATE_IP_PATTERNS = [
  /^https?:\/\/10\.\d+\.\d+\.\d+/,
  /^https?:\/\/172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
  /^https?:\/\/192\.168\.\d+\.\d+/,
  /^https?:\/\/[^/]*\.internal[./]/,
  /^https?:\/\/[^/]*\.local[./]/,
  /^https?:\/\/[^/]*\.corp[./]/,
  /^https?:\/\/[^/]*\.private[./]/
];

export const DEV_ENVIRONMENT_PATTERNS = [
  'staging', 'stage', 'dev', 'development', 'test', 'sandbox',
  'qa', 'uat', 'preprod', 'pre-prod', 'demo', 'preview'
];

export const SENSITIVE_ENDPOINT_PATTERNS = [
  '/password', '/credentials', '/tokens', '/keys', '/secrets',
  '/payment', '/billing', '/charge', '/subscription',
  '/pii', '/personal', '/private'
];

export const ADMIN_ENDPOINT_PATTERNS = [
  '/admin', '/management', '/internal', '/system', '/config', '/settings'
];

export const URL_PARAM_PATTERNS = [
  'url', 'uri', 'link', 'href', 'src', 'source', 'target', 'redirect', 'callback', 'webhook'
];

export const SENSITIVE_PROPERTY_PATTERNS = [
  'password', 'secret', 'token', 'apikey', 'api_key',
  'private', 'ssn', 'social_security', 'credit_card',
  'creditcard', 'cvv', 'pin', 'salary', 'income'
];

export const QUERY_INJECTION_PATTERNS = [
  'query', 'search', 'filter', 'sort', 'order', 'where', 'select', 'fields'
];

// HTTP method utilities
export const HTTP_METHODS = ['get', 'post', 'put', 'delete', 'patch'] as const;
export type HttpMethod = typeof HTTP_METHODS[number];

// Finding creation helper
export function createFinding(
  ruleId: string,
  title: string,
  description: string,
  severity: Severity,
  options: {
    owaspCategory?: string;
    filePath?: string;
    endpoint?: string;
    method?: string;
    remediation?: string;
  } = {}
): Finding {
  return {
    ruleId,
    title,
    description,
    severity,
    owaspCategory: options.owaspCategory,
    location: {
      path: options.filePath,
      endpoint: options.endpoint,
      method: options.method
    },
    remediation: options.remediation
  };
}

// Server URL check helper
export function isLocalhostUrl(url: string): boolean {
  return url.includes('localhost') || url.includes('127.0.0.1');
}

export function isHttpUrl(url: string): boolean {
  return url.startsWith('http://');
}

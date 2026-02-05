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

/**
 * FB6: Check if a Content-Type is JSON-compatible
 * Handles: application/json, application/hal+json, application/vnd.api+json, text/json, etc.
 */
export function isJsonContentType(contentType: string): boolean {
  const lower = contentType.toLowerCase();
  return (
    lower === 'application/json' ||
    lower === 'text/json' ||
    /^application\/[a-z0-9.+-]*\+json$/i.test(lower) ||  // application/*+json
    /^application\/vnd\.[a-z0-9.+-]*\+json$/i.test(lower)  // application/vnd.*+json
  );
}

/**
 * FB6: Get all JSON schemas from a response content object
 * Returns schemas for any JSON-compatible content types
 */
export function getJsonSchemasFromContent(content: Record<string, { schema?: unknown }> | undefined): unknown[] {
  if (!content) return [];
  
  const schemas: unknown[] = [];
  for (const [contentType, mediaType] of Object.entries(content)) {
    if (isJsonContentType(contentType) && mediaType.schema) {
      schemas.push(mediaType.schema);
    }
  }
  return schemas;
}

/**
 * FB5: Resolve $ref in schema to actual schema object
 * Handles local references like #/components/schemas/User
 */
export function resolveRef(ref: string, spec: OpenApiSpec): unknown {
  if (!ref.startsWith('#/')) return undefined;
  
  const parts = ref.slice(2).split('/');
  let current: unknown = spec;
  
  for (const part of parts) {
    if (current && typeof current === 'object' && part in current) {
      current = (current as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  
  return current;
}

/**
 * FB5: Recursively collect all property names from a schema
 * Handles $ref, nested objects, arrays, allOf/oneOf/anyOf
 * Uses visited set to prevent infinite loops on circular references
 */
export function collectSchemaProperties(
  schema: unknown,
  spec: OpenApiSpec,
  visited: Set<string> = new Set()
): string[] {
  if (!schema || typeof schema !== 'object') return [];
  
  const schemaObj = schema as Record<string, unknown>;
  const properties: string[] = [];
  
  // Handle $ref
  if (schemaObj.$ref && typeof schemaObj.$ref === 'string') {
    if (visited.has(schemaObj.$ref)) {
      return []; // Circular reference, stop recursion
    }
    visited.add(schemaObj.$ref);
    const resolved = resolveRef(schemaObj.$ref, spec);
    if (resolved) {
      properties.push(...collectSchemaProperties(resolved, spec, visited));
    }
    return properties;
  }
  
  // Collect direct properties
  if (schemaObj.properties && typeof schemaObj.properties === 'object') {
    for (const propName of Object.keys(schemaObj.properties)) {
      properties.push(propName);
      // Also collect nested properties
      const propSchema = (schemaObj.properties as Record<string, unknown>)[propName];
      properties.push(...collectSchemaProperties(propSchema, spec, visited));
    }
  }
  
  // Handle array items
  if (schemaObj.items) {
    properties.push(...collectSchemaProperties(schemaObj.items, spec, visited));
  }
  
  // Handle allOf/oneOf/anyOf
  for (const combiner of ['allOf', 'oneOf', 'anyOf'] as const) {
    if (Array.isArray(schemaObj[combiner])) {
      for (const subSchema of schemaObj[combiner]) {
        properties.push(...collectSchemaProperties(subSchema, spec, visited));
      }
    }
  }
  
  // Handle additionalProperties if it's a schema
  if (schemaObj.additionalProperties && typeof schemaObj.additionalProperties === 'object') {
    properties.push(...collectSchemaProperties(schemaObj.additionalProperties, spec, visited));
  }
  
  return properties;
}

/**
 * Get header names from a response, resolving $ref if needed
 * FB4: Handles direct headers and $ref to components.headers
 */
export function getResponseHeaderNames(
  response: { headers?: Record<string, unknown>; $ref?: string },
  spec: OpenApiSpec
): string[] {
  let resolvedResponse = response;
  
  // Resolve response $ref if present
  if (response.$ref && typeof response.$ref === 'string') {
    const resolved = resolveRef(response.$ref, spec);
    if (resolved && typeof resolved === 'object') {
      resolvedResponse = resolved as typeof response;
    }
  }
  
  if (!resolvedResponse.headers) return [];
  
  const headerNames: string[] = [];
  
  for (const [name, header] of Object.entries(resolvedResponse.headers)) {
    // Check if header itself is a $ref
    if (header && typeof header === 'object' && '$ref' in header) {
      const headerRef = (header as { $ref: string }).$ref;
      // Extract header name from ref if it's to components/headers
      if (headerRef.startsWith('#/components/headers/')) {
        headerNames.push(name.toLowerCase());
      } else {
        // Resolve and check if it has a name or schema
        const resolved = resolveRef(headerRef, spec);
        if (resolved) {
          headerNames.push(name.toLowerCase());
        }
      }
    } else {
      headerNames.push(name.toLowerCase());
    }
  }
  
  return headerNames;
}

/**
 * Check if a request body has any JSON content without schema
 * FB3: Handles application/json, application/*+json, etc.
 * Also resolves $ref in requestBody
 */
export function hasJsonContentWithoutSchema(
  requestBody: { content?: Record<string, { schema?: unknown }>; $ref?: string } | undefined,
  spec: OpenApiSpec
): boolean {
  if (!requestBody) return false;
  
  let resolvedBody = requestBody;
  
  // Resolve requestBody $ref if present
  if (requestBody.$ref && typeof requestBody.$ref === 'string') {
    const resolved = resolveRef(requestBody.$ref, spec);
    if (resolved && typeof resolved === 'object') {
      resolvedBody = resolved as typeof requestBody;
    }
  }
  
  if (!resolvedBody.content) return false;
  
  for (const [contentType, mediaType] of Object.entries(resolvedBody.content)) {
    if (isJsonContentType(contentType) && !mediaType.schema) {
      return true;
    }
  }
  
  return false;
}

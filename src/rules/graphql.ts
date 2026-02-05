/**
 * GraphQL-Specific Security Rules
 * APIVET076-083
 */

import type { OpenApiSpec, Finding } from '../types.js';
import {
  Rule,
  hasGlobalSecurity,
  hasSecuritySchemes,
  createFinding,
  getResponseHeaderNames
} from './utils.js';

// Helper: Check if endpoint is GraphQL
function isGraphQLEndpoint(path: string, operation: Record<string, unknown>): boolean {
  // Check path patterns
  const pathLower = path.toLowerCase();
  if (pathLower.includes('/graphql') || pathLower.includes('/gql') || pathLower === '/query') {
    return true;
  }

  // Check for GraphQL content types in request body
  const requestBody = operation.requestBody as Record<string, unknown> | undefined;
  if (requestBody?.content) {
    const content = requestBody.content as Record<string, unknown>;
    if (content['application/graphql'] || content['application/graphql+json']) {
      return true;
    }
  }

  // Check for x-graphql extension
  if (operation['x-graphql'] || operation['x-graphql-operation']) {
    return true;
  }

  // Check operation ID or summary for GraphQL indicators
  const opId = (operation.operationId as string || '').toLowerCase();
  const summary = (operation.summary as string || '').toLowerCase();
  if (opId.includes('graphql') || summary.includes('graphql')) {
    return true;
  }

  return false;
}

// Helper: Check if spec has any GraphQL endpoints
function hasGraphQLEndpoints(spec: OpenApiSpec): boolean {
  const paths = spec.paths || {};

  for (const [path, pathItem] of Object.entries(paths)) {
    for (const method of ['get', 'post'] as const) {
      const operation = pathItem[method] as Record<string, unknown> | undefined;
      if (operation && isGraphQLEndpoint(path, operation)) {
        return true;
      }
    }
  }

  return false;
}

export const graphqlRules: Rule[] = [
  // GraphQL Introspection
  {
    id: 'APIVET076',
    title: 'GraphQL introspection may be enabled',
    description: 'GraphQL introspection reveals the entire API schema to attackers',
    severity: 'medium',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const specStr = JSON.stringify(spec).toLowerCase();

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post'] as const) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          if (isGraphQLEndpoint(path, operation)) {
            // Check if introspection is explicitly disabled
            const hasIntrospectionDisabled =
              specStr.includes('introspection') && specStr.includes('disabled') ||
              specStr.includes('"introspection":false') ||
              specStr.includes('"introspection": false');

            if (!hasIntrospectionDisabled) {
              findings.push(createFinding(
                'APIVET076',
                'GraphQL introspection may be enabled',
                `${method.toUpperCase()} ${path} is a GraphQL endpoint. Introspection queries (__schema, __type) may expose the entire API schema.`,
                'medium',
                {
                  owaspCategory: 'API9:2023',
                  filePath,
                  endpoint: path,
                  method: method.toUpperCase(),
                  remediation: 'Disable introspection in production. Configure graphql-disable-introspection or similar middleware. Use schema allow-lists.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // GraphQL Query Depth
  {
    id: 'APIVET077',
    title: 'GraphQL without query depth limiting',
    description: 'Deeply nested GraphQL queries can cause DoS via exponential complexity',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const specStr = JSON.stringify(spec).toLowerCase();

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post'] as const) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          if (isGraphQLEndpoint(path, operation)) {
            // Check if depth limiting is mentioned
            const hasDepthLimit =
              specStr.includes('depth') && (specStr.includes('limit') || specStr.includes('max')) ||
              specStr.includes('maxdepth') ||
              specStr.includes('max_depth') ||
              specStr.includes('querydepth');

            if (!hasDepthLimit) {
              findings.push(createFinding(
                'APIVET077',
                'GraphQL endpoint without query depth limiting',
                `${method.toUpperCase()} ${path} is a GraphQL endpoint without indicated depth limiting. Deep nested queries can exhaust server resources.`,
                'medium',
                {
                  owaspCategory: 'API4:2023',
                  filePath,
                  endpoint: path,
                  method: method.toUpperCase(),
                  remediation: 'Implement query depth validation (e.g., graphql-depth-limit). Set maximum depth to 5-10 levels. Reject queries exceeding limits.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // GraphQL Query Complexity
  {
    id: 'APIVET078',
    title: 'GraphQL without query complexity analysis',
    description: 'Complex GraphQL queries can cause resource exhaustion',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const specStr = JSON.stringify(spec).toLowerCase();

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post'] as const) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          if (isGraphQLEndpoint(path, operation)) {
            // Check if complexity analysis is mentioned
            const hasComplexityLimit =
              specStr.includes('complexity') && (specStr.includes('limit') || specStr.includes('max') || specStr.includes('cost')) ||
              specStr.includes('querycost') ||
              specStr.includes('query_cost') ||
              specStr.includes('maxcomplexity');

            if (!hasComplexityLimit) {
              findings.push(createFinding(
                'APIVET078',
                'GraphQL endpoint without query complexity analysis',
                `${method.toUpperCase()} ${path} is a GraphQL endpoint without indicated complexity analysis. Complex queries can cause DoS.`,
                'medium',
                {
                  owaspCategory: 'API4:2023',
                  filePath,
                  endpoint: path,
                  method: method.toUpperCase(),
                  remediation: 'Implement query complexity analysis (e.g., graphql-cost-analysis, graphql-query-complexity). Set cost limits per query.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // GraphQL Batching
  {
    id: 'APIVET079',
    title: 'GraphQL batching without limits',
    description: 'Unlimited GraphQL batching can amplify attacks',
    severity: 'low',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const specStr = JSON.stringify(spec).toLowerCase();

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['post'] as const) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          if (isGraphQLEndpoint(path, operation)) {
            // Check request body for array type (batching)
            const requestBody = operation.requestBody as Record<string, unknown> | undefined;
            let allowsBatching = false;

            if (requestBody?.content) {
              const content = requestBody.content as Record<string, { schema?: Record<string, unknown> }>;
              const jsonContent = content['application/json'];
              if (jsonContent?.schema) {
                const schema = jsonContent.schema;
                // Check if schema is array or oneOf with array
                if (schema.type === 'array' || schema.oneOf || schema.anyOf) {
                  allowsBatching = true;
                }
              }
            }

            // Check if batching limits are mentioned
            const hasBatchLimit =
              specStr.includes('batch') && (specStr.includes('limit') || specStr.includes('max')) ||
              specStr.includes('maxbatch') ||
              specStr.includes('max_batch') ||
              specStr.includes('maxoperations');

            if (allowsBatching && !hasBatchLimit) {
              findings.push(createFinding(
                'APIVET079',
                'GraphQL batching without limits',
                `${method.toUpperCase()} ${path} appears to support GraphQL batching without indicated limits. Batch queries can amplify attacks.`,
                'low',
                {
                  owaspCategory: 'API4:2023',
                  filePath,
                  endpoint: path,
                  method: method.toUpperCase(),
                  remediation: 'Limit batch size (e.g., max 10 operations per request). Consider disabling batching for public APIs.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // GraphQL without authentication
  {
    id: 'APIVET080',
    title: 'GraphQL endpoint without authentication',
    description: 'GraphQL endpoints should require authentication',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post'] as const) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          if (!isGraphQLEndpoint(path, operation)) continue;

          // Check for security
          const hasSecurity = operation.security ||
                             hasGlobalSecurity(spec) ||
                             hasSecuritySchemes(spec);

          if (!hasSecurity) {
            findings.push(createFinding(
              'APIVET080',
              'GraphQL endpoint without authentication',
              `${method.toUpperCase()} ${path} is a GraphQL endpoint without authentication. Full schema access may be exposed.`,
              'high',
              {
                owaspCategory: 'API2:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Require authentication for GraphQL endpoints. Implement field-level authorization. Use persisted queries for public access.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // GraphQL Field Suggestions
  {
    id: 'APIVET081',
    title: 'GraphQL field suggestions may expose schema',
    description: 'GraphQL error messages with field suggestions reveal schema information',
    severity: 'low',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const specStr = JSON.stringify(spec).toLowerCase();

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post'] as const) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          if (isGraphQLEndpoint(path, operation)) {
            // Check if field suggestions are explicitly disabled
            const hasSuggestionsDisabled =
              specStr.includes('suggestion') && specStr.includes('disabled') ||
              specStr.includes('"suggestions":false') ||
              specStr.includes('hidesuggestions');

            if (!hasSuggestionsDisabled) {
              findings.push(createFinding(
                'APIVET081',
                'GraphQL field suggestions may expose schema',
                `${method.toUpperCase()} ${path} is a GraphQL endpoint. Field suggestions in error messages ("Did you mean X?") can reveal schema structure.`,
                'low',
                {
                  owaspCategory: 'API9:2023',
                  filePath,
                  endpoint: path,
                  method: method.toUpperCase(),
                  remediation: 'Disable field suggestions in production. Configure Apollo Server fieldSuggestion: false or equivalent. Return generic error messages.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // GraphQL over HTTP
  {
    id: 'APIVET082',
    title: 'GraphQL endpoint over HTTP',
    description: 'GraphQL endpoints should use HTTPS',
    severity: 'high',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];

      if (!hasGraphQLEndpoints(spec)) return findings;

      const servers = spec.servers || [];

      for (const server of servers) {
        if (server.url.startsWith('http://') &&
            !server.url.includes('localhost') &&
            !server.url.includes('127.0.0.1')) {
          findings.push(createFinding(
            'APIVET082',
            `GraphQL API served over HTTP: ${server.url}`,
            'This GraphQL API is served over unencrypted HTTP. GraphQL queries may contain sensitive data.',
            'high',
            {
              owaspCategory: 'API8:2023',
              filePath,
              remediation: 'Serve GraphQL exclusively over HTTPS. Redirect HTTP to HTTPS. Enable HSTS.'
            }
          ));
        }
      }

      return findings;
    }
  },

  // GraphQL without rate limiting
  {
    id: 'APIVET083',
    title: 'GraphQL without rate limiting',
    description: 'GraphQL endpoints should have rate limiting',
    severity: 'medium',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of ['get', 'post'] as const) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          if (!isGraphQLEndpoint(path, operation)) continue;

          // Check for rate limit headers
          let hasRateLimitHeaders = false;
          if (operation.responses) {
            for (const response of Object.values(operation.responses)) {
              const headerNames = getResponseHeaderNames(
                response as { headers?: Record<string, unknown>; $ref?: string },
                spec
              );

              if (headerNames.some(h =>
                h.includes('ratelimit') ||
                h.includes('x-ratelimit') ||
                h.includes('retry-after')
              )) {
                hasRateLimitHeaders = true;
                break;
              }
            }
          }

          // Check for 429 response
          const responses = operation.responses as Record<string, unknown> | undefined;
          const has429 = responses?.['429'] !== undefined;

          if (!hasRateLimitHeaders && !has429) {
            findings.push(createFinding(
              'APIVET083',
              'GraphQL endpoint without rate limiting indication',
              `${method.toUpperCase()} ${path} is a GraphQL endpoint without rate limiting headers or 429 response defined.`,
              'medium',
              {
                owaspCategory: 'API4:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Implement rate limiting based on query complexity, client IP, or user. Return 429 with Retry-After header when limits exceeded.'
              }
            ));
          }
        }
      }

      return findings;
    }
  }
];

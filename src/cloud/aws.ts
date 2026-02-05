/**
 * AWS API Gateway Scanner
 * Supports both REST API (V1) and HTTP API (V2)
 */

import {
  APIGatewayClient,
  GetRestApisCommand,
  GetResourcesCommand,
  GetMethodCommand,
  GetAuthorizersCommand,
  type RestApi,
  type Resource,
} from '@aws-sdk/client-api-gateway';

import {
  ApiGatewayV2Client,
  GetApisCommand,
  GetRoutesCommand,
  GetAuthorizersCommand as GetAuthorizersV2Command,
  type Api,
  type Route,
} from '@aws-sdk/client-apigatewayv2';

import type { OpenApiSpec } from '../types.js';

export interface AwsApiGatewayOptions {
  region?: string;
  apiId?: string;
  profile?: string;
}

export interface DiscoveredApi {
  id: string;
  name: string;
  type: 'REST' | 'HTTP' | 'WEBSOCKET';
  endpoint?: string;
  stage?: string;
  spec: OpenApiSpec;
}

/**
 * Convert AWS API Gateway REST API to OpenAPI spec
 */
async function convertRestApiToOpenApi(
  client: APIGatewayClient,
  api: RestApi
): Promise<OpenApiSpec> {
  const apiId = api.id!;
  
  // Get all resources (paths)
  const resourcesResponse = await client.send(new GetResourcesCommand({
    restApiId: apiId,
    limit: 500
  }));
  
  const resources = resourcesResponse.items || [];
  
  // Get authorizers
  const authorizersResponse = await client.send(new GetAuthorizersCommand({
    restApiId: apiId
  }));
  const authorizers = authorizersResponse.items || [];
  
  // Build OpenAPI spec
  const spec: OpenApiSpec = {
    openapi: '3.0.3',
    info: {
      title: api.name || 'AWS API Gateway REST API',
      version: api.version || '1.0.0',
      description: api.description || `AWS API Gateway REST API: ${apiId}`
    },
    servers: api.endpointConfiguration?.types?.includes('EDGE')
      ? [{ url: `https://${apiId}.execute-api.${process.env.AWS_REGION || 'us-east-1'}.amazonaws.com` }]
      : [],
    paths: {},
    components: {
      securitySchemes: {}
    },
    'x-amazon-apigateway-api-id': apiId
  };

  // Add authorizers as security schemes
  for (const auth of authorizers) {
    if (auth.name) {
      if (auth.type === 'COGNITO_USER_POOLS') {
        spec.components!.securitySchemes![auth.name] = {
          type: 'oauth2',
          description: `Cognito User Pool: ${auth.providerARNs?.join(', ')}`,
          flows: { implicit: { authorizationUrl: '', scopes: {} } }
        };
      } else if (auth.type === 'TOKEN' || auth.type === 'REQUEST') {
        spec.components!.securitySchemes![auth.name] = {
          type: 'apiKey',
          in: 'header',
          name: auth.identitySource || 'Authorization',
          description: `Lambda Authorizer: ${auth.authorizerUri || 'custom'}`
        };
      }
    }
  }

  // Build paths from resources
  for (const resource of resources) {
    if (!resource.path || resource.path === '/') continue;
    
    const pathItem: Record<string, unknown> = {};
    
    // Get methods for this resource
    if (resource.resourceMethods) {
      for (const [method, _] of Object.entries(resource.resourceMethods)) {
        if (method === 'OPTIONS') continue; // Skip CORS preflight
        
        try {
          const methodResponse = await client.send(new GetMethodCommand({
            restApiId: apiId,
            resourceId: resource.id!,
            httpMethod: method
          }));
          
          const operation: Record<string, unknown> = {
            responses: {
              '200': { description: 'Success' }
            }
          };
          
          // Add authorization info
          if (methodResponse.authorizationType === 'NONE') {
            operation['x-amazon-apigateway-auth'] = { type: 'NONE' };
          } else if (methodResponse.authorizationType === 'AWS_IAM') {
            operation.security = [{ 'aws-iam': [] }];
            spec.components!.securitySchemes!['aws-iam'] = {
              type: 'apiKey',
              in: 'header',
              name: 'Authorization',
              description: 'AWS IAM authentication'
            };
          } else if (methodResponse.authorizationType === 'COGNITO_USER_POOLS') {
            operation.security = [{ 'cognito': [] }];
          } else if (methodResponse.authorizationType === 'CUSTOM' && methodResponse.authorizerId) {
            const authName = authorizers.find(a => a.id === methodResponse.authorizerId)?.name || 'custom-auth';
            operation.security = [{ [authName]: [] }];
          }
          
          // Check for API key requirement
          if (methodResponse.apiKeyRequired) {
            operation['x-amazon-apigateway-api-key-required'] = true;
            if (!spec.components!.securitySchemes!['api-key']) {
              spec.components!.securitySchemes!['api-key'] = {
                type: 'apiKey',
                in: 'header',
                name: 'x-api-key'
              };
            }
          }
          
          // Add request validation info
          if (methodResponse.requestValidatorId) {
            operation['x-amazon-apigateway-request-validator'] = methodResponse.requestValidatorId;
          }
          
          pathItem[method.toLowerCase()] = operation;
        } catch (error) {
          // Method might not be accessible, add basic info
          pathItem[method.toLowerCase()] = {
            responses: { '200': { description: 'Success' } }
          };
        }
      }
    }
    
    if (Object.keys(pathItem).length > 0) {
      spec.paths![resource.path] = pathItem as import('../types.js').PathItem;
    }
  }

  return spec;
}

/**
 * Convert AWS API Gateway HTTP API (V2) to OpenAPI spec
 */
async function convertHttpApiToOpenApi(
  client: ApiGatewayV2Client,
  api: Api
): Promise<OpenApiSpec> {
  const apiId = api.ApiId!;
  
  // Get routes
  const routesResponse = await client.send(new GetRoutesCommand({
    ApiId: apiId,
    MaxResults: '500'
  }));
  const routes = routesResponse.Items || [];
  
  // Get authorizers
  const authorizersResponse = await client.send(new GetAuthorizersV2Command({
    ApiId: apiId
  }));
  const authorizers = authorizersResponse.Items || [];
  
  // Build OpenAPI spec
  const spec: OpenApiSpec = {
    openapi: '3.0.3',
    info: {
      title: api.Name || 'AWS API Gateway HTTP API',
      version: api.Version || '1.0.0',
      description: api.Description || `AWS API Gateway HTTP API: ${apiId}`
    },
    servers: api.ApiEndpoint ? [{ url: api.ApiEndpoint }] : [],
    paths: {},
    components: {
      securitySchemes: {}
    },
    'x-amazon-apigateway-api-id': apiId
  };

  // Add authorizers
  for (const auth of authorizers) {
    if (auth.Name) {
      if (auth.AuthorizerType === 'JWT') {
        spec.components!.securitySchemes![auth.Name] = {
          type: 'oauth2',
          description: `JWT Authorizer: ${auth.JwtConfiguration?.Issuer || 'unknown'}`,
          flows: { implicit: { authorizationUrl: '', scopes: {} } }
        };
      } else if (auth.AuthorizerType === 'REQUEST') {
        spec.components!.securitySchemes![auth.Name] = {
          type: 'apiKey',
          in: 'header',
          name: 'Authorization',
          description: 'Lambda Authorizer'
        };
      }
    }
  }

  // Build paths from routes
  for (const route of routes) {
    if (!route.RouteKey || route.RouteKey === '$default') continue;
    
    // Parse route key (e.g., "GET /users/{id}")
    const match = route.RouteKey.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|ANY)\s+(.+)$/);
    if (!match) continue;
    
    const [, method, path] = match;
    
    if (!spec.paths![path]) {
      spec.paths![path] = {};
    }
    
    const operation: Record<string, unknown> = {
      responses: {
        '200': { description: 'Success' }
      }
    };
    
    // Add authorization info
    if (route.AuthorizationType === 'NONE') {
      operation['x-amazon-apigateway-auth'] = { type: 'NONE' };
    } else if (route.AuthorizationType === 'JWT' && route.AuthorizerId) {
      const authName = authorizers.find(a => a.AuthorizerId === route.AuthorizerId)?.Name || 'jwt-auth';
      operation.security = [{ [authName]: [] }];
    } else if (route.AuthorizationType === 'AWS_IAM') {
      operation.security = [{ 'aws-iam': [] }];
      spec.components!.securitySchemes!['aws-iam'] = {
        type: 'apiKey',
        in: 'header',
        name: 'Authorization',
        description: 'AWS IAM authentication'
      };
    }
    
    // Handle ANY method - expand to all methods
    if (method === 'ANY') {
      for (const m of ['get', 'post', 'put', 'delete', 'patch']) {
        (spec.paths![path] as Record<string, unknown>)[m] = { ...operation };
      }
    } else {
      (spec.paths![path] as Record<string, unknown>)[method.toLowerCase()] = operation;
    }
  }

  return spec;
}

/**
 * Discover all API Gateway APIs in an AWS account/region
 */
export async function discoverAwsApis(
  options: AwsApiGatewayOptions = {}
): Promise<DiscoveredApi[]> {
  const region = options.region || process.env.AWS_REGION || 'us-east-1';
  const discoveredApis: DiscoveredApi[] = [];

  // REST API client (V1)
  const restClient = new APIGatewayClient({ region });
  
  // HTTP API client (V2)
  const httpClient = new ApiGatewayV2Client({ region });

  // Discover REST APIs (V1)
  try {
    const restApisResponse = await restClient.send(new GetRestApisCommand({
      limit: 500
    }));
    
    for (const api of restApisResponse.items || []) {
      if (options.apiId && api.id !== options.apiId) continue;
      
      try {
        const spec = await convertRestApiToOpenApi(restClient, api);
        discoveredApis.push({
          id: api.id!,
          name: api.name || 'Unnamed REST API',
          type: 'REST',
          endpoint: `https://${api.id}.execute-api.${region}.amazonaws.com`,
          spec
        });
      } catch (error) {
        console.error(`Error processing REST API ${api.id}:`, error);
      }
    }
  } catch (error) {
    // REST API access might not be available
    console.error('Error listing REST APIs:', error);
  }

  // Discover HTTP APIs (V2)
  try {
    const httpApisResponse = await httpClient.send(new GetApisCommand({
      MaxResults: '500'
    }));
    
    for (const api of httpApisResponse.Items || []) {
      if (options.apiId && api.ApiId !== options.apiId) continue;
      if (api.ProtocolType === 'WEBSOCKET') continue; // Skip WebSocket APIs for now
      
      try {
        const spec = await convertHttpApiToOpenApi(httpClient, api);
        discoveredApis.push({
          id: api.ApiId!,
          name: api.Name || 'Unnamed HTTP API',
          type: 'HTTP',
          endpoint: api.ApiEndpoint,
          spec
        });
      } catch (error) {
        console.error(`Error processing HTTP API ${api.ApiId}:`, error);
      }
    }
  } catch (error) {
    // HTTP API access might not be available
    console.error('Error listing HTTP APIs:', error);
  }

  return discoveredApis;
}

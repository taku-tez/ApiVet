/**
 * GCP API Gateway Scanner
 * Discovers and analyzes API Gateway configurations
 */

import { ApiGatewayServiceClient } from '@google-cloud/api-gateway';
import type { OpenApiSpec } from '../types.js';
import YAML from 'yaml';

export interface GcpApiGatewayOptions {
  project?: string;
  location?: string;
  gatewayId?: string;
}

export interface DiscoveredGcpApi {
  id: string;
  name: string;
  displayName: string;
  state: string;
  endpoint?: string;
  apiConfig?: string;
  spec: OpenApiSpec;
}

/**
 * Parse OpenAPI spec from API config
 */
function parseOpenApiSpec(content: string): OpenApiSpec {
  // Try JSON first, then YAML
  try {
    return JSON.parse(content);
  } catch {
    try {
      return YAML.parse(content);
    } catch {
      // Return minimal spec if parsing fails
      return {
        openapi: '3.0.0',
        info: { title: 'Unknown', version: '1.0.0' },
        paths: {}
      };
    }
  }
}

/**
 * Extract security info from GCP API Gateway config
 */
function enrichSpecWithGcpInfo(
  spec: OpenApiSpec,
  gateway: { name?: string; defaultHostname?: string; state?: string }
): OpenApiSpec {
  // Add GCP-specific metadata
  const enrichedSpec: OpenApiSpec = {
    ...spec,
    'x-google-gateway': gateway.name,
    'x-google-gateway-state': gateway.state
  };

  // Add server URL if available
  if (gateway.defaultHostname) {
    enrichedSpec.servers = [
      { url: `https://${gateway.defaultHostname}`, description: 'GCP API Gateway' },
      ...(spec.servers || [])
    ];
  }

  // Check for Google-specific security extensions
  if (!enrichedSpec.components) {
    enrichedSpec.components = {};
  }
  if (!enrichedSpec.components.securitySchemes) {
    enrichedSpec.components.securitySchemes = {};
  }

  // Look for x-google-backend (indicates backend authentication)
  const specStr = JSON.stringify(spec);
  if (specStr.includes('x-google-backend')) {
    enrichedSpec['x-google-backend-detected'] = true;
  }

  // Look for security definitions
  if (specStr.includes('x-google-audiences')) {
    enrichedSpec.components.securitySchemes['google-id-token'] = {
      type: 'oauth2',
      description: 'Google ID Token authentication',
      flows: { implicit: { authorizationUrl: 'https://accounts.google.com/o/oauth2/auth', scopes: {} } }
    };
  }

  if (specStr.includes('x-google-issuer')) {
    enrichedSpec.components.securitySchemes['google-jwt'] = {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      description: 'Google JWT authentication'
    };
  }

  // Check for API key requirement
  if (specStr.includes('x-google-api-key') || specStr.includes('api_key_required')) {
    enrichedSpec.components.securitySchemes['api-key'] = {
      type: 'apiKey',
      in: 'query',
      name: 'key',
      description: 'Google API Key'
    };
  }

  return enrichedSpec;
}

/**
 * Discover all API Gateway APIs in a GCP project
 */
export async function discoverGcpApis(
  options: GcpApiGatewayOptions = {}
): Promise<DiscoveredGcpApi[]> {
  const project = options.project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  const location = options.location || 'global';

  if (!project) {
    throw new Error('GCP project not specified. Use --project or set GOOGLE_CLOUD_PROJECT environment variable.');
  }

  const discoveredApis: DiscoveredGcpApi[] = [];
  const client = new ApiGatewayServiceClient();

  try {
    // List all gateways
    const parent = `projects/${project}/locations/${location}`;
    const [gateways] = await client.listGateways({ parent });

    for (const gateway of gateways) {
      if (options.gatewayId && !gateway.name?.includes(options.gatewayId)) {
        continue;
      }

      // Skip non-active gateways
      if (gateway.state !== 'ACTIVE') {
        console.log(`Skipping gateway ${gateway.displayName} (state: ${gateway.state})`);
        continue;
      }

      try {
        // Get the API config associated with this gateway
        if (gateway.apiConfig) {
          const [apiConfig] = await client.getApiConfig({ name: gateway.apiConfig });
          
          let spec: OpenApiSpec;
          
          // Try to get the OpenAPI spec from the config
          if (apiConfig.openapiDocuments && apiConfig.openapiDocuments.length > 0) {
            // Parse the first OpenAPI document
            const doc = apiConfig.openapiDocuments[0];
            if (doc.document?.contents) {
              const content = Buffer.from(doc.document.contents).toString('utf-8');
              spec = parseOpenApiSpec(content);
            } else {
              spec = {
                openapi: '3.0.0',
                info: { title: gateway.displayName || 'Unknown', version: '1.0.0' },
                paths: {}
              };
            }
          } else if (apiConfig.grpcServices && apiConfig.grpcServices.length > 0) {
            // gRPC service - create minimal spec
            spec = {
              openapi: '3.0.0',
              info: {
                title: gateway.displayName || 'gRPC Service',
                version: '1.0.0',
                description: 'gRPC service (protocol buffers)'
              },
              paths: {},
              'x-google-grpc': true
            };
          } else {
            spec = {
              openapi: '3.0.0',
              info: { title: gateway.displayName || 'Unknown', version: '1.0.0' },
              paths: {}
            };
          }

          // Enrich spec with GCP-specific info
          spec = enrichSpecWithGcpInfo(spec, {
            name: gateway.name || undefined,
            defaultHostname: gateway.defaultHostname || undefined,
            state: gateway.state as string
          });

          discoveredApis.push({
            id: gateway.name?.split('/').pop() || 'unknown',
            name: gateway.name || 'unknown',
            displayName: gateway.displayName || 'Unnamed Gateway',
            state: gateway.state as string,
            endpoint: gateway.defaultHostname ? `https://${gateway.defaultHostname}` : undefined,
            apiConfig: gateway.apiConfig || undefined,
            spec
          });
        }
      } catch (error) {
        console.error(`Error processing gateway ${gateway.name}:`, error);
      }
    }

    // Also try to discover Cloud Endpoints if available
    try {
      const endpointsParent = `projects/${project}/locations/global`;
      const [apis] = await client.listApis({ parent: endpointsParent });
      
      for (const api of apis) {
        // Check if we already have this API via gateway
        const existingApi = discoveredApis.find(d => d.name === api.name);
        if (existingApi) continue;

        // Get API configs for this API
        if (api.name) {
          try {
            const [configs] = await client.listApiConfigs({ parent: api.name });
            
            for (const config of configs) {
              if (config.state !== 'ACTIVE') continue;
              
              let spec: OpenApiSpec;
              
              if (config.openapiDocuments && config.openapiDocuments.length > 0) {
                const doc = config.openapiDocuments[0];
                if (doc.document?.contents) {
                  const content = Buffer.from(doc.document.contents).toString('utf-8');
                  spec = parseOpenApiSpec(content);
                } else {
                  spec = {
                    openapi: '3.0.0',
                    info: { title: api.displayName || 'Unknown', version: '1.0.0' },
                    paths: {}
                  };
                }
              } else {
                spec = {
                  openapi: '3.0.0',
                  info: { title: api.displayName || 'Unknown', version: '1.0.0' },
                  paths: {}
                };
              }

              discoveredApis.push({
                id: api.name?.split('/').pop() || 'unknown',
                name: api.name || 'unknown',
                displayName: api.displayName || 'Unnamed API',
                state: config.state as string,
                apiConfig: config.name || undefined,
                spec
              });
              
              // Only take the first active config
              break;
            }
          } catch (error) {
            // API might not have configs
          }
        }
      }
    } catch (error) {
      // Cloud Endpoints might not be enabled
    }

  } finally {
    await client.close();
  }

  return discoveredApis;
}

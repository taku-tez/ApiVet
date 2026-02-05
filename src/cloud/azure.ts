/**
 * Azure API Management Scanner
 * Discovers and exports OpenAPI specs from Azure APIM
 */

import { ApiManagementClient } from '@azure/arm-apimanagement';
import { DefaultAzureCredential } from '@azure/identity';
import type { OpenApiSpec } from '../types.js';

export interface AzureApimOptions {
  subscriptionId?: string;
  resourceGroup?: string;
  serviceName?: string;
  apiId?: string;
}

export interface DiscoveredAzureApi {
  id: string;
  name: string;
  displayName: string;
  path: string;
  serviceUrl?: string;
  state: string;
  protocols: string[];
  spec: OpenApiSpec;
}

/**
 * Discover APIs from Azure API Management
 */
export async function discoverAzureApis(
  options: AzureApimOptions = {}
): Promise<DiscoveredAzureApi[]> {
  const {
    subscriptionId = process.env.AZURE_SUBSCRIPTION_ID,
    resourceGroup,
    serviceName,
    apiId
  } = options;

  if (!subscriptionId) {
    throw new Error('Azure subscription ID not provided. Set AZURE_SUBSCRIPTION_ID or use --subscription-id');
  }

  // Use DefaultAzureCredential which supports multiple auth methods:
  // - Environment variables (AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET)
  // - Azure CLI (az login)
  // - Managed Identity (when running on Azure)
  // - VS Code Azure extension
  const credential = new DefaultAzureCredential();
  const client = new ApiManagementClient(credential, subscriptionId);

  const discoveredApis: DiscoveredAzureApi[] = [];

  // If resource group and service name provided, scan specific APIM instance
  if (resourceGroup && serviceName) {
    const apis = await scanApimService(client, resourceGroup, serviceName, apiId);
    discoveredApis.push(...apis);
  } else {
    // List all APIM services in subscription
    const services = [];
    for await (const service of client.apiManagementService.list()) {
      services.push(service);
    }

    if (services.length === 0) {
      console.log('No API Management services found in subscription.');
      return [];
    }

    console.log(`Found ${services.length} API Management service(s)`);

    // Scan each service
    for (const service of services) {
      if (!service.name) continue;

      // Extract resource group from service ID
      // Format: /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.ApiManagement/service/{name}
      const idParts = service.id?.split('/') || [];
      const rgIndex = idParts.indexOf('resourceGroups');
      const rg = rgIndex >= 0 ? idParts[rgIndex + 1] : undefined;

      if (!rg) continue;

      console.log(`Scanning APIM: ${service.name} (${rg})`);

      try {
        const apis = await scanApimService(client, rg, service.name, apiId);
        discoveredApis.push(...apis);
      } catch (err) {
        console.error(`  Error scanning ${service.name}: ${err instanceof Error ? err.message : err}`);
      }
    }
  }

  return discoveredApis;
}

/**
 * Scan a specific APIM service for APIs
 */
async function scanApimService(
  client: ApiManagementClient,
  resourceGroup: string,
  serviceName: string,
  specificApiId?: string
): Promise<DiscoveredAzureApi[]> {
  const discoveredApis: DiscoveredAzureApi[] = [];

  // List APIs in the service
  const apis = [];
  for await (const api of client.api.listByService(resourceGroup, serviceName)) {
    // Skip if looking for specific API and this isn't it
    if (specificApiId && api.name !== specificApiId) continue;
    apis.push(api);
  }

  console.log(`  Found ${apis.length} API(s) in ${serviceName}`);

  for (const api of apis) {
    if (!api.name) continue;

    try {
      // Export OpenAPI spec
      // Format: openapi+json-link exports OpenAPI 3.0 as JSON to a storage blob with SAS URL
      // ExportParam: 'true' to export
      const exportResult = await client.apiExport.get(
        resourceGroup,
        serviceName,
        api.name,
        'openapi+json-link', // KnownExportFormat.OpenapiJson
        'true' // KnownExportApi.True
      );

      // Parse the exported spec
      // The result contains a link to the exported file in value.link
      let spec: OpenApiSpec;
      const exportLink = exportResult.value?.link;
      
      if (exportLink) {
        // Fetch the spec from the SAS URL
        try {
          const response = await fetch(exportLink);
          if (response.ok) {
            spec = await response.json() as OpenApiSpec;
          } else {
            const reason = `HTTP ${response.status} ${response.statusText}`;
            console.warn(`Warning: Full spec export failed for API "${api.displayName || api.name}" (${reason}). Using minimal spec.`);
            spec = createMinimalSpec(api, serviceName, reason);
          }
        } catch (fetchErr) {
          const reason = fetchErr instanceof Error ? fetchErr.message : String(fetchErr);
          console.warn(`Warning: Full spec export failed for API "${api.displayName || api.name}" (${reason}). Using minimal spec.`);
          spec = createMinimalSpec(api, serviceName, reason);
        }
      } else {
        const reason = 'No export link returned';
        console.warn(`Warning: Full spec export failed for API "${api.displayName || api.name}" (${reason}). Using minimal spec.`);
        spec = createMinimalSpec(api, serviceName, reason);
      }

      // Add Azure-specific metadata
      const extSpec = spec as Record<string, unknown>;
      extSpec['x-azure-apim-service'] = serviceName;
      extSpec['x-azure-apim-api-id'] = api.name;

      // Ensure servers array includes APIM gateway URL
      if (!spec.servers || spec.servers.length === 0) {
        spec.servers = [{
          url: `https://${serviceName}.azure-api.net/${api.path || ''}`,
          description: 'Azure API Management Gateway'
        }];
      }

      // Get API state/lifecycle status
      const apiState = api.isCurrent ? 'current' : (api.apiRevision ? 'revision' : 'unknown');

      discoveredApis.push({
        id: api.name,
        name: api.name,
        displayName: api.displayName || api.name,
        path: api.path || '',
        serviceUrl: api.serviceUrl,
        state: apiState,
        protocols: api.protocols || ['https'],
        spec
      });

      console.log(`    ✓ ${api.displayName || api.name}`);
    } catch (err) {
      console.error(`    ✗ ${api.displayName || api.name}: ${err instanceof Error ? err.message : err}`);
    }
  }

  return discoveredApis;
}

/**
 * Create a minimal OpenAPI spec when export fails
 */
function createMinimalSpec(api: any, serviceName: string, failureReason?: string): OpenApiSpec {
  const baseDescription = api.description || `Azure API Management API: ${api.name}`;
  const description = failureReason
    ? `Warning: Full spec export failed (${failureReason}). Using minimal spec. Original: ${baseDescription}`
    : baseDescription;

  return {
    openapi: '3.0.3',
    info: {
      title: api.displayName || api.name || 'Azure APIM API',
      version: api.apiVersion || '1.0.0',
      description
    },
    servers: [{
      url: `https://${serviceName}.azure-api.net/${api.path || ''}`,
      description: 'Azure API Management Gateway'
    }],
    paths: {},
    components: {
      securitySchemes: {}
    },
    ...(failureReason ? { 'x-apivet-export-warning': `Full spec export failed: ${failureReason}` } : {})
  };
}

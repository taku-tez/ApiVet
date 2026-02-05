/**
 * Azure API Management Scanner
 * Discovers and exports OpenAPI specs from Azure APIM
 * Fetches and analyzes APIM policies (validate-jwt, rate-limit, ip-filter, cors, etc.)
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

/**
 * Parsed APIM policy structure extracted from XML
 */
export interface ApimPolicy {
  raw: string;
  hasValidateJwt: boolean;
  hasRateLimit: boolean;
  hasRateLimitByKey: boolean;
  hasIpFilter: boolean;
  hasCors: boolean;
  corsAllowAll: boolean;
  hasCheckHeader: boolean;
  hasSetBackendService: boolean;
  hasRewriteUri: boolean;
  hasCache: boolean;
  hasMockResponse: boolean;
  hasForwardRequest: boolean;
  hasSetHeader: boolean;
  hasSetVariable: boolean;
  hasReturnResponse: boolean;
  hasLog: boolean;
  hasAuthenticationManaged: boolean;
  hasAuthenticationCertificate: boolean;
  hasAuthenticationBasic: boolean;
  jwtValidation?: {
    hasRequiredClaims: boolean;
    hasAudiences: boolean;
    hasIssuers: boolean;
    hasOpenIdConfig: boolean;
  };
  ipFilter?: {
    action: 'allow' | 'forbid' | 'unknown';
    addressCount: number;
  };
  corsConfig?: {
    allowedOrigins: string[];
    allowCredentials: boolean;
  };
  rateLimitConfig?: {
    callsPerPeriod?: number;
    renewalPeriod?: number;
  };
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
  /** Global service-level policy */
  globalPolicy?: ApimPolicy;
  /** API-level policy */
  apiPolicy?: ApimPolicy;
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

  // Fetch global (service-level) policy
  const globalPolicy = await fetchGlobalPolicy(client, resourceGroup, serviceName);
  if (globalPolicy) {
    console.log(`  📋 Global policy loaded`);
  }

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

      // Fetch API-level policy
      const apiPolicy = await fetchApiPolicy(client, resourceGroup, serviceName, api.name);

      // Embed policy metadata into spec for rule analysis
      if (globalPolicy || apiPolicy) {
        const policyMeta: Record<string, unknown> = {};
        if (globalPolicy) {
          policyMeta.global = {
            hasValidateJwt: globalPolicy.hasValidateJwt,
            hasRateLimit: globalPolicy.hasRateLimit || globalPolicy.hasRateLimitByKey,
            hasIpFilter: globalPolicy.hasIpFilter,
            hasCors: globalPolicy.hasCors,
            corsAllowAll: globalPolicy.corsAllowAll,
            hasCache: globalPolicy.hasCache,
            hasLog: globalPolicy.hasLog,
            hasAuthenticationManaged: globalPolicy.hasAuthenticationManaged,
            jwtValidation: globalPolicy.jwtValidation,
            ipFilter: globalPolicy.ipFilter,
            corsConfig: globalPolicy.corsConfig,
            rateLimitConfig: globalPolicy.rateLimitConfig,
          };
        }
        if (apiPolicy) {
          policyMeta.api = {
            hasValidateJwt: apiPolicy.hasValidateJwt,
            hasRateLimit: apiPolicy.hasRateLimit || apiPolicy.hasRateLimitByKey,
            hasIpFilter: apiPolicy.hasIpFilter,
            hasCors: apiPolicy.hasCors,
            corsAllowAll: apiPolicy.corsAllowAll,
            hasCache: apiPolicy.hasCache,
            hasLog: apiPolicy.hasLog,
            hasAuthenticationManaged: apiPolicy.hasAuthenticationManaged,
            jwtValidation: apiPolicy.jwtValidation,
            ipFilter: apiPolicy.ipFilter,
            corsConfig: apiPolicy.corsConfig,
            rateLimitConfig: apiPolicy.rateLimitConfig,
          };
        }
        (spec as Record<string, unknown>)['x-azure-apim-policies'] = policyMeta;
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
        spec,
        globalPolicy,
        apiPolicy,
      });

      console.log(`    ✓ ${api.displayName || api.name}`);
    } catch (err) {
      console.error(`    ✗ ${api.displayName || api.name}: ${err instanceof Error ? err.message : err}`);
    }
  }

  return discoveredApis;
}

// ============================================
// Policy Fetching & Parsing
// ============================================

/**
 * Parse APIM policy XML into structured data
 * Lightweight XML parsing without a full parser dependency
 */
export function parseApimPolicy(xml: string): ApimPolicy {
  const lower = xml.toLowerCase();

  // JWT validation details
  let jwtValidation: ApimPolicy['jwtValidation'];
  if (lower.includes('<validate-jwt')) {
    jwtValidation = {
      hasRequiredClaims: lower.includes('<required-claims') || lower.includes('<claim '),
      hasAudiences: lower.includes('<audiences>') || lower.includes('<audience>'),
      hasIssuers: lower.includes('<issuers>') || lower.includes('<issuer>'),
      hasOpenIdConfig: lower.includes('openid-config') || lower.includes('open-id-url'),
    };
  }

  // IP filter details
  let ipFilter: ApimPolicy['ipFilter'];
  if (lower.includes('<ip-filter')) {
    const actionMatch = xml.match(/<ip-filter\s+action\s*=\s*["'](\w+)["']/i);
    const addressMatches = xml.match(/<address>/gi);
    const rangeMatches = xml.match(/<address-range/gi);
    ipFilter = {
      action: (actionMatch?.[1]?.toLowerCase() === 'allow' ? 'allow' :
               actionMatch?.[1]?.toLowerCase() === 'forbid' ? 'forbid' : 'unknown'),
      addressCount: (addressMatches?.length || 0) + (rangeMatches?.length || 0),
    };
  }

  // CORS details
  let corsConfig: ApimPolicy['corsConfig'];
  if (lower.includes('<cors')) {
    const originsSection = xml.match(/<allowed-origins>([\s\S]*?)<\/allowed-origins>/i);
    const origins: string[] = [];
    if (originsSection) {
      const originMatches = originsSection[1].matchAll(/<origin>(.*?)<\/origin>/gi);
      for (const m of originMatches) {
        origins.push(m[1].trim());
      }
    }
    corsConfig = {
      allowedOrigins: origins,
      allowCredentials: lower.includes('allow-credentials="true"'),
    };
  }

  // Rate limit details
  let rateLimitConfig: ApimPolicy['rateLimitConfig'];
  const rateLimitMatch = xml.match(/<rate-limit\s+calls\s*=\s*["'](\d+)["']\s+renewal-period\s*=\s*["'](\d+)["']/i);
  if (rateLimitMatch) {
    rateLimitConfig = {
      callsPerPeriod: parseInt(rateLimitMatch[1], 10),
      renewalPeriod: parseInt(rateLimitMatch[2], 10),
    };
  }

  return {
    raw: xml,
    hasValidateJwt: lower.includes('<validate-jwt'),
    hasRateLimit: lower.includes('<rate-limit') && !lower.includes('<rate-limit-by-key'),
    hasRateLimitByKey: lower.includes('<rate-limit-by-key'),
    hasIpFilter: lower.includes('<ip-filter'),
    hasCors: lower.includes('<cors'),
    corsAllowAll: lower.includes('<origin>*</origin>'),
    hasCheckHeader: lower.includes('<check-header'),
    hasSetBackendService: lower.includes('<set-backend-service'),
    hasRewriteUri: lower.includes('<rewrite-uri'),
    hasCache: lower.includes('<cache-lookup') || lower.includes('<cache-store'),
    hasMockResponse: lower.includes('<mock-response'),
    hasForwardRequest: lower.includes('<forward-request'),
    hasSetHeader: lower.includes('<set-header'),
    hasSetVariable: lower.includes('<set-variable'),
    hasReturnResponse: lower.includes('<return-response'),
    hasLog: lower.includes('<log-to-eventhub') || lower.includes('<trace'),
    hasAuthenticationManaged: lower.includes('<authentication-managed-identity'),
    hasAuthenticationCertificate: lower.includes('<authentication-certificate'),
    hasAuthenticationBasic: lower.includes('<authentication-basic'),
    jwtValidation,
    ipFilter,
    corsConfig,
    rateLimitConfig,
  };
}

/**
 * Fetch global (service-level) policy for an APIM instance
 */
async function fetchGlobalPolicy(
  client: ApiManagementClient,
  resourceGroup: string,
  serviceName: string
): Promise<ApimPolicy | undefined> {
  try {
    const result = await client.policy.get(resourceGroup, serviceName, 'policy');
    const xml = result.value || '';
    if (!xml.trim()) return undefined;
    return parseApimPolicy(xml);
  } catch {
    // Policy might not exist — that's a finding in itself
    return undefined;
  }
}

/**
 * Fetch API-level policy
 */
async function fetchApiPolicy(
  client: ApiManagementClient,
  resourceGroup: string,
  serviceName: string,
  apiId: string
): Promise<ApimPolicy | undefined> {
  try {
    const result = await client.apiPolicy.get(resourceGroup, serviceName, apiId, 'policy');
    const xml = result.value || '';
    if (!xml.trim()) return undefined;
    return parseApimPolicy(xml);
  } catch {
    // Policy might not exist
    return undefined;
  }
}

/**
 * Create a minimal OpenAPI spec when export fails
 */
// eslint-disable-next-line @typescript-eslint/no-explicit-any -- Azure SDK ApiContract type
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

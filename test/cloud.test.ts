import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// ---- AWS SDK Mocks ----
const mockRestClientSend = vi.fn();
const mockHttpClientSend = vi.fn();

vi.mock('@aws-sdk/client-api-gateway', () => ({
  APIGatewayClient: vi.fn().mockImplementation(() => ({
    send: mockRestClientSend
  })),
  GetRestApisCommand: vi.fn().mockImplementation((input: any) => ({ _type: 'GetRestApis', ...input })),
  GetResourcesCommand: vi.fn().mockImplementation((input: any) => ({ _type: 'GetResources', ...input })),
  GetMethodCommand: vi.fn().mockImplementation((input: any) => ({ _type: 'GetMethod', ...input })),
  GetAuthorizersCommand: vi.fn().mockImplementation((input: any) => ({ _type: 'GetAuthorizers', ...input })),
}));

vi.mock('@aws-sdk/client-apigatewayv2', () => ({
  ApiGatewayV2Client: vi.fn().mockImplementation(() => ({
    send: mockHttpClientSend
  })),
  GetApisCommand: vi.fn().mockImplementation((input: any) => ({ _type: 'GetApis', ...input })),
  GetRoutesCommand: vi.fn().mockImplementation((input: any) => ({ _type: 'GetRoutes', ...input })),
  GetAuthorizersCommand: vi.fn().mockImplementation((input: any) => ({ _type: 'GetAuthorizersV2', ...input })),
}));

// ---- GCP Mock ----
const mockListGateways = vi.fn();
const mockGetApiConfig = vi.fn();
const mockListApis = vi.fn();
const mockListApiConfigs = vi.fn();
const mockGcpClose = vi.fn();

vi.mock('@google-cloud/api-gateway', () => ({
  ApiGatewayServiceClient: vi.fn().mockImplementation(() => ({
    listGateways: mockListGateways,
    getApiConfig: mockGetApiConfig,
    listApis: mockListApis,
    listApiConfigs: mockListApiConfigs,
    close: mockGcpClose,
  })),
}));

// ---- Azure Mocks ----
const mockAzureApiList = vi.fn();
const mockAzureServiceList = vi.fn();
const mockAzureApiExportGet = vi.fn();
const mockAzureGlobalPolicyGet = vi.fn();
const mockAzureApiPolicyGet = vi.fn();

vi.mock('@azure/arm-apimanagement', () => ({
  ApiManagementClient: vi.fn().mockImplementation(() => ({
    api: {
      listByService: mockAzureApiList,
    },
    apiExport: {
      get: mockAzureApiExportGet,
    },
    apiManagementService: {
      list: mockAzureServiceList,
    },
    policy: {
      get: mockAzureGlobalPolicyGet,
    },
    apiPolicy: {
      get: mockAzureApiPolicyGet,
    },
  })),
}));

vi.mock('@azure/identity', () => ({
  DefaultAzureCredential: vi.fn(),
}));

// ---- Imports (after mocks) ----
import { discoverAwsApis } from '../src/cloud/aws.js';
import { discoverGcpApis } from '../src/cloud/gcp.js';
import { discoverAzureApis } from '../src/cloud/azure.js';

// ---- Test Suites ----

describe('AWS API Gateway Discovery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    process.env.AWS_REGION = 'us-east-1';
  });

  afterEach(() => {
    delete process.env.AWS_REGION;
  });

  it('should discover REST APIs', async () => {
    // REST APIs response
    mockRestClientSend.mockImplementation((cmd: any) => {
      if (cmd._type === 'GetRestApis') {
        return {
          items: [{
            id: 'rest123',
            name: 'My REST API',
            endpointConfiguration: { types: ['REGIONAL'] },
          }]
        };
      }
      if (cmd._type === 'GetResources') {
        return {
          items: [{
            id: 'res1',
            path: '/users',
            resourceMethods: { GET: {} }
          }]
        };
      }
      if (cmd._type === 'GetAuthorizers') {
        return { items: [] };
      }
      if (cmd._type === 'GetMethod') {
        return { authorizationType: 'NONE' };
      }
      return {};
    });

    // V2 returns no HTTP APIs
    mockHttpClientSend.mockImplementation(() => ({ Items: [] }));

    const result = await discoverAwsApis({ region: 'us-east-1' });

    expect(result).toHaveLength(1);
    expect(result[0].type).toBe('REST');
    expect(result[0].name).toBe('My REST API');
    expect(result[0].spec.paths).toHaveProperty('/users');
  });

  it('should discover HTTP APIs', async () => {
    // REST APIs response - empty
    mockRestClientSend.mockResolvedValue({ items: [] });

    // HTTP APIs
    mockHttpClientSend.mockImplementation((cmd: any) => {
      if (cmd._type === 'GetApis') {
        return {
          Items: [{
            ApiId: 'http456',
            Name: 'My HTTP API',
            ProtocolType: 'HTTP',
            ApiEndpoint: 'https://http456.execute-api.us-east-1.amazonaws.com',
          }]
        };
      }
      if (cmd._type === 'GetRoutes') {
        return {
          Items: [{
            RouteKey: 'GET /items',
            AuthorizationType: 'NONE',
          }]
        };
      }
      if (cmd._type === 'GetAuthorizersV2') {
        return { Items: [] };
      }
      return {};
    });

    const result = await discoverAwsApis({ region: 'us-east-1' });

    expect(result).toHaveLength(1);
    expect(result[0].type).toBe('HTTP');
    expect(result[0].name).toBe('My HTTP API');
    expect(result[0].spec.paths).toHaveProperty('/items');
  });

  it('should discover WebSocket APIs', async () => {
    // REST APIs - empty
    mockRestClientSend.mockResolvedValue({ items: [] });

    // V2 APIs including WebSocket
    mockHttpClientSend.mockImplementation((cmd: any) => {
      if (cmd._type === 'GetApis') {
        return {
          Items: [{
            ApiId: 'ws789',
            Name: 'My WebSocket API',
            ProtocolType: 'WEBSOCKET',
            ApiEndpoint: 'wss://ws789.execute-api.us-east-1.amazonaws.com',
          }]
        };
      }
      if (cmd._type === 'GetRoutes') {
        return {
          Items: [
            { RouteKey: '$connect', AuthorizationType: 'NONE' },
            { RouteKey: '$disconnect', AuthorizationType: 'NONE' },
            { RouteKey: 'sendMessage', AuthorizationType: 'NONE' },
          ]
        };
      }
      if (cmd._type === 'GetAuthorizersV2') {
        return { Items: [] };
      }
      return {};
    });

    const result = await discoverAwsApis({ region: 'us-east-1' });

    expect(result).toHaveLength(1);
    expect(result[0].type).toBe('WEBSOCKET');
    expect(result[0].name).toBe('My WebSocket API');
    expect(result[0].spec['x-amazon-apigateway-protocol']).toBe('WEBSOCKET');
    // WebSocket routes are mapped as paths
    expect(Object.keys(result[0].spec.paths!).length).toBe(3);
  });

  it('should return empty array when no APIs found', async () => {
    mockRestClientSend.mockResolvedValue({ items: [] });
    mockHttpClientSend.mockResolvedValue({ Items: [] });

    const result = await discoverAwsApis({ region: 'us-east-1' });
    expect(result).toHaveLength(0);
  });

  it('should handle REST API list error gracefully', async () => {
    mockRestClientSend.mockRejectedValue(new Error('Access Denied'));
    mockHttpClientSend.mockResolvedValue({ Items: [] });

    // Should not throw, just log and return empty
    const result = await discoverAwsApis({ region: 'us-east-1' });
    expect(result).toHaveLength(0);
  });

  it('should filter by apiId', async () => {
    mockRestClientSend.mockImplementation((cmd: any) => {
      if (cmd._type === 'GetRestApis') {
        return {
          items: [
            { id: 'api-a', name: 'API A', endpointConfiguration: { types: ['EDGE'] } },
            { id: 'api-b', name: 'API B', endpointConfiguration: { types: ['EDGE'] } },
          ]
        };
      }
      if (cmd._type === 'GetResources') return { items: [] };
      if (cmd._type === 'GetAuthorizers') return { items: [] };
      return {};
    });
    mockHttpClientSend.mockResolvedValue({ Items: [] });

    const result = await discoverAwsApis({ region: 'us-east-1', apiId: 'api-b' });

    expect(result).toHaveLength(1);
    expect(result[0].id).toBe('api-b');
  });
});

describe('GCP API Gateway Discovery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should discover GCP gateways with OpenAPI specs', async () => {
    const specContent = JSON.stringify({
      openapi: '3.0.0',
      info: { title: 'GCP API', version: '1.0.0' },
      paths: { '/hello': { get: { responses: { '200': { description: 'OK' } } } } },
      'x-google-backend': { address: 'https://my-func.run.app' },
    });

    mockListGateways.mockResolvedValue([[{
      name: 'projects/my-proj/locations/global/gateways/gw1',
      displayName: 'My Gateway',
      state: 'ACTIVE',
      defaultHostname: 'gw1-abc123.gateway.dev',
      apiConfig: 'projects/my-proj/locations/global/apis/api1/configs/cfg1',
    }]]);

    mockGetApiConfig.mockResolvedValue([{
      openapiDocuments: [{
        document: {
          contents: Buffer.from(specContent),
        }
      }],
    }]);

    // listApis for Cloud Endpoints discovery
    mockListApis.mockResolvedValue([[]]);

    const result = await discoverGcpApis({ project: 'my-proj' });

    expect(result).toHaveLength(1);
    expect(result[0].displayName).toBe('My Gateway');
    expect(result[0].endpoint).toBe('https://gw1-abc123.gateway.dev');
    expect(result[0].spec['x-google-backend-detected']).toBe(true);
  });

  it('should return empty results when no gateways found', async () => {
    mockListGateways.mockResolvedValue([[]]);
    mockListApis.mockResolvedValue([[]]);

    const result = await discoverGcpApis({ project: 'my-proj' });
    expect(result).toHaveLength(0);
  });

  it('should throw error when project is not specified', async () => {
    delete process.env.GOOGLE_CLOUD_PROJECT;
    delete process.env.GCLOUD_PROJECT;

    await expect(discoverGcpApis({})).rejects.toThrow('GCP project not specified');
  });

  it('should filter by gatewayId', async () => {
    mockListGateways.mockResolvedValue([[
      {
        name: 'projects/p/locations/global/gateways/gw-alpha',
        displayName: 'Alpha',
        state: 'ACTIVE',
        apiConfig: 'projects/p/locations/global/apis/a/configs/c1',
      },
      {
        name: 'projects/p/locations/global/gateways/gw-beta',
        displayName: 'Beta',
        state: 'ACTIVE',
        apiConfig: 'projects/p/locations/global/apis/b/configs/c2',
      }
    ]]);

    mockGetApiConfig.mockResolvedValue([{
      openapiDocuments: [{
        document: { contents: Buffer.from(JSON.stringify({
          openapi: '3.0.0',
          info: { title: 'Beta', version: '1.0.0' },
          paths: {}
        })) }
      }],
    }]);

    mockListApis.mockResolvedValue([[]]);

    const result = await discoverGcpApis({ project: 'p', gatewayId: 'gw-beta' });

    expect(result).toHaveLength(1);
    expect(result[0].displayName).toBe('Beta');
  });
});

describe('Azure APIM Discovery', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Default: no policies (most tests don't need them)
    mockAzureGlobalPolicyGet.mockRejectedValue(new Error('Not found'));
    mockAzureApiPolicyGet.mockRejectedValue(new Error('Not found'));
  });

  it('should discover Azure APIM APIs with exported spec', async () => {
    // Mock async iterator for api.listByService
    const apis = [
      {
        name: 'petstore-api',
        displayName: 'Petstore API',
        path: 'pets',
        serviceUrl: 'https://petstore.backend.com',
        isCurrent: true,
        protocols: ['https'],
      }
    ];
    mockAzureApiList.mockReturnValue((async function* () {
      for (const api of apis) yield api;
    })());

    // Mock export
    const exportedSpec = {
      openapi: '3.0.3',
      info: { title: 'Petstore', version: '1.0.0' },
      paths: { '/pets': { get: { responses: { '200': { description: 'OK' } } } } },
    };
    mockAzureApiExportGet.mockResolvedValue({
      value: { link: 'https://storage.blob.core.windows.net/export/spec.json' }
    });

    // Mock fetch for the export link
    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => exportedSpec,
    } as Response);

    const result = await discoverAzureApis({
      subscriptionId: 'sub-123',
      resourceGroup: 'my-rg',
      serviceName: 'my-apim',
    });

    expect(result).toHaveLength(1);
    expect(result[0].displayName).toBe('Petstore API');
    expect(result[0].spec.paths).toHaveProperty('/pets');
    expect(result[0].spec['x-azure-apim-service']).toBe('my-apim');

    mockFetch.mockRestore();
  });

  it('should create minimal spec with warning when export fails', async () => {
    const apis = [{
      name: 'broken-api',
      displayName: 'Broken API',
      path: 'broken',
      isCurrent: true,
      protocols: ['https'],
    }];
    mockAzureApiList.mockReturnValue((async function* () {
      for (const api of apis) yield api;
    })());

    mockAzureApiExportGet.mockResolvedValue({
      value: { link: 'https://storage.blob.core.windows.net/export/broken.json' }
    });

    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: false,
      status: 404,
      statusText: 'Not Found',
    } as Response);

    const result = await discoverAzureApis({
      subscriptionId: 'sub-123',
      resourceGroup: 'my-rg',
      serviceName: 'my-apim',
    });

    expect(result).toHaveLength(1);
    expect(result[0].spec.info?.description).toContain('Warning: Full spec export failed');
    expect(result[0].spec.info?.description).toContain('HTTP 404 Not Found');
    expect(result[0].spec['x-apivet-export-warning']).toBeTruthy();

    mockFetch.mockRestore();
  });

  it('should return empty results when no APIM APIs found', async () => {
    mockAzureApiList.mockReturnValue((async function* () {
      // empty
    })());

    const result = await discoverAzureApis({
      subscriptionId: 'sub-123',
      resourceGroup: 'my-rg',
      serviceName: 'my-apim',
    });

    expect(result).toHaveLength(0);
  });

  it('should throw when subscription ID is missing', async () => {
    delete process.env.AZURE_SUBSCRIPTION_ID;

    await expect(discoverAzureApis({})).rejects.toThrow('Azure subscription ID not provided');
  });

  it('should fetch and parse APIM policies', async () => {
    const apis = [{
      name: 'secure-api',
      displayName: 'Secure API',
      path: 'secure',
      serviceUrl: 'https://backend.com',
      isCurrent: true,
      protocols: ['https'],
    }];
    mockAzureApiList.mockReturnValue((async function* () {
      for (const api of apis) yield api;
    })());

    const exportedSpec = {
      openapi: '3.0.3',
      info: { title: 'Secure API', version: '1.0.0' },
      paths: { '/data': { get: { responses: { '200': { description: 'OK' } } } } },
    };
    mockAzureApiExportGet.mockResolvedValue({
      value: { link: 'https://storage.blob.core.windows.net/export/spec.json' }
    });

    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => exportedSpec,
    } as Response);

    // Mock global policy with validate-jwt and rate limiting
    mockAzureGlobalPolicyGet.mockResolvedValue({
      value: `<policies>
        <inbound>
          <validate-jwt header-name="Authorization">
            <audiences><audience>api://my-app</audience></audiences>
            <issuers><issuer>https://sts.windows.net/tenant/</issuer></issuers>
          </validate-jwt>
          <rate-limit calls="100" renewal-period="60" />
        </inbound>
      </policies>`
    });

    // Mock API policy with CORS
    mockAzureApiPolicyGet.mockResolvedValue({
      value: `<policies>
        <inbound>
          <cors>
            <allowed-origins>
              <origin>https://portal.example.com</origin>
            </allowed-origins>
          </cors>
        </inbound>
      </policies>`
    });

    const result = await discoverAzureApis({
      subscriptionId: 'sub-123',
      resourceGroup: 'my-rg',
      serviceName: 'my-apim',
    });

    expect(result).toHaveLength(1);

    // Check global policy was parsed
    expect(result[0].globalPolicy).toBeDefined();
    expect(result[0].globalPolicy?.hasValidateJwt).toBe(true);
    expect(result[0].globalPolicy?.hasRateLimit).toBe(true);
    expect(result[0].globalPolicy?.jwtValidation?.hasAudiences).toBe(true);
    expect(result[0].globalPolicy?.jwtValidation?.hasIssuers).toBe(true);
    expect(result[0].globalPolicy?.rateLimitConfig?.callsPerPeriod).toBe(100);

    // Check API policy was parsed
    expect(result[0].apiPolicy).toBeDefined();
    expect(result[0].apiPolicy?.hasCors).toBe(true);
    expect(result[0].apiPolicy?.corsAllowAll).toBe(false);
    expect(result[0].apiPolicy?.corsConfig?.allowedOrigins).toEqual(['https://portal.example.com']);

    // Check policy metadata embedded in spec
    const policyMeta = (result[0].spec as Record<string, unknown>)['x-azure-apim-policies'] as Record<string, unknown>;
    expect(policyMeta).toBeDefined();
    expect(policyMeta.global).toBeDefined();
    expect(policyMeta.api).toBeDefined();

    mockFetch.mockRestore();
  });

  it('should handle missing policies gracefully', async () => {
    const apis = [{
      name: 'basic-api',
      displayName: 'Basic API',
      path: 'basic',
      isCurrent: true,
      protocols: ['https'],
    }];
    mockAzureApiList.mockReturnValue((async function* () {
      for (const api of apis) yield api;
    })());

    mockAzureApiExportGet.mockResolvedValue({
      value: { link: 'https://storage.blob.core.windows.net/export/spec.json' }
    });

    const mockFetch = vi.spyOn(globalThis, 'fetch').mockResolvedValue({
      ok: true,
      json: async () => ({
        openapi: '3.0.3',
        info: { title: 'Basic', version: '1.0.0' },
        paths: {},
      }),
    } as Response);

    // Both policies fail (not found)
    mockAzureGlobalPolicyGet.mockRejectedValue(new Error('Not found'));
    mockAzureApiPolicyGet.mockRejectedValue(new Error('Not found'));

    const result = await discoverAzureApis({
      subscriptionId: 'sub-123',
      resourceGroup: 'my-rg',
      serviceName: 'my-apim',
    });

    expect(result).toHaveLength(1);
    expect(result[0].globalPolicy).toBeUndefined();
    expect(result[0].apiPolicy).toBeUndefined();

    // No policy metadata in spec
    const policyMeta = (result[0].spec as Record<string, unknown>)['x-azure-apim-policies'];
    expect(policyMeta).toBeUndefined();

    mockFetch.mockRestore();
  });
});

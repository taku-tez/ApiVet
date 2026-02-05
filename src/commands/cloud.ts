/**
 * Cloud API Gateway Scanning Commands
 * AWS, Azure, and GCP support
 */

import { discoverAwsApis } from '../cloud/aws.js';
import { discoverGcpApis } from '../cloud/gcp.js';
import { discoverAzureApis } from '../cloud/azure.js';
import {
  validateSeverity,
  parseRuleFilters,
  scanAndConvert,
  outputResults,
  handleCloudError,
  type CloudCommandOptions,
  type CloudApi
} from './cloud-utils.js';

// ============================================
// AWS API Gateway Command
// ============================================

interface CloudAwsCommandOptions extends CloudCommandOptions {
  region?: string;
  apiId?: string;
}

export async function cloudAwsCommand(options: CloudAwsCommandOptions): Promise<void> {
  const { region, apiId, json, output, severity, onlyRules, excludeRules } = options;

  validateSeverity(severity);
  const { onlyRuleIds, excludeRuleIds } = parseRuleFilters(onlyRules, excludeRules);

  console.log(`Discovering AWS API Gateway APIs${region ? ` in ${region}` : ''}...`);

  try {
    const rawApis = await discoverAwsApis({ region, apiId });

    if (rawApis.length === 0) {
      console.log('No API Gateway APIs found.');
      process.exit(0);
    }

    console.log(`Found ${rawApis.length} API(s). Scanning...`);

    // Convert to CloudApi format
    const apis: CloudApi[] = rawApis.map(api => ({
      id: api.id,
      name: api.name,
      displayName: api.name,
      type: api.type,
      endpoint: api.endpoint,
      spec: api.spec
    }));

    const results = scanAndConvert(apis, 'aws-apigateway', {
      severity,
      onlyRuleIds,
      excludeRuleIds
    });

    outputResults(results, apis, 'aws-apigateway', 'AWS API Gateway', { json, output });
  } catch (error) {
    handleCloudError(error, 'aws');
  }
}

// ============================================
// GCP API Gateway Command
// ============================================

interface CloudGcpCommandOptions extends CloudCommandOptions {
  project?: string;
  location?: string;
  gatewayId?: string;
}

export async function cloudGcpCommand(options: CloudGcpCommandOptions): Promise<void> {
  const { project, location, gatewayId, json, output, severity, onlyRules, excludeRules } = options;

  validateSeverity(severity);
  const { onlyRuleIds, excludeRuleIds } = parseRuleFilters(onlyRules, excludeRules);

  const projectId = project || process.env.GOOGLE_CLOUD_PROJECT || process.env.GCLOUD_PROJECT;
  console.log(`Discovering GCP API Gateway APIs${projectId ? ` in project ${projectId}` : ''}...`);

  try {
    const rawApis = await discoverGcpApis({ project, location, gatewayId });

    if (rawApis.length === 0) {
      console.log('No API Gateway APIs found.');
      process.exit(0);
    }

    console.log(`Found ${rawApis.length} API(s). Scanning...`);

    // Convert to CloudApi format
    const apis: CloudApi[] = rawApis.map(api => ({
      id: api.id,
      name: api.id,
      displayName: api.displayName,
      type: 'Gateway',
      endpoint: api.endpoint,
      state: api.state,
      spec: api.spec
    }));

    const results = scanAndConvert(apis, 'gcp-apigateway', {
      severity,
      onlyRuleIds,
      excludeRuleIds
    });

    outputResults(results, apis, 'gcp-apigateway', 'GCP API Gateway', { json, output });
  } catch (error) {
    handleCloudError(error, 'gcp');
  }
}

// ============================================
// Azure API Management Command
// ============================================

interface CloudAzureCommandOptions extends CloudCommandOptions {
  subscriptionId?: string;
  resourceGroup?: string;
  serviceName?: string;
  apiId?: string;
}

export async function cloudAzureCommand(options: CloudAzureCommandOptions): Promise<void> {
  const { subscriptionId, resourceGroup, serviceName, apiId, json, output, severity, onlyRules, excludeRules } = options;

  validateSeverity(severity);
  const { onlyRuleIds, excludeRuleIds } = parseRuleFilters(onlyRules, excludeRules);

  const subId = subscriptionId || process.env.AZURE_SUBSCRIPTION_ID;
  console.log(`Discovering Azure API Management APIs${subId ? ` in subscription ${subId.substring(0, 8)}...` : ''}...`);

  try {
    const rawApis = await discoverAzureApis({ subscriptionId, resourceGroup, serviceName, apiId });

    if (rawApis.length === 0) {
      console.log('No APIs found.');
      process.exit(0);
    }

    console.log(`Found ${rawApis.length} API(s). Scanning...`);

    // Convert to CloudApi format
    const apis: CloudApi[] = rawApis.map(api => ({
      id: api.id,
      name: api.name,
      displayName: api.displayName,
      type: 'APIM',
      path: api.path,
      state: api.state,
      protocols: api.protocols,
      serviceUrl: api.serviceUrl,
      spec: api.spec
    }));

    const results = scanAndConvert(apis, 'azure-apim', {
      severity,
      onlyRuleIds,
      excludeRuleIds
    });

    outputResults(results, apis, 'azure-apim', 'Azure API Management', { json, output });
  } catch (error) {
    handleCloudError(error, 'azure');
  }
}

/**
 * Cloud Command Utilities
 * Shared logic for AWS, Azure, and GCP cloud scanning commands
 */

import * as fs from 'node:fs';
import { runRules } from '../rules/index.js';
import { formatScanResultsJson } from '../formatter.js';
import type { ScanResult } from '../scanner/index.js';
import type { Finding, Severity, OpenApiSpec } from '../types.js';

// ============================================
// Common Types
// ============================================

export interface CloudCommandOptions {
  json?: boolean;
  output?: string;
  severity?: string;
  onlyRules?: string;
  excludeRules?: string;
}

export interface CloudApi {
  id: string;
  name: string;
  displayName?: string;
  type?: string;
  endpoint?: string;
  state?: string;
  path?: string;
  protocols?: string[];
  serviceUrl?: string;
  spec: OpenApiSpec;
}

// ============================================
// Validation
// ============================================

const VALID_SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

export function validateSeverity(severity?: string): void {
  if (severity && !VALID_SEVERITIES.includes(severity)) {
    console.error(`Error: Invalid severity. Must be one of: ${VALID_SEVERITIES.join(', ')}`);
    process.exit(2);
  }
}

export function parseRuleFilters(onlyRules?: string, excludeRules?: string): {
  onlyRuleIds?: string[];
  excludeRuleIds?: string[];
} {
  return {
    onlyRuleIds: onlyRules ? onlyRules.split(',').map(r => r.trim().toUpperCase()) : undefined,
    excludeRuleIds: excludeRules ? excludeRules.split(',').map(r => r.trim().toUpperCase()) : undefined
  };
}

// ============================================
// Finding Filtering
// ============================================

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0
};

export function filterFindings(
  findings: Finding[],
  options: {
    severity?: string;
    onlyRuleIds?: string[];
    excludeRuleIds?: string[];
  }
): Finding[] {
  const { severity, onlyRuleIds, excludeRuleIds } = options;
  let filtered = findings;

  // Filter by rule IDs
  if (onlyRuleIds || excludeRuleIds) {
    filtered = filtered.filter(f => {
      const ruleId = f.ruleId.toUpperCase();
      if (onlyRuleIds && !onlyRuleIds.some(id => ruleId.startsWith(id))) {
        return false;
      }
      if (excludeRuleIds && excludeRuleIds.some(id => ruleId.startsWith(id))) {
        return false;
      }
      return true;
    });
  }

  // Filter by severity
  if (severity) {
    const minSeverity = SEVERITY_ORDER[severity as Severity];
    filtered = filtered.filter(f => SEVERITY_ORDER[f.severity] >= minSeverity);
  }

  return filtered;
}

// ============================================
// Scan and Convert
// ============================================

export function scanAndConvert(
  apis: CloudApi[],
  provider: string,
  filterOptions: {
    severity?: string;
    onlyRuleIds?: string[];
    excludeRuleIds?: string[];
  }
): ScanResult[] {
  const results: ScanResult[] = [];

  for (const api of apis) {
    const findings = runRules(api.spec, `${provider}://${api.id}`);
    const filteredFindings = filterFindings(findings, filterOptions);

    results.push({
      file: api.displayName 
        ? `${api.type || provider} API: ${api.displayName} (${api.id})`
        : `${api.type || provider} API: ${api.name} (${api.id})`,
      spec: {
        title: api.spec.info?.title || api.displayName || api.name,
        version: api.spec.info?.version || '1.0.0',
        openApiVersion: '3.0.3'
      },
      findings: filteredFindings
    });
  }

  return results;
}

// ============================================
// Output Formatting
// ============================================

const SEVERITY_ICONS: Record<Severity, string> = {
  critical: '🔴',
  high: '🟠',
  medium: '🟡',
  low: '🔵',
  info: '⚪'
};

export function formatCloudResults(
  results: ScanResult[],
  apis: CloudApi[],
  provider: string,
  providerTitle: string
): string {
  const lines: string[] = [];
  
  lines.push('═'.repeat(60));
  lines.push(`${providerTitle} Security Scan Results`);
  lines.push('═'.repeat(60));
  lines.push('');

  let totalFindings = 0;
  const counts: Record<Severity, number> = {
    critical: 0, high: 0, medium: 0, low: 0, info: 0
  };

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const api = apis[i];
    
    // API Header
    lines.push(`📡 ${api.type || 'API'}: ${api.displayName || api.name}`);
    lines.push(`   ID: ${api.id}`);
    
    if (api.path) lines.push(`   Path: /${api.path}`);
    if (api.state) lines.push(`   State: ${api.state}`);
    if (api.endpoint) lines.push(`   Endpoint: ${api.endpoint}`);
    if (api.protocols?.length) lines.push(`   Protocols: ${api.protocols.join(', ')}`);
    if (api.serviceUrl) lines.push(`   Backend: ${api.serviceUrl}`);
    
    lines.push(`   Paths: ${Object.keys(api.spec.paths || {}).length}`);

    // Show policy status for Azure APIM
    const policyData = (api.spec as Record<string, unknown>)['x-azure-apim-policies'] as Record<string, unknown> | undefined;
    if (policyData) {
      const policyItems: string[] = [];
      const globalP = policyData.global as Record<string, unknown> | undefined;
      const apiP = policyData.api as Record<string, unknown> | undefined;
      const hasJwt = globalP?.hasValidateJwt || apiP?.hasValidateJwt;
      const hasRate = globalP?.hasRateLimit || apiP?.hasRateLimit;
      const hasIp = globalP?.hasIpFilter || apiP?.hasIpFilter;
      const hasCors = globalP?.hasCors || apiP?.hasCors;
      if (hasJwt) policyItems.push('JWT✓');
      if (hasRate) policyItems.push('RateLimit✓');
      if (hasIp) policyItems.push('IPFilter✓');
      if (hasCors) policyItems.push('CORS✓');
      if (policyItems.length > 0) {
        lines.push(`   📋 Policies: ${policyItems.join(', ')}`);
      } else {
        lines.push(`   📋 Policies: (no security policies detected)`);
      }
    }
    lines.push('');

    if (result.findings.length === 0) {
      lines.push('   ✅ No security issues found');
    } else {
      lines.push(`   ⚠️  ${result.findings.length} issue(s) found:`);
      lines.push('');
      
      for (const finding of result.findings) {
        totalFindings++;
        counts[finding.severity]++;

        lines.push(`   ${SEVERITY_ICONS[finding.severity]} [${finding.ruleId}] ${finding.title}`);
        lines.push(`      ${finding.description}`);
        if (finding.location?.endpoint) {
          lines.push(`      Path: ${finding.location.endpoint}`);
        }
        lines.push('');
      }
    }
    
    lines.push('─'.repeat(60));
    lines.push('');
  }

  // Summary
  lines.push('Summary');
  lines.push('═'.repeat(60));
  lines.push(`APIs Scanned: ${apis.length}`);
  lines.push(`Total Findings: ${totalFindings}`);
  if (totalFindings > 0) {
    lines.push(`  🔴 Critical: ${counts.critical}`);
    lines.push(`  🟠 High: ${counts.high}`);
    lines.push(`  🟡 Medium: ${counts.medium}`);
    lines.push(`  🔵 Low: ${counts.low}`);
    lines.push(`  ⚪ Info: ${counts.info}`);
  }

  return lines.join('\n');
}

// ============================================
// Output and Exit
// ============================================

export function outputResults(
  results: ScanResult[],
  apis: CloudApi[],
  provider: string,
  providerTitle: string,
  options: { json?: boolean; output?: string }
): void {
  const { json, output } = options;

  const formattedOutput = json
    ? formatScanResultsJson(results)
    : formatCloudResults(results, apis, provider, providerTitle);

  if (output) {
    fs.writeFileSync(output, formattedOutput);
    console.log(`Results written to: ${output}`);
  } else {
    console.log(formattedOutput);
  }

  // Exit code based on findings
  const hasFindings = results.some(r => r.findings.length > 0);
  process.exit(hasFindings ? 1 : 0);
}

// ============================================
// Error Handling
// ============================================

export function handleCloudError(error: unknown, provider: 'aws' | 'gcp' | 'azure'): never {
  if (!(error instanceof Error)) {
    console.error('Error:', error);
    process.exit(2);
  }

  const message = error.message;

  // AWS errors
  if (provider === 'aws') {
    if (message.includes('Could not load credentials') || message.includes('missing credentials')) {
      console.error('Error: AWS credentials not found.');
      console.error('Configure credentials using one of:');
      console.error('  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY');
      console.error('  - AWS credentials file: ~/.aws/credentials');
      console.error('  - IAM role (when running on AWS)');
      process.exit(2);
    }
  }

  // GCP errors
  if (provider === 'gcp') {
    if (message.includes('Could not load the default credentials') || message.includes('GOOGLE_APPLICATION_CREDENTIALS')) {
      console.error('Error: GCP credentials not found.');
      console.error('Configure credentials using one of:');
      console.error('  - Environment variable: GOOGLE_APPLICATION_CREDENTIALS');
      console.error('  - gcloud CLI: gcloud auth application-default login');
      console.error('  - Service account (when running on GCP)');
      process.exit(2);
    }
    if (message.includes('project')) {
      console.error('Error: GCP project not specified.');
      console.error('Use --project or set GOOGLE_CLOUD_PROJECT environment variable.');
      process.exit(2);
    }
  }

  // Azure errors
  if (provider === 'azure') {
    if (message.includes('DefaultAzureCredential') || message.includes('authentication') || message.includes('AZURE_')) {
      console.error('Error: Azure credentials not found.');
      console.error('Configure credentials using one of:');
      console.error('  - Environment variables: AZURE_CLIENT_ID, AZURE_TENANT_ID, AZURE_CLIENT_SECRET');
      console.error('  - Azure CLI: az login');
      console.error('  - Managed Identity (when running on Azure)');
      process.exit(2);
    }
    if (message.includes('subscription')) {
      console.error('Error: Azure subscription ID not specified.');
      console.error('Use --subscription-id or set AZURE_SUBSCRIPTION_ID environment variable.');
      process.exit(2);
    }
  }

  // Generic error
  console.error('Error:', message);
  process.exit(2);
}

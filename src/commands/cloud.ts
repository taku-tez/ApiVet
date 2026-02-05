import * as fs from 'node:fs';
import { discoverAwsApis, type DiscoveredApi } from '../cloud/aws.js';
import { runRules } from '../rules/index.js';
import { formatScanResults, formatScanResultsJson } from '../formatter.js';
import type { ScanResult } from '../scanner/index.js';
import type { Severity } from '../types.js';

interface CloudAwsCommandOptions {
  region?: string;
  apiId?: string;
  json?: boolean;
  output?: string;
  severity?: string;
  onlyRules?: string;
  excludeRules?: string;
}

export async function cloudAwsCommand(
  options: CloudAwsCommandOptions
): Promise<void> {
  const { region, apiId, json, output, severity, onlyRules, excludeRules } = options;

  // Validate severity
  const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
  if (severity && !validSeverities.includes(severity)) {
    console.error(`Error: Invalid severity. Must be one of: ${validSeverities.join(', ')}`);
    process.exit(2);
  }

  // Parse rule filters
  const onlyRuleIds = onlyRules ? onlyRules.split(',').map(r => r.trim().toUpperCase()) : undefined;
  const excludeRuleIds = excludeRules ? excludeRules.split(',').map(r => r.trim().toUpperCase()) : undefined;

  console.log(`Discovering AWS API Gateway APIs${region ? ` in ${region}` : ''}...`);

  try {
    const apis = await discoverAwsApis({ region, apiId });

    if (apis.length === 0) {
      console.log('No API Gateway APIs found.');
      process.exit(0);
    }

    console.log(`Found ${apis.length} API(s). Scanning...`);

    // Convert to ScanResults
    const results: ScanResult[] = [];

    for (const api of apis) {
      let findings = runRules(api.spec, `aws-apigateway://${api.id}`);

      // Filter rules if specified
      if (onlyRuleIds || excludeRuleIds) {
        findings = findings.filter(f => {
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
        const severityOrder: Record<Severity, number> = {
          critical: 4,
          high: 3,
          medium: 2,
          low: 1,
          info: 0
        };
        const minSeverity = severityOrder[severity as Severity];
        findings = findings.filter(f => severityOrder[f.severity] >= minSeverity);
      }

      results.push({
        file: `${api.type} API: ${api.name} (${api.id})`,
        spec: {
          title: api.spec.info?.title || api.name,
          version: api.spec.info?.version || '1.0.0',
          openApiVersion: '3.0.3'
        },
        findings
      });
    }

    // Format output
    const formattedOutput = json
      ? formatScanResultsJson(results)
      : formatCloudResults(results, apis);

    // Write to file or stdout
    if (output) {
      fs.writeFileSync(output, formattedOutput);
      console.log(`Results written to: ${output}`);
    } else {
      console.log(formattedOutput);
    }

    // Exit code
    const hasFindings = results.some(r => r.findings.length > 0);
    process.exit(hasFindings ? 1 : 0);

  } catch (error) {
    if (error instanceof Error) {
      if (error.message.includes('Could not load credentials') ||
          error.message.includes('missing credentials')) {
        console.error('Error: AWS credentials not found.');
        console.error('Configure credentials using one of:');
        console.error('  - Environment variables: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY');
        console.error('  - AWS credentials file: ~/.aws/credentials');
        console.error('  - IAM role (when running on AWS)');
      } else {
        console.error('Error:', error.message);
      }
    } else {
      console.error('Error:', error);
    }
    process.exit(2);
  }
}

/**
 * Format cloud scan results with API metadata
 */
function formatCloudResults(results: ScanResult[], apis: DiscoveredApi[]): string {
  const lines: string[] = [];
  
  lines.push('═'.repeat(60));
  lines.push('AWS API Gateway Security Scan Results');
  lines.push('═'.repeat(60));
  lines.push('');

  let totalFindings = 0;
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;
  let lowCount = 0;
  let infoCount = 0;

  for (let i = 0; i < results.length; i++) {
    const result = results[i];
    const api = apis[i];
    
    lines.push(`📡 ${api.type} API: ${api.name}`);
    lines.push(`   ID: ${api.id}`);
    if (api.endpoint) {
      lines.push(`   Endpoint: ${api.endpoint}`);
    }
    lines.push(`   Paths: ${Object.keys(api.spec.paths || {}).length}`);
    lines.push('');

    if (result.findings.length === 0) {
      lines.push('   ✅ No security issues found');
    } else {
      lines.push(`   ⚠️  ${result.findings.length} issue(s) found:`);
      lines.push('');
      
      for (const finding of result.findings) {
        totalFindings++;
        const severityIcon = {
          critical: '🔴',
          high: '🟠',
          medium: '🟡',
          low: '🔵',
          info: '⚪'
        }[finding.severity];

        switch (finding.severity) {
          case 'critical': criticalCount++; break;
          case 'high': highCount++; break;
          case 'medium': mediumCount++; break;
          case 'low': lowCount++; break;
          case 'info': infoCount++; break;
        }

        lines.push(`   ${severityIcon} [${finding.ruleId}] ${finding.title}`);
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
    lines.push(`  🔴 Critical: ${criticalCount}`);
    lines.push(`  🟠 High: ${highCount}`);
    lines.push(`  🟡 Medium: ${mediumCount}`);
    lines.push(`  🔵 Low: ${lowCount}`);
    lines.push(`  ⚪ Info: ${infoCount}`);
  }

  return lines.join('\n');
}

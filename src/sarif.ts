/**
 * SARIF (Static Analysis Results Interchange Format) Output
 * For GitHub Code Scanning and other SARIF-compatible tools
 * 
 * SARIF 2.1.0 specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */

import type { Finding, Severity } from './types.js';

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
  invocations?: Array<{
    executionSuccessful: boolean;
    endTimeUtc?: string;
  }>;
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription?: { text: string };
  helpUri?: string;
  help?: { text: string; markdown?: string };
  defaultConfiguration: {
    level: 'none' | 'note' | 'warning' | 'error';
  };
  properties?: {
    tags?: string[];
    precision?: string;
    'security-severity'?: string;
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: 'none' | 'note' | 'warning' | 'error';
  message: { text: string };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId?: string;
      };
      region?: {
        startLine?: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
    logicalLocations?: Array<{
      name?: string;
      kind?: string;
    }>;
  }>;
  fixes?: Array<{
    description: { text: string };
  }>;
  properties?: Record<string, unknown>;
}

interface SarifOutput {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

/**
 * Map ApiVet severity to SARIF level
 */
function severityToLevel(severity: Severity): 'none' | 'note' | 'warning' | 'error' {
  switch (severity) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'note';
  }
}

/**
 * Map severity to security-severity score (0.0 - 10.0)
 * Used by GitHub to prioritize security alerts
 */
function severityToScore(severity: Severity): string {
  switch (severity) {
    case 'critical':
      return '9.0';
    case 'high':
      return '7.0';
    case 'medium':
      return '5.0';
    case 'low':
      return '3.0';
    case 'info':
      return '1.0';
    default:
      return '1.0';
  }
}

/**
 * Convert findings to SARIF rules
 */
function findingsToRules(findings: Finding[]): SarifRule[] {
  const rulesMap = new Map<string, SarifRule>();

  for (const finding of findings) {
    if (rulesMap.has(finding.ruleId)) continue;

    const tags: string[] = ['security'];
    if (finding.owaspCategory) {
      tags.push(`owasp-api-${finding.owaspCategory.toLowerCase().replace(':', '-')}`);
    }

    rulesMap.set(finding.ruleId, {
      id: finding.ruleId,
      name: finding.title,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description },
      helpUri: `https://github.com/taku-tez/ApiVet#${finding.ruleId.toLowerCase()}`,
      help: finding.remediation
        ? {
            text: finding.remediation,
            markdown: `**Remediation:** ${finding.remediation}`
          }
        : undefined,
      defaultConfiguration: {
        level: severityToLevel(finding.severity)
      },
      properties: {
        tags,
        precision: 'high',
        'security-severity': severityToScore(finding.severity)
      }
    });
  }

  return Array.from(rulesMap.values());
}

/**
 * Convert findings to SARIF results
 */
function findingsToResults(findings: Finding[], rules: SarifRule[]): SarifResult[] {
  const ruleIdToIndex = new Map<string, number>();
  rules.forEach((rule, index) => ruleIdToIndex.set(rule.id, index));

  return findings.map(finding => {
    const result: SarifResult = {
      ruleId: finding.ruleId,
      ruleIndex: ruleIdToIndex.get(finding.ruleId),
      level: severityToLevel(finding.severity),
      message: { text: finding.description }
    };

    // Add location if available
    if (finding.location?.path) {
      result.locations = [{
        physicalLocation: {
          artifactLocation: {
            uri: finding.location.path,
            uriBaseId: '%SRCROOT%'
          },
          region: finding.location.line
            ? {
                startLine: finding.location.line,
                startColumn: 1
              }
            : undefined
        },
        logicalLocations: finding.location.endpoint
          ? [{
              name: `${finding.location.method || 'ANY'} ${finding.location.endpoint}`,
              kind: 'endpoint'
            }]
          : undefined
      }];
    }

    // Add fix suggestion if remediation is available
    if (finding.remediation) {
      result.fixes = [{
        description: { text: finding.remediation }
      }];
    }

    // Add OWASP category as property
    if (finding.owaspCategory) {
      result.properties = {
        owaspCategory: finding.owaspCategory
      };
    }

    return result;
  });
}

/**
 * Generate SARIF output from findings
 */
export function generateSarif(
  findings: Finding[],
  version: string = '0.5.0'
): SarifOutput {
  const rules = findingsToRules(findings);
  const results = findingsToResults(findings, rules);

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'ApiVet',
          version,
          informationUri: 'https://github.com/taku-tez/ApiVet',
          rules
        }
      },
      results,
      invocations: [{
        executionSuccessful: true,
        endTimeUtc: new Date().toISOString()
      }]
    }]
  };
}

/**
 * Format SARIF output as JSON string
 */
export function formatSarif(findings: Finding[], version?: string): string {
  const sarif = generateSarif(findings, version);
  return JSON.stringify(sarif, null, 2);
}

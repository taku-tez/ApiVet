import type { ScanResult } from './scanner/index.js';
import type { CheckResult } from './checker/index.js';
import type { Endpoint } from './inventory/index.js';
import type { Finding, Severity } from './types.js';

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: '\x1b[91m', // Bright red
  high: '\x1b[31m',     // Red
  medium: '\x1b[33m',   // Yellow
  low: '\x1b[36m',      // Cyan
  info: '\x1b[90m'      // Gray
};

const RESET = '\x1b[0m';
const BOLD = '\x1b[1m';

function colorize(text: string, severity: Severity): string {
  return `${SEVERITY_COLORS[severity]}${text}${RESET}`;
}

function formatFinding(finding: Finding, index: number): string {
  const lines: string[] = [];
  
  const severityBadge = colorize(`[${finding.severity.toUpperCase()}]`, finding.severity);
  lines.push(`  ${index}. ${severityBadge} ${BOLD}${finding.title}${RESET}`);
  lines.push(`     Rule: ${finding.ruleId}`);
  
  if (finding.owaspCategory) {
    lines.push(`     OWASP: ${finding.owaspCategory}`);
  }
  
  if (finding.location) {
    const loc = finding.location;
    if (loc.endpoint && loc.method) {
      lines.push(`     Location: ${loc.method} ${loc.endpoint}`);
    }
    if (loc.path && loc.line) {
      lines.push(`     File: ${loc.path}:${loc.line}`);
    } else if (loc.path) {
      lines.push(`     File: ${loc.path}`);
    }
  }
  
  lines.push(`     ${finding.description}`);
  
  if (finding.remediation) {
    lines.push(`     💡 ${finding.remediation}`);
  }
  
  lines.push('');
  
  return lines.join('\n');
}

export function formatScanResults(results: ScanResult[]): string {
  const lines: string[] = [];
  
  lines.push('');
  lines.push(`${BOLD}ApiVet Scan Results${RESET}`);
  lines.push('═'.repeat(50));
  lines.push('');
  
  let totalFindings = 0;
  const severityCounts: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0
  };
  
  for (const result of results) {
    if (result.error) {
      lines.push(`${BOLD}📁 ${result.file}${RESET}`);
      lines.push(`   ❌ Error: ${result.error}`);
      lines.push('');
      continue;
    }
    
    if (!result.spec) continue;
    
    lines.push(`${BOLD}📁 ${result.file}${RESET}`);
    lines.push(`   API: ${result.spec.title} v${result.spec.version} (OpenAPI ${result.spec.openApiVersion})`);
    
    if (result.findings.length === 0) {
      lines.push(`   ✅ No issues found`);
    } else {
      lines.push(`   Found ${result.findings.length} issue(s):`);
      lines.push('');
      
      result.findings.forEach((finding, i) => {
        lines.push(formatFinding(finding, i + 1));
        totalFindings++;
        severityCounts[finding.severity]++;
      });
    }
    
    lines.push('');
  }
  
  // Summary
  lines.push('─'.repeat(50));
  lines.push(`${BOLD}Summary${RESET}`);
  lines.push(`  Files scanned: ${results.length}`);
  lines.push(`  Total findings: ${totalFindings}`);
  
  if (totalFindings > 0) {
    const counts = Object.entries(severityCounts)
      .filter(([_, count]) => count > 0)
      .map(([sev, count]) => colorize(`${count} ${sev}`, sev as Severity))
      .join(', ');
    lines.push(`  By severity: ${counts}`);
  }
  
  lines.push('');
  
  return lines.join('\n');
}

export function formatScanResultsJson(results: ScanResult[]): string {
  return JSON.stringify(results, null, 2);
}

export function formatCheckResult(result: CheckResult): string {
  const lines: string[] = [];
  
  lines.push('');
  lines.push(`${BOLD}ApiVet Live Check${RESET}`);
  lines.push('═'.repeat(50));
  lines.push('');
  
  lines.push(`${BOLD}URL:${RESET} ${result.url}`);
  
  if (result.status === 'error') {
    lines.push(`${BOLD}Status:${RESET} ❌ Error - ${result.error}`);
  } else {
    lines.push(`${BOLD}Status:${RESET} ${result.statusCode} (${result.responseTime}ms)`);
    
    if (result.headers) {
      lines.push('');
      lines.push(`${BOLD}Security Headers:${RESET}`);
      
      const securityHeaders = [
        'strict-transport-security',
        'x-content-type-options',
        'x-frame-options',
        'content-security-policy',
        'x-xss-protection',
        'cache-control',
        'access-control-allow-origin'
      ];
      
      for (const header of securityHeaders) {
        const value = result.headers[header];
        if (value) {
          lines.push(`  ✓ ${header}: ${value.substring(0, 60)}${value.length > 60 ? '...' : ''}`);
        }
      }
    }
    
    if (result.findings.length > 0) {
      lines.push('');
      lines.push(`${BOLD}Findings (${result.findings.length}):${RESET}`);
      lines.push('');
      
      result.findings.forEach((finding, i) => {
        lines.push(formatFinding(finding, i + 1));
      });
    } else {
      lines.push('');
      lines.push('✅ No security issues detected');
    }
  }
  
  lines.push('');
  
  return lines.join('\n');
}

export function formatCheckResultJson(result: CheckResult): string {
  return JSON.stringify(result, null, 2);
}

export function formatInventory(endpoints: Endpoint[]): string {
  const lines: string[] = [];
  
  lines.push('');
  lines.push(`${BOLD}ApiVet Endpoint Inventory${RESET}`);
  lines.push('═'.repeat(50));
  lines.push('');
  
  if (endpoints.length === 0) {
    lines.push('No endpoints discovered.');
    lines.push('');
    return lines.join('\n');
  }
  
  // Group by file
  const byFile = new Map<string, Endpoint[]>();
  for (const ep of endpoints) {
    const existing = byFile.get(ep.file) || [];
    existing.push(ep);
    byFile.set(ep.file, existing);
  }
  
  for (const [file, eps] of byFile) {
    lines.push(`${BOLD}📁 ${file}${RESET}`);
    
    // Sort by path, then method
    eps.sort((a, b) => {
      const pathCompare = a.path.localeCompare(b.path);
      if (pathCompare !== 0) return pathCompare;
      return a.method.localeCompare(b.method);
    });
    
    for (const ep of eps) {
      const methodColor = {
        GET: '\x1b[32m',
        POST: '\x1b[33m',
        PUT: '\x1b[34m',
        DELETE: '\x1b[31m',
        PATCH: '\x1b[35m'
      }[ep.method] || '\x1b[90m';
      
      const method = `${methodColor}${ep.method.padEnd(7)}${RESET}`;
      const line = ep.line ? `:${ep.line}` : '';
      const framework = ep.framework ? ` (${ep.framework})` : '';
      
      lines.push(`   ${method} ${ep.path}${line}${framework}`);
    }
    
    lines.push('');
  }
  
  // Summary
  lines.push('─'.repeat(50));
  lines.push(`${BOLD}Summary${RESET}`);
  lines.push(`  Files: ${byFile.size}`);
  lines.push(`  Endpoints: ${endpoints.length}`);
  
  // Method counts
  const methodCounts = new Map<string, number>();
  for (const ep of endpoints) {
    methodCounts.set(ep.method, (methodCounts.get(ep.method) || 0) + 1);
  }
  
  const methods = [...methodCounts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([m, c]) => `${m}: ${c}`)
    .join(', ');
  lines.push(`  By method: ${methods}`);
  
  lines.push('');
  
  return lines.join('\n');
}

export function formatInventoryJson(endpoints: Endpoint[]): string {
  return JSON.stringify(endpoints, null, 2);
}

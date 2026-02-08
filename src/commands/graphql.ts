import * as fs from 'node:fs';
import { scanGraphQL } from '../graphql/index.js';
import type { GraphQLScanResult } from '../graphql/index.js';

interface GraphQLCommandOptions {
  endpoint: string;
  timeout?: string;
  auth?: string;
  header?: string[];
  skip?: string;
  json?: boolean;
  output?: string;
}

const BOLD = '\x1b[1m';
const RESET = '\x1b[0m';
const RED = '\x1b[31m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const CYAN = '\x1b[36m';
const GRAY = '\x1b[90m';
const BRIGHT_RED = '\x1b[91m';

function statusIcon(status: string): string {
  switch (status) {
    case 'pass': return `${GREEN}✓${RESET}`;
    case 'fail': return `${RED}✗${RESET}`;
    case 'warn': return `${YELLOW}⚠${RESET}`;
    case 'error': return `${RED}⚡${RESET}`;
    case 'skip': return `${GRAY}⊘${RESET}`;
    default: return '?';
  }
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return BRIGHT_RED;
    case 'high': return RED;
    case 'medium': return YELLOW;
    case 'low': return CYAN;
    default: return GRAY;
  }
}

function formatResult(result: GraphQLScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push(`${BOLD}ApiVet GraphQL Security Scan${RESET}`);
  lines.push('═'.repeat(50));
  lines.push(`${BOLD}Endpoint:${RESET} ${result.endpoint}`);
  lines.push('');

  if (result.status === 'error') {
    lines.push(`${RED}❌ Error: ${result.error}${RESET}`);
    lines.push('');
    return lines.join('\n');
  }

  // Detail results
  for (const detail of result.details) {
    const icon = statusIcon(detail.status);
    let line = `  ${icon} ${BOLD}${detail.check}${RESET}`;
    if (detail.severity) {
      const color = severityColor(detail.severity);
      line += ` ${color}[${detail.severity.toUpperCase()}]${RESET}`;
    }
    lines.push(line);
    lines.push(`     ${detail.message}`);
    lines.push('');
  }

  // Summary
  lines.push('─'.repeat(50));
  lines.push(`${BOLD}Summary${RESET}`);
  const passed = result.details.filter(d => d.status === 'pass').length;
  const failed = result.details.filter(d => d.status === 'fail').length;
  const warned = result.details.filter(d => d.status === 'warn').length;
  const errors = result.details.filter(d => d.status === 'error').length;

  lines.push(`  Checks: ${result.totalChecks}  ${GREEN}Pass: ${passed}${RESET}  ${RED}Fail: ${failed}${RESET}  ${YELLOW}Warn: ${warned}${RESET}  ${GRAY}Error: ${errors}${RESET}`);
  lines.push(`  Findings: ${result.findings.length}`);

  if (result.findings.length > 0) {
    const bySev = result.findings.reduce((acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
    const counts = Object.entries(bySev)
      .map(([s, c]) => `${severityColor(s)}${c} ${s}${RESET}`)
      .join(', ');
    lines.push(`  By severity: ${counts}`);
  }

  lines.push('');
  return lines.join('\n');
}

export async function graphqlCommand(options: GraphQLCommandOptions): Promise<void> {
  const { endpoint, timeout = '10000', auth, header: customHeaders, skip, json, output } = options;

  if (!endpoint) {
    console.error('Error: --endpoint is required');
    process.exit(2);
  }

  // Parse headers
  const headers: Record<string, string> = {};
  if (customHeaders) {
    for (const h of customHeaders) {
      const idx = h.indexOf(':');
      if (idx > 0) {
        headers[h.substring(0, idx).trim()] = h.substring(idx + 1).trim();
      }
    }
  }

  const skipChecks = skip ? skip.split(',').map(s => s.trim()) : undefined;
  const timeoutMs = parseInt(timeout, 10);

  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
    console.error(`Error: Invalid timeout "${timeout}"`);
    process.exit(2);
  }

  try {
    const result = await scanGraphQL(endpoint, {
      timeout: timeoutMs,
      headers,
      authToken: auth,
      skipChecks,
    });

    const formattedOutput = json ? JSON.stringify(result, null, 2) : formatResult(result);

    if (output) {
      fs.writeFileSync(output, formattedOutput);
      console.log(`Results written to ${output}`);
    } else {
      console.log(formattedOutput);
    }

    if (result.status === 'error') {
      process.exit(2);
    } else if (result.findings.length > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (error) {
    console.error('GraphQL scan error:', error instanceof Error ? error.message : error);
    process.exit(2);
  }
}

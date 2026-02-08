import * as fs from 'node:fs';
import * as path from 'node:path';
import YAML from 'yaml';
import { runBolaTests } from '../bola/index.js';
import type { BolaConfig, BolaResult } from '../bola/index.js';
import type { OpenApiSpec, Severity } from '../types.js';

interface BolaCommandOptions {
  spec: string;
  baseUrl: string;
  tokenA: string;
  tokenB: string;
  adminToken?: string;
  authHeader?: string;
  authScheme?: string;
  timeout?: string;
  json?: boolean;
  output?: string;
  dryRun?: boolean;
  verbose?: boolean;
}

function loadSpec(specPath: string): OpenApiSpec {
  const resolved = path.resolve(specPath);
  const content = fs.readFileSync(resolved, 'utf-8');

  if (resolved.endsWith('.json')) {
    return JSON.parse(content) as OpenApiSpec;
  }
  return YAML.parse(content) as OpenApiSpec;
}

export async function bolaCommand(options: BolaCommandOptions): Promise<void> {
  // Validate required options
  if (!options.spec) {
    console.error('Error: --spec is required');
    process.exit(2);
  }
  if (!options.baseUrl) {
    console.error('Error: --base-url is required');
    process.exit(2);
  }
  if (!options.tokenA) {
    console.error('Error: --token-a is required');
    process.exit(2);
  }
  if (!options.tokenB) {
    console.error('Error: --token-b is required');
    process.exit(2);
  }

  let spec: OpenApiSpec;
  try {
    spec = loadSpec(options.spec);
  } catch (err) {
    console.error(`Error loading spec: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  }

  const config: BolaConfig = {
    specPath: options.spec,
    baseUrl: options.baseUrl,
    tokenA: options.tokenA,
    tokenB: options.tokenB,
    adminToken: options.adminToken,
    authHeader: options.authHeader,
    authScheme: options.authScheme,
    timeout: options.timeout ? parseInt(options.timeout, 10) : 10000,
    dryRun: options.dryRun,
    verbose: options.verbose,
  };

  try {
    const result = await runBolaTests(spec, config);
    const formatted = options.json ? formatJson(result) : formatText(result);

    if (options.output) {
      fs.writeFileSync(options.output, formatted);
      console.log(`Results written to ${options.output}`);
    } else {
      console.log(formatted);
    }

    // Exit codes: 0=clean, 1=findings, 2=error
    if (result.findings.length > 0) {
      process.exit(1);
    }
  } catch (err) {
    console.error(`BOLA scan error: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  }
}

function formatJson(result: BolaResult): string {
  return JSON.stringify(result, null, 2);
}

function formatText(result: BolaResult): string {
  const RESET = '\x1b[0m';
  const BOLD = '\x1b[1m';
  const RED = '\x1b[31m';
  const GREEN = '\x1b[32m';
  const YELLOW = '\x1b[33m';
  const CYAN = '\x1b[36m';

  const lines: string[] = [];
  lines.push('');
  lines.push(`${BOLD}🔓 BOLA/IDOR Scan Results${RESET}`);
  lines.push(`${'─'.repeat(60)}`);
  lines.push(`  Endpoints analyzed: ${result.totalEndpoints}`);
  lines.push(`  Test cases run:     ${result.testCases.length}`);
  lines.push('');

  // Summary
  const s = result.summary;
  lines.push(`  ${RED}❌ Vulnerable: ${s.vulnerable}${RESET}`);
  lines.push(`  ${GREEN}✅ Protected:  ${s.protected}${RESET}`);
  if (s.errors > 0) lines.push(`  ${YELLOW}⚠️  Errors:     ${s.errors}${RESET}`);
  if (s.skipped > 0) lines.push(`  ${CYAN}⏭️  Skipped:    ${s.skipped}${RESET}`);
  lines.push('');

  // Findings
  if (result.findings.length > 0) {
    lines.push(`${BOLD}Findings:${RESET}`);
    lines.push('');
    for (const [i, f] of result.findings.entries()) {
      const sevColor = f.severity === 'critical' ? '\x1b[91m' : RED;
      lines.push(`  ${i + 1}. ${sevColor}[${f.severity.toUpperCase()}]${RESET} ${BOLD}${f.title}${RESET}`);
      lines.push(`     ${f.description}`);
      lines.push(`     Rule: ${f.ruleId} | OWASP: ${f.owaspCategory}`);
      lines.push(`     Fix: ${f.remediation}`);
      lines.push('');
    }
  } else {
    lines.push(`  ${GREEN}No BOLA/IDOR vulnerabilities detected.${RESET}`);
    lines.push('');
  }

  return lines.join('\n');
}

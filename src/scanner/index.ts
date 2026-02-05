import * as fs from 'node:fs';
import * as path from 'node:path';
import YAML from 'yaml';
import { glob } from 'glob';
import type { Finding, OpenApiSpec, Severity } from '../types.js';
import { runRules } from '../rules/index.js';

export interface ScanResult {
  file: string;
  spec?: {
    title: string;
    version: string;
    openApiVersion: string;
  };
  findings: Finding[];
  error?: string;
}

export interface ScanOptions {
  recursive?: boolean;
  severity?: Severity;
}

function parseSpec(content: string, filePath: string): OpenApiSpec {
  const ext = path.extname(filePath).toLowerCase();
  
  if (ext === '.json') {
    return JSON.parse(content);
  } else if (ext === '.yaml' || ext === '.yml') {
    return YAML.parse(content);
  }
  
  // Try JSON first, then YAML
  try {
    return JSON.parse(content);
  } catch {
    return YAML.parse(content);
  }
}

function isOpenApiSpec(obj: unknown): obj is OpenApiSpec {
  if (typeof obj !== 'object' || obj === null) return false;
  const spec = obj as Record<string, unknown>;
  return (
    typeof spec.openapi === 'string' ||
    typeof spec.swagger === 'string'
  );
}

export async function scanFile(filePath: string): Promise<ScanResult> {
  const absolutePath = path.resolve(filePath);
  
  try {
    const content = fs.readFileSync(absolutePath, 'utf-8');
    const spec = parseSpec(content, absolutePath);
    
    if (!isOpenApiSpec(spec)) {
      return {
        file: filePath,
        findings: [],
        error: 'Not a valid OpenAPI/Swagger specification'
      };
    }
    
    const findings = runRules(spec, filePath);
    
    return {
      file: filePath,
      spec: {
        title: spec.info?.title || 'Unknown',
        version: spec.info?.version || 'Unknown',
        openApiVersion: spec.openapi || spec.swagger || 'Unknown'
      },
      findings
    };
  } catch (error) {
    return {
      file: filePath,
      findings: [],
      error: error instanceof Error ? error.message : 'Unknown error'
    };
  }
}

export async function scanOpenApiSpec(
  targetPath: string,
  options: ScanOptions = {}
): Promise<ScanResult[]> {
  const { recursive = false, severity } = options;
  const results: ScanResult[] = [];
  
  const stat = fs.statSync(targetPath);
  
  if (stat.isFile()) {
    const result = await scanFile(targetPath);
    results.push(result);
  } else if (stat.isDirectory()) {
    const pattern = recursive 
      ? path.join(targetPath, '**/*.{json,yaml,yml}')
      : path.join(targetPath, '*.{json,yaml,yml}');
    
    const files = await glob(pattern, { nodir: true });
    
    for (const file of files) {
      const result = await scanFile(file);
      // Only include if it's a valid OpenAPI spec or has an error
      if (result.spec || result.error) {
        results.push(result);
      }
    }
  }
  
  // Filter by severity if specified
  if (severity) {
    const severityOrder: Record<Severity, number> = {
      critical: 4,
      high: 3,
      medium: 2,
      low: 1,
      info: 0
    };
    const minSeverity = severityOrder[severity];
    
    for (const result of results) {
      result.findings = result.findings.filter(
        f => severityOrder[f.severity] >= minSeverity
      );
    }
  }
  
  return results;
}

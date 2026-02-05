import * as fs from 'node:fs';
import { scanOpenApiSpec, type ScanResult } from '../scanner/index.js';
import { formatScanResults, formatScanResultsJson } from '../formatter.js';
import type { Severity } from '../types.js';

interface ScanCommandOptions {
  json?: boolean;
  severity?: string;
  recursive?: boolean;
  output?: string;
}

export async function scanCommand(
  targetPath: string,
  options: ScanCommandOptions
): Promise<void> {
  const { json, severity, recursive, output } = options;
  
  // Validate path exists
  if (!fs.existsSync(targetPath)) {
    console.error(`Error: Path not found: ${targetPath}`);
    process.exit(2);
  }
  
  // Validate severity
  const validSeverities = ['critical', 'high', 'medium', 'low', 'info'];
  if (severity && !validSeverities.includes(severity)) {
    console.error(`Error: Invalid severity. Must be one of: ${validSeverities.join(', ')}`);
    process.exit(2);
  }
  
  try {
    const results = await scanOpenApiSpec(targetPath, {
      recursive,
      severity: severity as Severity | undefined
    });
    
    // Format output
    const formattedOutput = json 
      ? formatScanResultsJson(results)
      : formatScanResults(results);
    
    // Write to file or stdout
    if (output) {
      fs.writeFileSync(output, formattedOutput);
      console.log(`Results written to: ${output}`);
    } else {
      console.log(formattedOutput);
    }
    
    // Exit code based on findings
    const hasFindings = results.some(r => r.findings.length > 0);
    const hasErrors = results.some(r => r.error);
    
    if (hasErrors && results.every(r => r.error)) {
      process.exit(2); // All files had errors
    } else if (hasFindings) {
      process.exit(1); // Issues found
    } else {
      process.exit(0); // Clean
    }
  } catch (error) {
    console.error('Scan error:', error instanceof Error ? error.message : error);
    process.exit(2);
  }
}

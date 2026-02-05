import * as fs from 'node:fs';
import { checkEndpoint, type CheckResult } from '../checker/index.js';
import { formatCheckResult, formatCheckResultJson } from '../formatter.js';

interface CheckCommandOptions {
  headers?: boolean;
  auth?: string;
  timeout?: string;
  json?: boolean;
}

export async function checkCommand(
  url: string,
  options: CheckCommandOptions
): Promise<void> {
  const { headers = true, auth, timeout = '10000', json } = options;
  
  // Validate URL
  try {
    new URL(url);
  } catch {
    console.error(`Error: Invalid URL: ${url}`);
    process.exit(2);
  }
  
  // Validate auth type
  const validAuthTypes = ['basic', 'bearer', 'apikey'];
  if (auth && !validAuthTypes.includes(auth)) {
    console.error(`Error: Invalid auth type. Must be one of: ${validAuthTypes.join(', ')}`);
    process.exit(2);
  }
  
  try {
    const result = await checkEndpoint(url, {
      headers,
      auth: auth as 'basic' | 'bearer' | 'apikey' | undefined,
      timeout: parseInt(timeout, 10)
    });
    
    // Format output
    const formattedOutput = json 
      ? formatCheckResultJson(result)
      : formatCheckResult(result);
    
    console.log(formattedOutput);
    
    // Exit code
    if (result.status === 'error') {
      process.exit(2);
    } else if (result.findings.length > 0) {
      process.exit(1);
    } else {
      process.exit(0);
    }
  } catch (error) {
    console.error('Check error:', error instanceof Error ? error.message : error);
    process.exit(2);
  }
}

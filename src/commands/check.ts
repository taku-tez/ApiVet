import * as fs from 'node:fs';
import { checkEndpoint, type CheckResult } from '../checker/index.js';
import { formatCheckResult, formatCheckResultJson } from '../formatter.js';

interface CheckCommandOptions {
  headers?: boolean;
  auth?: string;
  authToken?: string;
  authHeader?: string;
  timeout?: string;
  method?: string;
  json?: boolean;
  output?: string;
}

export async function checkCommand(
  url: string,
  options: CheckCommandOptions
): Promise<void> {
  const { headers = false, auth, authToken, authHeader, timeout = '10000', method = 'GET', json, output } = options;

  // Validate URL
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    console.error(`Error: Invalid URL: ${url}`);
    process.exit(2);
  }

  // FB2: Only allow HTTP/HTTPS protocols
  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    console.error(`Error: Unsupported protocol: ${parsedUrl.protocol} (only http: and https: are supported)`);
    process.exit(2);
  }

  // Validate auth type
  const validAuthTypes = ['basic', 'bearer', 'apikey'];
  if (auth && !validAuthTypes.includes(auth)) {
    console.error(`Error: Invalid auth type. Must be one of: ${validAuthTypes.join(', ')}`);
    process.exit(2);
  }

  // FB2: Validate auth options combination
  if (auth && !authToken) {
    console.error(`Error: --auth requires --auth-token to specify the credential value`);
    process.exit(2);
  }

  if (authToken && !auth) {
    console.error(`Error: --auth-token requires --auth to specify the authentication type`);
    process.exit(2);
  }

  // FB3: Warn when --auth-header is specified without --auth (it will be ignored)
  if (authHeader && !auth) {
    console.error(`Warning: --auth-header is ignored without --auth. Specify --auth to use authentication.`);
  }

  // Validate timeout
  const timeoutMs = parseInt(timeout, 10);
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) {
    console.error(`Error: Invalid timeout value "${timeout}". Must be a positive integer (milliseconds).`);
    process.exit(2);
  }

  // Validate HTTP method
  const validMethods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
  const normalizedMethod = method.toUpperCase();
  if (!validMethods.includes(normalizedMethod)) {
    console.error(`Error: Invalid HTTP method "${method}". Must be one of: ${validMethods.join(', ')}`);
    process.exit(2);
  }

  try {
    const result = await checkEndpoint(url, {
      headers,
      auth: auth as 'basic' | 'bearer' | 'apikey' | undefined,
      authToken,
      authHeader,
      timeout: timeoutMs,
      method: normalizedMethod
    });

    // Format output
    const formattedOutput = json
      ? formatCheckResultJson(result)
      : formatCheckResult(result);

    // Write to file or console
    if (output) {
      fs.writeFileSync(output, formattedOutput);
      console.log(`Results written to ${output}`);
    } else {
      console.log(formattedOutput);
    }

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

#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { checkCommand } from './commands/check.js';
import { inventoryCommand } from './commands/inventory.js';
import { cloudAwsCommand } from './commands/cloud.js';

const program = new Command();

program
  .name('apivet')
  .description('API Security Scanner - Static and runtime analysis for API security posture')
  .version('0.3.1');

program
  .command('scan <path>')
  .description('Scan OpenAPI/Swagger specification files')
  .option('-j, --json', 'Output as JSON')
  .option('-s, --severity <level>', 'Filter by severity (critical, high, medium, low, info)')
  .option('-r, --recursive', 'Scan directories recursively')
  .option('-o, --output <file>', 'Write results to file')
  .option('--ignore <patterns>', 'Additional glob patterns to ignore (comma-separated)')
  .option('--only-rules <ids>', 'Only run specific rules (comma-separated rule IDs)')
  .option('--exclude-rules <ids>', 'Exclude specific rules (comma-separated rule IDs)')
  .action(scanCommand);

program
  .command('check <url>')
  .description('Perform live security checks on an API endpoint (HTTP/HTTPS only)')
  .option('--headers', 'Check security headers (disabled by default)')
  .option('-m, --method <method>', 'HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS (default: GET)')
  .option('--auth <type>', 'Authentication type: basic, bearer, apikey')
  .option('--auth-token <token>', 'Authentication token/key value')
  .option('--auth-header <name>', 'Custom header name (default: Authorization for bearer/basic, X-API-Key for apikey)')
  .option('--timeout <ms>', 'Request timeout in milliseconds (default: 10000, min: 1)')
  .option('-j, --json', 'Output as JSON')
  .option('-o, --output <file>', 'Write results to file')
  .action(checkCommand);

program
  .command('inventory <path>')
  .description('Discover and catalog API endpoints from source code')
  .option('--framework <name>', 'Target framework: express, fastify, koa, hono, auto (default: auto)')
  .option('-j, --json', 'Output as JSON')
  .option('-o, --output <file>', 'Write results to file')
  .option('--ignore <patterns>', 'Additional glob patterns to ignore (comma-separated)')
  .action(inventoryCommand);

// Cloud commands
const cloudCmd = program
  .command('cloud')
  .description('Scan cloud API gateway services');

cloudCmd
  .command('aws')
  .description('Scan AWS API Gateway (REST API V1 and HTTP API V2)')
  .option('-r, --region <region>', 'AWS region (default: AWS_REGION env or us-east-1)')
  .option('--api-id <id>', 'Scan specific API by ID')
  .option('-j, --json', 'Output as JSON')
  .option('-o, --output <file>', 'Write results to file')
  .option('-s, --severity <level>', 'Filter by severity (critical, high, medium, low, info)')
  .option('--only-rules <ids>', 'Only run specific rules (comma-separated rule IDs)')
  .option('--exclude-rules <ids>', 'Exclude specific rules (comma-separated rule IDs)')
  .action(cloudAwsCommand);

program.parse();

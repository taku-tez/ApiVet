#!/usr/bin/env node

import { Command } from 'commander';
import { scanCommand } from './commands/scan.js';
import { checkCommand } from './commands/check.js';
import { inventoryCommand } from './commands/inventory.js';

const program = new Command();

program
  .name('apivet')
  .description('API Security Scanner - Static and runtime analysis for API security posture')
  .version('0.1.0');

program
  .command('scan <path>')
  .description('Scan OpenAPI/Swagger specification files')
  .option('-j, --json', 'Output as JSON')
  .option('-s, --severity <level>', 'Filter by severity (critical, high, medium, low)')
  .option('-r, --recursive', 'Scan directories recursively')
  .option('-o, --output <file>', 'Write results to file')
  .action(scanCommand);

program
  .command('check <url>')
  .description('Perform live security checks on an API endpoint')
  .option('--headers', 'Check security headers')
  .option('--auth <type>', 'Test authentication type (basic, bearer, apikey)')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '10000')
  .option('-j, --json', 'Output as JSON')
  .action(checkCommand);

program
  .command('inventory <path>')
  .description('Discover and catalog API endpoints from source code')
  .option('--framework <name>', 'Target framework (express, fastify, koa, hono)')
  .option('-j, --json', 'Output as JSON')
  .option('-o, --output <file>', 'Write results to file')
  .action(inventoryCommand);

program.parse();

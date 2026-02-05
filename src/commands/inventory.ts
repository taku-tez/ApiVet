import * as fs from 'node:fs';
import { discoverEndpoints, type Endpoint } from '../inventory/index.js';
import { formatInventory, formatInventoryJson } from '../formatter.js';

interface InventoryCommandOptions {
  framework?: string;
  json?: boolean;
  output?: string;
  ignore?: string;
}

export async function inventoryCommand(
  targetPath: string,
  options: InventoryCommandOptions
): Promise<void> {
  const { framework, json, output, ignore } = options;
  
  // Validate path exists
  if (!fs.existsSync(targetPath)) {
    console.error(`Error: Path not found: ${targetPath}`);
    process.exit(2);
  }
  
  // Validate framework
  const validFrameworks = ['express', 'fastify', 'koa', 'hono', 'nestjs', 'hapi', 'restify', 'auto'];
  if (framework && !validFrameworks.includes(framework)) {
    console.error(`Error: Invalid framework. Must be one of: ${validFrameworks.join(', ')}`);
    process.exit(2);
  }

  // Parse ignore patterns
  const extraIgnore = ignore ? ignore.split(',').map(p => p.trim()) : undefined;
  
  try {
    const endpoints = await discoverEndpoints(targetPath, {
      framework: framework as 'express' | 'fastify' | 'koa' | 'hono' | 'nestjs' | 'hapi' | 'restify' | 'auto' | undefined,
      extraIgnore
    });
    
    // Format output
    const formattedOutput = json 
      ? formatInventoryJson(endpoints)
      : formatInventory(endpoints);
    
    // Write to file or stdout
    if (output) {
      fs.writeFileSync(output, formattedOutput);
      console.log(`Results written to: ${output}`);
    } else {
      console.log(formattedOutput);
    }
    
    process.exit(0);
  } catch (error) {
    console.error('Inventory error:', error instanceof Error ? error.message : error);
    process.exit(2);
  }
}

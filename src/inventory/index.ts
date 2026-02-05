import * as fs from 'node:fs';
import * as path from 'node:path';
import { glob } from 'glob';

export interface Endpoint {
  method: string;
  path: string;
  file: string;
  line?: number;
  handler?: string;
  framework?: string;
}

export interface DiscoveryOptions {
  framework?: 'express' | 'fastify' | 'koa' | 'hono' | 'auto';
}

interface FrameworkPattern {
  name: string;
  routePatterns: RegExp[];
  methodExtractor: (match: RegExpMatchArray) => { method: string; path: string } | null;
}

const FRAMEWORKS: FrameworkPattern[] = [
  {
    name: 'express',
    routePatterns: [
      // app.get('/path', handler)
      /(?:app|router)\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      // router.route('/path').get(handler).post(handler)
      /\.route\s*\(\s*['"`]([^'"`]+)['"`]\s*\)\s*\.(get|post|put|delete|patch)/gi
    ],
    methodExtractor: (match) => {
      if (match[2] && match[1]) {
        // Check if it's the .route() pattern
        if (match[0].includes('.route')) {
          return { method: match[2].toUpperCase(), path: match[1] };
        }
        return { method: match[1].toUpperCase(), path: match[2] };
      }
      return null;
    }
  },
  {
    name: 'fastify',
    routePatterns: [
      // fastify.get('/path', handler)
      /(?:fastify|app|server)\.(get|post|put|delete|patch|options|head)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      // fastify.route({ method: 'GET', url: '/path' })
      /\.route\s*\(\s*\{[^}]*method\s*:\s*['"`](\w+)['"`][^}]*url\s*:\s*['"`]([^'"`]+)['"`]/gi
    ],
    methodExtractor: (match) => {
      if (match[1] && match[2]) {
        return { method: match[1].toUpperCase(), path: match[2] };
      }
      return null;
    }
  },
  {
    name: 'koa',
    routePatterns: [
      // router.get('/path', handler)
      /router\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi
    ],
    methodExtractor: (match) => {
      if (match[1] && match[2]) {
        return { method: match[1].toUpperCase(), path: match[2] };
      }
      return null;
    }
  },
  {
    name: 'hono',
    routePatterns: [
      // app.get('/path', handler)
      /(?:app|router|hono)\.(get|post|put|delete|patch|options|head|all)\s*\(\s*['"`]([^'"`]+)['"`]/gi,
      // new Hono().get('/path', handler)
      /new\s+Hono\s*\(\s*\)\s*\.(get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]/gi
    ],
    methodExtractor: (match) => {
      if (match[1] && match[2]) {
        return { method: match[1].toUpperCase(), path: match[2] };
      }
      return null;
    }
  }
];

function findLineNumber(content: string, matchIndex: number): number {
  const lines = content.substring(0, matchIndex).split('\n');
  return lines.length;
}

async function scanFile(
  filePath: string,
  frameworks: FrameworkPattern[]
): Promise<Endpoint[]> {
  const endpoints: Endpoint[] = [];
  
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    
    for (const framework of frameworks) {
      for (const pattern of framework.routePatterns) {
        // Reset lastIndex for global regex
        pattern.lastIndex = 0;
        
        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          const extracted = framework.methodExtractor(match);
          if (extracted) {
            endpoints.push({
              method: extracted.method,
              path: extracted.path,
              file: filePath,
              line: findLineNumber(content, match.index),
              framework: framework.name
            });
          }
        }
      }
    }
  } catch (error) {
    // Skip files that can't be read
  }
  
  return endpoints;
}

function detectFramework(content: string): FrameworkPattern[] {
  const detected: FrameworkPattern[] = [];
  
  if (/require\s*\(\s*['"`]express['"`]\s*\)|from\s+['"`]express['"`]/i.test(content)) {
    const framework = FRAMEWORKS.find(f => f.name === 'express');
    if (framework) detected.push(framework);
  }
  
  if (/require\s*\(\s*['"`]fastify['"`]\s*\)|from\s+['"`]fastify['"`]/i.test(content)) {
    const framework = FRAMEWORKS.find(f => f.name === 'fastify');
    if (framework) detected.push(framework);
  }
  
  if (/require\s*\(\s*['"`]@?koa/i.test(content) || /from\s+['"`]@?koa/i.test(content)) {
    const framework = FRAMEWORKS.find(f => f.name === 'koa');
    if (framework) detected.push(framework);
  }
  
  if (/require\s*\(\s*['"`]hono['"`]\s*\)|from\s+['"`]hono['"`]/i.test(content)) {
    const framework = FRAMEWORKS.find(f => f.name === 'hono');
    if (framework) detected.push(framework);
  }
  
  // If nothing detected, return all frameworks for generic scanning
  return detected.length > 0 ? detected : FRAMEWORKS;
}

export async function discoverEndpoints(
  targetPath: string,
  options: DiscoveryOptions = {}
): Promise<Endpoint[]> {
  const { framework } = options;
  const endpoints: Endpoint[] = [];
  
  // Determine which framework patterns to use
  let frameworksToScan: FrameworkPattern[];
  
  if (framework && framework !== 'auto') {
    const fw = FRAMEWORKS.find(f => f.name === framework);
    frameworksToScan = fw ? [fw] : FRAMEWORKS;
  } else {
    // Auto-detect or use all
    frameworksToScan = FRAMEWORKS;
  }
  
  const stat = fs.statSync(targetPath);
  
  if (stat.isFile()) {
    const content = fs.readFileSync(targetPath, 'utf-8');
    const detectedFrameworks = framework === 'auto' ? detectFramework(content) : frameworksToScan;
    const fileEndpoints = await scanFile(targetPath, detectedFrameworks);
    endpoints.push(...fileEndpoints);
  } else if (stat.isDirectory()) {
    const patterns = [
      path.join(targetPath, '**/*.{js,ts,mjs,mts}')
    ];
    
    for (const pattern of patterns) {
      const files = await glob(pattern, { 
        nodir: true,
        ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/*.test.*', '**/*.spec.*']
      });
      
      for (const file of files) {
        const content = fs.readFileSync(file, 'utf-8');
        const detectedFrameworks = framework === 'auto' ? detectFramework(content) : frameworksToScan;
        const fileEndpoints = await scanFile(file, detectedFrameworks);
        endpoints.push(...fileEndpoints);
      }
    }
  }
  
  // Deduplicate
  const seen = new Set<string>();
  return endpoints.filter(ep => {
    const key = `${ep.method}:${ep.path}:${ep.file}:${ep.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

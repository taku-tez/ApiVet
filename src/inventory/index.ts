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

/**
 * Remove comments from source code to prevent false positives
 * Handles single-line (//) and multi-line (/* *\/) comments
 * FB2: Also handles multi-line template literals (backtick strings)
 * Preserves strings but marks their position for later filtering
 */
function stripComments(content: string): { stripped: string; lineMap: number[]; stringRanges: Array<{start: number; end: number}> } {
  const stringRanges: Array<{start: number; end: number}> = [];
  let result = '';
  let i = 0;
  let lineNumber = 1;
  const lineMap: number[] = [];
  let currentLineStart = 0;
  
  // Track line numbers for the stripped content
  const updateLineMap = () => {
    const newLines = result.substring(currentLineStart).split('\n').length - 1;
    for (let n = 0; n < newLines; n++) {
      lineMap.push(lineNumber);
    }
    currentLineStart = result.length;
  };

  while (i < content.length) {
    // Track original line numbers
    if (content[i] === '\n') {
      lineNumber++;
    }

    // Check for single-line comment
    if (content[i] === '/' && content[i + 1] === '/') {
      // Skip until end of line
      while (i < content.length && content[i] !== '\n') {
        i++;
      }
      continue;
    }

    // Check for multi-line comment
    if (content[i] === '/' && content[i + 1] === '*') {
      i += 2;
      while (i < content.length && !(content[i] === '*' && content[i + 1] === '/')) {
        if (content[i] === '\n') lineNumber++;
        i++;
      }
      i += 2; // Skip */
      continue;
    }

    // Check for string literals (including multi-line template literals)
    if (content[i] === '"' || content[i] === "'" || content[i] === '`') {
      const quote = content[i];
      const stringStart = result.length;
      result += content[i];
      i++;

      // FB2: Handle multi-line template literals properly
      while (i < content.length) {
        if (content[i] === '\\' && i + 1 < content.length) {
          // Escape sequence
          result += content[i] + content[i + 1];
          if (content[i + 1] === '\n') lineNumber++;
          i += 2;
        } else if (content[i] === quote) {
          result += content[i];
          i++;
          break;
        } else {
          if (content[i] === '\n') lineNumber++;
          result += content[i];
          i++;
        }
      }

      const stringEnd = result.length;
      stringRanges.push({ start: stringStart, end: stringEnd });
      continue;
    }

    result += content[i];
    i++;
  }

  // Build line map from stripped content
  const strippedLines = result.split('\n');
  const finalLineMap: number[] = [];
  let origLine = 1;
  for (let idx = 0; idx < strippedLines.length; idx++) {
    finalLineMap.push(origLine);
    // Count newlines in original content to estimate line mapping
    origLine++;
  }

  return {
    stripped: result,
    lineMap: finalLineMap,
    stringRanges
  };
}

/**
 * Check if a match position is inside a string literal
 */
function isInsideString(matchIndex: number, stringRanges: Array<{start: number; end: number}>): boolean {
  for (const range of stringRanges) {
    if (matchIndex >= range.start && matchIndex < range.end) {
      return true;
    }
  }
  return false;
}

/**
 * Find original line number from stripped content position
 */
function findOriginalLineNumber(
  strippedContent: string,
  matchIndex: number,
  lineMap: number[]
): number {
  const linesBeforeMatch = strippedContent.substring(0, matchIndex).split('\n').length - 1;
  return lineMap[linesBeforeMatch] || linesBeforeMatch + 1;
}

/**
 * Scan file content for route patterns
 * FB4: Accepts optional pre-read content to avoid double file reads
 */
async function scanFile(
  filePath: string,
  frameworks: FrameworkPattern[],
  preReadContent?: string
): Promise<Endpoint[]> {
  const endpoints: Endpoint[] = [];

  try {
    const rawContent = preReadContent ?? fs.readFileSync(filePath, 'utf-8');

    // Strip comments before scanning
    const { stripped: content, lineMap, stringRanges } = stripComments(rawContent);

    for (const framework of frameworks) {
      for (const pattern of framework.routePatterns) {
        // Reset lastIndex for global regex
        pattern.lastIndex = 0;

        let match: RegExpExecArray | null;
        while ((match = pattern.exec(content)) !== null) {
          // Skip matches that are inside string literals
          if (isInsideString(match.index, stringRanges)) {
            continue;
          }

          const extracted = framework.methodExtractor(match);
          if (extracted) {
            endpoints.push({
              method: extracted.method,
              path: extracted.path,
              file: filePath,
              line: findOriginalLineNumber(content, match.index, lineMap),
              framework: framework.name
            });
          }
        }
      }
    }
  } catch {
    // Skip files that can't be read
  }

  return endpoints;
}

/**
 * Detect framework by analyzing import/require statements
 * Uses stripped content to avoid false positives from comments
 * FB3: Also checks stringRanges to avoid matching text inside string literals
 */
function detectFramework(rawContent: string): FrameworkPattern[] {
  const detected: FrameworkPattern[] = [];
  
  // Strip comments to avoid false positives (e.g., "// import express" in a fastify file)
  const { stripped: content, stringRanges } = stripComments(rawContent);

  // Helper to check if a regex match is a real import (not inside a string literal other than the import itself)
  const isRealImport = (pattern: RegExp): boolean => {
    pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      // The match itself contains a string (the module name), but the require/from keyword
      // should NOT be inside another string literal
      // Check if the start of the match (the keyword part) is inside a string
      const keywordStart = match.index;
      let insideString = false;
      for (const range of stringRanges) {
        // Check if the keyword (not the module name) is inside a string
        if (keywordStart >= range.start && keywordStart < range.end) {
          insideString = true;
          break;
        }
      }
      if (!insideString) {
        return true;
      }
    }
    return false;
  };

  if (isRealImport(/require\s*\(\s*['"`]express['"`]\s*\)|from\s+['"`]express['"`]/gi)) {
    const framework = FRAMEWORKS.find(f => f.name === 'express');
    if (framework) detected.push(framework);
  }

  if (isRealImport(/require\s*\(\s*['"`]fastify['"`]\s*\)|from\s+['"`]fastify['"`]/gi)) {
    const framework = FRAMEWORKS.find(f => f.name === 'fastify');
    if (framework) detected.push(framework);
  }

  if (isRealImport(/require\s*\(\s*['"`]@?koa/gi) || isRealImport(/from\s+['"`]@?koa/gi)) {
    const framework = FRAMEWORKS.find(f => f.name === 'koa');
    if (framework) detected.push(framework);
  }

  if (isRealImport(/require\s*\(\s*['"`]hono['"`]\s*\)|from\s+['"`]hono['"`]/gi)) {
    const framework = FRAMEWORKS.find(f => f.name === 'hono');
    if (framework) detected.push(framework);
  }

  // If nothing detected, return all frameworks for generic scanning
  return detected.length > 0 ? detected : FRAMEWORKS;
}

/**
 * Helper to scan a single file with caching of content
 * FB4: Avoids reading file twice by passing content to both detectFramework and scanFile
 */
async function scanFileWithDetection(
  filePath: string,
  framework: DiscoveryOptions['framework'],
  defaultFrameworks: FrameworkPattern[]
): Promise<Endpoint[]> {
  try {
    const content = fs.readFileSync(filePath, 'utf-8');
    const detectedFrameworks = framework === 'auto' ? detectFramework(content) : defaultFrameworks;
    // Pass content to scanFile to avoid re-reading
    return await scanFile(filePath, detectedFrameworks, content);
  } catch {
    // FB5: Skip files that can't be read
    return [];
  }
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

  // FB5: Handle fs.statSync exception gracefully
  let stat: fs.Stats;
  try {
    stat = fs.statSync(targetPath);
  } catch {
    // Return empty array for non-existent or inaccessible paths
    return [];
  }

  if (stat.isFile()) {
    const fileEndpoints = await scanFileWithDetection(targetPath, framework, frameworksToScan);
    endpoints.push(...fileEndpoints);
  } else if (stat.isDirectory()) {
    // FB1: Include .jsx, .tsx, .cjs, .cts extensions
    const pattern = path.join(targetPath, '**/*.{js,ts,mjs,mts,jsx,tsx,cjs,cts}');

    const files = await glob(pattern, {
      nodir: true,
      ignore: ['**/node_modules/**', '**/dist/**', '**/build/**', '**/*.test.*', '**/*.spec.*']
    });

    // FB4: Process files without re-reading
    for (const file of files) {
      const fileEndpoints = await scanFileWithDetection(file, framework, frameworksToScan);
      endpoints.push(...fileEndpoints);
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

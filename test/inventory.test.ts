import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import { discoverEndpoints } from '../src/inventory/index.js';

// FB5: Use os.tmpdir() for cross-platform compatibility
const TEST_DIR = path.join(os.tmpdir(), 'apivet-test-inventory');

beforeAll(() => {
  fs.mkdirSync(TEST_DIR, { recursive: true });
  
  // Express routes
  fs.writeFileSync(
    path.join(TEST_DIR, 'express-routes.js'),
    `
const express = require('express');
const app = express();
const router = express.Router();

app.get('/health', (req, res) => res.send('OK'));
app.post('/users', createUser);
app.put('/users/:id', updateUser);
app.delete('/users/:id', deleteUser);

router.get('/items', listItems);
router.route('/orders')
  .get(getOrders)
  .post(createOrder);

module.exports = router;
`
  );
  
  // Fastify routes
  fs.writeFileSync(
    path.join(TEST_DIR, 'fastify-routes.ts'),
    `
import Fastify from 'fastify';

const fastify = Fastify();

fastify.get('/api/health', async () => ({ status: 'ok' }));
fastify.post('/api/data', async (req) => req.body);
fastify.route({
  method: 'GET',
  url: '/api/items',
  handler: async () => []
});

export default fastify;
`
  );
  
  // Hono routes
  fs.writeFileSync(
    path.join(TEST_DIR, 'hono-routes.ts'),
    `
import { Hono } from 'hono';

const app = new Hono();

app.get('/api/v1/users', (c) => c.json([]));
app.post('/api/v1/users', (c) => c.json({ created: true }));
app.delete('/api/v1/users/:id', (c) => c.json({ deleted: true }));

export default app;
`
  );
  
  // Koa routes
  fs.writeFileSync(
    path.join(TEST_DIR, 'koa-routes.js'),
    `
const Router = require('@koa/router');
const router = new Router();

router.get('/koa/items', async (ctx) => { ctx.body = []; });
router.post('/koa/items', async (ctx) => { ctx.body = { ok: true }; });

module.exports = router;
`
  );
});

afterAll(() => {
  fs.rmSync(TEST_DIR, { recursive: true, force: true });
});

describe('Inventory', () => {
  describe('discoverEndpoints', () => {
    it('should discover Express routes', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'express-routes.js'),
        { framework: 'express' }
      );
      
      expect(endpoints.length).toBeGreaterThanOrEqual(4);
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/health')).toBe(true);
      expect(endpoints.some(e => e.method === 'POST' && e.path === '/users')).toBe(true);
      expect(endpoints.some(e => e.method === 'DELETE' && e.path === '/users/:id')).toBe(true);
    });

    it('should discover Fastify routes', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'fastify-routes.ts'),
        { framework: 'fastify' }
      );
      
      expect(endpoints.length).toBeGreaterThanOrEqual(2);
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/api/health')).toBe(true);
      expect(endpoints.some(e => e.method === 'POST' && e.path === '/api/data')).toBe(true);
    });

    it('should discover Hono routes', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'hono-routes.ts'),
        { framework: 'hono' }
      );
      
      expect(endpoints.length).toBeGreaterThanOrEqual(3);
      expect(endpoints.some(e => e.path === '/api/v1/users' && e.method === 'GET')).toBe(true);
      expect(endpoints.some(e => e.path === '/api/v1/users/:id' && e.method === 'DELETE')).toBe(true);
    });

    it('should discover Koa routes', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'koa-routes.js'),
        { framework: 'koa' }
      );
      
      expect(endpoints.length).toBeGreaterThanOrEqual(2);
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/koa/items')).toBe(true);
    });

    it('should auto-detect framework', async () => {
      const endpoints = await discoverEndpoints(TEST_DIR, { framework: 'auto' });
      
      // Should find routes from all frameworks
      expect(endpoints.length).toBeGreaterThanOrEqual(10);
    });

    it('should scan directory recursively', async () => {
      // Create nested directory
      const nestedDir = path.join(TEST_DIR, 'nested');
      fs.mkdirSync(nestedDir, { recursive: true });
      fs.writeFileSync(
        path.join(nestedDir, 'nested-routes.js'),
        `const app = require('express')();
app.get('/nested', (req, res) => res.send('OK'));
`
      );
      
      const endpoints = await discoverEndpoints(TEST_DIR);
      
      expect(endpoints.some(e => e.path === '/nested')).toBe(true);
    });

    it('should include line numbers', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'express-routes.js')
      );
      
      const healthEndpoint = endpoints.find(e => e.path === '/health');
      expect(healthEndpoint?.line).toBeGreaterThan(0);
    });

    it('should deduplicate endpoints', async () => {
      const endpoints = await discoverEndpoints(TEST_DIR);
      
      const uniqueKeys = new Set(
        endpoints.map(e => `${e.method}:${e.path}:${e.file}:${e.line}`)
      );
      
      expect(endpoints.length).toBe(uniqueKeys.size);
    });

    // FB4: Test that comments are ignored
    it('should not detect routes in comments', async () => {
      const commentTestFile = path.join(TEST_DIR, 'commented-routes.js');
      fs.writeFileSync(
        commentTestFile,
        `
const express = require('express');
const app = express();

// This is a comment: app.get('/commented-route', handler)
/* 
 * Multi-line comment
 * app.post('/also-commented', handler)
 */
/**
 * JSDoc comment
 * app.delete('/jsdoc-route', handler)
 */

// Real route below
app.get('/real-route', (req, res) => res.send('OK'));

const example = "app.get('/string-route', handler)"; // in string, should not match
`
      );

      const endpoints = await discoverEndpoints(commentTestFile, { framework: 'express' });
      
      // Should only find the real route, not commented ones or string ones
      expect(endpoints.length).toBe(1);
      expect(endpoints[0].path).toBe('/real-route');
      expect(endpoints.some(e => e.path === '/commented-route')).toBe(false);
      expect(endpoints.some(e => e.path === '/also-commented')).toBe(false);
      expect(endpoints.some(e => e.path === '/jsdoc-route')).toBe(false);
      expect(endpoints.some(e => e.path === '/string-route')).toBe(false);
    });
  });
});

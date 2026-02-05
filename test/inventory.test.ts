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

  // NestJS routes
  fs.writeFileSync(
    path.join(TEST_DIR, 'nest-controller.ts'),
    `
import { Controller, Get, Post, Put, Delete, Param, Body } from '@nestjs/common';

@Controller('users')
export class UsersController {
  @Get()
  findAll() {
    return [];
  }

  @Get(':id')
  findOne(@Param('id') id: string) {
    return { id };
  }

  @Post()
  create(@Body() data: any) {
    return { created: true };
  }

  @Delete(':id')
  remove(@Param('id') id: string) {
    return { deleted: true };
  }
}
`
  );

  // Hapi routes
  fs.writeFileSync(
    path.join(TEST_DIR, 'hapi-routes.js'),
    `
const Hapi = require('@hapi/hapi');
const server = Hapi.server({ port: 3000 });

server.route({
  method: 'GET',
  path: '/hapi/health',
  handler: () => ({ status: 'ok' })
});

server.route({
  path: '/hapi/users',
  method: 'POST',
  handler: (request) => request.payload
});

server.route([
  {
    method: 'GET',
    path: '/hapi/items',
    handler: () => []
  }
]);

module.exports = server;
`
  );

  // Restify routes
  fs.writeFileSync(
    path.join(TEST_DIR, 'restify-routes.js'),
    `
const restify = require('restify');
const server = restify.createServer();

server.get('/restify/health', (req, res, next) => {
  res.send('OK');
  return next();
});

server.post('/restify/users', (req, res, next) => {
  res.send(req.body);
  return next();
});

server.del('/restify/users/:id', (req, res, next) => {
  res.send({ deleted: true });
  return next();
});

module.exports = server;
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

    it('should discover NestJS routes', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'nest-controller.ts'),
        { framework: 'nestjs' }
      );
      
      expect(endpoints.length).toBeGreaterThanOrEqual(4);
      // Now includes @Controller('users') prefix
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/users')).toBe(true);  // @Get()
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/users/:id')).toBe(true);  // @Get(':id')
      expect(endpoints.some(e => e.method === 'POST' && e.path === '/users')).toBe(true);  // @Post()
      expect(endpoints.some(e => e.method === 'DELETE' && e.path === '/users/:id')).toBe(true);  // @Delete(':id')
    });

    it('should discover Hapi routes', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'hapi-routes.js'),
        { framework: 'hapi' }
      );
      
      expect(endpoints.length).toBeGreaterThanOrEqual(2);
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/hapi/health')).toBe(true);
      expect(endpoints.some(e => e.method === 'POST' && e.path === '/hapi/users')).toBe(true);
    });

    it('should discover Restify routes', async () => {
      const endpoints = await discoverEndpoints(
        path.join(TEST_DIR, 'restify-routes.js'),
        { framework: 'restify' }
      );
      
      expect(endpoints.length).toBeGreaterThanOrEqual(3);
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/restify/health')).toBe(true);
      expect(endpoints.some(e => e.method === 'POST' && e.path === '/restify/users')).toBe(true);
      expect(endpoints.some(e => e.method === 'DELETE' && e.path === '/restify/users/:id')).toBe(true);
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

    // FB5: Handle non-existent paths gracefully
    it('should return empty array for non-existent path', async () => {
      const endpoints = await discoverEndpoints('/nonexistent/path/to/code');
      
      expect(endpoints).toEqual([]);
    });

    // FB1: Support JSX/TSX/CJS/CTS files
    it('should discover routes in .tsx files', async () => {
      const tsxFile = path.join(TEST_DIR, 'react-routes.tsx');
      fs.writeFileSync(
        tsxFile,
        `
import express from 'express';
const app = express();

app.get('/tsx-route', (req, res) => res.json({ component: '<App />' }));
app.post('/tsx-post', (req, res) => res.json({ ok: true }));

export default app;
`
      );

      const endpoints = await discoverEndpoints(tsxFile, { framework: 'express' });
      
      expect(endpoints.some(e => e.path === '/tsx-route')).toBe(true);
      expect(endpoints.some(e => e.path === '/tsx-post')).toBe(true);
    });

    // FB2: Handle multiline template literals
    it('should handle multiline template literals correctly', async () => {
      const templateFile = path.join(TEST_DIR, 'template-literal.ts');
      fs.writeFileSync(
        templateFile,
        `
import express from 'express';
const app = express();

const longString = \`
  This is a multiline template literal
  app.get('/fake-in-template', handler)
  with route-like patterns inside
\`;

// Real route
app.get('/real-template-route', (req, res) => res.send('OK'));
`
      );

      const endpoints = await discoverEndpoints(templateFile, { framework: 'express' });
      
      // Should only find the real route
      expect(endpoints.length).toBe(1);
      expect(endpoints[0].path).toBe('/real-template-route');
      expect(endpoints.some(e => e.path === '/fake-in-template')).toBe(false);
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

    // Express router mount detection
    it('should detect Express router mount points', async () => {
      const routerMountFile = path.join(TEST_DIR, 'router-mounts.js');
      fs.writeFileSync(
        routerMountFile,
        `
const express = require('express');
const app = express();
const userRouter = require('./users');
const apiRouter = require('./api');

app.use('/api', apiRouter);
app.use('/users', userRouter);
router.use('/v1', v1Router);

app.get('/health', (req, res) => res.send('OK'));
`
      );

      const endpoints = await discoverEndpoints(routerMountFile, { framework: 'express' });
      
      // Should find mount points as USE method
      expect(endpoints.some(e => e.method === 'USE' && e.path.includes('/api'))).toBe(true);
      expect(endpoints.some(e => e.method === 'USE' && e.path.includes('/users'))).toBe(true);
      expect(endpoints.some(e => e.method === 'USE' && e.path.includes('/v1'))).toBe(true);
      // Should also find regular routes
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/health')).toBe(true);
    });

    // NestJS controller without prefix
    it('should handle NestJS controller without prefix', async () => {
      const noPrefixController = path.join(TEST_DIR, 'no-prefix-controller.ts');
      fs.writeFileSync(
        noPrefixController,
        `
import { Controller, Get } from '@nestjs/common';

@Controller()
export class RootController {
  @Get()
  root() {
    return 'Hello';
  }

  @Get('health')
  health() {
    return { status: 'ok' };
  }
}
`
      );

      const endpoints = await discoverEndpoints(noPrefixController, { framework: 'nestjs' });
      
      // Without @Controller prefix, routes should be at root level
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/')).toBe(true);
      expect(endpoints.some(e => e.method === 'GET' && e.path === '/health')).toBe(true);
    });
  });
});

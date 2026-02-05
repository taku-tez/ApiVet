import { describe, it, expect } from 'vitest';
import { checkEndpoint } from '../src/checker/index.js';

describe('Checker', () => {
  describe('checkEndpoint', () => {
    // FB1: Timeout cleanup - hard to test directly, but we can test error handling
    it('should handle timeout gracefully', async () => {
      // Use a very short timeout against a slow/non-existent endpoint
      const result = await checkEndpoint('http://10.255.255.1/', { timeout: 100 });
      
      expect(result.status).toBe('error');
      expect(result.error).toBeDefined();
    }, 5000);

    // FB2: HTTP/HTTPS protocol validation
    describe('protocol validation', () => {
      it('should accept http:// URLs', async () => {
        // This will fail to connect but shouldn't error on protocol
        const result = await checkEndpoint('http://nonexistent.test.local/', { timeout: 100 });
        
        // Error should be about connection, not protocol
        expect(result.error).not.toContain('Unsupported protocol');
      }, 5000);

      it('should accept https:// URLs', async () => {
        const result = await checkEndpoint('https://nonexistent.test.local/', { timeout: 100 });
        
        expect(result.error).not.toContain('Unsupported protocol');
      }, 5000);

      it('should reject ftp:// URLs', async () => {
        const result = await checkEndpoint('ftp://example.com/file');
        
        expect(result.status).toBe('error');
        expect(result.error).toContain('Unsupported protocol');
        expect(result.error).toContain('ftp:');
      });

      it('should reject file:// URLs', async () => {
        const result = await checkEndpoint('file:///etc/passwd');
        
        expect(result.status).toBe('error');
        expect(result.error).toContain('Unsupported protocol');
        expect(result.error).toContain('file:');
      });

      it('should reject data: URLs', async () => {
        const result = await checkEndpoint('data:text/plain,hello');
        
        expect(result.status).toBe('error');
        expect(result.error).toContain('Unsupported protocol');
      });

      it('should reject javascript: URLs', async () => {
        const result = await checkEndpoint('javascript:alert(1)');
        
        expect(result.status).toBe('error');
        expect(result.error).toContain('Unsupported protocol');
      });
    });

    // Invalid URL handling
    describe('URL validation', () => {
      it('should reject invalid URLs', async () => {
        const result = await checkEndpoint('not-a-valid-url');
        
        expect(result.status).toBe('error');
        expect(result.error).toContain('Invalid URL');
      });

      it('should reject empty URL', async () => {
        const result = await checkEndpoint('');
        
        expect(result.status).toBe('error');
        expect(result.error).toContain('Invalid URL');
      });
    });

    // Headers option
    describe('headers option', () => {
      it('should not return headers by default', async () => {
        // Will fail to connect, but that's OK - we're testing the options
        const result = await checkEndpoint('http://localhost:99999/', { timeout: 100 });
        
        // Headers should be undefined when not requested
        expect(result.headers).toBeUndefined();
      }, 5000);
    });

    // Custom headers option
    describe('customHeaders option', () => {
      it('should accept custom headers in Name:Value format', async () => {
        // Test that custom headers are accepted (we can't easily verify they're sent)
        const result = await checkEndpoint('http://localhost:99999/', {
          timeout: 100,
          customHeaders: ['X-Custom-Header: test-value', 'X-Another: value2']
        });
        
        // Should not throw, just fail to connect
        expect(result.status).toBe('error');
        expect(result.error).not.toContain('header');
      }, 5000);

      it('should handle headers with spaces around colon', async () => {
        const result = await checkEndpoint('http://localhost:99999/', {
          timeout: 100,
          customHeaders: ['X-Spaced : value with spaces']
        });
        
        expect(result.status).toBe('error');
      }, 5000);
    });

    // Body option
    describe('body option', () => {
      it('should accept body with POST method', async () => {
        const result = await checkEndpoint('http://localhost:99999/', {
          timeout: 100,
          method: 'POST',
          body: JSON.stringify({ test: 'data' })
        });
        
        expect(result.status).toBe('error');
        expect(result.error).not.toContain('body');
      }, 5000);

      it('should accept body with PUT method', async () => {
        const result = await checkEndpoint('http://localhost:99999/', {
          timeout: 100,
          method: 'PUT',
          body: '{"key": "value"}'
        });
        
        expect(result.status).toBe('error');
      }, 5000);
    });
  });
});

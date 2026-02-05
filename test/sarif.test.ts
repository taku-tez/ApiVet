import { describe, it, expect } from 'vitest';
import { generateSarif, formatSarif } from '../src/sarif.js';
import type { Finding } from '../src/types.js';

describe('SARIF Output', () => {
  const mockFindings: Finding[] = [
    {
      ruleId: 'APIVET001',
      title: 'Broken Object Level Authorization',
      description: 'GET /users/{id} has no security defined.',
      severity: 'high',
      owaspCategory: 'API1:2023',
      location: {
        path: 'openapi.yaml',
        endpoint: '/users/{id}',
        method: 'GET'
      },
      remediation: 'Add security scheme to the endpoint.'
    },
    {
      ruleId: 'APIVET009',
      title: 'HTTP Server URL',
      description: 'Server URL uses HTTP instead of HTTPS.',
      severity: 'high',
      owaspCategory: 'API8:2023',
      location: {
        path: 'openapi.yaml'
      }
    },
    {
      ruleId: 'APIVET001',
      title: 'Broken Object Level Authorization',
      description: 'GET /orders/{id} has no security defined.',
      severity: 'high',
      owaspCategory: 'API1:2023',
      location: {
        path: 'openapi.yaml',
        endpoint: '/orders/{id}',
        method: 'GET'
      },
      remediation: 'Add security scheme to the endpoint.'
    }
  ];

  describe('generateSarif', () => {
    it('should generate valid SARIF structure', () => {
      const sarif = generateSarif(mockFindings);

      expect(sarif.$schema).toContain('sarif-schema-2.1.0');
      expect(sarif.version).toBe('2.1.0');
      expect(sarif.runs).toHaveLength(1);
    });

    it('should include tool information', () => {
      const sarif = generateSarif(mockFindings);
      const driver = sarif.runs[0].tool.driver;

      expect(driver.name).toBe('ApiVet');
      expect(driver.informationUri).toContain('ApiVet');
    });

    it('should deduplicate rules', () => {
      const sarif = generateSarif(mockFindings);
      const rules = sarif.runs[0].tool.driver.rules;

      // APIVET001 appears twice but should only be in rules once
      expect(rules.filter(r => r.id === 'APIVET001')).toHaveLength(1);
      expect(rules).toHaveLength(2); // APIVET001 and APIVET009
    });

    it('should create results for all findings', () => {
      const sarif = generateSarif(mockFindings);
      const results = sarif.runs[0].results;

      expect(results).toHaveLength(3);
    });

    it('should map severity to SARIF levels correctly', () => {
      const findings: Finding[] = [
        { ruleId: 'TEST001', title: 'Critical', description: 'Test', severity: 'critical' },
        { ruleId: 'TEST002', title: 'High', description: 'Test', severity: 'high' },
        { ruleId: 'TEST003', title: 'Medium', description: 'Test', severity: 'medium' },
        { ruleId: 'TEST004', title: 'Low', description: 'Test', severity: 'low' },
        { ruleId: 'TEST005', title: 'Info', description: 'Test', severity: 'info' }
      ];

      const sarif = generateSarif(findings);
      const results = sarif.runs[0].results;

      expect(results[0].level).toBe('error');    // critical
      expect(results[1].level).toBe('error');    // high
      expect(results[2].level).toBe('warning');  // medium
      expect(results[3].level).toBe('note');     // low
      expect(results[4].level).toBe('note');     // info
    });

    it('should include location information', () => {
      const sarif = generateSarif(mockFindings);
      const result = sarif.runs[0].results[0];

      expect(result.locations).toBeDefined();
      expect(result.locations![0].physicalLocation.artifactLocation.uri).toBe('openapi.yaml');
      expect(result.locations![0].logicalLocations![0].name).toContain('/users/{id}');
    });

    it('should include OWASP tags in rules', () => {
      const sarif = generateSarif(mockFindings);
      const rule = sarif.runs[0].tool.driver.rules[0];

      expect(rule.properties?.tags).toContain('security');
      expect(rule.properties?.tags?.some(t => t.includes('owasp'))).toBe(true);
    });

    it('should include security-severity scores', () => {
      const sarif = generateSarif(mockFindings);
      const rule = sarif.runs[0].tool.driver.rules[0];

      expect(rule.properties?.['security-severity']).toBeDefined();
      expect(parseFloat(rule.properties!['security-severity']!)).toBeGreaterThan(0);
    });

    it('should include remediation as fix', () => {
      const sarif = generateSarif(mockFindings);
      const result = sarif.runs[0].results[0];

      expect(result.fixes).toBeDefined();
      expect(result.fixes![0].description.text).toContain('security');
    });
  });

  describe('formatSarif', () => {
    it('should return valid JSON string', () => {
      const sarifStr = formatSarif(mockFindings);
      
      expect(() => JSON.parse(sarifStr)).not.toThrow();
    });

    it('should include version parameter', () => {
      const sarif = generateSarif(mockFindings, '1.2.3');
      
      expect(sarif.runs[0].tool.driver.version).toBe('1.2.3');
    });
  });
});

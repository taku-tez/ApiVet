/**
 * General Cloud Security Rules
 * APIVET032-033, APIVET035
 */

import type { OpenApiSpec, Finding } from '../types.js';
import { Rule, PRIVATE_IP_PATTERNS, DEV_ENVIRONMENT_PATTERNS, HTTP_METHODS, createFinding } from './utils.js';

export const generalRules: Rule[] = [
  // Non-production URL
  {
    id: 'APIVET032',
    title: 'Non-production environment URL detected',
    description: 'API specification contains staging or development URLs',
    severity: 'medium',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      for (const server of servers) {
        const url = server.url.toLowerCase();
        const description = (server.description || '').toLowerCase();

        for (const pattern of DEV_ENVIRONMENT_PATTERNS) {
          if (url.includes(pattern) || description.includes(pattern)) {
            findings.push(createFinding(
              'APIVET032',
              `Non-production URL detected: ${server.url}`,
              `Server URL "${server.url}" appears to be a ${pattern} environment.`,
              'medium',
              {
                owaspCategory: 'API9:2023',
                filePath,
                remediation: 'Remove non-production URLs from production specs. Use environment variables or separate files.'
              }
            ));
            break;
          }
        }
      }

      return findings;
    }
  },

  // Internal/Private API exposure
  {
    id: 'APIVET033',
    title: 'Internal API URL potentially exposed',
    description: 'API specification contains internal or private network URLs',
    severity: 'high',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      for (const server of servers) {
        for (const pattern of PRIVATE_IP_PATTERNS) {
          if (pattern.test(server.url)) {
            findings.push(createFinding(
              'APIVET033',
              `Internal network URL exposed: ${server.url}`,
              `Server URL "${server.url}" is an internal/private network address.`,
              'high',
              {
                owaspCategory: 'API9:2023',
                filePath,
                remediation: 'Remove internal URLs from public specs. Use relative paths or environment-specific config.'
              }
            ));
            break;
          }
        }
      }

      return findings;
    }
  },

  // Cloud API without CORS
  {
    id: 'APIVET035',
    title: 'Cloud API without CORS configuration',
    description: 'APIs accessed from browsers need CORS configuration',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};
      const servers = spec.servers || [];

      const isCloudHosted = servers.some(s =>
        s.url.includes('.amazonaws.com') ||
        s.url.includes('.azure-api.net') ||
        s.url.includes('.run.app') ||
        s.url.includes('.cloudfunctions.net') ||
        s.url.includes('.execute-api.')
      );

      if (!isCloudHosted) return findings;

      let hasOptionsMethod = false;
      for (const pathItem of Object.values(paths)) {
        if (pathItem.options) {
          hasOptionsMethod = true;
          break;
        }
      }

      if (!hasOptionsMethod && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET035',
          'Cloud API without CORS preflight handlers',
          'This cloud-hosted API has no OPTIONS methods for CORS preflight.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Configure CORS at API gateway level if browser access is needed.'
          }
        ));
      }

      return findings;
    }
  }
];

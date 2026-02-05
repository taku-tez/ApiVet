/**
 * Azure API Management and Related Services Rules
 * APIVET030, APIVET039-040
 */

import type { OpenApiSpec, Finding } from '../types.js';
import { Rule, isAzureApim, isAzureService, createFinding } from './utils.js';

export const azureRules: Rule[] = [
  // Azure APIM detection
  {
    id: 'APIVET030',
    title: 'Azure APIM integration detected',
    description: 'Ensure Azure API Management policies are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];

      if (isAzureApim(spec.servers)) {
        findings.push(createFinding(
          'APIVET030',
          'Azure API Management detected',
          'This API uses Azure APIM. Ensure inbound/outbound policies are configured for security.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Review APIM policies: validate-jwt, rate-limit-by-key, ip-filter, cors.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure Functions / App Service
  {
    id: 'APIVET039',
    title: 'Azure Functions / App Service detected',
    description: 'Ensure Azure authentication is properly configured',
    severity: 'info',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      const isAzureFunc = servers.some(s =>
        s.url.includes('.azurewebsites.net') ||
        s.url.includes('.azure-mobile.net')
      );

      if (isAzureFunc) {
        findings.push(createFinding(
          'APIVET039',
          'Azure Functions / App Service detected',
          'This API is hosted on Azure Functions or App Service. Configure built-in or custom authentication.',
          'info',
          {
            owaspCategory: 'API2:2023',
            filePath,
            remediation: 'Enable Azure App Service Authentication (Easy Auth) or implement custom JWT validation.'
          }
        ));
      }

      return findings;
    }
  },

  // Azure Front Door
  {
    id: 'APIVET040',
    title: 'Azure Front Door detected',
    description: 'Ensure Azure Front Door security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      const isFrontDoor = servers.some(s =>
        s.url.includes('.azurefd.net') ||
        s.url.includes('.afd.') ||
        s.url.includes('frontdoor')
      );

      if (isFrontDoor) {
        findings.push(createFinding(
          'APIVET040',
          'Azure Front Door detected',
          'This API uses Azure Front Door. Ensure WAF policies and DDoS protection are configured.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Enable Azure WAF policy with OWASP rule sets. Configure rate limiting. Use Private Link.'
          }
        ));
      }

      return findings;
    }
  }
];

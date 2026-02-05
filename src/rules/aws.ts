/**
 * AWS API Gateway and Related Services Rules
 * APIVET026-029, APIVET034, APIVET036-038, APIVET048-049
 */

import type { Finding } from '../types.js';
import {
  Rule,
  HTTP_METHODS,
  isAwsSpec,
  isAwsApiGateway,
  hasGlobalSecurity,
  createFinding
} from './utils.js';

export const awsRules: Rule[] = [
  // AWS API Gateway without authorizer
  {
    id: 'APIVET026',
    title: 'AWS API Gateway endpoint without authorizer',
    description: 'AWS API Gateway endpoints should have authorization',
    severity: 'high',
    owaspCategory: 'API2:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAwsSpec(spec)) return findings;

      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          const integration = operation['x-amazon-apigateway-integration'] as Record<string, unknown> | undefined;
          if (integration?.type === 'mock') continue;

          const hasAwsAuth = operation['x-amazon-apigateway-auth'];
          const hasSecurity = operation.security || hasGlobalSecurity(spec);

          if (!hasAwsAuth && !hasSecurity) {
            findings.push(createFinding(
              'APIVET026',
              'AWS API Gateway endpoint without authorization',
              `${method.toUpperCase()} ${path} in AWS API Gateway has no authorizer.`,
              'high',
              {
                owaspCategory: 'API2:2023',
                filePath,
                endpoint: path,
                method: method.toUpperCase(),
                remediation: 'Configure x-amazon-apigateway-auth or add security. Use Cognito, Lambda authorizers, or IAM.'
              }
            ));
          }
        }
      }

      return findings;
    }
  },

  // AWS API Gateway missing request validation
  {
    id: 'APIVET027',
    title: 'AWS API Gateway without request validation',
    description: 'AWS API Gateway should validate requests',
    severity: 'medium',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAwsSpec(spec)) return findings;

      const extSpec = spec as Record<string, unknown>;
      const validators = extSpec['x-amazon-apigateway-request-validators'] as Record<string, unknown> | undefined;
      const defaultValidator = extSpec['x-amazon-apigateway-request-validator'] as string | undefined;

      if (!validators && !defaultValidator) {
        findings.push(createFinding(
          'APIVET027',
          'AWS API Gateway missing request validation configuration',
          'The API Gateway spec does not define request validators.',
          'medium',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Add x-amazon-apigateway-request-validators and set x-amazon-apigateway-request-validator.'
          }
        ));
      } else if (validators && !defaultValidator) {
        findings.push(createFinding(
          'APIVET027',
          'AWS API Gateway request validators defined but not enabled',
          'Validators are defined but no default is set.',
          'low',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Set x-amazon-apigateway-request-validator to enable validation.'
          }
        ));
      }

      return findings;
    }
  },

  // AWS API Gateway without API key
  {
    id: 'APIVET028',
    title: 'AWS API Gateway without API key requirement',
    description: 'Consider API keys for usage tracking',
    severity: 'info',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      if (!isAwsSpec(spec)) return findings;

      const paths = spec.paths || {};
      let hasAnyApiKey = false;

      for (const pathItem of Object.values(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          const integration = operation['x-amazon-apigateway-integration'] as Record<string, unknown> | undefined;
          if (integration?.type === 'mock') continue;

          const security = operation.security as Array<Record<string, string[]>> | undefined;
          if (operation['x-amazon-apigateway-api-key-source'] || security?.some(s => 'api_key' in s)) {
            hasAnyApiKey = true;
          }
        }
      }

      if (!hasAnyApiKey && Object.keys(paths).length > 0) {
        findings.push(createFinding(
          'APIVET028',
          'AWS API Gateway without API key requirements',
          'No endpoints require API keys. API keys enable usage plans and throttling.',
          'info',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Add API key requirements with usage plans for tracking and throttling.'
          }
        ));
      }

      return findings;
    }
  },

  // AWS Cognito without scopes
  {
    id: 'APIVET029',
    title: 'AWS Cognito authorizer without scope validation',
    description: 'Cognito authorizers should validate OAuth2 scopes',
    severity: 'medium',
    owaspCategory: 'API5:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const schemes = spec.components?.securitySchemes || {};

      for (const [name, scheme] of Object.entries(schemes)) {
        const extScheme = scheme as unknown as Record<string, unknown>;
        const authorizer = extScheme['x-amazon-apigateway-authorizer'] as Record<string, unknown> | undefined;

        if (authorizer?.type !== 'cognito_user_pools') continue;

        const paths = spec.paths || {};
        for (const [path, pathItem] of Object.entries(paths)) {
          for (const method of HTTP_METHODS) {
            const operation = pathItem[method];
            if (!operation?.security) continue;

            for (const secReq of operation.security) {
              if (name in secReq && (!secReq[name] || secReq[name].length === 0)) {
                findings.push(createFinding(
                  'APIVET029',
                  `Cognito authorizer "${name}" used without scopes`,
                  `${method.toUpperCase()} ${path} uses Cognito "${name}" without OAuth2 scopes.`,
                  'medium',
                  {
                    owaspCategory: 'API5:2023',
                    filePath,
                    endpoint: path,
                    method: method.toUpperCase(),
                    remediation: 'Specify required OAuth2 scopes for fine-grained access control.'
                  }
                ));
              }
            }
          }
        }
      }

      return findings;
    }
  },

  // AWS Lambda proxy without validation
  {
    id: 'APIVET034',
    title: 'AWS Lambda proxy without request validation',
    description: 'Lambda proxy integrations pass raw requests',
    severity: 'medium',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const paths = spec.paths || {};

      for (const [path, pathItem] of Object.entries(paths)) {
        for (const method of HTTP_METHODS) {
          const operation = pathItem[method] as Record<string, unknown> | undefined;
          if (!operation) continue;

          const integration = operation['x-amazon-apigateway-integration'] as Record<string, unknown> | undefined;
          const integrationType = integration?.type as string | undefined;

          if (integrationType?.toLowerCase() === 'aws_proxy') {
            const hasValidator = operation['x-amazon-apigateway-request-validator'] !== undefined;
            const hasRequestBody = operation.requestBody !== undefined;

            if (!hasValidator && hasRequestBody) {
              findings.push(createFinding(
                'APIVET034',
                'Lambda proxy integration without request validation',
                `${method.toUpperCase()} ${path} uses Lambda proxy with request body but no validator.`,
                'medium',
                {
                  owaspCategory: 'API8:2023',
                  filePath,
                  endpoint: path,
                  method: method.toUpperCase(),
                  remediation: 'Add x-amazon-apigateway-request-validator or validate in Lambda.'
                }
              ));
            }
          }
        }
      }

      return findings;
    }
  },

  // AWS AppSync
  {
    id: 'APIVET036',
    title: 'AWS AppSync GraphQL API detected',
    description: 'GraphQL APIs require specific security considerations',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.appsync-api.') || s.url.includes('appsync.'))) {
        findings.push(createFinding(
          'APIVET036',
          'AWS AppSync GraphQL API detected',
          'This API uses AWS AppSync. Ensure proper authorization and field-level permissions.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'Configure AppSync auth modes. Use @auth directives. Enable logging.'
          }
        ));
      }

      return findings;
    }
  },

  // AWS CloudFront recommendation
  {
    id: 'APIVET037',
    title: 'AWS API Gateway without CloudFront',
    description: 'Consider CloudFront for DDoS protection',
    severity: 'info',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      const hasDirectApiGw = servers.some(s => s.url.includes('.execute-api.') && !s.url.includes('.cloudfront.net'));
      const hasCloudFront = servers.some(s => s.url.includes('.cloudfront.net'));

      if (hasDirectApiGw && !hasCloudFront) {
        findings.push(createFinding(
          'APIVET037',
          'AWS API Gateway exposed without CloudFront',
          'API Gateway is directly exposed. Consider CloudFront for DDoS protection and caching.',
          'info',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Configure CloudFront distribution with API Gateway origin. Enable WAF.'
          }
        ));
      }

      return findings;
    }
  },

  // AWS WAF recommendation
  {
    id: 'APIVET038',
    title: 'AWS API without WAF indication',
    description: 'AWS APIs should consider WAF protection',
    severity: 'low',
    owaspCategory: 'API4:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (!isAwsApiGateway(servers)) return findings;

      const specStr = JSON.stringify(spec).toLowerCase();
      const hasWaf = specStr.includes('waf') || specStr.includes('x-waf') || specStr.includes('x-amazon-waf');

      if (!hasWaf) {
        findings.push(createFinding(
          'APIVET038',
          'AWS API without WAF configuration indicated',
          'This AWS API does not mention WAF protection.',
          'low',
          {
            owaspCategory: 'API4:2023',
            filePath,
            remediation: 'Enable AWS WAF with managed rule groups for common exploits.'
          }
        ));
      }

      return findings;
    }
  },

  // AWS HTTP API vs REST API
  {
    id: 'APIVET048',
    title: 'AWS HTTP API detected',
    description: 'HTTP APIs have different security features than REST APIs',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec);

      const isApiGw = servers.some(s => s.url.includes('.execute-api.'));
      const hasHttpApiMarkers = specStr.includes('x-amazon-apigateway-cors') || specStr.includes('payloadFormatVersion');

      if (isApiGw && hasHttpApiMarkers) {
        findings.push(createFinding(
          'APIVET048',
          'AWS API Gateway HTTP API detected',
          'This is an HTTP API (not REST API). Limited WAF integration and request validation.',
          'info',
          {
            owaspCategory: 'API8:2023',
            filePath,
            remediation: 'For HTTP APIs: use JWT authorizers, validate in Lambda. Consider REST API for WAF.'
          }
        ));
      }

      return findings;
    }
  },

  // AWS Private API consideration
  {
    id: 'APIVET049',
    title: 'AWS Private API Gateway consideration',
    description: 'Consider private endpoints for internal services',
    severity: 'info',
    owaspCategory: 'API9:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();

      const isAwsApi = servers.some(s => s.url.includes('.execute-api.'));
      const isInternal = specStr.includes('internal') || specStr.includes('private') || specStr.includes('backend');
      const hasVpcEndpoint = specStr.includes('vpce-') || specStr.includes('x-amazon-apigateway-endpoint-configuration');

      if (isAwsApi && isInternal && !hasVpcEndpoint) {
        findings.push(createFinding(
          'APIVET049',
          'Consider AWS Private API for internal service',
          'This API appears internal but may be public. Consider private API Gateway endpoint.',
          'info',
          {
            owaspCategory: 'API9:2023',
            filePath,
            remediation: 'Configure PRIVATE endpoint type. Create VPC endpoint. Use resource policies.'
          }
        ));
      }

      return findings;
    }
  }
];

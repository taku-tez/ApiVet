/**
 * Cloud Platforms, CDN, PaaS, and Infrastructure Rules
 * APIVET043-047, APIVET050-055
 */

import type { OpenApiSpec, Finding } from '../types.js';
import { Rule, createFinding } from './utils.js';

export const platformRules: Rule[] = [
  // Cloudflare Workers
  {
    id: 'APIVET043',
    title: 'Cloudflare Workers / Pages detected',
    description: 'Ensure Cloudflare security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.workers.dev') || s.url.includes('.pages.dev') || s.url.includes('cloudflare'))) {
        findings.push(createFinding(
          'APIVET043',
          'Cloudflare Workers / Pages detected',
          'This API uses Cloudflare. Consider enabling API Shield for schema validation.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Enable API Shield, rate limiting, Access for auth, Bot Management.' }
        ));
      }

      return findings;
    }
  },

  // Vercel
  {
    id: 'APIVET044',
    title: 'Vercel deployment detected',
    description: 'Ensure Vercel security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.vercel.app') || s.url.includes('.now.sh'))) {
        findings.push(createFinding(
          'APIVET044',
          'Vercel deployment detected',
          'This API is deployed on Vercel. Ensure proper authentication and Vercel Firewall.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Secure env vars. Use Vercel Auth. Enable Firewall. Use Edge Middleware.' }
        ));
      }

      return findings;
    }
  },

  // Netlify
  {
    id: 'APIVET045',
    title: 'Netlify deployment detected',
    description: 'Ensure Netlify security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.netlify.app') || s.url.includes('.netlify.com') || s.url.includes('netlify'))) {
        findings.push(createFinding(
          'APIVET045',
          'Netlify deployment detected',
          'This API is deployed on Netlify. Configure security headers and function authentication.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Configure security headers in netlify.toml. Use Netlify Identity. Secure env vars.' }
        ));
      }

      return findings;
    }
  },

  // Kubernetes / Service Mesh
  {
    id: 'APIVET046',
    title: 'Kubernetes Ingress pattern detected',
    description: 'Ensure Kubernetes Ingress security is configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const specStr = JSON.stringify(spec).toLowerCase();
      const servers = spec.servers || [];

      const isK8s = specStr.includes('kubernetes') || specStr.includes('nginx.ingress') ||
                   specStr.includes('traefik') || specStr.includes('istio') ||
                   servers.some(s => s.url.includes('.svc.cluster.local'));

      if (isK8s) {
        findings.push(createFinding(
          'APIVET046',
          'Kubernetes / Service Mesh pattern detected',
          'This API uses Kubernetes Ingress or Service Mesh. Ensure network policies and mTLS.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Configure TLS at Ingress. Use network policies. Enable mTLS with Istio/Linkerd.' }
        ));
      }

      return findings;
    }
  },

  // Kong Gateway
  {
    id: 'APIVET047',
    title: 'Kong Gateway pattern detected',
    description: 'Ensure Kong security plugins are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const specStr = JSON.stringify(spec).toLowerCase();

      if (specStr.includes('x-kong') || specStr.includes('konghq') || specStr.includes('kong-admin')) {
        findings.push(createFinding(
          'APIVET047',
          'Kong Gateway detected',
          'This API uses Kong Gateway. Ensure security plugins are configured.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Enable key-auth/jwt/oauth2, rate-limiting, ip-restriction, bot-detection.' }
        ));
      }

      return findings;
    }
  },

  // Supabase
  {
    id: 'APIVET050',
    title: 'Supabase API detected',
    description: 'Ensure Supabase Row Level Security is configured',
    severity: 'medium',
    owaspCategory: 'API1:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.supabase.co') || s.url.includes('supabase'))) {
        findings.push(createFinding(
          'APIVET050',
          'Supabase API detected',
          'This API uses Supabase. Ensure Row Level Security (RLS) is enabled on all tables.',
          'medium',
          { owaspCategory: 'API1:2023', filePath, remediation: 'Enable RLS on all tables. Create proper policies. Never expose service_role key.' }
        ));
      }

      return findings;
    }
  },

  // Railway / Render / Fly.io
  {
    id: 'APIVET051',
    title: 'PaaS deployment detected (Railway/Render/Fly.io)',
    description: 'Ensure PaaS security settings are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.railway.app') || s.url.includes('.onrender.com') ||
                          s.url.includes('.fly.dev') || s.url.includes('.up.railway.app'))) {
        findings.push(createFinding(
          'APIVET051',
          'PaaS deployment detected',
          'This API is deployed on a PaaS platform. Secure environment variables and use custom domains.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Secure env vars. Use custom domains with TLS. Enable health checks. Configure auto-scaling.' }
        ));
      }

      return findings;
    }
  },

  // Heroku
  {
    id: 'APIVET052',
    title: 'Heroku deployment detected',
    description: 'Ensure Heroku security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.herokuapp.com') || s.url.includes('heroku'))) {
        findings.push(createFinding(
          'APIVET052',
          'Heroku deployment detected',
          'This API is on Heroku. *.herokuapp.com shares SSL certificates. Use custom domains for production.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Use custom domains with ACM. Enable Private Spaces for sensitive workloads. Secure Config Vars.' }
        ));
      }

      return findings;
    }
  },

  // DigitalOcean
  {
    id: 'APIVET053',
    title: 'DigitalOcean App Platform detected',
    description: 'Ensure DigitalOcean security features are configured',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];

      if (servers.some(s => s.url.includes('.ondigitalocean.app') || s.url.includes('digitalocean'))) {
        findings.push(createFinding(
          'APIVET053',
          'DigitalOcean App Platform detected',
          'This API is on DigitalOcean. Ensure encrypted env vars and consider managed databases.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Use encrypted env vars. Configure custom domains. Use managed databases within VPC.' }
        ));
      }

      return findings;
    }
  },

  // Akamai
  {
    id: 'APIVET054',
    title: 'Akamai API Gateway detected',
    description: 'Ensure Akamai API security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();

      if (servers.some(s => s.url.includes('.akamaized.net') || s.url.includes('.akamaiapis.net') ||
                          s.url.includes('.akamai.com')) || specStr.includes('akamai')) {
        findings.push(createFinding(
          'APIVET054',
          'Akamai API Gateway detected',
          'This API uses Akamai. Ensure Kona Site Defender, Bot Manager, and API Gateway security.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Enable Kona Site Defender, Bot Manager, API Gateway schema validation and rate limiting.' }
        ));
      }

      return findings;
    }
  },

  // Fastly
  {
    id: 'APIVET055',
    title: 'Fastly CDN detected',
    description: 'Ensure Fastly security features are enabled',
    severity: 'info',
    owaspCategory: 'API8:2023',
    check: (spec, filePath) => {
      const findings: Finding[] = [];
      const servers = spec.servers || [];
      const specStr = JSON.stringify(spec).toLowerCase();

      if (servers.some(s => s.url.includes('.fastly.net') || s.url.includes('.global.ssl.fastly.net')) ||
          specStr.includes('fastly')) {
        findings.push(createFinding(
          'APIVET055',
          'Fastly CDN detected',
          'This API uses Fastly. Ensure Next-Gen WAF and rate limiting are configured.',
          'info',
          { owaspCategory: 'API8:2023', filePath, remediation: 'Enable Fastly Next-Gen WAF. Configure Edge Rate Limiting. Use VCL for security logic.' }
        ));
      }

      return findings;
    }
  }
];

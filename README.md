# ApiVet 🩺

API Security Scanner - Static and runtime analysis for API security posture.

## Features

- **OpenAPI/Swagger Spec Analysis** - Scan API specifications for security issues
- **OWASP API Top 10 Coverage** - Checks aligned with OWASP API Security Top 10 2023
- **Security Configuration Audit** - Authentication, authorization, rate limiting
- **API Inventory Discovery** - Find and catalog API endpoints
- **CI/CD Integration** - Exit codes and JSON output for automation

## Installation

```bash
npm install -g apivet
```

## Quick Start

```bash
# Scan an OpenAPI spec file
apivet scan openapi.yaml

# Scan a directory for API specs
apivet scan ./api-specs/

# Live endpoint check with header inspection
apivet check https://api.example.com --headers

# Output as JSON
apivet scan openapi.yaml --json
```

## OWASP API Security Top 10 2023 Coverage

| Risk | Description | Coverage |
|------|-------------|----------|
| API1 | Broken Object Level Authorization | ✅ Static |
| API2 | Broken Authentication | ✅ Static |
| API3 | Broken Object Property Level Authorization | ✅ Static |
| API4 | Unrestricted Resource Consumption | ✅ Static |
| API5 | Broken Function Level Authorization | ✅ Static |
| API6 | Unrestricted Access to Sensitive Business Flows | 🔄 Partial |
| API7 | Server Side Request Forgery | ✅ Static |
| API8 | Security Misconfiguration | ✅ Static + Live |
| API9 | Improper Inventory Management | ✅ Discovery |
| API10 | Unsafe Consumption of APIs | 🔄 Partial |

## Cloud Provider Support

### AWS
- API Gateway (REST & HTTP APIs)
- Lambda authorizers & Cognito
- Request validation
- AppSync GraphQL
- WAF & CloudFront recommendations

### Azure
- API Management (APIM)
- Functions & App Service
- Front Door

### GCP
- Cloud Endpoints
- Cloud Run authentication
- Firebase / Identity Platform

### Other Platforms
- **CDN**: Cloudflare Workers, Akamai, Fastly
- **Serverless**: Vercel, Netlify
- **PaaS**: Heroku, Railway, Render, Fly.io, DigitalOcean
- **BaaS**: Supabase (RLS checks)
- **API Gateways**: Kong
- **Kubernetes**: Ingress, Istio, Service Mesh

## Commands

### `apivet scan <path>`

Scan OpenAPI/Swagger specification files.

```bash
apivet scan api.yaml
apivet scan ./specs/ --recursive
apivet scan api.json --severity high
apivet scan api.json --severity info  # Include informational findings
```

Options:
- `-j, --json` - Output results as JSON
- `-s, --severity <level>` - Filter by minimum severity: `critical`, `high`, `medium`, `low`, `info`
- `-r, --recursive` - Scan directories recursively
- `-o, --output <file>` - Write results to file

### `apivet check <url>`

Perform live security checks on an API endpoint.

```bash
# Basic check (HTTP/HTTPS only)
apivet check https://api.example.com

# Check security headers
apivet check https://api.example.com --headers

# With Bearer token authentication
apivet check https://api.example.com --auth bearer --auth-token "your-token"

# With API key authentication
apivet check https://api.example.com --auth apikey --auth-token "your-api-key"

# With Basic authentication (username:password)
apivet check https://api.example.com --auth basic --auth-token "user:pass"

# Custom timeout
apivet check https://api.example.com --timeout 5000
```

Options:
- `--headers` - Check security headers (disabled by default)
- `--auth <type>` - Authentication type: `basic`, `bearer`, `apikey`
- `--auth-token <token>` - Authentication credential value
- `--auth-header <name>` - Custom header name (default: `Authorization` for bearer/basic, `X-API-Key` for apikey)
- `--timeout <ms>` - Request timeout in milliseconds (default: 10000, minimum: 1)
- `-j, --json` - Output results as JSON

### `apivet inventory <path>`

Discover and catalog API endpoints from source code.

```bash
apivet inventory ./src
apivet inventory ./src --framework express
apivet inventory ./src --json
```

Options:
- `--framework <name>` - Target framework: `express`, `fastify`, `koa`, `hono`, `auto`
- `-j, --json` - Output results as JSON
- `-o, --output <file>` - Write results to file

Supported frameworks:
- **Express** - `app.get()`, `router.get()`, `router.route()`
- **Fastify** - `fastify.get()`, `fastify.route()`
- **Koa** - `router.get()` (koa-router)
- **Hono** - `app.get()`, `new Hono().get()`

## Exit Codes

- `0` - No issues found
- `1` - Issues found
- `2` - Error during scan (invalid input, network error, etc.)

## License

MIT

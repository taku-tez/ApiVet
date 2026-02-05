# ApiVet 🩺

API Security Scanner - Static and runtime analysis for API security posture.

**89 rules | 7 frameworks | SARIF output**

## Features

- **OpenAPI/Swagger Spec Analysis** - Scan API specifications for security issues
- **OWASP API Top 10 Coverage** - Full coverage of OWASP API Security Top 10 2023
- **Cloud Provider Scanning** - Direct scanning of AWS, GCP, and Azure API gateways
- **Security Configuration Audit** - Authentication, authorization, rate limiting
- **API Inventory Discovery** - Find and catalog API endpoints from source code
- **CI/CD Integration** - Exit codes, JSON, and SARIF output for automation

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

# Scan cloud API gateways directly
apivet cloud aws
apivet cloud gcp --project my-project
apivet cloud azure --resource-group mygroup
```

## OWASP API Security Top 10 2023 Coverage

| Risk | Description | Coverage |
|------|-------------|----------|
| API1 | Broken Object Level Authorization | ✅ Static |
| API2 | Broken Authentication | ✅ Static |
| API3 | Broken Object Property Level Authorization | ✅ Static |
| API4 | Unrestricted Resource Consumption | ✅ Static |
| API5 | Broken Function Level Authorization | ✅ Static |
| API6 | Unrestricted Access to Sensitive Business Flows | ✅ Static |
| API7 | Server Side Request Forgery | ✅ Static |
| API8 | Security Misconfiguration | ✅ Static + Live |
| API9 | Improper Inventory Management | ✅ Discovery |
| API10 | Unsafe Consumption of APIs | ✅ Static |

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

# Output formats
apivet scan api.yaml --json
apivet scan api.yaml --sarif -o results.sarif

# Filter rules
apivet scan api.yaml --only-rules APIVET001,APIVET002
apivet scan api.yaml --exclude-rules APIVET010
apivet scan api.yaml --ignore "vendor/**,generated/**"
```

Options:
- `-j, --json` - Output results as JSON
- `--sarif` - Output as SARIF (for GitHub Code Scanning)
- `-s, --severity <level>` - Filter by minimum severity: `critical`, `high`, `medium`, `low`, `info`
- `-r, --recursive` - Scan directories recursively
- `-o, --output <file>` - Write results to file
- `--ignore <patterns>` - Additional glob patterns to ignore (comma-separated)
- `--only-rules <ids>` - Only run specific rules (comma-separated rule IDs)
- `--exclude-rules <ids>` - Exclude specific rules (comma-separated rule IDs)

### `apivet check <url>`

Perform live security checks on an API endpoint.

```bash
# Basic check (HTTP/HTTPS only)
apivet check https://api.example.com

# Specify HTTP method
apivet check https://api.example.com --method POST
apivet check https://api.example.com -m DELETE

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
- `-m, --method <method>` - HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS (default: GET)
- `--headers` - Check security headers (disabled by default)
- `--auth <type>` - Authentication type: `basic`, `bearer`, `apikey`
- `--auth-token <token>` - Authentication credential value
- `--auth-header <name>` - Custom header name (default: `Authorization` for bearer/basic, `X-API-Key` for apikey)
- `--timeout <ms>` - Request timeout in milliseconds (default: 10000, minimum: 1)
- `-j, --json` - Output results as JSON
- `-o, --output <file>` - Write results to file

### `apivet inventory <path>`

Discover and catalog API endpoints from source code.

```bash
apivet inventory ./src
apivet inventory ./src --framework express
apivet inventory ./src --json
apivet inventory ./src --ignore "test/**,__mocks__/**"
```

Options:
- `--framework <name>` - Target framework: `express`, `fastify`, `koa`, `hono`, `nestjs`, `hapi`, `restify`, `auto` (default: auto)
- `-j, --json` - Output results as JSON
- `-o, --output <file>` - Write results to file
- `--ignore <patterns>` - Additional glob patterns to ignore (comma-separated)

Supported frameworks:
- **Express** - `app.get()`, `router.get()`, `router.route()`
- **Fastify** - `fastify.get()`, `fastify.route()`
- **Koa** - `router.get()` (koa-router)
- **Hono** - `app.get()`, `new Hono().get()`
- **NestJS** - `@Controller()`, `@Get()`, `@Post()` decorators
- **Hapi** - `server.route()`, route configuration objects
- **Restify** - `server.get()`, `server.post()`, etc.

### `apivet cloud aws`

Scan AWS API Gateway (REST API V1 and HTTP API V2).

```bash
# Scan all APIs in default region
apivet cloud aws

# Scan specific region
apivet cloud aws --region us-west-2

# Scan specific API
apivet cloud aws --api-id abc123

# Output as JSON
apivet cloud aws --json -o aws-results.json

# Filter by severity
apivet cloud aws --severity high

# Filter rules
apivet cloud aws --only-rules APIVET026,APIVET027
apivet cloud aws --exclude-rules APIVET029
```

Options:
- `-r, --region <region>` - AWS region (default: AWS_REGION env or us-east-1)
- `--api-id <id>` - Scan specific API by ID
- `-j, --json` - Output as JSON
- `-o, --output <file>` - Write results to file
- `-s, --severity <level>` - Filter by severity (critical, high, medium, low, info)
- `--only-rules <ids>` - Only run specific rules (comma-separated rule IDs)
- `--exclude-rules <ids>` - Exclude specific rules (comma-separated rule IDs)

**Prerequisites:** Configure AWS credentials via environment variables, AWS CLI profile, or IAM role.

### `apivet cloud gcp`

Scan GCP API Gateway.

```bash
# Scan all gateways in default project
apivet cloud gcp

# Scan specific project
apivet cloud gcp --project my-project

# Scan specific location
apivet cloud gcp --location us-central1

# Scan specific gateway
apivet cloud gcp --gateway-id my-gateway

# Output as JSON
apivet cloud gcp --json -o gcp-results.json

# Filter by severity
apivet cloud gcp --severity high
```

Options:
- `-p, --project <project>` - GCP project ID (default: GOOGLE_CLOUD_PROJECT env)
- `-l, --location <location>` - Location (default: global)
- `--gateway-id <id>` - Scan specific gateway by ID
- `-j, --json` - Output as JSON
- `-o, --output <file>` - Write results to file
- `-s, --severity <level>` - Filter by severity (critical, high, medium, low, info)
- `--only-rules <ids>` - Only run specific rules (comma-separated rule IDs)
- `--exclude-rules <ids>` - Exclude specific rules (comma-separated rule IDs)

**Prerequisites:** Configure GCP credentials via `GOOGLE_APPLICATION_CREDENTIALS` or `gcloud auth application-default login`.

### `apivet cloud azure`

Scan Azure API Management.

```bash
# Scan all APIM instances in subscription
apivet cloud azure

# Scan specific subscription
apivet cloud azure --subscription-id xxx

# Scan specific resource group
apivet cloud azure --resource-group mygroup

# Scan specific APIM service
apivet cloud azure --service-name myapim

# Scan specific API within a service
apivet cloud azure --service-name myapim --api-id myapi

# Output as JSON
apivet cloud azure --json -o azure-results.json

# Filter by severity
apivet cloud azure --severity high
```

Options:
- `--subscription-id <id>` - Azure subscription ID (default: AZURE_SUBSCRIPTION_ID env)
- `-g, --resource-group <name>` - Resource group name (optional, scans all if not specified)
- `-n, --service-name <name>` - APIM service name (optional)
- `--api-id <id>` - Scan specific API by ID
- `-j, --json` - Output as JSON
- `-o, --output <file>` - Write results to file
- `-s, --severity <level>` - Filter by severity (critical, high, medium, low, info)
- `--only-rules <ids>` - Only run specific rules (comma-separated rule IDs)
- `--exclude-rules <ids>` - Exclude specific rules (comma-separated rule IDs)

**Prerequisites:** Configure Azure credentials via environment variables or Azure CLI login (`az login`).

## SARIF Output for CI/CD

ApiVet supports [SARIF](https://sarifweb.azurewebsites.net/) (Static Analysis Results Interchange Format) output for integration with GitHub Code Scanning and other security tools.

```bash
# Generate SARIF output
apivet scan api.yaml --sarif -o results.sarif

# Combine with severity filter
apivet scan api.yaml --sarif --severity high -o results.sarif
```

### GitHub Actions Integration

```yaml
name: API Security Scan

on: [push, pull_request]

jobs:
  apivet:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      
      - name: Install ApiVet
        run: npm install -g apivet
      
      - name: Scan API specs
        run: apivet scan ./api --sarif -o results.sarif
      
      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

## Rule Categories

| Category | Rules | Count |
|----------|-------|-------|
| OWASP Core | APIVET001-015, 084-089 | 21 |
| Authentication | APIVET016-025 | 10 |
| AWS | APIVET026-029, 034, 036-038, 048-049 | 11 |
| Azure | APIVET030, 039-040, 056-065 | 13 |
| GCP | APIVET031, 041-042, 066-075 | 13 |
| Platforms | APIVET043-047, 050-055 | 13 |
| GraphQL | APIVET076-083 | 8 |
| General | APIVET032-033, 035 | 3 |

Use `--only-rules` or `--exclude-rules` to customize which rules are run:

```bash
# Only run OWASP core rules
apivet scan api.yaml --only-rules APIVET001,APIVET002,APIVET003,APIVET004,APIVET005

# Exclude AWS-specific rules
apivet scan api.yaml --exclude-rules APIVET026,APIVET027,APIVET028,APIVET029
```

## Exit Codes

- `0` - No issues found
- `1` - Issues found
- `2` - Error during scan (invalid input, network error, etc.)

## License

MIT

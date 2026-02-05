import { describe, it, expect } from 'vitest';
import { parseApimPolicy } from '../src/cloud/azure.js';

describe('parseApimPolicy', () => {
  it('should parse validate-jwt policy', () => {
    const xml = `
<policies>
  <inbound>
    <validate-jwt header-name="Authorization" failed-validation-httpcode="401">
      <openid-config url="https://login.microsoftonline.com/tenant/.well-known/openid-configuration" />
      <audiences>
        <audience>api://my-app-id</audience>
      </audiences>
      <issuers>
        <issuer>https://sts.windows.net/tenant/</issuer>
      </issuers>
      <required-claims>
        <claim name="scp" match="any">
          <value>api.read</value>
        </claim>
      </required-claims>
    </validate-jwt>
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasValidateJwt).toBe(true);
    expect(policy.jwtValidation).toBeDefined();
    expect(policy.jwtValidation?.hasAudiences).toBe(true);
    expect(policy.jwtValidation?.hasIssuers).toBe(true);
    expect(policy.jwtValidation?.hasRequiredClaims).toBe(true);
    expect(policy.jwtValidation?.hasOpenIdConfig).toBe(true);
  });

  it('should parse validate-jwt without claims/audiences', () => {
    const xml = `
<policies>
  <inbound>
    <validate-jwt header-name="Authorization" />
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasValidateJwt).toBe(true);
    expect(policy.jwtValidation).toBeDefined();
    expect(policy.jwtValidation?.hasAudiences).toBe(false);
    expect(policy.jwtValidation?.hasIssuers).toBe(false);
    expect(policy.jwtValidation?.hasRequiredClaims).toBe(false);
  });

  it('should parse rate-limit policy', () => {
    const xml = `
<policies>
  <inbound>
    <rate-limit calls="100" renewal-period="60" />
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasRateLimit).toBe(true);
    expect(policy.hasRateLimitByKey).toBe(false);
    expect(policy.rateLimitConfig).toBeDefined();
    expect(policy.rateLimitConfig?.callsPerPeriod).toBe(100);
    expect(policy.rateLimitConfig?.renewalPeriod).toBe(60);
  });

  it('should parse rate-limit-by-key policy', () => {
    const xml = `
<policies>
  <inbound>
    <rate-limit-by-key calls="50" renewal-period="30"
      counter-key="@(context.Subscription?.Key ?? context.Request.IpAddress)" />
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasRateLimit).toBe(false);
    expect(policy.hasRateLimitByKey).toBe(true);
  });

  it('should parse ip-filter policy with allow action', () => {
    const xml = `
<policies>
  <inbound>
    <ip-filter action="allow">
      <address>10.0.0.1</address>
      <address>10.0.0.2</address>
      <address-range from="192.168.0.0" to="192.168.0.255" />
    </ip-filter>
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasIpFilter).toBe(true);
    expect(policy.ipFilter).toBeDefined();
    expect(policy.ipFilter?.action).toBe('allow');
    expect(policy.ipFilter?.addressCount).toBe(3);
  });

  it('should parse ip-filter with forbid action', () => {
    const xml = `
<policies>
  <inbound>
    <ip-filter action="forbid">
      <address>192.168.1.100</address>
    </ip-filter>
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);
    expect(policy.ipFilter?.action).toBe('forbid');
    expect(policy.ipFilter?.addressCount).toBe(1);
  });

  it('should parse CORS policy with specific origins', () => {
    const xml = `
<policies>
  <inbound>
    <cors allow-credentials="true">
      <allowed-origins>
        <origin>https://app.example.com</origin>
        <origin>https://admin.example.com</origin>
      </allowed-origins>
    </cors>
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasCors).toBe(true);
    expect(policy.corsAllowAll).toBe(false);
    expect(policy.corsConfig).toBeDefined();
    expect(policy.corsConfig?.allowedOrigins).toEqual([
      'https://app.example.com',
      'https://admin.example.com'
    ]);
    expect(policy.corsConfig?.allowCredentials).toBe(true);
  });

  it('should detect CORS wildcard origin', () => {
    const xml = `
<policies>
  <inbound>
    <cors>
      <allowed-origins>
        <origin>*</origin>
      </allowed-origins>
    </cors>
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasCors).toBe(true);
    expect(policy.corsAllowAll).toBe(true);
    expect(policy.corsConfig?.allowedOrigins).toEqual(['*']);
    expect(policy.corsConfig?.allowCredentials).toBe(false);
  });

  it('should parse backend authentication policies', () => {
    const xml = `
<policies>
  <inbound>
    <authentication-managed-identity resource="https://backend.api.com" />
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);
    expect(policy.hasAuthenticationManaged).toBe(true);
    expect(policy.hasAuthenticationCertificate).toBe(false);
    expect(policy.hasAuthenticationBasic).toBe(false);
  });

  it('should parse certificate authentication', () => {
    const xml = `
<policies>
  <inbound>
    <authentication-certificate thumbprint="abc123" />
  </inbound>
</policies>`;

    const policy = parseApimPolicy(xml);
    expect(policy.hasAuthenticationCertificate).toBe(true);
  });

  it('should detect logging policies', () => {
    const xml = `
<policies>
  <inbound>
    <trace source="my-api" severity="verbose">
      <message>Request received</message>
    </trace>
  </inbound>
  <outbound>
    <log-to-eventhub logger-id="my-logger">@{
      return context.Request.Body.As<string>();
    }</log-to-eventhub>
  </outbound>
</policies>`;

    const policy = parseApimPolicy(xml);
    expect(policy.hasLog).toBe(true);
  });

  it('should parse cache policies', () => {
    const xml = `
<policies>
  <inbound>
    <cache-lookup vary-by-developer="false" vary-by-developer-groups="false" />
  </inbound>
  <outbound>
    <cache-store duration="3600" />
  </outbound>
</policies>`;

    const policy = parseApimPolicy(xml);
    expect(policy.hasCache).toBe(true);
  });

  it('should parse other policy elements', () => {
    const xml = `
<policies>
  <inbound>
    <check-header name="X-Custom" failed-check-httpcode="401" />
    <set-backend-service base-url="https://new-backend.com" />
    <rewrite-uri template="/v2{context.Request.Url.Path}" />
    <set-header name="X-Request-Id" exists-action="skip">
      <value>@(Guid.NewGuid().ToString())</value>
    </set-header>
    <set-variable name="requestId" value="@(context.RequestId)" />
  </inbound>
  <outbound>
    <return-response>
      <set-status code="200" />
    </return-response>
  </outbound>
  <backend>
    <forward-request />
  </backend>
</policies>`;

    const policy = parseApimPolicy(xml);
    expect(policy.hasCheckHeader).toBe(true);
    expect(policy.hasSetBackendService).toBe(true);
    expect(policy.hasRewriteUri).toBe(true);
    expect(policy.hasForwardRequest).toBe(true);
    expect(policy.hasSetHeader).toBe(true);
    expect(policy.hasSetVariable).toBe(true);
    expect(policy.hasReturnResponse).toBe(true);
    expect(policy.hasMockResponse).toBe(false);
  });

  it('should handle empty/minimal policy XML', () => {
    const xml = `<policies><inbound /><outbound /><backend><forward-request /></backend></policies>`;

    const policy = parseApimPolicy(xml);

    expect(policy.hasValidateJwt).toBe(false);
    expect(policy.hasRateLimit).toBe(false);
    expect(policy.hasIpFilter).toBe(false);
    expect(policy.hasCors).toBe(false);
    expect(policy.jwtValidation).toBeUndefined();
    expect(policy.ipFilter).toBeUndefined();
    expect(policy.corsConfig).toBeUndefined();
    expect(policy.hasForwardRequest).toBe(true);
  });

  it('should parse complex production policy', () => {
    const xml = `
<policies>
  <inbound>
    <base />
    <cors allow-credentials="true">
      <allowed-origins>
        <origin>https://portal.contoso.com</origin>
      </allowed-origins>
      <allowed-methods preflight-result-max-age="300">
        <method>GET</method>
        <method>POST</method>
      </allowed-methods>
      <allowed-headers>
        <header>Authorization</header>
        <header>Content-Type</header>
      </allowed-headers>
    </cors>
    <validate-jwt header-name="Authorization" failed-validation-httpcode="401" require-expiration-time="true">
      <openid-config url="https://login.microsoftonline.com/contoso.onmicrosoft.com/.well-known/openid-configuration" />
      <audiences>
        <audience>api://contoso-api</audience>
      </audiences>
      <issuers>
        <issuer>https://sts.windows.net/contoso-tenant-id/</issuer>
      </issuers>
      <required-claims>
        <claim name="scp" match="any">
          <value>read</value>
          <value>write</value>
        </claim>
      </required-claims>
    </validate-jwt>
    <rate-limit-by-key calls="100" renewal-period="60" counter-key="@(context.Subscription.Key)" />
    <ip-filter action="allow">
      <address-range from="10.0.0.0" to="10.0.255.255" />
    </ip-filter>
    <authentication-managed-identity resource="https://backend.contoso.com" />
  </inbound>
  <backend>
    <forward-request />
  </backend>
  <outbound>
    <base />
    <trace source="contoso-api">
      <message>@(context.Response.StatusCode.ToString())</message>
    </trace>
  </outbound>
</policies>`;

    const policy = parseApimPolicy(xml);

    // Security policies
    expect(policy.hasValidateJwt).toBe(true);
    expect(policy.hasRateLimitByKey).toBe(true);
    expect(policy.hasIpFilter).toBe(true);
    expect(policy.hasCors).toBe(true);
    expect(policy.corsAllowAll).toBe(false);
    expect(policy.hasAuthenticationManaged).toBe(true);
    expect(policy.hasLog).toBe(true);
    expect(policy.hasForwardRequest).toBe(true);

    // JWT details
    expect(policy.jwtValidation?.hasAudiences).toBe(true);
    expect(policy.jwtValidation?.hasIssuers).toBe(true);
    expect(policy.jwtValidation?.hasRequiredClaims).toBe(true);
    expect(policy.jwtValidation?.hasOpenIdConfig).toBe(true);

    // IP filter details
    expect(policy.ipFilter?.action).toBe('allow');
    expect(policy.ipFilter?.addressCount).toBe(1);

    // CORS details
    expect(policy.corsConfig?.allowedOrigins).toEqual(['https://portal.contoso.com']);
    expect(policy.corsConfig?.allowCredentials).toBe(true);
  });
});

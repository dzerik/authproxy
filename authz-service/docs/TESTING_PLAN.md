# Authz-Service: Comprehensive Testing Plan

## Overview

This document defines the complete testing strategy for `authz-service` covering integration, end-to-end, load, security, and chaos engineering tests.

**Version:** 1.0
**Last Updated:** 2025-12-19
**Status:** Draft

---

## Table of Contents

1. [Test Architecture](#1-test-architecture)
2. [Test Stand Configuration](#2-test-stand-configuration)
3. [Integration Tests](#3-integration-tests)
4. [End-to-End Tests](#4-end-to-end-tests)
5. [Load Tests](#5-load-tests)
6. [Security Tests](#6-security-tests)
7. [Chaos Engineering Tests](#7-chaos-engineering-tests)
8. [Test Execution Matrix](#8-test-execution-matrix)
9. [CI/CD Pipeline Integration](#9-cicd-pipeline-integration)
10. [SLO Targets & Acceptance Criteria](#10-slo-targets--acceptance-criteria)

---

## 1. Test Architecture

### 1.1 Component Under Test

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                            authz-service                                     │
├─────────────────────────────────────────────────────────────────────────────┤
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │  JWT Service │  │Policy Service│  │ Cache Service│  │ Audit Service│    │
│  │  - Validation│  │  - Builtin   │  │  - L1 Memory │  │  - Events    │    │
│  │  - JWKS      │  │  - OPA       │  │  - L2 Redis  │  │  - Export    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐    │
│  │Proxy Service │  │Egress Service│  │Token Service │  │ TLS Service  │    │
│  │  - Routing   │  │  - Routing   │  │  - Exchange  │  │  - mTLS      │    │
│  │  - Upstreams │  │  - Creds     │  │  - RFC 8693  │  │  - SPIFFE    │    │
│  └──────────────┘  └──────────────┘  └──────────────┘  └──────────────┘    │
│                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────┐  │
│  │                        HTTP Transport Layer                           │  │
│  │  - Main Server (:8080)      - Proxy Listeners (:8088+)               │  │
│  │  - Management (:15000)      - Egress Listeners (:8090+)              │  │
│  │  - Health (:15020)          - Ready (:15021)                         │  │
│  └──────────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 External Dependencies

| Component | Purpose | Test Strategy |
|-----------|---------|---------------|
| Keycloak | Identity Provider (JWT issuer) | Real instance in compose/k8s |
| PostgreSQL | Keycloak database | Real instance |
| Redis | L2 cache, token store | Real instance |
| OPA | Policy evaluation (sidecar) | Real instance |
| Upstream Services | Backend services via proxy | Mock (WireMock) |
| External APIs | Egress targets | Mock (WireMock) |

### 1.3 Test Categories

```
┌─────────────────────────────────────────────────────────────────┐
│                      Test Pyramid                                │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│                         ╱╲                                       │
│                        ╱  ╲   E2E Tests (20+)                   │
│                       ╱────╲  Full user/service flows           │
│                      ╱      ╲                                    │
│                     ╱────────╲                                   │
│                    ╱Integration╲ Integration Tests (25+)        │
│                   ╱  Tests      ╲ Component interactions        │
│                  ╱────────────────╲                              │
│                 ╱    Unit Tests    ╲ Unit Tests (existing)      │
│                ╱      (100+)        ╲ Isolated logic            │
│               ╱──────────────────────╲                           │
│                                                                  │
│  + Load Tests (15+)    + Security Tests (25+)   + Chaos (20+)   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Test Stand Configuration

### 2.1 Tier 1: Local Development (Podman Compose)

**Purpose:** Fast iteration, local testing, CI integration

```yaml
# tests/compose/docker-compose.yml

version: "3.9"

services:
  # ============== Identity Provider ==============
  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    command: start-dev --import-realm
    environment:
      KEYCLOAK_ADMIN: admin
      KEYCLOAK_ADMIN_PASSWORD: admin
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: keycloak
    ports:
      - "8180:8080"
    volumes:
      - ./keycloak/realm-export.json:/opt/keycloak/data/import/realm.json
    depends_on:
      postgres:
        condition: service_healthy
    networks:
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/health/ready"]
      interval: 10s
      timeout: 5s
      retries: 10

  postgres:
    image: postgres:15-alpine
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: keycloak
    volumes:
      - postgres_data:/var/lib/postgresql/data
    networks:
      - backend
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak"]
      interval: 5s
      timeout: 3s
      retries: 5

  # ============== Cache ==============
  redis:
    image: redis:7-alpine
    command: redis-server --appendonly yes
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
    networks:
      - backend
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 5s
      timeout: 3s
      retries: 5

  # ============== Policy Engine ==============
  opa:
    image: openpolicyagent/opa:0.64.0
    command:
      - run
      - --server
      - --addr=0.0.0.0:8181
      - --log-level=info
      - /policies
    ports:
      - "8181:8181"
    volumes:
      - ./opa/policies:/policies
    networks:
      - backend
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:8181/health"]
      interval: 5s
      timeout: 3s
      retries: 5

  # ============== System Under Test ==============
  authz-service:
    build:
      context: ../../
      dockerfile: Dockerfile
    environment:
      AUTHZ_ENV_NAME: test
      AUTHZ_SERVER_HTTP_ADDR: ":8080"
      AUTHZ_LOGGING_LEVEL: debug
      AUTHZ_JWT_ISSUERS_0_ISSUER_URL: "http://keycloak:8080/realms/test"
      AUTHZ_CACHE_L2_ENABLED: "true"
      AUTHZ_CACHE_L2_REDIS_ADDRESSES: "redis:6379"
      AUTHZ_POLICY_ENGINE: "opa_sidecar"
      AUTHZ_POLICY_OPA_URL: "http://opa:8181"
    ports:
      - "8080:8080"
      - "8088:8088"
      - "15000:15000"
      - "15020:15020"
      - "15021:15021"
    volumes:
      - ./configs:/etc/authz
    depends_on:
      keycloak:
        condition: service_healthy
      redis:
        condition: service_healthy
      opa:
        condition: service_healthy
    networks:
      - frontend
      - backend
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:15020/healthz/ready"]
      interval: 5s
      timeout: 3s
      retries: 10

  # ============== Mock Upstream Services ==============
  mock-user-service:
    image: wiremock/wiremock:3.5.4
    command: --verbose --global-response-templating
    ports:
      - "8081:8080"
    volumes:
      - ./wiremock/user-service:/home/wiremock
    networks:
      - backend

  mock-admin-service:
    image: wiremock/wiremock:3.5.4
    command: --verbose --global-response-templating
    ports:
      - "8082:8080"
    volumes:
      - ./wiremock/admin-service:/home/wiremock
    networks:
      - backend

  mock-external-api:
    image: wiremock/wiremock:3.5.4
    command: --verbose --global-response-templating
    ports:
      - "8083:8080"
    volumes:
      - ./wiremock/external-api:/home/wiremock
    networks:
      - backend

  # ============== Chaos Engineering ==============
  toxiproxy:
    image: ghcr.io/shopify/toxiproxy:2.9.0
    ports:
      - "8474:8474"   # API
      - "18080:18080" # keycloak proxy
      - "16379:16379" # redis proxy
      - "18181:18181" # opa proxy
    networks:
      - backend

  # ============== Observability ==============
  jaeger:
    image: jaegertracing/all-in-one:1.55
    environment:
      COLLECTOR_OTLP_ENABLED: "true"
    ports:
      - "16686:16686"  # UI
      - "4317:4317"    # OTLP gRPC
      - "4318:4318"    # OTLP HTTP
    networks:
      - backend

  prometheus:
    image: prom/prometheus:v2.51.0
    ports:
      - "9090:9090"
    volumes:
      - ./prometheus/prometheus.yml:/etc/prometheus/prometheus.yml
    networks:
      - backend

  grafana:
    image: grafana/grafana:10.4.0
    ports:
      - "3000:3000"
    environment:
      GF_SECURITY_ADMIN_PASSWORD: admin
      GF_AUTH_ANONYMOUS_ENABLED: "true"
    volumes:
      - ./grafana/provisioning:/etc/grafana/provisioning
      - ./grafana/dashboards:/var/lib/grafana/dashboards
    networks:
      - backend

networks:
  frontend:
    driver: bridge
  backend:
    driver: bridge

volumes:
  postgres_data:
  redis_data:
```

### 2.2 Tier 2: Kubernetes (k3s Vanilla)

**Purpose:** Kubernetes-native testing, service discovery, scaling

```yaml
# tests/k8s/base/kustomization.yaml

apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization

resources:
  - namespace.yaml
  - keycloak/
  - redis/
  - opa/
  - authz-service/
  - mock-services/

configMapGenerator:
  - name: authz-environment
    literals:
      - AUTHZ_ENV_NAME=k8s-test
      - AUTHZ_LOGGING_LEVEL=info

secretGenerator:
  - name: authz-secrets
    literals:
      - REDIS_PASSWORD=secret
```

### 2.3 Tier 3: k3s + Istio (mTLS + Service Mesh)

**Purpose:** Service mesh integration, mTLS testing, advanced traffic management

```yaml
# tests/k8s/istio/authz-service-mesh.yaml

apiVersion: security.istio.io/v1
kind: PeerAuthentication
metadata:
  name: default
  namespace: authz-test
spec:
  mtls:
    mode: STRICT

---
apiVersion: security.istio.io/v1
kind: RequestAuthentication
metadata:
  name: authz-jwt-auth
  namespace: authz-test
spec:
  selector:
    matchLabels:
      app: authz-service
  jwtRules:
    - issuer: "http://keycloak.authz-test.svc:8080/realms/test"
      jwksUri: "http://keycloak.authz-test.svc:8080/realms/test/protocol/openid-connect/certs"
      forwardOriginalToken: true

---
apiVersion: security.istio.io/v1
kind: AuthorizationPolicy
metadata:
  name: authz-service-policy
  namespace: authz-test
spec:
  selector:
    matchLabels:
      app: authz-service
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/authz-test/sa/client-service"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/authorize", "/authorize/batch"]

---
apiVersion: networking.istio.io/v1
kind: DestinationRule
metadata:
  name: authz-service-circuit-breaker
  namespace: authz-test
spec:
  host: authz-service
  trafficPolicy:
    connectionPool:
      tcp:
        maxConnections: 100
      http:
        h2UpgradePolicy: UPGRADE
        http1MaxPendingRequests: 100
        http2MaxRequests: 1000
    outlierDetection:
      consecutive5xxErrors: 5
      interval: 30s
      baseEjectionTime: 30s
      maxEjectionPercent: 50
```

### 2.4 Tier 4: k3s + Cilium (eBPF + Network Policies)

**Purpose:** eBPF-based networking, L7 observability, network policies

```yaml
# tests/k8s/cilium/network-policy.yaml

apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: authz-service-policy
  namespace: authz-test
spec:
  endpointSelector:
    matchLabels:
      app: authz-service
  ingress:
    - fromEndpoints:
        - matchLabels:
            app: client-service
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
          rules:
            http:
              - method: POST
                path: "/authorize"
              - method: POST
                path: "/authorize/batch"
              - method: GET
                path: "/health"
  egress:
    - toEndpoints:
        - matchLabels:
            app: keycloak
      toPorts:
        - ports:
            - port: "8080"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            app: redis
      toPorts:
        - ports:
            - port: "6379"
              protocol: TCP
    - toEndpoints:
        - matchLabels:
            app: opa
      toPorts:
        - ports:
            - port: "8181"
              protocol: TCP
```

---

## 3. Integration Tests

### 3.1 JWT Service Integration

| ID | Test Case | Description | Expected Result |
|----|-----------|-------------|-----------------|
| TC-JWT-001 | Valid Keycloak Token | Validate token from Keycloak | Token parsed, claims extracted |
| TC-JWT-002 | Expired Token | Token with past exp claim | 401 Unauthorized, "token expired" |
| TC-JWT-003 | Wrong Audience | Token with different aud | 401 Unauthorized, "invalid audience" |
| TC-JWT-004 | Unknown Issuer | Token from unknown issuer | 401 Unauthorized, "unknown issuer" |
| TC-JWT-005 | JWKS Refresh | Key rotation in Keycloak | New keys fetched, validation continues |
| TC-JWT-006 | Multiple Issuers | Tokens from different issuers | Both validated correctly |
| TC-JWT-007 | Clock Skew | Token with near-future nbf | Accepted within skew tolerance |
| TC-JWT-008 | Invalid Signature | Modified token payload | 401 Unauthorized, "invalid signature" |
| TC-JWT-009 | Algorithm None | Token with alg:none | 401 Unauthorized, rejected |
| TC-JWT-010 | Missing Claims | Token without required claims | 401 Unauthorized, "missing claims" |

### 3.2 Policy Engine Integration

| ID | Test Case | Description | Expected Result |
|----|-----------|-------------|-----------------|
| TC-POL-001 | Builtin Path Match | Request matches path_prefix | Allow/Deny per rule |
| TC-POL-002 | Builtin Role Check | User has required role | Allow if role present |
| TC-POL-003 | Builtin Scope Check | Token has required scope | Allow if scope present |
| TC-POL-004 | Builtin IP Match | Request from allowed CIDR | Allow if IP matches |
| TC-POL-005 | Builtin Time Check | Request during allowed time | Allow if within window |
| TC-POL-006 | Builtin CEL Expression | Custom CEL condition | Evaluated correctly |
| TC-POL-007 | Builtin Deny Rule | deny_if condition | Deny overrides allow |
| TC-POL-008 | OPA Sidecar Basic | OPA returns allow:true | Request allowed |
| TC-POL-009 | OPA Sidecar Deny | OPA returns allow:false | Request denied with reason |
| TC-POL-010 | OPA Timeout | OPA slow response | Fallback engine activated |
| TC-POL-011 | OPA Embedded | Bundle-based policy | Evaluated correctly |
| TC-POL-012 | Fallback Engine | Primary engine fails | Fallback takes over |
| TC-POL-013 | Priority Ordering | Multiple matching rules | Highest priority wins |

### 3.3 Cache Integration

| ID | Test Case | Description | Expected Result |
|----|-----------|-------------|-----------------|
| TC-CACHE-001 | L1 Cache Hit | Same request twice | Second from L1 cache |
| TC-CACHE-002 | L1 Cache Miss | New unique request | Policy engine called |
| TC-CACHE-003 | L2 Redis Hit | L1 miss, L2 hit | Retrieved from Redis |
| TC-CACHE-004 | L2 Redis Miss | Both L1 and L2 miss | Policy engine called |
| TC-CACHE-005 | TTL Expiration | Wait for TTL | Cache entry expired |
| TC-CACHE-006 | Cache Invalidation | POST /cache/invalidate | All entries cleared |
| TC-CACHE-007 | Concurrent Access | Parallel requests | No race conditions |
| TC-CACHE-008 | L1 Eviction | Exceed max_size | LRU entries evicted |
| TC-CACHE-009 | Redis Connection Loss | Redis unavailable | L1 only, no errors |
| TC-CACHE-010 | Cache Key Collision | Different requests, same key | Handled correctly |

### 3.4 Proxy Integration

| ID | Test Case | Description | Expected Result |
|----|-----------|-------------|-----------------|
| TC-PROXY-001 | Route Match | /api/users → user-service | Correct upstream selected |
| TC-PROXY-002 | Header Add | add_headers configured | Headers added to upstream |
| TC-PROXY-003 | Header Remove | remove_headers configured | Headers removed |
| TC-PROXY-004 | Path Rewrite | rewrite_prefix configured | Path rewritten |
| TC-PROXY-005 | Strip Prefix | strip_prefix configured | Prefix stripped |
| TC-PROXY-006 | User Info Headers | add_user_info: true | X-User-ID, X-User-Roles added |
| TC-PROXY-007 | Upstream Timeout | Upstream slow | 504 Gateway Timeout |
| TC-PROXY-008 | Upstream Error | Upstream 500 | Error propagated |
| TC-PROXY-009 | Retry on 503 | Upstream returns 503 | Retried, succeeds |
| TC-PROXY-010 | Auth Required | require_auth: true | 401 without token |
| TC-PROXY-011 | Multi-Upstream | Multiple upstreams | Correct routing |
| TC-PROXY-012 | Rule Sets | rule_sets reference | Routes merged correctly |

### 3.5 Egress Integration

| ID | Test Case | Description | Expected Result |
|----|-----------|-------------|-----------------|
| TC-EGRESS-001 | Route to Target | /github → github target | Correct target selected |
| TC-EGRESS-002 | Bearer Injection | auth.type: bearer | Authorization header added |
| TC-EGRESS-003 | API Key Injection | auth.type: api_key | Custom header added |
| TC-EGRESS-004 | OAuth2 Token | auth.type: oauth2 | Token fetched and injected |
| TC-EGRESS-005 | Token Refresh | Expired token | New token fetched |
| TC-EGRESS-006 | Target Timeout | External API slow | Timeout error |
| TC-EGRESS-007 | Strip Prefix | strip_prefix configured | Prefix stripped |
| TC-EGRESS-008 | mTLS Certificate | TLS client cert | Cert presented |

---

## 4. End-to-End Tests

### 4.1 User Authentication Flows

| ID | Test Case | Description | Steps |
|----|-----------|-------------|-------|
| E2E-USER-001 | Login → API Access | Full user flow | 1. Login to Keycloak<br>2. Get JWT<br>3. Call /api with JWT<br>4. Verify response |
| E2E-USER-002 | Token Refresh | Refresh flow | 1. Get tokens<br>2. Wait near expiry<br>3. Refresh token<br>4. Continue access |
| E2E-USER-003 | Role-Based Access | Admin vs User | 1. Login as user<br>2. Access /admin → 403<br>3. Login as admin<br>4. Access /admin → 200 |
| E2E-USER-004 | Scope-Based Access | Limited scopes | 1. Get token with read scope<br>2. GET → 200<br>3. POST → 403 |
| E2E-USER-005 | Token Expiration | Expired access | 1. Get token<br>2. Wait for expiry<br>3. Call API → 401 |
| E2E-USER-006 | Logout | Token revocation | 1. Logout from Keycloak<br>2. Call API with old token<br>3. Verify rejection |

### 4.2 Service-to-Service Flows (mTLS + JWT)

| ID | Test Case | Description | Steps |
|----|-----------|-------------|-------|
| E2E-S2S-001 | mTLS Authentication | Service with cert | 1. Service A presents mTLS cert<br>2. authz validates SPIFFE ID<br>3. Request forwarded to Service B |
| E2E-S2S-002 | JWT Delegation | Service token | 1. Service A obtains service token<br>2. Token includes service identity<br>3. authz validates and authorizes |
| E2E-S2S-003 | Agent Delegation | LLM agent | 1. User delegates to LLM agent<br>2. Agent token has delegation_chain<br>3. authz validates chain and permissions |
| E2E-S2S-004 | SPIFFE Validation | Workload identity | 1. Extract SPIFFE ID from cert<br>2. Validate trusted domain<br>3. Match against policy |
| E2E-S2S-005 | Cert Rotation | New certificate | 1. Rotate service cert<br>2. Continue requests<br>3. Verify seamless auth |
| E2E-S2S-006 | mTLS + JWT Combined | Dual authentication | 1. Present mTLS cert<br>2. Include JWT header<br>3. Both validated |

### 4.3 Configuration E2E

| ID | Test Case | Description | Steps |
|----|-----------|-------------|-------|
| E2E-CFG-001 | Services Hot-Reload | Update services.yaml | 1. Modify services.yaml<br>2. Wait for reload<br>3. Verify new config active |
| E2E-CFG-002 | Rules Hot-Reload | Update rules.yaml | 1. Add new rule<br>2. Wait for reload<br>3. Test new rule works |
| E2E-CFG-003 | Listener Add | Add listener at runtime | 1. Add listener via config<br>2. Verify listener active<br>3. Test routing |
| E2E-CFG-004 | Invalid Config | Bad config rejected | 1. Submit invalid config<br>2. Verify rejection<br>3. Old config still active |

### 4.4 Proxy E2E

| ID | Test Case | Description | Steps |
|----|-----------|-------------|-------|
| E2E-PROXY-001 | Full Proxy Flow | Complete request cycle | 1. Client → authz-service<br>2. JWT validated<br>3. Policy evaluated<br>4. Proxy to upstream<br>5. Response returned |
| E2E-PROXY-002 | Multi-Service Route | Different upstreams | 1. /api/users → user-service<br>2. /api/admin → admin-service<br>3. Verify both work |
| E2E-PROXY-003 | Error Propagation | Upstream error | 1. Upstream returns 500<br>2. Error passed to client<br>3. Audit event logged |

### 4.5 Egress E2E

| ID | Test Case | Description | Steps |
|----|-----------|-------------|-------|
| E2E-EGRESS-001 | External API Call | Full egress flow | 1. Request to /egress/github<br>2. Token injected<br>3. External API called<br>4. Response returned |
| E2E-EGRESS-002 | OAuth2 Flow | Token exchange | 1. Request egress<br>2. OAuth2 token fetched<br>3. Token injected<br>4. API called |

---

## 5. Load Tests

### 5.1 k6 Test Scripts

```javascript
// tests/load/k6/authorize.js

import http from 'k6/http';
import { check, sleep } from 'k6';
import { Rate, Trend } from 'k6/metrics';

// Custom metrics
const authzLatency = new Trend('authz_latency', true);
const authzErrors = new Rate('authz_errors');

// Test configuration
export const options = {
  scenarios: {
    // Baseline: 1K RPS sustained
    baseline: {
      executor: 'constant-arrival-rate',
      rate: 1000,
      timeUnit: '1s',
      duration: '5m',
      preAllocatedVUs: 100,
      maxVUs: 200,
    },
    // Ramp-up: 0 → 5K RPS
    ramp_up: {
      executor: 'ramping-arrival-rate',
      startRate: 0,
      timeUnit: '1s',
      preAllocatedVUs: 200,
      maxVUs: 500,
      stages: [
        { duration: '2m', target: 1000 },
        { duration: '3m', target: 5000 },
        { duration: '2m', target: 5000 },
        { duration: '1m', target: 0 },
      ],
      startTime: '6m',
    },
    // Spike: Burst to 10K RPS
    spike: {
      executor: 'constant-arrival-rate',
      rate: 10000,
      timeUnit: '1s',
      duration: '30s',
      preAllocatedVUs: 500,
      maxVUs: 1000,
      startTime: '15m',
    },
  },
  thresholds: {
    'http_req_duration{scenario:baseline}': ['p(95)<20', 'p(99)<50'],
    'http_req_duration{scenario:ramp_up}': ['p(95)<50', 'p(99)<100'],
    'http_req_duration{scenario:spike}': ['p(95)<100', 'p(99)<200'],
    'authz_errors': ['rate<0.01'], // <1% error rate
    'authz_latency': ['p(50)<5', 'p(95)<20', 'p(99)<50'],
  },
};

const BASE_URL = __ENV.AUTHZ_URL || 'http://localhost:8080';
const TOKEN = __ENV.JWT_TOKEN;

export default function () {
  const payload = JSON.stringify({
    subject: 'user-123',
    resource: '/api/users',
    action: 'read',
  });

  const params = {
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${TOKEN}`,
    },
  };

  const start = Date.now();
  const res = http.post(`${BASE_URL}/authorize`, payload, params);
  const latency = Date.now() - start;

  authzLatency.add(latency);
  authzErrors.add(res.status !== 200);

  check(res, {
    'status is 200': (r) => r.status === 200,
    'response has allowed': (r) => r.json('allowed') !== undefined,
  });
}
```

### 5.2 Load Test Scenarios

| ID | Scenario | RPS | Duration | SLO Targets |
|----|----------|-----|----------|-------------|
| LOAD-THR-001 | Baseline | 1,000 | 5 min | P95 < 20ms, P99 < 50ms |
| LOAD-THR-002 | Normal | 5,000 | 5 min | P95 < 30ms, P99 < 75ms |
| LOAD-THR-003 | High | 10,000 | 2 min | P95 < 50ms, P99 < 100ms |
| LOAD-THR-004 | Burst | 20,000 | 30 sec | P95 < 100ms, errors < 1% |
| LOAD-LAT-001 | Latency Profile | 5,000 | 10 min | P50 < 5ms, P95 < 20ms |
| LOAD-CACHE-001 | Cache Efficiency | 5,000 | 5 min | Cache hit > 90% |
| LOAD-RES-001 | Memory Stability | 5,000 | 30 min | Memory delta < 100MB |
| LOAD-RES-002 | Connection Pool | 10,000 | 5 min | No conn exhaustion |

### 5.3 Resource Monitoring

```yaml
# Prometheus queries for load test monitoring

# Request latency
histogram_quantile(0.99, sum(rate(authz_request_duration_seconds_bucket[1m])) by (le))

# Error rate
sum(rate(authz_requests_total{status="error"}[1m])) / sum(rate(authz_requests_total[1m]))

# Cache hit ratio
sum(rate(authz_cache_hits_total[1m])) / (sum(rate(authz_cache_hits_total[1m])) + sum(rate(authz_cache_misses_total[1m])))

# Goroutine count
go_goroutines{service="authz-service"}

# Memory usage
go_memstats_alloc_bytes{service="authz-service"}

# Connection pool
redis_pool_active_connections{service="authz-service"}
```

---

## 6. Security Tests

### 6.1 Authentication Security

| ID | Test Case | Attack Vector | Expected Defense |
|----|-----------|---------------|------------------|
| SEC-AUTH-001 | Malformed JWT | Invalid base64 | 401, parse error |
| SEC-AUTH-002 | No Signature | Remove signature | 401, invalid token |
| SEC-AUTH-003 | Wrong Algorithm | HS256 instead of RS256 | 401, algorithm mismatch |
| SEC-AUTH-004 | Algorithm None | alg: "none" | 401, algorithm not allowed |
| SEC-AUTH-005 | Key Confusion | Use public key as HMAC | 401, signature invalid |
| SEC-AUTH-006 | Token Replay | Reuse old token | Based on exp/jti claims |
| SEC-AUTH-007 | Header Injection | Malicious claims | Sanitized, no injection |
| SEC-AUTH-008 | JKU/X5U Attack | Custom key URL | Ignored, use configured JWKS |

### 6.2 Authorization Security

| ID | Test Case | Attack Vector | Expected Defense |
|----|-----------|---------------|------------------|
| SEC-AUTHZ-001 | Privilege Escalation | Modify role claim | Signature validation fails |
| SEC-AUTHZ-002 | Path Traversal | /../admin in path | Normalized, no traversal |
| SEC-AUTHZ-003 | Method Override | X-HTTP-Method-Override | Ignored or blocked |
| SEC-AUTHZ-004 | Scope Bypass | Request higher scope | Policy denies |
| SEC-AUTHZ-005 | Admin Impersonation | Claim admin role | Signature validation |
| SEC-AUTHZ-006 | Null Byte Injection | %00 in path | Sanitized |
| SEC-AUTHZ-007 | Unicode Bypass | %c0%ae for ../ | Normalized |

### 6.3 Input Validation

| ID | Test Case | Attack Vector | Expected Defense |
|----|-----------|---------------|------------------|
| SEC-INPUT-001 | SQL Injection | ' OR 1=1 -- | Not applicable (no SQL) |
| SEC-INPUT-002 | Command Injection | ; ls -la | Sanitized |
| SEC-INPUT-003 | XSS in Headers | <script> in header | Escaped in logs |
| SEC-INPUT-004 | Oversized Request | 10MB body | 413 Payload Too Large |
| SEC-INPUT-005 | Slowloris | Slow headers | Timeout |
| SEC-INPUT-006 | Request Smuggling | CL/TE mismatch | Single parser |

### 6.4 TLS/mTLS Security

| ID | Test Case | Attack Vector | Expected Defense |
|----|-----------|---------------|------------------|
| SEC-TLS-001 | Invalid Client Cert | Self-signed | Rejected |
| SEC-TLS-002 | Expired Cert | Past validity | Rejected |
| SEC-TLS-003 | Wrong CA | Different CA | Rejected |
| SEC-TLS-004 | SPIFFE Spoof | Wrong SPIFFE ID | Domain validation fails |
| SEC-TLS-005 | Cert Chain | Missing intermediate | Chain validated |
| SEC-TLS-006 | Revoked Cert | CRL/OCSP check | Rejected (if enabled) |

### 6.5 Data Protection

| ID | Test Case | Verification | Expected Result |
|----|-----------|--------------|-----------------|
| SEC-DATA-001 | Log Masking | Check logs | Tokens masked as *** |
| SEC-DATA-002 | Audit Sanitization | Audit events | Sensitive data masked |
| SEC-DATA-003 | Error Messages | Error responses | No internal details |
| SEC-DATA-004 | Stack Traces | 500 errors | No stack in response |
| SEC-DATA-005 | Debug Endpoints | /debug/pprof | Disabled in prod |

### 6.6 OWASP ZAP Scan Configuration

```yaml
# tests/security/zap/zap-config.yaml

env:
  contexts:
    - name: "authz-service"
      urls:
        - "http://localhost:8080"
      authentication:
        method: "script"
        parameters:
          script: "keycloak-auth.js"
      users:
        - name: "test-user"
          credentials:
            username: "testuser"
            password: "testpass"

jobs:
  - type: spider
    parameters:
      maxDuration: 5
      maxDepth: 5

  - type: spiderAjax
    parameters:
      maxDuration: 5

  - type: passiveScan-wait
    parameters:
      maxDuration: 10

  - type: activeScan
    parameters:
      maxRuleDurationInMins: 5
      maxScanDurationInMins: 30
      policy: "API-Scan"

  - type: report
    parameters:
      template: "modern"
      reportDir: "/zap/reports"
      reportFile: "authz-security-report"
```

---

## 7. Chaos Engineering Tests

### 7.1 Toxiproxy Configuration

```go
// tests/chaos/toxiproxy_test.go

package chaos

import (
    "testing"
    "time"

    toxiproxy "github.com/Shopify/toxiproxy/v2/client"
)

func TestKeycloakUnavailable(t *testing.T) {
    client := toxiproxy.NewClient("localhost:8474")

    // Create proxy for Keycloak
    proxy, _ := client.CreateProxy("keycloak", "0.0.0.0:18080", "keycloak:8080")

    // Add latency toxic
    proxy.AddToxic("latency", "latency", "downstream", 1, toxiproxy.Attributes{
        "latency": 5000, // 5 second delay
    })

    // Test JWKS refresh fails gracefully
    // ... test code ...

    // Verify cached keys still work
    // ... assertions ...

    // Cleanup
    proxy.Delete()
}

func TestRedisConnectionFailure(t *testing.T) {
    client := toxiproxy.NewClient("localhost:8474")

    proxy, _ := client.CreateProxy("redis", "0.0.0.0:16379", "redis:6379")

    // Simulate connection reset
    proxy.AddToxic("reset", "reset_peer", "downstream", 1, toxiproxy.Attributes{
        "timeout": 0,
    })

    // Test L1 cache still works
    // ... test code ...

    proxy.Delete()
}

func TestOPALatency(t *testing.T) {
    client := toxiproxy.NewClient("localhost:8474")

    proxy, _ := client.CreateProxy("opa", "0.0.0.0:18181", "opa:8181")

    // Add latency beyond timeout
    proxy.AddToxic("slow", "latency", "downstream", 1, toxiproxy.Attributes{
        "latency": 15, // 15ms, beyond 10ms timeout
    })

    // Test fallback engine activation
    // ... test code ...

    proxy.Delete()
}
```

### 7.2 Chaos Test Scenarios

| ID | Scenario | Injection | Expected Behavior |
|----|----------|-----------|-------------------|
| CHAOS-DEP-001 | Keycloak Down | Block port 8080 | Use cached JWKS |
| CHAOS-DEP-002 | JWKS Latency | 5s delay | Refresh fails, cache used |
| CHAOS-DEP-003 | OPA Unavailable | Block port 8181 | Fallback engine |
| CHAOS-DEP-004 | OPA Slow | 100ms latency | Circuit breaker opens |
| CHAOS-DEP-005 | Redis Down | Block port 6379 | L1 cache only |
| CHAOS-DEP-006 | Redis Latency | 500ms delay | L1 cache preferred |
| CHAOS-DEP-007 | Upstream Timeout | 60s delay | 504 returned |
| CHAOS-DEP-008 | Upstream 50% Fail | Random 503 | Retry succeeds |
| CHAOS-NET-001 | Packet Loss 10% | Network toxic | Retries handle |
| CHAOS-NET-002 | Network Partition | Split brain | Graceful handling |
| CHAOS-RES-001 | Memory Pressure | Limit to 256MB | Graceful degradation |
| CHAOS-RES-002 | CPU Throttle | Limit to 0.5 CPU | Latency increase |
| CHAOS-RESIL-001 | Circuit Open | Trigger 5 failures | Circuit opens |
| CHAOS-RESIL-002 | Circuit Recovery | Wait timeout | Circuit half-opens |
| CHAOS-RESIL-003 | Rate Limit | Exceed 100 RPS | 429 responses |
| CHAOS-GRACE-001 | Drain Mode | POST /drain | New connections rejected |
| CHAOS-GRACE-002 | Graceful Shutdown | SIGTERM | In-flight complete |

### 7.3 Litmus Chaos (Kubernetes)

```yaml
# tests/chaos/litmus/pod-cpu-hog.yaml

apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: authz-cpu-chaos
  namespace: authz-test
spec:
  engineState: "active"
  appinfo:
    appns: "authz-test"
    applabel: "app=authz-service"
    appkind: "deployment"
  chaosServiceAccount: litmus-admin
  experiments:
    - name: pod-cpu-hog
      spec:
        components:
          env:
            - name: CPU_CORES
              value: "1"
            - name: TOTAL_CHAOS_DURATION
              value: "60"
            - name: CPU_LOAD
              value: "100"

---
apiVersion: litmuschaos.io/v1alpha1
kind: ChaosEngine
metadata:
  name: authz-pod-network-loss
  namespace: authz-test
spec:
  engineState: "active"
  appinfo:
    appns: "authz-test"
    applabel: "app=authz-service"
    appkind: "deployment"
  chaosServiceAccount: litmus-admin
  experiments:
    - name: pod-network-loss
      spec:
        components:
          env:
            - name: NETWORK_INTERFACE
              value: "eth0"
            - name: NETWORK_PACKET_LOSS_PERCENTAGE
              value: "50"
            - name: TOTAL_CHAOS_DURATION
              value: "60"
```

---

## 8. Test Execution Matrix

### 8.1 Environment vs Test Type

| Test Type | Local (Compose) | CI (GitHub Actions) | k3s Vanilla | k3s + Istio | k3s + Cilium |
|-----------|-----------------|---------------------|-------------|-------------|--------------|
| Unit Tests | ✅ | ✅ | - | - | - |
| Integration | ✅ | ✅ | ✅ | ✅ | ✅ |
| E2E User Flow | ✅ | ✅ | ✅ | ✅ | ✅ |
| E2E S2S (mTLS) | - | - | ✅ | ✅ | ✅ |
| E2E S2S (JWT) | ✅ | ✅ | ✅ | ✅ | ✅ |
| Load Basic | ✅ | ✅ (short) | ✅ | ✅ | ✅ |
| Load Full | - | - | ✅ | ✅ | ✅ |
| Security OWASP | ✅ | ✅ | ✅ | ✅ | ✅ |
| Security Custom | ✅ | ✅ | ✅ | ✅ | ✅ |
| Chaos Basic | ✅ (Toxiproxy) | - | ✅ | ✅ | ✅ |
| Chaos Full | - | - | ✅ (Litmus) | ✅ (Litmus) | ✅ (Litmus) |

### 8.2 Test Execution Commands

```bash
# Unit Tests
go test ./... -short -race -cover

# Integration Tests (requires compose up)
go test ./tests/integration/... -v -tags=integration

# E2E Tests
go test ./tests/e2e/... -v -tags=e2e

# Load Tests (k6)
k6 run --env AUTHZ_URL=http://localhost:8080 \
       --env JWT_TOKEN=$TOKEN \
       tests/load/k6/authorize.js

# Security Scan (OWASP ZAP)
docker run -v $(pwd)/tests/security:/zap/wrk:rw \
  -t ghcr.io/zaproxy/zaproxy:stable zap.sh \
  -cmd -autorun /zap/wrk/zap/zap-config.yaml

# Chaos Tests
go test ./tests/chaos/... -v -tags=chaos

# Full Test Suite (CI)
make test-all
```

---

## 9. CI/CD Pipeline Integration

### 9.1 GitHub Actions Workflow

```yaml
# .github/workflows/test.yml

name: Test Suite

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

env:
  GO_VERSION: "1.22"
  K6_VERSION: "v0.50.0"

jobs:
  unit-tests:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}

      - name: Run Unit Tests
        run: go test ./... -short -race -coverprofile=coverage.out

      - name: Upload Coverage
        uses: codecov/codecov-action@v4
        with:
          file: coverage.out

  integration-tests:
    runs-on: ubuntu-latest
    needs: unit-tests
    services:
      redis:
        image: redis:7-alpine
        ports:
          - 6379:6379
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}

      - name: Start Test Infrastructure
        run: |
          docker-compose -f tests/compose/docker-compose.yml up -d
          sleep 30  # Wait for services

      - name: Run Integration Tests
        run: go test ./tests/integration/... -v -tags=integration

      - name: Stop Infrastructure
        if: always()
        run: docker-compose -f tests/compose/docker-compose.yml down

  e2e-tests:
    runs-on: ubuntu-latest
    needs: integration-tests
    steps:
      - uses: actions/checkout@v4

      - name: Set up Go
        uses: actions/setup-go@v5
        with:
          go-version: ${{ env.GO_VERSION }}

      - name: Start Full Stack
        run: |
          docker-compose -f tests/compose/docker-compose.yml up -d
          ./tests/scripts/wait-for-keycloak.sh

      - name: Run E2E Tests
        run: go test ./tests/e2e/... -v -tags=e2e

      - name: Stop Stack
        if: always()
        run: docker-compose -f tests/compose/docker-compose.yml down

  security-scan:
    runs-on: ubuntu-latest
    needs: unit-tests
    steps:
      - uses: actions/checkout@v4

      - name: Run gosec
        uses: securego/gosec@master
        with:
          args: ./...

      - name: Run Trivy
        uses: aquasecurity/trivy-action@master
        with:
          scan-type: 'fs'
          scan-ref: '.'
          severity: 'CRITICAL,HIGH'

  load-test:
    runs-on: ubuntu-latest
    needs: e2e-tests
    steps:
      - uses: actions/checkout@v4

      - name: Set up k6
        run: |
          wget -q https://github.com/grafana/k6/releases/download/${{ env.K6_VERSION }}/k6-${{ env.K6_VERSION }}-linux-amd64.tar.gz
          tar -xzf k6-*.tar.gz
          sudo mv k6-*/k6 /usr/local/bin/

      - name: Start Services
        run: docker-compose -f tests/compose/docker-compose.yml up -d

      - name: Get Test Token
        id: token
        run: echo "token=$(./tests/scripts/get-test-token.sh)" >> $GITHUB_OUTPUT

      - name: Run Load Test (Short)
        run: |
          k6 run --env AUTHZ_URL=http://localhost:8080 \
                 --env JWT_TOKEN=${{ steps.token.outputs.token }} \
                 --duration 1m \
                 tests/load/k6/authorize.js
```

### 9.2 Test Reports

```yaml
# Test report generation
reports:
  - name: "Unit Test Coverage"
    format: HTML
    path: coverage.html

  - name: "Integration Test Results"
    format: JUnit XML
    path: integration-results.xml

  - name: "Load Test Results"
    format: HTML
    path: k6-report.html

  - name: "Security Scan"
    format: SARIF
    path: security-results.sarif
```

---

## 10. SLO Targets & Acceptance Criteria

### 10.1 Performance SLOs

| Metric | Target | Critical Threshold |
|--------|--------|-------------------|
| Availability | 99.9% | 99.5% |
| P50 Latency | < 5ms | < 10ms |
| P95 Latency | < 20ms | < 50ms |
| P99 Latency | < 50ms | < 100ms |
| P99.9 Latency | < 100ms | < 200ms |
| Error Rate | < 0.1% | < 1% |
| Cache Hit Ratio | > 90% | > 80% |

### 10.2 Security Requirements

| Requirement | Criteria |
|-------------|----------|
| No Critical Vulnerabilities | Trivy scan passes |
| No High OWASP Issues | ZAP scan passes |
| Sensitive Data Masked | Log audit passes |
| mTLS Enforced | Istio strict mode |
| JWT Validation | All attack vectors blocked |

### 10.3 Chaos Engineering SLOs

| Scenario | Recovery Time | Data Loss |
|----------|---------------|-----------|
| Single Dependency Failure | < 30s | None |
| Multiple Dependency Failure | < 60s | None |
| Full Network Partition | < 5m | None |
| Pod Restart | < 10s | None |
| Node Failure (k8s) | < 30s | None |

### 10.4 Acceptance Criteria Summary

```
✅ All unit tests pass (coverage > 80%)
✅ All integration tests pass
✅ All E2E tests pass
✅ Load test SLOs met (P99 < 50ms @ 5K RPS)
✅ Security scan: 0 critical/high findings
✅ Chaos tests: Recovery within SLO
✅ No memory leaks (30min stability test)
✅ mTLS + JWT validation working (k8s)
```

---

## Appendix A: Test Data & Fixtures

### A.1 Keycloak Realm Configuration

```json
{
  "realm": "test",
  "enabled": true,
  "users": [
    {
      "username": "testuser",
      "enabled": true,
      "credentials": [{"type": "password", "value": "testpass"}],
      "realmRoles": ["user"]
    },
    {
      "username": "adminuser",
      "enabled": true,
      "credentials": [{"type": "password", "value": "adminpass"}],
      "realmRoles": ["user", "admin"]
    },
    {
      "username": "service-a",
      "enabled": true,
      "serviceAccountClientId": "service-a-client"
    }
  ],
  "clients": [
    {
      "clientId": "authz-service",
      "enabled": true,
      "publicClient": false,
      "secret": "authz-secret",
      "standardFlowEnabled": true,
      "serviceAccountsEnabled": true
    }
  ]
}
```

### A.2 Test Policy Rules

```yaml
# tests/fixtures/rules.yaml
version: "1.0"
rules:
  - name: "allow-health"
    priority: 1000
    enabled: true
    conditions:
      paths: ["/health", "/ready", "/live"]
      methods: ["GET"]
    effect: allow

  - name: "require-auth"
    priority: 100
    enabled: true
    conditions:
      paths: ["/api/*"]
    effect: allow
    require_auth: true

  - name: "admin-only"
    priority: 90
    enabled: true
    conditions:
      paths: ["/admin/*"]
      roles: ["admin"]
    effect: allow
```

---

## Appendix B: Directory Structure

```
tests/
├── compose/
│   ├── docker-compose.yml
│   ├── keycloak/
│   │   └── realm-export.json
│   ├── opa/
│   │   └── policies/
│   ├── wiremock/
│   │   ├── user-service/
│   │   ├── admin-service/
│   │   └── external-api/
│   ├── prometheus/
│   │   └── prometheus.yml
│   └── grafana/
│       ├── provisioning/
│       └── dashboards/
├── k8s/
│   ├── base/
│   ├── istio/
│   └── cilium/
├── integration/
│   ├── jwt_test.go
│   ├── policy_test.go
│   ├── cache_test.go
│   ├── proxy_test.go
│   └── egress_test.go
├── e2e/
│   ├── user_flow_test.go
│   ├── s2s_flow_test.go
│   └── config_reload_test.go
├── load/
│   └── k6/
│       ├── authorize.js
│       ├── proxy.js
│       └── mixed.js
├── security/
│   ├── zap/
│   │   └── zap-config.yaml
│   └── custom/
│       ├── jwt_attacks_test.go
│       └── input_validation_test.go
├── chaos/
│   ├── toxiproxy_test.go
│   └── litmus/
│       ├── pod-cpu-hog.yaml
│       └── pod-network-loss.yaml
├── fixtures/
│   ├── rules.yaml
│   ├── tokens/
│   └── certs/
└── scripts/
    ├── wait-for-keycloak.sh
    ├── get-test-token.sh
    └── setup-test-data.sh
```

---

## Version History

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-12-19 | Claude | Initial comprehensive plan |

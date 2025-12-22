# Архитектура Auth-Portal

Этот документ описывает архитектуру системы auth-portal, включая компоненты, потоки данных и взаимодействие между модулями.

## Содержание

- [Обзор архитектуры](#обзор-архитектуры)
- [Компоненты системы](#компоненты-системы)
- [Потоки аутентификации](#потоки-аутентификации)
- [Интеграция с nginx](#интеграция-с-nginx)
- [Session Management](#session-management)
- [Конфигурация](#конфигурация)

---

## Обзор архитектуры

Auth-portal представляет собой OIDC-совместимый портал аутентификации, который работает в связке с nginx для защиты backend-сервисов.

### Общая архитектура компонентов

```mermaid
graph TB
    subgraph "Client Layer"
        Browser[Браузер пользователя]
    end

    subgraph "Reverse Proxy Layer"
        Nginx[Nginx]
    end

    subgraph "Auth-Portal Service"
        AuthHandler[Auth Handler<br/>OAuth2 Flow]
        PortalHandler[Portal Handler<br/>Service Directory]
        ForwardAuth[Forward Auth Handler<br/>nginx auth_request]
        SessionMgr[Session Manager]
        IDPMgr[IDP Manager<br/>OIDC Client]
    end

    subgraph "Backend Services"
        Service1[Grafana]
        Service2[Kibana]
        Service3[Prometheus]
        ServiceN[Other Services]
    end

    subgraph "External Services"
        Keycloak[Keycloak<br/>OIDC Provider]
        Redis[(Redis<br/>Session Store)]
    end

    Browser -->|HTTP/HTTPS| Nginx
    Nginx -->|auth_request| ForwardAuth
    Nginx -->|proxy_pass /login,/callback| AuthHandler
    Nginx -->|proxy_pass /portal| PortalHandler
    Nginx -->|proxy_pass /service/*| Service1
    Nginx -->|proxy_pass /service/*| Service2

    AuthHandler --> IDPMgr
    ForwardAuth --> SessionMgr
    PortalHandler --> SessionMgr

    IDPMgr -->|OIDC| Keycloak
    SessionMgr -.->|optional| Redis

    ForwardAuth -->|inject headers| Nginx
```

### Режимы работы

Auth-portal поддерживает два режима работы:

**Portal Mode (mode: portal)**
- После аутентификации показывается портал с доступными сервисами
- Пользователь выбирает сервис из списка
- Каждый сервис может иметь свои права доступа

**Single-Service Mode (mode: single-service)**
- После аутентификации происходит редирект на целевой сервис
- Упрощенный вариант для случая одного backend-сервиса

---

## Компоненты системы

### 1. Auth Handler

Отвечает за OAuth2/OIDC аутентификацию:

- **Инициация OAuth2 flow** — генерация authorization URL с state/nonce
- **Обработка callback** — обмен code на токены
- **Social login** — поддержка kc_idp_hint для social провайдеров
- **Logout** — завершение сессии и редирект на logout endpoint Keycloak
- **Dev mode** — mock-аутентификация с профилями пользователей

### 2. Portal Handler

Управляет сервисным порталом:

- **Service directory** — отображение списка доступных сервисов
- **Service redirect** — переход на выбранный сервис
- **User context** — передача информации о пользователе в UI

### 3. Forward Auth Handler

Реализует nginx auth_request интеграцию:

- **Валидация сессии** — проверка активной сессии пользователя
- **Token refresh** — автоматическое обновление токенов при необходимости
- **User headers** — установка заголовков с user context для backend
- **Introspection** — проверка валидности токена через Keycloak

Передаваемые заголовки:
```
X-Auth-Request-User: user-id
X-Auth-Request-Email: user@example.com
X-Auth-Request-Roles: ["admin", "user"]
X-Auth-Request-Groups: ["developers"]
X-Auth-Request-Access-Token: eyJhbGc...
```

### 4. Session Manager

Управляет пользовательскими сессиями:

**Поддерживаемые storage backends:**

- **Cookie Store** (stateless)
  - Зашифрованные AES-256 cookie
  - Максимальный размер ~4KB
  - Не требует внешних зависимостей

- **JWT Store** (stateless)
  - Подписанные JWT токены в cookie
  - Поддержка HS256/RS256
  - Больший размер токена, чем cookie

- **Redis Store** (stateful)
  - Централизованное хранение
  - Поддержка Redis Cluster/Sentinel
  - Масштабируемость и распределенность

### 5. IDP Manager

Интеграция с OIDC провайдерами:

- **Discovery** — автоматическое получение OIDC endpoints
- **Token exchange** — обмен authorization code на токены
- **Token refresh** — обновление access token через refresh token
- **UserInfo** — получение информации о пользователе
- **Token verification** — валидация JWT подписи и claims

### 6. Nginx Generator

Генерация конфигурации nginx:

- **Template-based** — использует Go templates
- **Service locations** — автоматическое создание location блоков
- **Auth_request integration** — настройка forward auth
- **Headers injection** — передача user context в backend
- **URL rewriting** — поддержка path rewriting

---

## Потоки аутентификации

### OAuth2/OIDC Authentication Flow

```mermaid
sequenceDiagram
    actor User as Пользователь
    participant Browser as Браузер
    participant Nginx as Nginx
    participant Portal as Auth-Portal
    participant KC as Keycloak

    User->>Browser: Переход на защищенный сервис
    Browser->>Nginx: GET /service
    Nginx->>Portal: auth_request GET /auth
    Portal-->>Nginx: 401 Unauthorized
    Nginx->>Browser: 302 Redirect /login?redirect=/service

    Browser->>Nginx: GET /login?redirect=/service
    Nginx->>Portal: GET /login
    Portal->>Browser: Страница выбора провайдера

    User->>Browser: Клик "Sign in with Keycloak"
    Browser->>Nginx: GET /login/keycloak
    Nginx->>Portal: GET /login/keycloak

    Note over Portal: Генерация state, nonce<br/>Сохранение в StateStore

    Portal->>Browser: 302 Redirect to Keycloak<br/>+ state, nonce, scope
    Browser->>KC: GET /auth?client_id=...&state=...

    KC->>Browser: Login form
    User->>Browser: Ввод credentials
    Browser->>KC: POST credentials

    KC->>Browser: 302 Redirect to callback<br/>+ code, state
    Browser->>Nginx: GET /callback?code=...&state=...
    Nginx->>Portal: GET /callback

    Portal->>Portal: Валидация state
    Portal->>KC: POST /token<br/>exchange code for tokens
    KC-->>Portal: access_token, id_token, refresh_token

    Portal->>KC: GET /userinfo<br/>+ access_token
    KC-->>Portal: User info (email, roles, etc.)

    Portal->>Portal: Создание сессии<br/>Сохранение в SessionStore
    Portal->>Browser: Set-Cookie: _auth_session<br/>302 Redirect /service

    Browser->>Nginx: GET /service + Cookie
    Nginx->>Portal: auth_request GET /auth + Cookie
    Portal->>Portal: Валидация сессии
    Portal-->>Nginx: 200 OK + User headers
    Nginx->>Browser: Доступ к сервису
```

### Social Login Flow

```mermaid
sequenceDiagram
    actor User as Пользователь
    participant Browser as Браузер
    participant Portal as Auth-Portal
    participant KC as Keycloak
    participant Social as Social Provider<br/>(Google/GitHub)

    User->>Browser: Клик "Sign in with Google"
    Browser->>Portal: GET /login/social/google

    Note over Portal: Добавление kc_idp_hint=google<br/>в authorization URL

    Portal->>Browser: 302 Redirect to Keycloak<br/>+ kc_idp_hint=google
    Browser->>KC: GET /auth?kc_idp_hint=google

    Note over KC: Автоматический редирект<br/>на Google OAuth2

    KC->>Browser: 302 Redirect to Google
    Browser->>Social: GET /oauth2/authorize

    Social->>Browser: Login page
    User->>Browser: Google login
    Browser->>Social: POST credentials

    Social->>Browser: 302 Redirect to Keycloak callback
    Browser->>KC: GET /broker/google/endpoint?code=...

    KC->>Social: Exchange code for Google token
    Social-->>KC: Google access_token
    KC->>Social: GET userinfo
    Social-->>KC: Google user data

    KC->>KC: Create/update Keycloak user<br/>Link to Google identity

    KC->>Browser: 302 Redirect to portal callback
    Browser->>Portal: GET /callback?code=...

    Note over Portal: Стандартный OIDC flow<br/>из предыдущей диаграммы
```

### Forward Auth Flow (nginx auth_request)

```mermaid
sequenceDiagram
    participant Browser as Браузер
    participant Nginx as Nginx
    participant Portal as Auth-Portal<br/>ForwardAuth Handler
    participant Backend as Backend Service<br/>(Grafana/Kibana)
    participant Session as Session Store<br/>(Cookie/Redis)

    Browser->>Nginx: GET /grafana/dashboard + Cookie

    Note over Nginx: auth_request directive<br/>для /grafana location

    Nginx->>Portal: GET /auth<br/>Cookie: _auth_session<br/>X-Forwarded-Uri: /grafana/dashboard

    Portal->>Session: Get session by cookie
    Session-->>Portal: User session data

    alt Сессия активна и токен валиден
        Portal->>Portal: Проверка expiration<br/>access_token

        alt Токен скоро истечет
            Portal->>Keycloak: POST /token<br/>grant_type=refresh_token
            Keycloak-->>Portal: Новый access_token
            Portal->>Session: Update session
        end

        Portal-->>Nginx: 200 OK<br/>X-Auth-Request-User: user-id<br/>X-Auth-Request-Email: user@example.com<br/>X-Auth-Request-Roles: ["admin"]

        Note over Nginx: Копирование заголовков<br/>auth_request_set

        Nginx->>Backend: GET /dashboard<br/>X-User-Email: user@example.com<br/>X-User-Roles: ["admin"]
        Backend-->>Nginx: Dashboard HTML
        Nginx-->>Browser: Dashboard page

    else Сессия отсутствует или невалидна
        Portal-->>Nginx: 401 Unauthorized

        Note over Nginx: error_page 401 = @auth_redirect

        Nginx->>Browser: 302 Redirect<br/>/login?redirect=/grafana/dashboard
    end
```

### Token Refresh Flow

```mermaid
sequenceDiagram
    participant Portal as Auth-Portal
    participant Session as Session Store
    participant KC as Keycloak

    Note over Portal: Периодическая проверка<br/>при каждом auth request

    Portal->>Session: Get session
    Session-->>Portal: access_token, refresh_token,<br/>expires_at

    Portal->>Portal: Check if token expires soon<br/>(< refresh_threshold)

    alt Токен скоро истечет
        Portal->>KC: POST /token<br/>grant_type=refresh_token<br/>refresh_token=...

        alt Refresh успешен
            KC-->>Portal: new access_token,<br/>new refresh_token,<br/>expires_in

            Portal->>Session: Update session<br/>с новыми токенами
            Session-->>Portal: OK

            Portal->>Portal: Continue with new token
        else Refresh failed
            KC-->>Portal: 401 Invalid refresh_token
            Portal->>Session: Delete session
            Portal->>Portal: Требуется повторная аутентификация
        end
    else Токен еще валиден
        Portal->>Portal: Continue with existing token
    end
```

---

## Интеграция с nginx

### Архитектура nginx интеграции

```mermaid
graph LR
    subgraph "Nginx Configuration"
        Main[Main Server Block]
        AuthReq[auth_request /_auth]
        AuthRedirect[error_page 401 @auth_redirect]

        subgraph "Service Locations"
            Loc1[location /grafana/]
            Loc2[location /kibana/]
            Loc3[location /prometheus/]
        end

        subgraph "Auth Endpoints"
            InternalAuth[location /_auth<br/>internal]
            LoginLoc[location /login]
            CallbackLoc[location /callback]
        end
    end

    subgraph "Auth-Portal Backend"
        AuthPort[auth-portal:8080]
    end

    Main --> Loc1
    Main --> Loc2
    Main --> Loc3

    Loc1 --> AuthReq
    Loc2 --> AuthReq
    Loc3 --> AuthReq

    AuthReq --> InternalAuth
    AuthRedirect --> LoginLoc

    InternalAuth -.proxy_pass.-> AuthPort
    LoginLoc -.proxy_pass.-> AuthPort
    CallbackLoc -.proxy_pass.-> AuthPort
```

### Генерация nginx.conf

Auth-portal автоматически генерирует конфигурацию nginx на основе `config.yaml`:

**Процесс генерации:**

1. **Загрузка конфигурации** — чтение `config.yaml`
2. **Template processing** — обработка `nginx.conf.tmpl`
3. **Service locations** — генерация блоков для каждого сервиса
4. **Auth_request setup** — настройка forward auth
5. **Headers mapping** — конфигурация передачи заголовков
6. **Validation** — проверка синтаксиса (если nginx установлен)

**Пример генерации location для сервиса:**

Из конфигурации:
```yaml
services:
  - name: grafana
    display_name: "Grafana"
    location: /grafana/
    upstream: http://grafana:3000
    auth_required: true
    rewrite: "^/grafana/(.*) /$1 break"
    headers:
      add:
        X-User-Email: "{{.User.Email}}"
        X-User-Roles: "{{.User.Roles | join \",\"}}"
      remove:
        - Authorization
```

Генерируется nginx location:
```nginx
# Service: grafana
location /grafana/ {
    # Authentication required
    auth_request /_auth;
    auth_request_set $auth_user $upstream_http_x_auth_request_user;
    auth_request_set $auth_email $upstream_http_x_auth_request_email;
    auth_request_set $auth_roles $upstream_http_x_auth_request_roles;

    error_page 401 = @auth_redirect;

    # URL rewrite
    rewrite ^/grafana/(.*) /$1 break;

    proxy_pass http://grafana_backend;
    proxy_set_header X-User-Email $auth_email;
    proxy_set_header X-User-Roles $auth_roles;
    # Remove Authorization header
    proxy_set_header Authorization "";
}
```

### User Context Headers

Auth-portal устанавливает следующие заголовки через `auth_request_set`:

| Заголовок | Описание | Пример |
|-----------|----------|--------|
| `X-Auth-Request-User` | User ID из OIDC | `123e4567-e89b-12d3-a456-426614174000` |
| `X-Auth-Request-Email` | Email пользователя | `user@example.com` |
| `X-Auth-Request-Roles` | Список ролей (JSON array) | `["admin","user"]` |
| `X-Auth-Request-Groups` | Список групп (JSON array) | `["developers","ops"]` |
| `X-Auth-Request-Tenant` | Tenant ID (если есть) | `acme-corp` |
| `X-Auth-Request-Access-Token` | JWT access token | `eyJhbGciOiJSUzI1NiIs...` |

Backend-сервисы могут использовать эти заголовки для:
- Идентификации пользователя
- Авторизации на уровне приложения
- Аудита действий пользователя
- Интеграции с внутренними системами

---

## Session Management

### Архитектура Session Store

```mermaid
graph TB
    subgraph "Session Manager"
        Manager[Session Manager]
        Interface[Store Interface]
    end

    subgraph "Storage Implementations"
        Cookie[Cookie Store<br/>Encrypted AES-256]
        JWT[JWT Store<br/>Signed HS256/RS256]
        Redis[Redis Store<br/>Cluster/Sentinel]
    end

    subgraph "Session Data"
        Data[Session<br/>- ID<br/>- UserInfo<br/>- Tokens<br/>- ExpiresAt]
    end

    Manager --> Interface
    Interface --> Cookie
    Interface --> JWT
    Interface --> Redis

    Cookie -.-> Data
    JWT -.-> Data
    Redis -.-> Data
```

### Cookie Store (stateless)

**Особенности:**
- Все данные хранятся в зашифрованном cookie
- AES-256-GCM encryption
- Ограничение размера ~4KB (browser limit)
- Не требует внешних зависимостей

**Структура cookie:**
```
_auth_session = encrypt(
  session_id,
  user_id,
  email,
  access_token,
  refresh_token,
  expires_at
)
```

**Конфигурация:**
```yaml
session:
  store: cookie
  encryption:
    enabled: true
    key: ${ENCRYPTION_KEY}  # 32 bytes
  cookie:
    max_size: 4096
```

### JWT Store (stateless)

**Особенности:**
- Подписанный JWT токен в cookie
- Поддержка HS256 (symmetric) и RS256 (asymmetric)
- Больший размер, чем cookie store
- Токен можно валидировать без обращения к auth-portal

**JWT Claims:**
```json
{
  "sub": "user-id",
  "email": "user@example.com",
  "roles": ["admin", "user"],
  "groups": ["developers"],
  "access_token": "...",
  "refresh_token": "...",
  "exp": 1234567890,
  "iat": 1234567890
}
```

**Конфигурация:**
```yaml
session:
  store: jwt
  jwt:
    algorithm: HS256
    signing_key: ${JWT_SIGNING_KEY}
    # Или для RS256:
    # algorithm: RS256
    # private_key: /certs/jwt-private.pem
    # public_key: /certs/jwt-public.pem
```

### Redis Store (stateful)

**Особенности:**
- Централизованное хранение
- Поддержка Redis Cluster для масштабирования
- Поддержка Redis Sentinel для HA
- Только session ID хранится в cookie
- TLS support для production

**Архитектура с Redis:**
```mermaid
graph LR
    subgraph "Auth-Portal Instances"
        AP1[auth-portal-1]
        AP2[auth-portal-2]
        AP3[auth-portal-3]
    end

    subgraph "Redis Cluster"
        R1[(Redis Master)]
        R2[(Redis Replica 1)]
        R3[(Redis Replica 2)]
    end

    AP1 -.session data.-> R1
    AP2 -.session data.-> R1
    AP3 -.session data.-> R1

    R1 -.replication.-> R2
    R1 -.replication.-> R3
```

**Структура данных в Redis:**
```
Key: authportal:session:{session-id}
Value: {
  "user_id": "...",
  "email": "...",
  "access_token": "...",
  "refresh_token": "...",
  "expires_at": "2024-01-01T00:00:00Z"
}
TTL: 24h (configurable)
```

**Конфигурация:**
```yaml
session:
  store: redis
  redis:
    enabled: true
    addresses:
      - redis-1:6379
      - redis-2:6379
      - redis-3:6379
    password: ${REDIS_PASSWORD}
    db: 0
    master_name: mymaster  # для Sentinel
    pool_size: 10
    key_prefix: "authportal:session:"
    tls:
      enabled: true
      cert: /certs/redis-client.crt
      key: /certs/redis-client.key
      ca: /certs/redis-ca.crt
```

---

## Конфигурация

### Структура конфигурации

```mermaid
graph TB
    Config[Config Root]

    Config --> Server[Server Config<br/>Ports, TLS]
    Config --> Mode[Operation Mode<br/>portal/single-service]
    Config --> Auth[Auth Config<br/>Keycloak, Social]
    Config --> Session[Session Config<br/>Store, Encryption]
    Config --> Token[Token Config<br/>Auto-refresh]
    Config --> Services[Services List<br/>Backend Junctions]
    Config --> Nginx[Nginx Config<br/>Workers, Limits]
    Config --> Observability[Observability<br/>Metrics, Tracing]
    Config --> Resilience[Resilience<br/>RateLimit, CircuitBreaker]
    Config --> Log[Log Config<br/>Level, Format]

    Auth --> KC[Keycloak<br/>Issuer, ClientID, Scopes]
    Auth --> Social[Social Providers<br/>Google, GitHub, etc.]

    Session --> StoreType[Store Type<br/>cookie/jwt/redis]
    Session --> Cookie[Cookie Config]
    Session --> JWT[JWT Config]
    Session --> Redis[Redis Config]

    Services --> Svc1[Service 1<br/>Name, Location, Upstream]
    Services --> Svc2[Service 2]
    Services --> SvcN[Service N]
```

### Приоритет конфигурации

Параметры загружаются в следующем порядке (последний перезаписывает предыдущий):

1. **Defaults** — встроенные значения по умолчанию
2. **Config file** — `config.yaml`
3. **Environment variables** — `${VAR_NAME}` или `${VAR_NAME:-default}`
4. **CLI flags** — `--dev`, `--config`, etc.

### Environment Variables

Все секретные параметры должны передаваться через переменные окружения:

```bash
# Обязательные
KC_CLIENT_SECRET=your-keycloak-secret
ENCRYPTION_KEY=your-32-byte-encryption-key!!

# Опциональные
KC_ISSUER_URL=https://keycloak.example.com/realms/main
KC_CLIENT_ID=auth-portal
KC_REDIRECT_URL=http://localhost:8080/callback
JWT_SIGNING_KEY=your-jwt-key
REDIS_PASSWORD=redis-password
LOG_LEVEL=info
```

### Валидация конфигурации

Auth-portal выполняет валидацию при старте:

**Проверки:**
- Обязательные поля заполнены
- URL корректные (scheme, host)
- Encryption key имеет правильную длину (32 bytes)
- Session store правильно сконфигурирован
- Service upstreams валидные URLs
- Nginx параметры в допустимых диапазонах

**JSON Schema:**
```bash
# Генерация schema для валидации
auth-portal --schema --schema-output config-schema.json

# Использование для валидации в CI/CD
jsonschema -i config.yaml config-schema.json
```

---

## Observability

### Компоненты observability

```mermaid
graph LR
    subgraph "Auth-Portal"
        Metrics[Metrics<br/>Prometheus]
        Tracing[Tracing<br/>OpenTelemetry]
        Health[Health Checks]
        Logs[Structured Logs]
    end

    subgraph "Monitoring Stack"
        Prom[Prometheus]
        Jaeger[Jaeger/Tempo]
        Grafana[Grafana]
        Loki[Loki]
    end

    Metrics -->|/metrics| Prom
    Tracing -->|OTLP gRPC| Jaeger
    Health -->|/health, /ready| Grafana
    Logs -->|JSON logs| Loki

    Prom --> Grafana
    Jaeger --> Grafana
    Loki --> Grafana
```

### Метрики

**Доступные метрики:**

```
# HTTP запросы
auth_portal_requests_total{method, path, status}
auth_portal_request_duration_seconds{method, path}

# Сессии
auth_portal_sessions_active
auth_portal_sessions_created_total
auth_portal_sessions_expired_total

# Аутентификация
auth_portal_auth_attempts_total{provider, result}
auth_portal_auth_failures_total{reason}
auth_portal_token_refresh_total{result}

# Circuit Breaker
auth_portal_circuit_breaker_state{service, state}
auth_portal_circuit_breaker_failures_total{service}

# Rate Limiter
auth_portal_rate_limit_exceeded_total{endpoint}
```

### Distributed Tracing

Auth-portal поддерживает OpenTelemetry tracing:

**Trace spans:**
- HTTP request processing
- OAuth2 authorization flow
- Token exchange/refresh
- Session operations
- Upstream service calls

**Конфигурация:**
```yaml
observability:
  tracing:
    enabled: true
    endpoint: jaeger:4317
    protocol: grpc
    insecure: true
    sampling_ratio: 0.1  # 10% sampling
```

---

## Resilience Patterns

### Rate Limiting

```mermaid
graph LR
    Request[Incoming Request] --> RateLimiter[Rate Limiter]
    RateLimiter -->|Within Limit| Handler[Request Handler]
    RateLimiter -->|Exceeded| Reject[429 Too Many Requests]

    RateLimiter -.check.-> Memory[In-Memory Limiter<br/>per IP/Endpoint]
```

**Возможности:**
- Per-IP rate limiting
- Per-endpoint rate limiting
- Configurable burst
- Custom exclude paths
- Rate limit headers в ответе

### Circuit Breaker

```mermaid
stateDiagram-v2
    [*] --> Closed: Начальное состояние
    Closed --> Open: Превышен failure_threshold
    Open --> HalfOpen: Истек timeout
    HalfOpen --> Closed: success_threshold успешных запросов
    HalfOpen --> Open: Запрос неудачный

    note right of Closed
        Обычная работа
        Считаем failures
    end note

    note right of Open
        Отклоняем все запросы
        Возвращаем cached error
    end note

    note right of HalfOpen
        Пропускаем max_requests
        Проверяем работоспособность
    end note
```

**Конфигурация per-service:**
```yaml
resilience:
  circuit_breaker:
    enabled: true
    services:
      keycloak:
        failure_threshold: 3      # Откроем после 3 ошибок
        timeout: 10s              # Перейдем в half-open через 10s
        max_requests: 3           # 3 запроса в half-open
        success_threshold: 2      # Закроем после 2 успехов
```

---

## Безопасность

### Security Headers

Nginx автоматически добавляет security headers:

```nginx
X-Frame-Options: SAMEORIGIN
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
```

### Cookie Security

```yaml
session:
  secure: true           # HTTPS only (production)
  same_site: lax         # CSRF protection
  encryption:
    enabled: true        # AES-256-GCM encryption
```

### TLS Configuration

```yaml
server:
  tls:
    enabled: true
    cert: /certs/server.crt
    key: /certs/server.key
    # Или Let's Encrypt
    auto_cert:
      enabled: true
      email: admin@example.com
      domains:
        - auth.example.com
```

---

## Deployment Patterns

### Standalone Deployment

```mermaid
graph TB
    LB[Load Balancer]

    subgraph "Host"
        Nginx[Nginx]
        Portal[Auth-Portal]
        Redis[(Redis)]
    end

    KC[Keycloak<br/>External]

    LB --> Nginx
    Nginx --> Portal
    Portal --> Redis
    Portal --> KC
```

### Distributed Deployment

```mermaid
graph TB
    LB[Load Balancer]

    subgraph "Instance 1"
        N1[Nginx]
        AP1[Auth-Portal]
    end

    subgraph "Instance 2"
        N2[Nginx]
        AP2[Auth-Portal]
    end

    subgraph "Instance 3"
        N3[Nginx]
        AP3[Auth-Portal]
    end

    subgraph "Shared Services"
        RC[Redis Cluster]
        KC[Keycloak Cluster]
    end

    LB --> N1
    LB --> N2
    LB --> N3

    AP1 --> RC
    AP2 --> RC
    AP3 --> RC

    AP1 --> KC
    AP2 --> KC
    AP3 --> KC
```

### Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: auth-portal
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: auth-portal
        image: auth-portal:latest
        ports:
        - containerPort: 8080
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
```

---

## Заключение

Auth-portal предоставляет гибкую и масштабируемую архитектуру для централизованной аутентификации и авторизации с интеграцией nginx. Модульная структура позволяет адаптировать систему под различные сценарии использования от простого single-service до сложных multi-tenant порталов.

Для детальной настройки и эксплуатации см. [Руководство администратора](admin-guide.md).

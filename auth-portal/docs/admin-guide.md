# Руководство администратора Auth-Portal

Это руководство предназначено для системных администраторов, DevOps-инженеров и SRE, отвечающих за установку, настройку и эксплуатацию auth-portal.

## Содержание

- [Установка](#установка)
- [Конфигурация](#конфигурация)
- [Интеграция с Keycloak](#интеграция-с-keycloak)
- [Настройка сервисов](#настройка-сервисов)
- [Session Storage](#session-storage)
- [Nginx Integration](#nginx-integration)
- [Мониторинг и Observability](#мониторинг-и-observability)
- [Резервное копирование](#резервное-копирование)
- [Масштабирование](#масштабирование)
- [Безопасность](#безопасность)
- [Troubleshooting](#troubleshooting)

---

## Установка

### Системные требования

**Минимальные:**
- CPU: 1 core
- RAM: 512MB
- Disk: 100MB

**Рекомендуемые для production:**
- CPU: 2 cores
- RAM: 2GB
- Disk: 1GB (для логов)

**Зависимости:**
- Go 1.22+ (для сборки из исходников)
- Nginx 1.20+ (опционально, для production)
- Redis 6.0+ (опционально, для session storage)
- Keycloak 22+ (обязательно)

### Установка из бинарных файлов

```bash
# Скачивание последней версии
wget https://github.com/your-org/auth-portal/releases/latest/download/auth-portal-linux-amd64
chmod +x auth-portal-linux-amd64
sudo mv auth-portal-linux-amd64 /usr/local/bin/auth-portal

# Проверка установки
auth-portal --version
```

### Сборка из исходников

```bash
# Клонирование репозитория
git clone https://github.com/your-org/auth-portal.git
cd auth-portal

# Сборка
make build

# Установка
sudo make install
```

### Установка через Docker

```bash
# Pull образа
docker pull your-registry/auth-portal:latest

# Запуск контейнера
docker run -d \
  --name auth-portal \
  -p 8080:8080 \
  -v /path/to/config.yaml:/etc/auth-portal/config.yaml:ro \
  -e KC_CLIENT_SECRET=your-secret \
  -e ENCRYPTION_KEY=your-32-byte-key \
  your-registry/auth-portal:latest
```

### Установка через Kubernetes

```bash
# Создание namespace
kubectl create namespace auth-portal

# Создание secrets
kubectl create secret generic auth-portal-secrets \
  --from-literal=kc-client-secret=your-secret \
  --from-literal=encryption-key=your-32-byte-key \
  -n auth-portal

# Применение манифестов
kubectl apply -f deployments/kubernetes/ -n auth-portal
```

### Создание systemd service

Создайте файл `/etc/systemd/system/auth-portal.service`:

```ini
[Unit]
Description=Auth-Portal Authentication Service
After=network.target

[Service]
Type=simple
User=auth-portal
Group=auth-portal
WorkingDirectory=/opt/auth-portal
ExecStart=/usr/local/bin/auth-portal --config /etc/auth-portal/config.yaml
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=auth-portal

# Environment variables (лучше использовать EnvironmentFile)
EnvironmentFile=/etc/auth-portal/env

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/auth-portal

[Install]
WantedBy=multi-user.target
```

Создайте файл `/etc/auth-portal/env`:

```bash
KC_CLIENT_SECRET=your-keycloak-client-secret
ENCRYPTION_KEY=your-32-byte-encryption-key!!
LOG_LEVEL=info
```

Запуск сервиса:

```bash
# Создание пользователя
sudo useradd -r -s /bin/false auth-portal

# Создание директорий
sudo mkdir -p /etc/auth-portal /var/log/auth-portal
sudo chown auth-portal:auth-portal /var/log/auth-portal

# Запуск и автозапуск
sudo systemctl daemon-reload
sudo systemctl enable auth-portal
sudo systemctl start auth-portal

# Проверка статуса
sudo systemctl status auth-portal
sudo journalctl -u auth-portal -f
```

---

## Конфигурация

### Структура конфигурационного файла

Основной конфигурационный файл: `/etc/auth-portal/config.yaml`

**Полный пример конфигурации:**

```yaml
# =============================================================================
# БАЗОВЫЕ НАСТРОЙКИ
# =============================================================================

# Режим работы: portal | single-service
mode: portal

# Настройки HTTP сервера
server:
  http_port: 8080
  https_port: 443
  tls:
    enabled: false
    cert: /certs/server.crt
    key: /certs/server.key

# =============================================================================
# АУТЕНТИФИКАЦИЯ
# =============================================================================

auth:
  keycloak:
    # URL Keycloak realm (OIDC issuer)
    issuer_url: ${KC_ISSUER_URL:-https://keycloak.example.com/realms/main}

    # OAuth2 client credentials
    client_id: ${KC_CLIENT_ID:-auth-portal}
    client_secret: ${KC_CLIENT_SECRET}

    # OAuth2 callback URL
    redirect_url: ${KC_REDIRECT_URL:-https://auth.example.com/callback}

    # Запрашиваемые scopes
    scopes:
      - openid
      - profile
      - email
      - roles
      - groups

    # Social login провайдеры
    social_providers:
      - name: google
        display_name: "Sign in with Google"
        idp_hint: google
        icon: google

      - name: github
        display_name: "Sign in with GitHub"
        idp_hint: github
        icon: github

# =============================================================================
# УПРАВЛЕНИЕ СЕССИЯМИ
# =============================================================================

session:
  # Тип хранилища: cookie | jwt | redis
  store: redis

  # Имя cookie
  cookie_name: _auth_session

  # Время жизни сессии
  ttl: 24h

  # Secure flag (только HTTPS)
  secure: true

  # SameSite attribute
  same_site: lax

  # Шифрование данных сессии
  encryption:
    enabled: true
    key: ${ENCRYPTION_KEY}

  # Настройки Redis (если store: redis)
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
    min_idle_conns: 5
    key_prefix: "authportal:session:"
    tls:
      enabled: false
      cert: /certs/redis-client.crt
      key: /certs/redis-client.key
      ca: /certs/redis-ca.crt

  # Настройки JWT (если store: jwt)
  jwt:
    algorithm: HS256
    signing_key: ${JWT_SIGNING_KEY}
    # Для RS256:
    # algorithm: RS256
    # private_key: /certs/jwt-private.pem
    # public_key: /certs/jwt-public.pem

  # Настройки Cookie (если store: cookie)
  cookie:
    max_size: 4096

# =============================================================================
# УПРАВЛЕНИЕ ТОКЕНАМИ
# =============================================================================

token:
  # Автоматическое обновление access token
  auto_refresh: true

  # Обновлять токен за N времени до истечения
  refresh_threshold: 5m

# =============================================================================
# СЕРВИСЫ (для portal mode)
# =============================================================================

services:
  - name: grafana
    display_name: "Grafana Monitoring"
    description: "Metrics visualization and dashboards"
    icon: chart-line
    location: /grafana/
    upstream: http://grafana:3000
    auth_required: true
    rewrite: "^/grafana/(.*) /$1 break"
    headers:
      add:
        X-User-Email: "{{.User.Email}}"
        X-User-ID: "{{.User.ID}}"
        X-User-Roles: "{{.User.Roles | join \",\"}}"
      remove:
        - Authorization

  - name: kibana
    display_name: "Kibana Logs"
    description: "Elasticsearch logs and analytics"
    icon: search
    location: /kibana/
    upstream: http://kibana:5601
    auth_required: true

# =============================================================================
# NGINX КОНФИГУРАЦИЯ
# =============================================================================

nginx:
  worker_processes: auto
  worker_connections: 1024
  keepalive_timeout: 65
  client_max_body_size: 100m

  # Rate limiting на уровне nginx
  rate_limit:
    enabled: true
    zone_size: 10m
    requests_per_second: 10
    burst: 20

  access_log: /var/log/nginx/access.log
  error_log: /var/log/nginx/error.log

# =============================================================================
# OBSERVABILITY
# =============================================================================

observability:
  # Prometheus метрики
  metrics:
    enabled: true
    path: /metrics

  # Distributed tracing
  tracing:
    enabled: true
    endpoint: jaeger:4317
    protocol: grpc
    insecure: false
    sampling_ratio: 0.1

  # Health checks
  health:
    path: /health

  ready:
    path: /ready

# =============================================================================
# RESILIENCE
# =============================================================================

resilience:
  # HTTP rate limiting
  rate_limit:
    enabled: true
    rate: "100-S"  # 100 req/sec
    trust_forwarded_for: true
    exclude_paths:
      - /health
      - /ready
      - /metrics
    by_endpoint: true
    endpoint_rates:
      "/login": "10-S"
      "/callback": "5-S"

  # Circuit breaker
  circuit_breaker:
    enabled: true
    default:
      failure_threshold: 5
      timeout: 30s
      success_threshold: 2
    services:
      keycloak:
        failure_threshold: 3
        timeout: 10s

# =============================================================================
# ЛОГИРОВАНИЕ
# =============================================================================

log:
  level: info
  format: json
  development: false
```

### Управление секретами

**НЕ ХРАНИТЕ СЕКРЕТЫ В config.yaml!**

Используйте environment variables или secret management системы:

**1. Environment Variables:**

```bash
# /etc/auth-portal/env
KC_CLIENT_SECRET=your-keycloak-secret
ENCRYPTION_KEY=your-32-byte-encryption-key!!
JWT_SIGNING_KEY=your-jwt-signing-key
REDIS_PASSWORD=redis-password
```

**2. Kubernetes Secrets:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: auth-portal-secrets
type: Opaque
stringData:
  kc-client-secret: your-keycloak-secret
  encryption-key: your-32-byte-encryption-key!!
  redis-password: redis-password
```

**3. HashiCorp Vault:**

```bash
# Запись секретов в Vault
vault kv put secret/auth-portal \
  kc_client_secret=xxx \
  encryption_key=yyy \
  redis_password=zzz

# Получение в runtime через vault agent или CSI driver
```

### Генерация секретов

```bash
# Encryption key (32 bytes)
openssl rand -base64 32

# JWT signing key (HMAC)
openssl rand -base64 64

# RSA key pair для JWT RS256
openssl genrsa -out jwt-private.pem 2048
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem
```

### Валидация конфигурации

```bash
# Генерация JSON Schema
auth-portal --schema --schema-output /tmp/schema.json

# Валидация конфигурации
# Установите jsonschema: pip install jsonschema
python -m jsonschema -i /etc/auth-portal/config.yaml /tmp/schema.json

# Или через yq + jq
yq eval -o=json /etc/auth-portal/config.yaml | \
  jsonschema -i /dev/stdin /tmp/schema.json
```

---

## Интеграция с Keycloak

### Создание Realm

1. Войдите в Keycloak Admin Console
2. Создайте новый realm: `Realms → Create Realm`
3. Настройте realm settings:
   - Realm name: `main` (или другое имя)
   - Enabled: `ON`
   - User registration: `ON` (опционально)

### Создание клиента

1. Перейдите в `Clients → Create Client`

2. **General Settings:**
   - Client type: `OpenID Connect`
   - Client ID: `auth-portal`

3. **Capability config:**
   - Client authentication: `ON` (confidential)
   - Authorization: `OFF`
   - Standard flow: `ON`
   - Direct access grants: `OFF`
   - Service accounts roles: `OFF`

4. **Login settings:**
   - Root URL: `https://auth.example.com`
   - Valid redirect URIs:
     - `https://auth.example.com/callback`
     - `http://localhost:8080/callback` (для dev)
   - Valid post logout redirect URIs: `https://auth.example.com`
   - Web origins: `+` (same as redirect URIs)

5. **Credentials:**
   - Скопируйте `Client secret`
   - Сохраните в переменную окружения `KC_CLIENT_SECRET`

### Настройка Scopes

1. Перейдите в `Client Scopes → Create Client Scope`

2. **Roles scope:**
   - Name: `roles`
   - Protocol: `openid-connect`
   - Include in Token Scope: `ON`

3. Добавьте mapper:
   - Mapper type: `User Realm Role`
   - Name: `realm-roles`
   - Token Claim Name: `roles`
   - Claim JSON Type: `String`
   - Add to ID token: `ON`
   - Add to access token: `ON`
   - Add to userinfo: `ON`

4. **Groups scope:**
   - Name: `groups`
   - Add mapper:
     - Mapper type: `Group Membership`
     - Token Claim Name: `groups`
     - Full group path: `OFF`

5. Назначьте scopes клиенту:
   - `Clients → auth-portal → Client Scopes`
   - Add scopes: `roles`, `groups`

### Настройка Social Providers

#### Google

1. Создайте OAuth2 credentials в [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
   - Authorized redirect URIs: `https://keycloak.example.com/realms/main/broker/google/endpoint`

2. В Keycloak:
   - `Identity Providers → Add provider → Google`
   - Client ID: `your-google-client-id`
   - Client Secret: `your-google-client-secret`
   - Alias: `google` (используется в auth-portal config)

#### GitHub

1. Создайте OAuth App в [GitHub Settings](https://github.com/settings/developers)
   - Authorization callback URL: `https://keycloak.example.com/realms/main/broker/github/endpoint`

2. В Keycloak:
   - `Identity Providers → Add provider → GitHub`
   - Client ID: `your-github-client-id`
   - Client Secret: `your-github-client-secret`
   - Alias: `github`

#### Yandex / Sber ID

Для других провайдеров используйте generic `OpenID Connect v1.0`:

1. `Identity Providers → Add provider → OpenID Connect v1.0`
2. Заполните:
   - Alias: `yandex` или `sberid`
   - Authorization URL, Token URL, etc.
   - Client ID, Client Secret

### Проверка конфигурации

```bash
# Проверка discovery endpoint
curl https://keycloak.example.com/realms/main/.well-known/openid-configuration | jq

# Проверка issuer URL
jq '.issuer' <<< "$(curl -s https://keycloak.example.com/realms/main/.well-known/openid-configuration)"

# Тест OAuth2 flow (получение токена)
curl -X POST https://keycloak.example.com/realms/main/protocol/openid-connect/token \
  -d "client_id=auth-portal" \
  -d "client_secret=YOUR_SECRET" \
  -d "grant_type=password" \
  -d "username=testuser" \
  -d "password=testpass" \
  | jq
```

---

## Настройка сервисов

### Добавление нового сервиса

Пример конфигурации сервиса в `config.yaml`:

```yaml
services:
  - name: prometheus
    display_name: "Prometheus Metrics"
    description: "Time-series database for metrics"
    icon: database

    # Location в nginx (должен заканчиваться на /)
    location: /prometheus/

    # Upstream URL (backend сервис)
    upstream: http://prometheus:9090

    # Требуется аутентификация
    auth_required: true

    # URL rewriting (опционально)
    # Удаляет /prometheus/ из пути перед проксированием
    rewrite: "^/prometheus/(.*) /$1 break"

    # Кастомные заголовки
    headers:
      # Добавить заголовки
      add:
        X-User-Email: "{{.User.Email}}"
        X-User-ID: "{{.User.ID}}"
        X-User-Name: "{{.User.Name}}"
        X-User-Roles: "{{.User.Roles | join \",\"}}"
        X-Tenant-ID: "{{.User.TenantID}}"

      # Удалить заголовки
      remove:
        - Authorization
        - Cookie

    # Дополнительные nginx директивы (опционально)
    nginx_extra: |
      proxy_set_header Upgrade $http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_buffering off;
```

### Доступные template переменные для headers

В значениях заголовков можно использовать Go templates:

| Переменная | Описание | Пример |
|------------|----------|--------|
| `{{.User.ID}}` | User ID | `123e4567-e89b-12d3-a456-426614174000` |
| `{{.User.Email}}` | Email | `user@example.com` |
| `{{.User.Name}}` | Полное имя | `John Doe` |
| `{{.User.PreferredUsername}}` | Username | `johndoe` |
| `{{.User.Roles}}` | Массив ролей | `["admin","user"]` |
| `{{.User.Groups}}` | Массив групп | `["developers"]` |
| `{{.User.TenantID}}` | Tenant ID | `acme-corp` |

**Функции:**

- `join ","` — соединить массив в строку
- `default "value"` — значение по умолчанию
- `upper` — верхний регистр
- `lower` — нижний регистр

### URL Rewriting

**Примеры:**

```yaml
# Простое удаление префикса
# /grafana/dashboard → /dashboard
rewrite: "^/grafana/(.*) /$1 break"

# Замена пути
# /old/path → /new/path
rewrite: "^/old/(.*) /new/$1 break"

# Добавление префикса для backend
# /service/api → /v1/api
rewrite: "^/service/(.*) /v1/$1 break"
```

### Сервисы без аутентификации

Для публичных сервисов установите `auth_required: false`:

```yaml
services:
  - name: docs
    display_name: "Documentation"
    location: /docs/
    upstream: http://docs:80
    auth_required: false  # Публичный доступ
```

### Регенерация nginx конфигурации

После изменения сервисов:

```bash
# Генерация нового nginx.conf
auth-portal --config /etc/auth-portal/config.yaml \
  --generate-nginx \
  --output /etc/nginx/nginx.conf

# Проверка синтаксиса
nginx -t

# Применение изменений
nginx -s reload

# Или через systemd
systemctl reload nginx
```

---

## Session Storage

### Cookie Store (Stateless)

**Преимущества:**
- Не требует внешних зависимостей
- Простая настройка
- Подходит для малых и средних развертываний

**Недостатки:**
- Ограничение размера ~4KB
- Невозможность централизованной инвалидации сессий

**Конфигурация:**

```yaml
session:
  store: cookie
  encryption:
    enabled: true
    key: ${ENCRYPTION_KEY}  # Обязательно!
  cookie:
    max_size: 4096
  ttl: 24h
  secure: true
  same_site: lax
```

**Генерация encryption key:**

```bash
# Генерация 32-байтового ключа
openssl rand -base64 32

# Сохраните в переменную окружения
export ENCRYPTION_KEY="generated-key-here"
```

### JWT Store (Stateless)

**Преимущества:**
- Токены можно валидировать без обращения к auth-portal
- Поддержка asymmetric keys (RS256)
- Подходит для микросервисной архитектуры

**Недостатки:**
- Больший размер cookie
- Невозможность отзыва токенов до истечения

**Конфигурация HMAC (HS256):**

```yaml
session:
  store: jwt
  jwt:
    algorithm: HS256
    signing_key: ${JWT_SIGNING_KEY}
  ttl: 24h
```

**Конфигурация RSA (RS256):**

```yaml
session:
  store: jwt
  jwt:
    algorithm: RS256
    private_key: /certs/jwt-private.pem
    public_key: /certs/jwt-public.pem
  ttl: 24h
```

**Генерация RSA ключей:**

```bash
# Private key
openssl genrsa -out jwt-private.pem 2048

# Public key
openssl rsa -in jwt-private.pem -pubout -out jwt-public.pem

# Для production используйте 4096 бит
openssl genrsa -out jwt-private.pem 4096
```

### Redis Store (Stateful)

**Преимущества:**
- Централизованное управление сессиями
- Возможность инвалидации сессий
- Масштабируемость
- Подходит для распределенных систем

**Недостатки:**
- Требует Redis инфраструктуры
- Дополнительная точка отказа

#### Standalone Redis

```yaml
session:
  store: redis
  redis:
    enabled: true
    addresses:
      - redis:6379
    password: ${REDIS_PASSWORD}
    db: 0
    pool_size: 10
    key_prefix: "authportal:session:"
```

#### Redis Sentinel (HA)

```yaml
session:
  store: redis
  redis:
    enabled: true
    addresses:
      - sentinel-1:26379
      - sentinel-2:26379
      - sentinel-3:26379
    password: ${REDIS_PASSWORD}
    master_name: mymaster
    db: 0
    pool_size: 10
```

#### Redis Cluster

```yaml
session:
  store: redis
  redis:
    enabled: true
    addresses:
      - redis-cluster-1:6379
      - redis-cluster-2:6379
      - redis-cluster-3:6379
      - redis-cluster-4:6379
      - redis-cluster-5:6379
      - redis-cluster-6:6379
    password: ${REDIS_PASSWORD}
    pool_size: 20
```

#### Redis with TLS

```yaml
session:
  store: redis
  redis:
    enabled: true
    addresses:
      - redis:6380
    password: ${REDIS_PASSWORD}
    tls:
      enabled: true
      cert: /certs/redis-client.crt
      key: /certs/redis-client.key
      ca: /certs/redis-ca.crt
```

**Мониторинг Redis:**

```bash
# Проверка подключения
redis-cli -h redis -p 6379 -a $REDIS_PASSWORD PING

# Просмотр активных сессий
redis-cli -h redis -a $REDIS_PASSWORD KEYS "authportal:session:*"

# Количество сессий
redis-cli -h redis -a $REDIS_PASSWORD KEYS "authportal:session:*" | wc -l

# TTL сессии
redis-cli -h redis -a $REDIS_PASSWORD TTL "authportal:session:SESSION_ID"

# Просмотр данных сессии
redis-cli -h redis -a $REDIS_PASSWORD GET "authportal:session:SESSION_ID"

# Удаление всех сессий (осторожно!)
redis-cli -h redis -a $REDIS_PASSWORD KEYS "authportal:session:*" | xargs redis-cli -h redis -a $REDIS_PASSWORD DEL
```

---

## Nginx Integration

### Установка и настройка nginx

**Установка:**

```bash
# Ubuntu/Debian
apt-get update
apt-get install nginx

# RHEL/CentOS
yum install nginx

# Alpine
apk add nginx
```

**Структура директорий:**

```
/etc/nginx/
├── nginx.conf              # Главный конфиг (генерируется auth-portal)
├── conf.d/                 # Дополнительные конфиги
│   └── custom.conf
└── ssl/                    # TLS сертификаты
    ├── server.crt
    └── server.key
```

### Генерация конфигурации

```bash
# Базовая генерация
auth-portal --config /etc/auth-portal/config.yaml \
  --generate-nginx \
  --output /etc/nginx/nginx.conf

# Проверка синтаксиса
nginx -t

# Применение
nginx -s reload
```

### Ручная настройка nginx (альтернатива)

Если вы не хотите использовать автогенерацию, настройте nginx вручную:

```nginx
# Upstream к auth-portal
upstream auth_portal {
    server 127.0.0.1:8080;
    keepalive 32;
}

# Upstream к backend сервису
upstream grafana_backend {
    server grafana:3000;
    keepalive 16;
}

server {
    listen 80;
    server_name auth.example.com;

    # Проксирование auth endpoints
    location / {
        proxy_pass http://auth_portal;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Connection "";
    }

    # Internal auth request endpoint
    location = /_auth {
        internal;
        proxy_pass http://auth_portal/auth;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_set_header Cookie $http_cookie;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
    }

    # Protected service (Grafana)
    location /grafana/ {
        # Forward auth
        auth_request /_auth;
        auth_request_set $auth_email $upstream_http_x_auth_request_email;
        auth_request_set $auth_user $upstream_http_x_auth_request_user;
        auth_request_set $auth_roles $upstream_http_x_auth_request_roles;

        # Error page для неаутентифицированных
        error_page 401 = @auth_redirect;

        # URL rewriting
        rewrite ^/grafana/(.*) /$1 break;

        # Проксирование к backend
        proxy_pass http://grafana_backend;
        proxy_set_header X-User-Email $auth_email;
        proxy_set_header X-User-ID $auth_user;
        proxy_set_header X-User-Roles $auth_roles;
    }

    # Redirect на login при 401
    location @auth_redirect {
        return 302 /login?redirect=$request_uri;
    }
}
```

### TLS/HTTPS настройка

**Let's Encrypt (certbot):**

```bash
# Установка certbot
apt-get install certbot python3-certbot-nginx

# Получение сертификата
certbot --nginx -d auth.example.com

# Автообновление
certbot renew --dry-run
```

**Ручная настройка TLS:**

```yaml
# config.yaml
server:
  tls:
    enabled: true
    cert: /etc/nginx/ssl/server.crt
    key: /etc/nginx/ssl/server.key
```

Или в nginx.conf:

```nginx
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;

    ssl_certificate /etc/nginx/ssl/server.crt;
    ssl_certificate_key /etc/nginx/ssl/server.key;

    # Modern TLS config
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # OCSP stapling
    ssl_stapling on;
    ssl_stapling_verify on;

    # Session cache
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # HSTS
    add_header Strict-Transport-Security "max-age=63072000" always;
}
```

### Rate Limiting в nginx

Nginx-level rate limiting (дополнительно к auth-portal rate limiting):

```yaml
# config.yaml
nginx:
  rate_limit:
    enabled: true
    zone_size: 10m
    requests_per_second: 10
    burst: 20
```

Генерируется в nginx.conf:

```nginx
# Rate limiting zone
limit_req_zone $binary_remote_addr zone=auth_limit:10m rate=10r/s;

server {
    # Apply rate limit
    limit_req zone=auth_limit burst=20 nodelay;
}
```

---

## Мониторинг и Observability

### Prometheus Metrics

**Эндпоинт:** `http://auth-portal:8080/metrics`

**Scrape конфигурация:**

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'auth-portal'
    static_configs:
      - targets: ['auth-portal:8080']
    metrics_path: /metrics
    scrape_interval: 15s
```

**Основные метрики:**

```prometheus
# HTTP запросы
auth_portal_requests_total{method="GET",path="/login",status="200"}
auth_portal_request_duration_seconds{method="GET",path="/login"}
auth_portal_request_size_bytes
auth_portal_response_size_bytes

# Сессии
auth_portal_sessions_active
auth_portal_sessions_created_total
auth_portal_sessions_expired_total
auth_portal_sessions_deleted_total

# Аутентификация
auth_portal_auth_attempts_total{provider="keycloak",result="success"}
auth_portal_auth_failures_total{reason="invalid_credentials"}
auth_portal_token_refresh_total{result="success"}

# Circuit Breaker
auth_portal_circuit_breaker_state{service="keycloak",state="closed"}
auth_portal_circuit_breaker_failures_total{service="keycloak"}

# Rate Limiter
auth_portal_rate_limit_exceeded_total{endpoint="/login"}
```

**Пример Grafana dashboard запросов:**

```promql
# Request rate
rate(auth_portal_requests_total[5m])

# Request duration 95th percentile
histogram_quantile(0.95, rate(auth_portal_request_duration_seconds_bucket[5m]))

# Error rate
rate(auth_portal_requests_total{status=~"5.."}[5m]) / rate(auth_portal_requests_total[5m])

# Active sessions
auth_portal_sessions_active

# Auth success rate
rate(auth_portal_auth_attempts_total{result="success"}[5m]) / rate(auth_portal_auth_attempts_total[5m])
```

### Distributed Tracing

**OpenTelemetry configuration:**

```yaml
observability:
  tracing:
    enabled: true
    endpoint: jaeger:4317
    protocol: grpc
    insecure: true
    sampling_ratio: 0.1  # Sample 10%
```

**Jaeger setup:**

```yaml
# docker-compose.yml
services:
  jaeger:
    image: jaegertracing/all-in-one:latest
    ports:
      - "16686:16686"  # Jaeger UI
      - "4317:4317"    # OTLP gRPC
      - "4318:4318"    # OTLP HTTP
    environment:
      COLLECTOR_OTLP_ENABLED: true
```

**Trace spans:**

- `HTTP Request` — весь HTTP запрос
- `OAuth2 Authorization` — OAuth2 flow
- `Token Exchange` — обмен code на токены
- `Token Refresh` — обновление access token
- `Session Load/Save` — операции с сессией
- `Upstream Request` — запросы к backend сервисам

### Health Checks

**Kubernetes liveness probe:**

```yaml
livenessProbe:
  httpGet:
    path: /health
    port: 8080
  initialDelaySeconds: 30
  periodSeconds: 10
  timeoutSeconds: 5
  failureThreshold: 3
```

**Kubernetes readiness probe:**

```yaml
readinessProbe:
  httpGet:
    path: /ready
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 5
  timeoutSeconds: 3
  failureThreshold: 2
```

**HTTP checks:**

```bash
# Health check
curl http://localhost:8080/health

# Readiness check
curl http://localhost:8080/ready

# Responses:
# {"status": "healthy", "timestamp": "2024-01-01T00:00:00Z"}
# {"status": "ready", "timestamp": "2024-01-01T00:00:00Z"}
```

### Логирование

**Structured JSON logging:**

```json
{
  "level": "info",
  "ts": "2024-01-01T12:00:00.000Z",
  "caller": "handler/auth.go:123",
  "msg": "user authenticated successfully",
  "user_id": "123e4567-e89b-12d3-a456-426614174000",
  "email": "user@example.com",
  "provider": "keycloak",
  "duration_ms": 245
}
```

**Log levels:**

- `debug` — подробная отладочная информация
- `info` — информационные сообщения
- `warn` — предупреждения
- `error` — ошибки

**Конфигурация:**

```yaml
log:
  level: info
  format: json  # или console для dev
  development: false
```

**Интеграция с Loki:**

```yaml
# promtail config
scrape_configs:
  - job_name: auth-portal
    static_configs:
      - targets:
          - localhost
        labels:
          job: auth-portal
          __path__: /var/log/auth-portal/*.log
```

**Полезные LogQL запросы:**

```logql
# Все ошибки за последний час
{job="auth-portal"} | json | level="error"

# Неудачные попытки аутентификации
{job="auth-portal"} | json | msg="authentication failed"

# Slow requests (> 1s)
{job="auth-portal"} | json | duration_ms > 1000

# Errors by endpoint
sum by (path) (rate({job="auth-portal"} | json | level="error" [5m]))
```

### Alerting

**Prometheus alert rules:**

```yaml
groups:
  - name: auth-portal
    interval: 30s
    rules:
      # High error rate
      - alert: AuthPortalHighErrorRate
        expr: |
          rate(auth_portal_requests_total{status=~"5.."}[5m]) / rate(auth_portal_requests_total[5m]) > 0.05
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High error rate in auth-portal"
          description: "Error rate is {{ $value | humanizePercentage }}"

      # Service down
      - alert: AuthPortalDown
        expr: up{job="auth-portal"} == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Auth-portal is down"

      # High auth failure rate
      - alert: AuthPortalHighAuthFailures
        expr: |
          rate(auth_portal_auth_failures_total[5m]) > 10
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High authentication failure rate"

      # Circuit breaker open
      - alert: AuthPortalCircuitBreakerOpen
        expr: |
          auth_portal_circuit_breaker_state{state="open"} == 1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "Circuit breaker open for {{ $labels.service }}"

      # Redis connection issues
      - alert: AuthPortalRedisConnectionFailed
        expr: |
          rate(auth_portal_session_errors_total{type="redis"}[5m]) > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "Redis connection issues"
```

---

## Резервное копирование

### Backup конфигурации

```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR=/backup/auth-portal
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

# Config files
tar czf $BACKUP_DIR/config-$DATE.tar.gz \
  /etc/auth-portal/config.yaml \
  /etc/auth-portal/env

# TLS certificates
tar czf $BACKUP_DIR/certs-$DATE.tar.gz \
  /etc/nginx/ssl/

# Keep last 30 days
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $BACKUP_DIR"
```

### Backup Redis (если используется)

```bash
#!/bin/bash
# backup-redis.sh

BACKUP_DIR=/backup/redis
DATE=$(date +%Y%m%d-%H%M%S)

mkdir -p $BACKUP_DIR

# Redis RDB snapshot
redis-cli -h redis -a $REDIS_PASSWORD BGSAVE
sleep 5
cp /var/lib/redis/dump.rdb $BACKUP_DIR/dump-$DATE.rdb

# Или используйте redis-dump
redis-dump -h redis -a $REDIS_PASSWORD > $BACKUP_DIR/dump-$DATE.json

# Keep last 7 days
find $BACKUP_DIR -mtime +7 -delete
```

### Restore процедура

```bash
#!/bin/bash
# restore-config.sh

BACKUP_FILE=$1

if [ -z "$BACKUP_FILE" ]; then
  echo "Usage: $0 <backup-file.tar.gz>"
  exit 1
fi

# Stop service
systemctl stop auth-portal

# Restore config
tar xzf $BACKUP_FILE -C /

# Restart service
systemctl start auth-portal

echo "Restore completed"
```

---

## Масштабирование

### Horizontal Scaling

**Требования:**
- Используйте Redis для session storage (обязательно!)
- Load balancer перед auth-portal instances
- Sticky sessions НЕ требуются (stateless с Redis)

**Kubernetes Horizontal Pod Autoscaler:**

```yaml
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: auth-portal-hpa
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: auth-portal
  minReplicas: 3
  maxReplicas: 10
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 70
    - type: Resource
      resource:
        name: memory
        target:
          type: Utilization
          averageUtilization: 80
    - type: Pods
      pods:
        metric:
          name: http_requests_per_second
        target:
          type: AverageValue
          averageValue: "1000"
```

**Docker Swarm:**

```bash
docker service scale auth-portal=5
```

**Manual scaling:**

```bash
# Запуск нескольких инстансов
for i in {1..3}; do
  auth-portal --config config.yaml &
done
```

### Load Balancing

**Nginx upstream:**

```nginx
upstream auth_portal_cluster {
    # Load balancing method
    least_conn;

    server auth-portal-1:8080 max_fails=3 fail_timeout=30s;
    server auth-portal-2:8080 max_fails=3 fail_timeout=30s;
    server auth-portal-3:8080 max_fails=3 fail_timeout=30s;

    # Keepalive connections
    keepalive 32;
}
```

**HAProxy:**

```
frontend auth_portal_front
    bind *:80
    default_backend auth_portal_back

backend auth_portal_back
    balance leastconn
    option httpchk GET /health
    server portal1 auth-portal-1:8080 check
    server portal2 auth-portal-2:8080 check
    server portal3 auth-portal-3:8080 check
```

### Redis Scaling

**Redis Cluster (6+ nodes):**

```yaml
session:
  redis:
    addresses:
      - redis-1:6379
      - redis-2:6379
      - redis-3:6379
      - redis-4:6379
      - redis-5:6379
      - redis-6:6379
```

**Redis Sentinel (HA):**

```yaml
session:
  redis:
    addresses:
      - sentinel-1:26379
      - sentinel-2:26379
      - sentinel-3:26379
    master_name: mymaster
```

---

## Безопасность

### Security Checklist

- [ ] **HTTPS обязательно** — используйте TLS в production
- [ ] **Secure cookies** — `session.secure: true`
- [ ] **Strong encryption key** — 32 случайных байта
- [ ] **Секреты через env vars** — не в config файлах
- [ ] **Rate limiting включен** — защита от brute-force
- [ ] **Restrict /metrics** — доступ только из internal network
- [ ] **Restrict /admin** — доступ только для администраторов
- [ ] **Redis TLS** — для production
- [ ] **Regular updates** — обновляйте auth-portal и зависимости
- [ ] **Audit logging** — включите детальное логирование
- [ ] **Firewall rules** — ограничьте доступ к портам

### Restrict access to sensitive endpoints

**Nginx config:**

```nginx
# Metrics только из internal networks
location /metrics {
    allow 10.0.0.0/8;
    allow 172.16.0.0/12;
    allow 192.168.0.0/16;
    deny all;

    proxy_pass http://auth_portal/metrics;
}

# Admin endpoints только для админов
location /admin/ {
    # Require auth + role check
    auth_request /_auth;
    auth_request_set $auth_roles $upstream_http_x_auth_request_roles;

    # Custom access control
    access_by_lua_block {
        if not string.find(ngx.var.auth_roles, "admin") then
            ngx.exit(403)
        end
    }

    proxy_pass http://auth_portal/admin/;
}
```

### Security Headers

Nginx автоматически добавляет security headers, но можно расширить:

```nginx
# Дополнительные security headers
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;
```

### Audit Logging

Включите детальное логирование для аудита:

```yaml
log:
  level: info  # или debug для детального аудита
  format: json
```

Логи будут содержать:
- User ID при каждом действии
- IP адрес клиента
- Timestamp
- Результат операции (success/failure)

### Rotation секретов

**Rotation encryption key:**

1. Сгенерируйте новый ключ
2. Обновите `ENCRYPTION_KEY` в env vars
3. Перезапустите auth-portal
4. Старые сессии будут инвалидированы (пользователи должны заново войти)

**Rotation JWT signing key:**

1. Сгенерируйте новый ключ
2. Временно поддерживайте оба ключа для валидации
3. Используйте новый ключ для подписи новых токенов
4. Через TTL удалите старый ключ

---

## Troubleshooting

### Проблемы с аутентификацией

**Симптом:** Ошибка "Invalid state" при callback

```bash
# Проверьте синхронизацию времени
timedatectl status

# Проверьте redirect_url
# Он должен совпадать с registered URI в Keycloak
grep redirect_url /etc/auth-portal/config.yaml

# Проверьте Keycloak доступность
curl -v ${KC_ISSUER_URL}/.well-known/openid-configuration
```

**Симптом:** "Client authentication failed"

```bash
# Проверьте client_secret
echo $KC_CLIENT_SECRET

# Проверьте в Keycloak Credentials tab
# Client ID и Secret должны совпадать
```

**Симптом:** "Invalid scope"

```bash
# Проверьте доступные scopes в Keycloak
curl ${KC_ISSUER_URL}/.well-known/openid-configuration | jq '.scopes_supported'

# Убедитесь что запрашиваемые scopes назначены клиенту
# Keycloak → Clients → auth-portal → Client Scopes
```

### Проблемы с сессиями

**Симптом:** Сессии не сохраняются (cookie store)

```bash
# Проверьте encryption key
echo $ENCRYPTION_KEY | wc -c  # Должно быть 45 (32 bytes base64)

# Проверьте cookie в браузере
# DevTools → Application → Cookies → _auth_session

# Проверьте логи
journalctl -u auth-portal | grep -i session
```

**Симптом:** Redis connection refused

```bash
# Проверьте Redis доступность
redis-cli -h redis -p 6379 -a $REDIS_PASSWORD PING

# Проверьте network connectivity
nc -zv redis 6379

# Проверьте Redis logs
docker logs redis

# Проверьте auth-portal config
grep -A 10 "redis:" /etc/auth-portal/config.yaml
```

**Симптом:** Сессии истекают слишком быстро

```bash
# Проверьте TTL в конфигурации
grep ttl /etc/auth-portal/config.yaml

# Проверьте TTL в Redis
redis-cli -h redis -a $REDIS_PASSWORD TTL "authportal:session:*"

# Проверьте token expiration в Keycloak
# Realm Settings → Tokens → Access Token Lifespan
```

### Проблемы с nginx

**Симптом:** 502 Bad Gateway

```bash
# Проверьте auth-portal запущен
systemctl status auth-portal
curl http://localhost:8080/health

# Проверьте nginx upstream
nginx -T | grep -A 5 "upstream auth_portal"

# Проверьте nginx error log
tail -f /var/log/nginx/error.log

# Проверьте connectivity
nc -zv localhost 8080
```

**Симптом:** auth_request всегда возвращает 401

```bash
# Проверьте /_auth endpoint
curl -v http://localhost/auth

# Проверьте передачу cookie
curl -v http://localhost/auth -H "Cookie: _auth_session=..."

# Проверьте nginx config
nginx -T | grep -A 10 "location = /_auth"

# Проверьте auth-portal logs
journalctl -u auth-portal | grep "/auth"
```

**Симптом:** Headers не передаются в backend

```bash
# Проверьте auth_request_set директивы
nginx -T | grep auth_request_set

# Проверьте proxy_set_header
nginx -T | grep -A 5 "proxy_set_header"

# Проверьте в backend логах получаемые headers
# Например, для Grafana:
docker logs grafana | grep -i "x-user"
```

### Проблемы с производительностью

**Симптом:** Медленные ответы

```bash
# Проверьте метрики
curl http://localhost:8080/metrics | grep request_duration

# Проверьте CPU/Memory
top -p $(pgrep auth-portal)

# Проверьте Redis latency
redis-cli -h redis -a $REDIS_PASSWORD --latency

# Проверьте Keycloak response time
time curl ${KC_ISSUER_URL}/.well-known/openid-configuration

# Включите debug logging
export LOG_LEVEL=debug
systemctl restart auth-portal
```

**Симптом:** High CPU usage

```bash
# Profile CPU
go tool pprof http://localhost:8080/debug/pprof/profile

# Проверьте горутины
curl http://localhost:8080/debug/pprof/goroutine?debug=1

# Проверьте rate limiting
# Возможно слишком много requests
curl http://localhost:8080/metrics | grep rate_limit
```

**Симптом:** Memory leak

```bash
# Heap profile
go tool pprof http://localhost:8080/debug/pprof/heap

# Проверьте количество сессий
redis-cli -h redis -a $REDIS_PASSWORD DBSIZE

# Проверьте memory metrics
curl http://localhost:8080/metrics | grep go_memstats
```

### Debug mode

```bash
# Запуск в debug режиме
export LOG_LEVEL=debug
export DEV_MODE=true
auth-portal --config config.yaml --dev

# Debug конкретного компонента
# Проверьте исходный код для logger.Debug() вызовов
```

### Сбор диагностической информации

```bash
#!/bin/bash
# collect-diagnostics.sh

DIAG_DIR=/tmp/auth-portal-diag-$(date +%Y%m%d-%H%M%S)
mkdir -p $DIAG_DIR

# Config
cp /etc/auth-portal/config.yaml $DIAG_DIR/ 2>/dev/null

# Logs
journalctl -u auth-portal --since "1 hour ago" > $DIAG_DIR/auth-portal.log
tail -1000 /var/log/nginx/error.log > $DIAG_DIR/nginx-error.log 2>/dev/null

# Status
systemctl status auth-portal > $DIAG_DIR/service-status.txt
curl -s http://localhost:8080/health > $DIAG_DIR/health.json
curl -s http://localhost:8080/metrics > $DIAG_DIR/metrics.txt

# Network
netstat -tlnp | grep auth-portal > $DIAG_DIR/network.txt

# Redis (if used)
redis-cli -h redis -a $REDIS_PASSWORD INFO > $DIAG_DIR/redis-info.txt 2>/dev/null

# Package
tar czf /tmp/auth-portal-diag.tar.gz -C /tmp $(basename $DIAG_DIR)

echo "Diagnostics collected: /tmp/auth-portal-diag.tar.gz"
```

### Получение помощи

При обращении в поддержку предоставьте:

1. **Версию auth-portal:** `auth-portal --version`
2. **Конфигурацию** (без секретов!)
3. **Логи** за период проблемы
4. **Метрики** если доступны
5. **Диагностическую информацию** из скрипта выше
6. **Описание проблемы:**
   - Что ожидали?
   - Что происходит на самом деле?
   - Шаги для воспроизведения

---

## Дополнительные ресурсы

- [README](../README.md) — обзор проекта и quick start
- [Архитектура](architecture.md) — детальное описание архитектуры с диаграммами
- [Keycloak Documentation](https://www.keycloak.org/documentation) — документация Keycloak
- [Nginx Documentation](https://nginx.org/en/docs/) — документация nginx
- [OpenTelemetry](https://opentelemetry.io/) — distributed tracing
- [Prometheus](https://prometheus.io/docs/) — monitoring

---

## Changelog

- **v1.0.0** (2024-01-01) — Initial release
  - OIDC authentication
  - Portal and single-service modes
  - Cookie/JWT/Redis session storage
  - Nginx integration
  - Observability (metrics, tracing, health checks)
  - Resilience (rate limiting, circuit breaker)

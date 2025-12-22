# Auth-Portal

**Auth-Portal** — это современный портал аутентификации и авторизации на базе Keycloak OIDC с интеграцией nginx для защиты backend-сервисов.

## Основные возможности

### Аутентификация и авторизация
- **OIDC/OAuth2** интеграция с Keycloak
- **Social login** через Google, GitHub, Yandex, Sber ID и другие провайдеры
- **Forward authentication** для nginx (auth_request)
- **Автоматическое обновление токенов** до истечения срока действия
- **Dev mode** с mock-профилями пользователей для разработки

### Режимы работы
- **Portal Mode** — показывает список доступных сервисов после аутентификации
- **Single-Service Mode** — прямой редирект на целевой сервис после логина

### Session Management
Три типа хранения сессий:
- **Cookie** — зашифрованные cookie (stateless, по умолчанию)
- **JWT** — подписанные JWT-токены в cookie (stateless)
- **Redis** — централизованное хранение для распределенных систем

### Nginx Integration
- **Автогенерация nginx.conf** из конфигурации
- **Auth_request** интеграция для защиты upstream-сервисов
- **Прозрачная передача user context** через заголовки (email, roles, groups)
- **URL rewriting** и кастомные заголовки для каждого сервиса

### Observability
- **Prometheus metrics** — мониторинг производительности
- **OpenTelemetry tracing** — распределенная трассировка запросов
- **Health & Readiness checks** — Kubernetes-ready endpoints
- **Structured logging** — JSON-логи с контекстом

### Resilience
- **Rate Limiting** — защита от перегрузки с поддержкой per-endpoint лимитов
- **Circuit Breaker** — автоматическое отключение нестабильных сервисов
- **Graceful Shutdown** — корректная остановка с завершением активных запросов

## Быстрый старт

### Предварительные требования
- Go 1.22+
- Keycloak 22+ (настроенный realm)
- Nginx (опционально, для production)
- Redis (опционально, для session storage)

### Установка

```bash
# Клонирование репозитория
git clone https://github.com/your-org/auth-portal.git
cd auth-portal

# Сборка
make build

# Или через Docker
docker build -t auth-portal .
```

### Минимальная конфигурация

Создайте файл `config.yaml`:

```yaml
mode: portal

server:
  http_port: 8080

auth:
  keycloak:
    issuer_url: https://keycloak.example.com/realms/main
    client_id: auth-portal
    client_secret: ${KC_CLIENT_SECRET}
    redirect_url: http://localhost:8080/callback
    scopes:
      - openid
      - profile
      - email

session:
  store: cookie
  cookie_name: _auth_session
  ttl: 24h
  encryption:
    enabled: true
    key: ${ENCRYPTION_KEY}

services:
  - name: grafana
    display_name: "Grafana Monitoring"
    location: /grafana/
    upstream: http://grafana:3000
    auth_required: true

log:
  level: info
  format: json
```

### Запуск

```bash
# Экспорт секретов
export KC_CLIENT_SECRET="your-keycloak-client-secret"
export ENCRYPTION_KEY="your-32-byte-encryption-key!!"

# Запуск сервиса
./bin/auth-portal --config config.yaml

# Или в dev mode без Keycloak
./bin/auth-portal --config config.yaml --dev
```

### Генерация nginx.conf

```bash
# Генерация конфигурации nginx
./bin/auth-portal --config config.yaml --generate-nginx --output /etc/nginx/nginx.conf

# Проверка и перезагрузка nginx
nginx -t && nginx -s reload
```

## Структура проекта

```
auth-portal/
├── cmd/auth-portal/           # Точка входа приложения
├── internal/
│   ├── config/                # Загрузка и валидация конфигурации
│   ├── handler/               # HTTP обработчики
│   │   ├── auth.go            # OAuth2 flow, login, callback
│   │   ├── portal.go          # Портал сервисов
│   │   └── forward_auth.go    # Forward auth для nginx
│   ├── service/
│   │   ├── idp/               # OIDC провайдеры
│   │   ├── session/           # Session management
│   │   ├── metrics/           # Prometheus метрики
│   │   └── crypto/            # JWT, encryption
│   ├── nginx/                 # Генератор nginx конфига
│   ├── model/                 # Модели данных
│   └── ui/                    # HTML шаблоны
├── configs/                   # Примеры конфигураций
├── deployments/               # Docker, Kubernetes манифесты
├── docs/                      # Документация
└── tests/                     # E2E тесты
```

## Основные эндпоинты

### Пользовательские эндпоинты
- `GET /` — Главная страница (редирект на /login или /portal)
- `GET /login` — Страница выбора способа входа
- `GET /login/keycloak` — Инициация OAuth2 flow с Keycloak
- `GET /login/social/{provider}` — Social login (google, github, etc.)
- `GET /callback` — OAuth2 callback endpoint
- `GET /logout` — Выход и завершение сессии
- `GET /portal` — Список доступных сервисов (portal mode)
- `GET /userinfo` — Информация о текущем пользователе (JSON)

### Служебные эндпоинты
- `GET /auth` — Forward auth для nginx auth_request
- `GET /verify` — Верификация токена (JSON)
- `GET /health` — Health check
- `GET /ready` — Readiness check
- `GET /metrics` — Prometheus метрики

### Admin эндпоинты
- `GET /admin/config` — Просмотр текущей конфигурации
- `GET /admin/sessions` — Статистика сессий
- `POST /admin/sessions/invalidate` — Инвалидация сессий

## CLI опции

```bash
auth-portal [options]

Options:
  --config PATH           Path to configuration file (default: /etc/auth-portal/config.yaml)
  --generate-nginx        Generate nginx config and exit
  --output PATH           Output path for nginx config (default: /etc/nginx/nginx.conf)
  --dev                   Enable development mode (mock authentication)
  --version               Show version and exit
  --help                  Show extended help
  --schema                Generate JSON schema for config validation
  --schema-output PATH    Output file for schema (default: stdout)
```

## Environment Variables

Все параметры конфигурации поддерживают environment variables:

```bash
# Keycloak
KC_ISSUER_URL=https://keycloak.example.com/realms/main
KC_CLIENT_ID=auth-portal
KC_CLIENT_SECRET=secret

# Session encryption
ENCRYPTION_KEY=your-32-byte-encryption-key!!

# JWT signing (для store: jwt)
JWT_SIGNING_KEY=your-jwt-signing-key

# Redis (для store: redis)
REDIS_PASSWORD=redis-password

# Logging
LOG_LEVEL=info
DEV_MODE=false
```

## Интеграция с Keycloak

### 1. Создание клиента

В Keycloak admin console:
- Create Client → Client ID: `auth-portal`
- Client Protocol: `openid-connect`
- Access Type: `confidential`
- Valid Redirect URIs: `http://localhost:8080/callback`, `https://auth.example.com/callback`
- Web Origins: `+` (разрешить CORS для redirect URIs)

### 2. Настройка Scopes

Добавьте custom scopes в клиент:
- `roles` — для передачи ролей пользователя
- `groups` — для передачи групп пользователя

### 3. Social Providers

Для настройки social login в Keycloak:
- Identity Providers → Add provider (Google, GitHub, etc.)
- Скопируйте Alias (используется как `idp_hint`)
- В auth-portal добавьте провайдер в `auth.keycloak.social_providers`

## Docker Deployment

### Docker Compose пример

```yaml
version: '3.8'

services:
  auth-portal:
    image: auth-portal:latest
    ports:
      - "8080:8080"
    environment:
      KC_CLIENT_SECRET: ${KC_CLIENT_SECRET}
      ENCRYPTION_KEY: ${ENCRYPTION_KEY}
    volumes:
      - ./config.yaml:/etc/auth-portal/config.yaml:ro
    depends_on:
      - redis
      - keycloak

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
    depends_on:
      - auth-portal

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
```

## Мониторинг и Observability

### Prometheus Metrics

```bash
# Доступны на /metrics
curl http://localhost:8080/metrics
```

Основные метрики:
- `auth_portal_requests_total` — всего запросов
- `auth_portal_request_duration_seconds` — время обработки
- `auth_portal_sessions_active` — активных сессий
- `auth_portal_auth_failures_total` — ошибок аутентификации

### OpenTelemetry Tracing

```yaml
observability:
  tracing:
    enabled: true
    endpoint: jaeger:4317
    protocol: grpc
    sampling_ratio: 0.1
```

### Health Checks

```bash
# Kubernetes liveness probe
curl http://localhost:8080/health

# Kubernetes readiness probe
curl http://localhost:8080/ready
```

## Безопасность

### Рекомендации для production

1. **HTTPS обязательно** — используйте TLS в production
2. **Secure cookies** — `session.secure: true` для HTTPS
3. **Session encryption** — всегда включайте шифрование
4. **Секреты через env vars** — не храните секреты в config файлах
5. **Rate limiting** — включите защиту от brute-force
6. **Restrict metrics** — ограничьте доступ к /metrics
7. **Redis TLS** — используйте TLS для Redis в production

### Генерация encryption key

```bash
# Генерация 32-байтного ключа
openssl rand -base64 32
```

## Troubleshooting

### Проблемы с аутентификацией

```bash
# Проверка доступности Keycloak
curl -v ${KC_ISSUER_URL}/.well-known/openid-configuration

# Проверка редиректа
# Убедитесь, что redirect_url совпадает с registered URIs в Keycloak

# Логи auth-portal
LOG_LEVEL=debug ./bin/auth-portal --config config.yaml
```

### Session проблемы

```bash
# Проверка Redis подключения (для store: redis)
redis-cli -h redis -a ${REDIS_PASSWORD} PING

# Просмотр сессий в Redis
redis-cli -h redis -a ${REDIS_PASSWORD} KEYS "authportal:session:*"
```

### Nginx forward auth проблемы

```bash
# Проверка /_auth endpoint
curl -v http://localhost:8080/auth -H "Cookie: _auth_session=..."

# Nginx error log
tail -f /var/log/nginx/error.log
```

## Документация

- [Архитектура](docs/architecture.md) — архитектура системы с диаграммами
- [Руководство администратора](docs/admin-guide.md) — установка, настройка, мониторинг

## Разработка

### Запуск в dev mode

```bash
# Dev mode с mock-профилями
./bin/auth-portal --config config.yaml --dev

# Доступны mock-пользователи из configs/profiles/
# - developer.yaml
# - admin.yaml
# - qa.yaml
```

### Запуск тестов

```bash
# Unit тесты
make test

# E2E тесты
cd tests/e2e/tier1
make test
```

### Генерация JSON Schema

```bash
# Для валидации конфигурации
./bin/auth-portal --schema --schema-output config-schema.json
```

## Лицензия

MIT License

## Авторы

Разработано командой DevOps

# Tier 1: E2E Testing Environment

Локальная среда для E2E тестирования на базе Docker/Podman Compose.

## Архитектура

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              E2E Test Stack                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │ auth-portal  │────▶│  Keycloak    │     │   Grafana    │                │
│  │   :8880      │     │   :8180      │◀────│   :3000      │                │
│  │  Login UI    │     │  OIDC/OAuth  │     │  OIDC Auth   │                │
│  └──────┬───────┘     └──────────────┘     └──────────────┘                │
│         │                    ▲                                              │
│         │ JWT                │ JWKS                                         │
│         ▼                    │                                              │
│  ┌──────────────┐     ┌──────┴───────┐     ┌──────────────┐                │
│  │authz-service │────▶│     OPA      │     │    Redis     │                │
│  │   :8080      │     │   :8181      │     │   :6379      │                │
│  │ JWT + Policy │     │ Rego Policy  │     │    Cache     │                │
│  └──────┬───────┘     └──────────────┘     └──────────────┘                │
│         │                                                                    │
│         │ Proxy                                                             │
│         ▼                                                                    │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │ user-service │     │admin-service │     │ external-api │                │
│  │   :8081      │     │   :8082      │     │   :8083      │                │
│  │  (WireMock)  │     │  (WireMock)  │     │  (WireMock)  │                │
│  └──────────────┘     └──────────────┘     └──────────────┘                │
│                                                                              │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐                │
│  │   Jaeger     │     │  Prometheus  │     │  ToxiProxy   │                │
│  │  :16686      │     │   :9090      │     │   :8474      │                │
│  │   Tracing    │     │   Metrics    │     │    Chaos     │                │
│  └──────────────┘     └──────────────┘     └──────────────┘                │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Быстрый старт

```bash
# 1. Перейти в директорию
cd tests/e2e/tier1

# 2. Скопировать переменные окружения
cp compose/.env.example compose/.env

# 3. Запустить полный стек
make stack-up

# 4. Проверить статус
make stack-status
```

## Endpoints

### Аутентификация

| Сервис | URL | Описание |
|--------|-----|----------|
| **Auth Portal** | http://localhost:8880 | UI для логина |
| **Keycloak Admin** | http://localhost:8180 | Управление пользователями (admin/admin) |

### API (через authz-service)

| Сервис | URL | Описание |
|--------|-----|----------|
| **authz-service** | http://localhost:8080 | Internal авторизация |
| **authz-external** | http://localhost:9080 | External partner авторизация |

### Мониторинг

| Сервис | URL | Аутентификация |
|--------|-----|----------------|
| **Grafana** | http://localhost:3000 | OIDC через Keycloak |
| **Jaeger** | http://localhost:16686 | - |
| **Prometheus** | http://localhost:9090 | - |

### Инфраструктура

| Сервис | URL/Port | Описание |
|--------|----------|----------|
| **Redis** | localhost:6379 | Кэш (password: redis) |
| **OPA** | http://localhost:8181 | Policy Engine |
| **PostgreSQL** | localhost:5432 | БД Keycloak |

## Тестовые пользователи

| Username | Password | Роли | Доступ |
|----------|----------|------|--------|
| `admin-user` | `admin-password` | admin, user | Полный доступ |
| `test-user` | `test-password` | user | Базовый доступ |
| `developer` | `developer` | developer, user | Мониторинг + API |
| `viewer` | `viewer` | viewer | Только чтение |
| `external-user` | `external-password` | external | Partner API |
| `agent-user` | `agent-password` | agent | Delegation chains |

## Команды Makefile

### Управление стеком

```bash
# Полный стек
make stack-up        # Запустить всё (infra + authz + portal)
make stack-down      # Остановить всё
make stack-status    # Показать статус
make stack-destroy   # Удалить всё включая volumes

# По компонентам
make infra-up        # Только инфраструктура
make authz-up        # authz-service (требует infra)
make portal-up       # auth-portal (требует authz)
```

### Токены

```bash
make token-admin      # Токен администратора
make token-user       # Токен обычного пользователя
make token-developer  # Токен разработчика
make token-viewer     # Токен read-only
make token-service    # Сервисный токен (client credentials)
```

### Логи

```bash
make logs             # Все логи
make logs-authz       # Только authz-service
make authz-logs       # authz-service (отдельный compose)
make portal-logs      # auth-portal
make infra-logs       # Инфраструктура
```

### Тестирование

```bash
make test             # Все E2E тесты
make test-short       # Быстрые smoke тесты
make test-auth        # Тесты аутентификации
make test-authz       # Тесты авторизации
make test-chaos       # Chaos engineering тесты
```

### Отладка

```bash
make shell-authz      # Shell в authz-service
make shell-keycloak   # Shell в Keycloak
make redis-cli        # Redis CLI
make opa-shell        # OPA REPL
```

## Сценарии использования

### 1. Логин через Auth Portal

```bash
# 1. Открыть http://localhost:8880
# 2. Ввести credentials (developer / developer)
# 3. После логина - доступ к сервисам через UI
```

### 2. API запросы с токеном

```bash
# Получить токен
TOKEN=$(make token-developer 2>/dev/null)

# Запрос к API
curl -H "Authorization: Bearer $TOKEN" \
     http://localhost:8080/api/v1/users/me

# Запрос к admin API (требует роль admin)
ADMIN_TOKEN=$(make token-admin 2>/dev/null)
curl -H "Authorization: Bearer $ADMIN_TOKEN" \
     http://localhost:8080/admin/dashboard
```

### 3. Grafana с SSO

```bash
# 1. Открыть http://localhost:3000
# 2. Нажать "Sign in with Keycloak"
# 3. Ввести credentials в Keycloak
# 4. Роли маппятся автоматически:
#    - admin -> Grafana Admin
#    - developer -> Grafana Editor
#    - остальные -> Grafana Viewer
```

### 4. Token Exchange (RFC 8693)

```bash
# Получить пользовательский токен
USER_TOKEN=$(make token-user 2>/dev/null)

# Обменять на токен для external service
./scripts/get-test-token.sh exchange "$USER_TOKEN" authz-service-external
```

## Структура директорий

```
tier1/
├── Makefile              # Основные команды
├── Makefile.infra        # Команды для инфраструктуры
├── README.md             # Этот файл
├── certs/                # TLS сертификаты (генерируются)
├── compose/
│   ├── .env.example      # Шаблон переменных
│   ├── docker-compose.infra.yaml   # Инфраструктура
│   ├── docker-compose.authz.yaml   # authz-service
│   └── docker-compose.portal.yaml  # auth-portal
├── configs/              # Конфиги authz-service (internal)
│   ├── environment.yaml
│   ├── rules.yaml        # Правила авторизации
│   └── services.yaml     # Конфигурация сервисов
├── configs-external/     # Конфиги authz-service (external)
├── configs-portal/       # Конфиги auth-portal
│   └── auth-portal.yaml
├── grafana/
│   ├── dashboards/       # Готовые дашборды
│   └── provisioning/     # Автонастройка datasources
├── keycloak/
│   └── realm-export.json # Realm с пользователями и клиентами
├── opa/
│   └── policies/
│       ├── authz.rego    # Rego политики
│       └── data.json     # Данные для политик
├── prometheus/
│   └── prometheus.yml    # Конфигурация Prometheus
├── scripts/
│   ├── detect-runtime.sh     # Определение Docker/Podman
│   ├── get-test-token.sh     # Получение токенов
│   ├── setup-certs.sh        # Генерация сертификатов
│   └── wait-for-services.sh  # Ожидание готовности
├── tests/                # Go E2E тесты
├── toxiproxy/            # Chaos engineering
└── wiremock/             # Mock сервисы
    ├── user-service/
    ├── admin-service/
    └── external-api/
```

## Права доступа по ролям

| Endpoint | admin | developer | user | viewer | external |
|----------|-------|-----------|------|--------|----------|
| `/api/v1/users/me` | ✅ | ✅ | ✅ | ❌ | ❌ |
| `/api/v1/users` (GET) | ✅ | ✅ | ❌ | ✅ | ❌ |
| `/api/v1/*` (POST/PUT) | ✅ | ✅ | ❌ | ❌ | ❌ |
| `/admin/*` | ✅ | ❌ | ❌ | ❌ | ❌ |
| `/partner/api/*` | ✅ | ❌ | ❌ | ❌ | ✅ |
| `/health`, `/metrics` | ✅ | ✅ | ✅ | ✅ | ✅ |
| Grafana | Admin | Editor | Viewer | Viewer | ❌ |

## Troubleshooting

### Keycloak не стартует

```bash
# Проверить логи
docker logs infra-keycloak

# Проверить PostgreSQL
docker logs infra-postgres

# Перезапустить
make infra-down && make infra-up
```

### Grafana не авторизует через Keycloak

```bash
# Проверить что Keycloak доступен
curl http://localhost:8180/realms/test/.well-known/openid-configuration

# Проверить client secret
# В compose/.env должен быть GRAFANA_OAUTH_SECRET=grafana-secret
```

### authz-service не принимает токены

```bash
# Проверить JWKS endpoint
curl http://localhost:8180/realms/test/protocol/openid-connect/certs

# Проверить audience в токене
TOKEN=$(make token-user 2>/dev/null)
echo $TOKEN | cut -d. -f2 | base64 -d | jq .aud
```

### Очистка и пересоздание

```bash
# Полная очистка
make stack-destroy
docker volume prune -f
docker network prune -f

# Пересоздание
make stack-up
```

## CI/CD

```bash
# Полный CI pipeline
make ci

# Быстрые smoke тесты
make ci-quick
```

## Ресурсные требования

| Ресурс | Минимум | Рекомендуется |
|--------|---------|---------------|
| CPU | 4 cores | 8 cores |
| RAM | 8 GB | 16 GB |
| Disk | 10 GB | 20 GB |

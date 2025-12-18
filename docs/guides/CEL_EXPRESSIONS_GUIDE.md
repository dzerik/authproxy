# CEL Expressions Guide

## Оглавление

1. [Введение](#1-введение)
2. [Быстрый старт](#2-быстрый-старт)
3. [Доступные переменные](#3-доступные-переменные)
4. [Пользовательские функции](#4-пользовательские-функции)
5. [Режимы выражений](#5-режимы-выражений)
6. [Примеры использования](#6-примеры-использования)
7. [Лучшие практики](#7-лучшие-практики)
8. [Производительность](#8-производительность)
9. [Отладка](#9-отладка)

---

## 1. Введение

### 1.1. Что такое CEL?

**CEL (Common Expression Language)** — это язык выражений от Google, предназначенный для безопасной оценки условий. В authz-service CEL используется для реализации сложной логики авторизации, которую невозможно выразить стандартными условиями (roles, scopes, paths).

### 1.2. Когда использовать CEL?

| Сценарий | Стандартные условия | CEL |
|----------|---------------------|-----|
| Проверка роли пользователя | ✅ `roles: [admin]` | ❌ Избыточно |
| Проверка нескольких ролей (OR) | ✅ `roles: [admin, user]` | ❌ Избыточно |
| Проверка роли И scope одновременно | ❌ | ✅ |
| Владелец ресурса = пользователь | ❌ | ✅ |
| Временные ограничения | ❌ | ✅ |
| Проверка кастомных claims | ❌ | ✅ |
| Сложная логика (A AND B) OR C | ❌ | ✅ |

### 1.3. Преимущества CEL

- **Безопасность**: CEL не позволяет выполнять системные вызовы или изменять состояние
- **Производительность**: Выражения компилируются один раз и кешируются
- **Типизация**: CEL проверяет типы на этапе компиляции
- **Читаемость**: Синтаксис похож на JavaScript/Go

---

## 2. Быстрый старт

### 2.1. Базовый синтаксис

```yaml
rules:
  - name: owner-access
    conditions:
      paths:
        - "/api/v1/documents/*"
      expression: 'resource.params["owner_id"] == token.sub'
    effect: allow
```

### 2.2. Режимы выражений

```yaml
# Режим "and" (по умолчанию): условия И выражение должны совпасть
conditions:
  roles: [user]
  expression: 'token.claims["verified"] == true'
  expression_mode: and

# Режим "or": условия ИЛИ выражение
conditions:
  roles: [admin]
  expression: 'resource.params["owner_id"] == token.sub'
  expression_mode: or

# Режим "override": только выражение
conditions:
  expression: '"admin" in token.roles || resource.params["owner_id"] == token.sub'
  expression_mode: override
```

---

## 3. Доступные переменные

### 3.1. token — JWT токен

| Переменная | Тип | Описание |
|------------|-----|----------|
| `token.sub` | string | Subject (ID пользователя) |
| `token.iss` | string | Issuer URL |
| `token.aud` | list | Audiences |
| `token.exp` | timestamp | Время истечения |
| `token.iat` | timestamp | Время выдачи |
| `token.roles` | list | Роли пользователя |
| `token.scopes` | list | OAuth scopes |
| `token.groups` | list | Группы пользователя |
| `token.client_id` | string | OAuth Client ID |
| `token.claims` | map | Дополнительные claims |
| `token.valid` | bool | Валидность токена |

**Примеры:**

```cel
// Проверка роли
"admin" in token.roles

// Проверка scope
"write" in token.scopes

// Проверка кастомного claim
token.claims["email_verified"] == true

// Проверка уровня подписки
int(token.claims["subscription_tier"]) >= 2
```

### 3.2. request — HTTP запрос

| Переменная | Тип | Описание |
|------------|-----|----------|
| `request.method` | string | HTTP метод (GET, POST и т.д.) |
| `request.path` | string | Путь запроса |
| `request.host` | string | Host заголовок |
| `request.headers` | map | HTTP заголовки |
| `request.query` | map | Query параметры |
| `request.protocol` | string | Протокол (HTTP/1.1, HTTP/2) |

**Примеры:**

```cel
// Проверка метода
request.method == "DELETE"

// Проверка метода из списка
request.method in ["PUT", "PATCH", "POST"]

// Проверка заголовка
"X-Api-Key" in request.headers

// Проверка значения заголовка
request.headers["Authorization"].startsWith("Bearer ")
```

### 3.3. resource — извлечённый ресурс

| Переменная | Тип | Описание |
|------------|-----|----------|
| `resource.type` | string | Тип ресурса |
| `resource.id` | string | ID ресурса |
| `resource.action` | string | Действие (read, write, delete) |
| `resource.params` | map | Path параметры из path_templates |

**Примеры:**

```cel
// Проверка типа ресурса
resource.type == "documents"

// Проверка владельца
resource.params["owner_id"] == token.sub

// Комбинация: тип + действие
resource.type == "orders" && resource.action == "cancel"
```

### 3.4. source — информация о клиенте

| Переменная | Тип | Описание |
|------------|-----|----------|
| `source.address` | string | IP адрес клиента |
| `source.principal` | string | mTLS/SPIFFE identity |
| `source.namespace` | string | Kubernetes namespace |
| `source.service_account` | string | Kubernetes service account |

**Примеры:**

```cel
// Проверка IP
source.address == "10.0.0.1"

// Проверка SPIFFE identity
source.principal.startsWith("spiffe://cluster.local/ns/production/")
```

### 3.5. context — контекст запроса

| Переменная | Тип | Описание |
|------------|-----|----------|
| `context.request_id` | string | Уникальный ID запроса |
| `context.trace_id` | string | Trace ID для distributed tracing |
| `context.timestamp` | int | Unix timestamp запроса |
| `context.custom` | map | Кастомные данные контекста |

### 3.6. now — текущее время

| Переменная | Тип | Описание |
|------------|-----|----------|
| `now` | timestamp | Текущее время (CEL timestamp) |

**Примеры:**

```cel
// Бизнес-часы (9:00 - 18:00 UTC)
now.getHours() >= 9 && now.getHours() < 18

// Рабочие дни (понедельник = 1, воскресенье = 0)
now.getDayOfWeek() >= 1 && now.getDayOfWeek() <= 5
```

---

## 4. Пользовательские функции

### 4.1. cidrMatch(ip, cidr)

Проверяет, входит ли IP адрес в CIDR диапазон.

**Сигнатура:**
```cel
cidrMatch(ip: string, cidr: string) -> bool
```

**Примеры:**

```cel
// Проверка одного CIDR
cidrMatch(source.address, "10.0.0.0/8")

// Проверка нескольких диапазонов
cidrMatch(source.address, "10.0.0.0/8") ||
cidrMatch(source.address, "172.16.0.0/12") ||
cidrMatch(source.address, "192.168.0.0/16")

// Точное совпадение IP
cidrMatch(source.address, "192.168.1.100")
```

### 4.2. globMatch(str, pattern)

Проверяет соответствие строки glob-паттерну.

**Сигнатура:**
```cel
globMatch(str: string, pattern: string) -> bool
```

**Паттерны:**
- `*` — любой сегмент пути
- `**` — любое количество сегментов
- `?` — любой символ

**Примеры:**

```cel
// Проверка пути
globMatch(request.path, "/api/v1/*/users")

// Multi-segment wildcard
globMatch(request.path, "/api/**/admin")

// Проверка host
globMatch(request.host, "*.example.com")
```

---

## 5. Режимы выражений

### 5.1. Режим "and" (по умолчанию)

Выражение CEL **И** все остальные условия должны быть выполнены.

```yaml
conditions:
  paths:
    - "/api/v1/documents/*"
  methods:
    - PUT
    - DELETE
  roles:
    - user
  expression: 'resource.params["owner_id"] == token.sub'
  expression_mode: and
```

**Логика:** `(path matches) AND (method matches) AND (role matches) AND (CEL expression)`

**Когда использовать:**
- Добавление дополнительной проверки к существующим условиям
- Проверка владельца ресурса в дополнение к роли
- Валидация кастомных claims

### 5.2. Режим "or"

Выражение CEL **ИЛИ** остальные условия должны быть выполнены.

```yaml
conditions:
  paths:
    - "/api/v1/documents/*"
  roles:
    - admin
  expression: 'resource.params["owner_id"] == token.sub'
  expression_mode: or
```

**Логика:** `(path matches) AND ((role matches) OR (CEL expression))`

> **Примечание:** paths и methods всегда проверяются в режиме AND!

**Когда использовать:**
- Альтернативные пути авторизации (admin ИЛИ владелец)
- Резервные условия

### 5.3. Режим "override"

**Только** CEL выражение оценивается, остальные условия игнорируются.

```yaml
conditions:
  # paths всё равно проверяются для определения применимости правила
  paths:
    - "/api/v1/documents/*"

  # Эти условия игнорируются при expression_mode: override
  roles:
    - admin
  scopes:
    - write

  expression: |
    ("admin" in token.roles) ||
    (resource.params["owner_id"] == token.sub && "user" in token.roles)
  expression_mode: override
```

**Когда использовать:**
- Сложная логика, которую проще выразить в CEL
- Полный контроль над авторизацией через выражение
- Комбинация нескольких условий с разной логикой

---

## 6. Примеры использования

### 6.1. Owner-based доступ

```yaml
- name: document-owner-access
  description: "Пользователи могут редактировать только свои документы"
  conditions:
    path_templates:
      - "/api/v1/documents/{document_id}"
    methods:
      - PUT
      - DELETE
    expression: 'resource.params["owner_id"] == token.sub'
  effect: allow
```

### 6.2. Admin или владелец

```yaml
- name: admin-or-owner
  description: "Админ имеет полный доступ, пользователи — к своим ресурсам"
  conditions:
    path_templates:
      - "/api/v1/resources/{resource_id}"
    expression: '"admin" in token.roles || resource.params["owner_id"] == token.sub'
    expression_mode: override
  effect: allow
```

### 6.3. Временные ограничения

```yaml
- name: business-hours-only
  description: "Торговые операции только в рабочее время"
  conditions:
    paths:
      - "/api/v1/trading/**"
    roles:
      - trader
    expression: |
      now.getHours() >= 9 && now.getHours() < 18 &&
      now.getDayOfWeek() >= 1 && now.getDayOfWeek() <= 5
    expression_mode: and
  effect: allow
```

### 6.4. Проверка подписки

```yaml
- name: premium-features
  description: "Премиум функции только для подписчиков"
  conditions:
    paths:
      - "/api/v1/premium/**"
    expression: |
      "premium" in token.roles &&
      token.claims["subscription_status"] == "active" &&
      int(token.claims["subscription_tier"]) >= 2
    expression_mode: override
  effect: allow
```

### 6.5. IP-based доступ

```yaml
- name: internal-network-only
  description: "Внутренний API только из корпоративной сети"
  conditions:
    paths:
      - "/api/v1/internal/**"
    expression: |
      cidrMatch(source.address, "10.0.0.0/8") ||
      cidrMatch(source.address, "172.16.0.0/12") ||
      cidrMatch(source.address, "192.168.0.0/16")
    expression_mode: override
  effect: allow
```

### 6.6. Method-specific авторизация

```yaml
- name: method-based-access
  description: "Разные права для разных методов"
  conditions:
    path_templates:
      - "/api/v1/items/{item_id}"
    expression: |
      (request.method == "GET" && "reader" in token.roles) ||
      (request.method in ["PUT", "POST"] && "editor" in token.roles) ||
      (request.method == "DELETE" && "admin" in token.roles)
    expression_mode: override
  effect: allow
```

### 6.7. Комбинация scope и role

```yaml
- name: sensitive-operations
  description: "Критичные операции требуют scope И role"
  conditions:
    paths:
      - "/api/v1/sensitive/**"
    methods:
      - POST
      - PUT
      - DELETE
    expression: '"write" in token.scopes && "manager" in token.roles'
    expression_mode: and
  effect: allow
```

### 6.8. Проверка заголовков

```yaml
- name: api-key-required
  description: "Требуется API ключ в заголовке"
  conditions:
    paths:
      - "/api/v1/partner/**"
    expression: |
      "X-Api-Key" in request.headers &&
      request.headers["X-Api-Key"] != ""
    expression_mode: and
  effect: allow
```

---

## 7. Лучшие практики

### 7.1. Используйте стандартные условия когда возможно

```yaml
# ❌ Избыточно — используйте стандартные условия
expression: '"admin" in token.roles'

# ✅ Правильно
roles:
  - admin
```

### 7.2. Предпочитайте режим "and" для дополнительных проверок

```yaml
# ✅ Хорошо: CEL добавляет проверку владельца
conditions:
  roles: [user]
  expression: 'resource.params["owner_id"] == token.sub'
  expression_mode: and
```

### 7.3. Используйте "override" для сложной логики

```yaml
# ✅ Хорошо: вся логика в CEL
conditions:
  expression: |
    ("admin" in token.roles) ||
    ("user" in token.roles && resource.params["owner_id"] == token.sub)
  expression_mode: override
```

### 7.4. Избегайте дублирования логики

```yaml
# ❌ Дублирование
conditions:
  roles: [admin]
  expression: '"admin" in token.roles || resource.owner == token.sub'
  expression_mode: or

# ✅ Лучше
conditions:
  expression: '"admin" in token.roles || resource.params["owner_id"] == token.sub'
  expression_mode: override
```

### 7.5. Документируйте сложные выражения

```yaml
- name: complex-auth
  # Подробное описание помогает понять логику
  description: |
    Доступ разрешён если:
    1. Пользователь — админ, ИЛИ
    2. Пользователь — владелец ресурса И имеет роль user, ИЛИ
    3. Запрос из внутренней сети
  conditions:
    expression: |
      "admin" in token.roles ||
      ("user" in token.roles && resource.params["owner_id"] == token.sub) ||
      cidrMatch(source.address, "10.0.0.0/8")
    expression_mode: override
  effect: allow
```

---

## 8. Производительность

### 8.1. Компиляция и кеширование

- Выражения компилируются при загрузке правил
- Скомпилированные программы кешируются
- Повторное использование кешированных программ

### 8.2. Precompilation

При запуске сервиса все выражения проверяются:

```
INFO  Precompiling CEL expressions...
INFO  Compiled 15 expressions in 23ms
```

Ошибки компиляции приводят к отказу загрузки правил (fail-fast).

### 8.3. Рекомендации

1. **Избегайте сложных вычислений** в выражениях
2. **Используйте короткие выражения** когда возможно
3. **Предпочитайте стандартные условия** для простых проверок

---

## 9. Отладка

### 9.1. Логирование

Включите debug логирование для CEL:

```yaml
logging:
  level: debug
```

Пример лога:

```json
{
  "level": "debug",
  "msg": "CEL evaluation",
  "expression": "\"admin\" in token.roles",
  "result": true,
  "duration_us": 45
}
```

### 9.2. Тестирование выражений

Используйте API для тестирования:

```bash
curl -X POST http://localhost:8080/api/v1/debug/cel/evaluate \
  -H "Content-Type: application/json" \
  -d '{
    "expression": "\"admin\" in token.roles",
    "context": {
      "token": {
        "roles": ["admin", "user"]
      }
    }
  }'
```

### 9.3. Типичные ошибки

**Ошибка компиляции:**
```
ERROR: CEL compilation error: undeclared reference to 'unknown_var'
```
**Решение:** Проверьте имена переменных в [разделе 3](#3-доступные-переменные).

**Ошибка типа:**
```
ERROR: CEL expression must return boolean, got string
```
**Решение:** Выражение должно возвращать `bool`.

**Ошибка доступа к map:**
```
ERROR: no such key: owner_id
```
**Решение:** Используйте `"key" in map` перед доступом к значению:
```cel
"owner_id" in resource.params && resource.params["owner_id"] == token.sub
```

---

## Связанные документы

- [Rules Example](../../authz-service/configs/examples/rules.example.yaml) — примеры правил с CEL
- [Policy Engine Spec](../specs/GO_AUTHZ_SERVICE_SPEC.md) — техническая спецификация
- [CEL Language Definition](https://github.com/google/cel-spec) — официальная спецификация CEL

# Архитектура Auth-Portal

## Обзор

Auth-Portal — единый Docker-контейнер, объединяющий Nginx и Go backend под управлением s6-overlay.

```mermaid
flowchart TB
    subgraph "Docker Container: auth-portal"
        subgraph "s6-overlay Process Manager"
            S6[s6-supervise]
        end

        subgraph "Processes"
            GO[Go Backend :8080]
            NG[Nginx :80/:443]
        end

        subgraph "Configuration"
            YAML[auth-portal.yaml]
            TMPL[nginx templates]
            NGCONF[nginx.conf]
        end

        S6 --> GO & NG
        GO -->|read| YAML
        GO -->|parse| TMPL
        GO -->|generate| NGCONF
        NG -->|load| NGCONF
        NG -->|auth_request| GO
    end

    User[User] -->|HTTPS| NG
    NG -->|proxy_pass| Backend[Backend Services]
    GO -->|OIDC| KC[Keycloak]
    GO <-.->|optional| Redis[(Redis)]
```

---

## Компоненты

### 1. Nginx (Frontend)

**Роль:** TLS termination, reverse proxy, rate limiting

**Конфигурация генерируется из YAML:**
- Locations для каждого сервиса
- auth_request к Go backend
- Per-service headers и rewrites

### 2. Go Backend

**Роль:** Аутентификация, сессии, конфигурация

**Endpoints:**
- `/login`, `/logout`, `/callback` — OIDC flow
- `/portal` — UI списка сервисов
- `/auth` — endpoint для nginx auth_request
- `/health`, `/ready`, `/metrics` — observability

### 3. s6-overlay

**Роль:** Process manager для multi-process container

**Сервисы:**
- `auth-portal` — Go backend (запускается первым)
- `nginx` — Nginx (зависит от auth-portal)
- `config-watcher` — hot reload при изменении конфига

---

## Хранилища сессий

### Сравнение вариантов

```mermaid
flowchart LR
    subgraph "Cookie Store (default)"
        C1[User] -->|Encrypted Cookie| C2[Auth-Portal]
    end

    subgraph "JWT Store"
        J1[User] -->|Signed JWT Cookie| J2[Auth-Portal]
    end

    subgraph "Redis Store"
        R1[User] -->|Session ID Cookie| R2[Auth-Portal #1]
        R1 -->|Session ID Cookie| R3[Auth-Portal #2]
        R2 & R3 <-->|Encrypted Data| R4[(Redis)]
    end
```

| Характеристика | Cookie | JWT | Redis |
|----------------|--------|-----|-------|
| Stateless | Да | Да | Нет |
| Масштабирование | Любое | Любое | Горизонтальное |
| Инвалидация сессии | Нет | Нет | Да |
| Размер данных | До 4KB | До 4KB | Любой |
| Шифрование | AES-256-GCM | Нет (подпись) | AES-256-GCM |
| Доп. инфраструктура | Нет | Нет | Redis |

### Когда что использовать

| Сценарий | Рекомендация |
|----------|--------------|
| MVP / Один инстанс | Cookie Store |
| Stateless / Kubernetes | JWT Store |
| Горизонтальное масштабирование | Redis Store |
| Нужна инвалидация сессий | Redis Store |

---

## Безопасность Redis

### Матрица рисков

| Риск | Вероятность | Импакт | Митигация |
|------|-------------|--------|-----------|
| Неавторизованный доступ | Высокая | Критический | AUTH + ACL + Network isolation |
| Перехват трафика | Средняя | Критический | TLS |
| Кража токенов из памяти | Низкая | Критический | Шифрование данных |
| Утечка через RDB/AOF | Средняя | Высокий | No persistence / Encrypted disk |

### Рекомендуемая конфигурация

```yaml
# auth-portal.yaml
session:
  store: redis

  encryption:
    enabled: true  # ОБЯЗАТЕЛЬНО!
    key: ${SESSION_ENCRYPTION_KEY}

  redis:
    addresses:
      - redis:6379
    password: ${REDIS_PASSWORD}

    tls:
      enabled: true
      cert: /certs/redis-client.crt
      key: /certs/redis-client.key
      ca: /certs/redis-ca.crt
```

```ini
# redis.conf
requirepass ${REDIS_PASSWORD}
bind 127.0.0.1
tls-port 6379
port 0
tls-cert-file /certs/redis.crt
tls-key-file /certs/redis.key
tls-ca-cert-file /certs/ca.crt
tls-auth-clients yes

# Отключить персистентность
save ""
appendonly no
```

### Архитектура с Redis (Production)

```mermaid
flowchart TB
    subgraph "Public"
        User[User Browser]
    end

    subgraph "DMZ"
        LB[Load Balancer]
    end

    subgraph "Private Network"
        subgraph "Auth-Portal Replicas"
            AP1[Auth-Portal #1]
            AP2[Auth-Portal #2]
            AP3[Auth-Portal #3]
        end

        subgraph "Redis HA"
            RM[Redis Master]
            RS1[Redis Replica]
            RS2[Redis Replica]
            SE[Sentinel x3]
        end
    end

    User --> LB
    LB --> AP1 & AP2 & AP3
    AP1 & AP2 & AP3 <-->|TLS + Encrypted| RM
    RM --> RS1 & RS2
    SE -.-> RM & RS1 & RS2
```

### Чеклист безопасности Redis

- [ ] Redis AUTH включён
- [ ] Redis ACL настроен (минимальные права)
- [ ] TLS для соединений
- [ ] mTLS (клиентские сертификаты)
- [ ] Данные зашифрованы на уровне приложения
- [ ] Redis в isolated network
- [ ] Firewall: только Auth-Portal → Redis
- [ ] Персистентность отключена или диск зашифрован
- [ ] Мониторинг подозрительных команд
- [ ] Регулярная ротация credentials

---

## Генерация Nginx конфигурации

### Процесс

```mermaid
sequenceDiagram
    participant YAML as auth-portal.yaml
    participant Go as Go Backend
    participant Tmpl as Templates (sprig)
    participant Nginx as Nginx

    Note over Go: Startup
    Go->>YAML: Read config
    Go->>Go: Parse & Validate
    Go->>Tmpl: Load templates
    Go->>Go: Execute templates
    Go->>Nginx: Write nginx.conf
    Go->>Nginx: nginx -t (test)
    Go->>Nginx: Start nginx

    Note over Go: Config change
    Go->>YAML: Detect change
    Go->>Go: Re-parse
    Go->>Go: Re-execute templates
    Go->>Nginx: Write nginx.conf
    Go->>Nginx: nginx -s reload
```

### Шаблонизатор: text/template + sprig

**Почему:**
- Стандартный синтаксис Go
- Sprig добавляет 100+ функций
- Совместим с Helm (знакомый DevOps)

**Пример шаблона:**

```nginx
{{/* location.tmpl */}}
{{ range .Services }}
# === SERVICE: {{ .Name }} ===
location {{ .Location }} {
    {{- if .AuthRequired }}
    auth_request /auth;
    auth_request_set $auth_user $upstream_http_x_user_email;
    auth_request_set $auth_id $upstream_http_x_user_id;
    {{- end }}

    {{- range $key, $value := .Headers.Add }}
    proxy_set_header {{ $key }} "{{ $value }}";
    {{- end }}

    {{- range .Headers.Remove }}
    proxy_set_header {{ . }} "";
    {{- end }}

    {{- if .Rewrite }}
    rewrite {{ .Rewrite }};
    {{- end }}

    proxy_pass {{ .Upstream }};

    {{- if .NginxExtra }}
    {{ .NginxExtra | nindent 4 }}
    {{- end }}
}
{{ end }}
```

---

## Потоки данных

### Portal Mode Flow

```mermaid
sequenceDiagram
    actor User
    participant Nginx
    participant Go as Go Backend
    participant KC as Keycloak
    participant Backend

    User->>Nginx: GET /
    Nginx->>Go: proxy_pass
    Go-->>Nginx: Redirect /login
    Nginx-->>User: 302 /login

    User->>Nginx: GET /login
    Nginx->>Go: proxy_pass
    Go-->>User: Login page

    User->>Nginx: GET /login/keycloak
    Nginx->>Go: proxy_pass
    Go-->>User: Redirect to Keycloak

    User->>KC: OAuth2 flow
    KC-->>User: Redirect /callback?code=xxx

    User->>Nginx: GET /callback?code=xxx
    Nginx->>Go: proxy_pass
    Go->>KC: Exchange code for tokens
    KC-->>Go: Tokens
    Go->>Go: Create session
    Go-->>User: Set-Cookie + Redirect /portal

    User->>Nginx: GET /portal
    Nginx->>Go: auth_request /auth
    Go-->>Nginx: 200 OK
    Nginx->>Go: proxy_pass /portal
    Go-->>User: Portal page

    User->>Nginx: GET /grafana/...
    Nginx->>Go: auth_request /auth
    Go-->>Nginx: 200 + X-User-Email
    Nginx->>Backend: proxy_pass + headers
    Backend-->>User: Response
```

### Forward Auth Flow

```mermaid
sequenceDiagram
    actor User
    participant Nginx
    participant Go as Go Backend
    participant Backend

    User->>Nginx: GET /grafana/dashboard
    Nginx->>Go: GET /auth (auth_request)

    alt No session
        Go-->>Nginx: 401
        Nginx-->>User: 302 /login?return_to=/grafana/dashboard
    end

    alt Valid session
        Go->>Go: Check token expiry
        opt Token needs refresh
            Go->>Go: Refresh via Keycloak
        end
        Go-->>Nginx: 200 OK
        Note right of Go: X-Auth-Request-User<br/>X-Auth-Request-Email
    end

    Nginx->>Nginx: auth_request_set variables
    Nginx->>Backend: GET /dashboard
    Note right of Nginx: X-User-Email: user@example.com<br/>X-User-ID: 12345
    Backend-->>Nginx: Response
    Nginx-->>User: Response
```

---

## Deployment

### Docker Compose (Development)

```yaml
version: '3.8'

services:
  auth-portal:
    build: .
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./configs/auth-portal.yaml:/etc/auth-portal/config.yaml:ro
      - ./certs:/certs:ro
    environment:
      - KC_CLIENT_SECRET=${KC_CLIENT_SECRET}
      - SESSION_ENCRYPTION_KEY=${SESSION_ENCRYPTION_KEY}
    depends_on:
      - keycloak

  keycloak:
    image: quay.io/keycloak/keycloak:24.0
    # ... keycloak config

  # Optional: Redis for session storage
  redis:
    image: redis:7-alpine
    command: >
      redis-server
      --requirepass ${REDIS_PASSWORD}
      --appendonly no
```

### Kubernetes (Production)

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
            - containerPort: 80
            - containerPort: 443
          env:
            - name: KC_CLIENT_SECRET
              valueFrom:
                secretKeyRef:
                  name: auth-portal-secrets
                  key: kc-client-secret
            - name: SESSION_ENCRYPTION_KEY
              valueFrom:
                secretKeyRef:
                  name: auth-portal-secrets
                  key: session-key
          volumeMounts:
            - name: config
              mountPath: /etc/auth-portal
            - name: certs
              mountPath: /certs
      volumes:
        - name: config
          configMap:
            name: auth-portal-config
        - name: certs
          secret:
            secretName: auth-portal-tls
```

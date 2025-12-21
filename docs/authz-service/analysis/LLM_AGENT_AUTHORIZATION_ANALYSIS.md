# Анализ: Аутентификация и авторизация LLM-агентов

## Оглавление

1. [Введение и проблематика](#1-введение-и-проблематика)
2. [Ключевые вызовы](#2-ключевые-вызовы)
3. [Модели авторизации агентов](#3-модели-авторизации-агентов)
4. [Существующие стандарты и протоколы](#4-существующие-стандарты-и-протоколы)
5. [Индустриальные решения](#5-индустриальные-решения)
6. [Best Practices](#6-best-practices)
7. [Архитектурные паттерны](#7-архитектурные-паттерны)
8. [Рекомендации для проекта](#8-рекомендации-для-проекта)
9. [Источники](#9-источники)

---

## 1. Введение и проблематика

### 1.1. Контекст

LLM-агенты — это автономные системы на базе больших языковых моделей, способные:
- Выполнять многошаговые задачи без постоянного контроля человека
- Взаимодействовать с внешними API, базами данных, инструментами
- Коммуницировать с другими агентами для решения сложных задач
- Действовать от имени пользователя (delegation)

По данным Gartner, в 2025 году **более 60% крупных предприятий** развернули автономных AI-агентов в production-среде (против 15% в 2023).

### 1.2. Фундаментальная проблема

```mermaid
flowchart TB
    subgraph Problem["Проблема"]
        ND["Недетерминированность<br/>LLM принимает решения<br/>на основе вероятностей"]
        AC["Agent-to-Agent<br/>Любой агент может<br/>обратиться к любому"]
        DE["Delegation<br/>Агент действует<br/>от имени пользователя"]
    end

    subgraph Risk["Риски"]
        PE["Privilege Escalation<br/>Расширение привилегий"]
        CC["Cascading Compromise<br/>Каскадная компрометация"]
        DL["Data Leakage<br/>Утечка данных"]
        UA["Unauthorized Actions<br/>Несанкционированные действия"]
    end

    ND --> PE
    AC --> CC
    DE --> DL
    ND --> UA
    AC --> UA
```

### 1.3. Почему традиционные IAM не работают

| Аспект | Традиционный IAM | LLM-агенты |
|--------|------------------|------------|
| **Субъект** | Человек или статичный сервис | Автономная, недетерминированная система |
| **Поведение** | Предсказуемое, детерминированное | Стохастическое, зависит от контекста |
| **Жизненный цикл** | Длительный (месяцы/годы) | Эфемерный (минуты/часы) |
| **Привилегии** | Фиксированные роли | Динамические, зависят от задачи |
| **Делегирование** | Редкое, явное | Постоянное, неявное |
| **Масштаб вызовов** | Десятки в минуту | Тысячи в час |

> *"OAuth 2.0 assumes deterministic clients, but in agentic settings stochastic reasoning, prompt injection, or multi-agent orchestration can silently expand privileges."* — arXiv: Agentic JWT

---

## 2. Ключевые вызовы

### 2.1. Недетерминированность поведения

```mermaid
sequenceDiagram
    participant User
    participant AgentA as Agent A
    participant AgentB as Agent B
    participant API as Sensitive API

    User->>AgentA: "Подготовь отчёт по продажам"

    Note over AgentA: LLM интерпретирует задачу

    AgentA->>AgentB: Запрос данных

    Note over AgentB: Prompt Injection?<br/>Confabulation?

    AgentB->>API: Неожиданный запрос<br/>(расширение scope)

    API-->>AgentB: Sensitive data
    AgentB-->>AgentA: Data
    AgentA-->>User: Отчёт + утечка?
```

**Проблема:** Один и тот же промпт может привести к разным действиям агента.

### 2.2. Agent-to-Agent коммуникация

В Multi-Agent Systems (MAS) агенты взаимодействуют друг с другом:

```mermaid
flowchart LR
    subgraph MAS["Multi-Agent System"]
        A1["Agent 1<br/>Orchestrator"]
        A2["Agent 2<br/>Data Analyst"]
        A3["Agent 3<br/>Report Generator"]
        A4["Agent 4<br/>Email Sender"]
    end

    A1 --> A2
    A1 --> A3
    A2 --> A3
    A3 --> A4
    A2 -.-> A4

    style A2 fill:#ff9999

    Note["Компрометация Agent 2<br/>= доступ к Agent 3, Agent 4"]
```

**Риск:** Каскадная компрометация — взлом одного агента распространяется по цепочке.

### 2.3. Транзитивная авторизация (Delegation)

```mermaid
sequenceDiagram
    participant U as User (Alice)
    participant A1 as Agent A
    participant A2 as Agent B
    participant A3 as Agent C
    participant R as Resource

    U->>A1: Задача + User Token
    Note over A1: Alice → Agent A

    A1->>A2: Delegate + ?token?
    Note over A2: Alice → Agent A → Agent B

    A2->>A3: Delegate + ?token?
    Note over A3: Alice → Agent A → Agent B → Agent C

    A3->>R: Access Resource
    Note over R: Кто запрашивает?<br/>Alice? Agent C?<br/>С какими правами?
```

**Вопросы:**
1. Как передать контекст пользователя через цепочку агентов?
2. Как ограничить scope на каждом шаге?
3. Как аудировать всю цепочку?

### 2.4. OWASP Top 10 для Agentic AI (Dec 2025)

OWASP GenAI Security Project выпустил отдельный Top 10 для агентных приложений:

| # | Риск | Описание |
|---|------|----------|
| 1 | **Excessive Agency** | Агент имеет больше привилегий, чем необходимо |
| 2 | Prompt Injection | Манипуляция поведением через входные данные |
| 3 | Memory Poisoning | Внедрение ложной информации в память агента |
| 4 | Tool Abuse | Злоупотребление доступными инструментами |
| 5 | Privilege Escalation | Расширение привилегий через цепочки делегирования |
| 6 | Cascading Failures | Распространение ошибок между агентами |
| 7 | Confused Deputy | Агент выполняет действия с неправильным контекстом |
| 8 | Data Exfiltration | Утечка данных через агентов |
| 9 | Supply Chain | Компрометация зависимостей агента |
| 10 | Audit Gaps | Невозможность отследить действия |

---

## 3. Модели авторизации агентов

### 3.1. Agent-to-Agent (A2A)

Прямая авторизация между агентами на основе их идентичности.

```mermaid
flowchart LR
    subgraph A2A["Agent-to-Agent Authorization"]
        Agent1["Agent A<br/>ID: agent-a"]
        Agent2["Agent B<br/>ID: agent-b"]

        Policy["Policy Engine"]
    end

    Agent1 -->|"Request + agent-a identity"| Policy
    Policy -->|"Check: Can agent-a call agent-b?"| Agent2
```

**Характеристики:**
- Агент имеет собственную идентичность (SPIFFE ID, Client Cert, API Key)
- Политики определяют, какие агенты могут взаимодействовать
- Не учитывает контекст пользователя

**Пример политики (Rego):**
```rego
package agent_authz

default allow = false

allow {
    input.source.agent_id == "agent-orchestrator"
    input.destination.agent_id == "agent-data-analyst"
    input.action == "query_data"
}
```

### 3.2. User-Delegated (On-Behalf-Of)

Агент действует от имени пользователя с его привилегиями.

```mermaid
sequenceDiagram
    participant User
    participant Agent
    participant AuthZ as Authorization
    participant Resource

    User->>Agent: Task + User Token
    Agent->>AuthZ: Request + User Token + Agent ID

    Note over AuthZ: Check:<br/>1. User permissions<br/>2. Agent allowed to act for user<br/>3. Scope restriction

    AuthZ-->>Agent: Delegated Token (scoped)
    Agent->>Resource: Request + Delegated Token
```

**Характеристики:**
- Агент наследует привилегии пользователя (с ограничениями)
- Требуется явное согласие пользователя на делегирование
- Scope должен сужаться на каждом шаге

### 3.3. Hybrid Model (Рекомендуемый)

Комбинация A2A и User-Delegated с учётом контекста.

```mermaid
flowchart TB
    subgraph Input["Authorization Input"]
        UI["User Identity<br/>(subject)"]
        AI["Agent Identity<br/>(actor)"]
        TI["Task Context<br/>(intent)"]
        RI["Resource<br/>(object)"]
    end

    subgraph Decision["Policy Decision"]
        P1["User has permission?"]
        P2["Agent allowed for user?"]
        P3["Agent-to-Agent allowed?"]
        P4["Task scope valid?"]
        P5["Chain depth OK?"]
    end

    subgraph Output["Decision"]
        Allow["ALLOW<br/>+ scoped token"]
        Deny["DENY<br/>+ reason"]
    end

    Input --> Decision
    Decision --> Output
```

**Формула авторизации:**
```
ALLOW =
    user_has_permission(user, resource, action) AND
    agent_can_act_for_user(agent, user) AND
    agent_to_agent_allowed(source_agent, target_agent) AND
    scope_is_valid(requested_scope, max_scope) AND
    chain_depth <= max_depth
```

---

## 4. Существующие стандарты и протоколы

### 4.1. OAuth 2.0 Token Exchange (RFC 8693)

Базовый механизм для delegation в OAuth.

```mermaid
sequenceDiagram
    participant Agent
    participant AuthServer as Authorization Server
    participant Resource

    Agent->>AuthServer: Token Exchange Request
    Note over Agent,AuthServer: grant_type=token-exchange<br/>subject_token=user_token<br/>actor_token=agent_token<br/>audience=target_resource

    AuthServer->>AuthServer: Validate tokens<br/>Check permissions<br/>Apply scope restrictions

    AuthServer-->>Agent: New Token<br/>(with act claim)

    Agent->>Resource: Request + New Token

    Note over Resource: Token contains:<br/>sub: user-123<br/>act: {sub: agent-a}
```

**Delegation chain в JWT:**
```json
{
  "sub": "user-123",
  "act": {
    "sub": "agent-a",
    "act": {
      "sub": "agent-b"
    }
  }
}
```

**Ограничения:**
- RFC 8693 — фреймворк, не готовое решение
- Не учитывает недетерминированность агентов
- Нет стандарта для scope attenuation

### 4.2. IETF Draft: OAuth for AI Agents (2025)

Новый draft, расширяющий OAuth для агентов.

**Ключевые расширения:**
- `requested_actor` параметр для идентификации агента
- Front-channel consent для делегирования агенту
- Явное разделение subject и actor

```http
POST /authorize HTTP/1.1
Host: auth.example.com

response_type=code
&client_id=agent-orchestrator
&requested_actor=agent-data-analyst
&scope=read:reports
&redirect_uri=https://agent.example.com/callback
```

### 4.3. Agentic JWT (A-JWT)

Исследовательский протокол (arXiv, Sept 2025) специально для агентов.

```mermaid
flowchart TB
    subgraph AJWT["Agentic JWT Structure"]
        subgraph Header["Header"]
            H1["alg: ES256"]
            H2["typ: A-JWT"]
        end

        subgraph Payload["Payload"]
            P1["sub: user-123"]
            P2["act: agent-identity-hash"]
            P3["intent: task-description-hash"]
            P4["delegation_chain: [...]"]
            P5["scope: narrowed-permissions"]
            P6["max_depth: 3"]
            P7["step: 1"]
        end

        subgraph Signature["Proof-of-Possession"]
            S1["Agent's private key signature"]
        end
    end
```

**Инновации:**
- **Agent Identity Hash** — хеш от prompt + tools + config агента
- **Intent Binding** — привязка токена к конкретной задаче
- **Proof-of-Possession** — каждый агент подписывает своим ключом
- **Scope Attenuation** — автоматическое сужение scope

### 4.4. SPIFFE/SPIRE для агентов

SPIFFE (Secure Production Identity Framework for Everyone) применим к агентам.

```mermaid
flowchart LR
    subgraph SPIRE["SPIRE Infrastructure"]
        Server["SPIRE Server"]
        Agent1["SPIRE Agent<br/>(Node 1)"]
        Agent2["SPIRE Agent<br/>(Node 2)"]
    end

    subgraph Workloads["AI Agent Workloads"]
        LLM1["LLM Agent A<br/>spiffe://domain/agent/a"]
        LLM2["LLM Agent B<br/>spiffe://domain/agent/b"]
    end

    Server --> Agent1
    Server --> Agent2
    Agent1 --> LLM1
    Agent2 --> LLM2

    LLM1 -->|mTLS with SVID| LLM2
```

**Преимущества:**
- Автоматическая ротация credentials (SVID)
- Zero Trust архитектура
- Cryptographic proof of identity
- Поддержка ephemeral identities

**Пример SPIFFE ID для агента:**
```
spiffe://corp.example.com/ns/production/agent/data-analyst/instance/abc123
```

### 4.5. Model Context Protocol (MCP) Authorization

MCP — стандарт Anthropic для подключения агентов к инструментам.

**MCP Auth Requirements (June 2025):**
- OAuth 2.1 обязателен
- MCP Server = OAuth Resource Server
- Внешний Authorization Server
- Tool-level permissions

```mermaid
flowchart LR
    subgraph Client["MCP Client (Agent)"]
        Agent["LLM Agent"]
    end

    subgraph MCP["MCP Layer"]
        MCPServer["MCP Server"]
    end

    subgraph Auth["Authorization"]
        AuthServer["OAuth 2.1<br/>Auth Server"]
    end

    subgraph Tools["Tools"]
        Tool1["Gmail API"]
        Tool2["Database"]
    end

    Agent -->|1. Auth Request| AuthServer
    AuthServer -->|2. Token| Agent
    Agent -->|3. MCP Request + Token| MCPServer
    MCPServer -->|4. Validate Token| AuthServer
    MCPServer -->|5. Tool Call| Tool1
    MCPServer -->|5. Tool Call| Tool2
```

---

## 5. Индустриальные решения

### 5.1. Okta Auth for GenAI

**Релиз:** April 2025 (Developer Preview)

**Компоненты:**

| Компонент | Назначение |
|-----------|------------|
| **Token Vault** | Безопасное хранение OAuth токенов для агентов |
| **Async Authentication** | CIBA flow для фоновых агентов |
| **Fine-Grained Authorization** | ABAC для RAG (какие данные видит агент) |
| **Cross App Access (XAA)** | Стандартизация agent-to-agent подключений |

```mermaid
flowchart TB
    subgraph Okta["Okta Auth for GenAI"]
        TV["Token Vault"]
        AA["Async Auth (CIBA)"]
        FGA["Fine-Grained AuthZ"]
    end

    subgraph Agent["AI Agent"]
        LLM["LLM Core"]
        Tools["Tools Integration"]
    end

    subgraph External["External Services"]
        Gmail["Gmail"]
        Slack["Slack"]
        DB["Database"]
    end

    Agent --> TV
    TV --> Gmail
    TV --> Slack

    Agent --> AA
    AA -->|Push notification| User

    Agent --> FGA
    FGA --> DB
```

### 5.2. Microsoft Entra Agent ID

**Релиз:** Microsoft Build 2025 (Public Preview)

**Особенности:**
- Отдельный тип identity для агентов (не workload identity)
- Интеграция с Copilot Studio и Azure AI Foundry
- Conditional Access для агентов
- Ограничения на привилегированные роли

```mermaid
flowchart TB
    subgraph Entra["Microsoft Entra"]
        AID["Agent ID Registry"]
        CA["Conditional Access"]
        PIM["Privileged Identity<br/>Management"]
    end

    subgraph Agents["AI Agents"]
        CS["Copilot Studio Agent"]
        AF["Azure AI Foundry Agent"]
        Custom["Custom Agent"]
    end

    subgraph Resources["Resources"]
        M365["Microsoft 365"]
        Azure["Azure Services"]
        Custom2["Custom APIs"]
    end

    Agents --> AID
    AID --> CA
    CA --> PIM
    PIM --> Resources
```

**Ограничения ролей:**
- Global Administrator — ЗАПРЕЩЕНО
- Privileged Role Administrator — ЗАПРЕЩЕНО
- User Administrator — ЗАПРЕЩЕНО
- Reader roles — РАЗРЕШЕНО

### 5.3. Cloud Security Alliance (CSA) Framework

**Документ:** "Agentic AI Identity & Access Management" (March 2025)

**Ключевые рекомендации:**

1. **Decentralized Identifiers (DIDs)** для агентов
2. **Verifiable Credentials (VCs)** для capabilities
3. **Zero Trust** принципы
4. **Agent Naming Service (ANS)** для discovery

```mermaid
flowchart TB
    subgraph CSA["CSA Framework"]
        DID["Decentralized<br/>Identifiers"]
        VC["Verifiable<br/>Credentials"]
        ZT["Zero Trust<br/>Architecture"]
    end

    subgraph Agent["Agent Identity"]
        ID["did:agent:abc123"]
        Caps["Capabilities VC"]
        Prov["Provenance VC"]
    end

    DID --> ID
    VC --> Caps
    VC --> Prov
    ZT --> Agent
```

### 5.4. HashiCorp Vault for AI Agents

**Pattern:** Dynamic secrets для агентов

```mermaid
sequenceDiagram
    participant Agent as AI Agent
    participant Vault as HashiCorp Vault
    participant DB as Database

    Agent->>Vault: Authenticate (AppRole/K8s)
    Vault-->>Agent: Vault Token

    Agent->>Vault: Request DB credentials
    Note over Vault: Generate short-lived<br/>credentials
    Vault-->>Agent: username/password (TTL: 1h)

    Agent->>DB: Connect with credentials

    Note over Vault: Auto-revoke after TTL
```

**Преимущества:**
- Ephemeral credentials
- Automatic rotation
- Audit trail
- Policy-based access

---

## 6. Best Practices

### 6.1. Zero Trust для агентов

```
"Never trust, always verify, assume breach" — NIST SP 800-207
```

**Применение к агентам:**

| Принцип | Реализация |
|---------|------------|
| Never Trust | Каждый запрос агента проверяется |
| Always Verify | Continuous authentication |
| Assume Breach | Blast radius minimization |

### 6.2. Principle of Least Privilege

```mermaid
flowchart TB
    subgraph Bad["Плохо"]
        B1["Agent: admin role"]
        B2["Full database access"]
        B3["All APIs available"]
    end

    subgraph Good["Хорошо"]
        G1["Agent: specific capabilities"]
        G2["Only required tables"]
        G3["Allowlisted tools only"]
    end
```

**Правила:**
1. Минимальный набор tools/functions
2. Ограниченный scope токенов
3. Time-bound permissions (JIT access)
4. Resource-specific access

### 6.3. Scope Attenuation

Каждый шаг делегирования должен **сужать** scope.

```mermaid
flowchart LR
    U["User<br/>scope: *"] --> A1["Agent A<br/>scope: read,write"]
    A1 --> A2["Agent B<br/>scope: read"]
    A2 --> A3["Agent C<br/>scope: read:reports"]
```

**Правило:** `scope(downstream) ⊂ scope(upstream)`

### 6.4. Chain Depth Limits

Ограничение глубины цепочки делегирования.

```yaml
delegation:
  max_chain_depth: 3

  # User → Agent A → Agent B → Agent C = depth 3
  # User → Agent A → Agent B → Agent C → Agent D = DENIED
```

### 6.5. Human-in-the-Loop для критических действий

```mermaid
flowchart TB
    Agent["Agent"] --> Check{"Critical Action?"}

    Check -->|No| Execute["Execute"]
    Check -->|Yes| Notify["Notify User"]

    Notify --> Approval{"User Approval?"}
    Approval -->|Yes| Execute
    Approval -->|No| Reject["Reject"]
    Approval -->|Timeout| Reject
```

**Критические действия:**
- Финансовые транзакции
- Удаление данных
- Отправка email/сообщений
- Доступ к PII
- Изменение конфигурации

### 6.6. Comprehensive Audit Trail

```json
{
  "event_id": "evt_abc123",
  "timestamp": "2025-12-17T10:30:00Z",
  "event_type": "AGENT_ACTION",

  "user": {
    "id": "user-123",
    "roles": ["analyst"]
  },

  "delegation_chain": [
    {"agent": "agent-orchestrator", "step": 1},
    {"agent": "agent-data-analyst", "step": 2}
  ],

  "action": {
    "type": "API_CALL",
    "target": "reports-api",
    "method": "GET",
    "path": "/api/v1/reports/sales"
  },

  "decision": {
    "result": "ALLOW",
    "policy_version": "v1.2.3",
    "reasons": ["user_permitted", "agent_authorized", "scope_valid"]
  },

  "context": {
    "task_id": "task-xyz",
    "intent_hash": "sha256:abc...",
    "original_prompt_hash": "sha256:def..."
  }
}
```

---

## 7. Архитектурные паттерны

### 7.1. Centralized Policy Decision Point

```mermaid
flowchart TB
    subgraph Agents["AI Agents"]
        A1["Agent A"]
        A2["Agent B"]
        A3["Agent C"]
    end

    subgraph PDP["Policy Decision Point"]
        PE["Policy Engine<br/>(OPA/Custom)"]
        PS["Policy Store"]
        PC["Policy Cache"]
    end

    subgraph PEP["Policy Enforcement Points"]
        PEP1["API Gateway"]
        PEP2["Agent Sidecar"]
        PEP3["MCP Server"]
    end

    A1 --> PEP1
    A2 --> PEP2
    A3 --> PEP3

    PEP1 --> PE
    PEP2 --> PE
    PEP3 --> PE

    PE --> PS
    PE --> PC
```

### 7.2. Agent Identity Mesh

```mermaid
flowchart TB
    subgraph Identity["Identity Layer"]
        IdP["Identity Provider<br/>(Keycloak)"]
        SPIRE["SPIRE Server"]
        Vault["HashiCorp Vault"]
    end

    subgraph Agents["Agent Mesh"]
        A1["Agent A"]
        A2["Agent B"]
        A3["Agent C"]

        A1 <-->|mTLS + SVID| A2
        A2 <-->|mTLS + SVID| A3
        A1 <-->|mTLS + SVID| A3
    end

    subgraph Policy["Policy Layer"]
        OPA["OPA"]
        Rules["Agent Policies"]
    end

    Identity --> Agents
    Agents --> Policy
```

### 7.3. Token Vault Pattern

```mermaid
sequenceDiagram
    participant User
    participant Agent
    participant Vault as Token Vault
    participant Tool as External Tool

    User->>Agent: Task
    Agent->>Vault: Get token for Tool

    alt Token exists and valid
        Vault-->>Agent: Cached token
    else Token expired or missing
        Vault->>Tool: OAuth refresh/exchange
        Tool-->>Vault: New token
        Vault-->>Agent: New token
    end

    Agent->>Tool: API call + token
    Tool-->>Agent: Response
    Agent-->>User: Result
```

### 7.4. Intent-Bound Authorization

```mermaid
flowchart TB
    subgraph Request["Authorization Request"]
        User["User Context"]
        Agent["Agent Identity"]
        Intent["Task Intent<br/>(hashed prompt)"]
        Resource["Target Resource"]
    end

    subgraph Validation["Intent Validation"]
        V1["Intent matches<br/>declared capabilities?"]
        V2["Intent within<br/>user permissions?"]
        V3["Intent not<br/>blocked by policy?"]
    end

    subgraph Decision["Decision"]
        Allow["ALLOW<br/>+ intent-bound token"]
        Deny["DENY"]
    end

    Request --> Validation
    V1 --> V2
    V2 --> V3
    V3 --> Decision
```

---

## 8. Рекомендации для проекта

### 8.1. Расширение текущей архитектуры

Текущая архитектура Go Authorization Service может быть расширена для поддержки агентов:

```mermaid
flowchart TB
    subgraph Current["Текущие компоненты"]
        JWT["JWT Service"]
        Policy["Policy Service"]
        TokenExchange["Token Exchange"]
        Audit["Audit Service"]
    end

    subgraph New["Новые компоненты для агентов"]
        AgentRegistry["Agent Registry"]
        DelegationManager["Delegation Manager"]
        IntentValidator["Intent Validator"]
        ChainTracker["Chain Tracker"]
    end

    subgraph Enhanced["Расширенные"]
        PolicyExt["Policy Service<br/>+ Agent rules"]
        AuditExt["Audit Service<br/>+ Delegation chains"]
    end

    Current --> Enhanced
    New --> Enhanced
```

### 8.2. Новые сущности

```go
// Agent Identity
type AgentIdentity struct {
    ID              string            `json:"id"`
    Name            string            `json:"name"`
    Type            AgentType         `json:"type"`
    Capabilities    []string          `json:"capabilities"`
    AllowedTools    []string          `json:"allowed_tools"`
    MaxChainDepth   int               `json:"max_chain_depth"`
    TrustLevel      TrustLevel        `json:"trust_level"`
    IdentityHash    string            `json:"identity_hash"` // hash(prompt + tools + config)
    CreatedAt       time.Time         `json:"created_at"`
    ExpiresAt       *time.Time        `json:"expires_at"`
}

// Delegation Chain
type DelegationChain struct {
    OriginalUser    string            `json:"original_user"`
    Steps           []DelegationStep  `json:"steps"`
    CurrentDepth    int               `json:"current_depth"`
    MaxDepth        int               `json:"max_depth"`
    OriginalScope   []string          `json:"original_scope"`
    CurrentScope    []string          `json:"current_scope"`
    IntentHash      string            `json:"intent_hash"`
}

type DelegationStep struct {
    AgentID         string            `json:"agent_id"`
    Timestamp       time.Time         `json:"timestamp"`
    ScopeReduction  []string          `json:"scope_reduction"`
    Justification   string            `json:"justification"`
}

// Agent-to-Agent Authorization Request
type A2AAuthzRequest struct {
    SourceAgent     AgentIdentity     `json:"source_agent"`
    TargetAgent     string            `json:"target_agent"`
    Action          string            `json:"action"`
    DelegationChain *DelegationChain  `json:"delegation_chain,omitempty"`
    Intent          *Intent           `json:"intent,omitempty"`
    Context         map[string]any    `json:"context"`
}

type Intent struct {
    Description     string            `json:"description"`
    Hash            string            `json:"hash"`
    AllowedActions  []string          `json:"allowed_actions"`
    ExpiresAt       time.Time         `json:"expires_at"`
}
```

### 8.3. Расширение Policy Engine

```rego
package agent_authz

import future.keywords.in

default allow = false

# Agent-to-Agent authorization
allow {
    valid_agent_identity
    agent_to_agent_permitted
    delegation_chain_valid
    scope_valid
    intent_valid
}

valid_agent_identity {
    input.source_agent.id != ""
    input.source_agent.identity_hash != ""
    not agent_revoked(input.source_agent.id)
}

agent_to_agent_permitted {
    rule := data.agent_policies[input.source_agent.id]
    input.target_agent in rule.allowed_targets
    input.action in rule.allowed_actions
}

delegation_chain_valid {
    chain := input.delegation_chain
    chain.current_depth <= chain.max_depth

    # Each step must reduce or maintain scope
    all_scopes_valid(chain.steps)
}

scope_valid {
    requested := input.requested_scope
    allowed := input.delegation_chain.current_scope

    # All requested scopes must be in allowed
    every scope in requested {
        scope in allowed
    }
}

intent_valid {
    intent := input.intent
    intent.expires_at > time.now_ns()
    input.action in intent.allowed_actions
}

# Helpers
agent_revoked(agent_id) {
    data.revoked_agents[agent_id]
}

all_scopes_valid(steps) {
    count(steps) <= 1
}

all_scopes_valid(steps) {
    count(steps) > 1
    every i in numbers.range(1, count(steps) - 1) {
        scope_subset(steps[i].scope_reduction, steps[i-1].scope_reduction)
    }
}
```

### 8.4. Конфигурация агентов

```yaml
# config/agents.yaml

agents:
  registration:
    enabled: true
    require_approval: true
    max_ttl: 24h

  identity:
    hash_algorithm: sha256
    include_in_hash:
      - system_prompt
      - tools
      - model_version

  delegation:
    max_chain_depth: 3
    require_scope_reduction: true
    require_intent_binding: true

  trust_levels:
    - name: untrusted
      max_scope: ["read:public"]
      max_chain_depth: 1
      require_human_approval: true

    - name: basic
      max_scope: ["read:*"]
      max_chain_depth: 2
      require_human_approval: false

    - name: trusted
      max_scope: ["read:*", "write:owned"]
      max_chain_depth: 3
      require_human_approval: false

    - name: privileged
      max_scope: ["*"]
      max_chain_depth: 3
      require_human_approval: true

  policies:
    agent-orchestrator:
      trust_level: trusted
      allowed_targets:
        - agent-data-analyst
        - agent-report-generator
      allowed_actions:
        - query_data
        - generate_report
      max_calls_per_minute: 100

    agent-data-analyst:
      trust_level: basic
      allowed_targets:
        - database-api
      allowed_actions:
        - read
      restricted_tables:
        - users
        - credentials

  audit:
    log_all_decisions: true
    log_delegation_chains: true
    log_intent_hashes: true
    retention_days: 90

  human_in_loop:
    critical_actions:
      - send_email
      - delete_*
      - financial_transaction
      - access_pii
    approval_timeout: 5m
    notification_channels:
      - push
      - email
```

### 8.5. API расширения

```yaml
# POST /v1/agents/register
# Регистрация нового агента

Request:
  name: string
  type: "llm" | "workflow" | "tool"
  capabilities: string[]
  system_prompt_hash: string
  tools: string[]
  requested_trust_level: string

Response:
  agent_id: string
  identity_hash: string
  status: "pending_approval" | "active"
  credentials:
    client_id: string
    client_secret: string  # one-time display

---

# POST /v1/authorize/agent
# Авторизация agent-to-agent

Request:
  source_agent:
    id: string
    identity_hash: string
  target_agent: string
  action: string
  delegation_chain:
    original_user: string
    steps: [...]
    current_scope: string[]
  intent:
    description: string
    hash: string

Response:
  allow: boolean
  reasons: string[]
  delegated_token: string  # if allowed
  scope: string[]
  expires_in: integer

---

# POST /v1/delegation/exchange
# Token exchange с delegation chain

Request:
  grant_type: "urn:ietf:params:oauth:grant-type:token-exchange"
  subject_token: string
  subject_token_type: "urn:ietf:params:oauth:token-type:access_token"
  actor_token: string  # agent's token
  actor_token_type: "urn:ietf:params:oauth:token-type:jwt"
  audience: string
  scope: string
  intent_hash: string

Response:
  access_token: string
  token_type: "Bearer"
  expires_in: integer
  scope: string
  delegation_chain: object  # included in token
```

### 8.6. Roadmap интеграции

```mermaid
gantt
    title Agent Authorization Integration
    dateFormat YYYY-MM-DD

    section Phase 1: Foundation
    Agent Registry             :a1, 2025-01-01, 10d
    Agent Identity Model       :a2, after a1, 7d
    Basic A2A Authorization    :a3, after a2, 14d

    section Phase 2: Delegation
    Delegation Chain Tracking  :b1, after a3, 10d
    Scope Attenuation         :b2, after b1, 7d
    Token Exchange Extension   :b3, after b2, 10d

    section Phase 3: Advanced
    Intent Binding            :c1, after b3, 14d
    Human-in-Loop Integration :c2, after c1, 10d
    Async Authorization (CIBA):c3, after c2, 14d

    section Phase 4: Hardening
    Audit Enhancement         :d1, after c3, 7d
    Policy Templates          :d2, after d1, 7d
    Performance Optimization  :d3, after d2, 10d
```

---

## 9. Источники

### Стандарты и спецификации

- [RFC 8693 - OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693)
- [IETF Draft: OAuth for AI Agents On-Behalf-Of User](https://www.ietf.org/archive/id/draft-oauth-ai-agents-on-behalf-of-user-01.html)
- [MCP Authorization Specification](https://modelcontextprotocol.io/specification/2025-03-26/basic/authorization)
- [SPIFFE/SPIRE Documentation](https://spiffe.io/docs/latest/)

### Индустриальные фреймворки

- [CSA: Agentic AI Identity & Access Management](https://cloudsecurityalliance.org/artifacts/agentic-ai-identity-and-access-management-a-new-approach)
- [CSA: Securing LLM-Backed Systems](https://cloudsecurityalliance.org/artifacts/securing-llm-backed-systems-essential-authorization-practices)
- [OWASP Top 10 for LLM Applications 2025](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/2025/12/09/owasp-genai-security-project-releases-top-10-risks-and-mitigations-for-agentic-ai-security/)

### Вендорские решения

- [Okta Auth for GenAI](https://www.okta.com/newsroom/press-releases/auth0-platform-innovation/)
- [Microsoft Entra Agent ID](https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/what-is-agent-id)
- [Auth0 Token Vault](https://auth0.com/blog/auth0-token-vault-secure-token-exchange-for-ai-agents/)
- [HashiCorp Vault for AI Agents](https://developer.hashicorp.com/validated-patterns/vault/ai-agent-identity-with-hashicorp-vault)

### Исследования

- [arXiv: Agentic JWT - Secure Delegation Protocol](https://arxiv.org/abs/2509.13597)
- [arXiv: Zero-Trust Identity Framework for Agentic AI](https://arxiv.org/abs/2505.19301)
- [OpenID Foundation: AI Agent Identity Whitepaper](https://openid.net/new-whitepaper-tackles-ai-agent-identity-challenges/)

### Практические руководства

- [AWS: Agentic AI Security Scoping Matrix](https://aws.amazon.com/blogs/security/the-agentic-ai-security-scoping-matrix-a-framework-for-securing-autonomous-ai-systems/)
- [McKinsey: Deploying Agentic AI with Safety and Security](https://www.mckinsey.com/capabilities/risk-and-resilience/our-insights/deploying-agentic-ai-with-safety-and-security-a-playbook-for-technology-leaders)
- [WorkOS: Securing AI Agents Guide](https://workos.com/blog/securing-ai-agents)
- [Wiz: Securing Agentic AI](https://www.wiz.io/academy/securing-agentic-ai)

### Security Best Practices

- [Anthropic: Claude Code Security](https://docs.claude.com/en/docs/claude-code/security)
- [OpenAI: ChatGPT Agent Security](https://help.openai.com/en/articles/11752874-chatgpt-agent)
- [Strata.io: OAuth and Agentic Identity](https://www.strata.io/blog/agentic-identity/oauth-agentic-identity-zero-trust-ai-6b/)
- [Solo.io: Can SPIFFE Work for Agent IAM?](https://www.solo.io/blog/agent-identity-and-access-management---can-spiffe-work)

---

## История изменений

| Версия | Дата | Автор | Изменения |
|--------|------|-------|-----------|
| 1.0 | 2025-12-17 | Claude | Начальная версия |

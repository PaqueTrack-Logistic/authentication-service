# Authentication Service - Documentación Técnica Completa


**Versión**: 0.0.1-SNAPSHOT  
**Java**: 21  
**Spring Boot**: 4.0.5  
**Arquitectura**: Hexagonal (Domain-Driven Design)  
**Autor**: Logistics Team  


---


## 📑 Tabla de Contenidos


1. [Descripción General](#descripción-general)
2. [Stack Tecnológico](#stack-tecnológico)
3. [Arquitectura de Alto Nivel](#arquitectura-de-alto-nivel)
4. [Estructura del Proyecto](#estructura-del-proyecto)
5. [Flujo de Autenticación](#flujo-de-autenticación)
6. [Seguridad](#seguridad)
7. [API REST](#api-rest)
8. [Configuración](#configuración)
9. [Testing](#testing)
10. [Docker & Despliegue](#docker--despliegue)




---


## Descripción General


**authentication-service** es un microservicio especializado en autenticación y autorización para arquitecturas de microservicios. Implementa:


- ✅ **Autenticación stateless** con JWT Bearer tokens
- ✅ **Refresh tokens opacos** con rotación automática
- ✅ **Control de acceso basado en roles (RBAC)** mediante claims JWT
- ✅ **Auditoría completa** de intentos de login
- ✅ **Protección contra ataques** de fuerza bruta (account lockout)
- ✅ **Integración con API Gateway** mediante headers forwarded
- ✅ **Arquitectura hexagonal** para máxima desacoplabilidad


Se ejecuta **detrás de un API Gateway** que mapea rutas públicas (`/api/auth/**`) a las rutas internas del servicio (`/api/v1/auth/**`).


---


## Stack Tecnológico


| Capa | Tecnología | Versión |
|------|-----------|---------|
| **Runtime** | Java (OpenJDK) | 21 |
| **Framework** | Spring Boot | 4.0.5 (LTS) |
| **Build** | Maven | 3.9+ |
| **Base de Datos** | PostgreSQL | 15+ |
| **Migraciones** | Flyway | Latest (spring-boot) |
| **Seguridad** | Spring Security | 6.x |
| **JWT** | JJWT | 0.12.6 |
| **Validación** | Jakarta Bean Validation | Latest |
| **API Docs** | SpringDoc OpenAPI | 3.0.0 |
| **Mapeo de Objetos** | Lombok | Latest |
| **Testing** | JUnit 5 + Karate | 1.5.0 |
| **Container** | Docker | Multi-stage |
| **Logs** | SLF4J + Logback | Default Spring Boot |


---


## Arquitectura de Alto Nivel


### Diagrama de Flujo: Autenticación y Autorización


```mermaid
sequenceDiagram
    participant FE as 🖥️ Frontend
    participant GW as 🚪 API Gateway
    participant AUTH as 🔐 Auth Service
    participant DB as 🗄️ PostgreSQL
    participant CRYPTO as 🔑 Security
   
    rect rgb(200, 220, 250)
    Note over FE,CRYPTO: 1️⃣ LOGIN FLOW
    FE->>GW: POST /api/auth/login<br/>{email, password}
    GW->>AUTH: POST /api/v1/auth/login
    AUTH->>DB: Busca usuario por email
    DB-->>AUTH: UserEntity (si existe)
    AUTH->>CRYPTO: Verifica BCrypt password
    CRYPTO-->>AUTH: ✓ Password válido
    AUTH->>CRYPTO: Genera JWT Access Token
    AUTH->>CRYPTO: Genera Refresh Token Opaco
    AUTH->>CRYPTO: SHA-256 hash del token
    AUTH->>DB: Persiste refresh token hash
    AUTH->>DB: Registra auditoría (éxito)
    AUTH-->>GW: 200 OK
    GW-->>FE: {accessToken, refreshToken, roles, expiresIn}
    end
   
    rect rgb(220, 250, 220)
    Note over FE,CRYPTO: 2️⃣ AUTHORIZED REQUEST
    FE->>GW: GET /api/auth/me<br/>Authorization: Bearer JWT
    GW->>AUTH: GET /api/v1/auth/me
    AUTH->>CRYPTO: Valida firma JWT (HS256)
    CRYPTO-->>AUTH: ✓ JWT válido
    AUTH->>DB: Carga UserAccount
    DB-->>AUTH: Usuario + roles
    AUTH-->>GW: 200 OK {user data}
    GW-->>FE: Datos del usuario
    end
   
    rect rgb(250, 220, 220)
    Note over FE,CRYPTO: 3️⃣ REFRESH TOKEN FLOW
    FE->>GW: POST /api/auth/refresh<br/>{refreshToken}
    GW->>AUTH: POST /api/v1/auth/refresh
    AUTH->>CRYPTO: SHA-256 hash del token
    AUTH->>DB: Busca refresh token (activo)
    DB-->>AUTH: RefreshTokenEntity
    AUTH->>DB: Revoca refresh token anterior
    AUTH->>CRYPTO: Genera JWT nuevo
    AUTH->>CRYPTO: Genera Refresh Token nuevo
    AUTH->>DB: Persiste nuevo refresh token
    AUTH-->>GW: 200 OK
    GW-->>FE: {accessToken nuevo, refreshToken nuevo}
    end
```


### Diagrama de Componentes: Arquitectura Hexagonal


```mermaid
graph TB
    subgraph INPUT["🌐 ENTRADA - Web Adapters"]
        CTRL["<b>AuthController</b><br/>AdminStatsController<br/>GlobalExceptionHandler"]
        FILTER["<b>Filters</b><br/>JwtAuthenticationFilter<br/>TraceIdFilter"]
    end
   
    subgraph APPPORT["📨 Puertos de Entrada - Use Cases"]
        UC1["<b>LoginUseCase</b>"]
        UC2["<b>RefreshTokenUseCase</b>"]
        UC3["<b>GetUserRoleStatsUseCase</b>"]
    end
   
    subgraph APPSERVICE["⚙️ Servicios de Aplicación"]
        SVC1["<b>LoginService</b><br/>Implementa LoginUseCase"]
        SVC2["<b>RefreshTokenService</b><br/>Implementa RefreshTokenUseCase"]
        SVC3["<b>UserRoleStatsService</b><br/>Implementa GetUserRoleStatsUseCase"]
    end
   
    subgraph DOMAIN["🎯 Capa de Dominio - Lógica Pura"]
        MODEL["<b>UserAccount</b><br/>LoginCommand<br/>LoginResult"]
        EXC["<b>AuthenticationDomainException</b>"]
        READM["<b>RoleUserCount</b><br/>(Read Model)"]
    end
   
    subgraph OUTPORT["📤 Puertos de Salida"]
        PORT1["UserRepositoryPort<br/>PasswordEncoderPort"]
        PORT2["JwtTokenProviderPort<br/>RefreshTokenIssuerPort"]
        PORT3["LoginAuditPort<br/>UserRoleStatsQueryPort"]
    end
   
    subgraph INFRAADAPT["🔧 Infraestructura - Adaptadores OUT"]
        PERSIST_ADAPT["<b>Adapters Persistencia</b><br/>UserPersistenceAdapter<br/>RefreshTokenPersistenceAdapter"]
        JWT_ADAPT["<b>Adapters Seguridad</b><br/>JwtTokenProviderAdapter<br/>PasswordEncoderAdapter<br/>RefreshTokenIssuerAdapter"]
        AUDIT_ADAPT["<b>LoginAuditJdbcAdapter</b>"]
    end
   
    subgraph INFRAENT["🗂️ Entidades JPA"]
        ENTITY["UserEntity<br/>RoleEntity<br/>RefreshTokenEntity"]
        REPO["<b>Repositories</b><br/>UserJpaRepository<br/>RefreshTokenJpaRepository"]
    end
   
    subgraph CONFIG["⚙️ Configuración"]
        CONF["SecurityConfig<br/>JwtProperties<br/>JwtSecretStrengthValidator"]
    end
   
    subgraph EXTERNAL["🗄️ SERVICIOS EXTERNOS"]
        DB[("PostgreSQL<br/>auth_db")]
    end
   
    %% Flujo de entrada
    FILTER -->|valida JWT| CTRL
    CTRL -->|solicita| UC1
    CTRL -->|solicita| UC2
    CTRL -->|solicita| UC3
   
    %% Puertos a Servicios
    UC1 -->|implementa| SVC1
    UC2 -->|implementa| SVC2
    UC3 -->|implementa| SVC3
   
    %% Servicios al Dominio
    SVC1 -->|usa| MODEL
    SVC2 -->|usa| MODEL
    SVC3 -->|usa| READM
    SVC1 -.->|lanza| EXC
    SVC2 -.->|lanza| EXC
   
    %% Servicios a Puertos OUT
    SVC1 -->|depende| PORT1
    SVC1 -->|depende| PORT2
    SVC1 -->|depende| PORT3
    SVC2 -->|depende| PORT1
    SVC2 -->|depende| PORT2
    SVC3 -->|depende| PORT3
   
    %% Puertos a Adaptadores
    PORT1 -->|implementa| PERSIST_ADAPT
    PORT1 -->|implementa| JWT_ADAPT
    PORT2 -->|implementa| JWT_ADAPT
    PORT3 -->|implementa| AUDIT_ADAPT
   
    %% Adaptadores a Entidades
    PERSIST_ADAPT -->|usa| ENTITY
    PERSIST_ADAPT -->|usa| REPO
    JWT_ADAPT -->|configura| CONF
   
    %% Repositorios a BD
    REPO -->|CRUD| DB
    AUDIT_ADAPT -->|escribe| DB
   
    %% Estilos
    classDef input fill:#bbdefb,stroke:#1976d2,stroke-width:2px,color:#000
    classDef port fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#000
    classDef service fill:#ffe0b2,stroke:#f57c00,stroke-width:2px,color:#000
    classDef domain fill:#fff9c4,stroke:#fbc02d,stroke-width:2px,color:#000
    classDef infra fill:#ffccbc,stroke:#d84315,stroke-width:2px,color:#000
    classDef entity fill:#f8bbd0,stroke:#c2185b,stroke-width:2px,color:#000
    classDef external fill:#d1c4e9,stroke:#512da8,stroke-width:2px,color:#fff
   
    class INPUT,CTRL,FILTER input
    class APPPORT,UC1,UC2,UC3 port
    class APPSERVICE,SVC1,SVC2,SVC3 service
    class DOMAIN,MODEL,EXC,READM domain
    class OUTPORT,PORT1,PORT2,PORT3 port
    class INFRAADAPT,PERSIST_ADAPT,JWT_ADAPT,AUDIT_ADAPT,CONFIG infra
    class INFRAENT,ENTITY,REPO entity
    class EXTERNAL,DB external
```




## Estructura del Proyecto


```
authentication-service-main/
│
├── src/main/
│   │
│   ├── java/com/logistics/authentication/
│   │   │
│   │   ├── AuthenticationApplication.java
│   │   │   └── @SpringBootApplication, @EnableJpaAuditing
│   │   │
│   │   ├── application/
│   │   │   ├── port/
│   │   │   │   ├── in/
│   │   │   │   │   ├── LoginUseCase.java (interface)
│   │   │   │   │   ├── RefreshTokenUseCase.java (interface)
│   │   │   │   │   └── GetUserRoleStatsUseCase.java (interface)
│   │   │   │   │
│   │   │   │   └── out/
│   │   │   │       ├── UserRepositoryPort.java (interface)
│   │   │   │       ├── PasswordEncoderPort.java (interface)
│   │   │   │       ├── JwtTokenProviderPort.java (interface)
│   │   │   │       ├── LoginAuditPort.java (interface)
│   │   │   │       ├── RefreshTokenIssuerPort.java (interface)
│   │   │   │       ├── RefreshTokenRepositoryPort.java (interface)
│   │   │   │       └── UserRoleStatsQueryPort.java (interface)
│   │   │   │
│   │   │   └── service/
│   │   │       ├── LoginService.java ⭐ Implementa LoginUseCase
│   │   │       ├── RefreshTokenService.java ⭐ Implementa RefreshTokenUseCase
│   │   │       └── UserRoleStatsService.java ⭐ Implementa GetUserRoleStatsUseCase
│   │   │
│   │   ├── domain/
│   │   │   ├── model/
│   │   │   │   ├── UserAccount.java (Value Object)
│   │   │   │   └── (CommandObjects & ResultObjects)
│   │   │   │
│   │   │   ├── exception/
│   │   │   │   └── AuthenticationDomainException.java
│   │   │   │
│   │   │   └── readmodel/
│   │   │       └── RoleUserCount.java
│   │   │
│   │   └── infrastructure/
│   │       │
│   │       ├── adapter/
│   │       │   │
│   │       │   ├── in/web/
│   │       │   │   ├── AuthController.java ⭐ REST endpoints
│   │       │   │   ├── AdminStatsController.java
│   │       │   │   ├── GlobalExceptionHandler.java
│   │       │   │   │
│   │       │   │   ├── dto/
│   │       │   │   │   ├── LoginRequest.java
│   │       │   │   │   ├── LoginResponseBody.java
│   │       │   │   │   ├── RefreshRequest.java
│   │       │   │   │   ├── MeResponseBody.java
│   │       │   │   │   └── ApiErrorResponse.java
│   │       │   │   │
│   │       │   │   ├── filter/
│   │       │   │   │   └── TraceIdFilter.java (Correlación)
│   │       │   │   │
│   │       │   │   └── security/
│   │       │   │       ├── JwtAuthenticationFilter.java
│   │       │   │       ├── JwtPrincipal.java
│   │       │   │       ├── JsonAuthenticationEntryPoint.java
│   │       │   │       └── JwtTokenExtractor.java
│   │       │   │
│   │       │   └── out/
│   │       │       │
│   │       │       ├── persistence/
│   │       │       │   ├── UserPersistenceAdapter.java
│   │       │       │   ├── RefreshTokenPersistenceAdapter.java
│   │       │       │   ├── UserRoleStatsAdapter.java
│   │       │       │   │
│   │       │       │   ├── entity/
│   │       │       │   │   ├── UserEntity.java (@Entity)
│   │       │       │   │   ├── RoleEntity.java (@Entity)
│   │       │       │   │   └── RefreshTokenEntity.java (@Entity)
│   │       │       │   │
│   │       │       │   ├── repository/
│   │       │       │   │   ├── UserJpaRepository.java (Spring Data)
│   │       │       │   │   └── RefreshTokenJpaRepository.java (Spring Data)
│   │       │       │   │
│   │       │       │   └── mapper/
│   │       │       │       └── UserMapper.java
│   │       │       │
│   │       │       ├── security/
│   │       │       │   ├── JwtTokenProviderAdapter.java
│   │       │       │   ├── PasswordEncoderAdapter.java
│   │       │       │   └── RefreshTokenIssuerAdapter.java
│   │       │       │
│   │       │       ├── crypto/
│   │       │       │   ├── OpaqueRefreshTokenGenerator.java
│   │       │       │   └── Sha256Hex.java
│   │       │       │
│   │       │       └── audit/
│   │       │           └── LoginAuditJdbcAdapter.java
│   │       │
│   │       └── config/
│   │           ├── SecurityConfig.java ⭐ @EnableWebSecurity
│   │           ├── SecurityProperties.java
│   │           ├── JwtProperties.java
│   │           ├── JwtSecretStrengthValidator.java
│   │           ├── ClockConfig.java
│   │           ├── JacksonConfig.java
│   │           ├── OpenApiConfig.java
│   │           └── SecurityBeansConfig.java
│   │
│   └── resources/
│       ├── application.properties (base, dev mode)
│       ├── application-prod.properties
│       │
│       └── db/migration/ (Flyway)
│           ├── V1__auth_schema_and_seed.sql ⭐
│           │   └── Tablas + stored procedure + seed data
│           ├── V2__security_events_user_index.sql
│           │   └── Índices adicionales
│           └── V3__auth_refresh_tokens.sql
│               └── Tabla refresh tokens
│
├── src/test/
│   │
│   ├── java/com/logistics/authentication/
│   │   ├── AuthenticationApplicationTest.java
│   │   ├── application/service/ (service tests)
│   │   ├── domain/ (domain tests)
│   │   ├── infrastructure/adapter/ (adapter tests)
│   │   └── karate/
│   │       ├── AuthKarateTest.java (entry point)
│   │       └── H2StoredProcedures.java (SP para tests)
│   │
│   └── resources/
│       ├── application.properties (H2 in-memory)
│       ├── schema.sql
│       ├── data.sql
│       ├── karate-config.js
│       └── karate/auth/
│           └── auth-login.feature ⭐ BDD scenarios
│
├── pom.xml ⭐ Maven dependencies & build
├── Dockerfile ⭐ Multi-stage build
├── docker-compose.yml (local dev)
├── render.yaml ⭐ Render deployment config
├── mvnw / mvnw.cmd (Maven wrapper)
└── README.md
```


---


## Flujo de Autenticación


### 1️⃣ Login (`POST /api/v1/auth/login`)


```
REQUEST:
{
  "email": "admin@logistics.com",
  "password": "password"
}


PROCESS (LoginService):
  1. Busca usuario por email (case-insensitive)
     → Si no existe: registra auditoría (USER_NOT_FOUND) y lanza 401
 
  2. Verifica si cuenta está habilitada
     → Si no: registra auditoría (ACCOUNT_DISABLED) y lanza 403
 
  3. Verifica si cuenta está bloqueada
     → Si sí: registra auditoría (ACCOUNT_LOCKED) y lanza 403
 
  4. Verifica password contra hash BCrypt
     → Si no coincide:
       • Incrementa failed_login_attempts
       • Si >= 5 intentos: bloquea 15 minutos (locked_until = now + 15min)
       • Registra auditoría (AUTH_INVALID_PASSWORD)
       • Lanza 401
     → Si coincide:
       • Resetea failed_login_attempts = 0
       • Registra auditoría exitosa
 
  5. Genera JWT Access Token (1h TTL)
     Sub: UUID del usuario
     Claims: email, roles (RBAC)
     Signed: HS256 (secret)
 
  6. Genera Refresh Token Opaco
     • Token: Base64 URL-safe (32 bytes = 256 bits de entropy)
     • Persistencia: Solo hash SHA-256 en BD
     • TTL: 7 días
     • Revocación masiva: Revoca todos los refresh tokens previos del usuario
 
  7. Registra auditoría de login exitoso


RESPONSE (200):
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "roles": ["ROLE_ADMIN"],
  "refreshToken": "R7n3bX9qZ2_LwKp8mE...",
  "refreshExpiresIn": 604800
}
```


### 2️⃣ Refresh Token (`POST /api/v1/auth/refresh`)


```
REQUEST:
{
  "refreshToken": "R7n3bX9qZ2_LwKp8mE..."
}


PROCESS (RefreshTokenService):
  1. Valida que refresh token no sea nulo/vacío
 
  2. Calcula hash SHA-256 del token opaco
 
  3. Busca en BD el token activo (no revocado, no expirado)
     → Si no existe: lanza 401 (INVALID_REFRESH)
 
  4. Busca usuario asociado
     → Si no existe: lanza 401
 
  5. Verifica cuenta habilitada y no bloqueada
     → Si problemas: lanza 403
 
  6. REVOCA el refresh token anterior (revoked = true)
 
  7. Genera nuevos tokens:
     • Nuevo JWT Access Token
     • Nuevo Refresh Token Opaco (rotación)
     • Nuevo TTL en BD


RESPONSE (200):
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...NUEVO",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "roles": ["ROLE_ADMIN"],
  "refreshToken": "X4m9pL2wQ5_JtRe3bN...NUEVO",
  "refreshExpiresIn": 604800
}
```


### 3️⃣ Get User Info (`GET /api/v1/auth/me`)


```
REQUEST:
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...


PROCESS:
  1. JwtAuthenticationFilter extrae JWT del header
  2. Valida firma HS256
  3. Valida expiración
  4. Extrae claims (email, roles)
  5. Carga UserAccount del contexto Spring Security


RESPONSE (200):
{
  "id": "33333333-3333-3333-3333-333333333333",
  "email": "admin@logistics.com",
  "roles": ["ROLE_ADMIN"]
}
```


### 4️⃣ Admin Stats (`GET /api/v1/admin/stats`)


```
REQUEST:
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...


CHECKS:
  1. JWT válido
  2. Usuario autenticado
  3. User debe tener rol ROLE_ADMIN (@PreAuthorize("hasRole('ROLE_ADMIN')"))
     → Si no: lanza 403 (AccessDenied)


RESPONSE (200):
{
  "stats": [
    { "roleName": "ROLE_ADMIN", "userCount": 1 },
    { "roleName": "ROLE_OPERATOR", "userCount": 0 }
  ]
}
```


---


## Seguridad


### 🔐 Seguridad de Credenciales


| Aspecto | Implementación | Justificación |
|--------|-----------------|---------------|
| **Password Hashing** | BCrypt (coste 10) | Resistance a brute-force, adaptive hashing |
| **Verificación** | Constant-time matching | Protección contra timing attacks |
| **Storage** | `password_hash` en BD | Nunca en claro |
| **Transmisión** | HTTPS/TLS (en production) | Encriptación en tránsito |


### 🔑 JWT Access Tokens


```
Header: {
  "alg": "HS256",
  "typ": "JWT"
}


Payload: {
  "sub": "33333333-3333-3333-3333-333333333333",  // UUID usuario
  "email": "admin@logistics.com",
  "roles": ["ROLE_ADMIN"],
  "iat": 1715604000,                               // Issued at
  "exp": 1715607600                                // Expires (3600s)
}


Signature: HMAC-SHA256(header + payload, secret)
```


**Características**:
- ✅ Stateless (no requiere sesión en servidor)
- ✅ RBAC integrado en claims
- ✅ TTL configurable (default 1h)
- ✅ Imposible falsificar (requiere secret)


### 🔄 Refresh Tokens Opacos


```
Token Plain:  R7n3bX9qZ2_LwKp8mE4vT1...  (nunca se devuelve)
              ↓ (SHA-256)
Token Hash:   a3f5c8d2e9b1... (persistido en BD)
```


**Características**:
- ✅ No son JWT (imposible leerlos/modificarlos)
- ✅ 256 bits de entropy (SecureRandom)
- ✅ Base64 URL-safe encoding
- ✅ Solo hash persistido (nunca el token en claro)
- ✅ Rotación en cada uso
- ✅ Revocación masiva al nuevo login
- ✅ TTL de 7 días (configurable)


### 🚫 Account Lockout


```
Fallos Permitidos:  5 intentos
Período de Bloqueo: 15 minutos
Almacenamiento:    
  - failed_login_attempts (contador)
  - locked_until (TIMESTAMPTZ)
```


**Lógica**:
```java
if (now.isBefore(lockedUntil)) {
    // Account está bloqueado
    throw new AuthenticationDomainException("AUTH_ACCOUNT_LOCKED", "Blocked 15 min");
}


// Si password es incorrecto:
if (newAttempts >= MAX_FAILED_ATTEMPTS) {
    lockedUntil = now.plusMinutes(15);
}
```


### 📋 Auditoría de Login


**Tabla `security_login_events`**:
```sql
- id: UUID (generado)
- user_id: UUID (nullable si falla antes de encontrar usuario)
- email: VARCHAR (siempre presente)
- success: BOOLEAN (true/false)
- reason: VARCHAR (ej: "INVALID_PASSWORD", "ACCOUNT_LOCKED", "USER_NOT_FOUND")
- occurred_at: TIMESTAMPTZ (timestamp automático)


Índices:
  - idx_security_login_events_email (para reportes por email)
  - idx_security_login_events_occurred (para análisis temporal)
  - idx_security_login_events_user_id (para soporte/auditoría)
```


**Procedimiento Almacenado**:
```sql
CALL sp_log_login_event(user_id, email, success, reason);
```


### 🛡️ HTTP Security Headers


| Header | Valor | Propósito |
|--------|-------|----------|
| `Strict-Transport-Security` | max-age=31536000 | HSTS (HTTPS-only) |
| `X-Content-Type-Options` | nosniff | Previene MIME sniffing |
| `X-Frame-Options` | DENY | Previene clickjacking |
| `Content-Security-Policy` | default-src 'self' | XSS protection |
| `X-XSS-Protection` | 1; mode=block | XSS protection (legacy) |


### 🔒 Session & CSRF


- **Session Policy**: `SessionCreationPolicy.STATELESS` (no HttpSession)
- **CSRF**: Deshabilitado (API REST con JWT, no cookies)
- **Cookies**: No se usan (stateless JWT)


### 📊 Rate Limiting


```
LOGIN_RATE_LIMIT = 5 intentos por minuto (configurable)
```


Implementación: Verificable desde logs (requiere componente externo para enforcement real).


### 🔑 JWT Secret


```properties
app.jwt.secret=${JWT_SECRET}
```


**Requerimientos**:
- ✅ Mínimo 256 bits (32 bytes)
- ✅ Generado aleatoriamente
- ✅ Único por ambiente
- ✅ Nunca hardcodeado en código
- ✅ Rotado periodicamente


**En producción**:
```bash
# Generar secret seguro (256 bits = 32 bytes en Base64 = ~44 chars)
echo $(openssl rand -base64 32)
```


---


## API REST


### Endpoints Públicos


#### `POST /api/v1/auth/login`


**Descripción**: Autentica un usuario y devuelve JWT + refresh token.


**Request**:
```json
{
  "email": "admin@logistics.com",
  "password": "password"
}
```


**Response 200**:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "roles": ["ROLE_ADMIN"],
  "refreshToken": "R7n3bX9qZ2_LwKp8mE...",
  "refreshExpiresIn": 604800,
  "_links": {
    "describedby": { "href": "/swagger-ui/index.html" }
  }
}
```


**Response 400** (Validación):
```json
{
  "errorCode": "VALIDATION_ERROR",
  "message": "Email is required",
  "timestamp": "2026-05-13T10:30:00Z"
}
```


**Response 401** (Credenciales inválidas):
```json
{
  "errorCode": "AUTH_INVALID_CREDENTIALS",
  "message": "Credenciales inválidas",
  "timestamp": "2026-05-13T10:30:00Z"
}
```


**Response 403** (Cuenta bloqueada):
```json
{
  "errorCode": "AUTH_ACCOUNT_LOCKED",
  "message": "Cuenta bloqueada temporalmente",
  "timestamp": "2026-05-13T10:30:00Z"
}
```


---


#### `POST /api/v1/auth/refresh`


**Descripción**: Renueva JWT y refresh token (rotación).


**Request**:
```json
{
  "refreshToken": "R7n3bX9qZ2_LwKp8mE..."
}
```


**Response 200**:
```json
{
  "accessToken": "eyJhbGciOiJIUzI1NiJ9...NUEVO",
  "tokenType": "Bearer",
  "expiresIn": 3600,
  "roles": ["ROLE_ADMIN"],
  "refreshToken": "X4m9pL2wQ5_JtRe3bN...NUEVO",
  "refreshExpiresIn": 604800,
  "_links": {
    "describedby": { "href": "/swagger-ui/index.html" }
  }
}
```


**Response 401** (Refresh token inválido/expirado):
```json
{
  "errorCode": "INVALID_REFRESH",
  "message": "Refresh token inválido o revocado",
  "timestamp": "2026-05-13T10:30:00Z"
}
```


---


### Endpoints Protegidos


#### `GET /api/v1/auth/me`


**Descripción**: Obtiene información del usuario autenticado.


**Authorization**: `Bearer {accessToken}`


**Response 200**:
```json
{
  "id": "33333333-3333-3333-3333-333333333333",
  "email": "admin@logistics.com",
  "roles": ["ROLE_ADMIN"]
}
```


**Response 401** (Sin token/token expirado):
```json
{
  "errorCode": "UNAUTHORIZED",
  "message": "Unauthorized",
  "timestamp": "2026-05-13T10:30:00Z"
}
```


---


#### `GET /api/v1/admin/stats`


**Descripción**: Obtiene estadísticas de usuarios por rol (solo ROLE_ADMIN).


**Authorization**: `Bearer {accessToken}` + `ROLE_ADMIN`


**Response 200**:
```json
{
  "stats": [
    {
      "roleName": "ROLE_ADMIN",
      "userCount": 1
    },
    {
      "roleName": "ROLE_OPERATOR",
      "userCount": 0
    }
  ]
}
```


**Response 403** (Sin permiso):
```json
{
  "errorCode": "ACCESS_DENIED",
  "message": "Access denied",
  "timestamp": "2026-05-13T10:30:00Z"
}
```


---


### Endpoints de Documentación


- **OpenAPI JSON**: `GET /v3/api-docs`
- **Swagger UI**: `GET /swagger-ui/index.html`


---


### Migraciones Flyway


- **V1**: Schema principal + roles + usuarios + auditoría + stored procedure
- **V2**: Índices adicionales para auditoría
- **V3**: Tabla de refresh tokens


---


## Configuración
#### `application-prod.properties` (Producción)


```properties
# Todas las propiedades vienen del entorno (variables de sistema)
server.port=${PORT:8080}
server.forward-headers-strategy=${FORWARD_HEADERS_STRATEGY}
spring.mvc.problemdetails.enabled=${MVC_PROBLEMDTLS_ENABLED}
spring.web.error.include-stacktrace=${WEB_ERROR_INCLUDE_STACKTRACE}


# Seguridad HTTP
app.security.hsts-enabled=${SECURITY_HSTS_ENABLED}
app.security.login-rate-limit-per-minute=${LOGIN_RATE_LIMIT}


# Persistencia
spring.jpa.open-in-view=${JPA_OPEN_IN_VIEW}
spring.jpa.properties.hibernate.jdbc.time_zone=${HIBERNATE_TIME_ZONE}


# Base de Datos (SECRETS)
spring.datasource.url=${DB_URL}
spring.datasource.username=${DB_USER}
spring.datasource.password=${DB_PASSWORD}
spring.jpa.hibernate.ddl-auto=${JPA_HBM2DDL_AUTO}
spring.jpa.show-sql=${JPA_SHOW_SQL}


# JWT (SECRETS)
app.jwt.secret=${JWT_SECRET}
app.jwt.access-token-ttl-seconds=${JWT_ACCESS_TOKEN_TTL_SECONDS}
app.jwt.refresh-token-ttl-seconds=${JWT_REFRESH_TOKEN_TTL_SECONDS}


# OpenAPI
springdoc.api-docs.path=${APIDOCS_PATH}
springdoc.swagger-ui.path=${SWAGGER_UI_PATH}


# Logs
logging.pattern.console=${LOGGING_PATTERN_CONSOLE}
```


## Testing


### Unit & Integration Tests


```bash
# Ejecutar todos los tests
mvn test


# Ejecutar un test específico
mvn test -Dtest=AuthenticationApplicationTest
```


**Cobertura**:
- Context loading test
- Service unit tests
- Repository adapter tests


**Base de Datos**: H2 in-memory


### BDD/E2E Tests con Karate


```bash
# Ejecutar tests Karate
mvn test -Dtest=*Karate*


# O específicamente
mvn test -Dtest=AuthKarateTest
```


**Suite**: `auth-login.feature`


**Escenarios**:
1. ✅ Login exitoso → Devuelve JWT + refresh token válidos
2. ✅ Password incorrecto → Devuelve 401
3. ✅ Email no registrado → Devuelve 401
4. ✅ Datos vacíos → Devuelve 400 (validación)


**Sintaxis Karate**:
```gherkin
Feature: Authentication Login API
  Background:
    * url baseUrl


  Scenario: Login with valid credentials returns access and refresh tokens
    Given path '/api/v1/auth/login'
    And request { email: 'admin@logistics.com', password: 'password' }
    When method POST
    Then status 200
    And match response.accessToken == '#string'
    And match response.refreshToken == '#string'
```


---


## Docker & Despliegue


### Dockerfile (Multi-stage)


```dockerfile
# Stage 1: Build
FROM maven:3.9-eclipse-temurin-22 AS builder
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -B
COPY src ./src
RUN mvn clean package -DskipTests -B


# Stage 2: Runtime
FROM eclipse-temurin:22-jre-noble
WORKDIR /app
COPY --from=builder /app/target/*.jar app.jar


# Usuario no-root para seguridad
RUN if ! id -u appuser >/dev/null 2>&1; then useradd -m appuser; fi \
    && chown -R appuser:appuser /app
USER appuser


EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```


### Docker Compose Local


```bash
# Levantar el servicio con su BD
docker compose up -d --build


# Logs
docker compose logs -f authentication-service


# Detener
docker compose down
```


### Render Deployment


```yaml
# render.yaml
services:
  - type: web
    name: authentication-service
    runtime: docker
    plan: free
    healthCheckPath: /actuator/health/readiness
    dockerfile: Dockerfile
    dockerContext: ./
    scaling:
      maxInstances: 2
      minInstances: 1
    envVars:
      - key: SPRING_PROFILES_ACTIVE
        value: prod
      - key: PORT
        value: "8080"
      # ... más variables ...
```


**Deploy**:
```bash
# Render detecta cambios en main/master automáticamente
git push origin main
```


---


## Conclusiones


**authentication-service** es un microservicio robusto, seguro y escalable que implementa:


- ✅ Autenticación stateless con JWT
- ✅ Refresh token rotation para máxima seguridad
- ✅ Protection contra brute-force attacks
- ✅ Auditoría completa
- ✅ Arquitectura hexagonal para mantenibilidad
- ✅ API Gateway integration ready
- ✅ Production-grade security practices

## Swagger / OpenAPI

Documentación REST disponible en:

```
https://authentication-service-mr3y.onrender.com/swagger-ui/index.html
```


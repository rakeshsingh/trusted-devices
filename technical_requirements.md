 overhead.

**SLA Targets:**

- Evaluation API latency: p95 < 50ms, p99 < 100ms
- Availability: 99.9% uptime
- Data retention: Audit logs 7 years, telemetry history 90 days

---

## 2. System Architecture

### 2.1 Technology Stack

- **Service Type:** RESTful Microservice
- **Language/Framework:** Python 3.11+ (FastAPI)
- **Database:** SQLite (use cloud platform specific product such as D1 on Cloudflare when available)

### 2.2 Authentication & Authorization

- **Admin/Dashboard:** JWT (JSON Web Tokens) via OAuth2 # Technical Specification: VeriDevice Core (v2.0)

**Project Name:** VeriDevice Core  
**Version:** 2.1.0  
**Status:** Draft  
**Last Updated:** February 2026

---

## 1. Executive Summary

**VeriDevice Core** is a middleware microservice designed to act as the "Single Source of Truth" for corporate device inventory and security posture. It serves two primary functions:

1. **Registry:** Maintaining a live database of trusted devices and their owners.
2. **Gatekeeper:** Providing a real-time API (`/evaluations/check`) that Identity Providers (IdPs) call to validate device trust before granting login access.

The system emphasizes "Modern PKI" (using Passkeys/WebAuthn) over traditional certificate management to ensure high security with low operational(Google/Microsoft SSO), 15-min expiry with refresh tokens.

- **MFA Required:** TOTP or WebAuthn enforced for all admin accounts
- **Session Management:** Idle timeout 15 min, absolute timeout 8 hours, max 3 concurrent sessions
- **Failed Login Protection:** Account lockout after 5 failed attempts within 5 minutes (15-min lockout)
- **Agent/Device:** API Key (rotated every 90 days) + Device-Bound Signature (WebAuthn/Passkey).
- **IdP Integration:** Service Account Bearer Tokens (rotated every 180 days, stored encrypted at rest).
- **Privileged Access:** Database and infrastructure access via PAM solution with session recording
- **Access Reviews:** Quarterly recertification of all admin and service account access
- **Rate Limiting:**
  - Evaluation API: 1000 req/min per Organization
  - Registration API: 10 req/min per user
  - Admin API: 100 req/min per admin

### 2.3 Security Controls

- **Replay Attack Protection:** Nonce-based challenges expire after 5 minutes
- **API Key Rotation:** Automated rotation with 7-day grace period for old keys
- **Encryption:**
  - At rest: AES-256 (database encryption)
  - In transit: TLS 1.3 only
  - PII fields: Application-level encryption (serial numbers, owner emails)
- **Organization Isolation:** PostgreSQL Row-Level Security (RLS) policies enforced at database level

---

## 3. Data Model (Schema)

### 3.1 Organizations (`Organizations`)

Multi-tenancy isolation.

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique Organization identifier. |
| `name` | String | Organization name. |
| `data_residency` | Enum | `US`, `EU`, `APAC` (for GDPR compliance). |
| `settings` | JSON | Organization-specific config (e.g., stale device threshold). |
| `created_at` | Timestamp | Organization onboarding date. |

**Indexes:** `id` (PK)

### 3.2 Device (`devices`)

The core entity representing a physical asset.

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique internal identifier. |
| `organization_id` | UUID (FK) | Multi-tenancy isolation. |
| `device_name` | String | User-friendly name (e.g., "John's MacBook"). |
| `serial_number_hash` | String | SHA-256 hash of hardware serial (mandatory). |
| `fingerprint` | String | Browser/Agent fingerprint hash (indexed). |
| `fingerprint_collision_count` | Integer | Tracks duplicate fingerprints (for VM detection). |
| `platform` | Enum | `macos`, `windows`, `linux`, `ios`, `android`. |
| `platform_version` | String | OS version at registration. |
| `owner_id` | UUID (FK) | Link to primary owner in `device_owners`. |
| `trust_status` | Enum | `PENDING`, `TRUSTED`, `REVOKED`, `STALE`. |
| `last_seen_at` | Timestamp | Used for "Stale Device" auto-cleanup. |
| `last_policy_evaluation` | Timestamp | Last time device was evaluated. |
| `created_at` | Timestamp | Registration date. |
| `updated_at` | Timestamp | Last modification. |

**Indexes:** `organization_id`, `fingerprint`, `owner_id`, `last_seen_at`, `trust_status`

### 3.3 Device Owners (`device_owners`)

Supports multi-user device scenarios and ownership transfers.

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique relationship ID. |
| `device_id` | UUID (FK) | Link to device. |
| `user_email` | String (encrypted) | Owner email (PII). |
| `is_primary` | Boolean | True for primary owner. |
| `assigned_at` | Timestamp | When ownership was granted. |
| `revoked_at` | Timestamp | Null if active. |

**Indexes:** `device_id`, `user_email`, `is_primary`

### 3.4 Device Credentials (`device_credentials`)

Stores WebAuthn public keys with revocation support.

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique credential ID. |
| `device_id` | UUID (FK) | Link to device. |
| `credential_id` | String | WebAuthn credential ID. |
| `public_key` | Text | COSE-encoded public key. |
| `attestation_format` | Enum | `packed`, `tpm`, `android-key`, `apple`, `none`. |
| `counter` | Integer | Signature counter (prevents cloning). |
| `status` | Enum | `ACTIVE`, `REVOKED`, `EXPIRED`. |
| `created_at` | Timestamp | Key creation date. |
| `expires_at` | Timestamp | Key expiration (default: 1 year). |

**Indexes:** `device_id`, `credential_id`, `status`

### 3.5 Device Telemetry History (`device_telemetry_history`)

Versioned health snapshots for trend analysis.

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique snapshot ID. |
| `device_id` | UUID (FK) | Link to device. |
| `os_family` | Enum | `macos`, `windows`, `linux`, `ios`, `android`. |
| `os_version` | String | e.g., "14.2.1". |
| `disk_encrypted` | Boolean | True if BitLocker/FileVault is active. |
| `firewall_enabled` | Boolean | True if host firewall is active. |
| `security_agents` | JSON | Schema-validated: `{"agent_name": {"status": "running", "version": "7.2"}}`. |
| `reported_at` | Timestamp | Time of health check. |
| `ttl` | Timestamp | Auto-delete after 90 days (partitioned table). |

**Indexes:** `device_id`, `reported_at`  
**Partitioning:** Monthly partitions, auto-pruned after 90 days

### 3.6 Policies (`policies`)

Defines trust evaluation rules.

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique policy ID. |
| `organization_id` | UUID (FK) | Organization isolation. |
| `name` | String | Policy name (e.g., "High Security Workstations"). |
| `rules` | JSON | Evaluation logic (see schema below). |
| `priority` | Integer | Higher number = higher priority. |
| `enabled` | Boolean | Active/inactive toggle. |
| `created_at` | Timestamp | Policy creation date. |
| `updated_at` | Timestamp | Last modification. |

**Rules Schema Example:**

```json
{
  "require_disk_encryption": true,
  "require_firewall": true,
  "allowed_os": ["macos", "windows"],
  "min_os_version": {"macos": "13.0", "windows": "10.0.19045"},
  "required_agents": ["crowdstrike", "jamf"],
  "max_stale_days": 30
}
```

**Indexes:** `organization_id`, `priority`, `enabled`

### 3.7 Audit Log (`audit_logs`)

Immutable history of all changes for compliance (SOC2/GDPR/ISO 27001).

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique log ID. |
| `organization_id` | UUID (FK) | Organization isolation. |
| `actor_id` | String | User email or Service Name. |
| `actor_type` | Enum | `USER`, `SERVICE`, `SYSTEM`. |
| `action_type` | String | `DEVICE_REGISTERED`, `TRUST_REVOKED`, `ACCESS_DENIED`, `LOGIN_SUCCESS`, `LOGIN_FAILED`, `DATA_ACCESSED`, `CONFIG_CHANGED`, etc. |
| `target_device_id` | UUID | The device affected. |
| `target_resource` | String | Resource accessed (e.g., device ID, policy ID, user email). |
| `result` | Enum | `SUCCESS`, `FAILURE`, `DENIED`. |
| `source_ip` | String | IP address of actor. |
| `user_agent` | String | Client user agent. |
| `metadata` | JSON | Context (reason, before/after state, risk score). |
| `timestamp` | Timestamp | When action occurred. |
| `ttl` | Timestamp | Retention: 7 years (partitioned table). |

**Logged Events:**

- All authentication attempts (success/failure)
- All admin actions (approve, revoke, transfer, policy changes)
- All data access (device details, audit log queries)
- All configuration changes (with before/after state)
- All API key operations (creation, rotation, revocation)
- All privilege escalations
- All failed authorization attempts

**Indexes:** `organization_id`, `target_device_id`, `timestamp`, `action_type`, `actor_id`, `result`  
**Partitioning:** Yearly partitions  
**Integrity:** SHA-256 hash chain linking each log entry to previous entry

### 3.8 API Keys (`api_keys`)

Service account credentials with rotation tracking.

| Field Name | Type | Description |
| :--- | :--- | :--- |
| `id` | UUID (PK) | Unique key ID. |
| `organization_id` | UUID (FK) | Organization isolation. |
| `key_hash` | String | SHA-256 hash of API key. |
| `key_prefix` | String | First 8 chars (for identification). |
| `name` | String | Human-readable name (e.g., "Okta Integration"). |
| `scopes` | Array | Permissions: `["evaluations:read", "devices:write"]`. |
| `status` | Enum | `ACTIVE`, `GRACE_PERIOD`, `REVOKED`. |
| `created_at` | Timestamp | Key creation date. |
| `expires_at` | Timestamp | Auto-rotation date (180 days). |
| `last_used_at` | Timestamp | For unused key detection. |

**Indexes:** `key_hash`, `organization_id`, `status`

---

## 4. API Specification

**Base URL:** `https://api.veridevice.com/v1`

**Global Headers:**

- `X-Organization-ID`: Required for all requests (except public endpoints)
- `X-Request-ID`: Optional, for request tracing
- `X-API-Version`: Optional, defaults to latest

**Error Response Format:**

```json
{
  "error": {
    "code": "DEVICE_NOT_FOUND",
    "message": "Device with ID 550e8400... not found",
    "request_id": "req_abc123",
    "timestamp": "2026-02-09T22:15:30Z"
  }
}
```

### 4.1. Ingestion APIs (Agent / User Portal)

Endpoints used by the "Ingest" module to register and update devices.

#### **A. Register Device**

Initiates the trust relationship.

- **Endpoint:** `POST /devices/register`

- **Auth:** User Session Token (from SSO login).
- **Rate Limit:** 10 req/min per user
- **Request Body:**

    ```json
    {
      "device_name": "John's MacBook Pro",
      "serial_number": "C02XXXXX",
      "platform": "macos",
      "platform_version": "14.2.1",
      "fingerprint": "a1b2c3d4...",
      "public_key_attestation": {
        "credential_id": "base64_encoded_id",
        "public_key": "base64_encoded_cose_key",
        "attestation_format": "packed",
        "attestation_object": "base64_encoded_object"
      }
    }
    ```

- **Response (201 Created):**

    ```json
    {
      "device_id": "550e8400-e29b-41d4-a716-446655440000",
      "status": "PENDING_APPROVAL",
      "message": "Device registered. Waiting for admin approval.",
      "credential_id": "cred_abc123"
    }
    ```

- **Response (409 Conflict - Duplicate Fingerprint):**

    ```json
    {
      "error": {
        "code": "FINGERPRINT_COLLISION",
        "message": "Device fingerprint already exists",
        "existing_device_id": "550e8400...",
        "collision_count": 2
      }
    }
    ```

#### **B. Send Telemetry (Heartbeat)**

Updates the health status.

- **Endpoint:** `POST /devices/{device_id}/telemetry`
- **Auth:** Device-Signed Header (WebAuthn challenge-response) or API Key.
- **Rate Limit:** 1 req/min per device
- **Request Headers:**
  - `X-Device-Signature`: Base64-encoded signature of request body
  - `X-Challenge-Response`: Nonce signed by device credential
- **Request Body:**

    ```json
    {
      "os_version": "14.4.1",
      "disk_encrypted": true,
      "firewall_enabled": true,
      "security_agents": {
        "crowdstrike": {
          "status": "running",
          "version": "7.2.1"
        },
        "jamf": {
          "status": "running",
          "version": "10.45.0"
        }
      }
    }
    ```

- **Response (200 OK):**

    ```json
    {
      "status": "accepted",
      "next_heartbeat_in": 300,
      "trust_status": "TRUSTED"
    }
    ```

#### **C. List Devices**

Retrieve devices for a Organization.

- **Endpoint:** `GET /devices`
- **Auth:** Admin JWT or Service API Key
- **Query Parameters:**
  - `page`: Page number (default: 1)
  - `limit`: Items per page (default: 50, max: 200)
  - `status`: Filter by trust_status
  - `owner_email`: Filter by owner
  - `sort`: Sort field (default: `created_at`)
  - `order`: `asc` or `desc` (default: `desc`)
- **Response (200 OK):**

    ```json
    {
      "devices": [
        {
          "id": "550e8400...",
          "device_name": "John's MacBook Pro",
          "platform": "macos",
          "trust_status": "TRUSTED",
          "owner_email": "john.doe@acme.com",
          "last_seen_at": "2026-02-09T22:10:00Z"
        }
      ],
      "pagination": {
        "page": 1,
        "limit": 50,
        "total": 150,
        "total_pages": 3
      }
    }
    ```

#### **D. Get Device Details**

Retrieve full device information.

- **Endpoint:** `GET /devices/{device_id}`
- **Auth:** Admin JWT or Device API Key (self-only)
- **Response (200 OK):**

    ```json
    {
      "id": "550e8400...",
      "device_name": "John's MacBook Pro",
      "platform": "macos",
      "platform_version": "14.2.1",
      "trust_status": "TRUSTED",
      "owners": [
        {
          "email": "john.doe@acme.com",
          "is_primary": true,
          "assigned_at": "2026-01-15T10:00:00Z"
        }
      ],
      "credentials": [
        {
          "id": "cred_abc123",
          "attestation_format": "packed",
          "status": "ACTIVE",
          "created_at": "2026-01-15T10:00:00Z",
          "expires_at": "2027-01-15T10:00:00Z"
        }
      ],
      "latest_telemetry": {
        "os_version": "14.4.1",
        "disk_encrypted": true,
        "firewall_enabled": true,
        "reported_at": "2026-02-09T22:10:00Z"
      },
      "last_seen_at": "2026-02-09T22:10:00Z",
      "created_at": "2026-01-15T10:00:00Z"
    }
    ```

---

### 4.2. Validation APIs (The "Gatekeeper")

High-performance API consumed by Customer Identity Providers (Okta/Auth0).

#### **E. Evaluate Access (Single)**

The core "Decision Engine." Checks Registry + Policy = Verdict.

- **Endpoint:** `POST /evaluations/check`
- **Auth:** Service API Key (Server-to-Server).
- **Rate Limit:** 1000 req/min per Organization
- **Caching:** Results cached in Redis for 60s (configurable per Organization)
- **Request Body:**

    ```json
    {
      "user_email": "john.doe@acme.com",
      "device_fingerprint": "a1b2c3d4...", 
      "device_id": "550e8400...", 
      "context": {
        "ip_address": "203.0.113.1",
        "resource": "salesforce_crm",
        "timestamp": "2026-02-09T22:15:30Z"
      }
    }
    ```

- **Response (200 OK - Allowed):**

    ```json
    {
      "decision": "ALLOW",
      "trust_score": 95,
      "device_id": "550e8400...",
      "reasons": [],
      "policy_id": "pol_xyz789",
      "ttl": 3600,
      "cached": false
    }
    ```

- **Response (200 OK - Denied):**

    ```json
    {
      "decision": "DENY",
      "trust_score": 20,
      "device_id": "550e8400...",
      "reasons": [
        {
          "code": "DEVICE_NOT_FOUND",
          "severity": "critical"
        },
        {
          "code": "DISK_NOT_ENCRYPTED",
          "severity": "high"
        }
      ],
      "remediation_url": "https://veridevice.com/fix/encrypt-disk",
      "policy_id": "pol_xyz789"
    }
    ```

- **Response (503 Service Unavailable - Degraded Mode):**

    ```json
    {
      "decision": "ALLOW",
      "trust_score": 50,
      "degraded_mode": true,
      "reason": "Cache unavailable, using fail-open policy"
    }
    ```

#### **F. Evaluate Access (Batch)**

Batch evaluation for performance optimization.

- **Endpoint:** `POST /evaluations/check/batch`
- **Auth:** Service API Key
- **Rate Limit:** 100 req/min per Organization
- **Request Body:**

    ```json
    {
      "evaluations": [
        {
          "id": "eval_1",
          "user_email": "john.doe@acme.com",
          "device_id": "550e8400..."
        },
        {
          "id": "eval_2",
          "user_email": "jane.smith@acme.com",
          "device_id": "660e9500..."
        }
      ]
    }
    ```

- **Response (200 OK):**

    ```json
    {
      "results": [
        {
          "id": "eval_1",
          "decision": "ALLOW",
          "trust_score": 95
        },
        {
          "id": "eval_2",
          "decision": "DENY",
          "trust_score": 30,
          "reasons": [{"code": "STALE_DEVICE", "severity": "high"}]
        }
      ]
    }
    ```

---

### 4.3. Management APIs (Admin Dashboard)

#### **G. Approve/Revoke Device**

- **Endpoint:** `POST /admin/devices/{device_id}/action`
- **Auth:** Admin JWT
- **Request Body:**

    ```json
    {
      "action": "APPROVE",
      "reason": "Verified with IT helpdesk ticket #12345"
    }
    ```

    Options: `APPROVE`, `REVOKE`, `MARK_STALE`
- **Response (200 OK):**

    ```json
    {
      "device_id": "550e8400...",
      "previous_status": "PENDING",
      "new_status": "TRUSTED",
      "audit_log_id": "log_abc123"
    }
    ```

#### **H. Transfer Device Ownership**

- **Endpoint:** `POST /admin/devices/{device_id}/transfer`
- **Auth:** Admin JWT
- **Request Body:**

    ```json
    {
      "new_owner_email": "jane.smith@acme.com",
      "revoke_previous_owner": true,
      "reason": "Employee transfer"
    }
    ```

- **Response (200 OK):**

    ```json
    {
      "device_id": "550e8400...",
      "previous_owner": "john.doe@acme.com",
      "new_owner": "jane.smith@acme.com",
      "audit_log_id": "log_def456"
    }
    ```

#### **I. Revoke Device Credential**

Revoke a specific WebAuthn key without revoking entire device.

- **Endpoint:** `POST /admin/devices/{device_id}/credentials/{credential_id}/revoke`
- **Auth:** Admin JWT
- **Request Body:**

    ```json
    {
      "reason": "Suspected key compromise"
    }
    ```

- **Response (200 OK):**

    ```json
    {
      "credential_id": "cred_abc123",
      "status": "REVOKED",
      "device_can_re_register": true
    }
    ```

#### **J. List Audit Logs**

- **Endpoint:** `GET /admin/audit-logs`
- **Auth:** Admin JWT
- **Query Parameters:**
  - `page`, `limit`: Pagination
  - `device_id`: Filter by device
  - `actor_id`: Filter by actor
  - `action_type`: Filter by action
  - `start_date`, `end_date`: Date range
- **Response (200 OK):**

    ```json
    {
      "logs": [
        {
          "id": "log_abc123",
          "actor_id": "admin@acme.com",
          "action_type": "DEVICE_APPROVED",
          "target_device_id": "550e8400...",
          "metadata": {
            "ip_address": "203.0.113.1",
            "reason": "Verified with IT"
          },
          "timestamp": "2026-02-09T22:00:00Z"
        }
      ],
      "pagination": {
        "page": 1,
        "limit": 50,
        "total": 500
      }
    }
    ```

#### **K. Manage Policies**

- **Endpoint:** `POST /admin/policies`
- **Auth:** Admin JWT
- **Request Body:**

    ```json
    {
      "name": "High Security Workstations",
      "rules": {
        "require_disk_encryption": true,
        "require_firewall": true,
        "allowed_os": ["macos", "windows"],
        "min_os_version": {"macos": "13.0", "windows": "10.0.19045"},
        "required_agents": ["crowdstrike"],
        "max_stale_days": 30
      },
      "priority": 100,
      "enabled": true
    }
    ```

- **Response (201 Created):**

    ```json
    {
      "policy_id": "pol_xyz789",
      "name": "High Security Workstations",
      "created_at": "2026-02-09T22:15:30Z"
    }
    ```

---

### 4.4. Webhook APIs

#### **L. Register Webhook**

- **Endpoint:** `POST /webhooks`
- **Auth:** Admin JWT
- **Request Body:**

    ```json
    {
      "url": "https://idp.acme.com/webhooks/veridevice",
      "events": ["device.revoked", "device.stale", "policy.updated"],
      "secret": "whsec_abc123"
    }
    ```

- **Response (201 Created):**

    ```json
    {
      "webhook_id": "wh_xyz789",
      "url": "https://idp.acme.com/webhooks/veridevice",
      "status": "active"
    }
    ```

**Webhook Payload Example:**

```json
{
  "event": "device.revoked",
  "timestamp": "2026-02-09T22:15:30Z",
  "data": {
    "device_id": "550e8400...",
    "owner_email": "john.doe@acme.com",
    "reason": "Device marked as lost"
  },
  "signature": "sha256=abc123..."
}
```

**Webhook Retry Logic:**

- Initial attempt: Immediate
- Retry 1: 1 minute
- Retry 2: 5 minutes
- Retry 3: 15 minutes
- Retry 4: 1 hour
- After 4 failures: Move to dead-letter queue, alert admin

---

## 5. Security & Compliance Logic

### 5.0 Data Classification

All data is classified according to sensitivity level:

| Classification | Examples | Protection Requirements |
| :--- | :--- | :--- |
| **Restricted (PII)** | `user_email`, `owner_email` | Application-level encryption, access logging, GDPR rights apply |
| **Confidential** | `serial_number_hash`, `fingerprint`, API keys | Encrypted at rest, access restricted to authorized services |
| **Internal** | Device names, platform info, telemetry | Encrypted at rest, Organization-isolated |
| **Public** | API documentation, status page | No special protection |

**Data Loss Prevention (DLP):**

- Bulk export operations (>100 devices) require admin approval and are logged
- PII fields masked in logs and error messages
- API responses exclude sensitive fields unless explicitly requested with proper scope

### 5.1 "Stale Device" Automation

- **Trigger:** Daily Background Job (Celery) at 02:00 UTC.
- **Logic:**

    ```sql
    UPDATE devices 
    SET trust_status = 'STALE',
        updated_at = NOW()
    WHERE last_seen_at < (NOW() - INTERVAL '30 DAYS')
      AND trust_status = 'TRUSTED';
    ```

- **Notification:** Webhook event `device.stale` sent to registered endpoints.
- **Grace Period:** Devices remain in `STALE` status for 7 days before auto-revocation.
- **Auto-Revocation:**

    ```sql
    UPDATE devices 
    SET trust_status = 'REVOKED',
        updated_at = NOW()
    WHERE trust_status = 'STALE'
      AND updated_at < (NOW() - INTERVAL '7 DAYS');
    ```

- **Purpose:** Ensures lost or former employee devices lose access automatically.

### 5.2 PKI / Signature Validation (Modern PKI)

#### Registration Flow

1. **Client Initiates:** User navigates to registration portal, authenticates via SSO.
2. **Challenge Generation:** API generates random 32-byte nonce, stores in Redis with 5-min TTL.
3. **WebAuthn Ceremony:** Client creates credential using platform authenticator (TPM/Secure Enclave).
4. **Attestation Validation:**
    - API validates attestation format (supports: `packed`, `tpm`, `android-key`, `apple`)
    - Verifies attestation signature chain
    - Extracts and stores `credential_id` and `public_key`
5. **Device Registration:** Creates device record with `PENDING` status.

#### Authentication Flow (Telemetry/API Calls)

1. **Challenge Request:** Device requests nonce via `GET /auth/challenge?device_id={id}`
2. **API Response:**

    ```json
    {
      "challenge": "base64_encoded_nonce",
      "expires_at": "2026-02-09T22:20:30Z"
    }
    ```

3. **Signature Generation:** Device signs challenge using stored credential.
4. **Verification:**
    - API retrieves public key for device
    - Validates signature using COSE algorithm (ES256/RS256)
    - Checks signature counter (must increment, prevents cloning)
    - Verifies challenge hasn't expired
5. **Success:** Request proceeds with device identity confirmed.
6. **Failure Scenarios:**
    - Invalid signature: `trust_score` = 0, audit log created
    - Expired challenge: HTTP 401, new challenge required
    - Counter regression: Device credential revoked, alert admin

#### Supported Attestation Formats

- **packed:** FIDO2 standard format (most common)
- **tpm:** Windows TPM 2.0
- **android-key:** Android hardware-backed keys
- **apple:** Apple Secure Enclave
- **none:** Self-attestation (lower trust score)

### 5.3 Fingerprint Collision Handling

- **Detection:** On registration, check if `fingerprint` already exists for Organization.
- **Action:**
  - Increment `fingerprint_collision_count` for both devices
  - If count > 3: Flag for admin review (possible VM farm)
  - Return HTTP 409 with existing device info
- **Resolution:** Admin can manually approve or require unique hardware identifier.

### 5.4 Graceful Degradation Strategy

#### Redis Unavailable

- **Evaluation API:**
  - Fallback to PostgreSQL direct query (slower, but functional)
  - Set `degraded_mode: true` in response
  - Apply Organization-specific fail-open/fail-closed policy
- **Challenge Storage:** Use PostgreSQL temporary table with auto-cleanup.

#### PostgreSQL Unavailable

- **Evaluation API:**
  - Return HTTP 503 with retry-after header
  - If Organization has `fail_open: true` setting, allow with `trust_score: 50`
- **Telemetry API:** Queue in Redis, process when DB recovers.

#### Celery Workers Down

- **Stale Device Job:** Manual trigger available via admin API.
- **Webhooks:** Messages remain in Redis queue, processed when workers restart.

### 5.5 Data Encryption

#### At Rest

- **PostgreSQL:** Transparent Data Encryption (TDE) enabled.
- **Application-Level:**
  - `serial_number_hash`: SHA-256 (one-way)
  - `user_email` in `device_owners`: AES-256-GCM with Organization-specific keys
  - `api_keys.key_hash`: SHA-256 with salt

#### In Transit

- **TLS 1.3:** Enforced for all API endpoints.
- **Certificate Pinning:** Recommended for agent-to-API communication.

#### Key Management

- **Encryption Keys:** Stored in AWS Secrets Manager or HashiCorp Vault.
- **Rotation:** Automatic rotation every 90 days with zero-downtime re-encryption.

### 5.6 Compliance Controls

#### SOC2 Type II

- **Audit Logs:** Immutable, 7-year retention, tamper-evident (hash chain).
- **Access Controls:** Role-based access control (RBAC) with least privilege.
- **Change Management:** All schema changes require approval + audit trail.
- **Monitoring:** Real-time alerting for security events, quarterly access reviews.
- **Vendor Management:** Annual security assessments for all third-party services.

#### GDPR

- **Data Residency:** Organization-level setting enforces regional data storage.
- **Right to Erasure:** API endpoint for device deletion (soft delete with anonymization).
- **Data Portability:** Export API for device data in JSON format.
- **Consent Management:** Device registration requires explicit user consent.
- **Breach Notification:** Automated workflow to notify DPA within 72 hours.
- **Data Processing Agreement:** Documented subprocessor list maintained.

#### ISO 27001

- **Information Security Policy:** Documented and reviewed annually.
- **Risk Assessment:** Annual threat modeling and risk register updates.
- **Asset Management:** Complete inventory of systems, data, and access.
- **Incident Management:** Documented incident response procedures with severity classification.
- **Business Continuity:** Tested DR procedures with documented RTO/RPO validation.

#### PCI-DSS (if applicable)

- **Network Segmentation:** Evaluation API isolated from admin API.
- **Logging:** All authentication attempts logged with outcome.
- **Encryption:** All cardholder data (if stored) encrypted at rest and in transit.

### 5.7 Data Retention & Deletion

| Data Type | Retention Period | Deletion Method |
| :--- | :--- | :--- |
| Active device records | While device is TRUSTED or PENDING | N/A |
| Revoked device records | 2 years after revocation | Soft delete, then hard delete |
| Audit logs | 7 years | Automated partition drop |
| Telemetry history | 90 days | Automated partition drop |
| API keys (revoked) | 1 year | Hard delete with audit log |
| User consent records | 7 years | Encrypted archive |

**Automated Deletion Jobs:**

- Daily: Expired challenges, temporary tokens
- Weekly: Revoked devices older than 2 years
- Monthly: Telemetry partitions older than 90 days
- Yearly: Audit log partitions older than 7 years

**Right to Erasure (GDPR Article 17):**

1. User submits deletion request via API or support ticket
2. System validates identity and Organization ownership
3. PII fields anonymized: `user_email` → `deleted_user_<hash>`
4. Device records soft-deleted (marked as `DELETED` status)
5. Audit log created with deletion reason
6. Confirmation sent to user within 30 days
7. Hard deletion after 90-day grace period

### 5.8 Backup Security

- **Encryption:** All backups encrypted with AES-256 before storage
- **Access Control:** Backup access restricted to designated recovery team
- **Verification:** Monthly backup restoration tests with integrity validation
- **Retention:** Daily backups for 30 days, monthly backups for 1 year
- **Secure Disposal:** Backups securely wiped using DoD 5220.22-M standard before media disposal

---

## 6. Performance & Scalability

### 6.1 Database Optimization

#### Indexes

```sql
-- Critical for evaluation API performance
CREATE INDEX idx_devices_fingerprint ON devices(organization_id, fingerprint);
CREATE INDEX idx_devices_trust_status ON devices(organization_id, trust_status);
CREATE INDEX idx_device_owners_email ON device_owners(user_email, is_primary);

-- For stale device cleanup
CREATE INDEX idx_devices_last_seen ON devices(last_seen_at) WHERE trust_status = 'TRUSTED';

-- For audit queries
CREATE INDEX idx_audit_logs_timestamp ON audit_logs(organization_id, timestamp DESC);
```

#### Partitioning

- **audit_logs:** Partitioned by year, auto-created via pg_partman.
- **device_telemetry_history:** Partitioned by month, auto-pruned after 90 days.

#### Connection Pooling

- **PgBouncer:** Transaction pooling mode, 100 connections per Organization.
- **Read Replicas:** Evaluation API reads from replicas, writes to primary.

### 6.2 Caching Strategy

#### Redis Cache Keys

- **Evaluation Results:** `eval:{organization_id}:{device_id}:{policy_id}` (TTL: 60s)
- **Device Lookup:** `device:{organization_id}:{fingerprint}` (TTL: 300s)
- **Policy Rules:** `policy:{organization_id}:{policy_id}` (TTL: 600s)

#### Cache Invalidation

- **Device Update:** Invalidate `device:*` and `eval:*` for that device.
- **Policy Update:** Invalidate all `eval:*` for Organization, send webhook.
- **Trust Status Change:** Immediate invalidation + webhook.

### 6.3 API Performance Targets

| Endpoint | p50 | p95 | p99 |
|----------|-----|-----|-----|
| POST /evaluations/check | 20ms | 50ms | 100ms |
| POST /evaluations/check/batch | 50ms | 150ms | 300ms |
| POST /devices/telemetry | 100ms | 200ms | 500ms |
| GET /devices | 50ms | 150ms | 300ms |

### 6.4 Horizontal Scaling

#### API Servers

- **Stateless:** All session data in Redis/PostgreSQL.
- **Load Balancer:** AWS ALB with health checks on `/health`.
- **Auto-Scaling:** CPU > 70% for 2 minutes triggers scale-up.

#### Celery Workers

- **Task Queues:** Separate queues for priority levels (high/normal/low).
- **Scaling:** Queue depth > 1000 triggers worker scale-up.

#### Database

- **Vertical Scaling:** Primary for writes (up to 64 vCPU).
- **Horizontal Scaling:** Read replicas for evaluation API (up to 5 replicas).
- **Sharding:** Future consideration if single Organization exceeds 10M devices.

---

## 7. Monitoring & Observability

### 7.1 Metrics (OpenTelemetry)

#### Application Metrics

- `veridevice.evaluations.total` (counter): Total evaluation requests.
- `veridevice.evaluations.decision` (counter): Labeled by `decision` (ALLOW/DENY).
- `veridevice.evaluations.latency` (histogram): Response time distribution.
- `veridevice.cache.hit_rate` (gauge): Redis cache effectiveness.
- `veridevice.devices.by_status` (gauge): Device count by trust_status.
- `veridevice.api_keys.expiring_soon` (gauge): Keys expiring in < 30 days.

#### Infrastructure Metrics

- PostgreSQL: Connection pool usage, query latency, replication lag.
- Redis: Memory usage, eviction rate, command latency.
- Celery: Queue depth, task success/failure rate, worker utilization.

### 7.2 Logging (Structured JSON)

#### Log Levels

- **ERROR:** System failures, unhandled exceptions.
- **WARN:** Degraded mode, retry attempts, suspicious activity.
- **INFO:** API requests, device registrations, policy changes.
- **DEBUG:** Detailed evaluation logic (disabled in production).

#### Required Fields

```json
{
  "timestamp": "2026-02-09T22:15:30.123Z",
  "level": "INFO",
  "service": "veridevice-api",
  "request_id": "req_abc123",
  "organization_id": "Organization_xyz",
  "message": "Device evaluation completed",
  "context": {
    "device_id": "550e8400...",
    "decision": "ALLOW",
    "latency_ms": 23
  }
}
```

### 7.3 Alerting

#### Critical Alerts (PagerDuty)

- Evaluation API p99 latency > 200ms for 5 minutes.
- PostgreSQL primary down.
- Redis cluster down.
- Error rate > 1% for 2 minutes.
- Failed authentication attempts > 5 from same IP in 5 minutes.
- Privilege escalation attempt detected.
- Backup failure.

#### Warning Alerts (Slack)

- Cache hit rate < 80%.
- API keys expiring in < 7 days.
- Stale device job failed.
- Webhook delivery failure rate > 10%.
- Unusual data access patterns (bulk exports, off-hours access).
- Vulnerability scan findings (Critical/High severity).

#### Security Alerts (SIEM Integration)

- Multiple failed login attempts across different accounts (credential stuffing).
- Admin action from unusual location/IP.
- Bulk device revocation (>10 devices in 1 hour).
- API abuse patterns (rate limit violations).
- Unauthorized access attempts to audit logs.
- Configuration changes outside maintenance windows.

### 7.4 Distributed Tracing

- **OpenTelemetry:** Trace evaluation requests across API → Cache → DB.
- **Sampling:** 100% for errors, 10% for successful requests.
- **Trace Context:** Propagated via `traceparent` header.

---

## 8. Disaster Recovery & Business Continuity

### 8.1 Backup Strategy

- **PostgreSQL:**
  - Continuous WAL archiving to S3.
  - Daily full backups, retained for 30 days.
  - Point-in-time recovery (PITR) capability.
- **Redis:**
  - RDB snapshots every 6 hours.
  - AOF (Append-Only File) for durability.
- **Configuration:**
  - Infrastructure as Code (Terraform) in Git.
  - Secrets backed up to secondary vault.

### 8.2 Recovery Objectives

- **RTO (Recovery Time Objective):** 1 hour for full service restoration.
- **RPO (Recovery Point Objective):** 5 minutes of data loss maximum.

### 8.3 Failover Procedures

- **Database:** Automatic failover to standby replica (30-60 seconds).
- **Redis:** Redis Sentinel for automatic failover.
- **API Servers:** Multi-AZ deployment, automatic health check failover.

### 8.4 Disaster Recovery Testing

- **Quarterly DR Drills:** Simulated failure scenarios with documented results.
- **Annual Full Failover Test:** Complete regional failover with customer notification.
- **Test Validation:** RTO/RPO metrics verified and documented.
- **Improvement Actions:** Post-test review with remediation tracking.
- **Runbook Updates:** DR procedures updated based on test findings.

---

## 9. Vulnerability & Change Management

### 9.1 Vulnerability Management

#### Dependency Scanning

- **Frequency:** Weekly automated scans using Snyk/OWASP Dependency-Check.
- **Scope:** All application dependencies, container images, infrastructure code.
- **Reporting:** Vulnerabilities tracked in security dashboard with CVSS scores.

#### Remediation SLAs

| Severity | Remediation Timeline | Approval Required |
| :--- | :--- | :--- |
| Critical (CVSS 9.0-10.0) | 7 days | Security team lead |
| High (CVSS 7.0-8.9) | 30 days | Engineering manager |
| Medium (CVSS 4.0-6.9) | 90 days | Product owner |
| Low (CVSS 0.1-3.9) | Next release cycle | Standard review |

#### Penetration Testing

- **Frequency:** Annual third-party penetration test.
- **Scope:** All external APIs, admin dashboard, authentication flows.
- **Reporting:** Findings documented with remediation plan within 30 days.
- **Retest:** Critical/High findings retested after remediation.

#### Security Patch Management

- **OS/Infrastructure:** Patches applied within 30 days of release (Critical: 7 days).
- **Application Dependencies:** Automated PR creation for security updates.
- **Emergency Patches:** Expedited change process for zero-day vulnerabilities.

### 9.2 Change Management

#### Change Request Process

1. **Submission:** Change request created with risk assessment and rollback plan.
2. **Review:** Technical review by engineering lead + security review for high-risk changes.
3. **Approval:** Approval matrix based on change risk level.
4. **Testing:** All changes tested in staging environment.
5. **Deployment:** Executed during approved maintenance window.
6. **Verification:** Post-deployment validation and monitoring.
7. **Documentation:** Change documented in audit log with before/after state.

#### Change Risk Levels

| Risk Level | Examples | Approval Required | Testing |
| :--- | :--- | :--- | :--- |
| **High** | Database schema changes, auth changes | CTO + Security lead | Full regression test |
| **Medium** | API changes, policy logic updates | Engineering manager | Integration tests |
| **Low** | UI updates, documentation | Tech lead | Unit tests |
| **Emergency** | Security patches, critical bugs | On-call engineer + post-approval | Smoke tests |

#### Deployment Windows

- **Standard Changes:** Tuesday/Thursday 10:00-14:00 UTC (low-traffic periods).
- **Emergency Changes:** Any time with incident commander approval.
- **Blackout Periods:** No changes during month-end (high evaluation API usage).

#### Rollback Procedures

- **Automated Rollback:** Triggered if error rate > 5% or latency > 500ms for 2 minutes.
- **Manual Rollback:** On-call engineer can trigger via deployment tool.
- **Database Rollback:** Point-in-time recovery available for last 30 days.
- **Rollback Testing:** All changes must include tested rollback procedure.

#### Separation of Duties

- **Code Author:** Cannot approve their own pull request.
- **Deployment:** Requires approval from someone other than code author.
- **Production Access:** Requires break-glass approval with audit logging.

---

## 10. Incident Response

### 10.1 Incident Classification

| Severity | Definition | Response Time | Escalation |
| :--- | :--- | :--- | :--- |
| **P0 - Critical** | Complete service outage, data breach | 15 minutes | CTO, Security lead, Legal |
| **P1 - High** | Partial outage, security vulnerability exploited | 1 hour | Engineering manager, Security team |
| **P2 - Medium** | Degraded performance, non-critical security issue | 4 hours | On-call engineer, Tech lead |
| **P3 - Low** | Minor issues, no customer impact | Next business day | Engineering team |

### 10.2 Incident Response Workflow

1. **Detection:** Automated alerting or manual report.
2. **Triage:** On-call engineer assesses severity and escalates if needed.
3. **Incident Commander:** Assigned for P0/P1 incidents.
4. **Communication:** Status page updated, customers notified per SLA.
5. **Investigation:** Root cause analysis with timeline documentation.
6. **Mitigation:** Immediate actions to restore service.
7. **Resolution:** Permanent fix deployed and verified.
8. **Post-Incident Review:** Blameless retrospective within 5 business days.

### 10.3 Security Incident Procedures

#### Data Breach Response

1. **Containment:** Isolate affected systems within 1 hour.
2. **Assessment:** Determine scope of data exposure within 24 hours.
3. **Legal Notification:** Notify legal team immediately for breach determination.
4. **Regulatory Notification:** GDPR breach notification to DPA within 72 hours if applicable.
5. **Customer Notification:** Notify affected customers within 72 hours with remediation guidance.
6. **Forensics:** Preserve evidence for investigation.
7. **Remediation:** Implement fixes to prevent recurrence.

#### Breach Notification Template

- Nature of the breach
- Data categories affected
- Approximate number of affected individuals
- Likely consequences
- Measures taken to address the breach
- Contact point for more information

### 10.4 Post-Incident Review

**Required for all P0/P1 incidents:**

- Timeline of events
- Root cause analysis (5 Whys)
- Impact assessment (customers affected, data exposed, revenue impact)
- Action items with owners and due dates
- Process improvements identified
- Documentation updates needed

**Review Distribution:** Engineering team, security team, executive leadership

---

## 11. Security Training & Awareness

### 11.1 Training Requirements

| Role | Training | Frequency | Tracking |
| :--- | :--- | :--- | :--- |
| **All Employees** | Security awareness, phishing training | Annual + quarterly phishing tests | LMS with completion certificates |
| **Developers** | Secure coding (OWASP Top 10), secrets management | Annual + onboarding | Completion logged in audit system |
| **Admins** | Privileged access management, incident response | Annual + onboarding | Completion logged in audit system |
| **Security Team** | Advanced threat detection, forensics | Ongoing professional development | Training budget tracked |

### 11.2 Secure Development Practices

- **Code Review:** All code changes require peer review with security checklist.
- **Static Analysis:** Automated SAST scanning on every commit.
- **Secrets Management:** No secrets in code; use secrets manager with rotation.
- **Dependency Management:** Automated vulnerability scanning with PR blocking for Critical/High.
- **Security Champions:** Designated security champion in each team for guidance.

### 11.3 Acceptable Use Policy

- **Access Control:** Access granted based on job role and business need.
- **Data Handling:** PII must not be stored locally or shared via unsecured channels.
- **Password Policy:** Minimum 12 characters, MFA required for all accounts.
- **Device Security:** Company devices must have disk encryption and EDR agent.
- **Incident Reporting:** Security concerns must be reported within 24 hours.

---

## 12. Vendor & Third-Party Risk Management

### 12.1 Vendor Security Assessment

**Pre-Engagement:**

- Security questionnaire (SOC2 report, ISO certification, data handling practices)
- Data Processing Agreement (DPA) for any vendor processing customer data
- Right to audit clause in contract

**Annual Review:**

- SOC2 Type II report review
- Security incident history
- Compliance status verification
- Access review and recertification

### 12.2 Subprocessor List (GDPR)

| Vendor | Service | Data Processed | Location | DPA Status |
| :--- | :--- | :--- | :--- | :--- |
| AWS | Infrastructure | All data | US/EU (Organization-specific) | Executed |
| Redis Labs | Caching | Device IDs, evaluation results | US/EU (Organization-specific) | Executed |
| Auth0/Okta | SSO | User emails, authentication logs | US | Executed |
| Datadog | Monitoring | Logs (PII masked) | US | Executed |

**Customer Notification:** 30-day notice required before adding new subprocessor.

### 12.3 Vendor Access Controls

- **Principle of Least Privilege:** Vendors granted minimum access required.
- **Time-Limited Access:** Support access expires after 24 hours.
- **Access Logging:** All vendor access logged and reviewed monthly.
- **Credential Management:** Vendor credentials rotated every 90 days.

---

## 13. Security Controls Matrix

### 13.1 SOC2 Trust Service Criteria Mapping

| Control ID | SOC2 Criteria | Implementation | Evidence |
| :--- | :--- | :--- | :--- |
| AC-01 | CC6.1 - Logical Access | MFA for all admin accounts | Authentication logs, MFA enrollment reports |
| AC-02 | CC6.2 - Access Removal | Quarterly access reviews | Access review reports, termination logs |
| AC-03 | CC6.3 - Access Provisioning | Role-based access with approval | Access request tickets, approval workflows |
| AU-01 | CC7.2 - System Monitoring | Comprehensive audit logging | Audit log samples, SIEM alerts |
| AU-02 | CC7.3 - Audit Log Protection | Immutable logs with hash chain | Log integrity verification reports |
| CM-01 | CC8.1 - Change Management | Formal change approval process | Change tickets, approval records |
| DR-01 | A1.2 - Backup & Recovery | Automated backups with testing | Backup logs, DR test reports |
| EN-01 | CC6.7 - Encryption | TLS 1.3, AES-256 at rest | Encryption configuration, key rotation logs |
| IR-01 | CC7.4 - Incident Response | Documented IR procedures | Incident reports, post-mortems |
| RA-01 | CC9.1 - Risk Assessment | Annual risk assessment | Risk register, threat model documentation |

### 13.2 ISO 27001 Controls Mapping

| Control ID | ISO 27001 | Implementation | Evidence |
| :--- | :--- | :--- | :--- |
| A.9.1.1 | Access Control Policy | RBAC with least privilege | Access control policy document |
| A.9.2.1 | User Registration | Automated provisioning with approval | User provisioning logs |
| A.9.4.1 | Access Restriction | Network segmentation, API isolation | Network diagrams, firewall rules |
| A.12.3.1 | Backup | Daily automated backups | Backup logs, restoration tests |
| A.12.4.1 | Event Logging | Comprehensive audit logs | Log samples, retention verification |
| A.12.6.1 | Vulnerability Management | Weekly scans, defined SLAs | Scan reports, remediation tracking |
| A.16.1.1 | Incident Response | Documented procedures with testing | IR plan, incident reports |
| A.17.1.1 | Business Continuity | DR plan with quarterly testing | DR test reports, RTO/RPO validation |
| A.18.1.1 | Legal Requirements | GDPR, SOC2 compliance | Compliance reports, audit results |

---

## 14. Implementation Roadmap

### Phase 1: MVP (Weeks 1-4)

**Goal:** Basic device registry with manual approval.

- **Database:**
  - Implement `Organizations`, `devices`, `device_owners`, `audit_logs` tables.
  - Set up PostgreSQL with basic indexes.
- **APIs:**
  - `POST /devices/register` (without WebAuthn, API key auth only).
  - `GET /devices` and `GET /devices/{id}`.
  - `POST /admin/devices/{id}/action` (approve/revoke).
- **Authentication:** Simple API key validation (no rotation yet).
- **Deployment:** Single-region, single-AZ deployment.
- **UI**
  - built a django frameork based UI that is compatible with the above API
  - use django Unfold for the UI framework
  - build and test the UI locally
**Success Criteria:**

- API: Can register 100 devices.
- API: Admin can approve/revoke devices.
- API: Basic audit logging functional.
- UI: an admin is able to login to the web application using login and password
- UI: an admin is mapped to only one organization
- UI: an admin is able to register a device for an organization
- UI: an admin is able to list all the devices for an organization. The list view should support pagination, and filtering capabilities. The default page size should be 50 devices. The device list should be filterable on platform, trust_status, and registration dates.

### Phase 2: Evaluation Logic (Weeks 5-8)

**Goal:** Implement gatekeeper functionality.

- **Database:**
  - Add `policies` table.
  - Implement `device_telemetry_history` (without partitioning).
- **APIs:**
  - `POST /evaluations/check` (single evaluation).
  - `POST /devices/{id}/telemetry`.
  - `POST /admin/policies` (CRUD operations).
- **Logic:**
  - Policy evaluation engine (disk encryption, firewall checks).
  - Trust score calculation.
- **Caching:** Redis integration for evaluation results.

**Success Criteria:**

- Evaluation API responds in < 100ms (p95).
- Policies correctly enforce disk encryption requirement.
- Cache hit rate > 70%.

### Phase 3: Security Hardening (Weeks 9-12)

**Goal:** Add WebAuthn and advanced security features.

- **Database:**
  - Add `device_credentials` table.
  - Implement `api_keys` table with rotation tracking.
- **APIs:**
  - WebAuthn registration flow.
  - Challenge-response authentication for telemetry.
  - `POST /admin/devices/{id}/credentials/{cred_id}/revoke`.
- **Security:**
  - Implement signature validation.
  - Add rate limiting (per-Organization).
  - Enable TLS 1.3 enforcement.
  - MFA enforcement for admin accounts.
  - Failed login protection and account lockout.
- **Compliance:**
  - Application-level encryption for PII.
  - Audit log hash chain for tamper detection.
  - Enhanced audit logging (all auth attempts, data access).
  - Data classification implementation.

**Success Criteria:**

- WebAuthn registration success rate > 95%.
- Zero signature validation bypasses.
- SOC2 audit controls in place.
- MFA enrollment rate 100% for admins.

### Phase 4: Scale & Reliability (Weeks 13-16)

**Goal:** Production-ready scalability and observability.

- **Infrastructure:**
  - Multi-AZ deployment.
  - PostgreSQL read replicas.
  - Redis cluster mode.
- **Features:**
  - `POST /evaluations/check/batch` (batch evaluation).
  - Webhook system with retry logic.
  - Stale device automation (Celery jobs).
- **Observability:**
  - OpenTelemetry integration.
  - Structured logging.
  - Alerting rules configured (including security alerts).
  - SIEM integration for security monitoring.
- **Performance:**
  - Database partitioning for audit logs and telemetry.
  - Query optimization based on load testing.
- **Compliance:**
  - Vulnerability scanning pipeline (weekly).
  - Change management process documented.
  - Incident response procedures documented.
  - DR testing schedule established.

**Success Criteria:**

- Handle 10,000 evaluations/minute.
- 99.9% uptime over 30 days.
- All SLA targets met.
- Security alerts functional with <5 min response time.

### Phase 5: Advanced Features (Weeks 17-20)

**Goal:** Enterprise-grade capabilities.

- **Features:**
  - Device ownership transfer.
  - Fingerprint collision detection.
  - Graceful degradation modes.
  - GDPR data export/deletion APIs.
  - Automated data retention enforcement.
- **Integrations:**
  - Pre-built connectors for Okta, Auth0, Azure AD.
  - Webhook templates for common IdPs.
- **Analytics:**
  - Trust score trending dashboard.
  - Device health reports.
  - Compliance reporting dashboard.
- **Compliance:**
  - Vendor security assessments completed.
  - Security training program launched.
  - Penetration test scheduled.
  - SOC2 Type II audit preparation.

**Success Criteria:**

- 3+ IdP integrations live.
- Customer self-service for 90% of operations.
- Zero data residency violations.
- All compliance documentation complete.
- First penetration test completed with remediation plan.

### Phase 6: Compliance Certification (Weeks 21-24)

**Goal:** Achieve SOC2 Type II and ISO 27001 readiness.

- **Compliance:**
  - Complete SOC2 Type II audit.
  - ISO 27001 gap analysis and remediation.
  - All security policies documented and approved.
  - Quarterly access reviews completed.
  - DR drill completed with documented results.
- **Documentation:**
  - Security controls matrix validated.
  - Compliance evidence repository established.
  - Customer-facing security documentation published.
  - Vendor DPAs executed for all subprocessors.
- **Training:**
  - 100% employee security training completion.
  - Security champions program established.
  - Incident response tabletop exercise completed.

**Success Criteria:**

- SOC2 Type II report issued without exceptions.
- ISO 27001 certification achieved or on track.
- All compliance controls operational and tested.
- Customer security questionnaire response rate <24 hours.

---

## 15. Open Questions & Future Considerations

### 15.1 Open Questions

1. **Mobile Device Management (MDM) Integration:** Should we integrate with Jamf/Intune APIs for automated telemetry collection?
2. **Biometric Authentication:** Should we support biometric re-authentication for high-risk actions?
3. **Zero Trust Network Access (ZTNA):** Should evaluation API support network-level access decisions (VPN/firewall rules)?
4. **Device Families:** How to handle device replacement scenarios (e.g., user upgrades MacBook, wants to transfer trust)?

### 15.2 Future Enhancements

- **Machine Learning:** Anomaly detection for unusual device behavior patterns.
- **Risk-Based Authentication:** Dynamic trust scores based on login context (location, time, resource sensitivity).
- **Federated Trust:** Cross-organization device trust sharing (e.g., contractor devices).
- **Offline Mode:** Allow devices to cache evaluation results for temporary network outages.
- **Hardware Security Module (HSM):** Store Organization encryption keys in FIPS 140-2 Level 3 HSM.

---

## 16. Appendix

### 16.1 Glossary

- **Attestation:** Cryptographic proof of a device's hardware/software state.
- **COSE:** CBOR Object Signing and Encryption, used in WebAuthn.
- **Fingerprint:** Unique identifier derived from device characteristics.
- **Nonce:** Number used once, prevents replay attacks.
- **Passkey:** User-friendly term for WebAuthn credentials.
- **TPM:** Trusted Platform Module, hardware security chip.

### 16.2 References

- WebAuthn Specification: <https://www.w3.org/TR/webauthn-2/>
- FIDO2 CTAP: <https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html>
- SOC2 Trust Service Criteria: <https://www.aicpa.org/soc>
- ISO 27001:2022: <https://www.iso.org/standard/27001>
- GDPR Compliance Guide: <https://gdpr.eu/>
- OWASP Top 10: <https://owasp.org/www-project-top-ten/>
- NIST Cybersecurity Framework: <https://www.nist.gov/cyberframework>
- CIS Controls: <https://www.cisecurity.org/controls>

### 16.3 Change Log

- **v2.1.0 (2026-02-10):** Added comprehensive SOC2/ISO 27001 compliance controls including:
  - MFA and session management requirements
  - Enhanced audit logging with security events
  - Data classification and DLP controls
  - Vulnerability and change management procedures
  - Incident response workflows
  - Security training requirements
  - Vendor risk management
  - Security controls matrix (SOC2/ISO 27001 mapping)
  - Data retention and deletion procedures
  - Backup security controls
  - SIEM integration and security alerting
- **v2.0.0 (2026-02-09):** Major revision with enhanced security, scalability, and compliance features.
- **v1.0.0 (2026-02-01):** Initial draft specification.

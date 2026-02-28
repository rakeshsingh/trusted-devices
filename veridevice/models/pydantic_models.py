from pydantic import BaseModel, Field, UUID4
from typing import List, Optional, Dict, Any
from enum import Enum
import datetime

class DataResidency(str, Enum):
    US = "US"
    EU = "EU"
    APAC = "APAC"

class OrganizationBase(BaseModel):
    name: str
    data_residency: DataResidency
    settings: Optional[Dict[str, Any]] = None

class OrganizationCreate(OrganizationBase):
    pass

class Organization(OrganizationBase):
    id: UUID4
    created_at: datetime.datetime

    class Config:
        from_attributes = True

class DevicePlatform(str, Enum):
    macos = "macos"
    windows = "windows"
    linux = "linux"
    ios = "ios"
    android = "android"

class TrustStatus(str, Enum):
    PENDING = "PENDING"
    TRUSTED = "TRUSTED"
    REVOKED = "REVOKED"
    STALE = "STALE"

class PublicKeyAttestation(BaseModel):
    credential_id: str
    public_key: str
    attestation_format: str
    attestation_object: str

class DeviceRegisterRequest(BaseModel):
    device_name: str
    serial_number: str
    platform: DevicePlatform
    platform_version: str
    fingerprint: str
    public_key_attestation: PublicKeyAttestation

class DeviceRegisterResponse(BaseModel):
    device_id: UUID4
    status: str
    message: str
    credential_id: str

class Device(BaseModel):
    id: UUID4
    device_name: str
    platform: DevicePlatform
    trust_status: TrustStatus
    last_seen_at: Optional[datetime.datetime] = None
    owner_email: Optional[str] = None

    class Config:
        from_attributes = True

class DeviceDetail(Device):
    platform_version: str
    owners: List[Dict[str, Any]]
    credentials: List[Dict[str, Any]]
    latest_telemetry: Optional[Dict[str, Any]] = None
    created_at: datetime.datetime

class DeviceList(BaseModel):
    devices: List[Device]
    pagination: Dict[str, Any]

class AdminAction(str, Enum):
    APPROVE = "APPROVE"
    REVOKE = "REVOKE"
    MARK_STALE = "MARK_STALE"

class AdminActionRequest(BaseModel):
    action: AdminAction
    reason: Optional[str] = None

class DeviceTransferRequest(BaseModel):
    new_owner_email: str
    revoke_previous_owner: bool = True
    reason: Optional[str] = None

class DeviceCredentialRevokeRequest(BaseModel):
    reason: Optional[str] = None

class TelemetryRequest(BaseModel):
    os_version: str
    disk_encrypted: bool
    firewall_enabled: bool
    security_agents: Dict[str, Any]

class TelemetryResponse(BaseModel):
    status: str
    next_heartbeat_in: int
    trust_status: TrustStatus

class EvaluationRequest(BaseModel):
    user_email: str
    device_fingerprint: str
    device_id: Optional[UUID4] = None
    context: Dict[str, Any]

class EvaluationResponse(BaseModel):
    decision: str
    trust_score: int
    device_id: Optional[UUID4] = None
    reasons: List[Dict[str, Any]] = []
    policy_id: Optional[UUID4] = None
    ttl: int = 3600
    cached: bool = False
    remediation_url: Optional[str] = None
    degraded_mode: Optional[bool] = None

class EvaluationBatchItem(BaseModel):
    id: str
    user_email: str
    device_id: UUID4

class EvaluationBatchRequest(BaseModel):
    evaluations: List[EvaluationBatchItem]

class EvaluationBatchResult(BaseModel):
    id: str
    decision: str
    trust_score: int
    reasons: Optional[List[Dict[str, Any]]] = None

class EvaluationBatchResponse(BaseModel):
    results: List[EvaluationBatchResult]

class AuditLog(BaseModel):
    id: UUID4
    actor_id: str
    action_type: str
    target_device_id: Optional[UUID4] = None
    result: str
    source_ip: str
    metadata: Optional[Dict[str, Any]] = None
    timestamp: datetime.datetime

    class Config:
        from_attributes = True

class AuditLogListResponse(BaseModel):
    logs: List[AuditLog]
    pagination: Dict[str, Any]

class PolicyCreateRequest(BaseModel):
    name: str
    rules: Dict[str, Any]
    priority: int = 0
    enabled: bool = True

class WebhookRegisterRequest(BaseModel):
    url: str
    events: List[str]
    secret: str

class WebhookResponse(BaseModel):
    webhook_id: str
    url: str
    status: str

class ChallengeResponse(BaseModel):
    challenge: str
    expires_at: datetime.datetime

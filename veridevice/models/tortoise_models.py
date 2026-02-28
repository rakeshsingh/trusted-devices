from tortoise.models import Model
from tortoise import fields
import enum


class DataResidency(str, enum.Enum):
    US = "US"
    EU = "EU"
    APAC = "APAC"


class DevicePlatform(str, enum.Enum):
    MACOS = "macos"
    WINDOWS = "windows"
    LINUX = "linux"
    IOS = "ios"
    ANDROID = "android"


class TrustStatus(str, enum.Enum):
    PENDING = "PENDING"
    TRUSTED = "TRUSTED"
    REVOKED = "REVOKED"
    STALE = "STALE"


class CredentialStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    REVOKED = "REVOKED"
    EXPIRED = "EXPIRED"


class ActorType(str, enum.Enum):
    USER = "USER"
    SERVICE = "SERVICE"
    SYSTEM = "SYSTEM"


class ActionResult(str, enum.Enum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class ApiKeyStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    GRACE_PERIOD = "GRACE_PERIOD"
    REVOKED = "REVOKED"


class Organization(Model):
    id = fields.UUIDField(pk=True)
    name = fields.CharField(max_length=255)
    data_residency = fields.CharEnumField(DataResidency, max_length=10)
    settings = fields.JSONField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)


class Device(Model):
    id = fields.UUIDField(pk=True)
    organization = fields.ForeignKeyField("models.Organization", related_name="devices")
    device_name = fields.CharField(max_length=255)
    serial_number_hash = fields.CharField(max_length=255)
    fingerprint = fields.CharField(max_length=255, unique=True)
    fingerprint_collision_count = fields.IntField(default=0)
    platform = fields.CharEnumField(DevicePlatform, max_length=20)
    platform_version = fields.CharField(max_length=50)
    trust_status = fields.CharEnumField(TrustStatus, max_length=20, default=TrustStatus.PENDING)
    last_seen_at = fields.DatetimeField(null=True)
    last_policy_evaluation = fields.DatetimeField(null=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)


class DeviceOwner(Model):
    id = fields.UUIDField(pk=True)
    device = fields.ForeignKeyField("models.Device", related_name="owners")
    user_email = fields.CharField(max_length=255)  # Should be encrypted
    is_primary = fields.BooleanField(default=False)
    assigned_at = fields.DatetimeField(auto_now_add=True)
    revoked_at = fields.DatetimeField(null=True)


class DeviceCredential(Model):
    id = fields.UUIDField(pk=True)
    device = fields.ForeignKeyField("models.Device", related_name="credentials")
    credential_id = fields.CharField(max_length=255, unique=True)
    public_key = fields.TextField()
    attestation_format = fields.CharField(max_length=50)
    counter = fields.IntField(default=0)
    status = fields.CharEnumField(CredentialStatus, max_length=20, default=CredentialStatus.ACTIVE)
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField(null=True)


class DeviceTelemetryHistory(Model):
    id = fields.UUIDField(pk=True)
    device = fields.ForeignKeyField("models.Device", related_name="telemetry_history")
    os_family = fields.CharEnumField(DevicePlatform, max_length=20)
    os_version = fields.CharField(max_length=50)
    disk_encrypted = fields.BooleanField()
    firewall_enabled = fields.BooleanField()
    security_agents = fields.JSONField(null=True)
    reported_at = fields.DatetimeField(auto_now_add=True)
    ttl = fields.DatetimeField(null=True)


class Policy(Model):
    id = fields.UUIDField(pk=True)
    organization = fields.ForeignKeyField("models.Organization", related_name="policies")
    name = fields.CharField(max_length=255)
    rules = fields.JSONField()
    priority = fields.IntField()
    enabled = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    updated_at = fields.DatetimeField(auto_now=True)


class AuditLog(Model):
    id = fields.UUIDField(pk=True)
    organization = fields.ForeignKeyField("models.Organization", related_name="audit_logs")
    actor_id = fields.CharField(max_length=255)
    actor_type = fields.CharEnumField(ActorType, max_length=20)
    action_type = fields.CharField(max_length=255)
    target_device = fields.ForeignKeyField("models.Device", related_name="audit_logs_target", null=True, on_delete=fields.SET_NULL)
    target_resource = fields.CharField(max_length=255)
    result = fields.CharEnumField(ActionResult, max_length=20)
    source_ip = fields.CharField(max_length=50)
    user_agent = fields.TextField(null=True)
    metadata = fields.JSONField(null=True)
    timestamp = fields.DatetimeField(auto_now_add=True)
    ttl = fields.DatetimeField(null=True)


class ApiKey(Model):
    id = fields.UUIDField(pk=True)
    organization = fields.ForeignKeyField("models.Organization", related_name="api_keys")
    key_hash = fields.CharField(max_length=255, unique=True)
    key_prefix = fields.CharField(max_length=8, unique=True)
    name = fields.CharField(max_length=255)
    scopes = fields.JSONField()
    status = fields.CharEnumField(ApiKeyStatus, max_length=20, default=ApiKeyStatus.ACTIVE)
    created_at = fields.DatetimeField(auto_now_add=True)
    expires_at = fields.DatetimeField(null=True)
    last_used_at = fields.DatetimeField(null=True)


class Webhook(Model):
    id = fields.UUIDField(pk=True)
    organization = fields.ForeignKeyField("models.Organization", related_name="webhooks")
    url = fields.CharField(max_length=1024)
    events = fields.JSONField()
    secret = fields.CharField(max_length=255)
    is_active = fields.BooleanField(default=True)
    created_at = fields.DatetimeField(auto_now_add=True)


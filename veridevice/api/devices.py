from fastapi import APIRouter, HTTPException, Query, Header, Request
from hashlib import sha256
from veridevice.models.pydantic_models import (
    DeviceRegisterRequest,
    DeviceRegisterResponse,
    DeviceList,
    DeviceDetail,
    AdminActionRequest,
    Device,
    TelemetryRequest,
    TelemetryResponse,
    DeviceTransferRequest,
    DeviceCredentialRevokeRequest,
)
from veridevice.models.tortoise_models import (
    Device as DeviceDB,
    Organization,
    DeviceOwner,
    DeviceCredential,
    DeviceTelemetryHistory,
    TrustStatus,
    AuditLog,
    ActorType,
    ActionResult,
    CredentialStatus,
)
from tortoise.exceptions import DoesNotExist
from tortoise.expressions import Q
from typing import List, Optional
import uuid
import datetime


router = APIRouter(
    prefix="/devices",
    tags=["devices"],
)

admin_router = APIRouter(
    prefix="/admin/devices",
    tags=["admin"],
)


@router.post("/register", response_model=DeviceRegisterResponse, status_code=201)
async def register_device(request: Request, device_registration: DeviceRegisterRequest, x_organization_id: Optional[uuid.UUID] = Header(None)):
    if not x_organization_id:
        organization = await Organization.first()
    else:
        try:
            organization = await Organization.get(id=x_organization_id)
        except DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found")

    if not organization:
         raise HTTPException(status_code=400, detail="Organization context required for registration")

    serial_number_hash = sha256(device_registration.serial_number.encode()).hexdigest()

    existing_device = await DeviceDB.filter(
        fingerprint=device_registration.fingerprint, organization=organization
    ).first()
    if existing_device:
        # According to spec 4.1.A response 409
        raise HTTPException(
            status_code=409,
            detail={
                "error": {
                    "code": "FINGERPRINT_COLLISION",
                    "message": "Device fingerprint already exists",
                    "existing_device_id": str(existing_device.id),
                    "collision_count": existing_device.fingerprint_collision_count + 1
                }
            },
        )

    device = await DeviceDB.create(
        organization=organization,
        device_name=device_registration.device_name,
        serial_number_hash=serial_number_hash,
        fingerprint=device_registration.fingerprint,
        platform=device_registration.platform,
        platform_version=device_registration.platform_version,
    )

    # Create credential
    await DeviceCredential.create(
        device=device,
        credential_id=device_registration.public_key_attestation.credential_id,
        public_key=device_registration.public_key_attestation.public_key,
        attestation_format=device_registration.public_key_attestation.attestation_format,
        status=CredentialStatus.ACTIVE
    )

    # Audit Log
    await AuditLog.create(
        organization=organization,
        actor_id="user@example.com", # In real app, from auth token
        actor_type=ActorType.USER,
        action_type="DEVICE_REGISTERED",
        target_device=device,
        target_resource=str(device.id),
        result=ActionResult.SUCCESS,
        source_ip=request.client.host if request.client else "unknown",
    )

    return DeviceRegisterResponse(
        device_id=device.id,
        status=device.trust_status,
        message="Device registered. Waiting for admin approval.",
        credential_id=device_registration.public_key_attestation.credential_id
    )

    return DeviceRegisterResponse(
        device_id=device.id,
        status=device.trust_status,
        message="Device registered. Waiting for admin approval.",
        credential_id=device_registration.public_key_attestation.credential_id
    )


@router.get("", response_model=DeviceList)
async def list_devices(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    status: TrustStatus = Query(None),
    owner_email: str = Query(None),
    sort: str = Query("created_at"),
    order: str = Query("desc"),
    x_organization_id: Optional[uuid.UUID] = Header(None)
):
    if not x_organization_id:
        organization = await Organization.first()
    else:
        try:
            organization = await Organization.get(id=x_organization_id)
        except DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found")

    if not organization:
        raise HTTPException(status_code=404, detail="Organization not found")

    query = DeviceDB.filter(organization=organization)
    if status:
        query = query.filter(trust_status=status)
    if owner_email:
        query = query.filter(owners__user_email=owner_email)

    if order == "desc":
        sort = f"-{sort}"
    query = query.order_by(sort)

    total = await query.count()
    devices = await query.offset((page - 1) * limit).limit(limit).prefetch_related("owners")

    device_list = []
    for d in devices:
        primary_owner = None
        for o in d.owners:
            if o.is_primary:
                primary_owner = o
                break
        device_list.append(
            Device(
                id=d.id,
                device_name=d.device_name,
                platform=d.platform,
                trust_status=d.trust_status,
                last_seen_at=d.last_seen_at,
                owner_email= primary_owner.user_email if primary_owner else None,
            )
        )

    return {
        "devices": device_list,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": (total + limit - 1) // limit,
        },
    }


@router.get("/{device_id}", response_model=DeviceDetail)
async def get_device_details(device_id: uuid.UUID, x_organization_id: Optional[uuid.UUID] = Header(None)):
    try:
        device = await DeviceDB.get(id=device_id).prefetch_related("owners", "credentials", "organization")
        if x_organization_id and device.organization.id != x_organization_id:
            raise HTTPException(status_code=403, detail="Access denied to this organization's device")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Device not found")

    latest_telemetry_obj = await DeviceTelemetryHistory.filter(device=device).order_by("-reported_at").first()
    latest_telemetry = None
    if latest_telemetry_obj:
        latest_telemetry = {
            "os_version": latest_telemetry_obj.os_version,
            "disk_encrypted": latest_telemetry_obj.disk_encrypted,
            "firewall_enabled": latest_telemetry_obj.firewall_enabled,
            "reported_at": latest_telemetry_obj.reported_at
        }

    return DeviceDetail(
        id=device.id,
        device_name=device.device_name,
        platform=device.platform,
        platform_version=device.platform_version,
        trust_status=device.trust_status,
        created_at=device.created_at,
        owners=[{"email": o.user_email, "is_primary": o.is_primary, "assigned_at": o.assigned_at} for o in device.owners],
        credentials=[{"id": c.credential_id, "attestation_format": c.attestation_format, "status": c.status, "created_at": c.created_at, "expires_at": c.expires_at} for c in device.credentials],
        latest_telemetry=latest_telemetry,
        last_seen_at=device.last_seen_at
    )

@router.post("/{device_id}/telemetry", response_model=TelemetryResponse)
async def send_telemetry(device_id: uuid.UUID, telemetry: TelemetryRequest, x_device_signature: str = Header(None)):
    try:
        device = await DeviceDB.get(id=device_id).prefetch_related("organization")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Device not found")

    # In a real app, verify x_device_signature here

    await DeviceTelemetryHistory.create(
        device=device,
        os_family=device.platform,
        os_version=telemetry.os_version,
        disk_encrypted=telemetry.disk_encrypted,
        firewall_enabled=telemetry.firewall_enabled,
        security_agents=telemetry.security_agents
    )

    device.last_seen_at = datetime.datetime.now(datetime.timezone.utc)
    await device.save()

    return TelemetryResponse(
        status="accepted",
        next_heartbeat_in=300,
        trust_status=device.trust_status
    )


@admin_router.post("/{device_id}/action")
async def device_action(request: Request, device_id: uuid.UUID, admin_action: AdminActionRequest):
    try:
        device = await DeviceDB.get(id=device_id).prefetch_related("organization")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Device not found")

    previous_status = device.trust_status

    if admin_action.action == "APPROVE":
        device.trust_status = TrustStatus.TRUSTED
    elif admin_action.action == "REVOKE":
        device.trust_status = TrustStatus.REVOKED
    elif admin_action.action == "MARK_STALE":
        device.trust_status = TrustStatus.STALE

    await device.save()

    # Audit Log
    await AuditLog.create(
        organization=device.organization,
        actor_id="admin@example.com", # In real app, from auth token
        actor_type=ActorType.USER,
        action_type=f"DEVICE_{admin_action.action}",
        target_device=device,
        target_resource=str(device.id),
        result=ActionResult.SUCCESS,
        source_ip=request.client.host if request.client else "unknown",
        metadata={"reason": admin_action.reason, "previous_status": previous_status}
    )

    return {
        "device_id": device.id,
        "previous_status": previous_status,
        "new_status": device.trust_status,
        "audit_log_id": str(uuid.uuid4()) # Placeholder
    }

@admin_router.post("/{device_id}/transfer")
async def transfer_ownership(request: Request, device_id: uuid.UUID, transfer: DeviceTransferRequest):
    try:
        device = await DeviceDB.get(id=device_id).prefetch_related("organization", "owners")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Device not found")

    previous_owner_email = None
    for owner in device.owners:
        if owner.is_primary:
            previous_owner_email = owner.user_email
            if transfer.revoke_previous_owner:
                owner.revoked_at = datetime.datetime.now(datetime.timezone.utc)
                owner.is_primary = False
                await owner.save()
            break

    await DeviceOwner.create(
        device=device,
        user_email=transfer.new_owner_email,
        is_primary=True
    )

    # Audit Log
    await AuditLog.create(
        organization=device.organization,
        actor_id="admin@example.com",
        actor_type=ActorType.USER,
        action_type="DEVICE_OWNERSHIP_TRANSFERRED",
        target_device=device,
        target_resource=str(device.id),
        result=ActionResult.SUCCESS,
        source_ip=request.client.host if request.client else "unknown",
        metadata={"reason": transfer.reason, "previous_owner": previous_owner_email, "new_owner": transfer.new_owner_email}
    )

    return {
        "device_id": device.id,
        "previous_owner": previous_owner_email,
        "new_owner": transfer.new_owner_email,
        "audit_log_id": str(uuid.uuid4())
    }

@admin_router.post("/{device_id}/credentials/{credential_id}/revoke")
async def revoke_credential(request: Request, device_id: uuid.UUID, credential_id: str, revoke: DeviceCredentialRevokeRequest):
    try:
        credential = await DeviceCredential.get(device_id=device_id, credential_id=credential_id).prefetch_related("device__organization")
    except DoesNotExist:
        raise HTTPException(status_code=404, detail="Credential not found")

    credential.status = CredentialStatus.REVOKED
    await credential.save()

    # Audit Log
    await AuditLog.create(
        organization=credential.device.organization,
        actor_id="admin@example.com",
        actor_type=ActorType.USER,
        action_type="CREDENTIAL_REVOKED",
        target_device=credential.device,
        target_resource=credential_id,
        result=ActionResult.SUCCESS,
        source_ip=request.client.host if request.client else "unknown",
        metadata={"reason": revoke.reason}
    )

    return {
        "credential_id": credential_id,
        "status": "REVOKED",
        "device_can_re_register": True
    }

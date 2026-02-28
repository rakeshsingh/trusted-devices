from fastapi import APIRouter, HTTPException, Query, Header
from veridevice.models.pydantic_models import (
    AuditLogListResponse,
    AuditLog as AuditLogPydantic,
    PolicyCreateRequest,
)
from veridevice.models.tortoise_models import (
    AuditLog,
    Policy,
    Organization,
)
from tortoise.exceptions import DoesNotExist
from typing import Optional, List
import uuid

router = APIRouter(
    prefix="/admin",
    tags=["admin"],
)

@router.get("/audit-logs", response_model=AuditLogListResponse)
async def list_audit_logs(
    page: int = Query(1, ge=1),
    limit: int = Query(50, ge=1, le=200),
    device_id: Optional[uuid.UUID] = Query(None),
    actor_id: Optional[str] = Query(None),
    action_type: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
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

    query = AuditLog.filter(organization=organization)
    if device_id:
        query = query.filter(target_device_id=device_id)
    if actor_id:
        query = query.filter(actor_id=actor_id)
    if action_type:
        query = query.filter(action_type=action_type)

    total = await query.count()
    logs_db = await query.order_by("-timestamp").offset((page - 1) * limit).limit(limit)

    logs = []
    for log in logs_db:
        logs.append(AuditLogPydantic(
            id=log.id,
            actor_id=log.actor_id,
            action_type=log.action_type,
            target_device_id=log.target_device_id,
            result=log.result,
            source_ip=log.source_ip,
            metadata=log.metadata,
            timestamp=log.timestamp
        ))

    return {
        "logs": logs,
        "pagination": {
            "page": page,
            "limit": limit,
            "total": total,
            "total_pages": (total + limit - 1) // limit,
        },
    }

@router.post("/policies")
async def create_policy(policy_req: PolicyCreateRequest, x_organization_id: Optional[uuid.UUID] = Header(None)):
    if not x_organization_id:
        organization = await Organization.first()
    else:
        try:
            organization = await Organization.get(id=x_organization_id)
        except DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found")

    if not organization:
         raise HTTPException(status_code=404, detail="Organization not found")

    policy = await Policy.create(
        organization=organization,
        name=policy_req.name,
        rules=policy_req.rules,
        priority=policy_req.priority,
        enabled=policy_req.enabled
    )

    return {
        "policy_id": str(policy.id),
        "name": policy.name,
        "created_at": policy.created_at
    }

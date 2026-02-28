from fastapi import APIRouter, HTTPException, Header
from veridevice.models.pydantic_models import (
    EvaluationRequest,
    EvaluationResponse,
    EvaluationBatchRequest,
    EvaluationBatchResponse,
    EvaluationBatchResult,
)
from veridevice.models.tortoise_models import (
    Device,
    Organization,
    Policy,
    AuditLog,
    ActorType,
    ActionResult,
)
from tortoise.exceptions import DoesNotExist
from typing import Optional
import uuid

router = APIRouter(
    prefix="/evaluations",
    tags=["evaluations"],
)

@router.post("/check", response_model=EvaluationResponse)
async def evaluate_access(evaluation: EvaluationRequest, x_organization_id: Optional[uuid.UUID] = Header(None)):
    if not x_organization_id:
        organization = await Organization.first()
    else:
        try:
            organization = await Organization.get(id=x_organization_id)
        except DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found")

    if not organization:
         raise HTTPException(status_code=404, detail="Organization not found")

    # Simple logic for MVP: check if device exists and is TRUSTED
    device = None
    if evaluation.device_id:
        device = await Device.filter(id=evaluation.device_id, organization=organization).first()
    elif evaluation.device_fingerprint:
        device = await Device.filter(fingerprint=evaluation.device_fingerprint, organization=organization).first()

    decision = "DENY"
    trust_score = 0
    reasons = []
    policy_id = None

    if not device:
        reasons.append({"code": "DEVICE_NOT_FOUND", "severity": "critical"})
    elif device.trust_status != "TRUSTED":
        reasons.append({"code": "DEVICE_NOT_TRUSTED", "severity": "high", "status": device.trust_status})
    else:
        decision = "ALLOW"
        trust_score = 100 # Default for trusted device in MVP
        # In real app, apply policies here

    # Audit Log
    await AuditLog.create(
        organization=organization,
        actor_id=evaluation.user_email,
        actor_type=ActorType.SERVICE,
        action_type="ACCESS_EVALUATED",
        target_device=device,
        target_resource=evaluation.user_email,
        result=ActionResult.SUCCESS if decision == "ALLOW" else ActionResult.DENIED,
        source_ip=evaluation.context.get("ip_address", "0.0.0.0"),
        metadata={"decision": decision, "trust_score": trust_score, "reasons": reasons}
    )

    return EvaluationResponse(
        decision=decision,
        trust_score=trust_score,
        device_id=device.id if device else None,
        reasons=reasons,
        policy_id=policy_id,
        ttl=3600,
        cached=False
    )

@router.post("/check/batch", response_model=EvaluationBatchResponse)
async def evaluate_access_batch(batch: EvaluationBatchRequest, x_organization_id: Optional[uuid.UUID] = Header(None)):
    if not x_organization_id:
        organization = await Organization.first()
    else:
        try:
            organization = await Organization.get(id=x_organization_id)
        except DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found")

    if not organization:
         raise HTTPException(status_code=404, detail="Organization not found")

    results = []
    for item in batch.evaluations:
        # Reusing single evaluation logic (simplified for batch)
        device = await Device.filter(id=item.device_id, organization=organization).first()
        decision = "DENY"
        trust_score = 0
        if device and device.trust_status == "TRUSTED":
            decision = "ALLOW"
            trust_score = 100
        
        results.append(EvaluationBatchResult(
            id=item.id,
            decision=decision,
            trust_score=trust_score
        ))
    
    return EvaluationBatchResponse(results=results)

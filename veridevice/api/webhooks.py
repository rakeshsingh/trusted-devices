from fastapi import APIRouter, HTTPException, Header
from veridevice.models.pydantic_models import (
    WebhookRegisterRequest,
    WebhookResponse,
)
from veridevice.models.tortoise_models import (
    Organization,
    Webhook,
)
from tortoise.exceptions import DoesNotExist
from typing import Optional
import uuid

router = APIRouter(
    prefix="/webhooks",
    tags=["webhooks"],
)

@router.post("", response_model=WebhookResponse, status_code=201)
async def register_webhook(webhook_req: WebhookRegisterRequest, x_organization_id: Optional[uuid.UUID] = Header(None)):
    if not x_organization_id:
        organization = await Organization.first()
    else:
        try:
            organization = await Organization.get(id=x_organization_id)
        except DoesNotExist:
            raise HTTPException(status_code=404, detail="Organization not found")

    if not organization:
         raise HTTPException(status_code=404, detail="Organization not found")

    webhook = await Webhook.create(
        organization=organization,
        url=webhook_req.url,
        events=webhook_req.events,
        secret=webhook_req.secret
    )
    
    return WebhookResponse(
        webhook_id=str(webhook.id),
        url=webhook.url,
        status="active" if webhook.is_active else "inactive"
    )

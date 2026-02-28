import pytest
from httpx import AsyncClient, ASGITransport
from veridevice.main import app
from veridevice.core.config import settings
from tortoise import Tortoise
from veridevice.models.tortoise_models import Organization, Device as DeviceDB, TrustStatus, DeviceCredential, CredentialStatus, AuditLog
import uuid


@pytest.fixture(scope="module")
async def client():
    # Force sqlite memory for tests
    settings.database_url = "sqlite://:memory:"
    await Tortoise.init(db_url=settings.database_url, modules={"models": settings.models})
    await Tortoise.generate_schemas()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as c:
        yield c
    await Tortoise.close_connections()

@pytest.fixture(autouse=True)
async def setup_organization():
    await AuditLog.all().delete()
    await DeviceDB.all().delete()
    await Organization.all().delete()
    await Organization.create(name="Test Organization", data_residency="US")

@pytest.mark.asyncio
async def test_register_device(client: AsyncClient):
    response = await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Test MacBook Pro",
            "serial_number": "C02TEST",
            "platform": "macos",
            "platform_version": "14.2.1",
            "fingerprint": "a1b2c3d4e5f6",
            "public_key_attestation": {
                "credential_id": "cred_123",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert data["status"] == "PENDING"
    assert "device_id" in data
    assert data["credential_id"] == "cred_123"

@pytest.mark.asyncio
async def test_list_devices(client: AsyncClient):
    await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Test MacBook Pro",
            "serial_number": "C02TEST_LIST",
            "platform": "macos",
            "platform_version": "14.2.1",
            "fingerprint": "a1b2c3d4e5f6_list",
            "public_key_attestation": {
                "credential_id": "cred_list",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )
    response = await client.get("/api/v1/devices")
    assert response.status_code == 200
    data = response.json()
    assert "devices" in data
    assert "pagination" in data
    assert len(data["devices"]) == 1
    assert data["devices"][0]["device_name"] == "Test MacBook Pro"


@pytest.mark.asyncio
async def test_device_details(client: AsyncClient):
    reg_response = await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Test MacBook Pro 2",
            "serial_number": "C02TEST2",
            "platform": "macos",
            "platform_version": "14.2.1",
            "fingerprint": "a1b2c3d4e5f7",
            "public_key_attestation": {
                "credential_id": "cred_2",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )
    device_id = reg_response.json()["device_id"]

    response = await client.get(f"/api/v1/devices/{device_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == device_id
    assert data["device_name"] == "Test MacBook Pro 2"
    assert len(data["credentials"]) == 1
    assert data["credentials"][0]["id"] == "cred_2"


@pytest.mark.asyncio
async def test_admin_actions(client: AsyncClient):
    reg_response = await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Test MacBook Pro 3",
            "serial_number": "C02TEST3",
            "platform": "windows",
            "platform_version": "11",
            "fingerprint": "a1b2c3d4e5f8",
            "public_key_attestation": {
                "credential_id": "cred_3",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )
    device_id = reg_response.json()["device_id"]

    # Approve
    response = await client.post(
        f"/api/v1/admin/devices/{device_id}/action",
        json={"action": "APPROVE", "reason": "Test approval"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["new_status"] == "TRUSTED"

    device = await DeviceDB.get(id=device_id)
    assert device.trust_status == TrustStatus.TRUSTED

    # Revoke
    response = await client.post(
        f"/api/v1/admin/devices/{device_id}/action",
        json={"action": "REVOKE", "reason": "Test revocation"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["new_status"] == "REVOKED"
    
    device = await DeviceDB.get(id=device_id)
    assert device.trust_status == TrustStatus.REVOKED

@pytest.mark.asyncio
async def test_fingerprint_collision(client: AsyncClient):
    await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Test MacBook Pro 4",
            "serial_number": "C02TEST4",
            "platform": "linux",
            "platform_version": "6.1",
            "fingerprint": "a1b2c3d4e5f9",
            "public_key_attestation": {
                "credential_id": "cred_4",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )

    response = await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Test MacBook Pro 5",
            "serial_number": "C02TEST5",
            "platform": "linux",
            "platform_version": "6.1",
            "fingerprint": "a1b2c3d4e5f9",
            "public_key_attestation": {
                "credential_id": "cred_5",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )
    assert response.status_code == 409
    assert "FINGERPRINT_COLLISION" in response.text

@pytest.mark.asyncio
async def test_telemetry(client: AsyncClient):
    reg_response = await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Telemetry Device",
            "serial_number": "C02TELEMETRY",
            "platform": "macos",
            "platform_version": "14.2.1",
            "fingerprint": "fingerprint_telemetry",
            "public_key_attestation": {
                "credential_id": "cred_telemetry",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )
    device_id = reg_response.json()["device_id"]

    response = await client.post(
        f"/api/v1/devices/{device_id}/telemetry",
        json={
            "os_version": "14.4.1",
            "disk_encrypted": True,
            "firewall_enabled": True,
            "security_agents": {"crowdstrike": {"status": "running", "version": "7.2.1"}}
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "accepted"

@pytest.mark.asyncio
async def test_evaluation(client: AsyncClient):
    reg_response = await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Evaluation Device",
            "serial_number": "C02EVAL",
            "platform": "macos",
            "platform_version": "14.2.1",
            "fingerprint": "fingerprint_eval",
            "public_key_attestation": {
                "credential_id": "cred_eval",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )
    device_id = reg_response.json()["device_id"]

    # Not trusted yet
    response = await client.post(
        "/api/v1/evaluations/check",
        json={
            "user_email": "john.doe@example.com",
            "device_fingerprint": "fingerprint_eval",
            "context": {"ip_address": "1.1.1.1"}
        }
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "DENY"

    # Approve
    await client.post(
        f"/api/v1/admin/devices/{device_id}/action",
        json={"action": "APPROVE", "reason": "Test approval"},
    )

    # Now trusted
    response = await client.post(
        "/api/v1/evaluations/check",
        json={
            "user_email": "john.doe@example.com",
            "device_fingerprint": "fingerprint_eval",
            "context": {"ip_address": "1.1.1.1"}
        }
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert response.json()["trust_score"] == 100

@pytest.mark.asyncio
async def test_audit_logs(client: AsyncClient):
    # Trigger an action that creates a log
    await client.post(
        "/api/v1/devices/register",
        json={
            "device_name": "Audit Device",
            "serial_number": "C02AUDIT",
            "platform": "macos",
            "platform_version": "14.2.1",
            "fingerprint": "fingerprint_audit",
            "public_key_attestation": {
                "credential_id": "cred_audit",
                "public_key": "base64_pubkey",
                "attestation_format": "packed",
                "attestation_object": "base64_obj"
            }
        },
    )

    response = await client.get("/api/v1/admin/audit-logs")
    assert response.status_code == 200
    data = response.json()
    assert "logs" in data
    assert len(data["logs"]) > 0

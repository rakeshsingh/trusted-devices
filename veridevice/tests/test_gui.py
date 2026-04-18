import pytest
import respx
from unittest.mock import patch
from httpx import Response
from veridevice.gui import DeviceDashboard, API_BASE_URL

ORG_ID = "1d81e5d4-8da5-4656-b649-06d57150644c"

@pytest.fixture
def dashboard():
    d = DeviceDashboard()
    d.selected_org_id = ORG_ID
    return d

@pytest.mark.asyncio
async def test_refresh_organizations(dashboard):
    with respx.mock:
        respx.get(f"{API_BASE_URL}/organizations").mock(return_value=Response(200, json=[{"id": ORG_ID, "name": "Acme Corp"}]))
        
        await dashboard.refresh_organizations()
        assert len(dashboard.organizations) == 1
        assert dashboard.organizations[0]["name"] == "Acme Corp"

@pytest.mark.asyncio
async def test_api_call_success(dashboard):
    with respx.mock:
        respx.get(f"{API_BASE_URL}/organizations/{ORG_ID}/devices").mock(return_value=Response(200, json={"devices": [{"id": "1", "device_name": "Test Device"}]}))
        
        await dashboard.refresh_devices()
        assert len(dashboard.devices) == 1
        assert dashboard.devices[0]["device_name"] == "Test Device"

@pytest.mark.asyncio
async def test_api_call_failure(dashboard):
    with respx.mock, patch('nicegui.ui.notify') as mock_notify:
        respx.get(f"{API_BASE_URL}/organizations/{ORG_ID}/devices").mock(return_value=Response(500))
        
        await dashboard.refresh_devices()
        assert dashboard.devices == []
        mock_notify.assert_called()

@pytest.mark.asyncio
async def test_perform_action(dashboard):
    device_id = "test-uuid"
    action = "APPROVE"
    
    with respx.mock, patch('nicegui.ui.notify') as mock_notify:
        # Mocking refresh calls too as they are called inside perform_action
        respx.post(f"{API_BASE_URL}/organizations/{ORG_ID}/admin/devices/{device_id}/action").mock(return_value=Response(200, json={"status": "success"}))
        respx.get(f"{API_BASE_URL}/organizations/{ORG_ID}/devices").mock(return_value=Response(200, json={"devices": []}))
        respx.get(f"{API_BASE_URL}/organizations/{ORG_ID}/admin/audit-logs").mock(return_value=Response(200, json={"logs": []}))
        
        await dashboard.perform_action(device_id, action)
        mock_notify.assert_called_with(f"Device {action} successful", type='positive')

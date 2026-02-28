from django.shortcuts import render, redirect
import requests
from django.conf import settings

# In a real app, this might be in settings or env
API_BASE_URL = "http://127.0.0.1:8000/api/v1"

def device_list(request):
    try:
        response = requests.get(f"{API_BASE_URL}/devices")
        response.raise_for_status()
        data = response.json()
        devices = data.get("devices", [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching devices: {e}")
        devices = []

    return render(request, "dashboard/device_list.html", {"devices": devices})

def device_action(request, device_id, action):
    try:
        response = requests.post(
            f"{API_BASE_URL}/admin/devices/{device_id}/action",
            json={"action": action.upper(), "reason": "Action from web dashboard"},
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        print(f"Error performing action {action} on device {device_id}: {e}")

    return redirect("device_list")

def audit_log_list(request):
    try:
        response = requests.get(f"{API_BASE_URL}/admin/audit-logs")
        response.raise_for_status()
        data = response.json()
        logs = data.get("logs", [])
    except requests.exceptions.RequestException as e:
        print(f"Error fetching audit logs: {e}")
        logs = []

    return render(request, "dashboard/audit_logs.html", {"logs": logs})

def register_device_view(request):
    if request.method == "POST":
        device_data = {
            "device_name": request.POST.get("device_name"),
            "serial_number": request.POST.get("serial_number"),
            "platform": request.POST.get("platform"),
            "platform_version": request.POST.get("platform_version"),
            "fingerprint": request.POST.get("fingerprint"),
            "public_key_attestation": {
                "credential_id": f"web_{request.POST.get('serial_number')}",
                "public_key": "web_placeholder",
                "attestation_format": "none",
                "attestation_object": "web_placeholder"
            }
        }
        try:
            response = requests.post(f"{API_BASE_URL}/devices/register", json=device_data)
            response.raise_for_status()
            return redirect("device_list")
        except requests.exceptions.RequestException as e:
            print(f"Error registering device: {e}")
            # In a real app, show error in template
    
    return render(request, "dashboard/register_device.html")

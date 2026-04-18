from nicegui import app, ui
import httpx
import asyncio
from datetime import datetime
import uuid

API_BASE_URL = "http://192.168.4.50:8000/api/v1"

# Helper for API calls
async def api_call(method: str, endpoint: str, data: dict = None, params: dict = None):
    async with httpx.AsyncClient() as client:
        url = f"{API_BASE_URL}{endpoint}"
        try:
            if method == "GET":
                response = await client.get(url, params=params)
            elif method == "POST":
                response = await client.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            ui.notify(f"API Error: {str(e)}", type='negative')
            return None

class DeviceDashboard:
    def __init__(self):
        self.devices = []
        self.audit_logs = []
        self.organizations = []
        self.selected_org_id = None
        self.device_table = None
        self.audit_table = None
        self.org_select = None

    async def refresh_organizations(self):
        data = await api_call("GET", "/organizations")
        if data:
            self.organizations = data
            options = {org['id']: org['name'] for org in self.organizations}
            if self.org_select:
                self.org_select.options = options
                if not self.selected_org_id and self.organizations:
                    self.selected_org_id = self.organizations[0]['id']
                    self.org_select.value = self.selected_org_id
                self.org_select.update()

    async def refresh_devices(self):
        if not self.selected_org_id:
            return
        data = await api_call("GET", f"/organizations/{self.selected_org_id}/devices")
        if data:
            self.devices = data.get("devices", [])
            if self.device_table:
                self.device_table.rows = self.devices
                self.device_table.update()

    async def refresh_audit_logs(self):
        if not self.selected_org_id:
            return
        data = await api_call("GET", f"/organizations/{self.selected_org_id}/admin/audit-logs")
        if data:
            self.audit_logs = data.get("logs", [])
            if self.audit_table:
                self.audit_table.rows = self.audit_logs
                self.audit_table.update()

    async def perform_action(self, device_id, action, reason="GUI Action"):
        if not self.selected_org_id:
            return
        result = await api_call("POST", f"/organizations/{self.selected_org_id}/admin/devices/{device_id}/action", data={"action": action, "reason": reason})
        if result:
            ui.notify(f"Device {action} successful", type='positive')
            await self.refresh_devices()
            await self.refresh_audit_logs()

    def show_device_details(self, device_id):
        async def load_details():
            if not self.selected_org_id:
                return
            details = await api_call("GET", f"/organizations/{self.selected_org_id}/devices/{device_id}")
            if details:
                with ui.dialog() as dialog, ui.card().classes('w-full max-w-lg'):
                    ui.label(f"Device Details: {details['device_name']}").classes('text-h6')
                    with ui.grid(columns=2).classes('w-full'):
                        ui.label('ID:')
                        ui.label(details['id'])
                        ui.label('Platform:')
                        ui.label(f"{details['platform']} {details['platform_version']}")
                        ui.label('Status:')
                        ui.label(details['trust_status']).classes('font-bold')
                        ui.label('Created At:')
                        ui.label(details['created_at'])
                        ui.label('Last Seen:')
                        ui.label(details['last_seen_at'] or 'Never')

                    if details['latest_telemetry']:
                        ui.separator()
                        ui.label('Latest Telemetry').classes('text-subtitle1 mt-2')
                        with ui.grid(columns=2).classes('w-full'):
                            ui.label('OS Version:')
                            ui.label(details['latest_telemetry']['os_version'])
                            ui.label('Disk Encrypted:')
                            ui.label('Yes' if details['latest_telemetry']['disk_encrypted'] else 'No')
                            ui.label('Firewall Enabled:')
                            ui.label('Yes' if details['latest_telemetry']['firewall_enabled'] else 'No')

                    with ui.row().classes('w-full justify-end mt-4'):
                        if details['trust_status'] != 'TRUSTED':
                            ui.button('APPROVE', on_click=lambda: self.run_action(device_id, 'APPROVE', dialog)).props('color=positive')
                        if details['trust_status'] != 'REVOKED':
                            ui.button('REVOKE', on_click=lambda: self.run_action(device_id, 'REVOKE', dialog)).props('color=negative')
                        ui.button('Close', on_click=dialog.close).props('flat')
                dialog.open()

        ui.timer(0, load_details, once=True)

    async def run_action(self, device_id, action, dialog):
        await self.perform_action(device_id, action)
        dialog.close()

    async def on_org_change(self, e):
        self.selected_org_id = e.value
        await self.refresh_devices()
        await self.refresh_audit_logs()

    def build(self):
        ui.dark_mode().enable()
        
        with ui.header().classes('items-center justify-between'):
            with ui.row().classes('items-center'):
                ui.label('Veridevice Management Console').classes('text-h5')
                self.org_select = ui.select(
                    options={},
                    label='Organization',
                    on_change=self.on_org_change
                ).classes('w-64 ml-4').props('dark standout color=white')
            
            ui.button('Refresh', on_click=self.refresh_devices).props('flat icon=refresh color=white')

        with ui.tabs().classes('w-full') as tabs:
            devices_tab = ui.tab('Devices')
            audit_tab = ui.tab('Audit Logs')

        with ui.tab_panels(tabs, value=devices_tab).classes('w-full'):
            with ui.tab_panel(devices_tab):
                columns = [
                    {'name': 'device_name', 'label': 'Device Name', 'field': 'device_name', 'required': True, 'align': 'left', 'sortable': True},
                    {'name': 'platform', 'label': 'Platform', 'field': 'platform', 'sortable': True},
                    {'name': 'trust_status', 'label': 'Status', 'field': 'trust_status', 'sortable': True},
                    {'name': 'owner_email', 'label': 'Owner', 'field': 'owner_email'},
                    {'name': 'last_seen_at', 'label': 'Last Seen', 'field': 'last_seen_at', 'sortable': True},
                    {'name': 'actions', 'label': 'Actions', 'field': 'id'}
                ]
                
                self.device_table = ui.table(columns=columns, rows=self.devices, row_key='id').classes('w-full')
                self.device_table.add_slot('body-cell-actions', '''
                    <q-td :props="props">
                        <q-btn flat round icon="visibility" @click="$parent.$emit('view_details', props.row.id)" />
                    </q-td>
                ''')
                self.device_table.on('view_details', lambda msg: self.show_device_details(msg.args))

            with ui.tab_panel(audit_tab):
                log_columns = [
                    {'name': 'timestamp', 'label': 'Timestamp', 'field': 'timestamp'},
                    {'name': 'actor_id', 'label': 'Actor', 'field': 'actor_id'},
                    {'name': 'action_type', 'label': 'Action', 'field': 'action_type'},
                    {'name': 'result', 'label': 'Result', 'field': 'result'},
                ]
                self.audit_table = ui.table(columns=log_columns, rows=self.audit_logs).classes('w-full')
                ui.button('Refresh Logs', on_click=self.refresh_audit_logs)

@ui.page('/')
async def index():
    dashboard = DeviceDashboard()
    dashboard.build()
    await dashboard.refresh_organizations()
    await dashboard.refresh_devices()
    await dashboard.refresh_audit_logs()

if __name__ in {"__main__", "__mp_main__", "builtins"}:
    ui.run(title="Veridevice Management Console", host="0.0.0.0", port=8080)

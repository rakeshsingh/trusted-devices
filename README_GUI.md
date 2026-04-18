# Veridevice GUI

This is a NiceGUI-based management console for the Veridevice API.

## Prerequisites

- Python 3.14+
- `nicegui`
- `httpx`

## Running the GUI

1.  Ensure the API is running at `http://192.168.4.50:8000`.
2.  Install dependencies:
    ```bash
    pip install nicegui httpx
    ```
3.  Run the GUI:
    ```bash
    python -m veridevice.gui
    ```
4.  Open your browser at `http://localhost:8080`.

## Features

- **Device List**: View all registered devices, their status, and last seen time.
- **Device Details**: Click the eye icon to see detailed information including telemetry data.
- **Actions**: Approve or Revoke devices directly from the details view.
- **Audit Logs**: View a history of actions performed in the system.
- **Dark Mode**: Modern and clean interface by default.

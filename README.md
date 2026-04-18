# Veridevice Management Console

This is the frontend management console for the Veridevice API.

## Project Structure

This project is a standalone frontend designed to interact with a Veridevice FastAPI backend running at `192.168.4.50:8000`.

- `veridevice/gui.py`: Main application (NiceGUI-based).
- `README_GUI.md`: Detailed instructions for running the console.
- `pyproject.toml`: Project configuration and dependencies.

## Quick Start

1. Ensure the API is reachable at `http://192.168.4.50:8000`.
2. Install dependencies:
   ```bash
   uv sync
   ```
3. Run the GUI:
   ```bash
   python -m veridevice.gui
   ```
4. Access at `http://localhost:8080`.

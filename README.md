# Fleet MSCP Importer

A tool for importing macOS security compliance manifests into Fleet, generating osquery rules and fix files.

## Features

- Process security compliance manifests
- Generate osquery rules for compliance checking
- Generate fix files (shell scripts or mobileconfig) for remediation
- Upload policies to Fleet
- Upload configuration profiles to Fleet

## Requirements

- macOS 10.15 or later
- Python 3.8 or later
- PyQt6
- Fleet API access (for policy and profile uploads)

## Installation

1. Clone the repository:
   ```
   git clone https://github.com/harrisonravazzolo/fleet-mscp-importer.git
   cd fleet-mscp-importer
   ```

2. Create a virtual environment:
   ```
   python -m venv venv
   source venv/bin/activate
   ```

3. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

1. Run the application:
   ```
   python run_gui.py
   ```

2. Go to the "Input" tab and select a manifest file
3. Click "Process Manifest"
4. View the generated files in the "Output" tab
5. Configure Fleet API settings in the "Fleet API" tab
6. Upload policies and configuration profiles to Fleet
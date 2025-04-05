import sys
import os
from pathlib import Path
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLabel, QFileDialog, QTextEdit, QTabWidget,
    QMessageBox, QProgressBar, QGroupBox, QFormLayout, QLineEdit, QComboBox, QCheckBox, QDialog, QListWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon

from manifest_parser import ManifestParser, SecurityManifest

# Remove complex styling
APP_STYLE = """
QMainWindow {
    background-color: #f0f0f0;
}

QTabWidget::pane {
    border: 1px solid #cccccc;
    background-color: white;
}

QTabBar::tab {
    background-color: #e0e0e0;
    color: #000000;
    border: 1px solid #cccccc;
    padding: 5px 10px;
}

QTabBar::tab:selected {
    background-color: white;
    border-bottom: none;
}

QGroupBox {
    border: 1px solid #cccccc;
    margin-top: 10px;
    font-weight: bold;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 5px 0 5px;
}

QPushButton {
    background-color: #e0e0e0;
    color: black;
    border: 1px solid #cccccc;
    padding: 5px 10px;
}

QPushButton:hover {
    background-color: #d0d0d0;
}

QPushButton:pressed {
    background-color: #c0c0c0;
}

QPushButton:disabled {
    background-color: #f0f0f0;
    color: #a0a0a0;
}

QLineEdit, QComboBox {
    border: 1px solid #cccccc;
    padding: 3px;
    background-color: white;
    color: black;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid #0078d7;
}

QComboBox::drop-down {
    border: none;
    background-color: white;
}

QComboBox::down-arrow {
    image: none;
    border: none;
}

QComboBox QAbstractItemView {
    background-color: white;
    color: black;
    selection-background-color: #0078d7;
    selection-color: white;
    border: 1px solid #cccccc;
}

QTextEdit {
    border: 1px solid #cccccc;
    padding: 3px;
    background-color: white;
    color: black;
}

QLabel {
    color: black;
}

QProgressBar {
    border: 1px solid #cccccc;
    text-align: center;
    background-color: #f0f0f0;
}

QProgressBar::chunk {
    background-color: #0078d7;
}
"""

class ProcessingThread(QThread):
    """Thread for processing the manifest file"""
    progress = pyqtSignal(str)
    finished = pyqtSignal(object)
    error = pyqtSignal(str)
    
    def __init__(self, manifest_path, output_dir=None):
        super().__init__()
        self.manifest_path = manifest_path
        self.output_dir = output_dir
        
    def run(self):
        try:
            self.progress.emit("Loading manifest...")
            parser = ManifestParser(self.manifest_path, self.output_dir)
            manifest = parser.load_manifest()
            
            self.progress.emit("Processing manifest...")
            parser.process_manifest(manifest)
            
            self.finished.emit(parser)
        except Exception as e:
            self.error.emit(str(e))

class MainWindow(QMainWindow):
    """Main window for the macOS Security Compliance Tool"""
    def __init__(self):
        super().__init__()
        self.setWindowTitle("macOS Security Compliance Tool")
        self.setMinimumSize(800, 600)
        
        # Set application style
        self.setStyleSheet(APP_STYLE)
        
        # Initialize variables
        self.manifest_path = None
        self.output_dir = None
        self.parser = None
        self.manifest = None
        
        # Set up the UI
        self.setup_ui()
        
    def setup_ui(self):
        """Set up the main UI components"""
        # Create central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Create tab widget
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Add tabs
        self.tabs.addTab(self.create_input_tab(), "Input")
        self.tabs.addTab(self.create_output_tab(), "Output")
        self.tabs.addTab(self.create_fleet_api_tab(), "Fleet API")
        self.tabs.addTab(self.create_about_tab(), "About")
        
        # Set the first tab as active
        self.tabs.setCurrentIndex(0)
        
    def create_input_tab(self):
        """Create the input tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Welcome message
        welcome_label = QLabel("Welcome to the macOS Security Compliance Tool")
        welcome_label.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(welcome_label)
        
        intro_text = QLabel("This tool helps you process security compliance manifests and generate osquery rules and fix files.")
        intro_text.setWordWrap(True)
        layout.addWidget(intro_text)
        
        # File selection group
        file_group = QGroupBox("Manifest File")
        file_layout = QFormLayout()
        
        self.manifest_path_label = QLabel("No file selected")
        self.manifest_path_label.setWordWrap(True)
        file_layout.addRow("Manifest:", self.manifest_path_label)
        
        browse_button = QPushButton("Browse...")
        browse_button.clicked.connect(self.browse_manifest)
        file_layout.addRow("", browse_button)
        
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)
        
        # Output directory group
        output_group = QGroupBox("Output Directory")
        output_layout = QFormLayout()
        
        self.output_dir_label = QLabel("Default (same as manifest)")
        self.output_dir_label.setWordWrap(True)
        output_layout.addRow("Directory:", self.output_dir_label)
        
        browse_output_button = QPushButton("Browse...")
        browse_output_button.clicked.connect(self.browse_output_dir)
        output_layout.addRow("", browse_output_button)
        
        output_group.setLayout(output_layout)
        layout.addWidget(output_group)
        
        # Process button
        self.process_button = QPushButton("Process Manifest")
        self.process_button.setEnabled(False)
        self.process_button.clicked.connect(self.process_manifest)
        layout.addWidget(self.process_button)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v - %m")
        layout.addWidget(self.progress_bar)
        
        # Status label
        self.status_label = QLabel("")
        layout.addWidget(self.status_label)
        
        return tab
    
    def create_output_tab(self):
        """Create the output tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Output header
        output_header = QLabel("Processing Results")
        output_header.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(output_header)
        
        # Output description
        output_desc = QLabel("The manifest has been processed. You can view the generated files below.")
        output_desc.setWordWrap(True)
        layout.addWidget(output_desc)
        
        # Output text area
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        layout.addWidget(self.output_text)
        
        # Files group
        files_group = QGroupBox("Generated Files")
        files_layout = QVBoxLayout()
        
        # Osquery rules
        osquery_layout = QHBoxLayout()
        osquery_label = QLabel("Osquery Rules:")
        osquery_layout.addWidget(osquery_label)
        
        self.osquery_path_label = QLabel("Not generated yet")
        self.osquery_path_label.setWordWrap(True)
        osquery_layout.addWidget(self.osquery_path_label)
        
        open_osquery_button = QPushButton("Open")
        open_osquery_button.clicked.connect(self.open_osquery_dir)
        osquery_layout.addWidget(open_osquery_button)
        
        files_layout.addLayout(osquery_layout)
        
        # Fix files
        fixes_label = QLabel("Fix Files:")
        files_layout.addWidget(fixes_label)
        
        # Fix files list
        self.fixes_list = QTextEdit()
        self.fixes_list.setReadOnly(True)
        self.fixes_list.setMaximumHeight(150)
        files_layout.addWidget(self.fixes_list)
        
        # Open fixes directory button
        open_fixes_button = QPushButton("Open Fixes Directory")
        open_fixes_button.clicked.connect(self.open_fixes_dir)
        files_layout.addWidget(open_fixes_button)
        
        files_group.setLayout(files_layout)
        layout.addWidget(files_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        return tab
    
    def create_fleet_api_tab(self):
        """Create the Fleet API tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # Fleet API header
        fleet_header = QLabel("Fleet API Integration")
        fleet_header.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(fleet_header)
        
        # Fleet API description
        fleet_desc = QLabel("Configure your Fleet API connection and upload policies and scripts.")
        fleet_desc.setWordWrap(True)
        layout.addWidget(fleet_desc)
        
        # Fleet API configuration group
        fleet_group = QGroupBox("Fleet API Configuration")
        fleet_layout = QFormLayout()
        
        # Fleet URL input
        self.fleet_url_input = QLineEdit()
        self.fleet_url_input.setPlaceholderText("Enter your Fleet URL (e.g., fleet.example.com)")
        fleet_layout.addRow("Fleet URL:", self.fleet_url_input)
        
        # API Token input
        self.fleet_token_input = QLineEdit()
        self.fleet_token_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.fleet_token_input.setPlaceholderText("Enter your API token")
        fleet_layout.addRow("API Token:", self.fleet_token_input)
        
        # Team ID input
        self.team_id_input = QLineEdit()
        self.team_id_input.setPlaceholderText("Enter your team ID (default: 10)")
        self.team_id_input.setText("10")
        fleet_layout.addRow("Team ID:", self.team_id_input)
        
        # Save configuration button
        save_config_button = QPushButton("Save Configuration")
        save_config_button.clicked.connect(self.save_fleet_config)
        fleet_layout.addRow("", save_config_button)
        
        fleet_group.setLayout(fleet_layout)
        layout.addWidget(fleet_group)
        
        # Policy upload group
        upload_group = QGroupBox("Upload Policies to Fleet")
        upload_layout = QFormLayout()
        
        # Policy selection
        self.policy_combo = QComboBox()
        self.policy_combo.setEnabled(False)
        self.policy_combo.setPlaceholderText("Select a policy to upload")
        upload_layout.addRow("Select Policy:", self.policy_combo)
        
        # Upload button
        self.upload_button = QPushButton("Upload to Fleet")
        self.upload_button.setEnabled(False)
        self.upload_button.clicked.connect(self.upload_policy_to_fleet)
        upload_layout.addRow("", self.upload_button)
        
        # Status label
        self.fleet_status_label = QLabel("Ready")
        upload_layout.addRow("Status:", self.fleet_status_label)
        
        upload_group.setLayout(upload_layout)
        layout.addWidget(upload_group)
        
        # Script upload group
        script_group = QGroupBox("Upload Shell Scripts to Fleet")
        script_layout = QFormLayout()
        
        # Script selection
        self.script_combo = QComboBox()
        self.script_combo.setEnabled(False)
        self.script_combo.setPlaceholderText("Select a script to upload")
        script_layout.addRow("Select Script:", self.script_combo)
        
        # Upload script button
        self.upload_script_button = QPushButton("Upload Script to Fleet")
        self.upload_script_button.setEnabled(False)
        self.upload_script_button.clicked.connect(self.upload_script_to_fleet)
        script_layout.addRow("", self.upload_script_button)
        
        # Script status label
        self.script_status_label = QLabel("Ready")
        script_layout.addRow("Status:", self.script_status_label)
        
        script_group.setLayout(script_layout)
        layout.addWidget(script_group)
        
        # Configuration profile upload group
        profile_group = QGroupBox("Upload Configuration Profiles to Fleet")
        profile_layout = QFormLayout()
        
        # Upload button
        self.upload_profile_button = QPushButton("Upload Configuration Profile")
        self.upload_profile_button.clicked.connect(self.upload_configuration_profile_to_fleet)
        profile_layout.addRow("", self.upload_profile_button)
        
        profile_group.setLayout(profile_layout)
        layout.addWidget(profile_group)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        return tab
    
    def create_about_tab(self):
        """Create the about tab"""
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        # About header
        about_header = QLabel("About")
        about_header.setFont(QFont("Arial", 14, QFont.Weight.Bold))
        layout.addWidget(about_header)
        
        # Logo placeholder (you can replace this with an actual logo)
        logo_label = QLabel("🔒")
        logo_label.setFont(QFont("Arial", 48))
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(logo_label)
        
        # About text
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setHtml("""
            <h1>macOS Security Compliance Tool</h1>
            <p>Version 1.0.0</p>
            
            <p>This tool processes macOS security compliance manifests and generates:</p>
            <ul>
                <li>Osquery YAML files for compliance checking</li>
                <li>Fix files (shell scripts or mobileconfig) for remediation</li>
            </ul>
            
            <p>Features:</p>
            <ul>
                <li>Process security compliance manifests</li>
                <li>Generate osquery rules for compliance checking</li>
                <li>Generate fix files for remediation</li>
                <li>Upload policies to Fleet</li>
                <li>Upload configuration profiles to Fleet</li>
            </ul>
            
            <p>Requirements:</p>
            <ul>
                <li>macOS 10.15 or later</li>
                <li>Python 3.8 or later</li>
                <li>PyQt6</li>
                <li>Fleet API access (for policy and profile uploads)</li>
            </ul>
        """)
        layout.addWidget(about_text)
        
        # Add stretch to push everything to the top
        layout.addStretch()
        
        return tab
    
    def browse_manifest(self):
        """Open file dialog to select manifest file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select Manifest File", "", "JSON Files (*.json)"
        )
        
        if file_path:
            self.manifest_path = file_path
            self.manifest_path_label.setText(file_path)
            self.process_button.setEnabled(True)
    
    def browse_output_dir(self):
        """Open directory dialog to select output directory"""
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Output Directory"
        )
        
        if dir_path:
            self.output_dir = dir_path
            self.output_dir_label.setText(dir_path)
    
    def process_manifest(self):
        """Process the manifest file"""
        if not self.manifest_path:
            QMessageBox.warning(self, "Error", "Please select a manifest file")
            return
            
        # Disable the process button
        self.process_button.setEnabled(False)
        
        # Start processing thread
        self.processing_thread = ProcessingThread(
            self.manifest_path, 
            self.output_dir
        )
        self.processing_thread.progress.connect(self.update_progress)
        self.processing_thread.finished.connect(self.processing_finished)
        self.processing_thread.error.connect(self.processing_error)
        self.processing_thread.start()
    
    def update_progress(self, message):
        """Update progress bar and status label"""
        self.status_label.setText(message)
    
    def processing_finished(self, parser):
        """Handle processing finished"""
        self.parser = parser
        self.process_button.setEnabled(True)
        self.status_label.setText("Processing completed successfully")
        
        # Update output tab
        self.output_text.clear()
        self.output_text.append("Processing completed successfully!\n")
        self.output_text.append(f"Osquery rules: {parser.osquery_dir}/security_rules.yaml\n")
        self.output_text.append(f"Fix files: {parser.fixes_dir}/")
        
        # Update osquery path label
        self.osquery_path_label.setText(f"{parser.osquery_dir}/security_rules.yaml")
        
        # Update fixes list
        self.fixes_list.clear()
        if os.path.exists(parser.fixes_dir):
            for file in os.listdir(parser.fixes_dir):
                file_path = os.path.join(parser.fixes_dir, file)
                file_type = "Shell Script" if file.endswith('.sh') else "Configuration Profile" if file.endswith('.mobileconfig') else "Unknown"
                self.fixes_list.append(f"{file} ({file_type})")
        
        # Update policy list for Fleet tab
        self.update_policy_list()
        
        # Update script list for Fleet tab
        self.update_script_list()
        
        # Switch to output tab
        self.findChild(QTabWidget).setCurrentIndex(1)
    
    def processing_error(self, error_message):
        """Handle processing error"""
        self.process_button.setEnabled(True)
        self.status_label.setText(f"Error: {error_message}")
        QMessageBox.critical(self, "Error", f"An error occurred: {error_message}")
    
    def open_osquery_dir(self):
        """Open the osquery directory"""
        if self.parser:
            os.system(f"open {self.parser.osquery_dir}")
        else:
            QMessageBox.warning(self, "Error", "No output directory available")
    
    def open_fixes_dir(self):
        """Open the fixes directory"""
        if self.parser:
            os.system(f"open {self.parser.fixes_dir}")
        else:
            QMessageBox.warning(self, "Error", "No output directory available")
    
    def save_fleet_config(self):
        """Save Fleet API configuration"""
        self.fleet_url = self.fleet_url_input.text().strip()
        self.fleet_token = self.fleet_token_input.text().strip()
        self.team_id = self.team_id_input.text().strip() or "10"  # Default to 10 if empty
        
        if not self.fleet_url:
            QMessageBox.warning(self, "Error", "Please enter a Fleet URL")
            return
        
        if not self.fleet_token:
            QMessageBox.warning(self, "Error", "Please enter an API token")
            return
        
        # Save configuration (in a real app, you might want to save this securely)
        self.fleet_status_label.setText("Configuration saved")
        
        # Enable policy selection if we have policies
        if self.parser and hasattr(self.parser, 'osquery_dir'):
            self.update_policy_list()
            self.update_script_list()
    
    def update_policy_list(self):
        """Update the policy combo box with available policies"""
        if not self.parser or not hasattr(self.parser, 'osquery_dir'):
            return
        
        # Clear the combo box
        self.policy_combo.clear()
        
        # Check if the osquery directory exists
        if not os.path.exists(self.parser.osquery_dir):
            return
        
        # Get the YAML file
        yaml_file = os.path.join(self.parser.osquery_dir, "security_rules.yaml")
        if not os.path.exists(yaml_file):
            return
        
        # Load the YAML file
        try:
            import yaml
            with open(yaml_file, 'r') as f:
                policies = yaml.safe_load(f)
            
            # Add policies to the combo box
            for policy in policies:
                # Get the title from the policy data
                title = policy.get('title', 'Unnamed Policy')
                
                # Add the policy to the combo box with the title as the display text
                self.policy_combo.addItem(title, policy)
            
            # Enable the combo box and upload button
            self.policy_combo.setEnabled(True)
            self.upload_button.setEnabled(True)
        except Exception as e:
            self.fleet_status_label.setText(f"Error loading policies: {str(e)}")
    
    def update_script_list(self):
        """Update the script combo box with available shell scripts"""
        if not self.parser or not hasattr(self.parser, 'fixes_dir'):
            return
        
        # Clear the combo box
        self.script_combo.clear()
        
        # Check if the fixes directory exists
        if not os.path.exists(self.parser.fixes_dir):
            return
        
        # Find all .sh files
        shell_scripts = []
        for file in os.listdir(self.parser.fixes_dir):
            if file.endswith('.sh'):
                shell_scripts.append(file)
        
        # Add scripts to the combo box
        for script_file in shell_scripts:
            self.script_combo.addItem(script_file, os.path.join(self.parser.fixes_dir, script_file))
        
        # Enable the combo box and upload button if we have scripts
        if shell_scripts:
            self.script_combo.setEnabled(True)
            self.upload_script_button.setEnabled(True)
            
    def format_script_name(self, title):
        """Format a policy title into a valid script name"""
        # Convert to lowercase
        name = title.lower()
        
        # Replace spaces and special characters with underscores
        import re
        name = re.sub(r'[^a-z0-9]+', '_', name)
        
        # Remove leading/trailing underscores
        name = name.strip('_')
        
        # Add .sh extension
        return f"{name}.sh"
            
    def upload_policy_to_fleet(self):
        """Upload the selected policy to Fleet"""
        if not hasattr(self, 'fleet_url') or not hasattr(self, 'fleet_token'):
            QMessageBox.warning(self, "Error", "Please configure Fleet API first")
            return
        
        # Get the selected policy
        policy_data = self.policy_combo.currentData()
        if not policy_data:
            QMessageBox.warning(self, "Error", "Please select a policy")
            return
        
        # Debug: Print the policy data to help diagnose issues
        print(f"Policy data: {policy_data}")
        
        # Prepare the API request
        import requests
        
        # Construct the API URL - use the team-specific endpoint
        api_url = f"https://{self.fleet_url}/api/v1/fleet/teams/{self.team_id}/policies"
        
        # Check if this policy has an associated shell script
        script_id = None
        
        # Get the policy name from the combo box text (which is the title)
        policy_name = self.policy_combo.currentText()
        
        # Format the expected script name based on the policy title
        expected_script_name = self.format_script_name(policy_name)
        
        # Look for a matching shell script in the fixes directory
        if self.parser and hasattr(self.parser, 'fixes_dir') and os.path.exists(self.parser.fixes_dir):
            # First try to find an exact match with the formatted name
            script_path = os.path.join(self.parser.fixes_dir, expected_script_name)
            
            if os.path.exists(script_path):
                # Found an exact match
                self.fleet_status_label.setText(f"Found matching script: {expected_script_name}")
            else:
                # Try to find a partial match
                for file in os.listdir(self.parser.fixes_dir):
                    if file.endswith('.sh'):
                        # Check if the base name of the policy is in the script name
                        base_name = policy_name.lower().replace(' ', '_')
                        if base_name in file.lower():
                            script_path = os.path.join(self.parser.fixes_dir, file)
                            self.fleet_status_label.setText(f"Found related script: {file}")
                            break
                else:
                    # No matching script found
                    script_path = None
            
            if script_path:
                # Upload the script first
                self.fleet_status_label.setText(f"Uploading associated script: {os.path.basename(script_path)}...")
                
                # Construct the script upload URL
                script_api_url = f"https://{self.fleet_url}/api/v1/fleet/scripts"
                
                # Read the script content to ensure it's valid
                try:
                    with open(script_path, 'r') as f:
                        script_content = f.read()
                        
                    # Ensure the script has a shebang line
                    if not script_content.startswith('#!/'):
                        script_content = '#!/bin/bash\n' + script_content
                        
                    # Ensure the script ends with a newline
                    if not script_content.endswith('\n'):
                        script_content += '\n'
                        
                    # Write the validated script back to a temporary file
                    import tempfile
                    temp_script = tempfile.NamedTemporaryFile(delete=False, suffix='.sh')
                    temp_script.write(script_content.encode('utf-8'))
                    temp_script.close()
                    
                    # Use the temporary file for upload
                    script_path = temp_script.name
                except Exception as e:
                    self.fleet_status_label.setText(f"Error preparing script: {str(e)}")
                    return
                
                # Prepare the form data for script upload
                script_files = {
                    'script': (os.path.basename(script_path), open(script_path, 'rb'), 'application/octet-stream')
                }
                
                # Add team_id
                script_data = {
                    'team_id': self.team_id
                }
                
                # Set up the headers
                headers = {
                    "Authorization": f"Bearer {self.fleet_token}"
                }
                
                try:
                    # Upload the script
                    script_response = requests.post(script_api_url, files=script_files, data=script_data, headers=headers)
                    
                    if script_response.status_code == 200:
                        script_id = script_response.json().get('script_id')
                        self.fleet_status_label.setText(f"Script uploaded successfully (ID: {script_id}), now uploading policy...")
                    else:
                        error_message = f"Error uploading script: {script_response.status_code} - {script_response.text}"
                        self.fleet_status_label.setText(error_message)
                        QMessageBox.warning(self, "Upload Error", error_message)
                        return
                except Exception as e:
                    self.fleet_status_label.setText(f"Error uploading script: {str(e)}")
                    return
                finally:
                    # Clean up the temporary file
                    try:
                        os.unlink(script_path)
                    except:
                        pass
        
        # Get the query directly from the check field in the manifest
        query = policy_data.get('check', '')
        
        # Debug: Print the query to help diagnose issues
        print(f"Query from check field: {query}")
        
        # Check if the query is empty
        if not query:
            error_message = "Error: Policy query cannot be empty. Please ensure the policy has a valid query."
            self.fleet_status_label.setText(error_message)
            QMessageBox.warning(self, "Upload Error", error_message)
            return
        
        # Always use the title from the manifest for the policy name
        title = policy_data.get('title', policy_name)
        
        # Prepare the request data for policy upload - exactly matching the required format
        request_data = {
            "name": title,  # Use the title from the manifest
            "query": query,  # Use the check field directly as the query
            "description": policy_data.get('description', ''),  # Use the description from the manifest
            "resolution": "See the fix file for resolution steps.",
            "platform": "darwin",  # Since this is a macOS tool
            "critical": policy_data.get('severity', 'unknown') == 'high'
            # No need to include team_id in the request body since it's in the URL
        }
        
        # Debug: Print the request data to help diagnose issues
        print(f"Request data: {request_data}")
        
        # Add script_id if we have one
        if script_id:
            request_data["script_id"] = script_id
        
        # Set up the headers
        headers = {
            "Authorization": f"Bearer {self.fleet_token}",
            "Content-Type": "application/json"
        }
        
        # Disable the upload button during the request
        self.upload_button.setEnabled(False)
        if not script_id:
            self.fleet_status_label.setText("Uploading policy...")
        
        # Make the API request
        try:
            response = requests.post(api_url, json=request_data, headers=headers)
            
            if response.status_code == 200:
                self.fleet_status_label.setText("Policy uploaded successfully")
            else:
                error_message = f"Error: {response.status_code} - {response.text}"
                self.fleet_status_label.setText(error_message)
                QMessageBox.warning(self, "Upload Error", error_message)
        except Exception as e:
            self.fleet_status_label.setText(f"Error: {str(e)}")
        finally:
            # Re-enable the upload button
            self.upload_button.setEnabled(True)
            
    def upload_script_to_fleet(self):
        """Upload the selected shell script to Fleet"""
        if not hasattr(self, 'fleet_url') or not hasattr(self, 'fleet_token'):
            QMessageBox.warning(self, "Error", "Please configure Fleet API first")
            return
        
        # Get the selected script
        script_path = self.script_combo.currentData()
        if not script_path:
            QMessageBox.warning(self, "Error", "Please select a shell script")
            return
        
        # Check if the file exists
        if not os.path.exists(script_path):
            QMessageBox.warning(self, "Error", f"Script file not found: {script_path}")
            return
        
        # Get the script name
        script_name = os.path.basename(script_path)
        
        # Prepare the API request
        import requests
        
        # Construct the API URL
        api_url = f"https://{self.fleet_url}/api/v1/fleet/scripts"
        
        # Read the script content to ensure it's valid
        try:
            with open(script_path, 'r') as f:
                script_content = f.read()
                
            # Ensure the script has a shebang line
            if not script_content.startswith('#!/'):
                script_content = '#!/bin/bash\n' + script_content
                
            # Ensure the script ends with a newline
            if not script_content.endswith('\n'):
                script_content += '\n'
                
            # Write the validated script back to a temporary file
            import tempfile
            temp_script = tempfile.NamedTemporaryFile(delete=False, suffix='.sh')
            temp_script.write(script_content.encode('utf-8'))
            temp_script.close()
            
            # Use the temporary file for upload
            script_path = temp_script.name
        except Exception as e:
            self.script_status_label.setText(f"Error preparing script: {str(e)}")
            return
        
        # Prepare the form data
        files = {
            'script': (script_name, open(script_path, 'rb'), 'application/octet-stream')
        }
        
        # Add team_id
        data = {
            'team_id': self.team_id
        }
        
        # Set up the headers
        headers = {
            "Authorization": f"Bearer {self.fleet_token}"
        }
        
        # Disable the upload button during the request
        self.upload_script_button.setEnabled(False)
        self.script_status_label.setText("Uploading...")
        
        # Make the API request
        try:
            response = requests.post(api_url, files=files, data=data, headers=headers)
            
            if response.status_code == 200:
                script_id = response.json().get('script_id')
                self.script_status_label.setText(f"Script uploaded successfully (ID: {script_id})")
            else:
                error_message = f"Error: {response.status_code} - {response.text}"
                self.script_status_label.setText(error_message)
                QMessageBox.warning(self, "Upload Error", error_message)
        except Exception as e:
            self.script_status_label.setText(f"Error: {str(e)}")
        finally:
            # Re-enable the upload button
            self.upload_script_button.setEnabled(True)
            
            # Clean up the temporary file
            try:
                os.unlink(script_path)
            except:
                pass

    def upload_configuration_profile_to_fleet(self):
        """Upload configuration profiles from the fix directory to Fleet"""
        if not hasattr(self, 'fleet_url') or not hasattr(self, 'fleet_token'):
            QMessageBox.warning(self, "Error", "Please configure Fleet API first")
            return
        
        # Check if we have a parser with a fixes directory
        if not self.parser or not hasattr(self.parser, 'fixes_dir') or not os.path.exists(self.parser.fixes_dir):
            QMessageBox.warning(self, "Error", "No fix directory found. Please process a manifest first.")
            return
        
        # Find all .mobileconfig files in the fixes directory
        mobileconfig_files = []
        for file in os.listdir(self.parser.fixes_dir):
            if file.endswith('.mobileconfig'):
                mobileconfig_files.append(os.path.join(self.parser.fixes_dir, file))
        
        if not mobileconfig_files:
            QMessageBox.warning(self, "Error", "No .mobileconfig files found in the fix directory.")
            return
        
        # Ask the user which configuration profile to upload
        if len(mobileconfig_files) > 1:
            # Create a dialog to select which profile to upload
            dialog = QDialog(self)
            dialog.setWindowTitle("Select Configuration Profile")
            dialog.setMinimumWidth(400)
            
            layout = QVBoxLayout()
            
            # Add a label
            label = QLabel("Select a configuration profile to upload:")
            layout.addWidget(label)
            
            # Add a list widget
            list_widget = QListWidget()
            for file in mobileconfig_files:
                list_widget.addItem(os.path.basename(file))
            layout.addWidget(list_widget)
            
            # Add buttons
            button_layout = QHBoxLayout()
            ok_button = QPushButton("Upload")
            cancel_button = QPushButton("Cancel")
            button_layout.addWidget(ok_button)
            button_layout.addWidget(cancel_button)
            layout.addLayout(button_layout)
            
            dialog.setLayout(layout)
            
            # Connect signals
            ok_button.clicked.connect(dialog.accept)
            cancel_button.clicked.connect(dialog.reject)
            
            # Show the dialog
            if dialog.exec() != QDialog.DialogCode.Accepted:
                return
            
            # Get the selected file
            selected_index = list_widget.currentRow()
            if selected_index < 0:
                return
            
            selected_file = mobileconfig_files[selected_index]
        else:
            # Only one file, use it directly
            selected_file = mobileconfig_files[0]
        
        # Prepare the API request
        import requests
        
        # Construct the API URL
        api_url = f"https://{self.fleet_url}/api/v1/fleet/configuration_profiles"
        
        # Prepare the form data
        files = {
            'profile': (os.path.basename(selected_file), open(selected_file, 'rb'), 'application/x-apple-aspen-config')
        }
        
        # Add team_id if specified
        data = {}
        if hasattr(self, 'team_id') and self.team_id:
            data['team_id'] = self.team_id
        
        # Set up the headers
        headers = {
            "Authorization": f"Bearer {self.fleet_token}"
        }
        
        # Disable the upload button during the request
        self.upload_profile_button.setEnabled(False)
        self.fleet_status_label.setText(f"Uploading configuration profile: {os.path.basename(selected_file)}...")
        
        # Make the API request
        try:
            response = requests.post(api_url, files=files, data=data, headers=headers)
            
            if response.status_code == 200:
                self.fleet_status_label.setText(f"Configuration profile uploaded successfully: {os.path.basename(selected_file)}")
            else:
                error_message = f"Error: {response.status_code} - {response.text}"
                self.fleet_status_label.setText(error_message)
                QMessageBox.warning(self, "Upload Error", error_message)
        except Exception as e:
            self.fleet_status_label.setText(f"Error: {str(e)}")
        finally:
            # Re-enable the upload button
            self.upload_profile_button.setEnabled(True)
            
            # Close the file
            files['profile'][1].close()

def main():
    """Main function to run the application"""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main() 
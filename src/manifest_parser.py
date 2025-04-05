import json
import os
import yaml
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from pydantic import BaseModel, Field
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime
import click
import uuid

class Fix(BaseModel):
    """Model for fix information"""
    mobileconfig_info: Optional[Dict[str, str]] = None
    shell_script: Optional[str] = None

class Rule(BaseModel):
    """Model for security rule"""
    id: str
    title: str
    description: str
    references: str
    tags: str
    severity: Optional[str] = None
    check: str
    result: str
    fix: Fix

class SecurityManifest(BaseModel):
    """Model for macOS security manifest"""
    benchmark: str
    parent: str
    os: str
    plist_location: str
    log_location: str
    creation_date: datetime
    rules: List[Rule]

class ManifestParser:
    def __init__(self, manifest_path: str, output_dir: str = None):
        self.manifest_path = Path(manifest_path)
        self.console = Console()
        
        # Set output directory
        if output_dir:
            self.output_dir = Path(output_dir)
        else:
            self.output_dir = self.manifest_path.parent
        
        # Create output directories
        self.osquery_dir = self.output_dir / "osquery"
        self.fixes_dir = self.output_dir / "fixes"
        
        # Create directories if they don't exist
        os.makedirs(self.osquery_dir, exist_ok=True)
        os.makedirs(self.fixes_dir, exist_ok=True)

    def load_manifest(self) -> SecurityManifest:
        """Load and parse the JSON manifest file"""
        try:
            with open(self.manifest_path, 'r') as f:
                data = json.load(f)
            return SecurityManifest(**data)
        except json.JSONDecodeError as e:
            self.console.print(f"[red]Error parsing JSON: {str(e)}[/red]")
            raise
        except FileNotFoundError:
            self.console.print(f"[red]Manifest file not found: {self.manifest_path}[/red]")
            raise
    
    def convert_check_to_osquery(self, rule: Rule) -> Dict[str, Any]:
        """Convert the check command to osquery format"""
        # Extract the query from the check command
        query = self._extract_osquery_query(rule.check)
        
        # Determine severity level
        severity = rule.severity or "unknown"
        
        # Create a name that matches the shell script name if it exists
        # This helps with associating policies and scripts in Fleet
        name = rule.id
        
        # Create a more Fleet-friendly query
        osquery_query = {
            "name": name,
            "title": rule.title,  # Include the title from the manifest
            "description": rule.description,
            "query": query,
            "interval": "3600",
            "platform": "darwin",
            "tags": rule.tags.split(", "),
            "severity": severity,
            "check": rule.check  # Include the original check field for Fleet API
        }
        
        return osquery_query
    
    def _extract_osquery_query(self, check_command: str) -> str:
        """Extract or convert a shell command to an osquery query"""
        # This is a simplified conversion - in a real implementation,
        # you would need a more sophisticated parser
        
        # Check if it's a simple plist check
        if "NSUserDefaults" in check_command and "objectForKey" in check_command:
            # Extract the domain and key
            import re
            domain_match = re.search(r"initWithSuiteName\('([^']+)'\)", check_command)
            key_match = re.search(r"objectForKey\('([^']+)'\)", check_command)
            
            if domain_match and key_match:
                domain = domain_match.group(1)
                key = key_match.group(1)
                
                # Convert to osquery plist query
                return f"""
SELECT 
    CASE 
        WHEN value = 'false' OR value = '0' THEN 0 
        ELSE 1 
    END as result
FROM plist 
WHERE path = '/Library/Preferences/{domain}.plist' 
    AND key = '{key}'
    AND value = 'false';
"""
        
        # Check if it's a file check
        elif "test" in check_command or "ls" in check_command or "stat" in check_command:
            # Extract file path
            import re
            path_match = re.search(r'(?:test|ls|stat)\s+([^\s]+)', check_command)
            
            if path_match:
                path = path_match.group(1)
                # Convert to osquery file query
                return f"""
SELECT 
    CASE 
        WHEN path IS NOT NULL THEN 1 
        ELSE 0 
    END as result
FROM file 
WHERE path = '{path}';
"""
        
        # Default query for unknown checks
        return f"""
-- Original check: {check_command}
-- TODO: Convert to proper osquery format
SELECT 1 as result;
"""
    
    def generate_fix_file(self, rule: Rule) -> str:
        """Generate fix file (shell script or mobileconfig) based on the fix component"""
        if rule.fix.mobileconfig_info:
            # Generate mobileconfig file in XML plist format
            
            # Generate unique UUIDs
            payload_uuid = str(uuid.uuid4()).upper()
            content_uuid = str(uuid.uuid4()).upper()
            
            # Create the XML plist content
            xml_content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadDisplayName</key>
            <string>{rule.title}</string>
            <key>PayloadIdentifier</key>
            <string>com.security.{rule.id}.{content_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.applicationaccess</string>
            <key>PayloadUUID</key>
            <string>{content_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>"""
            
            # Add the specific settings from mobileconfig_info
            for key, value in rule.fix.mobileconfig_info.items():
                if isinstance(value, bool) or value.lower() in ('true', 'false'):
                    # Handle boolean values
                    bool_value = 'true' if str(value).lower() == 'true' else 'false'
                    xml_content += f"""
            <key>{key}</key>
            <{bool_value}/>"""
                elif isinstance(value, int):
                    # Handle integer values
                    xml_content += f"""
            <key>{key}</key>
            <integer>{value}</integer>"""
                else:
                    # Handle string values
                    xml_content += f"""
            <key>{key}</key>
            <string>{value}</string>"""
            
            # Close the content dict and array
            xml_content += """
        </dict>
    </array>
    <key>PayloadDisplayName</key>
    <string>"""
            
            # Add a short display name
            display_name = rule.id.replace('_', ' ').title()
            xml_content += f"""{display_name}</string>
    <key>PayloadIdentifier</key>
    <string>com.security.{rule.id}.{payload_uuid}</string>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{payload_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"""
            
            # Save as .mobileconfig file
            fix_path = self.fixes_dir / f"{rule.id}.mobileconfig"
            with open(fix_path, 'w') as f:
                f.write(xml_content)
            return str(fix_path)
            
        elif rule.fix.shell_script:
            # Generate shell script
            fix_path = self.fixes_dir / f"{rule.id}.sh"
            
            # Get the script content and ensure it has a shebang line
            script_content = rule.fix.shell_script.strip()
            if not script_content.startswith('#!/'):
                script_content = "#!/bin/bash\n" + script_content
            
            # Write the script
            with open(fix_path, 'w') as f:
                f.write(script_content)
            
            # Make the script executable
            os.chmod(fix_path, 0o755)
            return str(fix_path)
        
        return None
            
    def process_manifest(self, manifest: SecurityManifest):
        """Process the manifest and generate output files"""
        # Create osquery YAML file
        osquery_rules = []
        
        for rule in manifest.rules:
            osquery_rules.append(self.convert_check_to_osquery(rule))
        
        osquery_path = self.osquery_dir / "security_rules.yaml"
        with open(osquery_path, 'w') as f:
            yaml.dump(osquery_rules, f, default_flow_style=False)
        
        self.console.print(f"[green]Generated osquery rules: {osquery_path}[/green]")
        
        # Generate fix files
        for rule in manifest.rules:
            fix_path = self.generate_fix_file(rule)
            if fix_path:
                self.console.print(f"[green]Generated fix file: {fix_path}[/green]")

    def display_manifest(self, manifest: SecurityManifest):
        """Display the manifest contents in a formatted way"""
        # Display manifest metadata
        self.console.print(Panel.fit(
            f"[bold cyan]Benchmark:[/bold cyan] {manifest.benchmark}\n"
            f"[bold cyan]Parent:[/bold cyan] {manifest.parent}\n"
            f"[bold cyan]OS:[/bold cyan] {manifest.os}\n"
            f"[bold cyan]Plist Location:[/bold cyan] {manifest.plist_location}\n"
            f"[bold cyan]Log Location:[/bold cyan] {manifest.log_location}\n"
            f"[bold cyan]Creation Date:[/bold cyan] {manifest.creation_date}",
            title="Manifest Information",
            border_style="cyan"
        ))
        
        # Display rules
        self.console.print("\n[bold]Rules:[/bold]")
        for rule in manifest.rules:
            # Create a table for each rule
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Field", style="cyan")
            table.add_column("Value", style="green")
            
            table.add_row("ID", rule.id)
            table.add_row("Title", rule.title)
            table.add_row("Description", rule.description)
            table.add_row("References", rule.references)
            table.add_row("Tags", rule.tags)
            table.add_row("Severity", rule.severity or "Not specified")
            table.add_row("Result", rule.result)
            
            # Add fix information if available
            fix_info = []
            if rule.fix.mobileconfig_info:
                fix_info.append(f"MobileConfig: {json.dumps(rule.fix.mobileconfig_info, indent=2)}")
            if rule.fix.shell_script:
                fix_info.append(f"Shell Script: {rule.fix.shell_script}")
            table.add_row("Fix", "\n".join(fix_info) if fix_info else "No fix specified")
            
            self.console.print(table)
            self.console.print("")  # Add spacing between rules

@click.command()
@click.argument('manifest_path', type=click.Path(exists=True))
@click.option('--output-dir', '-o', type=click.Path(), help='Output directory for generated files')
@click.option('--display-only', '-d', is_flag=True, help='Only display the manifest without generating files')
def main(manifest_path: str, output_dir: str, display_only: bool):
    """Parse and display macOS security compliance manifest"""
    parser = ManifestParser(manifest_path, output_dir)
    try:
        manifest = parser.load_manifest()
        parser.display_manifest(manifest)
        
        if not display_only:
            parser.process_manifest(manifest)
            parser.console.print(f"\n[bold green]Output files generated in: {parser.output_dir}[/bold green]")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)
        raise click.Abort()

if __name__ == '__main__':
    main() 
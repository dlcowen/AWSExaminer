#!/usr/bin/env python3

import sys
from PySide6 import QtWidgets, QtCore, QtGui
import boto3
from botocore.exceptions import ClientError
from PySide6.QtWidgets import (
    QDialog,
    QVBoxLayout,
    QHBoxLayout,
    QLabel,
    QRadioButton,
    QButtonGroup,
    QComboBox,
    QLineEdit,
    QCheckBox,
    QPushButton,
    QMessageBox,
    QProgressDialog,
    QToolBar,
    QFileDialog,
    QDialogButtonBox,
)
import configparser
import os
from PySide6.QtCore import QCoreApplication
from datetime import datetime
import json
import pandas as pd

def get_all_resources(session, progress_dialog=None):
    """
    Enumerate AWS resources across all regions and return them in a dictionary, keyed by region.
    Uses the provided Boto3 session for AWS service clients.
    """
    if progress_dialog:
        progress_dialog.update_status("Fetching AWS regions...", 0, 0)
        QCoreApplication.processEvents()  # Process GUI events
    
    ec2_client = session.client('ec2')
    try:
        regions_data = ec2_client.describe_regions()
        regions = [r['RegionName'] for r in regions_data['Regions']]
    except ClientError as e:
        print(f"Error fetching regions: {e}")
        return {}

    # Include a special 'ALL' region label
    regions.insert(0, 'ALL')
    
    # Calculate progress increments
    total_regions = len(regions) - 1  # Subtract 1 for 'ALL'
    progress_per_region = 90 / total_regions  # Save 10% for initialization
    current_progress = 10

    resources_by_region = {}

    for region in regions:
        if region == 'ALL':
            continue

        if progress_dialog:
            progress_dialog.update_status(f"Starting enumeration in {region}...", 
                                       int(current_progress), 0)

        region_data = {
            'Instances': [],
            'Volumes': [],
            'Snapshots': [],
            'SecurityGroups': [],
            'S3Buckets': [],
            'RDSInstances': []
        }

        # EC2 Resources (50% of region progress)
        try:
            if progress_dialog:
                progress_dialog.update_status(f"Checking EC2 instances in {region}...", 
                                           int(current_progress), 10)
            
            ec2 = session.client('ec2', region_name=region)
            # Instances
            instances_data = ec2.describe_instances()
            for reservation in instances_data['Reservations']:
                for instance in reservation['Instances']:
                    region_data['Instances'].append(instance['InstanceId'])

            if progress_dialog:
                progress_dialog.update_status(f"Checking EC2 volumes in {region}...", 
                                           int(current_progress), 20)
            
            # Volumes
            volumes_data = ec2.describe_volumes()
            for volume in volumes_data['Volumes']:
                region_data['Volumes'].append(volume['VolumeId'])

            if progress_dialog:
                progress_dialog.update_status(f"Checking EC2 snapshots in {region}...", 
                                           int(current_progress), 30)
            
            # Snapshots
            snapshots_data = ec2.describe_snapshots(OwnerIds=['self'])
            for snapshot in snapshots_data['Snapshots']:
                region_data['Snapshots'].append(snapshot['SnapshotId'])

            if progress_dialog:
                progress_dialog.update_status(f"Checking security groups in {region}...", 
                                           int(current_progress), 40)
            
            # Security Groups
            sgs_data = ec2.describe_security_groups()
            for sg in sgs_data['SecurityGroups']:
                region_data['SecurityGroups'].append(f"{sg['GroupName']} ({sg['GroupId']})")

        except ClientError as e:
            # Handle or log errors
            pass

        # S3 Resources (25% of region progress)
        try:
            if progress_dialog:
                progress_dialog.update_status(f"Checking S3 buckets in {region}...", 
                                           int(current_progress), 60)
            
            s3_client = session.client('s3')
            buckets_data = s3_client.list_buckets()
            for bucket in buckets_data['Buckets']:
                bucket_region = s3_client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
                if bucket_region == region or (bucket_region is None and region == 'us-east-1'):
                    region_data['S3Buckets'].append(bucket['Name'])
        except ClientError:
            pass

        # RDS Resources (25% of region progress)
        try:
            if progress_dialog:
                progress_dialog.update_status(f"Checking RDS instances in {region}...", 
                                           int(current_progress), 80)
            
            rds = session.client('rds', region_name=region)
            rds_data = rds.describe_db_instances()
            for db_instance in rds_data['DBInstances']:
                region_data['RDSInstances'].append(
                    f"{db_instance['DBInstanceIdentifier']} (Status: {db_instance['DBInstanceStatus']})"
                )
        except ClientError:
            pass

        resources_by_region[region] = region_data
        current_progress += progress_per_region

        if progress_dialog:
            progress_dialog.update_status(f"Completed enumeration in {region}", 
                                       int(current_progress), 100)

    if progress_dialog:
        progress_dialog.update_status("Finalizing...", 100, 100)

    return resources_by_region

class AuthDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("AWS Authentication")
        self.setModal(True)

        self.layout = QVBoxLayout()

        # Authentication Method Selection
        self.auth_label = QLabel("Select Authentication Method:")
        self.layout.addWidget(self.auth_label)

        self.profile_radio = QRadioButton("Profile from credentials file")
        self.api_radio = QRadioButton("API Key (Access Key ID and Secret Access Key)")
        self.profile_radio.setChecked(True)

        self.button_group = QButtonGroup()
        self.button_group.addButton(self.profile_radio)
        self.button_group.addButton(self.api_radio)

        self.layout.addWidget(self.profile_radio)
        self.layout.addWidget(self.api_radio)

        # Profile Selection
        self.profile_layout = QHBoxLayout()
        self.profile_label = QLabel("Select Profile:")
        self.profile_combo = QComboBox()
        self.profile_layout.addWidget(self.profile_label)
        self.profile_layout.addWidget(self.profile_combo)

        # API Key Inputs
        self.api_layout = QVBoxLayout()
        self.access_key_input = QLineEdit()
        self.access_key_input.setPlaceholderText("Access Key ID")
        self.secret_key_input = QLineEdit()
        self.secret_key_input.setPlaceholderText("Secret Access Key")
        self.secret_key_input.setEchoMode(QLineEdit.Password)
        self.store_key_checkbox = QCheckBox("Store API Key for future use")
        self.api_layout.addWidget(self.access_key_input)
        self.api_layout.addWidget(self.secret_key_input)
        self.api_layout.addWidget(self.store_key_checkbox)

        # Create container widgets for layouts
        self.profile_widget = QtWidgets.QWidget()
        self.profile_widget.setLayout(self.profile_layout)
        self.api_widget = QtWidgets.QWidget()
        self.api_widget.setLayout(self.api_layout)
        self.layout.addWidget(self.profile_widget)
        self.layout.addWidget(self.api_widget)

        # Hide API inputs initially by hiding the container widget
        self.api_widget.setVisible(False)

        # Buttons
        self.button_layout = QHBoxLayout()
        self.ok_button = QPushButton("OK")
        self.cancel_button = QPushButton("Cancel")
        self.button_layout.addWidget(self.ok_button)
        self.button_layout.addWidget(self.cancel_button)
        self.layout.addLayout(self.button_layout)

        self.setLayout(self.layout)

        # Connect signals
        self.profile_radio.toggled.connect(self.toggle_auth_method)
        self.ok_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

        self.load_profiles()

    def toggle_auth_method(self):
        if self.profile_radio.isChecked():
            self.profile_widget.setVisible(True)
            self.api_widget.setVisible(False)
        else:
            self.profile_widget.setVisible(False)
            self.api_widget.setVisible(True)

    def load_profiles(self):
        config_path = os.path.expanduser('~/.aws/credentials')
        if os.path.exists(config_path):
            config = configparser.ConfigParser()
            config.read(config_path)
            profiles = config.sections()
            self.profile_combo.addItems(profiles)
        else:
            self.profile_combo.addItem("default")

class ProgressDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enumerating AWS Resources")
        self.setModal(True)
        self.setMinimumWidth(400)

        # Create layout
        layout = QVBoxLayout()

        # Overall progress
        self.overall_label = QLabel("Overall Progress:")
        layout.addWidget(self.overall_label)
        self.overall_progress = QtWidgets.QProgressBar()
        self.overall_progress.setMinimum(0)
        self.overall_progress.setMaximum(100)
        layout.addWidget(self.overall_progress)

        # Current region progress
        self.region_label = QLabel("Current Region:")
        layout.addWidget(self.region_label)
        self.region_progress = QtWidgets.QProgressBar()
        self.region_progress.setMinimum(0)
        self.region_progress.setMaximum(100)
        layout.addWidget(self.region_progress)

        # Status message
        self.status_label = QLabel("Initializing...")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def update_status(self, message, overall_value, region_value=None):
        self.status_label.setText(message)
        self.overall_progress.setValue(overall_value)
        if region_value is not None:
            self.region_progress.setValue(region_value)
        # Process events to update the GUI
        QCoreApplication.processEvents()

class ExportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Data")
        self.setModal(True)
        
        layout = QVBoxLayout()
        
        # Export format options
        self.text_radio = QRadioButton("Text (as displayed)")
        self.json_radio = QRadioButton("JSON")
        self.xlsx_radio = QRadioButton("Excel (XLSX)")
        self.text_radio.setChecked(True)
        
        layout.addWidget(QLabel("Select export format:"))
        layout.addWidget(self.text_radio)
        layout.addWidget(self.json_radio)
        layout.addWidget(self.xlsx_radio)
        
        # OK/Cancel buttons
        button_box = QDialogButtonBox(
            QDialogButtonBox.Ok | QDialogButtonBox.Cancel
        )
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)
        
        self.setLayout(layout)
    
    def get_selected_format(self):
        if self.text_radio.isChecked():
            return "txt"
        elif self.json_radio.isChecked():
            return "json"
        else:
            return "xlsx"

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AWS Enumerator Tool")
        self.resize(1000, 600)

        # Create toolbar
        self.toolbar = QToolBar()
        self.addToolBar(self.toolbar)
        
        # Add export action
        export_action = self.toolbar.addAction("Export")
        export_action.triggered.connect(self.export_data)

        # Main Widget and Layout
        main_widget = QtWidgets.QWidget()
        main_layout = QtWidgets.QVBoxLayout(main_widget)
        self.setCentralWidget(main_widget)

        # A splitter for top area (regions on left, resources on right)
        top_splitter = QtWidgets.QSplitter()
        top_splitter.setOrientation(QtCore.Qt.Horizontal)
        main_layout.addWidget(top_splitter)

        # Bottom log pane
        self.log_text = QtWidgets.QTextEdit()
        self.log_text.setReadOnly(True)
        main_layout.addWidget(self.log_text)

        # Left side: region list
        self.region_list = QtWidgets.QListWidget()
        self.region_list.setFixedWidth(200)
        top_splitter.addWidget(self.region_list)

        # Right side: resources display
        self.resource_display = QtWidgets.QTextEdit()
        self.resource_display.setReadOnly(True)
        top_splitter.addWidget(self.resource_display)

        # Connect region list selection to display update
        self.region_list.currentItemChanged.connect(self.display_resources_for_region)

    def initialize_aws(self):
        """Initialize AWS session and fetch resources after GUI is shown"""
        # Authentication
        self.session = self.authenticate()
        if not self.session:
            sys.exit(0)  # Exit if authentication failed or was cancelled

        # Create and show progress dialog
        progress = ProgressDialog(self)
        progress.show()
        QCoreApplication.processEvents()  # Process GUI events

        # Fetch all resource data from AWS
        self.resources = get_all_resources(self.session, progress)

        # Close progress dialog
        progress.close()

        # Calculate total resources for ALL regions
        all_resources_count = 0
        for region, data in self.resources.items():
            if region != 'ALL':
                region_count = sum(len(resources) for resources in data.values())
                all_resources_count += region_count
                # Add region with resource count to the list
                self.region_list.addItem(f"{region} ({region_count} resources)")

        # Add ALL option at the top with total resource count
        self.region_list.insertItem(0, f"ALL ({all_resources_count} resources)")

        # Initial log message
        self.log("AWS Enumerator initialized. Select a region on the left to see its resources.")

    def authenticate(self):
        auth_dialog = AuthDialog(self)
        if auth_dialog.exec() == QDialog.Accepted:
            if auth_dialog.profile_radio.isChecked():
                selected_profile = auth_dialog.profile_combo.currentText()
                self.log(f"Using AWS profile: {selected_profile}")
                return boto3.Session(profile_name=selected_profile)
            else:
                access_key = auth_dialog.access_key_input.text().strip()
                secret_key = auth_dialog.secret_key_input.text().strip()
                if not access_key or not secret_key:
                    QMessageBox.warning(self, "Input Error", "Please provide both Access Key ID and Secret Access Key.")
                    return self.authenticate()
                store_key = auth_dialog.store_key_checkbox.isChecked()
                if store_key:
                    self.store_api_key(access_key, secret_key)
                self.log("Using provided API Key for authentication.")
                return boto3.Session(
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key
                )
        else:
            self.log("Authentication canceled by user.")
            return None

    def store_api_key(self, access_key, secret_key):
        config_path = os.path.expanduser('~/.aws/credentials')
        config = configparser.ConfigParser()
        if os.path.exists(config_path):
            config.read(config_path)
        # Use a special profile name for stored API keys
        profile_name = "stored_api_key"
        config[profile_name] = {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key
        }
        with open(config_path, 'w') as configfile:
            config.write(configfile)
        self.log(f"API Key stored under profile '{profile_name}'.")

    def display_resources_for_region(self, current, previous):
        if not current:
            return

        # Extract region name from the list item text (remove the resource count)
        region = current.text().split(" (")[0]
        
        if region == "ALL":
            # Combine data for all regions
            combined = {
                'Instances': [],
                'Volumes': [],
                'Snapshots': [],
                'SecurityGroups': [],
                'S3Buckets': [],
                'RDSInstances': []
            }
            for r, region_data in self.resources.items():
                if r == "ALL":
                    continue
                for key in combined:
                    combined[key].extend(region_data[key])

            self.log(f"Displaying resources for ALL regions.")
            self.resource_display.clear()
            self.resource_display.append(self.format_region_data("ALL", combined))
        else:
            region_data = self.resources.get(region, {})
            self.log(f"Displaying resources for region {region}.")
            self.resource_display.clear()
            self.resource_display.append(self.format_region_data(region, region_data))

    def format_region_data(self, region, data_dict):
        lines = [f"Resources in region: {region}\n"]
        for resource_type, items in data_dict.items():
            lines.append(f"{resource_type}:")
            if not items:
                lines.append("  - (none)")
            else:
                for item in items:
                    lines.append(f"  - {item}")
            lines.append("")
        return "\n".join(lines)

    def log(self, message):
        self.log_text.append(message)

    def get_account_id(self):
        """Get AWS Account ID from the current session"""
        try:
            sts = self.session.client('sts')
            return sts.get_caller_identity()["Account"]
        except Exception:
            return "unknown-account"

    def export_data(self):
        # Show export format dialog
        dialog = ExportDialog(self)
        if dialog.exec() != QDialog.Accepted:
            return
        
        export_format = dialog.get_selected_format()
        
        # Generate default filename
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        account_id = self.get_account_id()
        default_filename = f"aws-resources-{account_id}-{timestamp}.{export_format}"
        
        # Get save location
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Export As",
            default_filename,
            f"Export Files (*.{export_format})"
        )
        
        if not file_path:
            return
            
        try:
            if export_format == "txt":
                self.export_as_text(file_path)
            elif export_format == "json":
                self.export_as_json(file_path)
            else:  # xlsx
                self.export_as_xlsx(file_path)
                
            self.log(f"Successfully exported data to {file_path}")
        except Exception as e:
            QMessageBox.critical(
                self,
                "Export Error",
                f"Failed to export data: {str(e)}"
            )
            self.log(f"Export failed: {str(e)}")

    def export_as_text(self, file_path):
        """Export data as text format"""
        with open(file_path, 'w') as f:
            # Export ALL regions first
            all_data = self.format_region_data("ALL", self.combine_all_regions())
            f.write(all_data)
            f.write("\n" + "="*50 + "\n\n")
            
            # Export individual regions
            for region in sorted(self.resources.keys()):
                if region != "ALL":
                    region_data = self.format_region_data(region, self.resources[region])
                    f.write(region_data)
                    f.write("\n" + "="*50 + "\n\n")

    def export_as_json(self, file_path):
        """Export data as JSON format"""
        export_data = {
            "metadata": {
                "account_id": self.get_account_id(),
                "export_date": datetime.now().isoformat(),
            },
            "all_regions": self.combine_all_regions(),
            "regions": self.resources
        }
        
        with open(file_path, 'w') as f:
            json.dump(export_data, f, indent=2)

    def export_as_xlsx(self, file_path):
        """Export data as Excel format"""
        with pd.ExcelWriter(file_path) as writer:
            # Create summary sheet
            summary_data = {
                'Region': [],
                'Resource Type': [],
                'Count': []
            }
            
            # Add ALL regions summary
            all_resources = self.combine_all_regions()
            for resource_type, items in all_resources.items():
                summary_data['Region'].append('ALL')
                summary_data['Resource Type'].append(resource_type)
                summary_data['Count'].append(len(items))
            
            # Add individual region summaries
            for region in sorted(self.resources.keys()):
                if region != "ALL":
                    for resource_type, items in self.resources[region].items():
                        summary_data['Region'].append(region)
                        summary_data['Resource Type'].append(resource_type)
                        summary_data['Count'].append(len(items))
            
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
            
            # Create detailed sheets for each resource type
            resource_types = ['Instances', 'Volumes', 'Snapshots', 'SecurityGroups', 'S3Buckets', 'RDSInstances']
            
            for resource_type in resource_types:
                resource_data = {
                    'Region': [],
                    'Resource': []
                }
                
                for region in sorted(self.resources.keys()):
                    if region != "ALL":
                        for resource in self.resources[region][resource_type]:
                            resource_data['Region'].append(region)
                            resource_data['Resource'].append(resource)
                
                if resource_data['Region']:  # Only create sheet if there's data
                    pd.DataFrame(resource_data).to_excel(
                        writer,
                        sheet_name=resource_type[:31],  # Excel sheet names limited to 31 chars
                        index=False
                    )

    def combine_all_regions(self):
        """Helper method to combine resources from all regions"""
        combined = {
            'Instances': [],
            'Volumes': [],
            'Snapshots': [],
            'SecurityGroups': [],
            'S3Buckets': [],
            'RDSInstances': []
        }
        
        for region, region_data in self.resources.items():
            if region != "ALL":
                for key in combined:
                    combined[key].extend(region_data[key])
        
        return combined

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MainWindow()
    window.show()  # Show the window first
    # Use QTimer to call initialize_aws after the window is shown
    QtCore.QTimer.singleShot(0, window.initialize_aws)
    sys.exit(app.exec_())

# Remove the old "if __name__ == '__main__': main()" that enumerated in console
# and replace it with the new PySide6 launch:
if __name__ == "__main__":
    main() 
#!/usr/bin/env python3

import sys
from PySide6 import QtWidgets, QtCore, QtGui
import boto3
from botocore.exceptions import ClientError, ParamValidationError
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
    QTreeWidget,
    QTreeWidgetItem,
)
import configparser
import os
from PySide6.QtCore import QCoreApplication
from datetime import datetime
import json
import pandas as pd
import re
from multiprocessing import Pool, cpu_count, Pipe, Process
from functools import partial
import time

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

def get_organization_accounts(session):
    """Get all accounts in the organization"""
    try:
        org_client = session.client('organizations')
        accounts = []
        paginator = org_client.get_paginator('list_accounts')
        
        for page in paginator.paginate():
            accounts.extend(page['Accounts'])
            
        return accounts
    except ClientError as e:
        if e.response['Error']['Code'] == 'AWSOrganizationsNotInUseException':
            return []
        raise e

def can_assume_role(session, account_id, role_name="OrganizationAccountAccessRole"):
    """Test if we can assume the specified role in the account"""
    try:
        sts = session.client('sts')
        role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
        
        # Try to assume the role
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="AWSEnumeratorTest",
            DurationSeconds=900
        )
        return True, response['Credentials']
    except (ClientError, ParamValidationError) as e:
        return False, str(e)

def get_session_with_assumed_role(credentials):
    """Create a new session using assumed role credentials"""
    return boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

def scan_region(credentials, region, progress_pipe=None):
    """Scan a single region for resources"""
    try:
        if progress_pipe:
            progress_pipe.send(("debug", f"Starting session creation for {region}"))

        # Create a new session in the worker process
        if isinstance(credentials, dict):
            if progress_pipe:
                progress_pipe.send(("debug", f"Creating session with provided credentials for {region}"))
            session = boto3.Session(
                aws_access_key_id=credentials['AccessKeyId'],
                aws_secret_access_key=credentials['SecretAccessKey'],
                aws_session_token=credentials.get('SessionToken')
            )
        else:
            if progress_pipe:
                progress_pipe.send(("debug", f"Creating session from credentials object for {region}"))
            creds = credentials.get_credentials()
            session = boto3.Session(
                aws_access_key_id=creds.access_key,
                aws_secret_access_key=creds.secret_key,
                aws_session_token=creds.token
            )

        if progress_pipe:
            progress_pipe.send(("status", f"Scanning {region}...", 0))

        region_data = {
            'Instances': [],
            'Volumes': [],
            'Snapshots': [],
            'SecurityGroups': [],
            'S3Buckets': [],
            'RDSInstances': []
        }

        # EC2 Resources
        if progress_pipe:
            progress_pipe.send(("status", f"Checking EC2 resources in {region}...", 20))

        try:
            ec2 = session.client('ec2', region_name=region)
            # Instances
            instances_data = ec2.describe_instances()
            for reservation in instances_data['Reservations']:
                for instance in reservation['Instances']:
                    region_data['Instances'].append(instance['InstanceId'])

            # Volumes
            volumes_data = ec2.describe_volumes()
            for volume in volumes_data['Volumes']:
                region_data['Volumes'].append(volume['VolumeId'])

            # Snapshots
            snapshots_data = ec2.describe_snapshots(OwnerIds=['self'])
            for snapshot in snapshots_data['Snapshots']:
                region_data['Snapshots'].append(snapshot['SnapshotId'])

            # Security Groups
            sgs_data = ec2.describe_security_groups()
            for sg in sgs_data['SecurityGroups']:
                region_data['SecurityGroups'].append(f"{sg['GroupName']} ({sg['GroupId']})")

        except ClientError as e:
            if progress_pipe:
                progress_pipe.send(("error", f"Error scanning EC2 in {region}: {str(e)}"))

        # S3 Resources
        if progress_pipe:
            progress_pipe.send(("status", f"Checking S3 buckets in {region}...", 60))

        try:
            # S3 Buckets
            s3_client = session.client('s3')
            buckets_data = s3_client.list_buckets()
            for bucket in buckets_data['Buckets']:
                bucket_region = s3_client.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
                if bucket_region == region or (bucket_region is None and region == 'us-east-1'):
                    region_data['S3Buckets'].append(bucket['Name'])
        except ClientError as e:
            if progress_pipe:
                progress_pipe.send(("error", f"Error scanning S3 in {region}: {str(e)}"))

        # RDS Resources
        if progress_pipe:
            progress_pipe.send(("status", f"Checking RDS in {region}...", 80))

        try:
            # RDS Instances
            rds = session.client('rds', region_name=region)
            rds_data = rds.describe_db_instances()
            for db_instance in rds_data['DBInstances']:
                region_data['RDSInstances'].append(
                    f"{db_instance['DBInstanceIdentifier']} (Status: {db_instance['DBInstanceStatus']})"
                )
        except ClientError as e:
            if progress_pipe:
                progress_pipe.send(("error", f"Error scanning RDS in {region}: {str(e)}"))

        if progress_pipe:
            progress_pipe.send(("status", f"Completed scanning {region}", 100))

        return region, region_data

    except Exception as e:
        if progress_pipe:
            progress_pipe.send(("error", f"Error in {region}: {str(e)}"))
        return region, {}

def scan_account(credentials, regions, progress_callback=None):
    """Scan an entire account using provided credentials"""
    print(f"Starting account scan with {len(regions)} regions")
    if isinstance(credentials, dict) and 'RoleArn' in credentials:
        print(f"Using role: {credentials['RoleArn']}")
    
    # Create pipes for progress updates
    pipes = [Pipe() for _ in regions]
    
    try:
        # Create pool with processes
        with Pool(processes=min(cpu_count(), len(regions))) as pool:
            print(f"Created process pool with {min(cpu_count(), len(regions))} processes")
            
            # Start processes with pipes
            async_results = []
            for region, (pipe_send, pipe_recv) in zip(regions, pipes):
                creds = credentials.copy() if isinstance(credentials, dict) else credentials
                print(f"Starting scan for region: {region}")
                async_results.append(
                    pool.apply_async(scan_region, (creds, region, pipe_send))
                )

            # Monitor progress with timeout
            completed_regions = 0
            total_regions = len(regions)
            while completed_regions < total_regions:
                # Update overall progress based on completed regions
                if progress_callback:
                    overall_progress = (completed_regions / total_regions) * 100
                    progress_callback(f"Completed {completed_regions}/{total_regions} regions", overall_progress)

                # Check pipes with timeout
                for pipe_send, pipe_recv in pipes:
                    if pipe_recv.poll(timeout=0.1):  # Add 100ms timeout
                        try:
                            msg_type, *msg_data = pipe_recv.recv()
                            if msg_type == "status" and progress_callback:
                                progress_callback(*msg_data)
                            elif msg_type == "error" and progress_callback:
                                print(f"Error received: {msg_data[0]}")
                                progress_callback(f"Error: {msg_data[0]}", 0)
                            elif msg_type == "debug":
                                print(f"Debug: {msg_data[0]}")
                        except EOFError:
                            print("Pipe closed unexpectedly")

                # Check results with timeout
                for i, result in enumerate(async_results):
                    try:
                        if result.ready():
                            if not result.successful():
                                print(f"Region scan failed: {result.get(timeout=1)}")
                            else:
                                print(f"Successfully completed region scan {i+1}/{total_regions}")
                            completed_regions += 1
                            print(f"Completed regions: {completed_regions}/{total_regions}")
                    except Exception as e:
                        print(f"Error checking result: {str(e)}")

                # Add small sleep to prevent CPU spinning
                QCoreApplication.processEvents()
                time.sleep(0.05)  # Reduced sleep time for more frequent updates

            print("Getting all results")
            # Get all results with timeout
            results = []
            for i, result in enumerate(async_results):
                try:
                    if progress_callback:
                        progress_callback(
                            f"Collecting results: {i+1}/{len(async_results)}", 
                            ((i + 1) / len(async_results)) * 100
                        )
                    print(f"Collecting result {i+1}/{len(async_results)}")
                    region_result = result.get(timeout=30)  # 30 second timeout per region
                    results.append(region_result)
                except Exception as e:
                    print(f"Error collecting result {i+1}: {str(e)}")
                    results.append((f"region-{i}", {}))  # Add empty result on error

            if progress_callback:
                progress_callback("Processing collected results...", 100)
            print("All results collected")

    except Exception as e:
        print(f"Error in scan_account: {str(e)}")
        return {}
    finally:
        # Clean up pipes
        for pipe_send, pipe_recv in pipes:
            pipe_send.close()
            pipe_recv.close()

    # Combine results into a single dictionary
    account_data = {}
    for region, region_data in results:
        account_data[region] = region_data
    
    print(f"Account scan completed with {len(account_data)} regions")
    return account_data

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

        # Overall progress (renamed to account overall)
        self.overall_label = QLabel("Account Overall Progress:")
        layout.addWidget(self.overall_label)
        self.overall_progress = QtWidgets.QProgressBar()
        self.overall_progress.setMinimum(0)
        self.overall_progress.setMaximum(100)
        layout.addWidget(self.overall_progress)

        # Current Account progress
        self.account_label = QLabel("Current Account Progress:")
        layout.addWidget(self.account_label)
        self.account_progress = QtWidgets.QProgressBar()
        self.account_progress.setMinimum(0)
        self.account_progress.setMaximum(100)
        layout.addWidget(self.account_progress)

        # Region progress
        self.region_label = QLabel("Region Progress:")
        layout.addWidget(self.region_label)
        self.region_progress = QtWidgets.QProgressBar()
        self.region_progress.setMinimum(0)
        self.region_progress.setMaximum(100)
        layout.addWidget(self.region_progress)

        # Status message
        self.status_label = QLabel("Initializing...")
        layout.addWidget(self.status_label)

        self.setLayout(layout)

    def update_status(self, message, overall_value, region_value=None, account_value=None):
        self.status_label.setText(message)
        self.overall_progress.setValue(overall_value)
        if region_value is not None:
            self.region_progress.setValue(region_value)
        if account_value is not None:
            self.account_progress.setValue(account_value)
        # Process events to update the GUI
        QCoreApplication.processEvents()

    def set_account_label(self, account_id):
        """Update the overall progress label with the current account ID"""
        self.overall_label.setText(f"Account {account_id} Overall Progress:")
        # Reset progress bars and clear message when switching accounts
        self.overall_progress.setValue(0)
        self.account_progress.setValue(0)
        self.region_progress.setValue(0)
        self.status_label.setText("Starting account scan...")
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

        # Left side: account/region tree
        self.account_tree = QTreeWidget()
        self.account_tree.setHeaderLabel("Accounts & Regions")
        self.account_tree.setFixedWidth(300)
        top_splitter.addWidget(self.account_tree)

        # Right side: resources display
        self.resource_display = QtWidgets.QTextEdit()
        self.resource_display.setReadOnly(True)
        top_splitter.addWidget(self.resource_display)

        # Connect tree selection to display update
        self.account_tree.currentItemChanged.connect(self.display_resources_for_selection)

    def initialize_aws(self):
        """Initialize AWS session and fetch resources after GUI is shown"""
        # Authentication
        self.session = self.authenticate()
        if not self.session:
            sys.exit(0)

        # Create and show progress dialog
        progress = ProgressDialog(self)
        progress.show()
        QCoreApplication.processEvents()

        # Get current account ID and set it in the progress dialog
        current_account = self.get_account_id()
        progress.set_account_label(current_account)

        try:
            # Get organization accounts
            progress.update_status("Checking for organization accounts...", 0, 0, 0)
            self.accounts = get_organization_accounts(self.session)
            self.log(f"Found {len(self.accounts)} accounts in the organization")
        except Exception as e:
            self.log(f"Error checking organization accounts: {str(e)}")
            self.accounts = []

        # Initialize resources dictionary
        self.resources = {}
        
        # Get list of regions
        ec2_client = self.session.client('ec2')
        regions_data = ec2_client.describe_regions()
        regions = [r['RegionName'] for r in regions_data['Regions']]

        # Create account items in tree
        all_accounts_item = QTreeWidgetItem(self.account_tree, ["All Accounts"])
        self.account_tree.addTopLevelItem(all_accounts_item)
        
        # Calculate total number of accounts to process
        total_accounts = 1 + len(self.accounts)
        account_progress = 0
        progress_per_account = 100 / total_accounts

        def progress_callback(progress_dialog):
            """Create a callback closure with access to the progress dialog"""
            def callback(message, progress):
                progress_dialog.update_status(
                    message, 
                    int(account_progress), 
                    progress,  # region progress
                    int(progress)  # account progress
                )
            return callback

        # Process current account
        current_account = self.get_account_id()
        progress.set_account_label(current_account)
        current_account_item = QTreeWidgetItem(all_accounts_item, [f"Account: {current_account} (current)"])
        
        # Get credentials from current session
        creds = self.session.get_credentials()
        session_creds = {
            'AccessKeyId': creds.access_key,
            'SecretAccessKey': creds.secret_key,
            'SessionToken': creds.token
        }
        
        # Scan current account in parallel
        self.resources[current_account] = scan_account(
            session_creds, 
            regions, 
            progress_callback(progress)  # Pass the callback closure
        )
        
        # Update progress and tree for current account
        self.update_account_tree_item(current_account_item, current_account, self.resources[current_account])
        account_progress += progress_per_account
        
        # Process organization accounts
        if self.accounts:
            for account in self.accounts:
                account_id = account['Id']
                if account_id != current_account:
                    self.log(f"Starting processing of account {account_id}")
                    progress.set_account_label(account_id)
                    
                    # Try to assume role
                    self.log(f"Attempting to assume role in account {account_id}")
                    can_assume, credentials = can_assume_role(self.session, account_id)
                    
                    if can_assume:
                        self.log(f"Successfully assumed role in account {account_id}")
                        account_item = QTreeWidgetItem(all_accounts_item, 
                            [f"Account: {account_id} ({account['Name']})"])
                        
                        # Use the credentials we got from assume_role directly
                        # No need to add RoleArn as we've already assumed the role
                        
                        # Scan account in parallel
                        self.log(f"Starting parallel scan of account {account_id}")
                        self.resources[account_id] = scan_account(
                            credentials,  # Use the credentials directly
                            regions,
                            progress_callback(progress)
                        )
                        self.log(f"Completed parallel scan of account {account_id}")
                        
                        self.update_account_tree_item(account_item, account_id, self.resources[account_id])
                    else:
                        self.log(f"Cannot assume role in account {account_id}: {credentials}")
                        account_item = QTreeWidgetItem(all_accounts_item, 
                            [f"Account: {account_id} ({account['Name']}) - Access Denied"])
                        account_item.setToolTip(0, f"Cannot assume role: {credentials}")
                
                account_progress += progress_per_account
                self.log(f"Completed processing of account {account_id}")

        # Calculate and update grand total
        grand_total = self.calculate_grand_total()
        all_accounts_item.setText(0, f"All Accounts ({grand_total} total resources)")

        # Expand the tree and clean up
        self.account_tree.expandAll()
        progress.close()
        self.log("AWS Enumerator initialized. Select an account/region to see its resources.")

    def update_account_tree_item(self, account_item, account_id, account_data):
        """Update tree item with account resource information"""
        total_account_resources = 0
        for region, data in account_data.items():
            if region != 'ALL':
                region_count = sum(len(resources) for resources in data.values())
                total_account_resources += region_count
                QTreeWidgetItem(account_item, [f"{region} ({region_count} resources)"])
        
        # Update account text with total resources
        name = account_item.text(0).split(" - ")[0]  # Keep existing name/description
        account_item.setText(0, f"{name} - {total_account_resources} total resources")
        
        # Add "All Regions" under account
        QTreeWidgetItem(account_item, [f"All Regions ({total_account_resources} resources)"])

    def calculate_grand_total(self):
        """Calculate total resources across all accounts"""
        grand_total = 0
        for account_data in self.resources.values():
            for region_data in account_data.values():
                if isinstance(region_data, dict):  # Ensure it's a region data dictionary
                    grand_total += sum(len(resources) for resources in region_data.values())
        return grand_total

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

    def display_resources_for_selection(self, current, previous):
        if not current:
            return

        item_text = current.text(0)
        
        # Check if this is an account selection
        if item_text.startswith("Account:"):
            account_id = item_text.split()[1]
            if account_id not in self.resources:
                self.resource_display.clear()
                self.resource_display.append(f"Switch to account {account_id} to view its resources")
                return
        
        # Check if this is a region selection
        region_match = re.match(r"([a-z]{2}-[a-z]+-\d+)\s+\(", item_text)
        if region_match:
            region = region_match.group(1)
            account_id = self.get_account_from_item(current)
            if account_id in self.resources:
                region_data = self.resources[account_id].get(region, {})
                self.resource_display.clear()
                self.resource_display.append(self.format_region_data(region, region_data))
        
        # Check if this is "All Regions" for an account
        if item_text.startswith("All Regions"):
            account_id = self.get_account_from_item(current)
            if account_id in self.resources:
                combined = self.combine_all_regions(account_id)
                self.resource_display.clear()
                self.resource_display.append(self.format_region_data("ALL", combined))

    def get_account_from_item(self, item):
        """Get account ID from a tree item by walking up to its account parent"""
        while item:
            if item.text(0).startswith("Account:"):
                return item.text(0).split()[1]
            item = item.parent()
        return None

    def combine_all_regions(self, account_id):
        """Helper method to combine resources from all regions for a specific account"""
        combined = {
            'Instances': [],
            'Volumes': [],
            'Snapshots': [],
            'SecurityGroups': [],
            'S3Buckets': [],
            'RDSInstances': []
        }
        
        if account_id in self.resources:
            for region, region_data in self.resources[account_id].items():
                if region != "ALL":
                    for key in combined:
                        combined[key].extend(region_data[key])
        
        return combined

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
                'Account': [],
                'Region': [],
                'Resource Type': [],
                'Count': []
            }
            
            has_data = False
            # Add data for each account
            for account_id, account_resources in self.resources.items():
                # Add individual region summaries
                for region, region_data in account_resources.items():
                    if region != "ALL":
                        for resource_type, items in region_data.items():
                            summary_data['Account'].append(account_id)
                            summary_data['Region'].append(region)
                            summary_data['Resource Type'].append(resource_type)
                            summary_data['Count'].append(len(items))
                            has_data = True
            
            # Always create summary sheet
            pd.DataFrame(summary_data).to_excel(writer, sheet_name='Summary', index=False)
            
            # Create detailed sheets for each resource type
            resource_types = ['Instances', 'Volumes', 'Snapshots', 'SecurityGroups', 'S3Buckets', 'RDSInstances']
            
            has_detailed_sheets = False
            for resource_type in resource_types:
                resource_data = {
                    'Account': [],
                    'Region': [],
                    'Resource': []
                }
                
                # Collect data from all accounts and regions
                for account_id, account_resources in self.resources.items():
                    for region, region_data in account_resources.items():
                        if region != "ALL" and resource_type in region_data:
                            for resource in region_data[resource_type]:
                                resource_data['Account'].append(account_id)
                                resource_data['Region'].append(region)
                                resource_data['Resource'].append(resource)
                
                # Only create sheet if we found data for this resource type
                if len(resource_data['Account']) > 0:
                    df = pd.DataFrame(resource_data)
                    sheet_name = resource_type[:31]  # Excel sheet names limited to 31 chars
                    df.to_excel(writer, sheet_name=sheet_name, index=False)
                    has_detailed_sheets = True
            
            # If no data at all, add an empty "Details" sheet
            if not has_data and not has_detailed_sheets:
                pd.DataFrame({
                    'Note': ['No resources found in any account/region']
                }).to_excel(writer, sheet_name='Details', index=False)

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
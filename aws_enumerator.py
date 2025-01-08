#!/usr/bin/env python3
"""
AWS Resource Enumerator

A GUI tool for enumerating AWS resources across multiple accounts and regions.
This tool supports AWS Organizations and provides parallel scanning capabilities
for efficient resource discovery.

Key Features:
- Multi-account scanning through AWS Organizations
- Parallel region processing using multiprocessing
- Real-time progress tracking
- Multiple export formats
- CloudTrail and CloudWatch Logs analysis
"""

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
from botocore.config import Config

# AWS API Configuration
boto_config = Config(
    retries = dict(
        max_attempts = 3,
        mode = 'standard'  # Uses exponential backoff
    )
)

def create_client_with_retries(session, service, region=None):
    """
    Create a boto3 client with retry configuration.
    
    Args:
        session (boto3.Session): AWS session to use
        service (str): AWS service name (e.g., 'ec2', 's3')
        region (str, optional): AWS region name
    
    Returns:
        boto3.client: Configured AWS client with retry handling
    """
    return session.client(service, region_name=region, config=boto_config)

def retry_with_backoff(func, max_attempts=3):
    """
    Execute a function with exponential backoff retry logic.
    
    Args:
        func (callable): Function to execute
        max_attempts (int): Maximum number of retry attempts
    
    Returns:
        Any: Result from the function
    
    Raises:
        Exception: Last error encountered after all retries
    """
    for attempt in range(max_attempts):
        try:
            return func()
        except Exception as e:
            if attempt == max_attempts - 1:
                raise
            wait_time = (2 ** attempt) * 0.5  # 0.5, 1, 2 seconds
            time.sleep(wait_time)

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
            'RDSInstances': [],
            'CloudTrails': []
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
                # Get snapshot metadata
                snapshot_info = {
                    'SnapshotId': snapshot['SnapshotId'],
                    'VolumeId': snapshot.get('VolumeId', 'Unknown Volume'),
                    'StartTime': snapshot['StartTime'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Size': snapshot['VolumeSize'],
                    'Encrypted': snapshot['Encrypted'],
                    'State': snapshot['State'],
                    'Description': snapshot.get('Description', 'No description'),
                    'InstanceId': None,
                    'InstanceName': None
                }

                # Try to get instance information from description or volume
                instance_pattern = r'i-[a-f0-9]{8,17}'
                if snapshot.get('Description'):
                    instance_match = re.search(instance_pattern, snapshot['Description'])
                    if instance_match:
                        instance_id = instance_match.group(0)
                        snapshot_info['InstanceId'] = instance_id
                        snapshot_info['InstanceName'] = instance_map.get(instance_id, instance_id)

                # Format the snapshot information
                formatted_snapshot = (
                    f"{snapshot_info['SnapshotId']}:\n"
                    f"    Size: {snapshot_info['Size']} GiB\n"
                    f"    Created: {snapshot_info['StartTime']}\n"
                    f"    Volume: {snapshot_info['VolumeId']}\n"
                    f"    State: {snapshot_info['State']}\n"
                    f"    Encrypted: {snapshot_info['Encrypted']}\n"
                )

                if snapshot_info['InstanceId']:
                    formatted_snapshot += f"    Instance: {snapshot_info['InstanceName']} ({snapshot_info['InstanceId']})\n"
                if snapshot_info['Description']:
                    formatted_snapshot += f"    Description: {snapshot_info['Description']}\n"

                region_data['Snapshots'].append(formatted_snapshot)

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

        # CloudTrail Resources
        try:
            if progress_dialog:
                progress_dialog.update_status(f"Checking CloudTrail in {region}...", 
                                           int(current_progress), 90)

            def get_cloudtrails():
                trails = get_cloudtrail_info(session, region)
                region_data['CloudTrails'].extend(trails)

            retry_with_backoff(get_cloudtrails)

        except Exception as e:
            if progress_dialog:
                progress_dialog.update_status(f"Error scanning CloudTrail in {region}: {str(e)}", 
                                           100, 100)

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

def get_cloudtrail_info(session, region):
    """
    Retrieve CloudTrail configuration for a region, including organization trails.
    
    Args:
        session (boto3.Session): AWS session
        region (str): AWS region name
    
    Returns:
        list: List of dictionaries containing trail configurations:
            - Name: Trail name
            - S3BucketName: Log destination bucket
            - IsMultiRegionTrail: Whether trail logs multiple regions
            - HomeRegion: Trail's home region
            - IsLogging: Current logging status
            - IsOrganizationTrail: Whether trail applies to entire organization
            - TrailARN: Trail's ARN
    """
    try:
        cloudtrail = create_client_with_retries(session, 'cloudtrail', region)
        trails = cloudtrail.describe_trails(includeShadowTrails=False)
        trail_info = []
        
        for trail in trails['trailList']:
            # Get active/inactive status
            status = cloudtrail.get_trail_status(Name=trail['TrailARN'])
            
            # Get organization trail settings
            trail_config = cloudtrail.get_trail(Name=trail['TrailARN'])
            
            trail_info.append({
                'Name': trail['Name'],
                'S3BucketName': trail['S3BucketName'],
                'IsMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
                'HomeRegion': trail.get('HomeRegion', region),
                'IsLogging': status.get('IsLogging', False),
                'IsOrganizationTrail': trail.get('IsOrganizationTrail', False),
                'TrailARN': trail['TrailARN']
            })
        
        return trail_info
    except Exception as e:
        print(f"Error getting CloudTrail info in {region}: {str(e)}")
        return []

def get_cloudwatch_logs_info(session, region):
    """Get CloudWatch Logs configuration for a region"""
    try:
        logs = create_client_with_retries(session, 'logs', region)
        log_groups = []
        paginator = logs.get_paginator('describe_log_groups')
        
        for page in paginator.paginate():
            for group in page['logGroups']:
                log_groups.append({
                    'Name': group['logGroupName'],
                    'StoredBytes': group.get('storedBytes', 0),
                    'RetentionDays': group.get('retentionInDays', 'Never Expires'),
                    'CreatedTimestamp': group.get('creationTime', 0)
                })
        
        return log_groups
    except Exception as e:
        print(f"Error getting CloudWatch Logs info in {region}: {str(e)}")
        return []

def get_lightsail_resources(session, region):
    """
    Get Lightsail resources in a region.
    
    Args:
        session (boto3.Session): AWS session
        region (str): AWS region name
    
    Returns:
        dict: Dictionary containing Lightsail resources:
            - Instances: List of instance details
            - Databases: List of database details
            - LoadBalancers: List of load balancer details
    """
    try:
        lightsail = create_client_with_retries(session, 'lightsail', region)
        resources = {
            'Instances': [],
            'Databases': [],
            'LoadBalancers': []
        }
        
        # Get Lightsail instances
        paginator = lightsail.get_paginator('get_instances')
        for page in paginator.paginate():
            for instance in page['instances']:
                resources['Instances'].append({
                    'Name': instance['name'],
                    'State': instance['state']['name'],
                    'Type': instance['bundleId'],
                    'IP': instance.get('publicIpAddress', 'No public IP')
                })
        
        # Get Lightsail databases
        paginator = lightsail.get_paginator('get_relational_databases')
        for page in paginator.paginate():
            for db in page['relationalDatabases']:
                resources['Databases'].append({
                    'Name': db['name'],
                    'Engine': f"{db['engine']} {db.get('engineVersion', '')}",
                    'State': db['state'],
                    'Type': db['masterDatabaseName']
                })
        
        # Get Lightsail load balancers
        try:
            lbs = lightsail.get_load_balancers()
            for lb in lbs['loadBalancers']:
                resources['LoadBalancers'].append({
                    'Name': lb['name'],
                    'State': lb['state'],
                    'Protocol': lb['protocol'],
                    'InstanceCount': len(lb.get('instanceHealthSummary', []))
                })
        except ClientError:
            pass  # Some regions might not support load balancers
            
        return resources
    except Exception as e:
        print(f"Error getting Lightsail resources in {region}: {str(e)}")
        return {'Instances': [], 'Databases': [], 'LoadBalancers': []}

def scan_region(credentials, region, progress_pipe=None):
    """Scan a single region for resources"""
    try:
        if progress_pipe:
            progress_pipe.send(("status", "Initializing region scan", 0))

        # Create session with retries
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

        region_data = {
            'Instances': [],
            'Volumes': [],
            'Snapshots': [],
            'SecurityGroups': [],
            'S3Buckets': [],
            'RDSInstances': [],
            'CloudTrails': [],
            'CloudWatchLogs': [],
            'LightsailInstances': [],
            'LightsailDatabases': [],
            'LightsailLoadBalancers': [],
            'VPCFlowLogs': []
        }

        # EC2 Resources
        try:
            progress_pipe.send(("status", f"Scanning EC2 resources in {region}", 20))
            ec2 = create_client_with_retries(session, 'ec2', region)
            
            # Get instance information first to map volume attachments
            instance_map = {}
            instances_data = ec2.describe_instances()
            for reservation in instances_data['Reservations']:
                for instance in reservation['Instances']:
                    instance_id = instance['InstanceId']
                    instance_name = next((tag['Value'] for tag in instance.get('Tags', []) 
                                       if tag['Key'] == 'Name'), 'Unnamed')
                    instance_map[instance_id] = instance_name

            # Enhanced volume information
            volumes_data = ec2.describe_volumes()
            for volume in volumes_data['Volumes']:
                # Get volume metadata
                volume_info = {
                    'VolumeId': volume['VolumeId'],
                    'Size': volume['Size'],
                    'Type': volume['VolumeType'],
                    'State': volume['State'],
                    'Encrypted': volume['Encrypted'],
                    'IOPS': volume.get('Iops', 'N/A'),
                    'Throughput': volume.get('Throughput', 'N/A'),
                    'AttachedTo': []
                }

                # Get attachment information
                for attachment in volume.get('Attachments', []):
                    instance_id = attachment['InstanceId']
                    instance_name = instance_map.get(instance_id, instance_id)
                    device = attachment['Device']
                    volume_info['AttachedTo'].append(f"{instance_name} ({instance_id}) - {device}")

                # Format the volume information
                formatted_volume = (
                    f"{volume_info['VolumeId']}:\n"
                    f"    Size: {volume_info['Size']} GiB\n"
                    f"    Type: {volume_info['Type']}\n"
                    f"    State: {volume_info['State']}\n"
                    f"    Encrypted: {volume_info['Encrypted']}\n"
                    f"    IOPS: {volume_info['IOPS']}\n"
                    f"    Throughput: {volume_info['Throughput']} MB/s\n"
                )

                if volume_info['AttachedTo']:
                    formatted_volume += "    Attached to:\n"
                    for attachment in volume_info['AttachedTo']:
                        formatted_volume += f"      - {attachment}\n"
                else:
                    formatted_volume += "    Not attached to any instance\n"

                region_data['Volumes'].append(formatted_volume)

            # Enhanced instance information
            instances_data = ec2.describe_instances()
            for reservation in instances_data['Reservations']:
                for instance in reservation['Instances']:
                    instance_info = {
                        'InstanceId': instance['InstanceId'],
                        'Type': instance['InstanceType'],
                        'State': instance['State']['Name'],
                        'PrivateIP': instance.get('PrivateIpAddress', 'No private IP'),
                        'PublicIP': instance.get('PublicIpAddress', 'No public IP'),
                        'KeyName': instance.get('KeyName', 'No key pair'),
                        'Platform': instance.get('Platform', 'Linux/UNIX'),
                        'VpcId': instance.get('VpcId', 'No VPC'),
                        'SubnetId': instance.get('SubnetId', 'No subnet'),
                        'LaunchTime': instance['LaunchTime'].strftime('%Y-%m-%d %H:%M:%S'),
                        'Name': next((tag['Value'] for tag in instance.get('Tags', []) 
                                   if tag['Key'] == 'Name'), 'Unnamed')
                    }
                    formatted_instance = (
                        f"{instance_info['Name']} ({instance_info['InstanceId']}):\n"
                        f"    Type: {instance_info['Type']}\n"
                        f"    State: {instance_info['State']}\n"
                        f"    Private IP: {instance_info['PrivateIP']}\n"
                        f"    Public IP: {instance_info['PublicIP']}\n"
                        f"    Key Pair: {instance_info['KeyName']}\n"
                        f"    Platform: {instance_info['Platform']}\n"
                        f"    VPC: {instance_info['VpcId']}\n"
                        f"    Subnet: {instance_info['SubnetId']}\n"
                        f"    Launched: {instance_info['LaunchTime']}"
                    )
                    region_data['Instances'].append(formatted_instance)

            # Snapshots
            snapshots_data = ec2.describe_snapshots(OwnerIds=['self'])
            for snapshot in snapshots_data['Snapshots']:
                # Get snapshot metadata
                snapshot_info = {
                    'SnapshotId': snapshot['SnapshotId'],
                    'VolumeId': snapshot.get('VolumeId', 'Unknown Volume'),
                    'StartTime': snapshot['StartTime'].strftime('%Y-%m-%d %H:%M:%S'),
                    'Size': snapshot['VolumeSize'],
                    'Encrypted': snapshot['Encrypted'],
                    'State': snapshot['State'],
                    'Description': snapshot.get('Description', 'No description'),
                    'InstanceId': None,
                    'InstanceName': None
                }

                # Try to get instance information from description or volume
                instance_pattern = r'i-[a-f0-9]{8,17}'
                if snapshot.get('Description'):
                    instance_match = re.search(instance_pattern, snapshot['Description'])
                    if instance_match:
                        instance_id = instance_match.group(0)
                        snapshot_info['InstanceId'] = instance_id
                        snapshot_info['InstanceName'] = instance_map.get(instance_id, instance_id)

                # Format the snapshot information
                formatted_snapshot = (
                    f"{snapshot_info['SnapshotId']}:\n"
                    f"    Size: {snapshot_info['Size']} GiB\n"
                    f"    Created: {snapshot_info['StartTime']}\n"
                    f"    Volume: {snapshot_info['VolumeId']}\n"
                    f"    State: {snapshot_info['State']}\n"
                    f"    Encrypted: {snapshot_info['Encrypted']}\n"
                )

                if snapshot_info['InstanceId']:
                    formatted_snapshot += f"    Instance: {snapshot_info['InstanceName']} ({snapshot_info['InstanceId']})\n"
                if snapshot_info['Description']:
                    formatted_snapshot += f"    Description: {snapshot_info['Description']}\n"

                region_data['Snapshots'].append(formatted_snapshot)

            # Security Groups
            sgs_data = ec2.describe_security_groups()
            for sg in sgs_data['SecurityGroups']:
                region_data['SecurityGroups'].append(f"{sg['GroupName']} ({sg['GroupId']})")

        except Exception as e:
            progress_pipe.send(("error", f"EC2 scan failed in {region}: {str(e)}"))

        # S3 Resources
        try:
            progress_pipe.send(("status", f"Scanning S3 resources in {region}", 40))
            s3 = create_client_with_retries(session, 's3')
            buckets_data = s3.list_buckets()
            for bucket in buckets_data['Buckets']:
                try:
                    bucket_region = s3.get_bucket_location(Bucket=bucket['Name'])['LocationConstraint']
                    if bucket_region == region or (bucket_region is None and region == 'us-east-1'):
                        region_data['S3Buckets'].append(bucket['Name'])
                except Exception as e:
                    if progress_pipe:
                        progress_pipe.send(("error", f"Error checking bucket {bucket['Name']}: {str(e)}"))

        except Exception as e:
            progress_pipe.send(("error", f"S3 scan failed in {region}: {str(e)}"))

        # RDS Resources
        try:
            progress_pipe.send(("status", f"Scanning RDS resources in {region}", 60))
            rds = create_client_with_retries(session, 'rds', region)
            rds_data = rds.describe_db_instances()
            for db_instance in rds_data['DBInstances']:
                region_data['RDSInstances'].append(
                    f"{db_instance['DBInstanceIdentifier']} (Status: {db_instance['DBInstanceStatus']})"
                )

        except Exception as e:
            progress_pipe.send(("error", f"RDS scan failed in {region}: {str(e)}"))

        # CloudTrail Resources
        try:
            progress_pipe.send(("status", f"Scanning CloudTrail in {region}", 80))
            def get_cloudtrails():
                trails = get_cloudtrail_info(session, region)
                region_data['CloudTrails'].extend(trails)

            retry_with_backoff(get_cloudtrails)

        except Exception as e:
            progress_pipe.send(("error", f"CloudTrail scan failed in {region}: {str(e)}"))

        # CloudWatch Logs Resources
        try:
            progress_pipe.send(("status", f"Scanning CloudWatch Logs in {region}", 90))
            logs = get_cloudwatch_logs_info(session, region)
            region_data['CloudWatchLogs'].extend(logs)

        except Exception as e:
            progress_pipe.send(("error", f"CloudWatch Logs scan failed in {region}: {str(e)}"))

        # Lightsail Resources
        try:
            progress_pipe.send(("status", f"Scanning Lightsail in {region}", 95))
            lightsail_resources = get_lightsail_resources(session, region)
            region_data['LightsailInstances'].extend(
                f"{instance['Name']} ({instance['Type']}) - {instance['State']}"
                for instance in lightsail_resources['Instances']
            )
            region_data['LightsailDatabases'].extend(
                f"{db['Name']} ({db['Engine']}) - {db['State']}"
                for db in lightsail_resources['Databases']
            )
            region_data['LightsailLoadBalancers'].extend(
                f"{lb['Name']} ({lb['Protocol']}) - {lb['InstanceCount']} instances"
                for lb in lightsail_resources['LoadBalancers']
            )

        except Exception as e:
            progress_pipe.send(("error", f"Lightsail scan failed in {region}: {str(e)}"))

        # VPC Flow Logs
        try:
            progress_pipe.send(("status", f"Scanning VPC Flow Logs in {region}", 97))
            flow_logs = get_vpc_flow_logs_info(session, region)
            region_data['VPCFlowLogs'].extend(flow_logs)

        except Exception as e:
            progress_pipe.send(("error", f"VPC Flow Logs scan failed in {region}: {str(e)}"))

        progress_pipe.send(("status", f"Completed scanning {region}", 100))
        return region, region_data

    except Exception as e:
        progress_pipe.send(("error", f"Region scan failed: {str(e)}"))
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
                    pool.apply_async(scan_region, (creds, region, pipe_send)))

            # Monitor progress with timeout
            completed_regions = 0
            total_regions = len(regions)
            results = []

            while completed_regions < total_regions:
                # Update account progress based on completed regions
                if progress_callback:
                    account_message = f"Scanning regions: {completed_regions}/{total_regions} completed"
                    account_progress = (completed_regions / total_regions) * 100
                    progress_callback(account_message, account_progress, None, None)

                # Check pipes with timeout
                for pipe_send, pipe_recv in pipes:
                    if pipe_recv.poll(timeout=0.1):
                        try:
                            msg_type, *msg_data = pipe_recv.recv()
                            if msg_type == "status" and progress_callback:
                                # Region-specific status goes to region progress
                                service_message, service_progress = msg_data
                                progress_callback(account_message, account_progress, service_message, service_progress)
                            elif msg_type == "error":
                                print(f"Error received: {msg_data[0]}")
                                progress_callback(account_message, account_progress, f"Error: {msg_data[0]}", 0)
                            elif msg_type == "debug":
                                print(f"Debug: {msg_data[0]}")
                        except EOFError:
                            print("Pipe closed unexpectedly")

                # Check results with timeout
                for i, result in enumerate(async_results):
                    try:
                        if result.ready():
                            if result.successful():
                                results.append(result.get(timeout=30))
                                print(f"Successfully completed region scan {len(results)}/{total_regions}")
                            else:
                                print(f"Region scan failed: {result.get(timeout=1)}")
                                results.append((f"region-{i}", {}))
                            completed_regions += 1
                    except Exception as e:
                        print(f"Error checking result: {str(e)}")
                        results.append((f"region-{i}", {}))
                        completed_regions += 1

                # Add small sleep to prevent CPU spinning
                QCoreApplication.processEvents()
                time.sleep(0.05)

            # Combine results into a single dictionary
            account_data = {}
            for region, region_data in results:
                account_data[region] = region_data

            if progress_callback:
                progress_callback("Account scan completed", 100, "Completed", 100)

            print(f"Account scan completed with {len(account_data)} regions")
            return account_data

    except Exception as e:
        print(f"Error in scan_account: {str(e)}")
        if progress_callback:
            progress_callback(f"Error: {str(e)}", 0, "Error occurred", 0)
        return {}
    finally:
        # Clean up pipes
        for pipe_send, pipe_recv in pipes:
            pipe_send.close()
            pipe_recv.close()

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

class CloudTrailTab(QtWidgets.QWidget):
    """
    Tab widget displaying CloudTrail configurations across accounts and regions.
    
    Features:
    - Shows organization-wide trails
    - Displays trail status and configuration
    - Color codes active/inactive trails
    - Groups trails by account and region
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout()
        
        # Tree widget setup with columns
        self.trail_tree = QTreeWidget()
        self.trail_tree.setHeaderLabels([
            "Account/Region",  # Account ID or region name
            "Trail Name",     # CloudTrail trail name
            "S3 Bucket",      # Destination bucket
            "Multi-Region",   # Yes/No for multi-region coverage
            "Status",         # Enabled/Disabled
            "Org Trail"       # Yes/No for organization trail
        ])
        
        # Set column widths for better visibility
        self.trail_tree.setColumnWidth(0, 200)
        self.trail_tree.setColumnWidth(1, 150)
        self.trail_tree.setColumnWidth(2, 300)
        self.trail_tree.setColumnWidth(3, 100)
        self.trail_tree.setColumnWidth(4, 100)
        self.trail_tree.setColumnWidth(5, 100)
        
        layout.addWidget(self.trail_tree)
        self.setLayout(layout)

    def _add_org_trails(self, account_item, org_trails):
        """Add organization trails to an account item"""
        for trail in org_trails:
            org_trail_item = QTreeWidgetItem(account_item)
            org_trail_item.setText(0, "Organization Trail")
            org_trail_item.setText(1, trail["Name"])
            org_trail_item.setText(2, trail["S3BucketName"])
            org_trail_item.setText(3, "Yes" if trail["IsMultiRegionTrail"] else "No")
            org_trail_item.setText(4, "Enabled" if trail["IsLogging"] else "Disabled")
            org_trail_item.setText(5, "Yes")
            # Set green background for enabled trails
            if trail["IsLogging"]:
                for i in range(6):
                    org_trail_item.setBackground(i, QtGui.QColor("#e6ffe6"))

    def _add_account_trails(self, account_item, account_data, org_trails):
        """Add account-specific trails to an account item"""
        has_trails = False
        trails_by_region = {}
        seen_trails = set()
        
        for region, region_data in account_data.items():
            if region != "ALL" and "CloudTrails" in region_data:
                for trail in region_data["CloudTrails"]:
                    trail_id = f"{trail['Name']}_{trail['HomeRegion']}"
                    if trail_id not in seen_trails:
                        home_region = trail["HomeRegion"]
                        if home_region not in trails_by_region:
                            trails_by_region[home_region] = []
                        trails_by_region[home_region].append(trail)
                        seen_trails.add(trail_id)
                        has_trails = True
        
        if not has_trails and not org_trails:
            # No trails found in this account and not covered by org trails
            no_trail_item = QTreeWidgetItem(account_item)
            no_trail_item.setText(0, "AWS STORED ONLY")
            no_trail_item.setForeground(0, QtGui.QColor("red"))
        else:
            # Add account's own trails grouped by home region
            for region, trails in sorted(trails_by_region.items()):
                region_item = QTreeWidgetItem(account_item)
                region_item.setText(0, region)
                
                for trail in trails:
                    trail_item = QTreeWidgetItem(region_item)
                    trail_item.setText(0, "")  # Region column
                    trail_item.setText(1, trail["Name"])
                    trail_item.setText(2, trail["S3BucketName"])
                    trail_item.setText(3, "Yes" if trail["IsMultiRegionTrail"] else "No")
                    trail_item.setText(4, "Enabled" if trail["IsLogging"] else "Disabled")
                    trail_item.setText(5, "Yes" if trail.get("IsOrganizationTrail") else "No")
                    # Set green background for enabled trails
                    if trail["IsLogging"]:
                        for i in range(6):
                            trail_item.setBackground(i, QtGui.QColor("#e6ffe6"))

    def update_trails(self, resources):
        """
        Update the tree with CloudTrail information from all accounts.
        
        Args:
            resources (dict): Nested dictionary of resources by account and region
        
        The function:
        1. Identifies organization-wide trails
        2. Shows org trails for member accounts
        3. Displays account-specific trails
        4. Color codes based on trail status
        """
        self.trail_tree.clear()
        
        # First pass: find organization trails
        org_trails = []
        management_account = None
        for account_id, account_data in resources.items():
            for region, region_data in account_data.items():
                if region != "ALL" and "CloudTrails" in region_data:
                    for trail in region_data["CloudTrails"]:
                        if trail.get('IsOrganizationTrail', False):
                            org_trails.append(trail)
                            management_account = account_id
                            break
                    if org_trails:
                        break
            if org_trails:
                break

        # Second pass: display trails for each account
        for account_id, account_data in resources.items():
            account_item = QTreeWidgetItem(self.trail_tree)
            account_item.setText(0, f"Account: {account_id}")
            
            if org_trails and account_id != management_account:
                # Show organization trails for member accounts
                self._add_org_trails(account_item, org_trails)
            else:
                # Show account's own trails
                self._add_account_trails(account_item, account_data, org_trails)
        
        self.trail_tree.expandAll()

class VPCFlowLogsTab(QtWidgets.QWidget):
    """
    Tab widget displaying VPC Flow Logs configurations across accounts and regions.
    
    Features:
    - Shows VPC Flow Logs status for each account
    - Displays log destinations and retention periods
    - Color codes enabled/disabled flow logs
    - Groups logs by account and region
    """
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()
    
    def _setup_ui(self):
        """Initialize the UI components"""
        layout = QVBoxLayout()
        
        # Tree widget setup with columns
        self.flow_logs_tree = QTreeWidget()
        self.flow_logs_tree.setHeaderLabels([
            "Account/Region",     # Account ID or region name
            "VPC ID",            # VPC being logged
            "Destination Path",   # Full log destination path
            "Retention",         # Retention period
            "Status"             # Active/Inactive
        ])
        
        # Set column widths for better visibility
        self.flow_logs_tree.setColumnWidth(0, 200)
        self.flow_logs_tree.setColumnWidth(1, 150)
        self.flow_logs_tree.setColumnWidth(2, 400)  # Wider for full paths
        self.flow_logs_tree.setColumnWidth(3, 100)
        self.flow_logs_tree.setColumnWidth(4, 100)
        
        layout.addWidget(self.flow_logs_tree)
        self.setLayout(layout)

    def update_flow_logs(self, resources):
        """Update the tree with VPC Flow Logs information"""
        self.flow_logs_tree.clear()
        
        for account_id, account_data in resources.items():
            account_item = QTreeWidgetItem(self.flow_logs_tree)
            account_item.setText(0, f"Account: {account_id}")
            
            has_flow_logs = False
            for region, region_data in account_data.items():
                if region != "ALL" and "VPCFlowLogs" in region_data:
                    flow_logs = region_data["VPCFlowLogs"]
                    if flow_logs:
                        has_flow_logs = True
                        region_item = QTreeWidgetItem(account_item)
                        region_item.setText(0, region)
                        
                        for flow_log in flow_logs:
                            log_item = QTreeWidgetItem(region_item)
                            log_item.setText(0, "")  # Region column
                            log_item.setText(1, flow_log['VpcId'])
                            log_item.setText(2, flow_log['LogDestination'])
                            log_item.setText(3, str(flow_log['RetentionDays']))
                            log_item.setText(4, flow_log['Status'])
                            
                            # Set green background for active flow logs
                            if flow_log['Status'] == 'ACTIVE':
                                for i in range(5):
                                    log_item.setBackground(i, QtGui.QColor("#e6ffe6"))
            
            if not has_flow_logs:
                no_logs_item = QTreeWidgetItem(account_item)
                no_logs_item.setText(0, "No VPC Flow Logs Enabled")
                no_logs_item.setForeground(0, QtGui.QColor("red"))
        
        self.flow_logs_tree.expandAll()

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AWS Enumerator Tool")
        self.resize(1000, 600)

        # Create toolbar
        self.toolbar = QToolBar()
        self.addToolBar(self.toolbar)
        
        # Add export action with new name
        export_action = self.toolbar.addAction("Export Inventory")
        export_action.triggered.connect(self.export_data)

        # Main Widget and Layout
        main_widget = QtWidgets.QWidget()
        main_layout = QtWidgets.QVBoxLayout(main_widget)
        self.setCentralWidget(main_widget)

        # Create tab widget
        self.tab_widget = QtWidgets.QTabWidget()
        main_layout.addWidget(self.tab_widget)

        # Resources Tab
        resources_widget = QtWidgets.QWidget()
        resources_layout = QtWidgets.QVBoxLayout(resources_widget)
        
        # Move existing splitter to resources tab
        self.top_splitter = QtWidgets.QSplitter()
        self.top_splitter.setOrientation(QtCore.Qt.Horizontal)
        resources_layout.addWidget(self.top_splitter)

        # Left side: account/region tree
        self.account_tree = QTreeWidget()
        self.account_tree.setHeaderLabel("Accounts & Regions")
        self.account_tree.setFixedWidth(300)
        self.top_splitter.addWidget(self.account_tree)

        # Right side: resources display
        self.resource_display = QtWidgets.QTextEdit()
        self.resource_display.setReadOnly(True)
        self.top_splitter.addWidget(self.resource_display)

        # Add Resources tab
        self.tab_widget.addTab(resources_widget, "Resources")

        # Add CloudTrail tab
        self.cloudtrail_tab = CloudTrailTab()
        self.tab_widget.addTab(self.cloudtrail_tab, "CloudTrail")

        # Add VPC Flow Logs tab
        self.vpc_flow_logs_tab = VPCFlowLogsTab()
        self.tab_widget.addTab(self.vpc_flow_logs_tab, "VPC Flow Logs")

        # Bottom log pane
        self.log_text = QtWidgets.QTextEdit()
        self.log_text.setReadOnly(True)
        main_layout.addWidget(self.log_text)

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
            def callback(message, overall_progress, region_message=None, region_progress=None):
                # Update overall progress
                progress_dialog.overall_progress.setValue(int(overall_progress))
                
                # Update account progress if region message is None (account-level update)
                if region_message is None:
                    progress_dialog.account_progress.setValue(int(overall_progress))
                    progress_dialog.status_label.setText(message)
                else:
                    # Update region progress and status for service-level updates
                    progress_dialog.region_progress.setValue(int(region_progress))
                    progress_dialog.status_label.setText(region_message)
                
                # Process events to keep UI responsive
                QCoreApplication.processEvents()
            
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

        # Update CloudTrail tab
        self.cloudtrail_tab.update_trails(self.resources)

        # Update VPC Flow Logs tab
        self.vpc_flow_logs_tab.update_flow_logs(self.resources)

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
            'RDSInstances': [],
            'CloudTrails': [],
            'CloudWatchLogs': []  # Add CloudWatch Logs
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
                if resource_type == 'CloudWatchLogs':
                    # Special formatting for CloudWatch Logs
                    for item in items:
                        size_mb = item['StoredBytes'] / (1024 * 1024)  # Convert to MB
                        lines.append(f"  - {item['Name']}")
                        lines.append(f"    Size: {size_mb:.2f} MB")
                        lines.append(f"    Retention: {item['RetentionDays']} days")
                else:
                    # Standard formatting for other resources
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
            resource_types = [
                'Instances', 'Volumes', 'Snapshots', 'SecurityGroups', 
                'S3Buckets', 'RDSInstances', 'CloudWatchLogs',
                'LightsailInstances', 'LightsailDatabases', 'LightsailLoadBalancers'
            ]
            
            has_detailed_sheets = False
            for resource_type in resource_types:
                if resource_type == 'Instances':
                    # Special handling for EC2 instances
                    resource_data = {
                        'Account': [],
                        'Region': [],
                        'Name': [],
                        'Instance ID': [],
                        'Type': [],
                        'State': [],
                        'Private IP': [],
                        'Public IP': [],
                        'Key Pair': [],
                        'Platform': [],
                        'VPC': [],
                        'Subnet': [],
                        'Launch Time': []
                    }
                    
                    for account_id, account_resources in self.resources.items():
                        for region, region_data in account_resources.items():
                            if region != "ALL" and resource_type in region_data:
                                for instance_text in region_data[resource_type]:
                                    # Parse the formatted instance text
                                    lines = instance_text.split('\n')
                                    name_id = lines[0].split(' (')
                                    name = name_id[0]
                                    instance_id = name_id[1].rstrip('):')
                                    
                                    # Extract other fields
                                    fields = {}
                                    for line in lines[1:]:
                                        if ':' in line:
                                            key, value = line.strip().split(': ', 1)
                                            fields[key.strip()] = value
                                    
                                    resource_data['Account'].append(account_id)
                                    resource_data['Region'].append(region)
                                    resource_data['Name'].append(name)
                                    resource_data['Instance ID'].append(instance_id)
                                    resource_data['Type'].append(fields.get('Type', ''))
                                    resource_data['State'].append(fields.get('State', ''))
                                    resource_data['Private IP'].append(fields.get('Private IP', ''))
                                    resource_data['Public IP'].append(fields.get('Public IP', ''))
                                    resource_data['Key Pair'].append(fields.get('Key Pair', ''))
                                    resource_data['Platform'].append(fields.get('Platform', ''))
                                    resource_data['VPC'].append(fields.get('VPC', ''))
                                    resource_data['Subnet'].append(fields.get('Subnet', ''))
                                    resource_data['Launch Time'].append(fields.get('Launched', ''))
                    
                    if len(resource_data['Account']) > 0:
                        df = pd.DataFrame(resource_data)
                        df.to_excel(writer, sheet_name='EC2 Instances', index=False)
                        has_detailed_sheets = True
                
                elif resource_type == 'Volumes':
                    # Special handling for EBS volumes
                    resource_data = {
                        'Account': [],
                        'Region': [],
                        'Volume ID': [],
                        'Size (GiB)': [],
                        'Type': [],
                        'State': [],
                        'Encrypted': [],
                        'IOPS': [],
                        'Throughput': [],
                        'Attachments': []
                    }
                    
                    for account_id, account_resources in self.resources.items():
                        for region, region_data in account_resources.items():
                            if region != "ALL" and resource_type in region_data:
                                for volume_text in region_data[resource_type]:
                                    # Parse the formatted volume text
                                    lines = volume_text.split('\n')
                                    volume_id = lines[0].rstrip(':')
                                    
                                    # Extract fields
                                    fields = {}
                                    attachments = []
                                    in_attachments = False
                                    
                                    for line in lines[1:]:
                                        line = line.strip()
                                        if line.startswith('Attached to:'):
                                            in_attachments = True
                                            continue
                                        if in_attachments:
                                            if line.startswith('-'):
                                                attachments.append(line[2:])
                                        elif ':' in line:
                                            key, value = line.split(': ', 1)
                                            fields[key.strip()] = value
                                    
                                    resource_data['Account'].append(account_id)
                                    resource_data['Region'].append(region)
                                    resource_data['Volume ID'].append(volume_id)
                                    resource_data['Size (GiB)'].append(fields.get('Size', '').split()[0])
                                    resource_data['Type'].append(fields.get('Type', ''))
                                    resource_data['State'].append(fields.get('State', ''))
                                    resource_data['Encrypted'].append(fields.get('Encrypted', ''))
                                    resource_data['IOPS'].append(fields.get('IOPS', ''))
                                    resource_data['Throughput'].append(fields.get('Throughput', '').split()[0])
                                    resource_data['Attachments'].append('\n'.join(attachments) if attachments else 'Not attached')
                    
                    if len(resource_data['Account']) > 0:
                        df = pd.DataFrame(resource_data)
                        df.to_excel(writer, sheet_name='EBS Volumes', index=False)
                        has_detailed_sheets = True
                
                elif resource_type == 'Snapshots':
                    # Special handling for EC2 snapshots
                    resource_data = {
                        'Account': [],
                        'Region': [],
                        'Snapshot ID': [],
                        'Size (GiB)': [],
                        'Created': [],
                        'Volume ID': [],
                        'State': [],
                        'Encrypted': [],
                        'Instance': [],
                        'Description': []
                    }
                    
                    for account_id, account_resources in self.resources.items():
                        for region, region_data in account_resources.items():
                            if region != "ALL" and resource_type in region_data:
                                for snapshot_text in region_data[resource_type]:
                                    # Parse the formatted snapshot text
                                    lines = snapshot_text.split('\n')
                                    snapshot_id = lines[0].rstrip(':')
                                    
                                    # Extract fields
                                    fields = {}
                                    for line in lines[1:]:
                                        if ':' in line:
                                            key, value = line.strip().split(': ', 1)
                                            fields[key.strip()] = value
                                    
                                    resource_data['Account'].append(account_id)
                                    resource_data['Region'].append(region)
                                    resource_data['Snapshot ID'].append(snapshot_id)
                                    resource_data['Size (GiB)'].append(fields.get('Size', '').split()[0])
                                    resource_data['Created'].append(fields.get('Created', ''))
                                    resource_data['Volume ID'].append(fields.get('Volume', ''))
                                    resource_data['State'].append(fields.get('State', ''))
                                    resource_data['Encrypted'].append(fields.get('Encrypted', ''))
                                    resource_data['Instance'].append(fields.get('Instance', 'N/A'))
                                    resource_data['Description'].append(fields.get('Description', ''))
                    
                    if len(resource_data['Account']) > 0:
                        df = pd.DataFrame(resource_data)
                        df.to_excel(writer, sheet_name='EC2 Snapshots', index=False)
                        has_detailed_sheets = True
                
                else:
                    # Standard handling for other resources
                    resource_data = {
                        'Account': [],
                        'Region': [],
                        'Resource': []
                    }

                    for account_id, account_resources in self.resources.items():
                        for region, region_data in account_resources.items():
                            if region != "ALL" and resource_type in region_data:
                                for resource in region_data[resource_type]:
                                    resource_data['Account'].append(account_id)
                                    resource_data['Region'].append(region)
                                    resource_data['Resource'].append(resource)

                    # Create sheet if we have data
                    if len(resource_data['Account']) > 0:
                        df = pd.DataFrame(resource_data)
                        sheet_name = resource_type[:31]
                        df.to_excel(writer, sheet_name=sheet_name, index=False)
                        has_detailed_sheets = True
            
            # If no data at all, add an empty "Details" sheet
            if not has_data and not has_detailed_sheets:
                pd.DataFrame({
                    'Note': ['No resources found in any account/region']
                }).to_excel(writer, sheet_name='Details', index=False)

def get_vpc_flow_logs_info(session, region):
    """
    Get VPC Flow Logs configuration for a region.
    
    Args:
        session (boto3.Session): AWS session
        region (str): AWS region name
    
    Returns:
        list: List of dictionaries containing flow log configurations:
            - FlowLogId: Flow log identifier
            - VpcId: VPC being logged
            - LogDestination: Full path to log destination (S3 bucket/prefix or CloudWatch log group)
            - LogFormat: Flow log format
            - RetentionDays: Log retention period (for CloudWatch)
            - Status: Active/Inactive status
    """
    try:
        ec2 = create_client_with_retries(session, 'ec2', region)
        logs = create_client_with_retries(session, 'logs', region)
        flow_logs = []
        
        # Get all VPC Flow Logs in the region
        paginator = ec2.get_paginator('describe_flow_logs')
        for page in paginator.paginate():
            for flow_log in page['FlowLogs']:
                log_info = {
                    'FlowLogId': flow_log['FlowLogId'],
                    'VpcId': flow_log.get('ResourceId', 'N/A'),
                    'LogFormat': flow_log.get('LogFormat', 'Default'),
                    'Status': flow_log['FlowLogStatus'],
                    'RetentionDays': 'N/A'
                }
                
                # Get detailed destination information
                if flow_log.get('LogDestinationType') == 'cloud-watch-logs':
                    log_group = flow_log.get('LogGroupName', 'Unknown')
                    log_info['LogDestination'] = f"CloudWatch Logs: {log_group}"
                    
                    try:
                        if log_group != 'Unknown':
                            response = logs.describe_log_groups(logGroupNamePrefix=log_group)
                            if response['logGroups']:
                                retention = response['logGroups'][0].get('retentionInDays')
                                log_info['RetentionDays'] = retention if retention else 'Never Expires'
                    except Exception as e:
                        print(f"Error getting log group info: {str(e)}")
                
                elif flow_log.get('LogDestinationType') == 's3':
                    bucket = flow_log.get('LogDestinationValue', '')
                    if bucket:
                        # Parse S3 ARN to get bucket and prefix
                        # Format: arn:aws:s3:::bucket-name/optional/prefix/
                        try:
                            parts = bucket.split(':', 5)
                            bucket_path = parts[5]
                            bucket_name = bucket_path.split('/')[0]
                            prefix = '/'.join(bucket_path.split('/')[1:])
                            prefix = prefix if prefix else '(root)'
                            log_info['LogDestination'] = f"S3: {bucket_name}/{prefix}"
                        except Exception:
                            log_info['LogDestination'] = f"S3: {bucket}"
                    else:
                        log_info['LogDestination'] = "S3: Unknown bucket"
                
                else:
                    log_info['LogDestination'] = flow_log.get('LogDestinationType', 'Unknown')
                
                flow_logs.append(log_info)
        
        return flow_logs
    except Exception as e:
        print(f"Error getting VPC Flow Logs info in {region}: {str(e)}")
        return []

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
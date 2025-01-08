# AWS Resource Enumerator

A Python-based GUI tool for enumerating and analyzing AWS resources across multiple accounts and regions. This tool helps security professionals, incident responders, and cloud administrators quickly gather and analyze AWS resource information across an entire AWS Organization.

## Features

- Enumerate AWS resources across all regions
- Support for AWS Organizations:
  - Automatic discovery of member accounts
  - Role assumption for cross-account access
  - Parallel scanning of multiple accounts
- Support for multiple resource types:
  - EC2 Instances:
    - Instance type and state
    - Private and public IP addresses
    - SSH key names
    - Platform details
    - VPC and subnet information
    - Launch time
  - EBS Volumes:
    - Volume size and type
    - Encryption status
    - IOPS and throughput
    - Attachment information
  - EC2 Snapshots:
    - Size and creation date
    - Source volume and instance
    - Encryption status
    - Description and state
  - Security Groups
  - S3 Buckets
  - RDS Instances
  - CloudWatch Logs:
    - Log group names
    - Storage size
    - Retention periods
  - CloudTrail:
    - Organization-wide trail detection
    - Trail status and configuration
    - S3 bucket destinations
  - VPC Flow Logs:
    - Destination paths (S3/CloudWatch)
    - Retention periods
    - Status and configuration
  - Lightsail:
    - Instances
    - Databases
    - Load Balancers
- Real-time progress tracking:
  - Overall account progress
  - Current account progress
  - Region-specific progress
- Multiple authentication methods:
  - AWS Profile
  - Direct API Key input
- Export capabilities:
  - Text format (as displayed)
  - JSON format
  - Excel spreadsheet (with summary and detailed sheets)
- Multi-processing support:
  - Parallel region scanning
  - Concurrent account processing
  - Progress tracking across all operations
- Enhanced data visualization:
  - Color-coded status indicators
  - Hierarchical resource views
  - Detailed metadata display

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aws-resource-enumerator.git
cd aws-resource-enumerator
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows, use: .venv\Scripts\activate
```

3. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python aws_enumerator.py
```

2. Select your authentication method:
   - **AWS Profile**: Choose an existing profile from your AWS credentials file
   - **API Key**: Enter your AWS Access Key ID and Secret Access Key

3. Wait for the enumeration to complete:
   - Progress bars show scanning status
   - Log window displays detailed information
   - Resource tree updates as data is collected

4. Browse resources:
   - By account
   - By region
   - View resource counts and details
   - Inspect detailed metadata

5. Export results using the Export Inventory button in the toolbar:
   - Text: Human-readable format
   - JSON: Structured data format
   - Excel: Spreadsheet with summary and detailed sheets

## AWS Credentials

The tool supports two methods of AWS authentication:

1. **AWS Profile**: Uses profiles from your `~/.aws/credentials` file
2. **Direct API Keys**: Allows input of Access Key ID and Secret Access Key
   - Option to save credentials as a new profile

For AWS Organizations support, ensure your credentials have appropriate permissions to:
- List organization accounts
- Assume roles in member accounts

## Required Permissions

The AWS credentials used should have the following permissions:
- `organizations:ListAccounts`
- `sts:AssumeRole`
- `ec2:DescribeInstances`
- `ec2:DescribeVolumes`
- `ec2:DescribeSnapshots`
- `ec2:DescribeSecurityGroups`
- `ec2:DescribeFlowLogs`
- `s3:ListBuckets`
- `s3:GetBucketLocation`
- `rds:DescribeDBInstances`
- `logs:DescribeLogGroups`
- `cloudtrail:DescribeTrails`
- `cloudtrail:GetTrailStatus`
- `cloudtrail:GetTrail`
- `sts:GetCallerIdentity`
- `lightsail:GetInstances`
- `lightsail:GetRelationalDatabases`
- `lightsail:GetLoadBalancers`

For scanning organization member accounts, the OrganizationAccountAccessRole (or equivalent) must be present in member accounts.

## Performance

The tool uses Python's multiprocessing to scan regions and accounts in parallel:
- Number of parallel processes is based on CPU cores
- Progress tracking across all parallel operations
- Memory-efficient resource collection
- Automatic retry with exponential backoff for API calls

## License

Copyright 2024

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


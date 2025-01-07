# AWS Resource Enumerator

A Python-based GUI tool for enumerating and analyzing AWS resources across all regions in an AWS account. This tool helps security professionals, incident responders, and cloud administrators quickly gather and analyze AWS resource information.

## Features

- Enumerate AWS resources across all regions
- Support for multiple resource types:
  - EC2 Instances
  - EBS Volumes
  - EC2 Snapshots
  - Security Groups
  - S3 Buckets
  - RDS Instances
- Real-time progress tracking
- Multiple authentication methods:
  - AWS Profile
  - Direct API Key input
- Export capabilities:
  - Text format (as displayed)
  - JSON format
  - Excel spreadsheet (with summary)

## Installation

1. Clone the repository:
```bash
ne https://github.com/yourusername/aws-resource-enumerator.git
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

3. Wait for the enumeration to complete (progress will be displayed)

4. Browse resources by region in the left panel

5. Export results using the Export button in the toolbar:
   - Text: Human-readable format
   - JSON: Structured data format
   - Excel: Spreadsheet with summary and detailed sheets

## AWS Credentials

The tool supports two methods of AWS authentication:

1. **AWS Profile**: Uses profiles from your `~/.aws/credentials` file
2. **Direct API Keys**: Allows input of Access Key ID and Secret Access Key
   - Option to save credentials as a new profile

Ensure your AWS credentials have appropriate permissions to list resources in your account.

## Required Permissions

The AWS credentials used should have the following permissions:
- `ec2:DescribeInstances`
- `ec2:DescribeVolumes`
- `ec2:DescribeSnapshots`
- `ec2:DescribeSecurityGroups`
- `s3:ListBuckets`
- `s3:GetBucketLocation`
- `rds:DescribeDBInstances`
- `sts:GetCallerIdentity`

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


# NetSuite to Aliyun IP Sync

Automated tool to synchronize NetSuite outbound IP addresses with an Aliyun ECS Security Group.

## Description

NetSuite's outbound IP addresses can change periodically. This script ensures that your Aliyun instances remain accessible to NetSuite services by dynamically updating Security Group ingress rules (specifically for SSH/Port 22).

## Features

- **Multi-Group Support**: Syncs multiple security groups across different regions (e.g., Shanghai and Hong Kong) in a single run.
- **Cross-Platform DNS Discovery**: Uses standard Python `socket` library to resolve `outboundips.netsuite.com`.
- **Intelligent Diffing**: Only adds new IPs and removes stale ones to minimize API calls and rule changes.
- **Dry-Run Mode**: Safely preview changes before applying them.
- **Aliyun SDK Integration**: Uses the official `alibabacloud-ecs20140526` Python SDK.

## Prerequisites

- Python 3.6+
- Aliyun Access Key ID and Secret with `AliyunECSFullAccess` (or specific Security Group permissions).

## Installation

1. Clone or download this repository.
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration

### Default Security Groups
By default, the script updates two security groups:
1. **Shanghai Default**: `sg-uf67dcdf6rhingo4wsnc` in `cn-shanghai` (Port 22).
2. **Hong Kong Custom**: `sg-j6chr1b73i3yyg3hf3gm` in `cn-hongkong` (Port 2222).

### Environment Variables
Set your Aliyun credentials:
```bash
export ALIBABA_CLOUD_ACCESS_KEY_ID='your_access_key_id'
export ALIBABA_CLOUD_ACCESS_KEY_SECRET='your_access_key_secret'
```

## Usage

### Basic Usage
Run the script to sync all default security groups:
```bash
python3 sync_ips.py
```

### Options
```bash
python3 sync_ips.py --help
# usage: sync_ips.py [-h] [--dry-run] [--sg-id SG_ID] [--region REGION] [--port PORT]

# options:
#   -h, --help       show this help message and exit
#   --dry-run        Perform a dry run without making changes.
#   --sg-id SG_ID    Aliyun Security Group ID (overrides defaults)
#   --region REGION  Aliyun Region ID (used with --sg-id)
#   --port PORT      Port to open (used with --sg-id)
```

## Automation (Cron)

To keep the security group updated, schedule the script to run via cron:

```bash
0 * * * * export ALIBABA_CLOUD_ACCESS_KEY_ID='...' && export ALIBABA_CLOUD_ACCESS_KEY_SECRET='...' && /usr/bin/python3 /absolute/path/to/sync_ips.py >> /absolute/path/to/sync.log 2>&1
```

## License

MIT

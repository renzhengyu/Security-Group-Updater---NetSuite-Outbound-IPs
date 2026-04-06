"""
NetSuite to Aliyun Security Group Sync Tool
Author: Antigravity AI
Description: Automatically updates Aliyun Security Group ingress rules based on
             NetSuite's outbound IP list (outboundips.netsuite.com).
"""

import os
import socket
import argparse
import sys
from alibabacloud_ecs20140526.client import Client as Ecs20140526Client
from alibabacloud_tea_openapi import models as open_api_models
from alibabacloud_ecs20140526 import models as ecs_20140526_models


class AliyunSync:
    """Handles communication with Aliyun ECS API for security group management."""

    def __init__(self, region_id, access_key_id, access_key_secret, security_group_id, dry_run=False):
        """
        Initialize the Aliyun ECS client.
        
        Args:
            region_id (str): Aliyun region (e.g., 'cn-shanghai').
            access_key_id (str): Aliyun Access Key ID.
            access_key_secret (str): Aliyun Access Key Secret.
            security_group_id (str): Target security group ID.
            dry_run (bool): If True, no changes will be applied to Aliyun.
        """
        self.region_id = region_id
        self.security_group_id = security_group_id
        self.dry_run = dry_run
        
        config = open_api_models.Config(
            access_key_id=access_key_id,
            access_key_secret=access_key_secret
        )
        # Endpoint convention: ecs.<region_id>.aliyuncs.com
        config.endpoint = f'ecs.{region_id}.aliyuncs.com'
        self.client = Ecs20140526Client(config)

    def get_current_rules(self, port):
        """
        Fetch current ingress rules for the security group on the specified port.
        
        Args:
            port (int): The port to check (e.g., 22).
            
        Returns:
            set: A set of source CIDR strings (e.g., {'1.2.3.4/32'}).
        """
        request = ecs_20140526_models.DescribeSecurityGroupAttributeRequest(
            region_id=self.region_id,
            security_group_id=self.security_group_id,
            direction='ingress'
        )
        response = self.client.describe_security_group_attribute(request)
        
        rules = []
        if response.body.permissions and response.body.permissions.permission:
            for rule in response.body.permissions.permission:
                # Filter for SSH (or specified port) and TCP protocol
                if rule.port_range == f"{port}/{port}" and rule.ip_protocol == 'TCP':
                    rules.append(rule.source_cidr_ip)
        return set(rules)

    def authorize_ip(self, ip, port):
        """
        Add an ingress rule for the specific IP and port.
        
        Args:
            ip (str): Source IP address.
            port (int): Destination port.
        """
        cidr = f"{ip}/32"
        print(f"Adding rule for {cidr}...")
        if self.dry_run:
            print(f"[DRY-RUN] Would authorize {cidr}")
            return

        request = ecs_20140526_models.AuthorizeSecurityGroupRequest(
            region_id=self.region_id,
            security_group_id=self.security_group_id,
            ip_protocol='TCP',
            port_range=f"{port}/{port}",
            source_cidr_ip=cidr,
            description="Sync from NetSuite outboundips"
        )
        self.client.authorize_security_group(request)

    def revoke_ip(self, ip, port):
        """
        Remove an ingress rule for the specific IP and port.
        
        Args:
            ip (str): Source IP address to remove.
            port (int): Destination port.
        """
        cidr = f"{ip}/32"
        print(f"Removing rule for {cidr}...")
        if self.dry_run:
            print(f"[DRY-RUN] Would revoke {cidr}")
            return

        request = ecs_20140526_models.RevokeSecurityGroupRequest(
            region_id=self.region_id,
            security_group_id=self.security_group_id,
            ip_protocol='TCP',
            port_range=f"{port}/{port}",
            source_cidr_ip=cidr
        )
        self.client.revoke_security_group(request)


import subprocess

def get_netsuite_ips():
    """
    Fetch NetSuite outbound IPs using robust DNS resolution across multiple resolvers.
    
    Returns:
        set: A set of IP address strings.
    """
    hostname = 'outboundips.netsuite.com'
    all_ips = set()
    
    # 1. Try resolving using 'dig' with multiple resolvers for maximum completeness
    resolvers = [
        None,       # System default
        '8.8.8.8',  # Google
        '1.1.1.1'   # Cloudflare
    ]
    
    for resolver in resolvers:
        try:
            cmd = ['dig', '+short', hostname]
            if resolver:
                cmd.insert(1, f"@{resolver}")
            
            # Run dig and capture output
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                ips = {line.strip() for line in result.stdout.splitlines() if line.strip()}
                # Filter for valid IPv4 (simple check)
                ips = {ip for ip in ips if all(c.isdigit() or c == '.' for c in ip) and ip.count('.') == 3}
                if ips:
                    print(f"Resolved {len(ips)} IPs using {'system default' if not resolver else resolver}")
                    all_ips.update(ips)
        except Exception as e:
            print(f"Dig attempt ({resolver or 'default'}) failed: {e}")

    # 2. Fallback/Supplement with socket.getaddrinfo
    try:
        addr_info = socket.getaddrinfo(hostname, None)
        socket_ips = {info[4][0] for info in addr_info if socket.AF_INET == info[0]}
        if socket_ips:
            print(f"Resolved {len(socket_ips)} IPs using socket.getaddrinfo")
            all_ips.update(socket_ips)
    except Exception as e:
        print(f"Socket resolution failed: {e}")

    return all_ips


def main():
    """Main execution block."""
    parser = argparse.ArgumentParser(description="Sync NetSuite outbound IPs to Aliyun Security Group.")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without making changes.")
    parser.add_argument("--sg-id", help="Aliyun Security Group ID (overrides defaults).")
    parser.add_argument("--region", help="Aliyun Region ID (used with --sg-id).")
    parser.add_argument("--port", type=int, help="Port to open (used with --sg-id).")
    args = parser.parse_args()

    # Define default security group configurations
    default_sgs = [
        {
            "id": "sg-uf67dcdf6rhingo4wsnc",
            "region": "cn-shanghai",
            "port": 22,
            "name": "Shanghai Default"
        },
        {
            "id": "sg-j6chr1b73i3yyg3hf3gm",
            "region": "cn-hongkong",
            "port": 2222,
            "name": "Hong Kong Custom"
        }
    ]

    # Priority 1: Fetch NetSuite IPs as they are public data
    print(f"Fetching latest NetSuite IPs for outboundips.netsuite.com...")
    netsuite_ips = get_netsuite_ips()
    if not netsuite_ips:
        print("No IPs found for NetSuite. Exiting to avoid clearing rules.")
        sys.exit(1)
    
    print(f"Found {len(netsuite_ips)} NetSuite IPs.")

    # Priority 2: Check for necessary credentials
    access_key_id = os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_ID')
    access_key_secret = os.environ.get('ALIBABA_CLOUD_ACCESS_KEY_SECRET')

    if not access_key_id or not access_key_secret:
        print("Error: ALIBABA_CLOUD_ACCESS_KEY_ID and ALIBABA_CLOUD_ACCESS_KEY_SECRET environment variables must be set.")
        print("Use: export ALIBABA_CLOUD_ACCESS_KEY_ID='...' && export ALIBABA_CLOUD_ACCESS_KEY_SECRET='...'")
        sys.exit(1)


    # Determine which SGs to sync
    sgs_to_sync = []
    if args.sg_id:
        sgs_to_sync.append({
            "id": args.sg_id,
            "region": args.region or "cn-shanghai",
            "port": args.port or 22,
            "name": "CLI Override"
        })
    else:
        sgs_to_sync = default_sgs

    for sg in sgs_to_sync:
        print(f"\n--- Syncing Security Group: {sg['name']} ({sg['id']} in {sg['region']}, port {sg['port']}) ---")
        
        syncer = AliyunSync(sg['region'], access_key_id, access_key_secret, sg['id'], args.dry_run)
        
        # Priority 3: Fetch current Aliyun state
        print(f"Fetching current Aliyun rules for {sg['id']} (port {sg['port']})...")
        try:
            current_cidr_rules = syncer.get_current_rules(sg['port'])
        except Exception as e:
            print(f"Error fetching Aliyun rules for {sg['id']}: {e}")
            continue
        
        # Process CIDRs into simple IPs for comparison
        current_ips = {cidr.split('/')[0] for cidr in current_cidr_rules if '/32' in cidr or '/' not in cidr}
        print(f"Found {len(current_ips)} existing IP rules.")

        # Calculate diff
        ips_to_add = netsuite_ips - current_ips
        ips_to_remove = current_ips - netsuite_ips

        if not ips_to_add and not ips_to_remove:
            print(f"No changes detected for {sg['name']}. Security group is up to date.")
            continue

        print(f"Planning to add {len(ips_to_add)} IPs and remove {len(ips_to_remove)} IPs.")

        # Execute changes
        for ip in ips_to_add:
            try:
                syncer.authorize_ip(ip, sg['port'])
            except Exception as e:
                print(f"Failed to add {ip}: {e}")

        for ip in ips_to_remove:
            try:
                syncer.revoke_ip(ip, sg['port'])
            except Exception as e:
                print(f"Failed to remove {ip}: {e}")

    print("\nAll sync tasks complete.")


if __name__ == "__main__":
    main()

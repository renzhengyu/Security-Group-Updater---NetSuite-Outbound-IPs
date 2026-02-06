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


def get_netsuite_ips():
    """
    Fetch NetSuite outbound IPs using cross-platform DNS resolution.
    
    Returns:
        set: A set of IP address strings.
    """
    hostname = 'outboundips.netsuite.com'
    try:
        # socket.getaddrinfo is cross-platform and reliable for resolving all A records
        addr_info = socket.getaddrinfo(hostname, None)
        # The IP address is the first element of the address tuple (5th element of info)
        ips = {info[4][0] for info in addr_info if socket.AF_INET == info[0]}
        return ips
    except Exception as e:
        print(f"Error resolving {hostname}: {e}")
        return set()


def main():
    """Main execution block."""
    parser = argparse.ArgumentParser(description="Sync NetSuite outbound IPs to Aliyun Security Group.")
    parser.add_argument("--dry-run", action="store_true", help="Perform a dry run without making changes.")
    parser.add_argument("--sg-id", default="sg-uf67dcdf6rhingo4wsnc", help="Aliyun Security Group ID.")
    parser.add_argument("--region", default="cn-shanghai", help="Aliyun Region ID.")
    parser.add_argument("--port", type=int, default=22, help="Port to open (default 22).")
    args = parser.parse_args()

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

    syncer = AliyunSync(args.region, access_key_id, access_key_secret, args.sg_id, args.dry_run)
    
    # Priority 3: Fetch current Aliyun state
    print(f"Fetching current Aliyun rules for {args.sg_id} (port {args.port})...")
    try:
        current_cidr_rules = syncer.get_current_rules(args.port)
    except Exception as e:
        print(f"Error fetching Aliyun rules: {e}")
        sys.exit(1)
    
    # Process CIDRs into simple IPs for comparison
    current_ips = {cidr.split('/')[0] for cidr in current_cidr_rules if '/32' in cidr or '/' not in cidr}
    print(f"Found {len(current_ips)} existing IP rules.")

    # Calculate diff
    ips_to_add = netsuite_ips - current_ips
    ips_to_remove = current_ips - netsuite_ips

    if not ips_to_add and not ips_to_remove:
        print("No changes detected. Security group is up to date.")
        return

    print(f"Planning to add {len(ips_to_add)} IPs and remove {len(ips_to_remove)} IPs.")

    # Execute changes
    for ip in ips_to_add:
        try:
            syncer.authorize_ip(ip, args.port)
        except Exception as e:
            print(f"Failed to add {ip}: {e}")

    for ip in ips_to_remove:
        try:
            syncer.revoke_ip(ip, args.port)
        except Exception as e:
            print(f"Failed to remove {ip}: {e}")

    print("Sync complete.")


if __name__ == "__main__":
    main()

#!/bin/bash

# Source the credentials if they exist
if [ -f .env.sh ]; then
    source .env.sh
else
    echo "Error: .env.sh file not found. Please create it with your Alibaba Cloud credentials."
    exit 1
fi

# Run the Python script with any arguments passed to this script
python3 sync_ips.py "$@"

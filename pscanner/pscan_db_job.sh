#!/bin/bash

# Bash file to run on ivre-client container with command
# docker exec -i ivreclient /bin/bash /ivre-opt/pscan_db_job.sh
# 1. Purge the view database (web gui view) to start fresh
# 2. Import the latest scan into scan database
# 3. Create two new views -- 1. View of previous scan 2. View of Newest Current Scan

/bin/sh -c "echo yes | ivre view --purgedb"
/bin/sh -c "ivre scan2db --open-ports -s SCAN_SERVER -c pscan_$(cat "/ivre-opt/current_scan_date.txt") /ivre-share/$(cat "/ivre-opt/current_scan_date.txt")*.xml"

/bin/sh -c "ivre db2view --no-merge nmap --category pscan_$(cat "/ivre-opt/previous_scan_date.txt")"
/bin/sh -c "ivre db2view --no-merge nmap --category pscan_$(cat "/ivre-opt/current_scan_date.txt")"

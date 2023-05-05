#! /bin/bash

# tar xml output scans
tar -czf /opt/pscanner-backups/backups/pscanner_$(date +%Y-%m-%d).tar.gz /opt/ivre/

# delete backups older than 7 days but not first of month backups
find /opt/pscanner-backups/backups/ ! -name '*01.tar.gz' ! -name 'backup.sh' -mmin +$((7*60*24)) -exec rm -f {} \;

# sync backups to s3 bucket
aws s3 sync /opt/pscanner-backups/ s3://pscanner-bucket/backups/
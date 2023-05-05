### Script run on ivre client container to print out latest scan results from mongo DB
### Calls the mongo query: list(db.view.get_ips_ports(flt=db.view.searchcategory("pscan_"+current_date))[0])
### Converts results to a json dict exported to recent_scan_results.json so future script can read it for email generation

from ivre.db import db
import json

file1 = open("/ivre-opt/current_scan_date.txt", "r")
current_date = file1.readline()
file1.close

result_list = []

# Data to be written
scan_export = list(db.view.get_ips_ports(flt=db.view.searchcategory("pscan_"+current_date))[0])

for result in scan_export:
    result_list.append({"ip_address": result['addr'], "ports": result['ports']})

json_obj = json.dumps(result_list, indent=4)

with open("/ivre-opt/recent_scan_result.json", "w") as outfile:
    outfile.write(json_obj)
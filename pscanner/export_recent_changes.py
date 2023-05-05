### Script run on ivre client container to print out latest diff of changes from previous scan to current scan
### Calls the mongo query: list(db.view.diff_categories(category1="1",category2="2",include_both_open=False))
### Converts results to a json dict exported to whats_changed.json so future script can read it for email generation

from ivre.db import db
import json

file1 = open("/ivre-opt/current_scan_date.txt", "r")
current_date = file1.readline().strip()
file1.close

file2 = open("/ivre-opt/previous_scan_date.txt", "r")
previous_date = file2.readline().strip()
file2.close

result_list = []

value_map = {"-1": "No Longer Detected", "0": "Still Open: Open in previous scan "+previous_date+" and open in current scan "+current_date, "1": "Newly Detected"}

# Data to be written
scan_export = list(db.view.diff_categories(category1="pscan_"+previous_date,category2="pscan_"+current_date,include_both_open=False))

for result in scan_export:
    result_list.append({"ip_address": result['addr'], "protocol": result['proto'], "port": result['port'], "status": value_map[str(result['value'])]})

sorted_result_list = sorted(result_list, key=lambda d: d['status']) 

json_obj = json.dumps(sorted_result_list, indent=2)

with open("/ivre-opt/whats_changed.json", "w") as outfile:
    outfile.write(json_obj)
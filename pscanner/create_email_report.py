import requests
import json
import datetime
from jinja2 import Template
import smtplib

### global vars
netbox_url = 'https://netbox'
netbox_token = 'token'
netbox_headers = {'Authorization': "Token {}".format(netbox_token)}
date_parser = datetime.datetime.now() 
date_stamp = date_parser.strftime("%Y-%m-%d")
recent_scan_filename = "/opt/ivre/ivre-opt/recent_scan_result.json"
whats_changed_filename = "/opt/ivre/ivre-opt/whats_changed.json"
output_list_no_reason = []
output_list_all = []

### functions

### Search if IP + Port Combo exists in netbox custom field called 'known open ports
### example 172.1.1.5-->443 see if exists in data structure:
# {'known_open_ports': [
#        {'port': 443, 'reason': 'web server', 'protocol': 'tcp'
#        }
#    ]
# }
def get_netbox_known_ports_justification(ip_address,port):
    ipam_api_call = requests.get(netbox_url+"/api/ipam/ip-addresses/?address="+ip_address, headers=netbox_headers, verify=False).json()
    if len(ipam_api_call['results']) > 0:
        known_ports_list = ipam_api_call['results'][0].get('custom_fields')
        if known_ports_list['known_open_ports'] is not None:
            for known_port in known_ports_list['known_open_ports']:
                if known_port.get('port') == port:
                    return known_port.get('reason')
        else:
            return "No Justification"
    else:
        return "No Justification"
    return "No Justification"

def get_recent_scan(filename):
    f = open(filename)
    return json.load(f)


### Gather Data
recent_scan_results_dict = get_recent_scan(recent_scan_filename)
whats_changed_dict = get_recent_scan(whats_changed_filename)

### Iterate through every entry of most recent scan and compare each entry to netbox "known open port" field
for entry in recent_scan_results_dict:
     for discovered_port in entry['ports']:
        ## ignore udp open/filtered state as its not truly open
        if discovered_port['state_state'] == 'open':
            reason = get_netbox_known_ports_justification(entry['ip_address'],discovered_port['port'])
        else:
            continue
        if reason == "No Justification":
            output_list_no_reason.append({"IP Address": entry['ip_address'],"Open Port": discovered_port['port'], "Reason": reason})
        else:
            output_list_all.append({"IP Address": entry['ip_address'],"Open Port": discovered_port['port'], "Reason": reason})

### Build Email Template
with open('/opt/ivre/ivre-opt/email_template.j2') as f:
    rendered = Template(f.read()).render(date_stamp=date_stamp,output_list_no_reason=output_list_no_reason,output_list_all=output_list_all,whats_changed_dict=whats_changed_dict)

message = 'Subject: {}\n\n{}'.format("Network Perimeter Port Scanner Summary", rendered)

s = smtplib.SMTP('smtp-server')
s.sendmail('pscanner@domain', ['notify@domain'], message)
s.sendmail()
s.quit()

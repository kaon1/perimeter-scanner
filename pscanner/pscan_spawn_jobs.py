import ipaddress
import requests
import subprocess
import time
from datetime import datetime, timedelta
from netutils.ip import netmask_to_cidr

### start by killing all nmap processes (if they are running)
subprocess.Popen(['killall', '-9', 'nmap'])

## this is the tag used in netbox to classify prefixes and ips to scan
nmap_tag = "nmap_scanning"

netbox_url = 'https://netbox'
netbox_token = 'token'
netbox_headers = {'Authorization': "Token {}".format(netbox_token)}

# writing date files
date_parser = datetime.now()
date_stamp = date_parser.strftime("%Y-%m-%d")
prev_date_parser = datetime.now() + timedelta(days=-7)
prev_date_stamp = prev_date_parser.strftime("%Y-%m-%d")
current_scan_fh = open("/opt/ivre/ivre-opt/current_scan_date.txt", "w")
previous_scan_fh = open("/opt/ivre/ivre-opt/previous_scan_date.txt", "w")
current_scan_fh.write(date_stamp)
current_scan_fh.close()
previous_scan_fh.write(prev_date_stamp)
previous_scan_fh.close()
# end writing date files

# nmap args to use for TCP Scans
nmap_base_args = "nohup nmap --log-errors --open -T3 -Pn -sS --top-ports 2000 -oX /opt/ivre/ivre-share/"+date_stamp+"_tcp_"

# nmap args to use for UDP Scans
nmap_base_args_udp = "nohup nmap --log-errors --open -T3 -Pn -sU --top-ports 250 -oX /opt/ivre/ivre-share/"+date_stamp+"_udp_"

# netbox api calls to grab all ip addresses and prefixes tagged with nmap_scanning tag
netbox_api_ip_addr = requests.get(netbox_url+"/api/ipam/ip-addresses/?limit=0&tag="+nmap_tag, headers=netbox_headers, verify=False).json()
netbox_api_ip_prefix = requests.get(netbox_url+"/api/ipam/prefixes/?limit=0&tag="+nmap_tag, headers=netbox_headers, verify=False).json()

# function to take in address like 172.3.3.0/25 and return 172_3_3_0 and netmask 25
def explode_address_elements(address_to_scan):
    exploded_elements_dict = {}
    exploded_elements_dict['address_to_scan_exploded'] = str(
        ipaddress.IPv4Interface(address_to_scan).ip).replace('.', '_')
    exploded_elements_dict['address_to_scan_mask'] = str(
        netmask_to_cidr((ipaddress.IPv4Interface(address_to_scan).netmask)))
    return exploded_elements_dict

# function to spawn one nmap job per ingested prefix or ip address
def spawn_nmap_jobs(address_to_scan, address_to_scan_exploded, address_to_scan_mask, is_prefix):
    if is_prefix:
        ## spawn tcp scans
        nmap_raw_cmd = nmap_base_args+address_to_scan_exploded+"_" + address_to_scan_mask+".xml "+address_to_scan
        subprocess.Popen(nmap_raw_cmd.split())

        ##spawn udp scans
        nmap_raw_cmd = nmap_base_args_udp+address_to_scan_exploded+"_" + address_to_scan_mask+".xml "+address_to_scan
        subprocess.Popen(nmap_raw_cmd.split())

    else:
        ## spawn tcp scans
        nmap_raw_cmd = nmap_base_args+address_to_scan_exploded+"_" + address_to_scan_mask+".xml "+address_to_scan.split("/")[0]
        subprocess.Popen(nmap_raw_cmd.split())

        ## spawn udp scans
        nmap_raw_cmd = nmap_base_args_udp+address_to_scan_exploded+"_" + address_to_scan_mask+".xml "+address_to_scan.split("/")[0]
        subprocess.Popen(nmap_raw_cmd.split())

# iterate through netbox ip address query results and start the nmap job
for ip_addr in netbox_api_ip_addr['results']:
    ip_elements = explode_address_elements(ip_addr['address'])
    spawn_nmap_jobs(ip_addr['address'], ip_elements['address_to_scan_exploded'], ip_elements['address_to_scan_mask'], is_prefix=False)
    time.sleep(.3)

# iterate through netbox prefix query results and start the nmap job
for prefix in netbox_api_ip_prefix['results']:
    ip_elements = explode_address_elements(prefix['prefix'])
    spawn_nmap_jobs(prefix['prefix'], ip_elements['address_to_scan_exploded'], ip_elements['address_to_scan_mask'], is_prefix=True)
    time.sleep(.3)

# all jobs should be started now and script exits. With current params the jobs will complete in 24 hours
# example output of psaux www
###
## nmap --log-errors --open -T4 -Pn -sS --top-ports 2000 -oX /opt/ivre/ivre-share/2023-02-08_tcp_172_1_1_0_23.xml 172.1.1.0/23
## nmap --log-errors --open -T4 -Pn -sU --top-ports 250 -oX /opt/ivre/ivre-share/2023-02-08_udp_172_2_2_0_23.xml 172.2.2.0/23

import subprocess
import sys
import requests
import os
from datetime import datetime

pcap = '2026-01-31-traffic-analysis-exercise.pcap'
alert_ip = '153.92.1.49'
api_key = os.environ.get('VT_API_KEY') # get api key from environment


def run_tshark(display_filter, fields):
    command = ['tshark', '-r', pcap, '-Y', display_filter, '-T', 'fields']
    for field in fields:
        command.append('-e')
        command.append(field)
    result = subprocess.run(command, capture_output=True, text=True)
    return result.stdout


def get_rows(display_filter, fields):
    rows = []
    output = run_tshark(display_filter, fields)
    lines = output.split('\n')
    for line in lines:
        columns = line.split('\t')
        if len(columns) < len(fields):
            continue
        if '' in columns:
            continue
        rows.append(columns)
    return rows


def defang(value):
    return value.replace('.', '[.]')

def vt_lookup(kind, value):
    # kind is 'domains' or 'ip_addresses'
    if api_key is None:
        return 'not checked (no API key set)'
    url = 'https://www.virustotal.com/api/v3/' + kind + '/' + value
    headers = {'x-apikey': api_key}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        return 'lookup failed (status ' + str(response.status_code) + ')'
    
    #get dictionary jason data from the response, which is a dictionary with keys 'data' and 'meta'
    data = response.json()
    stats = data['data']['attributes']['last_analysis_stats']
    malicious = stats['malicious']
    # out of score
    total = 0
    for count in stats.values():
        total += count
    return str(malicious) + '/' + str(total) + ' engines flag as malicious'


# which internal host talked to the alert IP and what domain did it ask for
http_rows = get_rows('ip.dst == ' + alert_ip + ' && http.request', ['frame.number', 'ip.src', 'http.host'])
if len(http_rows) == 0:
    sys.exit('No HTTP requests to ' + alert_ip + ' found. Stopping.')

http_packet = http_rows[0][0]
infected_ip = http_rows[0][1]
alert_domain = http_rows[0][2]

# hostname and MAC for the infected IP only
hostname = 'not found'
mac_address = 'not found'
dhcp_packet = '-'
dhcp_rows = get_rows('dhcp.option.requested_ip_address == ' + infected_ip, ['frame.number', 'dhcp.hw.mac_addr', 'dhcp.option.hostname'])
if len(dhcp_rows) > 0:
    dhcp_packet = dhcp_rows[0][0]
    # don't pront mac address multiple times and get 1st ocurrence
    mac_address = dhcp_rows[0][1].split(',')[0]
    hostname = dhcp_rows[0][2]

# user account logged in from the infected IP only
username = 'not found'
kerberos_packet = '-'
kerberos_rows = get_rows('kerberos.CNameString && ip.src == ' + infected_ip, ['frame.number', 'ip.src', 'kerberos.CNameString'])
for row in kerberos_rows:
    if not row[2].endswith('$'):
        kerberos_packet = row[0]
        username = row[2]
        break

# perform VirusTotal lookup for the alert IP and domain
vt_domain = vt_lookup('domains', alert_domain)
vt_ip = vt_lookup('ip_addresses', alert_ip)
now = datetime.now().strftime('%Y-%m-%d %H:%M')

# Print a summary 
print('Infected IP: ' + infected_ip)
print('Alert Domain: ' + alert_domain + ' (VirusTotal: ' + vt_domain + ')')
print('Alert IP VirusTotal: ' + vt_ip)
print('Hostname: ' + hostname)
print('MAC Address: ' + mac_address)
print('Username: ' + username)

# Step 5: build the ticket
ticket = ''
ticket += '# Incident Ticket: Suspicious HTTP traffic to ' + defang(alert_ip) + '\n\n'
ticket += '**Generated:** ' + now + ' by triage.py\n\n'
ticket += '**Source PCAP:** ' + pcap + '\n\n'
ticket += '**Status:** Needs analyst review\n\n'
ticket += '## Findings\n\n'
ticket += '| Field | Value | Evidence (packet) |\n'
ticket += '|---|---|---|\n'
ticket += '| Alert IP | ' + defang(alert_ip) + ' | IDS alert |\n'
ticket += '| Alert domain | ' + defang(alert_domain) + ' | ' + http_packet + ' |\n'
ticket += '| Infected IP | ' + infected_ip + ' | ' + http_packet + ' |\n'
ticket += '| Hostname | ' + hostname + ' | ' + dhcp_packet + ' |\n'
ticket += '| MAC address | ' + mac_address + ' | ' + dhcp_packet + ' |\n'
ticket += '| User account | ' + username + ' | ' + kerberos_packet + ' |\n\n'
ticket += '## Enrichment (VirusTotal, checked ' + now + ')\n\n'
ticket += '| Indicator | Result |\n'
ticket += '|---|---|\n'
ticket += '| ' + defang(alert_domain) + ' | ' + vt_domain + ' |\n'
ticket += '| ' + defang(alert_ip) + ' | ' + vt_ip + ' |\n\n'
ticket += '_Automated output. External indicators are defanged. Detection counts change over time. Do not escalate without verification._\n'

#write the ticket to a file
with open('ticket.md', 'w') as f:
    f.write(ticket)

print('Ticket written to ticket.md')
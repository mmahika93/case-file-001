import subprocess

pcap = '2026-01-31-traffic-analysis-exercise.pcap'

def run_tshark(display_filter, fields):
    command = ['tshark', '-r', pcap, '-Y', display_filter, '-T', 'fields']
    for field in fields:
        command.append('-e')
        command.append(field)
        
    result = subprocess.run(command, capture_output=True, text=True,)
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

# display hostname and mac addr
dhcp_rows = get_rows('dhcp', ['frame.number', 'dhcp.hw.mac_addr', 'dhcp.option.hostname'])
first = dhcp_rows[0]
print('Hostname: ' + first[2] + ' (packet number: ' + first[0] + ')')
print('MAC Address: ' + first[1].split(',')[0])

# display username and source IP
kerberos_rows = get_rows('kerberos.CNameString', ['frame.number', 'ip.src', 'kerberos.CNameString'])
for row in kerberos_rows:
    if not row[2].endswith('$'):
        print('Username: ' + row[2] + ' from ' + row[1] + ' (packet number: ' + row[0] + ')')
        break

# Domain
domain_rows = get_rows('ip.addr == 153.92.1.49 && http.request', [ 'frame.number', 'http.host'])
# if the filter doesn't output anything
if len(domain_rows) > 0:
    print('Alert Domain: ' + domain_rows[0][1] + ' (packet number: ' + domain_rows[0][0] + ')')
else:
    print('Alert Domain: not found')
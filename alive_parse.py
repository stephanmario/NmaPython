import xml.etree.ElementTree as ET

# Parses the XML output from nmap to grab IP addresses

tree = ET.parse('/Users/v-morem/Desktop/Scans/Nmap_scans/up_hosts.xml')
root = tree.getroot()

ips = open('/Users/v-morem/Desktop/Scans/Nmap_scans/targets_wireless.txt', 'w')


def get_ip_from_xml():
    tree = ET.parse('/Users/v-morem/Desktop/Scans/Nmap_scans/up_hosts.xml')
    root = tree.getroot()
    ips = open('/Users/v-morem/Desktop/Scans/Nmap_scans/targets_wireless.txt', 'w')
    for host in root.findall('host'):
        for address in host:
            if address.get('addr') and address.get('addrtype') == 'ipv4':
                addr = address.get('addr')
                ips.write(addr + "\n")


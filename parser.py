from libnmap.parser import NmapParser

# Parses Nmap XML Data from OS Detection Scan ad sorts each IP into corresponging .txt file

nmap_report = NmapParser.parse_fromfile('/Users/v-morem/Desktop/Scans/Nmap_scans/msft_wireless_internal_20170606.xml')
scanned_hosts = nmap_report.hosts
unix = open('/Users/v-morem/Desktop/Scans/unix_wifi_hosts.txt', 'w')
windows = open('/Users/v-morem/Desktop/Scans/windows_wifi_hosts.txt', 'w')
unknown = open('/Users/v-morem/Desktop/Scans/unknown_wifi_hosts.txt', 'w')


for host in scanned_hosts:
    if host.is_up():
        os_guess = str(host.os)
        if 'Linux' and 'Apple' in os_guess:
            unix.write("{0}\n".format(host.ipv4))
        elif 'Windows' in os_guess:
            windows.write("{0}\n".format(host.ipv4))
        else:
            unknown.write("{0}\n".format(host.ipv4))

from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from time import sleep

# Runs an NMAP scan based on the targets and options you pass EX: 'sort_scan.py target opts'
# Then seperates IP's into One of three files based on the OS detected.

'''
windows_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/windows_hosts.txt', 'a')
unix_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/unix_hosts.txt', 'a')
unknown_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/unknown_hosts.txt', 'a')
'''
windows_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/unix.txt', 'w')
unix_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/windows.txt', 'w')
unknown_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/unknown.txt', 'w')

def scan_sort_os(target, opts):
    nm = NmapProcess(target, opts)
    nm.run_background()
    while nm.is_running():
        print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,nm.progress))
        sleep(60)
    print "Summary: {0}".format(nm.summary)
    scan_results = NmapParser.parse(nm.stdout)
    scanned_hosts = scan_results.hosts
    for host in scanned_hosts:
        if host.is_up():
            os_guess = str(host.os)
            if 'Linux' and 'Apple' in os_guess:
                unix_hosts.write("{0}\n".format(host.ipv4))
            elif 'Windows' in os_guess:
                windows_hosts.write("{0}\n".format(host.ipv4))
            else:
                unknown_hosts.write("{0}\n".format(host.ipv4))
    print "Done Check File Location for output"



scan_sort_os('10.92.52.1/22', '-sS -O -T4 --osscan-limit --top-ports 150')
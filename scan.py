from libnmap.process import NmapProcess
from libnmap.parser import NmapParser
from time import sleep

windows_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/windows_hosts_wired.txt', 'w')
unix_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/unix_hosts_wired.txt', 'w')
unknown_hosts = open('/Users/v-morem/Desktop/scans/Nmap_scans/unknown_hosts_wired.txt', 'w')



def scan_sort_os(target, opts):
    nm = NmapProcess(target, opts)
    nm.run()
    while nm.is_running():
        print("Nmap Scan running: ETC: {0} DONE: {1}%".format(nm.etc,nm.progress))
        sleep(5)
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



scan_sort_os('10.163.132.0/23', '-sS -O -T4')
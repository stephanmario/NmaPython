import argparse
from libnmap.process import NmapProcess
from libnmap.parser import NmapParser, NmapParserException

parser = argparse.ArgumentParser(description='Nmap Port Scanner')

parser.add_argument('host',
                    nargs=1,
                    default='127.0.0.1',
                    help='One Host or a CIDR Range'
                    )
args= parser.parse_args()

def scan(host, options):
    nm = NmapProcess(host, options)
    nm.run()
    print nm.stdout


if args.host:
    host = args.host
    options = '-sS'
    scan(host,options)
else:
    print args.description
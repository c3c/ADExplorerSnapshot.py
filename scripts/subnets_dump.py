# Script to dump subnets and IPs
# author: Signum21

from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
import ipaddress
import argparse
import os

parser = argparse.ArgumentParser(add_help=True, description="Script to extract subnets and IPs from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-p", "--parse_ips", required=False, help="Expand subnets in corresponding IPs", action="store_true")
parser.add_argument("-o", "--output_file", required=False, help="Save output to file")
args = parser.parse_args()

logging.basicConfig(handlers=[pwnlib.log.console])
log = pwnlib.log.getLogger(__name__)
log.setLevel(20)

if pwnlib.term.can_init():
    pwnlib.term.init()

log.term_mode = pwnlib.term.term_mode

ades = ADExplorerSnapshot(args.snapshot, ".", log)
ades.preprocessCached()
out = set()

for domain in ades.domains:
    print()
    print("[+]",f"Searching inside domain {domain.replace('DC=', '').replace(',', '.')}")
    findSub = f",CN=Subnets,CN=Sites,CN=Configuration,{domain}".lower()

    for k,v in ades.dncache.items():
        if k.lower().endswith(findSub):
            subnet = k.split(",")[0].split("=")[1]
            
            if not args.parse_ips:
                if not args.output_file:
                    print(subnet)
                out.add(subnet)
            else:
                sub_ips = [str(ip) for ip in ipaddress.IPv4Network(subnet)]
                print("[+]",f"Parsing subnet {subnet}")
                
                for ip in sub_ips:
                    if ip not in out:                    
                        if not args.output_file:
                            print(ip)
                        out.add(ip)
    
if args.output_file:
    outFile = open(args.output_file, "w")
    outFile.write(os.linesep.join(out))
    print()
    print("[+]",f"Output written to {args.output_file}")
# Script to list out servers
# author: @oddvarmoe

from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
import argparse
import os

parser = argparse.ArgumentParser(add_help=True, description="Script to extract server list from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
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

print("[+]",f"Finding Servers - Searching for ComputerObjects with Operating system containing Server")
print("[+]",f"Outputformat:")
print("[+]",f"samaccountname | dnshostname | operatingsystem | operatingsystemversion | description")
    
for idx,obj in enumerate(ades.snap.objects):
    # get users
    if ADUtils.get_entry_property(obj, 'sAMAccountType', -1) == 805306369:
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        operatingsystem = ADUtils.get_entry_property(obj, 'operatingsystem')
        operatingsystemversion = ADUtils.get_entry_property(obj, 'operatingsystemversion')
        description = ADUtils.get_entry_property(obj, 'description')
        dnshostname = ADUtils.get_entry_property(obj, 'dnshostname')
        if operatingsystem and 'server' in operatingsystem.lower():
            if not args.output_file:
                print(f"{samaccountname} | {dnshostname} | {operatingsystem} | {operatingsystemversion} | {description}")
            out.add(f"{samaccountname}|{dnshostname}|{operatingsystem}|{operatingsystemversion}|{description}")

if args.output_file:
    outFile = open(args.output_file, "w")
    outFile.write(os.linesep.join(out))
    print()
    print("[+]",f"Output written to {args.output_file}")

# Script to list out phone numbers
# author: @oddvarmoe

from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
import argparse
import os

parser = argparse.ArgumentParser(add_help=True, description="Script to extract subnets and IPs from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
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

print("[+]",f"Finding users with the attribute telephonenumber set")
print("[+]",f"Outputformat:")
print("[+]",f"name | telephonenumber | title | department | samaccountname | userprincipalname")
    
for idx,obj in enumerate(ades.snap.objects):
    # get users
    if ADUtils.get_entry_property(obj, 'sAMAccountType', -1) == 805306368:
        name = ADUtils.get_entry_property(obj, 'name')
        title = ADUtils.get_entry_property(obj, 'title')
        department = ADUtils.get_entry_property(obj, 'department')
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        telephonenumber = ADUtils.get_entry_property(obj, 'telephonenumber')
        userprincipalname = ADUtils.get_entry_property(obj, 'userprincipalname')
        if telephonenumber:
            if not args.output_file:
                print(f"{name} | {telephonenumber} | {title} | {department} | {samaccountname} | {userprincipalname}")
            out.add(f"{name} | {telephonenumber} | {title} | {department} | {samaccountname} | {userprincipalname}")

if args.output_file:
    outFile = open(args.output_file, "w")
    outFile.write(os.linesep.join(out))
    print()
    print("[+]",f"Output written to {args.output_file}")

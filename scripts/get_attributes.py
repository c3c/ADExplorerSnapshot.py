# Script to dump specific AD attributes
# author: @knavesec

from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
from datetime import datetime, timezone
from pathlib import Path
import argparse
import os

parser = argparse.ArgumentParser(add_help=True, description="Script to dump interesting stuff from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-a", "--attributes", required=True, action="append", nargs="*", help="Attributes to extract")
parser.add_argument("-t", "--type", required=False, default=None, help="Object type (User, Computer, Group, Base), optional and case-sensitive")
args = parser.parse_args()

logging.basicConfig(handlers=[pwnlib.log.console])
log = pwnlib.log.getLogger(__name__)
log.setLevel(20)

if pwnlib.term.can_init():
    pwnlib.term.init()

log.term_mode = pwnlib.term.term_mode

ades = ADExplorerSnapshot(args.snapshot, ".", log)
ades.preprocessCached()

# Get snapshot time
snapshot_time = datetime.fromtimestamp(ades.snap.header.filetimeUnix, tz=timezone.utc)

# ty stack overflow for reducing a 2d array
attrs = [j for sub in args.attributes for j in sub]

out_list = []
out_list.append("||".join(attrs))

prog = log.progress(f"Going through objects and outputting to files", rate=0.1)    
for idx,obj in enumerate(ades.snap.objects):
    # get computers
    object_resolved = ADUtils.resolve_ad_entry(obj)
    if object_resolved['type'] == args.type or args.type == None:
        obj_out = []
        for attr in attrs:

            if attr in ['lastlogontimestamp', 'whencreated', 'pwdlastset']:
                obj_out.append(str(convert_ad_timestamp(ADUtils.get_entry_property(obj, attr))))
            else: 
                out_list.append("||".join(obj_out))

    prog.status(f"{idx+1}/{ades.snap.header.numObjects}")


outFile = open(Path("objs.txt"), "w")
outFile.write(os.linesep.join(out_list))

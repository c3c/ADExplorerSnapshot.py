# Script to dump DFS link paths and their target servers
# Author: @snovvcrash

import sys
import xml.etree.ElementTree as ET

import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
from adexpsnapshot import ADExplorerSnapshot

logging.basicConfig(handlers=[pwnlib.log.console])
log = pwnlib.log.getLogger(__name__)
log.setLevel(20)

if pwnlib.term.can_init():
    pwnlib.term.init()

log.term_mode = pwnlib.term.term_mode

ades = ADExplorerSnapshot(open(sys.argv[1], 'rb'), '.', log)
ades.preprocessCached()

findDN = f',CN=Dfs-Configuration,CN=System,{ades.rootdomain}'.lower()

dfs_pairs = []
for key, val in ades.dncache.items():
    if key.lower().endswith(findDN):
        entry = ades.snap.getObject(val)
        dfs_pairs.append((
            ADUtils.get_entry_property(entry, 'msDFS-TargetListv2', None, raw=True),
            ADUtils.get_entry_property(entry, 'msDFS-LinkPathv2', None, raw=True)
        ))

namespace = {'ns': 'http://schemas.microsoft.com/dfs/2007/03'}

result = []
for target_list, link_path in dfs_pairs:
    if link_path is not None:
        try:
            xml_data = target_list.decode('utf-16le')
            root = ET.fromstring(xml_data)
            targets = [t.text for t in root.findall("ns:target", namespace)]
        except Exception as e:
            print(f'[-] {e}')
        else:
            joined_targets = '\n             '.join(targets)
            print('--------------------------------------------------------------------------------')
            print(f'Link path:   {link_path}')
            print(f'Target list: {joined_targets}')

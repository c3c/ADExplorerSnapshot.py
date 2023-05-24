from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
from adidnsdump import dnsdump

logging.basicConfig(handlers=[pwnlib.log.console])
log = pwnlib.log.getLogger(__name__)
log.setLevel(20)

if pwnlib.term.can_init():
    pwnlib.term.init()
log.term_mode = pwnlib.term.term_mode

import sys
fh = open(sys.argv[1],"rb")

ades = ADExplorerSnapshot(fh, '.', log)
ades.preprocessCached()

findDN = f',CN=MicrosoftDNS,CN=System,{ades.rootdomain}'.lower()

print()

for k,v in ades.dncache.items():
    if k.lower().endswith(findDN):
        entry = ades.snap.getObject(v)
        for address in ADUtils.get_entry_property(entry, 'dnsRecord', [], raw=True):
            dr = dnsdump.DNS_RECORD(address)
            if dr['Type'] == 1:
                address = dnsdump.DNS_RPC_RECORD_A(dr['Data'])
                print("[+]","Type:",dnsdump.RECORD_TYPE_MAPPING[dr['Type']],"name:",k.split(',')[0].split('=')[1],"value:",address.formatCanonical())
            if dr['Type'] in [a for a in dnsdump.RECORD_TYPE_MAPPING if dnsdump.RECORD_TYPE_MAPPING[a] in ['CNAME', 'NS', 'PTR']]:
                address = dnsdump.DNS_RPC_RECORD_NODE_NAME(dr['Data'])
                print("[+]","Type:",dnsdump.RECORD_TYPE_MAPPING[dr['Type']],"name:",k.split(',')[0].split('=')[1],"value:",address[list(address.fields)[0]].toFqdn())
            elif dr['Type'] == 28:
                address = dnsdump.DNS_RPC_RECORD_AAAA(dr['Data'])
                print("[+]","Type:",dnsdump.RECORD_TYPE_MAPPING[dr['Type']],"name:",k.split(',')[0].split('=')[1],"value:",address.formatCanonical())
            elif dr['Type'] not in [a for a in dnsdump.RECORD_TYPE_MAPPING if dnsdump.RECORD_TYPE_MAPPING[a] in ['A', 'AAAA,' 'CNAME', 'NS']]:
                print("[+]","name:",k.split(',')[0].split('=')[1],'Unexpected record type seen: {}'.format(dr['Type']))

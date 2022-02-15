from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils

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

findDN = f',CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,{ades.rootdomain}'.lower()

print()

for k,v in ades.dncache.items():
    if k.lower().endswith(findDN):

        print("[+] " + k.split(',')[0].split('=')[1])

        entry = ades.snap.getObject(v)
        aces = ades.parse_acl(None, 'user', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True))
        processed_aces = ades.resolve_aces(aces)

        for ace in processed_aces:
            pidx = ades.sidcache.get(ace['PrincipalSID'])
            if pidx:
                principal = ades.snap.getObject(pidx)
                the_principal = ADUtils.get_entry_property(principal, 'sAMAccountName').upper() + "@" + ADUtils.ldap2domain(ades.rootdomain).upper()
            else:
                the_principal = ace['PrincipalSID']

            status_inherited = " (inherited)" if ace['IsInherited'] else ""
            status_rights = ace['RightName'] + status_inherited

            print("{: >60} | {: <20}".format(the_principal, status_rights))

        print("")



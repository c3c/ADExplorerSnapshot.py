from adexpsnapshot.parser.classes import Snapshot
from requests.structures import CaseInsensitiveDict

import pwnlib.log, pwnlib.term, logging

import argparse
import shelve, hashlib, os, tempfile
from pickle import Pickler, Unpickler

from bloodhound.ad.utils import ADUtils
from bloodhound.ad.trusts import ADDomainTrust
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.acls import parse_binary_acl
from frozendict import frozendict
from bloodhound.enumeration.outputworker import OutputWorker

import functools
import queue, threading
import datetime, calendar

class ADExplorerSnapshot(object):
    def __init__(self, snapfile, log=None):

        self.log = log
        self.snap = Snapshot(snapfile, log=log)

        self.snap.parseHeader()

        if self.log:
            filetimeiso = datetime.datetime.fromtimestamp(self.snap.header.filetimeUnix).isoformat()
            self.log.info(f'Server: {self.snap.header.server}')
            self.log.info(f'Time of snapshot: {filetimeiso}')
            self.log.info('Mapping offset: 0x{:x}'.format(self.snap.header.mappingOffset))
            self.log.info(f'Object count: {self.snap.header.numObjects}')

        self.snap.parseProperties()
        self.snap.parseClasses()

        self.snap.parseObjectOffsets()

        self.sidcache = {}
        self.dncache = CaseInsensitiveDict()
        self.computersidcache = CaseInsensitiveDict()
        self.domains = CaseInsensitiveDict()
        self.objecttype_guid_map = CaseInsensitiveDict()
        self.domaincontrollers = []
        self.rootdomain = None

        cacheFileName = hashlib.md5(f"{self.snap.header.filetime}_{self.snap.header.server}".encode()).hexdigest() + ".cache"
        cachePath = os.path.join(tempfile.gettempdir(), cacheFileName)

        dico = None
        try:
            dico = Unpickler(open(cachePath, "rb")).load()
        except (OSError, IOError, EOFError) as e:
            pass

        if dico and dico.get('shelved', False):
            if self.log:
                self.log.success("Restored pre-processed information from data cache")

            self.objecttype_guid_map = dico['guidmap']
            self.sidcache = dico['sidcache']
            self.dncache = dico['dncache']
            self.computersidcache = dico['computersidcache']
            self.domains = dico['domains']
            self.domaincontrollers = dico['domaincontrollers']
            self.rootdomain = dico['rootdomain']
        else:
            self.preprocess()

            dico = {}
            dico['guidmap'] = self.objecttype_guid_map
            dico['sidcache'] = self.sidcache
            dico['dncache'] = self.dncache
            dico['computersidcache'] = self.computersidcache
            dico['domains'] = self.domains
            dico['domaincontrollers'] = self.domaincontrollers
            dico['rootdomain'] = self.rootdomain
            dico['shelved'] = True

            Pickler(open(cachePath, "wb")).dump(dico)

        self.numUsers = 0
        self.numGroups = 0
        self.numComputers = 0
        self.numTrusts = 0

        self.writeQueues = {}

        self.process()

    # build caches: guidmap, domains, forest_domains, computers
    def preprocess(self):
        for k,cl in self.snap.classes.items():
            self.objecttype_guid_map[k] = str(cl.schemaIDGUID)

        if self.log:
            prog = self.log.progress("Preprocessing objects", rate=0.1)

        for idx,obj in enumerate(self.snap.objects):

            # create sid cache
            objectSid = ADUtils.get_entry_property(obj, 'objectSid')
            if objectSid:
                self.sidcache[objectSid] = idx

            # create dn cache
            distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
            if distinguishedName:
                self.dncache[distinguishedName] = idx

            # get domains
            if 'domain' in obj.classes:
                if self.rootdomain is not None: # is it possible to find multiple?
                    if self.log:
                        self.log.warn("Multiple domains in snapshot(?)")
                else:
                    self.rootdomain = distinguishedName
                    self.domains[distinguishedName] = idx

            # get forest domains
            if 'crossref' in obj.classes:
                if ADUtils.get_entry_property(obj, 'systemFlags', 0) & 2 == 2:
                    ncname = ADUtils.get_entry_property(obj, 'nCName')
                    if ncname and ncname not in self.domains:
                        self.domains[ncname] = idx

            # get computers
            if ADUtils.get_entry_property(obj, 'sAMAccountType', -1) == 805306369 and not (ADUtils.get_entry_property(obj, 'userAccountControl', 0) & 0x02 == 0x02):
                dnshostname = ADUtils.get_entry_property(obj, 'dNSHostname')
                if dnshostname:
                    self.computersidcache[dnshostname] = objectSid

            # get dcs
            if ADUtils.get_entry_property(obj, 'userAccountControl', 0) & 0x2000 == 0x2000:
                self.domaincontrollers.append(idx)

            if self.log and self.log.term_mode:
                prog.status(f"{idx+1}/{self.snap.header.numObjects} ({len(self.sidcache)} sids, {len(self.computersidcache)} computers, {len(self.domains)} domains with {len(self.domaincontrollers)} DCs)")

        if self.log:
            prog.success(f"{len(self.sidcache)} sids, {len(self.computersidcache)} computers, {len(self.domains)} domains with {len(self.domaincontrollers)} DCs")

    def process(self):
        processors = [
            ["users", self.processUsers],
            ["computers", self.processComputers],
            ["groups", self.processGroups],
            ["trusts", self.processTrusts]
        ]

        if self.log:
            prog = self.log.progress("Collecting data", rate=0.1)

        for ptype,fun in processors:
            self.writeQueues[ptype] = queue.Queue()
            results_worker = threading.Thread(target=OutputWorker.membership_write_worker, args=(self.writeQueues[ptype], ptype, f"{self.snap.header.server}_{self.snap.header.filetimeUnix}_{ptype}.json"))
            results_worker.daemon = True
            results_worker.start()

        for idx,obj in enumerate(self.snap.objects):
            for ptype,fun in processors:
                ret = fun(obj)
                if ret:
                    break

            if self.log and self.log.term_mode:
                prog.status(f"{idx+1}/{self.snap.header.numObjects} ({self.numUsers} users, {self.numGroups} groups, {self.numComputers} computers, {self.numTrusts} trusts)")

        if self.log:
            prog.success(f"{self.numUsers} users, {self.numGroups} groups, {self.numComputers} computers, {self.numTrusts} trusts")

        self.write_default_groups()

        for ptype,fun in processors:
            self.writeQueues[ptype].put(None)
            self.writeQueues[ptype].join()

        if self.log:
            self.log.success(f"Output written to {self.snap.header.server}_{self.snap.header.filetimeUnix}_*.json files")

    def processComputers(self, entry):
        if not ADUtils.get_entry_property(entry, 'sAMAccountType', -1) == 805306369 or (ADUtils.get_entry_property(entry, 'userAccountControl', 0) & 0x02 == 0x02):
            return

        hostname = ADUtils.get_entry_property(entry, 'dNSHostName')
        if not hostname:
            return

        distinguishedName = ADUtils.get_entry_property(entry, 'distinguishedName')
        domain = ADUtils.ldap2domain(distinguishedName)

        samname = ADUtils.get_entry_property(entry, 'sAMAccountName')
        primarygroup = MembershipEnumerator.get_primary_membership(entry)

        computer = {
            'ObjectIdentifier': ADUtils.get_entry_property(entry, 'objectsid'),
            'AllowedToAct': [],
            'PrimaryGroupSid': primarygroup,
            'Properties': {
                'name': hostname.upper(),
                'objectid': ADUtils.get_entry_property(entry, 'objectsid'),
                'domain': domain.upper(),
                'highvalue': False,
                'distinguishedname': distinguishedName
            },
            'AllowedToDelegate': [],
            'Aces': []
        }

        props = computer['Properties']
        # via the TRUSTED_FOR_DELEGATION (0x00080000) flag in UAC
        props['unconstraineddelegation'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00080000 == 0x00080000
        props['enabled'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 2 == 0


        props['haslaps'] = ADUtils.get_entry_property(entry, 'ms-mcs-admpwdexpirationtime', 0) != 0


        props['lastlogontimestamp'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'lastlogontimestamp', default=0, raw=True)
        )
        props['pwdlastset'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'pwdLastSet', default=0, raw=True)
        )
        props['serviceprincipalnames'] = ADUtils.get_entry_property(entry, 'servicePrincipalName', [])
        props['description'] = ADUtils.get_entry_property(entry, 'description')
        props['operatingsystem'] = ADUtils.get_entry_property(entry, 'operatingSystem')
        # Add SP to OS if specified
        servicepack = ADUtils.get_entry_property(entry, 'operatingSystemServicePack')
        if servicepack:
            props['operatingsystem'] = '%s %s' % (props['operatingsystem'], servicepack)

        delegatehosts = ADUtils.get_entry_property(entry, 'msDS-AllowedToDelegateTo', [])
        for host in delegatehosts:
            try:
                target = host.split('/')[1]
            except IndexError:
                logging.warning('Invalid delegation target: %s', host)
                continue
            try:
                sid = self.computersidcache.get(target)
                data['AllowedToDelegate'].append(sid)
            except KeyError:
                if '.' in target:
                    data['AllowedToDelegate'].append(target.upper())
        if len(delegatehosts) > 0:
            props['allowedtodelegate'] = delegatehosts


        # Process resource-based constrained delegation
        aces = self.parse_acl(computer, 'computer', ADUtils.get_entry_property(entry, 'msDS-AllowedToActOnBehalfOfOtherIdentity', raw=True))
        outdata = self.resolve_aces(aces, domain)

        for delegated in outdata:
            if delegated['RightName'] == 'Owner':
                continue
            if delegated['RightName'] == 'GenericAll':
                computer['AllowedToAct'].append({'MemberId': delegated['PrincipalSID'], 'MemberType': delegated['PrincipalType']})

        aces = self.parse_acl(computer, 'computer', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True))
        computer['Aces'] = self.resolve_aces(aces, domain)

        self.numComputers += 1
        self.writeQueues["computers"].put(computer)
        return True


    def processTrusts(self, entry):
        if 'trusteddomain' not in entry.classes:
            return

        domtrust = ADDomainTrust(ADUtils.get_entry_property(entry, 'name'), ADUtils.get_entry_property(entry, 'trustDirection'), ADUtils.get_entry_property(entry, 'trustType'), 
                                ADUtils.get_entry_property(entry, 'trustAttributes'), ADUtils.get_entry_property(entry, 'securityIdentifier'))
        
        trust = domtrust.to_output()
        self.numTrusts += 1
        self.writeQueues["trusts"].put(trust)
        return True

    def processGroups(self, entry):
        if not 'group' in entry.classes:
            return

        highvalue = ["S-1-5-32-544", "S-1-5-32-550", "S-1-5-32-549", "S-1-5-32-551", "S-1-5-32-548"]

        def is_highvalue(sid):
            if sid.endswith("-512") or sid.endswith("-516") or sid.endswith("-519") or sid.endswith("-520"):
                return True
            if sid in highvalue:
                return True
            return False

        distinguishedName = ADUtils.get_entry_property(entry, 'distinguishedName')
        resolved_entry = ADUtils.resolve_ad_entry(entry)
        domain = ADUtils.ldap2domain(distinguishedName)

        sid = ADUtils.get_entry_property(entry, "objectSid")

        group = {
            "ObjectIdentifier": sid,
            "Properties": {
                "domain": domain.upper(),
                "objectid": sid,
                "highvalue": is_highvalue(sid),
                "name": resolved_entry['principal'],
                "distinguishedname": distinguishedName
            },
            "Members": [],
            "Aces": []
        }
        if sid in ADUtils.WELLKNOWN_SIDS:
            group['ObjectIdentifier'] = '%s-%s' % (domain.upper(), sid)
            group['Properties']['objectid'] = group['ObjectIdentifier']

        group['Properties']['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', default=0) == 1
        group['Properties']['description'] = ADUtils.get_entry_property(entry, 'description')

        for member in ADUtils.get_entry_property(entry, 'member', []):
            resolved_member = self.get_membership(member)
            if resolved_member:
                group['Members'].append(resolved_member)

        aces = self.parse_acl(group, 'group', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True))
        group['Aces'] += self.resolve_aces(aces, domain)

        self.numGroups += 1
        self.writeQueues["groups"].put(group)
        return True

    def processUsers(self, entry):
        if not (('user' in entry.classes and 'person' == entry.category) or 'msds-groupmanagedserviceaccount' in entry.classes):
            return

        distinguishedName = ADUtils.get_entry_property(entry, 'distinguishedName')

        resolved_entry = ADUtils.resolve_ad_entry(entry)
        if resolved_entry['type'] == 'trustaccount':
            return

        domain = ADUtils.ldap2domain(distinguishedName)

        user = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": ADUtils.get_entry_property(entry, 'objectSid'),
            "PrimaryGroupSid": MembershipEnumerator.get_primary_membership(entry),
            "Properties": {
                "name": resolved_entry['principal'],
                "domain": domain.upper(),
                "objectid": ADUtils.get_entry_property(entry, 'objectSid'),
                "distinguishedName": distinguishedName,
                "highvalue": False,
                "unconstraineddelegation": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00080000 == 0x00080000,
                "passwordnotreqd": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00000020 == 0x00000020
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": []
        }

        MembershipEnumerator.add_user_properties(user, entry)

        if 'allowedtodelegate' in user['Properties']: 
            for host in user['Properties']['allowedtodelegate']:
                try:
                    target = host.split('/')[1]
                except IndexError:
                    self.log.warn('Invalid delegation target: %s', host)
                    continue
                try:
                    sid = self.computersidcache[target]
                    user['AllowedToDelegate'].append(sid)
                except KeyError:
                    if '.' in target:
                        user['AllowedToDelegate'].append(target.upper())

        # Parse SID history - in this case, will be all unknown(?)
        if len(user['Properties']['sidhistory']) > 0:
            for historysid in user['Properties']['sidhistory']:
                user['HasSIDHistory'].append(self.resolve_sid(historysid, domain))

        # If this is a GMSA, process it's ACL
        # DACLs which control who can read their password
        if ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', default=b'', raw=True) != b'':
            aces = self.parse_acl(user, 'user', ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', raw=True))
            processed_aces = self.resolve_aces(aces, domain)

            for ace in processed_aces:
                if ace['RightName'] == 'Owner':
                    continue
                ace['RightName'] = 'ReadGMSAPassword'
                user['Aces'].append(ace)

        # parse ACL
        aces = self.parse_acl(user, 'user', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True))
        user['Aces'] += self.resolve_aces(aces, domain)

        self.numUsers += 1
        self.writeQueues["users"].put(user)
        return True

    @functools.lru_cache(maxsize=4096)
    def resolve_aces(self, aces, domain):
        aces_out = []
        for ace in aces:
            out = {
                'RightName': ace['rightname'],
                'AceType': ace['acetype'],
                'IsInherited': ace['inherited']
            }
            # Is it a well-known sid?
            if ace['sid'] in ADUtils.WELLKNOWN_SIDS:
                out['PrincipalSID'] = u'%s-%s' % (domain.upper(), ace['sid'])
                out['PrincipalType'] = ADUtils.WELLKNOWN_SIDS[ace['sid']][1].capitalize()
            else:
                try:
                    entry = self.snap.getObject(self.sidcache[ace['sid']])
                except KeyError:
                    entry = {
                        'type': 'Unknown',
                        'principal': ace['sid']
                    }

                resolved_entry = ADUtils.resolve_ad_entry(entry)
                out['PrincipalSID'] = ace['sid']
                out['PrincipalType'] = resolved_entry['type']
            aces_out.append(out)
        return aces_out

    # CacheInfo(hits=633024, misses=19340, maxsize=4096, currsize=4096)
    @functools.lru_cache(maxsize=4096)
    def _parse_acl_cached(self, haslaps, entrytype, acl):
        fake_entry = {"Properties":{"haslaps":haslaps}}
        _, aces = parse_binary_acl(fake_entry, entrytype, acl, self.objecttype_guid_map)

        # freeze result so we can cache it for resolve_aces function
        for i, ace in enumerate(aces):
            aces[i] = frozendict(ace)
        return frozenset(aces)

    def parse_acl(self, entry, entrytype, acl):
        haslaps = entrytype == 'computer' and entry['Properties']['haslaps']
        aces = self._parse_acl_cached(haslaps, entrytype, acl)
        self.cacheInfo = self._parse_acl_cached.cache_info()
        return aces

    # kinda useless I'm guessing as we're staying in the local domain?
    @functools.lru_cache(maxsize=2048)
    def resolve_sid(self, sid, domain):
        out = {}
        # Is it a well-known sid?
        if sid in ADUtils.WELLKNOWN_SIDS:
            out['ObjectID'] = u'%s-%s' % (domain.upper(), sid)
            out['ObjectType'] = ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
        else:
            try:
                entry = self.snap.getObject(self.sidcache[sid])
            except KeyError:
                entry = {
                    'type': 'Unknown',
                    'principal':sid
                }

            resolved_entry = ADUtils.resolve_ad_entry(entry)
            out['ObjectID'] = sid
            out['ObjectType'] = resolved_entry['type']
        return out

    @functools.lru_cache(maxsize=2048)
    def get_membership(self, member):
        try:
            entry = self.snap.getObject(self.dncache[member])
        except KeyError:
            return None

        resolved_entry = ADUtils.resolve_ad_entry(entry)
        return {
            "MemberId": resolved_entry['objectid'],
            "MemberType": resolved_entry['type'].capitalize()
        }


    def write_default_groups(self):
        domainname = ADUtils.ldap2domain(self.rootdomain).upper()

        group = {
            "ObjectIdentifier": "%s-S-1-5-9" % domainname,
            "Properties": {
                "domain": domainname,
                "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % domainname,
            },
            "Members": [],
            "Aces": []
        }

        for dc in self.domaincontrollers:
            entry = self.snap.getObject(dc)
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            memberdata = {
                "MemberId": resolved_entry['objectid'],
                "MemberType": resolved_entry['type'].capitalize()
            }
            group["Members"].append(memberdata)

        self.writeQueues["groups"].put(group)

        domain_object = self.snap.getObject(self.dncache[self.rootdomain])
        domainsid =  ADUtils.get_entry_property(domain_object, 'objectSid')

        # Everyone
        evgroup = {
            "ObjectIdentifier": "%s-S-1-1-0" % domainname,
            "Properties": {
                "domain": domainname,
                "name": "EVERYONE@%s" % domainname,
            },
            "Members": [
                {
                    "MemberId": "%s-515" % domainsid,
                    "MemberType": "Group"
                },
                {
                    "MemberId": "%s-513" % domainsid,
                    "MemberType": "Group"
                }
            ],
            "Aces": []
        }
        self.writeQueues["groups"].put(evgroup)

        # Authenticated users
        augroup = {
            "ObjectIdentifier": "%s-S-1-5-11" % domainname,
            "Properties": {
                "domain": domainname,
                "name": "AUTHENTICATED USERS@%s" % domainname,
            },
            "Members": [
                {
                    "MemberId": "%s-515" % domainsid,
                    "MemberType": "Group"
                },
                {
                    "MemberId": "%s-513" % domainsid,
                    "MemberType": "Group"
                }
            ],
            "Aces": []
        }
        self.writeQueues["groups"].put(augroup)


def main():

    parser = argparse.ArgumentParser(add_help=True, description='AD Explorer snapshot ingestor for BloodHound', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('snapshot')

    args = parser.parse_args()

    # add basic config for logging module to use pwnlib logging also in bloodhound libs
    logging.basicConfig(handlers=[pwnlib.log.console])
    log = pwnlib.log.getLogger(__name__)
    log.setLevel(20)

    if pwnlib.term.can_init():
        pwnlib.term.init()
    log.term_mode = pwnlib.term.term_mode

    fh = open(args.snapshot, "rb")
    ADExplorerSnapshot(fh, log)

if __name__ == '__main__':
    main()

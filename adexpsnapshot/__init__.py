from requests.structures import CaseInsensitiveDict

import pwnlib.log, pwnlib.term, logging

import argparse
import hashlib, os, tempfile, pathlib
from pickle import Pickler, Unpickler

from bloodhound.ad.utils import ADUtils
from bloodhound.ad.trusts import ADDomainTrust
from bloodhound.enumeration.memberships import MembershipEnumerator
from bloodhound.enumeration.acls import parse_binary_acl
from bloodhound.ad.structures import LDAP_SID
from frozendict import frozendict
from bloodhound.enumeration.outputworker import OutputWorker

from certipy.lib.constants import *
from certipy.lib.security import ActiveDirectorySecurity, CertificateSecurity as CertificateSecurity, CASecurity
from certipy.commands.find import filetime_to_str
from asn1crypto import x509

from collections import defaultdict
import functools
import queue, threading
import datetime
from enum import Enum
from typing import List

class ADExplorerSnapshot(object):
    OutputMode = Enum('OutputMode', ['BloodHound', 'Objects', 'LDIF'])

    def __init__(self, snapfile, outputfolder, log=None, snapshot_parser=None):
        self.log = log
        self.output = outputfolder

        if not snapshot_parser:
            from adexpsnapshot.parser.classes import Snapshot
            snapshot_parser = Snapshot

        self.snap = snapshot_parser(snapfile, log=log)

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
        self.certtemplates = defaultdict(set)

    def outputObjects(self):
        import codecs, json, base64

        outputfile = f"{self.snap.header.server}_{self.snap.header.filetimeUnix}_objects.ndjson"

        class BaseSafeEncoder(json.JSONEncoder):
            def default(self, obj):
                if isinstance(obj, bytes):
                    return base64.b64encode(obj).decode("ascii")
                return json.JSONEncoder.default(self, obj)

        def write_worker(result_q, filename):
            try:
                fh_out = codecs.open(filename, 'w', 'utf-8')
            except:
                logging.warning('Could not write file: %s', filename)
                result_q.task_done()
                return

            wroteOnce = False
            while True:
                data = result_q.get()

                if data is None:
                    break

                if not wroteOnce:
                    wroteOnce = True
                else:
                    fh_out.write('\n')

                try:
                    encoded_member = json.dumps(data, indent=None, cls=BaseSafeEncoder)
                    fh_out.write(encoded_member)
                except TypeError:
                    logging.error('Data error {0}, could not convert data to json'.format(repr(data)))
                result_q.task_done()

            fh_out.close()
            result_q.task_done()
            
        wq = queue.Queue()
        results_worker = threading.Thread(target=write_worker, args=(wq, os.path.join(self.output, outputfile)))
        results_worker.daemon = True
        results_worker.start()

        if self.log:
            prog = self.log.progress("Collecting data", rate=0.1)

        for idx, obj in enumerate(self.snap.objects):
            wq.put((dict(obj.attributes.data)))

            if self.log and self.log.term_mode:
                prog.status(f"dumped {idx+1}/{self.snap.header.numObjects} objects")

        if self.log:
            prog.success(f"dumped {self.snap.header.numObjects} objects")

        wq.put(None)
        wq.join()

        if self.log:
            self.log.success(f"Output written to {outputfile}")

    def outputLDIF(self):

        import codecs, base64, datetime

        outputfile = f"{self.snap.header.server}_{self.snap.header.filetimeUnix}_objects.ldif"

        class LDIFEncoder:

            timestamp_attributes = ['whenCreated', 'whenChanged', 'dSCorePropagationData' ]

            def encode(self, obj):
                if obj is None:
                    return ""
                elif isinstance(obj, dict):
                    return self.encode_dict(obj)
                elif isinstance(obj, list):
                    return ", ".join(self.encode(item) for item in obj)
                elif isinstance(obj, int):
                    return str(obj if obj < 0x80000000 else obj - 0x100000000)
                elif isinstance(obj, bytes):
                    return base64.b64encode(obj).decode("ascii")
                elif isinstance(obj, (str, float, bool)):
                    return str(obj)
                else:
                    raise Exception(f"LDIFEncoder does not support objects of type {type(obj)}")

            def encode_dict(self, obj):
                lines = []
                for key in sorted(obj.keys()):
                    if key in LDIFEncoder.timestamp_attributes:
                        encoded = self.encode_timestamp(obj[key], key)
                    else:
                        encoded = self.encode(obj[key])
                    lines.append(f"{key}: {encoded}")
                if len(lines):
                    lines.append("")
                return "\n".join(lines)

            def encode_timestamp(self, value, attr=''):
                try:
                    if isinstance(value, list):
                        if len(value) == 0:
                            return "0"
                        value = value[0]
                    return datetime.datetime.fromtimestamp(value, datetime.UTC).strftime('%Y%m%d%H%M%S.0Z')
                except:
                    logging.warning(f"Failed to parse timestamp for attribute {attr}")
                    return "0"

        ldif_encoder = LDIFEncoder()

        def write_worker(result_q, filename):
            try:
                fh_out = codecs.open(filename, 'w', 'utf-8')
            except:
                logging.warning('Could not write file: %s', filename)
                result_q.task_done()
                return

            wroteOnce = False
            while True:
                data = result_q.get()

                if data is None:
                    break

                if not wroteOnce:
                    wroteOnce = True
                else:
                    fh_out.write('--------------------\n')

                try:
                    encoded_member = ldif_encoder.encode(data)
                    fh_out.write(encoded_member)
                except TypeError:
                    logging.error('Data error {0}, could not convert data to LDIF'.format(repr(data)))
                result_q.task_done()

            fh_out.close()
            result_q.task_done()

        wq = queue.Queue()
        results_worker = threading.Thread(target=write_worker, args=(wq, os.path.join(self.output, outputfile)))
        results_worker.daemon = True
        results_worker.start()

        if self.log:
            prog = self.log.progress("Collecting data", rate=0.1)

        for idx, obj in enumerate(self.snap.objects):
            wq.put((dict(obj.attributes.data)))

            if self.log and self.log.term_mode:
                prog.status(f"dumped {idx+1}/{self.snap.header.numObjects} objects")

        if self.log:
            prog.success(f"dumped {self.snap.header.numObjects} objects")

        wq.put(None)
        wq.join()

        if self.log:
            self.log.success(f"Output written to {outputfile}")

    def outputBloodHound(self):
        self.preprocessCached()

        self.numUsers = 0
        self.numGroups = 0
        self.numComputers = 0
        self.numTrusts = 0
        self.numCertTemplates = 0
        self.numCAs = 0

        self.trusts = []
        self.writeQueues = {}

        self.process()

    def preprocessCached(self):
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
            self.certtemplates = dico['certtemplates']
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
            dico['certtemplates'] = self.certtemplates
            dico['shelved'] = True
            Pickler(open(cachePath, "wb")).dump(dico)

    # build caches: guidmap, domains, forest_domains, computers
    def preprocess(self):
        for k,cl in self.snap.classes.items():
            self.objecttype_guid_map[k] = str(cl.schemaIDGUID)

        for k,idx in self.snap.propertyDict.items():
            self.objecttype_guid_map[k] = str(self.snap.properties[idx].schemaIDGUID)

        if self.log:
            prog = self.log.progress("Preprocessing objects", rate=0.1)

        for idx,obj in enumerate(self.snap.objects):

            # create sid cache
            objectSid = ADUtils.get_entry_property(obj, 'objectSid')
            if objectSid:
                self.sidcache[str(objectSid)] = idx

            # create dn cache
            distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
            if distinguishedName:
                self.dncache[str(distinguishedName)] = idx

            # get domains
            if 'domain' in obj.classes:
                if self.rootdomain is not None: # is it possible to find multiple?
                    if self.log:
                        self.log.warn("Multiple domains in snapshot(?)")
                else:
                    self.rootdomain = str(distinguishedName)
                    self.domains[str(distinguishedName)] = idx

            # get forest domains
            if 'crossref' in obj.classes:
                if ADUtils.get_entry_property(obj, 'systemFlags', 0) & 2 == 2:
                    ncname = ADUtils.get_entry_property(obj, 'nCName')
                    if ncname and ncname not in self.domains:
                        self.domains[str(ncname)] = idx

            # get computers
            if ADUtils.get_entry_property(obj, 'sAMAccountType', -1) == 805306369:
                dnshostname = ADUtils.get_entry_property(obj, 'dNSHostname')
                if dnshostname:
                    self.computersidcache[str(dnshostname)] = str(objectSid)

            # get all cert templates
            if 'pkienrollmentservice' in obj.classes:
                name = str(ADUtils.get_entry_property(obj, 'name'))
                if ADUtils.get_entry_property(obj, 'certificateTemplates'):
                    templates = ADUtils.get_entry_property(obj, 'certificateTemplates')
                    for template in templates:
                        self.certtemplates[str(template)].add(name)

            # get dcs
            if ADUtils.get_entry_property(obj, 'userAccountControl', 0) & 0x2000 == 0x2000:
                self.domaincontrollers.append(idx)

            if self.log and self.log.term_mode:
                prog.status(f"{idx+1}/{self.snap.header.numObjects} ({len(self.sidcache)} sids, {len(self.computersidcache)} computers, {len(self.domains)} domains with {len(self.domaincontrollers)} DCs)")

        if self.log:
            prog.success(f"{len(self.sidcache)} sids, {len(self.computersidcache)} computers, {len(self.domains)} domains with {len(self.domaincontrollers)} DCs")

    def process(self):
        self.domainname = ADUtils.ldap2domain(self.rootdomain)
        self.domain_object = self.snap.getObject(self.dncache[self.rootdomain])
        self.domainsid = ADUtils.get_entry_property(self.domain_object, 'objectSid')

        if self.log:
            prog = self.log.progress("Collecting data", rate=0.1)

        for ptype in ['users', 'computers', 'groups', 'domains', 'cert_bh', 'cert_ly4k_tpls', 'cert_ly4k_cas']:
            self.writeQueues[ptype] = queue.Queue()
            btype = ptype

            if ptype.startswith("cert_"):
                if ptype.endswith("bh"):
                    btype = "gpos"
                elif ptype.endswith("ly4k_tpls"):
                    btype = "templates"
                elif ptype.endswith("ly4k_cas"):
                    btype = "cas"
            
            results_worker = threading.Thread(target=OutputWorker.membership_write_worker, args=(self.writeQueues[ptype], btype, os.path.join(self.output, f"{self.snap.header.server}_{self.snap.header.filetimeUnix}_{ptype}.json")))
            results_worker.daemon = True
            results_worker.start()

        for idx,obj in enumerate(self.snap.objects):
            for fun in [self.processUsers, self.processComputers, self.processGroups, self.processTrusts, self.processCertTemplates, self.processCAs]:
                ret = fun(obj)
                if ret:
                    break

            if self.log and self.log.term_mode:
                prog.status(f"{idx+1}/{self.snap.header.numObjects} ({self.numUsers} users, {self.numGroups} groups, {self.numComputers} computers, {self.numCertTemplates} certtemplates, {self.numCAs} CAs, {self.numTrusts} trusts)")

        if self.log:
            prog.success(f"{self.numUsers} users, {self.numGroups} groups, {self.numComputers} computers, {self.numCertTemplates} certtemplates, {self.numCAs} CAs, {self.numTrusts} trusts")

        self.write_default_users()
        self.write_default_groups()
        self.processDomains()

        for ptype in ['users', 'computers', 'groups', 'domains', 'cert_bh', 'cert_ly4k_tpls', 'cert_ly4k_cas']:
            self.writeQueues[ptype].put(None)
            self.writeQueues[ptype].join()

        if self.log:
            self.log.success(f"Output written to {self.snap.header.server}_{self.snap.header.filetimeUnix}_*.json files")

    def processDomains(self):
        level_id = ADUtils.get_entry_property(self.domain_object, 'msds-behavior-version', -1)
        try:
            functional_level = ADUtils.FUNCTIONAL_LEVELS[int(level_id)]
        except KeyError:
            functional_level = 'Unknown'

        domain = {
            "ObjectIdentifier": ADUtils.get_entry_property(self.domain_object, 'objectSid'),
            "Properties": {
                "name": self.domainname.upper(),
                "domain": self.domainname.upper(),
                "domainsid": ADUtils.get_entry_property(self.domain_object, 'objectSid'),
                "distinguishedname": ADUtils.get_entry_property(self.domain_object, 'distinguishedName'),
                "description": ADUtils.get_entry_property(self.domain_object, 'description', ''),
                "functionallevel": functional_level,
                "Machine Account Quota": ADUtils.get_entry_property(self.domain_object, 'ms-DS-MachineAccountQuota'),
                "highvalue": True,
                "isaclprotected": False,
                "collected": True,
                "whencreated": ADUtils.get_entry_property(self.domain_object, 'whencreated', default=0)
            },
            "Trusts": [],
            "Aces": [],
            # The below is all for GPO collection, unsupported as of now.
            "Links": [],
            "ChildObjects": [],
            "GPOChanges": {
                "AffectedComputers": [],
                "DcomUsers": [],
                "LocalAdmins": [],
                "PSRemoteUsers": [],
                "RemoteDesktopUsers": []
            },
            "IsDeleted": False,
            "IsACLProtected": False
        }

        aces = self.parse_acl(domain, 'domain', ADUtils.get_entry_property(self.domain_object, 'nTSecurityDescriptor', raw=True))
        domain['Aces'] = self.resolve_aces(aces)
        domain['Trusts'] = self.trusts

        self.writeQueues["domains"].put(domain)

    def processComputers(self, entry):
        if not ADUtils.get_entry_property(entry, 'sAMAccountType', -1) == 805306369:
            return

        hostname = ADUtils.get_entry_property(entry, 'dNSHostName')
        if not hostname:
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            hostname = resolved_entry['principal']

        distinguishedName = ADUtils.get_entry_property(entry, 'distinguishedName')

        membership_entry = {
            "attributes": {
                "objectSid": ADUtils.get_entry_property(entry, 'objectSid'),
                "primaryGroupID": ADUtils.get_entry_property(entry, 'primaryGroupID')
            }
        }

        computer = {
            'ObjectIdentifier': ADUtils.get_entry_property(entry, 'objectsid'),
            'AllowedToAct': [],
            'PrimaryGroupSID': MembershipEnumerator.get_primary_membership(membership_entry),
            'ContainedBy': None,
            'DumpSMSAPassword': [],
            'Properties': {
                'name': hostname.upper(),
                'domainsid': self.domainsid,
                'domain': self.domainname.upper(),
                'highvalue': False,
                'distinguishedname': distinguishedName
            },
            'LocalGroups': [],
            'LocalAdmins': {'Collected': False, 'FailureReason': None, 'Results': []},
            'RemoteDesktopUsers': {'Collected': False, 'FailureReason': None, 'Results': []},
            'DcomUsers': {'Collected': False, 'FailureReason': None, 'Results': []},
            'PSRemoteUsers': {'Collected': False, 'FailureReason': None, 'Results': []},
            'UserRights': [],
            'PrivilegedSessions': {
                'Collected': False,
                'FailureReason': None,
                'Results': []
            },
            'Sessions': {
                'Collected': False,
                'FailureReason': None,
                'Results': []
            },
            'RegistrySessions': {
                'Collected': False,
                'FailureReason': None,
                'Results': []
            },
            'AllowedToDelegate': [],
            'Aces': [],
            'HasSIDHistory': [],
            'IsDeleted': ADUtils.get_entry_property(entry, 'isDeleted', default=False),
            'Status': None
        }

        props = computer['Properties']
        # via the TRUSTED_FOR_DELEGATION (0x00080000) flag in UAC
        props['unconstraineddelegation'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00080000 == 0x00080000
        props['enabled'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 2 == 0
        props['trustedtoauth'] = ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x01000000 == 0x01000000
        props['samaccountname'] = ADUtils.get_entry_property(entry, 'sAMAccountName')

        props['haslaps'] = ADUtils.get_entry_property(entry, 'ms-mcs-admpwdexpirationtime', 0) != 0

        props['lastlogon'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'lastlogon', default=-1, raw=True)
        )

        props['lastlogontimestamp'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'lastlogontimestamp', default=-1, raw=True)
        )
        if props['lastlogontimestamp'] == 0:
            props['lastlogontimestamp'] = -1

        props['pwdlastset'] = ADUtils.win_timestamp_to_unix(
            ADUtils.get_entry_property(entry, 'pwdLastSet', default=-1, raw=True)
        )

        props['whencreated'] = ADUtils.get_entry_property(entry, 'whencreated', default=0)

        props['serviceprincipalnames'] = ADUtils.get_entry_property(entry, 'servicePrincipalName', [])
        props['description'] = ADUtils.get_entry_property(entry, 'description')
        props['operatingsystem'] = ADUtils.get_entry_property(entry, 'operatingSystem')
        # Add SP to OS if specified
        servicepack = ADUtils.get_entry_property(entry, 'operatingSystemServicePack')
        if servicepack:
            props['operatingsystem'] = '%s %s' % (props['operatingsystem'], servicepack)

        props['sidhistory'] = [LDAP_SID(bsid).formatCanonical() for bsid in ADUtils.get_entry_property(entry, 'sIDHistory', [])]

        delegatehosts = ADUtils.get_entry_property(entry, 'msDS-AllowedToDelegateTo', [])
        for host in delegatehosts:
            try:
                target = host.split('/')[1]
            except IndexError:
                logging.warning('Invalid delegation target: %s', host)
                continue
            try:
                sid = self.computersidcache[target]
                delegateObj = {
                    "ObjectIdentifier":sid,
                    "ObjectType": self.resolve_sid(sid)['ObjectType']
                }
                computer['AllowedToDelegate'].append(delegateObj)
            except KeyError:
                if '.' in target:
                    self.log.warn('Unable to find sid for delegation target: %s', host)
                    # TODO: figure out what to do here
                    #computer['AllowedToDelegate'].append(target.upper())
                    pass
        # deprecated
        #if len(delegatehosts) > 0:
        #    props['allowedtodelegate'] = delegatehosts


        # Process resource-based constrained delegation
        aces = self.parse_acl(computer, 'computer', ADUtils.get_entry_property(entry, 'msDS-AllowedToActOnBehalfOfOtherIdentity', raw=True))
        outdata = self.resolve_aces(aces)

        for delegated in outdata:
            if delegated['RightName'] == 'Owner':
                continue
            if delegated['RightName'] == 'GenericAll':
                computer['AllowedToAct'].append({'ObjectIdentifier': delegated['PrincipalSID'], 'ObjectType': delegated['PrincipalType']})

        aces = self.parse_acl(computer, 'computer', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True))
        computer['Aces'] = self.resolve_aces(aces)

        self.numComputers += 1
        self.writeQueues["computers"].put(computer)
        return True

    def processCertTemplates(self, entry):
        if not 'pkicertificatetemplate' in entry.classes:
            return

        name = ADUtils.get_entry_property(entry, 'name')
        if not name:
            return

        # Enable check if cert is under any CA (e.g. enabled)
        enabled = name in self.certtemplates

        object_identifier = ADUtils.get_entry_property(entry, 'objectGUID')
        validity_period = filetime_to_str(ADUtils.get_entry_property(entry, 'pKIExpirationPeriod'))
        renewal_period = filetime_to_str(ADUtils.get_entry_property(entry, 'pKIOverlapPeriod'))
        
        certificate_name_flag = ADUtils.get_entry_property(entry, 'msPKI-Certificate-Name-Flag', 0)
        certificate_name_flag = CertificateNameFlag(int(certificate_name_flag))

        enrollment_flag = ADUtils.get_entry_property(entry, 'msPKI-Enrollment-Flag', 0)
        enrollment_flag = EnrollmentFlag(int(enrollment_flag))

        authorized_signatures_required = int(ADUtils.get_entry_property(entry, 'msPKI-RA-Signature', 0))

        application_policies = ADUtils.get_entry_property(entry, 'msPKI-RA-Application-Policies', raw=True, default=[])
        application_policies = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                application_policies,
            )
        )

        extended_key_usage = ADUtils.get_entry_property(entry, "pKIExtendedKeyUsage", default=[])
        extended_key_usage = list(
            map(lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x, extended_key_usage)
        )

        client_authentication = (
            any(
                eku in extended_key_usage
                for eku in [
                    "Client Authentication",
                    "Smart Card Logon",
                    "PKINIT Client Authentication",
                    "Any Purpose",
                ]
            )
            or len(extended_key_usage) == 0
        )

        enrollment_agent = (
            any(
                eku in extended_key_usage
                for eku in [
                    "Certificate Request Agent",
                    "Any Purpose",
                ]
            )
            or len(extended_key_usage) == 0
        )

        enrollee_supplies_subject = any(
            flag in certificate_name_flag
            for flag in [
                CertificateNameFlag.ENROLLEE_SUPPLIES_SUBJECT,
            ]
        )

        requires_manager_approval = (
            EnrollmentFlag.PEND_ALL_REQUESTS in enrollment_flag
        )

        security = CertificateSecurity(ADUtils.get_entry_property(entry, "nTSecurityDescriptor", raw=True))
        aces = self.security_to_bloodhound_aces(security)

        certtemplate = {
            'Properties': {
              'highvalue': (
                enabled
                and any(
                  [
                    all(
                      [
                        enrollee_supplies_subject,
                        not requires_manager_approval,
                        client_authentication,
                      ]
                    ),
                    all([enrollment_agent, not requires_manager_approval]),
                  ]
                )
              ),
            'name': "%s@%s"
            % (
              ADUtils.get_entry_property(entry, "CN").upper(),
              self.domainname.upper()
            ),
            'type': 'Certificate Template',
            'domain': self.domainname.upper(),
            'Template Name': ADUtils.get_entry_property(entry, 'CN'),
            'Display Name': ADUtils.get_entry_property(entry, 'displayName'),
            'Client Authentication': client_authentication,
            'Enrollee Supplies Subject': enrollee_supplies_subject,
            'Extended Key Usage': extended_key_usage,
            'Requires Manager Approval': requires_manager_approval,
            'Validity Period': validity_period,
            'Renewal Period': renewal_period,
            'Certificate Name Flag': certificate_name_flag.to_str_list(),
            'Enrollment Flag': enrollment_flag.to_str_list(),
            'Authorized Signatures Required': authorized_signatures_required,
            'Application Policies': application_policies,
            'Enabled': enabled,
            'Certificate Authorities': list(self.certtemplates[name]),
            },          
            'ObjectIdentifier': object_identifier.lstrip("{").rstrip("}"), 
            'Aces': aces,
        }

        self.numCertTemplates += 1
        self.writeQueues["cert_bh"].put(certtemplate)
        self.writeQueues["cert_ly4k_tpls"].put(certtemplate)
        return True

    def processCAs(self, entry):
        if not 'pkienrollmentservice' in entry.classes:
            return
        
        name = ADUtils.get_entry_property(entry, 'name')
        if not name:
            return
        
        object_identifier = ADUtils.get_entry_property(entry, 'objectGUID')
        ca_name = ADUtils.get_entry_property(entry, 'cn') 
        dns_name = ADUtils.get_entry_property(entry, 'dNSHostName')
       
        subject_name = ADUtils.get_entry_property(entry, 'cACertificateDN')

        ca_certificate = x509.Certificate.load(
            ADUtils.get_entry_property(entry, 'cACertificate', raw=True)
        )["tbs_certificate"]

        serial_number = hex(int(ca_certificate["serial_number"]))[2:].upper()

        validity = ca_certificate["validity"].native
        validity_start = str(validity["not_before"])
        validity_end = str(validity["not_after"])

        security = CASecurity(ADUtils.get_entry_property(entry, "nTSecurityDescriptor"))
        aces = self.ca_security_to_bloodhound_aces(security)

        cas = {
                "Properties": {
                    "highvalue": True,
                    "name": "%s@%s"
                    % (
                        name.upper(),
                        self.domainname.upper(),
                    ),
                    "domain": self.domainname.upper(),
                    "type": "Enrollment Service",
                    "CA Name": ca_name,
                    "DNS Name": dns_name,
                    "Certificate Subject": subject_name,
                    "Certificate Serial Number": serial_number,
                    "Certificate Validity Start": validity_start,
                    "Certificate Validity End": validity_end,
                    # the below values cannot be obtained from ADExplorer
                    "Web Enrollment": "",
                    "User Specified SAN" : "",
                    "Request Disposition" : "",
                },
                "ObjectIdentifier": object_identifier.lstrip("{").rstrip("}"),
                "Aces": aces,
            }

        self.numCAs += 1
        self.writeQueues["cert_bh"].put(cas)
        self.writeQueues["cert_ly4k_cas"].put(cas)
        return True

    def processTrusts(self, entry):
        if 'trusteddomain' not in entry.classes:
            return

        domtrust = ADDomainTrust(ADUtils.get_entry_property(entry, 'name'), ADUtils.get_entry_property(entry, 'trustDirection'), ADUtils.get_entry_property(entry, 'trustType'), 
                                ADUtils.get_entry_property(entry, 'trustAttributes'), ADUtils.get_entry_property(entry, 'securityIdentifier'))
        
        trust = domtrust.to_output()
        self.numTrusts += 1
        self.trusts.append(trust)
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

        sid = ADUtils.get_entry_property(entry, "objectSid")

        group = {
            "ObjectIdentifier": sid,
            "Properties": {
                "domain": self.domainname.upper(),
                "domainsid": self.domainsid,
                "highvalue": is_highvalue(sid),
                "name": resolved_entry['principal'],
                "distinguishedname": distinguishedName,
            },
            "Members": [],
            "Aces": [],
            "IsDeleted": ADUtils.get_entry_property(entry, 'isDeleted', default=False),
            "IsACLProtected": False,
        }
        if sid in ADUtils.WELLKNOWN_SIDS:
            group['ObjectIdentifier'] = '%s-%s' % (self.domainname.upper(), sid)

        group['Properties']['admincount'] = ADUtils.get_entry_property(entry, 'adminCount', default=0) == 1
        group['Properties']['description'] = ADUtils.get_entry_property(entry, 'description', '')
        group['Properties']['whencreated'] = ADUtils.get_entry_property(entry, 'whencreated', default=0)
        group['Properties']['samaccountname'] = ADUtils.get_entry_property(entry, 'samaccountname')

        for member in ADUtils.get_entry_property(entry, 'member', []):
            resolved_member = self.get_membership(member)
            if resolved_member:
                group['Members'].append(resolved_member)

        aces = self.parse_acl(group, 'group', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True))
        group['Aces'] += self.resolve_aces(aces)

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

        membership_entry = {
            "attributes": {
                "objectSid": ADUtils.get_entry_property(entry, 'objectSid'),
                "primaryGroupID": ADUtils.get_entry_property(entry, 'primaryGroupID')
            }
        }

        user = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": ADUtils.get_entry_property(entry, 'objectSid'),
            "PrimaryGroupSID": MembershipEnumerator.get_primary_membership(membership_entry),
            "ContainedBy": None,
            "Properties": {
                "name": resolved_entry['principal'],
                "domain": domain.upper(),
                "domainsid": self.domainsid,
                "highvalue": False,
                "distinguishedname": distinguishedName,
                "unconstraineddelegation": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00080000 == 0x00080000,
                "trustedtoauth": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x01000000 == 0x01000000,
                "passwordnotreqd": ADUtils.get_entry_property(entry, 'userAccountControl', default=0) & 0x00000020 == 0x00000020
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
            "IsDeleted": ADUtils.get_entry_property(entry, 'isDeleted', default=False),
            "IsACLProtected": False,
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
                    delegateObj = {
                        "ObjectIdentifier":sid,
                        "ObjectType": self.resolve_sid(sid)['ObjectType']
                    }
                    
                    user['AllowedToDelegate'].append(delegateObj)
                except KeyError:
                    self.log.warn('Unable to find sid for delegation target: %s', host)
                    #if '.' in target:
                    #    user['AllowedToDelegate'].append(target.upper())
                    # TODO: Figure out what to do here
                    pass
            # Remove bad allowedtodelegate prop
            del user['Properties']['allowedtodelegate']
        # Parse SID history - in this case, will be all unknown(?)
        if len(user['Properties']['sidhistory']) > 0:
            for historysid in user['Properties']['sidhistory']:
                user['HasSIDHistory'].append(self.resolve_sid(historysid))

        # If this is a GMSA, process it's ACL
        # DACLs which control who can read their password
        if ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', default=b'', raw=True) != b'':
            aces = self.parse_acl(user, 'user', ADUtils.get_entry_property(entry, 'msDS-GroupMSAMembership', raw=True))
            processed_aces = self.resolve_aces(aces)

            for ace in processed_aces:
                if ace['RightName'] == 'Owner':
                    continue
                ace['RightName'] = 'ReadGMSAPassword'
                user['Aces'].append(ace)

        # parse ACL
        aces = self.parse_acl(user, 'user', ADUtils.get_entry_property(entry, 'nTSecurityDescriptor', raw=True))
        user['Aces'] += self.resolve_aces(aces)

        self.numUsers += 1
        self.writeQueues["users"].put(user)
        return True

    @functools.lru_cache(maxsize=4096)
    def resolve_aces(self, aces):
        aces_out = []
        for ace in aces:
            out = {
                'RightName': ace['rightname'],
                'IsInherited': ace['inherited']
            }
            # Is it a well-known sid?
            if ace['sid'] in ADUtils.WELLKNOWN_SIDS:
                out['PrincipalSID'] = u'%s-%s' % (self.domainname.upper(), ace['sid'])
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
    def _parse_acl_cached(self, parselaps, entrytype, acl): 
        fake_entry = {"Properties":{"haslaps": True if parselaps else False}} 
        _, aces = parse_binary_acl(fake_entry, entrytype, acl, self.objecttype_guid_map)

        # freeze result so we can cache it for resolve_aces function
        for i, ace in enumerate(aces):
            aces[i] = frozendict(ace)
        return frozenset(aces)

    def parse_acl(self, entry, entrytype, acl):
        parselaps = entrytype == 'computer' and entry['Properties']['haslaps'] and "ms-mcs-admpwd" in self.objecttype_guid_map
        aces = self._parse_acl_cached(parselaps, entrytype, acl)
        self.cacheInfo = self._parse_acl_cached.cache_info()
        return aces

    # kinda useless I'm guessing as we're staying in the local domain?
    @functools.lru_cache(maxsize=2048)
    def resolve_sid(self, sid):
        out = {}
        # Is it a well-known sid?
        if sid in ADUtils.WELLKNOWN_SIDS:
            out['ObjectID'] = u'%s-%s' % (self.domainname.upper(), sid)
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
            "ObjectIdentifier": resolved_entry['objectid'],
            "ObjectType": resolved_entry['type'].capitalize()
        }


    def write_default_users(self):
        user = {
            "AllowedToDelegate": [],
            "ObjectIdentifier": "%s-S-1-5-20" % self.domainname.upper(),
            "PrimaryGroupSID": None,
            "Properties": {
                "domain": self.domainname.upper(),
                "domainsid": self.domainsid,
                "name": "NT AUTHORITY@%s" % self.domainname.upper(),
                "highvalue": False,
            },
            "Aces": [],
            "SPNTargets": [],
            "HasSIDHistory": [],
            "IsDeleted": False,
            "ContainedBy": None,
            "IsACLProtected": False,
        }
        self.writeQueues["users"].put(user)


    def write_default_groups(self):
        group = {
            "ObjectIdentifier": "%s-S-1-5-9" % self.domainname.upper(),
            "Properties": {
                "domain": self.domainname.upper(),
                "domainsid": self.domainsid,
                "name": "ENTERPRISE DOMAIN CONTROLLERS@%s" % self.domainname.upper()
            },
            "ContainedBy": None,
            "Members": [],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None
        }

        for dc in self.domaincontrollers:
            entry = self.snap.getObject(dc)
            resolved_entry = ADUtils.resolve_ad_entry(entry)
            memberdata = {
                "ObjectIdentifier": resolved_entry['objectid'],
                "ObjectType": resolved_entry['type'].capitalize()
            }
            group["Members"].append(memberdata)

        self.writeQueues["groups"].put(group)

        # Everyone
        evgroup = {
            "ObjectIdentifier": "%s-S-1-1-0" % self.domainname.upper(),
            "Properties": {
                "domain": self.domainname.upper(),
                "domainsid": self.domainsid,
                "name": "EVERYONE@%s" % self.domainname.upper()
            },
            "Members": [],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None
        }
        self.writeQueues["groups"].put(evgroup)

        # Authenticated users
        augroup = {
            "ObjectIdentifier": "%s-S-1-5-11" % self.domainname.upper(),
            "Properties": {
                "domain": self.domainname.upper(),
                "domainsid": self.domainsid,
                "name": "AUTHENTICATED USERS@%s" % self.domainname.upper()
            },
            "Members": [],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None
        }
        self.writeQueues["groups"].put(augroup)

        # Interactive
        iugroup = {
            "ObjectIdentifier": "%s-S-1-5-4" % self.domainname.upper(),
            "Properties": {
                "domain": self.domainname.upper(),
                "domainsid": self.domainsid,
                "name": "INTERACTIVE@%s" % self.domainname.upper()
            },
            "Members": [],
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
            "ContainedBy": None
        }
        self.writeQueues["groups"].put(iugroup)



    def security_to_bloodhound_aces(self, security: ActiveDirectorySecurity) -> List:
        aces = []
        principal_type = ""

        owner_sid = security.owner
        if owner_sid in ADUtils.WELLKNOWN_SIDS:
            principal = u'%s-%s' % (self.domainname.upper(), owner_sid)
            principal_type = ADUtils.WELLKNOWN_SIDS[owner_sid][1].capitalize()
        else:
            try:
                entry = self.snap.getObject(self.sidcache[owner_sid])
                resolved_entry = ADUtils.resolve_ad_entry(entry)
                principal_type = resolved_entry['type']
            except KeyError:
                entry = {
                    'type': 'Unknown',
                    'principal': owner_sid
                }
        aces.append(
            {
                "PrincipalSID": owner_sid,
                "PrincipalType": principal_type,
                "RightName": "Owner",
                "IsInherited": False,
            }
        )

        for sid, rights in security.aces.items():
            principal = sid
            principal_type = ""



            if sid in ADUtils.WELLKNOWN_SIDS:
                principal = u'%s-%s' % (self.domainname.upper(), sid)
                principal_type = ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
            else:
                try:
                    entry = self.snap.getObject(self.sidcache[sid])
                    resolved_entry = ADUtils.resolve_ad_entry(entry)
                    principal_type = resolved_entry['type']
                except KeyError:
                    entry = {
                        'type': 'Unknown',
                        'principal': sid
                    }

            try:
                standard_rights = list(rights["rights"])
            except:
                standard_rights = rights["rights"].to_list()

            for right in standard_rights:
                aces.append(
                    {
                        "PrincipalSID": principal,
                        "PrincipalType": principal_type,
                        "RightName": str(right),
                        "IsInherited": False,
                    }
                )

            extended_rights = rights["extended_rights"]

            for extended_right in extended_rights:
                aces.append(
                    {
                        "PrincipalSID": principal,
                        "PrincipalType": principal_type,
                        "RightName": EXTENDED_RIGHTS_MAP[extended_right].replace(
                            "-", ""
                        )
                        if extended_right in EXTENDED_RIGHTS_MAP
                        else extended_right,
                        "IsInherited": False,
                    }
                )

        return aces


    def ca_security_to_bloodhound_aces(self, security: ActiveDirectorySecurity) -> List:
        aces = []
        principal_type = ""

        for sid, rights in security.aces.items():
            principal = sid
            principal_type = ""

            if sid in ADUtils.WELLKNOWN_SIDS:
                principal = u'%s-%s' % (self.domainname.upper(), sid)
                principal_type = ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
            else:
                try:
                    entry = self.snap.getObject(self.sidcache[sid])
                    resolved_entry = ADUtils.resolve_ad_entry(entry)
                    principal_type = resolved_entry['type']
                except KeyError:
                    entry = {
                        'type': 'Unknown',
                        'principal': sid
                    }

            try:
                standard_rights = list(rights["rights"])
            except:
                standard_rights = rights["rights"].to_list()
            

            for right in standard_rights:
                if not principal_type == "Computer":
                    aces.append(
                        {
                            "PrincipalSID": principal,
                            "PrincipalType": principal_type,
                            "RightName": str(right),
                            "IsInherited": False,
                        }
                    )

            extended_rights = rights["extended_rights"]

            for extended_right in extended_rights:
                aces.append(
                    {
                        "PrincipalSID": principal,
                        "PrincipalType": principal_type,
                        "RightName": EXTENDED_RIGHTS_MAP[extended_right].replace(
                            "-", ""
                        )
                        if extended_right in EXTENDED_RIGHTS_MAP
                        else extended_right,
                        "IsInherited": False,
                    }
                )

        return aces

def main():

    parser = argparse.ArgumentParser(add_help=True, description='AD Explorer snapshot ingestor for BloodHound', formatter_class=argparse.RawDescriptionHelpFormatter)

    parser.add_argument('snapshot', type=argparse.FileType('rb'), help="Path to the snapshot .dat file.")
    parser.add_argument('-o', '--output', required=False, type=pathlib.Path, help="Path to the *.json output folder. Folder will be created if it doesn't exist. Defaults to the current directory.", default=".")
    parser.add_argument('-m', '--mode', required=False, help="The output mode to use. Besides BloodHound JSON output files, it is possible to dump all objects with all attributes to NDJSON or LDIF formats. Defaults to BloodHound output mode.", choices=ADExplorerSnapshot.OutputMode.__members__, default='BloodHound')

    args = parser.parse_args()

    # add basic config for logging module to use pwnlib logging also in bloodhound libs
    logging.basicConfig(handlers=[pwnlib.log.console])
    log = pwnlib.log.getLogger(__name__)
    log.setLevel(20)

    if pwnlib.term.can_init():
        pwnlib.term.init()
    log.term_mode = pwnlib.term.term_mode

    if not os.path.exists(args.output):
        try:
            os.mkdir(args.output)
        except:
            log.error(f"Unable to create output directory '{args.output}'.")
            return
    
    if not os.path.isdir(args.output):
        log.warn(f"Path '{args.output}' does not exist or is not a folder.")
        parser.print_help()
        return
    
    ades = ADExplorerSnapshot(args.snapshot, args.output, log)

    outputmode = ADExplorerSnapshot.OutputMode[args.mode]
    if outputmode == ADExplorerSnapshot.OutputMode.BloodHound:
        ades.outputBloodHound()
    if outputmode == ADExplorerSnapshot.OutputMode.Objects:
        ades.outputObjects()
    if outputmode == ADExplorerSnapshot.OutputMode.LDIF:
        ades.outputLDIF()

if __name__ == '__main__':
    main()

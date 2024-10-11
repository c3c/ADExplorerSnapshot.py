# Script to dump Certificate information
# author: @oddvarmoe

from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
from datetime import datetime, timedelta, timezone
from certipy.lib.constants import *
from certipy.lib.security import ActiveDirectorySecurity, CertifcateSecurity as CertificateSecurity, CASecurity
from certipy.commands.find import filetime_to_str
from pathlib import Path
import argparse
import os
from typing import List

def valid_directory(path):
    """Check if the provided path is a valid directory or create it if it does not exist."""
    path = Path(path) 
    if not path.exists():
        # Attempt to create the directory
        try:
            path.mkdir(parents=True, exist_ok=True)
            #print(f"Directory created at {path}")
        except OSError as e:
            # If creation fails, raise an argparse error
            raise argparse.ArgumentTypeError(f"Could not create directory: {path}. {str(e)}")
    elif not path.is_dir():
        # If the path exists but is not a directory, raise an error
        raise argparse.ArgumentTypeError(f"The path {path} exists but is not a directory.")
    return path

parser = argparse.ArgumentParser(add_help=True, description="Script to dump interesting stuff from an AdExplorer snapshot", formatter_class=argparse.RawDescriptionHelpFormatter)
parser.add_argument("snapshot", type=argparse.FileType("rb"), help="Path to the snapshot file")
parser.add_argument("-o", "--output_folder", required=True, type=valid_directory, help="Folder to save output to")
parser.add_argument("-e", "--enabled", required=False, help="Only get enabled templates", action="store_true")
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

# Out streams
out_certs = []

def resolve_aces(aces):
    print(aces.RIGHTS_TYPE)

def security_to_bloodhound_aces(security: ActiveDirectorySecurity) -> List:
        aces = []
        principal_type = ""

        owner_sid = security.owner
        if owner_sid in ADUtils.WELLKNOWN_SIDS:
            principal = u'%s-%s' % (ADUtils.ldap2domain(ades.rootdomain).upper(), owner_sid)
            principal_type = ADUtils.WELLKNOWN_SIDS[owner_sid][1].capitalize()
            principal_accountname = ADUtils.WELLKNOWN_SIDS[sid][0]
        else:
            try:
                entry = ades.snap.getObject(ades.sidcache[owner_sid])
                resolved_entry = ADUtils.resolve_ad_entry(entry)
                principal_type = resolved_entry['type']
                principal_accountname = ADUtils.get_entry_property(entry, 'SamAccountName')
            except KeyError:
                principal_accountname = "Unknown"
                principal_type = "Unknown"
        aces.append(
            {
                "Principal AccountName": principal_accountname,
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
                principal = u'%s-%s' % (ADUtils.ldap2domain(ades.rootdomain).upper(), sid)
                principal_type = ADUtils.WELLKNOWN_SIDS[sid][1].capitalize()
                principal_accountname = ADUtils.WELLKNOWN_SIDS[sid][0]
            else:
                try:
                    entry = ades.snap.getObject(ades.sidcache[sid])
                    resolved_entry = ADUtils.resolve_ad_entry(entry)
                    principal_type = resolved_entry['type']
                    principal_accountname = ADUtils.get_entry_property(entry, 'SamAccountName')
                except KeyError:
                    principal_accountname = "Unknown"
                    principal_type = "Unknown"

            try:
                standard_rights = list(rights["rights"])
            except:
                standard_rights = rights["rights"].to_list()

            for right in standard_rights:
                aces.append(
                    {
                        "Principal AccountName": principal_accountname,
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
                        "Principal AccountName": principal_accountname,
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

prog = log.progress(f"Going through objects and outputting to files", rate=0.1)
domainname = ADUtils.ldap2domain(ades.rootdomain).upper()

for idx,obj in enumerate(ades.snap.objects):
    object_resolved = ADUtils.resolve_ad_entry(obj)
    
    if 'pkicertificatetemplate' in obj.classes:
        name = ADUtils.get_entry_property(obj, 'name')
        if args.enabled:
            if (name in ades.certtemplates) == False:
                continue
            
        # Enable check if cert is under any CA (e.g. enabled)
        enabled = name in ades.certtemplates
        object_identifier = ADUtils.get_entry_property(obj, 'objectGUID')
        validity_period = filetime_to_str(ADUtils.get_entry_property(obj, 'pKIExpirationPeriod'))
        renewal_period = filetime_to_str(ADUtils.get_entry_property(obj, 'pKIOverlapPeriod'))
        
        schema_version = ADUtils.get_entry_property(obj, 'msPKI-Template-Schema-Version', 0)

        certificate_name_flag = ADUtils.get_entry_property(obj, 'msPKI-Certificate-Name-Flag', 0)
        certificate_name_flag = MS_PKI_CERTIFICATE_NAME_FLAG(int(certificate_name_flag))

        enrollment_flag = ADUtils.get_entry_property(obj, 'msPKI-Enrollment-Flag', 0)
        enrollment_flag = MS_PKI_ENROLLMENT_FLAG(int(enrollment_flag))

        authorized_signatures_required = int(ADUtils.get_entry_property(obj, 'msPKI-RA-Signature', 0))

        application_policies = ADUtils.get_entry_property(obj, 'msPKI-RA-Application-Policies', raw=True, default=[])
        application_policies = list(
            map(
                lambda x: OID_TO_STR_MAP[x] if x in OID_TO_STR_MAP else x,
                application_policies,
            )
        )

        extended_key_usage = ADUtils.get_entry_property(obj, "pKIExtendedKeyUsage", default=[])
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
                MS_PKI_CERTIFICATE_NAME_FLAG.ENROLLEE_SUPPLIES_SUBJECT,
            ]
        )

        requires_manager_approval = (
            MS_PKI_ENROLLMENT_FLAG.PEND_ALL_REQUESTS in enrollment_flag
        )

        security = CertificateSecurity(ADUtils.get_entry_property(obj, "nTSecurityDescriptor", raw=True))

        aces = security_to_bloodhound_aces(security)

        # Could be useful later if we want to output to JSON
        # certtemplate = {
        #     'Properties': {
        #         'highvalue': (
        #         enabled
        #         and any(
        #             [
        #             all(
        #                 [
        #                 enrollee_supplies_subject,
        #                 not requires_manager_approval,
        #                 client_authentication,
        #                 ]
        #             ),
        #             all([enrollment_agent, not requires_manager_approval]),
        #             ]
        #         )
        #         ),
        #     'name': "%s@%s"
        #     % (
        #         ADUtils.get_entry_property(obj, "CN").upper(),
        #         domainname
        #     ),
        #     'type': 'Certificate Template',
        #     'domain': domainname,
        #     'Schema Version': schema_version,
        #     'Template Name': ADUtils.get_entry_property(obj, 'CN'),
        #     'Display Name': ADUtils.get_entry_property(obj, 'displayName'),
        #     'Client Authentication': client_authentication,
        #     'Enrollee Supplies Subject': enrollee_supplies_subject,
        #     'Extended Key Usage': extended_key_usage,
        #     'Requires Manager Approval': requires_manager_approval,
        #     'Validity Period': validity_period,
        #     'Renewal Period': renewal_period,
        #     'Certificate Name Flag': certificate_name_flag.to_str_list(),
        #     'Enrollment Flag': enrollment_flag.to_str_list(),
        #     'Authorized Signatures Required': authorized_signatures_required,
        #     'Application Policies': application_policies,
        #     'Enabled': enabled,
        #     'Certificate Authorities': list(ades.certtemplates[name]),
        #     },          
        #     'ObjectIdentifier': object_identifier.lstrip("{").rstrip("}"), 
        #     'Aces': aces,
        # }
        out_certs.append(f"-----------------------------------------")
        out_certs.append(f"Enabled: {enabled}")
        out_certs.append(f"CA Name: {list(ades.certtemplates[name])}")
        out_certs.append(f"Template Name: {ADUtils.get_entry_property(obj, 'CN')}")
        out_certs.append(f"Display Name: {ADUtils.get_entry_property(obj, 'displayName')}")
        out_certs.append(f"Schema Version: {schema_version}")        
        out_certs.append(f"Validity Period: {validity_period}")
        out_certs.append(f"Renewal Period: {renewal_period}")
        out_certs.append(f"Client Authentication: {client_authentication}")        
        out_certs.append(f"Enrollee Supplies Subject: {enrollee_supplies_subject}")
        out_certs.append(f"Enrollment Flag: {enrollment_flag.to_str_list()}")
        out_certs.append(f"Authorized Signatures Required: {authorized_signatures_required}")
        out_certs.append(f"Extended Key Usage: {extended_key_usage}")
        out_certs.append(f"Requires Manager Approval: {requires_manager_approval}")
        out_certs.append(f"Certificate Name Flag: {certificate_name_flag.to_str_list()}")
        out_certs.append(f"Application Policies: {application_policies}")
        out_certs.append(f"Aces:")
        for ace in aces:
            out_certs.append(f"{ace}")
        out_certs.append("\n")

    prog.status(f"{idx+1}/{ades.snap.header.numObjects}")

if args.output_folder:
    if out_certs:
        outFile_certs = open(Path(args.output_folder / "certs.txt"), "w")
        outFile_certs.write(os.linesep.join(out_certs))

    log.info(f"Output written to files in {args.output_folder}")

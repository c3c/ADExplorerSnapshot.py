# Script to dump Certificate information
# author: @oddvarmoe

from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
from datetime import datetime, timedelta, timezone
from certipy.lib.constants import *
from certipy.lib.security import ActiveDirectorySecurity, CertifcateSecurity as CertificateSecurity, CASecurity
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
out_gpo = []

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
    if 'grouppolicycontainer' in obj.classes:
        name = ADUtils.get_entry_property(obj, 'name')
        displayname = ADUtils.get_entry_property(obj, 'displayname')
        gpcfilesyspath = ADUtils.get_entry_property(obj, 'gpcfilesyspath')
        flags = ADUtils.get_entry_property(obj, 'flags')
        if flags == 0:
            flags = str(flags) + " (GPO is enabled)"
        elif flags == 1:
            flags = str(flags) + " (User part of GPO is disabled)"
        elif flags == 2:
            flags = str(flags) + " (Computer part of GPO is disabled)"
        elif flags == 3:
            flags = str(flags) + " (GPO is disabled)"
        gpcmachineextensionnames = ADUtils.get_entry_property(obj, 'gpcmachineextensionnames')
        versionnumber = ADUtils.get_entry_property(obj, 'versionnumber')
        # Extract user and computer versions
        user_version = versionnumber >> 16
        computer_version = versionnumber & 0xFFFF

        # Convert to human readable timestamp
        whenchanged = datetime.utcfromtimestamp(ADUtils.get_entry_property(obj, 'whenchanged')).strftime('%Y-%m-%d %H:%M:%S')
        whencreated = datetime.utcfromtimestamp(ADUtils.get_entry_property(obj, 'whencreated')).strftime('%Y-%m-%d %H:%M:%S')

        security = CertificateSecurity(ADUtils.get_entry_property(obj, "nTSecurityDescriptor", raw=True))

        aces = security_to_bloodhound_aces(security)

        out_gpo.append(f"-----------------------------------------")
        out_gpo.append(f"Displayname: {displayname}")
        out_gpo.append(f"Name: {name}")
        out_gpo.append(f"gPCFileSysPath: {gpcfilesyspath}")
        out_gpo.append(f"Flags: {flags}")
        out_gpo.append(f"gPCMachineExtensionNames: {gpcmachineextensionnames}")
        out_gpo.append(f"versionNumber: {versionnumber} (UserVersion: {user_version} / ComputerVersion: {computer_version})")
        out_gpo.append(f"whenChanged: {whenchanged}")
        out_gpo.append(f"whenCreated: {whencreated}")
        out_gpo.append(f"Aces:")
        for ace in aces:
            out_gpo.append(f"{ace}")

    prog.status(f"{idx+1}/{ades.snap.header.numObjects}")

if args.output_folder:
    if out_gpo:
        outFile_gpo = open(Path(args.output_folder / "gpo.txt"), "w")
        outFile_gpo.write(os.linesep.join(map(str, out_gpo)))

    log.info(f"Output written to files in {args.output_folder}")

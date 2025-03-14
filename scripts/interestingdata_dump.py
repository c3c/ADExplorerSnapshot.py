# Script to dump interesting AD stuff
# author: @oddvarmoe

from adexpsnapshot import ADExplorerSnapshot
import pwnlib.term, pwnlib.log, logging
from bloodhound.ad.utils import ADUtils
from datetime import datetime, timedelta, timezone
from pathlib import Path
import argparse
import os

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

def convert_ad_timestamp(timestamp):
    if timestamp is None:
        return None
    base_date = datetime(1601, 1, 1, tzinfo=timezone.utc) # Base date for Windows File Time (January 1, 1601)
    return base_date + timedelta(microseconds=timestamp / 10) # Convert the timestamp (in 100-nanosecond intervals) to microseconds (/10) and add to base date
    

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
out_computers = []
out_active_servers = []
out_users = []
out_sccm = []
out_sccm_potential_pxe = [] 
out_groups = []
out_printers = []
out_shares = []
out_laps = []
out_asreproast = []
out_unconstraineddelegation = []
out_userspn = []
out_plaintextpwd = []
out_pwdnotreqd = []
out_precreated = []
out_sql_systems = []

# Attributes to check for plaintext passwords
plaintext_pwd_attributes = ['UserPassword','UnixUserPassword','unicodePwd','msSFU30Password','orclCommonAttribute','os400Password']


# Add headers
out_computers.append("samaccountname||dnshostname||description||distinguishedName||operatingsystem||operatingsystemversion||useraccountcontrol||lastlogontimestamp||logoncount||pwdlastset||objectsid||memberof")
out_active_servers.append("samaccountname||dnshostname||operatingsystem||operatingsystemversion||description||lastlogontimestamp")
out_users.append("samaccountname||distinguishedName||description||useraccountcontrol||lastlogontimestamp||logoncount||pwdlastset||badpwdcount||badpasswordtime||objectsid||memberof||msds_allowedtoactonbehalfofotheridentity||title")
out_groups.append("cn||samaccountname||distinguishedName||description||objectsid||member||memberof")
out_sccm.append("mssmsmpname||dnshostname||distinguishedname||mssmssitecode||mssmsversion")
out_sccm_potential_pxe.append("distinguishedname")
out_printers.append("name||uncname||distinguishedname||servername||location||drivername||driverversion")
out_shares.append("name||uncname||distinguishedname")
out_laps.append("dnshostname||ms_mcs_admpwd||ms_mcs_admpwdexpirationtime")
out_asreproast.append("samaccountname||distinguishedName||lastlogontimestamp")
out_unconstraineddelegation.append("samaccountname||dnshostname||distinguishedName")
out_userspn.append("samaccountname||distinguishedName||serviceprincipalname||pwdlastset||logoncount")
out_plaintextpwd.append("samaccountname||distinguishedName||attribute")
out_pwdnotreqd.append("samaccountname||distinguishedName||useraccountcontrol||logoncount")
out_precreated.append("samaccountname||useraccountcontrol||pwdlastset||whencreated||description")
out_sql_systems.append("samaccountname||dnshostname||operatingsystem||operatingsystemversion||description||lastlogontimestamp")

prog = log.progress(f"Going through objects and outputting to files", rate=0.1)    
for idx,obj in enumerate(ades.snap.objects):
    # get computers
    object_resolved = ADUtils.resolve_ad_entry(obj)
    if object_resolved['type'] == 'Computer':
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        dnshostname = ADUtils.get_entry_property(obj, 'dnshostname')
        description = ADUtils.get_entry_property(obj, 'description')
        distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
        operatingsystem = ADUtils.get_entry_property(obj, 'operatingsystem')
        operatingsystemversion = ADUtils.get_entry_property(obj, 'operatingsystemversion')
        useraccountcontrol = ADUtils.get_entry_property(obj, 'useraccountcontrol')
        lastlogontimestamp = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'lastlogontimestamp'))
        whencreated = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'whencreated'))
        pwdlastset = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'pwdlastset'))
        objectsid = ADUtils.get_entry_property(obj, 'objectsid')
        memberof = ADUtils.get_entry_property(obj, 'memberof')
        msds_allowedtoactonbehalfofotheridentity = ADUtils.get_entry_property(obj, 'msds-allowedtoactonbehalfofotheridentity')
        serviceprincipalname = ADUtils.get_entry_property(obj, 'serviceprincipalname')
        logoncount = ADUtils.get_entry_property(obj, 'logoncount')
        
        if serviceprincipalname:
            # Ensure serviceprincipalname is a list or iterable before checking for "MSSQLSvc"
            if isinstance(serviceprincipalname, str):
                serviceprincipalname = [serviceprincipalname] 
            
            if any("MSSQLSvc" in spn for spn in serviceprincipalname): # Can easily add more things to output based on SPN
                out_sql_systems.append(f"{samaccountname}||{dnshostname}||{operatingsystem}||{operatingsystemversion}||{description}||{lastlogontimestamp}")

        # Active servers
        if operatingsystem and 'server' in operatingsystem.lower():
            if lastlogontimestamp is not None and (snapshot_time - lastlogontimestamp) <= timedelta(days=30):
                out_active_servers.append(f"{samaccountname}||{dnshostname}||{operatingsystem}||{operatingsystemversion}||{description}||{lastlogontimestamp}")
        
        # LAPS
        ms_mcs_admpwd = ADUtils.get_entry_property(obj, 'ms-Mcs-AdmPwd')
        if ms_mcs_admpwd:
            ms_mcs_admpwdexpirationtime = ADUtils.get_entry_property(obj, 'ms-Mcs-AdmPwdExpirationTime')
            out_laps.append(f"{dnshostname}||{ms_mcs_admpwd}||{ms_mcs_admpwdexpirationtime}")
        
        # Check for asreproast
        if useraccountcontrol is not None and useraccountcontrol & 4194304:
            out_asreproast.append(f"{samaccountname}||{distinguishedName}||{lastlogontimestamp}")
        
        # Check for unconstrained delegation
        if useraccountcontrol is not None and useraccountcontrol & 524288:
            out_unconstraineddelegation.append(f"{samaccountname}||{dnshostname}||{distinguishedName}")

        # Check for pwdnotreqd
        if useraccountcontrol is not None and useraccountcontrol & 32:
            out_pwdnotreqd.append(f"{samaccountname}||{distinguishedName}||{useraccountcontrol}||{logoncount}")
        
        # Check for pre created computer accounts 
        if not lastlogontimestamp:
            out_precreated.append(f"{samaccountname}||{useraccountcontrol}||{pwdlastset}||{whencreated}||{description}")
        
        out_computers.append(f"{samaccountname}||{dnshostname}||{description}||{distinguishedName}||{operatingsystem}||{operatingsystemversion}||{useraccountcontrol}||{lastlogontimestamp}||{logoncount}||{pwdlastset}||{objectsid}||{memberof}||{msds_allowedtoactonbehalfofotheridentity}")

    # # get users
    elif object_resolved['type'] == 'User':
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
        description = ADUtils.get_entry_property(obj, 'description')
        useraccountcontrol = ADUtils.get_entry_property(obj, 'useraccountcontrol')
        lastlogontimestamp = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'lastlogontimestamp'))
        logoncount = ADUtils.get_entry_property(obj, 'logoncount')
        pwdlastset = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'pwdlastset'))
        badpwdcount = ADUtils.get_entry_property(obj, 'badpwdcount')
        badpasswordtime = convert_ad_timestamp(ADUtils.get_entry_property(obj, 'badpasswordtime'))
        objectsid = ADUtils.get_entry_property(obj, 'objectsid')
        memberof = ADUtils.get_entry_property(obj, 'memberof')
        msds_allowedtoactonbehalfofotheridentity = ADUtils.get_entry_property(obj, 'msds-allowedtoactonbehalfofotheridentity')
        title = ADUtils.get_entry_property(obj, 'title')

        # Check for asreproast
        if useraccountcontrol is not None and useraccountcontrol & 4194304:
            out_asreproast.append(f"{samaccountname}||{distinguishedName}||{lastlogontimestamp}")
        
        # Check for service principal names / Kerberoast
        serviceprincipalname = ADUtils.get_entry_property(obj, 'serviceprincipalname')
        if serviceprincipalname:
            out_userspn.append(f"{samaccountname}||{distinguishedName}||{serviceprincipalname}||{pwdlastset}||{logoncount}")
        
        # Check special attributes (Potential plaintext passwords)
        for attr in plaintext_pwd_attributes:
            if ADUtils.get_entry_property(obj, attr):
                out_plaintextpwd.append(f"{samaccountname}||{distinguishedName}||{attr}:{ADUtils.get_entry_property(obj, attr)}")

        # Check for pwdnotreqd
        if useraccountcontrol is not None and useraccountcontrol & 32:
            out_pwdnotreqd.append(f"{samaccountname}||{distinguishedName}||{useraccountcontrol}||{logoncount}")

        out_users.append(f"{samaccountname}||{distinguishedName}||{description}||{useraccountcontrol}||{lastlogontimestamp}||{logoncount}||{pwdlastset}||{badpwdcount}||{badpasswordtime}||{objectsid}||{memberof}||{msds_allowedtoactonbehalfofotheridentity}||{title}")
        
    # get groups
    elif object_resolved['type'] == 'Group':
        cn = ADUtils.get_entry_property(obj, 'cn')
        samaccountname = ADUtils.get_entry_property(obj, 'samaccountname')
        distinguishedName = ADUtils.get_entry_property(obj, 'distinguishedName')
        description = ADUtils.get_entry_property(obj, 'description')
        objectsid = ADUtils.get_entry_property(obj, 'objectsid')
        member = ADUtils.get_entry_property(obj, 'member')
        memberof = ADUtils.get_entry_property(obj, 'memberof')
        out_groups.append(f"{cn}||{samaccountname}||{distinguishedName}||{description}||{objectsid}||{member}||{memberof}")
    
    elif object_resolved['type'] == 'Base':
        if "connectionPoint" in ADUtils.get_entry_property(obj, 'objectClass', "0"): 
            if "-Remote-Installation-Services" in ADUtils.get_entry_property(obj, 'cn', "0"): 
                _, server_dn = ADUtils.get_entry_property(obj, 'distinguishedName', "0").split(',', 1)
                out_sccm_potential_pxe.append(server_dn)
        # get sccm mp
        if "mSSMSManagementPoint" in ADUtils.get_entry_property(obj, 'objectClass', "0"): 
            mssmsmpname = ADUtils.get_entry_property(obj, 'mssmsmpname')
            dnshostname = ADUtils.get_entry_property(obj, 'dnshostname')
            distinguishedname = ADUtils.get_entry_property(obj, 'distinguishedName')
            mssmssitecode = ADUtils.get_entry_property(obj, 'mssmssitecode')
            mssmsversion = ADUtils.get_entry_property(obj, 'mssmsversion')
            out_sccm.append(f"{mssmsmpname}||{dnshostname}||{distinguishedname}||{mssmssitecode}||{mssmsversion}")
        # get printers
        if "printQueue" in ADUtils.get_entry_property(obj, 'objectClass', "0"):
            name = ADUtils.get_entry_property(obj, 'name')
            uncname = ADUtils.get_entry_property(obj, 'uncname')
            distinguishedname = ADUtils.get_entry_property(obj, 'distinguishedname')
            servername = ADUtils.get_entry_property(obj, 'servername')
            location = ADUtils.get_entry_property(obj, 'location')
            drivername = ADUtils.get_entry_property(obj, 'drivername')
            driverversion = ADUtils.get_entry_property(obj, 'driverversion')
            out_printers.append(f"{name}||{uncname}||{distinguishedname}||{servername}||{location}||{drivername}||{driverversion}")
            
        # get shares
        if "volume" in ADUtils.get_entry_property(obj, 'objectClass', "0"):
            name = ADUtils.get_entry_property(obj, 'name')
            uncname = ADUtils.get_entry_property(obj, 'uncname')
            distinguishedname = ADUtils.get_entry_property(obj, 'distinguishedname')
            out_shares.append(f"{name}||{uncname}||{distinguishedname}")

    prog.status(f"{idx+1}/{ades.snap.header.numObjects}")



if args.output_folder:
    if out_computers:
        outFile_comp = open(Path(args.output_folder / "computers.txt"), "w")
        outFile_comp.write(os.linesep.join(out_computers))
    
    if out_active_servers:
        outFile_active_servers = open(Path(args.output_folder / "active_servers.txt"), "w")
        outFile_active_servers.write(os.linesep.join(out_active_servers))

    if out_users:
        outFile_user = open(Path(args.output_folder / "users.txt"), "w")
        outFile_user.write(os.linesep.join(out_users))

    if out_sccm:
        outFile_sccm = open(Path(args.output_folder / "sccm.txt"), "w")
        outFile_sccm.write(os.linesep.join(out_sccm))

    if out_groups:
        outFile_groups = open(Path(args.output_folder / "groups.txt"), "w")
        outFile_groups.write(os.linesep.join(out_groups))

    if out_printers:
        outFile_printers = open(Path(args.output_folder / "printers.txt"), "w")
        outFile_printers.write(os.linesep.join(out_printers))

    if out_shares:
        outFile_shares = open(Path(args.output_folder / "shares.txt"), "w")
        outFile_shares.write(os.linesep.join(out_shares))

    if out_laps:
        outFile_laps = open(Path(args.output_folder / "laps.txt"), "w")
        outFile_laps.write(os.linesep.join(out_laps))

    if out_asreproast:
        outFile_asreproast = open(Path(args.output_folder / "asreproast.txt"), "w")
        outFile_asreproast.write(os.linesep.join(out_asreproast))

    if out_unconstraineddelegation:
        outFile_unconstraineddelegation = open(Path(args.output_folder / "unconstraineddelegation.txt"), "w")
        outFile_unconstraineddelegation.write(os.linesep.join(out_unconstraineddelegation))

    if out_userspn:
        outFile_userspn = open(Path(args.output_folder / "userspn.txt"), "w")
        outFile_userspn.write(os.linesep.join(out_userspn))

    if out_plaintextpwd:
        outFile_plaintextpwd = open(Path(args.output_folder / "plaintextpwd.txt"), "w")
        outFile_plaintextpwd.write(os.linesep.join(out_plaintextpwd))

    if out_pwdnotreqd:
        outFile_pwdnotreqd = open(Path(args.output_folder / "pwdnotreqd.txt"), "w")
        outFile_pwdnotreqd.write(os.linesep.join(out_pwdnotreqd))

    if out_precreated:
        outFile_precreated = open(Path(args.output_folder / "precreated.txt"), "w")
        outFile_precreated.write(os.linesep.join(out_precreated))

    if out_sccm_potential_pxe:
        outFile_sccm_potential_pxe = open(Path(args.output_folder / "sccm_potential_pxe.txt"), "w")
        outFile_sccm_potential_pxe.write(os.linesep.join(out_sccm_potential_pxe))

    if out_sql_systems:
        outFile_sql_systems = open(Path(args.output_folder / "sql_systems.txt"), "w")
        outFile_sql_systems.write(os.linesep.join(out_sql_systems))

    log.info(f"Output written to files in {args.output_folder}")

from adexpsnapshot.parser.structure import structure
from bloodhound.ad.utils import ADUtils
from bloodhound.enumeration.acls import LdapSid
from requests.structures import CaseInsensitiveDict

import functools
import hashlib, os, tempfile, pickle #@
import uuid
from io import BytesIO

ADSTYPE_INVALID = 0
ADSTYPE_DN_STRING = 1
ADSTYPE_CASE_EXACT_STRING = 2
ADSTYPE_CASE_IGNORE_STRING = 3
ADSTYPE_PRINTABLE_STRING = 4
ADSTYPE_NUMERIC_STRING = 5
ADSTYPE_BOOLEAN = 6
ADSTYPE_INTEGER = 7
ADSTYPE_OCTET_STRING = 8
ADSTYPE_UTC_TIME = 9
ADSTYPE_LARGE_INTEGER = 10
ADSTYPE_PROV_SPECIFIC = 11
ADSTYPE_OBJECT_CLASS = 12
ADSTYPE_CASEIGNORE_LIST = 13
ADSTYPE_OCTET_LIST = 14
ADSTYPE_PATH = 15
ADSTYPE_POSTALADDRESS = 16
ADSTYPE_TIMESTAMP = 17
ADSTYPE_BACKLINK = 18
ADSTYPE_TYPEDNAME = 19
ADSTYPE_HOLD = 20
ADSTYPE_NETADDRESS = 21
ADSTYPE_REPLICAPOINTER = 22
ADSTYPE_FAXNUMBER = 23
ADSTYPE_EMAIL = 24
ADSTYPE_NT_SECURITY_DESCRIPTOR = 25
ADSTYPE_UNKNOWN = 26
ADSTYPE_DN_WITH_BINARY = 27
ADSTYPE_DN_WITH_STRING = 28

class WrapStruct(object):
    def __init__(self, snap, in_obj=None):
        self.snap = snap
        self.fh = snap.fh
        self.log = snap.log

        if in_obj:
            self._data = in_obj
        else:
            self._data = getattr(structure, type(self).__name__)(self.fh)

    def __getattr__(self, attr):
        if attr.startswith('__') and attr.endswith('__'):
            raise AttributeError

        return getattr(self._data, attr)

class SystemTime(WrapStruct):
    def __init__(self, snap=None, in_obj=None):
        super().__init__(snap, in_obj)

        d = datetime.datetime(self.wYear, self.wMonth, self.wDay, self.wHour, self.wMinute, self.wSecond)
        self.unixtimestamp = calendar.timegm(d.timetuple())

    def __repr__(self):
        return str(self.unixtimestamp)

class Object(WrapStruct):
    def __init__(self, snap=None, in_obj=None):
        super().__init__(snap, in_obj)

        self.fileOffset = self.fh.tell() - 4 - 4 - (self.tableSize * 8)
        self.fh.seek(self.fileOffset + self.objSize) # move file pointer to the next object

        self.attributes = CaseInsensitiveDict()
        self.attributes_raw = CaseInsensitiveDict()

    @functools.lru_cache(maxsize=1)
    def getObjectClasses(self):
        return list(map(str.casefold, self.attributes.get('objectClass', [])))

    @functools.lru_cache(maxsize=1)
    def getObjectCategory(self):
        catDN = self.attributes.get('objectCategory', '')
        catObj = self.snap.classes.get(catDN, None)
        if catObj:
            return catObj.className.lower()
        else:
            return None

    # lower case list with short-hand values
    classes = property(getObjectClasses)
    category = property(getObjectCategory)

    # for easy compatibility with the bloodhound lib
    def __getitem__(self, key):
        if key == "attributes":
            return self.attributes
        elif key == "raw_attributes":
            return self.attributes_raw
        else:
            return None

    def processAttributes(self, onlyProcessAttributes=None):

        for m,entry in enumerate(self.mappingTable):
            prop = self.snap.properties[entry.attrIndex]
            attrName = prop.propName.casefold()

            if onlyProcessAttributes is not None: # if not set, process all attributes
                if attrName not in map(str.casefold, onlyProcessAttributes):
                    continue

            if attrName in self.attributes: # already processed
                    continue

            # at the offset at which the attribute is stored, 
            #  - the first quad indicates how many elements are in the attribute (attributes can be multi-valued), 
            #  - the bytes after depend on what sort of information is stored (e.g. for DN_STRING, the quads after are the offsets at which the element values are stored)

            fileAttrOffset = self.fileOffset + entry.attrOffset
            self.fh.seek(fileAttrOffset)
            numValues = structure.uint32(self.fh)
            values = []
            values_raw = []
            self.attributes[attrName] = values # below, we'll update the values list
            self.attributes_raw[attrName] = values_raw # below, we'll update the values list

            # https://docs.microsoft.com/en-us/windows/win32/api/iads/ns-iads-adsvalue
            # https://docs.microsoft.com/en-us/windows/win32/adsi/adsi-simple-data-types

            if prop.adsType in [ADSTYPE_DN_STRING, ADSTYPE_CASE_IGNORE_STRING, ADSTYPE_CASE_IGNORE_STRING, ADSTYPE_PRINTABLE_STRING, ADSTYPE_NUMERIC_STRING, ADSTYPE_OBJECT_CLASS]:
                offsets = structure.uint32[numValues](self.fh)

                for v in range(numValues):
                    self.fh.seek(fileAttrOffset + offsets[v]) # this can also be a negative offset, e.g. referencing data in a previous object
                    val = structure.wchar[None](self.fh)
                    values_raw.append(val)
                    values.append(val)

            elif prop.adsType == ADSTYPE_OCTET_STRING:
                lengths = structure.uint32[numValues](self.fh)

                for v in range(numValues):
                    octetStr = structure.char[lengths[v]](self.fh)
                    values_raw.append(octetStr)

                    if len(octetStr) == 16 and attrName.endswith("guid"):
                        val = uuid.UUID(bytes_le=octetStr)
                    elif attrName == 'objectsid':
                        val = str(LdapSid(BytesIO(octetStr)))
                    else:
                        val = octetStr.hex()

                    if attrName == 'sidhistory':
                        values.append(octetStr)
                    else:
                        values.append(val)

            elif prop.adsType == ADSTYPE_BOOLEAN:
                assert numValues == 1, ["Multiple boolean values, verify data size", self.fileOffset, attrName, self.attributes]

                for v in range(numValues):
                    val = bool(structure.uint32(self.fh)) # not sure if uint32 is correct type here, check against more data sets
                    values.append(val)
                    values_raw.append(val)

            elif prop.adsType == ADSTYPE_INTEGER:

                for v in range(numValues):
                    # defined as DWORD, so reading as uint32 (unsigned)
                    val = structure.uint32(self.fh)
                    values.append(val)
                    values_raw.append(val)

            elif prop.adsType == ADSTYPE_LARGE_INTEGER:

                for v in range(numValues):
                    # defined as LARGE_INTEGER, interestingly this is an int64 (signed) according to MS docs
                    val = structure.int64(self.fh)
                    values.append(val)
                    values_raw.append(val)

            elif prop.adsType == ADSTYPE_UTC_TIME:

                for v in range(numValues):
                    val = SystemTime(self)
                    values.append(val.unixtimestamp)
                    values_raw.append(val)

            elif prop.adsType == ADSTYPE_NT_SECURITY_DESCRIPTOR:

                for v in range(numValues):
                    lenDescriptorBytes = structure.uint32(self.fh)
                    descriptorBytes = self.fh.read(lenDescriptorBytes)
                    # commented out, parsing is handled bloodhound lib, and this will just take extra processing time
                    #val = secdesc.SecurityDescriptor(BytesIO(descriptorBytes))
                    #values.append(val)
                    values_raw.append(descriptorBytes)

            else:
                print("Unhandled adsType: %s -> %d" % (attrName, prop.adsType))

            # currently handling a number of single-valued attributes here
            # not complete list - this can be retrieved from the schema too, but hacking it in for now when needed...
            # ToDo: remove this, and rely on ADUtils to assume type instead
            if attrName in map(str.casefold, ['primaryGroupID', 'objectSid', 'sAMAccountType', 'userAccountControl', 'lDAPDisplayName', 'distinguishedName', 'objectCategory', 'systemFlags', 'nCName', 'dNSHostname', 'name']): 
                self.attributes[attrName] = values[0]
                self.attributes_raw[attrName] = values_raw[0]

class Property(WrapStruct):
    def __init__(self, snap=None, in_obj=None):
        super().__init__(snap, in_obj)
        self.propName = self.propName.rstrip('\x00')

class Class(WrapStruct):
    def __init__(self, snap=None, in_obj=None):
        super().__init__(snap, in_obj)

        self.className = self.className.rstrip('\x00')
        self.DN = self.DN.rstrip('\x00')
        self.schemaIDGUID = uuid.UUID(bytes_le=self.schemaIDGUID)


class Header(WrapStruct):
    def __init__(self, snap, in_obj=None):
        super().__init__(snap, in_obj)

        self.server = self.server.rstrip('\x00')
        self.mappingOffset = (self.fileoffsetHigh << 32) | self.fileoffsetLow
        self.filetimeUnix = ADUtils.win_timestamp_to_unix(self.filetime)

class Snapshot(object):
    def __init__(self, fh, log=None):
        self.fh = fh
        self.log = log
        self.objectOffsets = {}

        # the order in which we're parsing matters, due to the file handle's position
        # typically, you would call as follows:

        # self.parseHeader()
        # self.parseObjectOffsets()
        # self.parseProperties()
        # self.parseClasses()
        # self.parseRights()

    def parseHeader(self):
        self.fh.seek(0)
        self.header = Header(self)

    def parseObjectOffsets(self):
        self.fh.seek(0x43e)

        # we are only keeping offsets at this stage, as some databases grow very big

        cacheFileName = hashlib.md5(f"{self.header.filetime}_{self.header.server}".encode()).hexdigest() + ".cache"
        cachePath = os.path.join(tempfile.gettempdir(), cacheFileName)

        if self.log: 
            self.log.info(f"Object offset cache file: {cachePath}")

        if os.path.exists(cachePath):
            self.objectOffsets = pickle.load(open(cachePath,"rb"))

            if self.log:
                self.log.success(f"Parsing object offsets: {len(self.objectOffsets)} (from cache)")
        else:
            if self.log:
                prog = self.log.progress(f"Parsing object offsets")

            self.objectOffsets = []
            for i in range(self.header.numObjects):
                self.objectOffsets.append(Object(self).fileOffset)

                if self.log and self.log.term_mode:
                    prog.status(f"{i+1}/{self.header.numObjects}")

            pickle.dump(self.objectOffsets, open(cacheFileName,"wb"))

            if self.log:
                prog.success()
                self.log.success(f"Parsing object offsets: {len(self.objectOffsets)}")

        if len(self.objectOffsets) != self.header.numObjects:
                if self.log:
                    self.log.warn("Number of objects defined in header does not match number of parsed object offsets")

    def getObject(self, i):
        self.fh.seek(self.objectOffsets[i])
        return Object(self)

    def getObjects(self):
        i = 0
        while i < self.header.numObjects:
            yield self.getObject(i)
            i += 1

    objects = property(getObjects)

    def parseProperties(self):
        if self.log:
            prog = self.log.progress("Parsing properties")

        self.fh.seek(self.header.mappingOffset)

        properties_with_header = structure.Properties(self.fh)
        self.properties = []

        for p in properties_with_header.properties:
            prop = Property(self, in_obj=p)
            self.properties.append(prop)

        if self.log:
            prog.success(str(properties_with_header.numProperties))

    def parseClasses(self):
        if self.log:
            prog = self.log.progress("Parsing classes")

        classes_with_header = structure.Classes(self.fh)
        self.classes = CaseInsensitiveDict()
        for c in classes_with_header.classes:
            cl = Class(self, in_obj=c)
            # abuse our dict for both DNs and the display name
            self.classes[cl.className] = cl
            self.classes[cl.DN] = cl

        if self.log:
            prog.success(str(classes_with_header.numClasses))

    def parseRights(self):
        if self.log:
            prog = self.log.progress("Parsing rights")

        rights_with_header = structure.Rights(self.fh)
        self.rights = rights_with_header.rights

        if self.log:
            prog.success(str(rights_with_header.numRights))

from dissect.cstruct import cstruct

structure = cstruct()
structure.load("""
    struct Header {
        char winAdSig[10];
        int marker;

        uint64 filetime;
        wchar optionalDescription[260];
        wchar  server[260];

        uint32 numObjects;
        uint32 numAttributes;

        uint32 fileoffsetLow;
        uint32 fileoffsetHigh;
        uint32 fileoffsetEnd;

        int unk0x43a;
    };

    struct MappingEntry {
        uint32 attrIndex; // index of the attribute in the global attribute table
        int attrOffset; // offset to the value of the attribute in this object
    }

    struct Object {
        uint32 objSize;
        uint32 tableSize;
        MappingEntry mappingTable[tableSize];

        //char blob[objSize - 4 - 4 - (tableSize * 8)]; // omitted as we use file offsetting instead
    };

    struct Property {
        uint32 lenPropName;
        wchar propName[lenPropName/2];
        int unk1;
        uint32 adsType;
        uint32 lenDN;
        wchar DN[lenDN/2];
        char schemaIDGUID[16];
        char attributeSecurityGUID[16];
        char blob[4];
    };

    struct Properties {
        uint32 numProperties;
        Property properties[numProperties];
    };

    struct SystemPossSuperior {
        uint32 lenSystemPossSuperior;
        wchar systemPossSuperior[lenSystemPossSuperior/2];
    };

    struct AuxiliaryClasses {
        uint32 lenAuxiliaryClass;
        wchar auxiliaryClass[lenAuxiliaryClass/2];
    };

    struct Block {
        uint32 unk1;
        uint32 unk2;
        wchar unk3[unk2/2];
    };

    struct Class {
        uint32 lenClassName;
        wchar className[lenClassName/2];
        uint32 lenDN;
        wchar DN[lenDN/2];

        uint32 lenCommonClassName; // in AD Explorer, some class names are common and some are considered advanced - the common ones are given a description
        wchar commonClassName[lenCommonClassName/2];

        uint32 lenSubClassOf;
        wchar subClassOf[lenSubClassOf/2];

        char schemaIDGUID[16];

        uint32 offsetToNumBlocks;
        char unk2[offsetToNumBlocks];

        uint32 numBlocks;
        Block blocks[numBlocks];

        uint32 numExtraShiz;
        char extraShiz[numExtraShiz*0x10];

        uint32 numSystemPossSuperiors;
        SystemPossSuperior systemPossSuperiors[numSystemPossSuperiors];

        uint32 numAuxiliaryClasses;
        AuxiliaryClasses auxiliaryClasses[numAuxiliaryClasses];

    };

    struct Classes {
        uint32 numClasses;
        Class classes[numClasses];
    };

    struct Right {
        uint32 lenName;
        wchar name[lenName/2];
        uint32 lenDesc;
        wchar desc[lenDesc/2];
        char blob[20];
    };

    struct Rights {
        uint32 numRights;
        Right rights[numRights];
    };

    // https://docs.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-systemtime
    struct SystemTime {
        WORD wYear;
        WORD wMonth;
        WORD wDayOfWeek;
        WORD wDay;
        WORD wHour;
        WORD wMinute;
        WORD wSecond;
        WORD wMilliseconds;
    };

""", compiled=True)

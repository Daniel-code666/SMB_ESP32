#pragma once

#include <cstddef>
#include <cstdint>
#include "ff.h"

namespace SmbProtocol
{
    namespace LogoffAndX
    {
        constexpr uint8_t REQUEST_WORD_COUNT = 2;
        constexpr uint8_t RESPONSE_WORD_COUNT = 2;
    }

    namespace TreeDisconnect
    {
        constexpr uint8_t REQUEST_WORD_COUNT = 0;
        constexpr uint8_t RESPONSE_WORD_COUNT = 0;
    }

    namespace OpenAndX
    {
        constexpr uint8_t REQUEST_WORD_COUNT = 15;
        constexpr uint8_t RESPONSE_WORD_COUNT = 15;

        constexpr uint16_t FILE_TYPE_DISK = 0x0000;
        constexpr uint16_t OPEN_ACTION_OPENED = 0x0001;
    }

    namespace FindNext2
    {
        constexpr uint16_t SUBCOMMAND = 0x0002;
    }

    namespace NtCreateAndX
    {
        constexpr uint8_t REQUEST_WORD_COUNT = 0x18;
        constexpr uint8_t RESPONSE_WORD_COUNT = 0x22;

        constexpr uint8_t OPLOCK_LEVEL_NONE = 0x00;

        constexpr uint32_t CREATE_ACTION_OPENED = 0x00000001;

        constexpr uint16_t RESOURCE_TYPE_DISK = 0x0000;
    }

    namespace FindFirst2
    {
        constexpr uint16_t SUBCOMMAND = 0x0001;

        constexpr uint16_t FLAG_CLOSE_AFTER_REQUEST = 0x0001;
        constexpr uint16_t FLAG_CLOSE_AT_EOS = 0x0002;
        constexpr uint16_t FLAG_RETURN_RESUME_KEYS = 0x0004;
        constexpr uint16_t FLAG_CONTINUE_FROM_LAST = 0x0008;
        constexpr uint16_t FLAG_BACKUP_INTENT = 0x0010;

        constexpr uint16_t INFO_LEVEL_BOTH_DIRECTORY = 0x0104;
    }

    namespace QueryFileInformation
    {
        constexpr uint16_t BASIC_INFO = 0x0101;
        constexpr uint16_t STANDARD_INFO = 0x0102;

        constexpr uint32_t ATTRIBUTE_READONLY = 0x00000001;
        constexpr uint32_t ATTRIBUTE_HIDDEN = 0x00000002;
        constexpr uint32_t ATTRIBUTE_SYSTEM = 0x00000004;
        constexpr uint32_t ATTRIBUTE_DIRECTORY = 0x00000010;
        constexpr uint32_t ATTRIBUTE_ARCHIVE = 0x00000020;
        constexpr uint32_t ATTRIBUTE_NORMAL = 0x00000080;
    }

    namespace Transaction2
    {
        constexpr uint8_t REQUEST_WORD_COUNT_MIN = 14;

        enum class Subcommand : uint16_t
        {
            Open2 = 0x0000,
            FindFirst2 = 0x0001,
            FindNext2 = 0x0002,
            QueryFsInformation = 0x0003,
            SetFsInformation = 0x0004,
            QueryPathInformation = 0x0005,
            SetPathInformation = 0x0006,
            QueryFileInformation = 0x0007,
            SetFileInformation = 0x0008,
            Fsctl = 0x0009,
            Ioctl2 = 0x000A,
            FindNotifyFirst = 0x000B,
            FindNotifyNext = 0x000C,
            CreateDirectory = 0x000D,
            SessionSetup = 0x000E,
            GetDfsReferral = 0x0010,
            ReportDfsInconsistency = 0x0011
        };
    }

    namespace TreeConnect
    {
        constexpr uint8_t REQUEST_WORD_COUNT = 4;
        constexpr uint8_t RESPONSE_WORD_COUNT = 3;

        constexpr uint16_t OPTIONAL_SUPPORT_NONE = 0x0000;

        constexpr const char *SERVICE_DISK = "A:";
        constexpr const char *NATIVE_FILE_SYSTEM = "FAT";
    }

    namespace DirectTcp
    {
        constexpr size_t HEADER_SIZE = 4;
        constexpr uint8_t SESSION_MESSAGE = 0x00;
        constexpr uint32_t MAX_PAYLOAD_LENGTH = 0x00FFFFFF;

#pragma pack(push, 1)

        struct Header
        {
            uint8_t type;
            uint8_t lengthHigh;
            uint8_t lengthMiddle;
            uint8_t lengthLow;
        };

#pragma pack(pop)

        static_assert(
            sizeof(Header) == HEADER_SIZE,
            "Direct TCP Header debe medir 4 bytes");

        inline uint32_t GetPayloadLength(const Header &header)
        {
            return (static_cast<uint32_t>(header.lengthHigh) << 16) |
                   (static_cast<uint32_t>(header.lengthMiddle) << 8) |
                   static_cast<uint32_t>(header.lengthLow);
        }

        inline bool SetPayloadLength(Header &header, uint32_t length)
        {
            if (length > MAX_PAYLOAD_LENGTH)
            {
                return false;
            }

            header.type = SESSION_MESSAGE;
            header.lengthHigh = static_cast<uint8_t>((length >> 16) & 0xFF);
            header.lengthMiddle = static_cast<uint8_t>((length >> 8) & 0xFF);
            header.lengthLow = static_cast<uint8_t>(length & 0xFF);

            return true;
        }
    }

    constexpr size_t SMB1_HEADER_SIZE = 32;

    constexpr uint8_t SIGNATURE_0 = 0xFF;
    constexpr uint8_t SIGNATURE_1 = 'S';
    constexpr uint8_t SIGNATURE_2 = 'M';
    constexpr uint8_t SIGNATURE_3 = 'B';

    namespace Dialect
    {
        constexpr uint8_t FORMAT = 0x02;
        constexpr uint16_t NOT_SELECTED = 0xFFFF;
    }

    namespace AndX
    {
        constexpr uint8_t NO_FURTHER_COMMAND = 0xFF;
        constexpr uint8_t RESERVED = 0x00;
    }

    namespace SessionSetup
    {
        constexpr uint8_t REQUEST_WORD_COUNT = 13;
        constexpr uint8_t RESPONSE_WORD_COUNT = 3;

        constexpr uint16_t ACTION_NONE = 0x0000;
        constexpr uint16_t ACTION_LOGGED_IN_AS_GUEST = 0x0001;
        constexpr uint16_t ACTION_USE_LANMAN_KEY = 0x0002;
    }

    enum class Command : uint8_t
    {
        Open = 0x02,
        Create = 0x03,
        Close = 0x04,
        Delete = 0x06,
        Rename = 0x07,
        QueryInformation = 0x08,
        Echo = 0x2B,
        OpenAndX = 0x2D,
        ReadAndX = 0x2E,
        Transaction2 = 0x32,
        FindClose2 = 0x34,
        TreeDisconnect = 0x71,
        Negotiate = 0x72,
        SessionSetupAndX = 0x73,
        LogoffAndX = 0x74,
        TreeConnectAndX = 0x75,
        NtCreateAndX = 0xA2,
    };

    enum class Flags : uint8_t
    {
        None = 0x00,
        LockAndReadOk = 0x01,
        CaseInsensitive = 0x08,
        CanonicalizedPaths = 0x10,
        Oplock = 0x20,
        OpBatch = 0x40,
        Reply = 0x80
    };

    enum class Flags2 : uint16_t
    {
        None = 0x0000,
        LongNames = 0x0001,
        Eas = 0x0002,
        SecuritySignature = 0x0004,
        SecuritySignatureRequired = 0x0010,
        IsLongName = 0x0040,
        ExtendedSecurity = 0x0800,
        Dfs = 0x1000,
        PagingIo = 0x2000,
        NtStatus = 0x4000,
        Unicode = 0x8000
    };

    enum class SecurityMode : uint8_t
    {
        None = 0x00,
        UserSecurity = 0x01,
        EncryptPasswords = 0x02,
        SignaturesEnabled = 0x04,
        SignaturesRequired = 0x08
    };

    enum class Capability : uint32_t
    {
        None = 0x00000000,
        RawMode = 0x00000001,
        MpxMode = 0x00000002,
        Unicode = 0x00000004,
        LargeFiles = 0x00000008,
        NtSmbs = 0x00000010,
        RpcRemoteApis = 0x00000020,
        Status32 = 0x00000040,
        LevelIIOplocks = 0x00000080,
        LockAndRead = 0x00000100,
        NtFind = 0x00000200,
        Dfs = 0x00001000,
        InfoLevelPassthru = 0x00002000,
        LargeReadX = 0x00004000,
        LargeWriteX = 0x00008000,
        Lwio = 0x00010000,
        Unix = 0x00800000,
        CompressedData = 0x02000000,
        DynamicReauth = 0x20000000,
        PersistentHandles = 0x40000000,
        ExtendedSecurity = 0x80000000
    };

    enum class Status : uint32_t
    {
        Success = 0x00000000,
        InvalidHandle = 0xC0000008,
        AccessDenied = 0xC0000022,
        ObjectNameNotFound = 0xC0000034,
        ObjectPathNotFound = 0xC000003A,
        NotSupported = 0xC00000BB,
        NoSuchFile = 0xC000000F,
    };

    constexpr Flags operator|(Flags left, Flags right)
    {
        return static_cast<Flags>(
            static_cast<uint8_t>(left) |
            static_cast<uint8_t>(right));
    }

    constexpr Flags2 operator|(Flags2 left, Flags2 right)
    {
        return static_cast<Flags2>(
            static_cast<uint16_t>(left) |
            static_cast<uint16_t>(right));
    }

    constexpr SecurityMode operator|(
        SecurityMode left,
        SecurityMode right)
    {
        return static_cast<SecurityMode>(
            static_cast<uint8_t>(left) |
            static_cast<uint8_t>(right));
    }

    constexpr Capability operator|(
        Capability left,
        Capability right)
    {
        return static_cast<Capability>(
            static_cast<uint32_t>(left) |
            static_cast<uint32_t>(right));
    }

    constexpr bool HasFlag(Flags value, Flags flag)
    {
        return (static_cast<uint8_t>(value) &
                static_cast<uint8_t>(flag)) != 0;
    }

    constexpr bool HasFlag(Flags2 value, Flags2 flag)
    {
        return (static_cast<uint16_t>(value) &
                static_cast<uint16_t>(flag)) != 0;
    }

    constexpr bool HasFlag(
        SecurityMode value,
        SecurityMode flag)
    {
        return (static_cast<uint8_t>(value) &
                static_cast<uint8_t>(flag)) != 0;
    }

    constexpr bool HasFlag(
        Capability value,
        Capability flag)
    {
        return (static_cast<uint32_t>(value) &
                static_cast<uint32_t>(flag)) != 0;
    }

#pragma pack(push, 1)

    struct OpenAndXResponseParameters
    {
        uint8_t wordCount;

        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;

        uint16_t fid;
        uint16_t fileAttributes;

        uint32_t lastWriteTime;
        uint32_t fileDataSize;

        uint16_t grantedAccess;
        uint16_t resourceType;
        uint16_t nmPipeStatus;
        uint16_t openResult;

        uint32_t serverFid;
        uint16_t reserved;
    };

    struct OpenAndXRequestParameters
    {
        uint8_t wordCount;

        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;

        uint16_t openFlags;
        uint16_t desiredAccess;
        uint16_t searchAttributes;
        uint16_t fileAttributes;

        uint32_t creationTime;

        uint16_t openFunction;

        uint32_t allocationSize;
        uint32_t timeout;
        uint32_t reserved;
    };

    struct FindNext2ResponseParameters
    {
        uint16_t searchCount;
        uint16_t endOfSearch;
        uint16_t eaErrorOffset;
        uint16_t lastNameOffset;
    };

    struct FindNext2RequestParameters
    {
        uint16_t sid;
        uint16_t searchCount;
        uint16_t informationLevel;
        uint32_t resumeKey;
        uint16_t flags;
    };

    struct NtCreateAndXResponseParameters
    {
        uint8_t wordCount;

        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;

        uint8_t oplockLevel;

        uint16_t fid;

        uint32_t createDisposition;

        uint64_t createTime;
        uint64_t lastAccessTime;
        uint64_t lastWriteTime;
        uint64_t lastChangeTime;

        uint32_t extFileAttributes;

        uint64_t allocationSize;
        uint64_t endOfFile;

        uint16_t resourceType;
        uint16_t nmPipeStatus;

        uint8_t directory;
    };

    struct FindFileBothDirectoryInfo
    {
        uint32_t nextEntryOffset;
        uint32_t fileIndex;

        uint64_t creationTime;
        uint64_t lastAccessTime;
        uint64_t lastWriteTime;
        uint64_t lastChangeTime;

        uint64_t endOfFile;
        uint64_t allocationSize;

        uint32_t extFileAttributes;
        uint32_t fileNameLength;

        uint32_t eaSize;

        uint8_t shortNameLength;
        uint8_t reserved;

        uint16_t shortName[12];
    };

    struct FindFirst2ResponseParameters
    {
        uint16_t sid;
        uint16_t searchCount;
        uint16_t endOfSearch;
        uint16_t eaErrorOffset;
        uint16_t lastNameOffset;
    };

    struct FindFirst2RequestParameters
    {
        uint16_t searchAttributes;
        uint16_t searchCount;
        uint16_t flags;
        uint16_t informationLevel;
        uint32_t searchStorageType;
    };

    struct NtCreateAndXRequestParameters
    {
        uint8_t wordCount;

        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;

        uint8_t reserved;

        uint16_t nameLength;

        uint32_t flags;
        uint32_t rootDirectoryFid;
        uint32_t desiredAccess;

        uint64_t allocationSize;

        uint32_t extFileAttributes;
        uint32_t shareAccess;
        uint32_t createDisposition;
        uint32_t createOptions;
        uint32_t impersonationLevel;

        uint8_t securityFlags;
    };

    struct QueryFileStandardInfo
    {
        uint64_t allocationSize;
        uint64_t endOfFile;
        uint32_t numberOfLinks;
        uint8_t deletePending;
        uint8_t directory;
    };

    struct QueryFileBasicInfo
    {
        uint64_t creationTime;
        uint64_t lastAccessTime;
        uint64_t lastWriteTime;
        uint64_t changeTime;
        uint32_t fileAttributes;
    };

    struct Transaction2RequestParameters
    {
        uint8_t wordCount;

        uint16_t totalParameterCount;
        uint16_t totalDataCount;

        uint16_t maxParameterCount;
        uint16_t maxDataCount;

        uint8_t maxSetupCount;
        uint8_t reserved1;

        uint16_t flags;
        uint32_t timeout;
        uint16_t reserved2;

        uint16_t parameterCount;
        uint16_t parameterOffset;

        uint16_t dataCount;
        uint16_t dataOffset;

        uint8_t setupCount;
        uint8_t reserved3;
    };

    struct Transaction2ResponseParameters
    {
        uint8_t wordCount;
        uint16_t totalParameterCount;
        uint16_t totalDataCount;
        uint16_t reserved;
        uint16_t parameterCount;
        uint16_t parameterOffset;
        uint16_t parameterDisplacement;
        uint16_t dataCount;
        uint16_t dataOffset;
        uint16_t dataDisplacement;
        uint8_t setupCount;
        uint8_t reserved2;
    };

    struct Header
    {
        uint8_t protocol[4];
        uint8_t command;
        uint32_t status;
        uint8_t flags;
        uint16_t flags2;
        uint16_t pidHigh;
        uint8_t securityFeatures[8];
        uint16_t reserved;
        uint16_t treeId;
        uint16_t processId;
        uint16_t userId;
        uint16_t multiplexId;
    };

    struct NegotiateResponseParameters
    {
        uint8_t wordCount;
        uint16_t dialectIndex;
        uint8_t securityMode;
        uint16_t maxMpxCount;
        uint16_t maxNumberVcs;
        uint32_t maxBufferSize;
        uint32_t maxRawSize;
        uint32_t sessionKey;
        uint32_t capabilities;
        uint64_t systemTime;
        int16_t serverTimeZone;
        uint8_t challengeLength;
    };

    struct SessionSetupAndXRequestParameters
    {
        uint8_t wordCount;
        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;
        uint16_t maxBufferSize;
        uint16_t maxMpxCount;
        uint16_t vcNumber;
        uint32_t sessionKey;
        uint16_t oemPasswordLength;
        uint16_t unicodePasswordLength;
        uint32_t reserved;
        uint32_t capabilities;
    };

    struct SessionSetupAndXResponseParameters
    {
        uint8_t wordCount;
        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;
        uint16_t action;
    };

    struct EchoRequestParameters
    {
        uint8_t wordCount;
        uint16_t echoCount;
    };

    struct EchoResponseParameters
    {
        uint8_t wordCount;
        uint16_t sequenceNumber;
    };

    struct TreeConnectAndXRequestParameters
    {
        uint8_t wordCount;
        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;
        uint16_t flags;
        uint16_t passwordLength;
    };

    struct TreeConnectAndXResponseParameters
    {
        uint8_t wordCount;
        uint8_t andXCommand;
        uint8_t andXReserved;
        uint16_t andXOffset;
        uint16_t optionalSupport;
    };

#pragma pack(pop)

    static_assert(
        sizeof(OpenAndXRequestParameters) == 31,
        "SMB_COM_OPEN_ANDX request parameters debe medir 31 bytes");

    static_assert(
        sizeof(OpenAndXResponseParameters) == 31,
        "SMB_COM_OPEN_ANDX response parameters debe medir 31 bytes");

    static_assert(
        sizeof(FindNext2RequestParameters) == 12,
        "TRANS2_FIND_NEXT2 request parameters debe medir 12 bytes");

    static_assert(
        sizeof(FindNext2ResponseParameters) == 8,
        "TRANS2_FIND_NEXT2 response parameters debe medir 8 bytes");

    static_assert(
        sizeof(NtCreateAndXResponseParameters) == 69,
        "SMB_COM_NT_CREATE_ANDX response parameters debe medir 69 bytes");

    static_assert(
        sizeof(FindFileBothDirectoryInfo) == 94,
        "SMB_FIND_FILE_BOTH_DIRECTORY_INFO fijo debe medir 94 bytes");

    static_assert(
        sizeof(FindFirst2ResponseParameters) == 10,
        "TRANS2_FIND_FIRST2 response parameters debe medir 10 bytes");

    static_assert(
        sizeof(FindFirst2RequestParameters) == 12,
        "TRANS2_FIND_FIRST2 request parameters debe medir 12 bytes");

    static_assert(
        sizeof(Header) == SMB1_HEADER_SIZE,
        "SMB1 Header debe medir 32 bytes");

    static_assert(
        sizeof(NegotiateResponseParameters) == 35,
        "SMB_COM_NEGOTIATE response parameters debe medir 35 bytes");

    static_assert(
        sizeof(SessionSetupAndXRequestParameters) == 27,
        "SMB_COM_SESSION_SETUP_ANDX request parameters debe medir 27 bytes");

    static_assert(
        sizeof(SessionSetupAndXResponseParameters) == 7,
        "SMB_COM_SESSION_SETUP_ANDX response parameters debe medir 7 bytes");

    static_assert(
        sizeof(EchoRequestParameters) == 3,
        "SMB_COM_ECHO request parameters debe medir 3 bytes");

    static_assert(
        sizeof(EchoResponseParameters) == 3,
        "SMB_COM_ECHO response parameters debe medir 3 bytes");

    static_assert(
        sizeof(TreeConnectAndXRequestParameters) == 9,
        "TREE_CONNECT_ANDX request parameters debe medir 9 bytes");

    static_assert(
        sizeof(TreeConnectAndXResponseParameters) == 7,
        "TREE_CONNECT_ANDX response parameters debe medir 7 bytes");

    static_assert(
        sizeof(Transaction2RequestParameters) == 29,
        "SMB_COM_TRANSACTION2 request parameters debe medir 29 bytes");

    static_assert(
        sizeof(QueryFileBasicInfo) == 36,
        "SMB_QUERY_FILE_BASIC_INFO debe medir 36 bytes");

    static_assert(
        sizeof(Transaction2ResponseParameters) == 21,
        "Transaction2ResponseParameters debe medir 21 bytes");

    static_assert(
        sizeof(QueryFileStandardInfo) == 22,
        "SMB_QUERY_FILE_STANDARD_INFO debe medir 22 bytes");

    static_assert(
        sizeof(NtCreateAndXRequestParameters) == 49,
        "SMB_COM_NT_CREATE_ANDX request parameters debe medir 49 bytes");

    inline bool IsSmb1(const Header &header)
    {
        return header.protocol[0] == SIGNATURE_0 &&
               header.protocol[1] == SIGNATURE_1 &&
               header.protocol[2] == SIGNATURE_2 &&
               header.protocol[3] == SIGNATURE_3;
    }

    inline void SetSignature(Header &header)
    {
        header.protocol[0] = SIGNATURE_0;
        header.protocol[1] = SIGNATURE_1;
        header.protocol[2] = SIGNATURE_2;
        header.protocol[3] = SIGNATURE_3;
    }

    inline Command GetCommand(const Header &header)
    {
        return static_cast<Command>(header.command);
    }
}

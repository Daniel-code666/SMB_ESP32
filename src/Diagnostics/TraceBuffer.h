#pragma once

#include <cstddef>
#include <cstdint>

namespace TraceBuffer
{
    // Activar solo para capturar una falla. Desactivado en el firmware de
    // rendimiento para no escribir varios eventos en PSRAM por cada READ_ANDX.
    constexpr bool ENABLED = false;

    constexpr uint16_t FORMAT_VERSION = 1;
    constexpr uint32_t EVENT_CAPACITY = 4096;

    enum class EventType : uint8_t
    {
        None = 0,
        System = 1,
        ConnectionOpen = 2,
        ConnectionClose = 3,
        Receive = 4,
        SmbRequest = 5,
        Seek = 6,
        Read = 7,
        Send = 8,
        Idle = 9,
        ListenPending = 10,
        Heap = 11,
        Error = 12,
        SdDetect = 13,
        EthernetLink = 14,
        SmbServer = 15
    };

    enum class Phase : uint8_t
    {
        Idle = 0,
        Accept = 1,
        WaitSocket = 2,
        ReceiveDirectHeader = 3,
        ReceiveSmbBody = 4,
        ParseRequest = 5,
        Dispatch = 6,
        Seek = 7,
        Read = 8,
        BuildResponse = 9,
        Send = 10,
        Close = 11
    };

#pragma pack(push, 1)
    struct Event
    {
        uint64_t timestampUs;
        uint64_t fileOffset;
        uint32_t durationUs;
        int32_t result;
        uint32_t auxiliary;
        uint16_t connectionId;
        uint16_t multiplexId;
        uint16_t fileId;
        uint16_t size;
        uint8_t type;
        uint8_t command;
        uint8_t phase;
        uint8_t flags;
    };

    struct SnapshotHeader
    {
        char magic[8];
        uint16_t version;
        uint16_t headerSize;
        uint16_t eventSize;
        uint16_t reserved16;
        uint32_t capacity;
        uint32_t count;
        uint64_t totalRecorded;
        uint64_t overwritten;
        uint32_t frozen;
        uint32_t reserved32;
        Event activeOperation;
    };
#pragma pack(pop)

    static_assert(sizeof(Event) == 40, "Trace event binary format changed");
    static_assert(sizeof(SnapshotHeader) == 88, "Trace header binary format changed");

    bool Init();
    bool IsEnabled();

    void Record(
        EventType type,
        Phase phase = Phase::Idle,
        uint16_t connectionId = 0,
        uint8_t command = 0,
        uint16_t multiplexId = 0,
        uint16_t fileId = 0,
        uint64_t fileOffset = 0,
        uint16_t size = 0,
        uint32_t durationUs = 0,
        int32_t result = 0,
        uint32_t auxiliary = 0,
        uint8_t flags = 0);

    void SetActive(
        Phase phase,
        uint16_t connectionId = 0,
        uint8_t command = 0,
        uint16_t multiplexId = 0,
        uint16_t fileId = 0,
        uint64_t fileOffset = 0,
        uint16_t size = 0,
        uint32_t auxiliary = 0);

    void ClearActive(uint16_t connectionId = 0);
    void RecordHeap(uint16_t connectionId, uint32_t readCount);

    bool GetInfo(SnapshotHeader &header);
    bool Freeze(SnapshotHeader &header);
    bool CopySnapshotEvent(uint32_t chronologicalIndex, Event &event);
    void Clear();
}

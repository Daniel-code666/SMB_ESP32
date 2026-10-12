#pragma once

#include <cstddef>
#include <cstdint>

namespace TraceBuffer
{
    // Firmware de juego: el trazador detallado se compila fuera del camino
    // critico. Cambiar a true solo para generar una captura de diagnostico.
    constexpr bool ENABLED = false;
    constexpr uint16_t FORMAT_VERSION = 2;
    constexpr uint32_t EVENT_CAPACITY = 4096;
    constexpr uint32_t SLOW_EVENT_CAPACITY = 64;
    constexpr uint32_t LATENCY_HISTOGRAM_BINS = 24;

    enum class EventType : uint8_t
    {
        None = 0, System = 1, ConnectionOpen = 2, ConnectionClose = 3,
        Receive = 4, SmbRequest = 5, Seek = 6, Read = 7, Send = 8,
        Idle = 9, ListenPending = 10, Heap = 11, Error = 12,
        SdDetect = 13, EthernetLink = 14, SmbServer = 15,
        SmbOperation = 16, Marker = 17, FileOpen = 18, TcpTransfer = 19
    };

    enum class Phase : uint8_t
    {
        Idle = 0, Accept = 1, WaitSocket = 2, ReceiveDirectHeader = 3,
        ReceiveSmbBody = 4, ParseRequest = 5, Dispatch = 6, Seek = 7,
        Read = 8, BuildResponse = 9, Send = 10, Close = 11
    };

    enum EventFlags : uint8_t
    {
        FlagNone = 0, FlagCacheHit = 1U << 0, FlagCacheMiss = 1U << 1,
        FlagSequential = 1U << 2, FlagForwardJump = 1U << 3,
        FlagBackwardJump = 1U << 4, FlagRepeated = 1U << 5,
        FlagPartial = 1U << 6, FlagError = 1U << 7
    };

    enum class Marker : uint8_t
    {
        Unknown = 0,
        MarvelStart = 1, MarvelMagenta1 = 2, MarvelGreen = 3,
        MarvelMagenta2 = 4, MarvelYellow = 5, MarvelRunning = 6,
        MarvelCinematicStart = 7, MarvelCinematicEnd = 8,
        GowStart = 16, GowMagenta1 = 17, GowGreen = 18,
        GowMagenta2 = 19, GowYellow = 20, GowRunning = 21,
        GowCinematicStart = 22, GowStutter = 23, GowCinematicEnd = 24,
        Gameplay = 32,
        GameLoadStart = 33, ScreenMagenta1 = 34, ScreenGreen = 35,
        ScreenMagenta2 = 36, ScreenYellow = 37, GameRunning = 38,
        CinematicStart = 39, CinematicStutter = 40, CinematicEnd = 41
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

    struct LatencyStats
    {
        uint64_t count;
        uint64_t totalUs;
        uint32_t minimumUs;
        uint32_t maximumUs;
        uint32_t histogram[LATENCY_HISTOGRAM_BINS];
    };

    struct MetricsSummary
    {
        uint64_t captureStartedUs;
        uint64_t connections;
        uint64_t reconnections;
        uint64_t smbOperations;
        uint64_t readRequests;
        uint64_t requestedBytes;
        uint64_t deliveredBytes;
        uint64_t totalSeekUs;
        uint64_t totalReadUs;
        uint64_t totalSendUs;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        uint64_t sequentialReads;
        uint64_t forwardJumps;
        uint64_t backwardJumps;
        uint64_t repeatedReads;
        uint64_t partialReads;
        uint64_t tcpPartialSends;
        uint64_t tcpBytesSent;
        uint64_t tcpSendCalls;
        uint64_t fatFsErrors;
        uint64_t tcpErrors;
        uint64_t sdErrors;
        uint64_t idleOver100ms;
        uint64_t idleOver500ms;
        uint64_t idleOver1000ms;
        uint64_t ignoredWhileFrozen;
        uint64_t slowEventsSeen;
        uint64_t slowEventsOverwritten;
        LatencyStats smbLatency;
        LatencyStats seekLatency;
        LatencyStats readLatency;
        LatencyStats sendLatency;
        LatencyStats clientGap;
    };

    struct SnapshotHeader
    {
        char magic[8];
        uint16_t version;
        uint16_t headerSize;
        uint16_t eventSize;
        uint16_t summarySize;
        uint32_t capacity;
        uint32_t count;
        uint32_t slowCapacity;
        uint32_t slowCount;
        uint64_t totalRecorded;
        uint64_t overwritten;
        uint64_t dropped;
        uint32_t frozen;
        uint32_t reserved32;
        Event activeOperation;
    };
#pragma pack(pop)

    static_assert(sizeof(Event) == 40, "Trace event binary format changed");
    static_assert(sizeof(LatencyStats) == 120, "Latency stats format changed");
    static_assert(sizeof(SnapshotHeader) == 104, "Trace header binary format changed");

    bool Init();
    bool StartSerialConsole();
    bool IsEnabled();
    void Record(EventType type, Phase phase = Phase::Idle,
                uint16_t connectionId = 0, uint8_t command = 0,
                uint16_t multiplexId = 0, uint16_t fileId = 0,
                uint64_t fileOffset = 0, uint16_t size = 0,
                uint32_t durationUs = 0, int32_t result = 0,
                uint32_t auxiliary = 0, uint8_t flags = 0);
    void SetActive(Phase phase, uint16_t connectionId = 0,
                   uint8_t command = 0, uint16_t multiplexId = 0,
                   uint16_t fileId = 0, uint64_t fileOffset = 0,
                   uint16_t size = 0, uint32_t auxiliary = 0);
    void ClearActive(uint16_t connectionId = 0);
    void RecordHeap(uint16_t connectionId, uint32_t readCount);
    void RecordConnectionOpen();
    void SetConnectionActive(bool active);
    bool IsConnectionActive();
    void RecordSmbOperation(uint64_t startedUs, uint16_t connectionId,
                            uint8_t command, uint16_t multiplexId,
                            uint16_t fileId, uint64_t fileOffset,
                            uint16_t requestedBytes, int32_t deliveredOrError,
                            uint32_t seekUs, uint32_t readUs, uint32_t sendUs,
                            uint8_t flags);
    void RecordTcpTransfer(size_t requested, size_t sent, uint32_t calls, int errorCode);
    void RecordFatFsError();
    void RecordSdError();
    bool RecordMarker(Marker marker);
    bool ParseMarker(const char *name, Marker &marker);
    bool GetInfo(SnapshotHeader &header);
    bool GetSummary(MetricsSummary &summary);
    bool Freeze(SnapshotHeader &header);
    bool CopySnapshotEvent(uint32_t chronologicalIndex, Event &event);
    bool CopySlowEvent(uint32_t chronologicalIndex, Event &event);
    void Clear();
}

#include "TraceBuffer.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <strings.h>

#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_err.h"
#include "sdkconfig.h"
#include "driver/uart.h"
#include "driver/uart_vfs.h"
#include "Storage/SdProfiler.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace
{
    TraceBuffer::Event *events = nullptr;
    TraceBuffer::Event *slowEvents = nullptr;
    uint32_t capacity = 0, writeIndex = 0, eventCount = 0;
    uint32_t slowWriteIndex = 0, slowEventCount = 0;
    uint64_t totalRecorded = 0, lastOperationEndedUs = 0;
    bool frozen = false;
    bool connectionActive = false;
    TraceBuffer::Event activeOperation{};
    TraceBuffer::MetricsSummary metrics{};
    portMUX_TYPE traceMux = portMUX_INITIALIZER_UNLOCKED;
    constexpr uint32_t SLOW_SMB_US = 10000;
    constexpr uint32_t SLOW_PHASE_US = 5000;

    uint32_t ClampDuration(uint64_t value)
    {
        return static_cast<uint32_t>(std::min<uint64_t>(value, UINT32_MAX));
    }

    TraceBuffer::Event MakeEvent(
        TraceBuffer::EventType type, TraceBuffer::Phase phase,
        uint16_t connectionId, uint8_t command, uint16_t multiplexId,
        uint16_t fileId, uint64_t fileOffset, uint16_t size,
        uint32_t durationUs, int32_t result, uint32_t auxiliary, uint8_t flags,
        uint64_t timestampUs = 0)
    {
        TraceBuffer::Event event{};
        event.timestampUs = timestampUs != 0 ? timestampUs : static_cast<uint64_t>(esp_timer_get_time());
        event.fileOffset = fileOffset;
        event.durationUs = durationUs;
        event.result = result;
        event.auxiliary = auxiliary;
        event.connectionId = connectionId;
        event.multiplexId = multiplexId;
        event.fileId = fileId;
        event.size = size;
        event.type = static_cast<uint8_t>(type);
        event.command = command;
        event.phase = static_cast<uint8_t>(phase);
        event.flags = flags;
        return event;
    }

    void ObserveLatency(TraceBuffer::LatencyStats &stats, uint32_t value)
    {
        ++stats.count;
        stats.totalUs += value;
        if (stats.count == 1 || value < stats.minimumUs) stats.minimumUs = value;
        if (value > stats.maximumUs) stats.maximumUs = value;
        uint32_t bin = 0, remaining = value;
        while (remaining > 1 && bin + 1 < TraceBuffer::LATENCY_HISTOGRAM_BINS)
        {
            remaining >>= 1;
            ++bin;
        }
        ++stats.histogram[bin];
    }

    void StoreEventUnlocked(const TraceBuffer::Event &event)
    {
        events[writeIndex] = event;
        writeIndex = (writeIndex + 1U) % capacity;
        if (eventCount < capacity) ++eventCount;
        ++totalRecorded;
    }

    void StoreSlowUnlocked(const TraceBuffer::Event &event)
    {
        slowEvents[slowWriteIndex] = event;
        slowWriteIndex = (slowWriteIndex + 1U) % TraceBuffer::SLOW_EVENT_CAPACITY;
        if (slowEventCount < TraceBuffer::SLOW_EVENT_CAPACITY) ++slowEventCount;
        else ++metrics.slowEventsOverwritten;
        ++metrics.slowEventsSeen;
    }

    void FillHeader(TraceBuffer::SnapshotHeader &header)
    {
        header = TraceBuffer::SnapshotHeader{};
        constexpr char magic[8] = {'S','M','B','M','T','R','2','\0'};
        memcpy(header.magic, magic, sizeof(magic));
        header.version = TraceBuffer::FORMAT_VERSION;
        header.headerSize = sizeof(header);
        header.eventSize = sizeof(TraceBuffer::Event);
        header.summarySize = sizeof(TraceBuffer::MetricsSummary);
        header.capacity = capacity;
        header.count = eventCount;
        header.slowCapacity = TraceBuffer::SLOW_EVENT_CAPACITY;
        header.slowCount = slowEventCount;
        header.totalRecorded = totalRecorded;
        header.overwritten = totalRecorded > capacity ? totalRecorded - capacity : 0;
        header.frozen = frozen ? 1U : 0U;
        header.activeOperation = activeOperation;
    }

    bool GetEventAt(uint32_t index, TraceBuffer::Event &event, bool slow)
    {
        const uint32_t count = slow ? slowEventCount : eventCount;
        const uint32_t cap = slow ? TraceBuffer::SLOW_EVENT_CAPACITY : capacity;
        const uint32_t next = slow ? slowWriteIndex : writeIndex;
        TraceBuffer::Event *buffer = slow ? slowEvents : events;
        if (index >= count) return false;
        const uint32_t oldest = count < cap ? 0U : next;
        event = buffer[(oldest + index) % cap];
        return true;
    }

    uint32_t Crc32Update(uint32_t crc, const uint8_t *data, size_t length)
    {
        for (size_t i = 0; i < length; ++i)
        {
            crc ^= data[i];
            for (uint8_t bit = 0; bit < 8; ++bit)
                crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
        return crc;
    }

    void PrintHexBlock(const void *data, size_t length)
    {
        const auto *bytes = static_cast<const uint8_t *>(data);
        constexpr size_t CHUNK = 80;
        char line[sizeof("METRICS_DATA ") + CHUNK * 2 + 2]{};
        for (size_t offset = 0; offset < length; offset += CHUNK)
        {
            const size_t count = std::min(CHUNK, length - offset);
            size_t used = static_cast<size_t>(snprintf(line, sizeof(line), "METRICS_DATA "));
            for (size_t i = 0; i < count; ++i)
                used += static_cast<size_t>(snprintf(line + used, sizeof(line) - used, "%02X", bytes[offset + i]));
            line[used++] = '\n'; line[used] = '\0';
            printf("%s", line);
        }
    }

    void PrintInfo()
    {
        TraceBuffer::SnapshotHeader h{};
        TraceBuffer::MetricsSummary s{};
        if (!TraceBuffer::GetInfo(h) || !TraceBuffer::GetSummary(s))
        {
            printf("METRICS_ERROR DISABLED\n"); return;
        }
        printf("METRICS_INFO active=%u count=%lu/%lu overwritten=%llu slow=%lu reads=%llu bytes=%llu connections=%llu\n",
               h.frozen ? 0U : 1U, static_cast<unsigned long>(h.count),
               static_cast<unsigned long>(h.capacity), static_cast<unsigned long long>(h.overwritten),
               static_cast<unsigned long>(h.slowCount), static_cast<unsigned long long>(s.readRequests),
               static_cast<unsigned long long>(s.deliveredBytes), static_cast<unsigned long long>(s.connections));
    }

    void DumpSerial()
    {
        if (TraceBuffer::IsConnectionActive())
        {
            printf("METRICS_ERROR SMB_ACTIVE use_F_then_disconnect_before_D\n");
            return;
        }
        TraceBuffer::SnapshotHeader h{};
        if (!TraceBuffer::Freeze(h)) { printf("METRICS_ERROR DISABLED\n"); return; }
        TraceBuffer::MetricsSummary s{};
        TraceBuffer::GetSummary(s);
        uint32_t crc = 0xFFFFFFFFU;
        crc = Crc32Update(crc, reinterpret_cast<const uint8_t *>(&h), sizeof(h));
        crc = Crc32Update(crc, reinterpret_cast<const uint8_t *>(&s), sizeof(s));
        TraceBuffer::Event event{};
        for (uint32_t i = 0; i < h.count; ++i)
        {
            TraceBuffer::CopySnapshotEvent(i, event);
            crc = Crc32Update(crc, reinterpret_cast<const uint8_t *>(&event), sizeof(event));
        }
        for (uint32_t i = 0; i < h.slowCount; ++i)
        {
            TraceBuffer::CopySlowEvent(i, event);
            crc = Crc32Update(crc, reinterpret_cast<const uint8_t *>(&event), sizeof(event));
        }
        crc ^= 0xFFFFFFFFU;
        const size_t bytes = sizeof(h) + sizeof(s) + (h.count + h.slowCount) * sizeof(event);
        printf("METRICS_DUMP_BEGIN version=%u bytes=%u crc32=%08lX\n",
               h.version, static_cast<unsigned>(bytes), static_cast<unsigned long>(crc));
        PrintHexBlock(&h, sizeof(h)); PrintHexBlock(&s, sizeof(s));
        for (uint32_t i = 0; i < h.count; ++i)
        {
            TraceBuffer::CopySnapshotEvent(i, event); PrintHexBlock(&event, sizeof(event));
        }
        for (uint32_t i = 0; i < h.slowCount; ++i)
        {
            TraceBuffer::CopySlowEvent(i, event); PrintHexBlock(&event, sizeof(event));
        }
        printf("METRICS_DUMP_END crc32=%08lX\n", static_cast<unsigned long>(crc));
    }

    void SerialConsoleTask(void *)
    {
        char line[96]{};
        printf("METRICS: consola lista (METRICS INFO|START|FREEZE|DUMP, MARK <nombre>)\n");
        while (true)
        {
            if (fgets(line, sizeof(line), stdin) == nullptr)
            {
                clearerr(stdin); vTaskDelay(pdMS_TO_TICKS(50)); continue;
            }
            line[strcspn(line, "\r\n")] = '\0';
            if (strcasecmp(line, "METRICS INFO") == 0) PrintInfo();
            else if (strcasecmp(line, "METRICS START") == 0 || strcasecmp(line, "METRICS CLEAR") == 0)
            {
                TraceBuffer::Clear(); printf("METRICS_OK STARTED\n");
            }
            else if (strcasecmp(line, "METRICS FREEZE") == 0)
            {
                TraceBuffer::SnapshotHeader h{}; TraceBuffer::Freeze(h);
                printf("METRICS_OK FROZEN count=%lu overwritten=%llu\n",
                       static_cast<unsigned long>(h.count), static_cast<unsigned long long>(h.overwritten));
            }
            else if (strcasecmp(line, "METRICS DUMP") == 0) DumpSerial();
            else if (strcasecmp(line, "SD PROFILE") == 0)
            {
                if (TraceBuffer::IsConnectionActive())
                    printf("SD_PROFILE_ERROR SMB_ACTIVE disconnect_PS2_first\n");
                else
                    SdProfiler::Start();
            }
            else if (strncasecmp(line, "MARK ", 5) == 0)
            {
                TraceBuffer::Marker marker{};
                if (TraceBuffer::ParseMarker(line + 5, marker) && TraceBuffer::RecordMarker(marker))
                    printf("METRICS_OK MARK %s\n", line + 5);
                else printf("METRICS_ERROR UNKNOWN_MARK %s\n", line + 5);
            }
        }
    }
}

namespace TraceBuffer
{
    bool Init()
    {
        if constexpr (!ENABLED) return false;
        if (events != nullptr) return true;
        events = static_cast<Event *>(heap_caps_calloc(EVENT_CAPACITY, sizeof(Event), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        slowEvents = static_cast<Event *>(heap_caps_calloc(SLOW_EVENT_CAPACITY, sizeof(Event), MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));
        if (events == nullptr || slowEvents == nullptr)
        {
            if (events != nullptr) heap_caps_free(events);
            if (slowEvents != nullptr) heap_caps_free(slowEvents);
            events = slowEvents = nullptr;
            printf("METRICS: no fue posible reservar %u bytes en PSRAM\n",
                   static_cast<unsigned>((EVENT_CAPACITY + SLOW_EVENT_CAPACITY) * sizeof(Event)));
            return false;
        }
        capacity = EVENT_CAPACITY; Clear();
        Record(EventType::System, Phase::Idle, 0, 0, 0, 0, 0, 0, 0, 1,
               static_cast<uint32_t>((EVENT_CAPACITY + SLOW_EVENT_CAPACITY) * sizeof(Event)));
        printf("METRICS: activo, eventos=%u lentos=%u memoria_eventos=%u bytes PSRAM\n",
               static_cast<unsigned>(EVENT_CAPACITY),
               static_cast<unsigned>(SLOW_EVENT_CAPACITY),
               static_cast<unsigned>((EVENT_CAPACITY + SLOW_EVENT_CAPACITY) * sizeof(Event)));
        return true;
    }

    bool StartSerialConsole()
    {
        if (!IsEnabled()) return false;

#if CONFIG_ESP_CONSOLE_UART
        const auto consoleUart = static_cast<uart_port_t>(CONFIG_ESP_CONSOLE_UART_NUM);
        if (!uart_is_driver_installed(consoleUart))
        {
            const esp_err_t installResult = uart_driver_install(
                consoleUart,
                1024,
                0,
                0,
                nullptr,
                0);
            if (installResult != ESP_OK)
            {
                printf("METRICS: error instalando RX UART: %s\n", esp_err_to_name(installResult));
                return false;
            }
        }
        uart_vfs_dev_use_driver(consoleUart);
#endif

        return xTaskCreate(SerialConsoleTask, "metrics_uart", 4096, nullptr, 2, nullptr) == pdPASS;
    }

    bool IsEnabled() { return ENABLED && events != nullptr; }

    void Record(EventType type, Phase phase, uint16_t connectionId, uint8_t command,
                uint16_t multiplexId, uint16_t fileId, uint64_t fileOffset,
                uint16_t size, uint32_t durationUs, int32_t result,
                uint32_t auxiliary, uint8_t flags)
    {
        if (!IsEnabled()) return;
        const Event event = MakeEvent(type, phase, connectionId, command, multiplexId,
                                      fileId, fileOffset, size, durationUs, result, auxiliary, flags);
        portENTER_CRITICAL(&traceMux);
        if (!frozen) StoreEventUnlocked(event); else ++metrics.ignoredWhileFrozen;
        portEXIT_CRITICAL(&traceMux);
    }

    void SetActive(Phase phase, uint16_t connectionId, uint8_t command,
                   uint16_t multiplexId, uint16_t fileId, uint64_t fileOffset,
                   uint16_t size, uint32_t auxiliary)
    {
        if (!IsEnabled()) return;
        const Event event = MakeEvent(EventType::System, phase, connectionId, command,
                                      multiplexId, fileId, fileOffset, size, 0, 0, auxiliary, 0);
        portENTER_CRITICAL(&traceMux); if (!frozen) activeOperation = event; portEXIT_CRITICAL(&traceMux);
    }

    void ClearActive(uint16_t connectionId) { SetActive(Phase::Idle, connectionId); }

    void RecordHeap(uint16_t connectionId, uint32_t readCount)
    {
        if (!IsEnabled()) return;
        Record(EventType::Heap, Phase::Idle, connectionId, 0,
               static_cast<uint16_t>(readCount), static_cast<uint16_t>(readCount >> 16),
               heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT), 0,
               ClampDuration(heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT)),
               static_cast<int32_t>(std::min<size_t>(heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT), INT32_MAX)),
               static_cast<uint32_t>(heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT)));
    }

    void RecordConnectionOpen()
    {
        if (!IsEnabled()) return;
        portENTER_CRITICAL(&traceMux);
        if (!frozen)
        {
            if (metrics.connections > 0) ++metrics.reconnections;
            ++metrics.connections; lastOperationEndedUs = 0;
        }
        portEXIT_CRITICAL(&traceMux);
    }

    void SetConnectionActive(bool active)
    {
        if (!IsEnabled()) return;
        portENTER_CRITICAL(&traceMux);
        connectionActive = active;
        portEXIT_CRITICAL(&traceMux);
    }

    bool IsConnectionActive()
    {
        if (!IsEnabled()) return false;
        bool active;
        portENTER_CRITICAL(&traceMux);
        active = connectionActive;
        portEXIT_CRITICAL(&traceMux);
        return active;
    }

    void RecordSmbOperation(uint64_t startedUs, uint16_t connectionId,
                            uint8_t command, uint16_t multiplexId, uint16_t fileId,
                            uint64_t fileOffset, uint16_t requestedBytes,
                            int32_t deliveredOrError, uint32_t seekUs, uint32_t readUs,
                            uint32_t sendUs, uint8_t flags)
    {
        if (!IsEnabled()) return;
        const uint64_t endedUs = static_cast<uint64_t>(esp_timer_get_time());
        const uint32_t durationUs = ClampDuration(endedUs >= startedUs ? endedUs - startedUs : 0);
        uint32_t gapUs = 0;
        portENTER_CRITICAL(&traceMux);
        if (!frozen)
        {
            if (lastOperationEndedUs != 0 && startedUs >= lastOperationEndedUs)
                gapUs = ClampDuration(startedUs - lastOperationEndedUs);
            lastOperationEndedUs = endedUs;
            Event event = MakeEvent(EventType::SmbOperation, Phase::Dispatch,
                                    connectionId, command, multiplexId, fileId,
                                    fileOffset, requestedBytes, durationUs,
                                    deliveredOrError, gapUs, flags, startedUs);
            StoreEventUnlocked(event);
            ++metrics.smbOperations;
            ObserveLatency(metrics.smbLatency, durationUs); ObserveLatency(metrics.clientGap, gapUs);
            if (gapUs > 100000) ++metrics.idleOver100ms;
            if (gapUs > 500000) ++metrics.idleOver500ms;
            if (gapUs > 1000000) ++metrics.idleOver1000ms;
            if (command == 0x2E)
            {
                ++metrics.readRequests; metrics.requestedBytes += requestedBytes;
                if (deliveredOrError > 0) metrics.deliveredBytes += static_cast<uint32_t>(deliveredOrError);
                metrics.totalSeekUs += seekUs; metrics.totalReadUs += readUs; metrics.totalSendUs += sendUs;
                ObserveLatency(metrics.seekLatency, seekUs); ObserveLatency(metrics.readLatency, readUs);
                ObserveLatency(metrics.sendLatency, sendUs);
                if (flags & FlagCacheHit) ++metrics.cacheHits;
                if (flags & FlagCacheMiss) ++metrics.cacheMisses;
                if (flags & FlagSequential) ++metrics.sequentialReads;
                if (flags & FlagForwardJump) ++metrics.forwardJumps;
                if (flags & FlagBackwardJump) ++metrics.backwardJumps;
                if (flags & FlagRepeated) ++metrics.repeatedReads;
                if (flags & FlagPartial) ++metrics.partialReads;
                if (deliveredOrError < 0) ++metrics.fatFsErrors;
            }
            if (durationUs >= SLOW_SMB_US || (flags & (FlagPartial | FlagError))) StoreSlowUnlocked(event);
            auto storePhase = [&](Phase phase, EventType type, uint32_t phaseUs)
            {
                if (phaseUs >= SLOW_PHASE_US)
                    StoreSlowUnlocked(MakeEvent(type, phase, connectionId, command, multiplexId,
                                                fileId, fileOffset, requestedBytes, phaseUs,
                                                deliveredOrError, 0, flags, startedUs));
            };
            storePhase(Phase::Seek, EventType::Seek, seekUs);
            storePhase(Phase::Read, EventType::Read, readUs);
            storePhase(Phase::Send, EventType::Send, sendUs);
        }
        else ++metrics.ignoredWhileFrozen;
        portEXIT_CRITICAL(&traceMux);
    }

    void RecordTcpTransfer(size_t requested, size_t sent, uint32_t calls, int errorCode)
    {
        if (!IsEnabled()) return;
        portENTER_CRITICAL(&traceMux);
        if (!frozen)
        {
            if (calls > 1 || sent < requested) ++metrics.tcpPartialSends;
            metrics.tcpBytesSent += sent;
            metrics.tcpSendCalls += calls;
            if (errorCode != 0) ++metrics.tcpErrors;
        }
        portEXIT_CRITICAL(&traceMux);
    }

    void RecordFatFsError()
    {
        if (!IsEnabled()) return;
        portENTER_CRITICAL(&traceMux);
        if (!frozen) ++metrics.fatFsErrors;
        portEXIT_CRITICAL(&traceMux);
    }
    void RecordSdError()
    {
        if (!IsEnabled()) return;
        portENTER_CRITICAL(&traceMux);
        if (!frozen) ++metrics.sdErrors;
        portEXIT_CRITICAL(&traceMux);
    }

    bool RecordMarker(Marker marker)
    {
        if (!IsEnabled() || marker == Marker::Unknown) return false;
        Record(EventType::Marker, Phase::Idle, 0, static_cast<uint8_t>(marker)); return true;
    }

    bool ParseMarker(const char *name, Marker &marker)
    {
        struct Entry { const char *name; Marker marker; };
        static constexpr Entry entries[] = {
            {"MARVEL_START", Marker::MarvelStart}, {"MARVEL_MAGENTA_1", Marker::MarvelMagenta1},
            {"MARVEL_GREEN", Marker::MarvelGreen}, {"MARVEL_MAGENTA_2", Marker::MarvelMagenta2},
            {"MARVEL_YELLOW", Marker::MarvelYellow}, {"MARVEL_RUNNING", Marker::MarvelRunning},
            {"MARVEL_CINEMATIC_START", Marker::MarvelCinematicStart}, {"MARVEL_CINEMATIC_END", Marker::MarvelCinematicEnd},
            {"GOW_START", Marker::GowStart}, {"GOW_MAGENTA_1", Marker::GowMagenta1},
            {"GOW_GREEN", Marker::GowGreen}, {"GOW_MAGENTA_2", Marker::GowMagenta2},
            {"GOW_YELLOW", Marker::GowYellow}, {"GOW_RUNNING", Marker::GowRunning},
            {"GOW_CINEMATIC_START", Marker::GowCinematicStart}, {"GOW_STUTTER", Marker::GowStutter},
            {"GOW_CINEMATIC_END", Marker::GowCinematicEnd}, {"GAMEPLAY", Marker::Gameplay},
            {"GAME_LOAD_START", Marker::GameLoadStart}, {"SCREEN_MAGENTA_1", Marker::ScreenMagenta1},
            {"SCREEN_GREEN", Marker::ScreenGreen}, {"SCREEN_MAGENTA_2", Marker::ScreenMagenta2},
            {"SCREEN_YELLOW", Marker::ScreenYellow}, {"GAME_RUNNING", Marker::GameRunning},
            {"CINEMATIC_START", Marker::CinematicStart}, {"CINEMATIC_STUTTER", Marker::CinematicStutter},
            {"CINEMATIC_END", Marker::CinematicEnd}
        };
        for (const auto &entry : entries)
            if (strcasecmp(name, entry.name) == 0) { marker = entry.marker; return true; }
        marker = Marker::Unknown; return false;
    }

    bool GetInfo(SnapshotHeader &header)
    {
        if (!IsEnabled()) return false;
        portENTER_CRITICAL(&traceMux); FillHeader(header); portEXIT_CRITICAL(&traceMux); return true;
    }
    bool GetSummary(MetricsSummary &summary)
    {
        if (!IsEnabled()) return false;
        portENTER_CRITICAL(&traceMux); summary = metrics; portEXIT_CRITICAL(&traceMux); return true;
    }
    bool Freeze(SnapshotHeader &header)
    {
        if (!IsEnabled()) return false;
        portENTER_CRITICAL(&traceMux); frozen = true; FillHeader(header); portEXIT_CRITICAL(&traceMux); return true;
    }
    bool CopySnapshotEvent(uint32_t index, Event &event)
    {
        if (!IsEnabled()) return false;
        bool ok; portENTER_CRITICAL(&traceMux); ok = frozen && GetEventAt(index, event, false); portEXIT_CRITICAL(&traceMux); return ok;
    }
    bool CopySlowEvent(uint32_t index, Event &event)
    {
        if (!IsEnabled()) return false;
        bool ok; portENTER_CRITICAL(&traceMux); ok = frozen && GetEventAt(index, event, true); portEXIT_CRITICAL(&traceMux); return ok;
    }
    void Clear()
    {
        if (!IsEnabled()) return;
        portENTER_CRITICAL(&traceMux);
        writeIndex = eventCount = slowWriteIndex = slowEventCount = 0;
        totalRecorded = lastOperationEndedUs = 0; frozen = false;
        activeOperation = Event{}; metrics = MetricsSummary{};
        metrics.captureStartedUs = static_cast<uint64_t>(esp_timer_get_time());
        portEXIT_CRITICAL(&traceMux);
    }
}

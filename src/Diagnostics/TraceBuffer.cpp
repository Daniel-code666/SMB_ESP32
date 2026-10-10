#include "TraceBuffer.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "esp_heap_caps.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace
{
    TraceBuffer::Event *events = nullptr;
    uint32_t capacity = 0;
    uint32_t writeIndex = 0;
    uint32_t eventCount = 0;
    uint64_t totalRecorded = 0;
    bool frozen = false;
    TraceBuffer::Event activeOperation{};
    portMUX_TYPE traceMux = portMUX_INITIALIZER_UNLOCKED;
    constexpr int64_t AUTO_FREEZE_US = 30LL * 1000LL * 1000LL;

    uint32_t ClampDuration(uint64_t durationUs)
    {
        return static_cast<uint32_t>(
            std::min<uint64_t>(durationUs, UINT32_MAX));
    }

    TraceBuffer::Event MakeEvent(
        TraceBuffer::EventType type,
        TraceBuffer::Phase phase,
        uint16_t connectionId,
        uint8_t command,
        uint16_t multiplexId,
        uint16_t fileId,
        uint64_t fileOffset,
        uint16_t size,
        uint32_t durationUs,
        int32_t result,
        uint32_t auxiliary,
        uint8_t flags)
    {
        TraceBuffer::Event event{};
        event.timestampUs = static_cast<uint64_t>(esp_timer_get_time());
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

    void FillHeader(TraceBuffer::SnapshotHeader &header)
    {
        header = TraceBuffer::SnapshotHeader{};
        constexpr char magic[8] = {'S', 'M', 'B', 'T', 'R', 'C', '1', '\0'};
        memcpy(header.magic, magic, sizeof(magic));
        header.version = TraceBuffer::FORMAT_VERSION;
        header.headerSize = sizeof(TraceBuffer::SnapshotHeader);
        header.eventSize = sizeof(TraceBuffer::Event);
        header.capacity = capacity;
        header.count = eventCount;
        header.totalRecorded = totalRecorded;
        header.overwritten = totalRecorded > capacity
            ? totalRecorded - capacity
            : 0;
        header.frozen = frozen ? 1U : 0U;
        header.activeOperation = activeOperation;
    }

    void TraceMonitorTask(void *)
    {
        while (true)
        {
            vTaskDelay(pdMS_TO_TICKS(1000));

            bool frozeNow = false;
            uint32_t frozenCount = 0;
            uint64_t frozenOverwritten = 0;
            const uint64_t nowUs = static_cast<uint64_t>(esp_timer_get_time());

            portENTER_CRITICAL(&traceMux);
            if (
                events != nullptr &&
                !frozen &&
                activeOperation.connectionId != 0 &&
                activeOperation.phase != static_cast<uint8_t>(TraceBuffer::Phase::Idle) &&
                nowUs >= activeOperation.timestampUs &&
                nowUs - activeOperation.timestampUs >= static_cast<uint64_t>(AUTO_FREEZE_US))
            {
                frozen = true;
                frozeNow = true;
                frozenCount = eventCount;
                frozenOverwritten = totalRecorded > capacity
                    ? totalRecorded - capacity
                    : 0;
            }
            portEXIT_CRITICAL(&traceMux);

            if (frozeNow)
            {
                printf(
                    "TRACE: congelado automaticamente: operacion activa sin terminar durante 30s; "
                    "eventos=%lu, sobrescritos=%llu\n",
                    static_cast<unsigned long>(frozenCount),
                    static_cast<unsigned long long>(frozenOverwritten));
            }
        }
    }
}

namespace TraceBuffer
{
    bool Init()
    {
        if constexpr (!ENABLED)
        {
            return false;
        }

        if (events != nullptr)
        {
            return true;
        }

        events = static_cast<Event *>(
            heap_caps_calloc(
                EVENT_CAPACITY,
                sizeof(Event),
                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT));

        if (events == nullptr)
        {
            printf("TRACE: no fue posible reservar %u bytes en PSRAM; trazador desactivado\n",
                   static_cast<unsigned>(EVENT_CAPACITY * sizeof(Event)));
            return false;
        }

        capacity = EVENT_CAPACITY;
        Clear();
        Record(EventType::System, Phase::Idle, 0, 0, 0, 0, 0, 0, 0, 1,
               static_cast<uint32_t>(EVENT_CAPACITY * sizeof(Event)));

        printf("TRACE: activo, %u eventos de %u bytes (%u bytes PSRAM)\n",
               static_cast<unsigned>(capacity),
               static_cast<unsigned>(sizeof(Event)),
               static_cast<unsigned>(capacity * sizeof(Event)));

        if (
            xTaskCreate(
                TraceMonitorTask,
                "trace_monitor",
                3072,
                nullptr,
                2,
                nullptr) != pdPASS)
        {
            printf("TRACE: no fue posible iniciar monitor de congelado automatico\n");
        }
        return true;
    }

    bool IsEnabled()
    {
        return ENABLED && events != nullptr;
    }

    void Record(
        EventType type,
        Phase phase,
        uint16_t connectionId,
        uint8_t command,
        uint16_t multiplexId,
        uint16_t fileId,
        uint64_t fileOffset,
        uint16_t size,
        uint32_t durationUs,
        int32_t result,
        uint32_t auxiliary,
        uint8_t flags)
    {
        if (events == nullptr)
        {
            return;
        }

        const Event event = MakeEvent(
            type, phase, connectionId, command, multiplexId, fileId,
            fileOffset, size, durationUs, result, auxiliary, flags);

        portENTER_CRITICAL(&traceMux);
        if (!frozen)
        {
            events[writeIndex] = event;
            writeIndex = (writeIndex + 1U) % capacity;
            if (eventCount < capacity)
            {
                ++eventCount;
            }
            ++totalRecorded;
        }
        portEXIT_CRITICAL(&traceMux);
    }

    void SetActive(
        Phase phase,
        uint16_t connectionId,
        uint8_t command,
        uint16_t multiplexId,
        uint16_t fileId,
        uint64_t fileOffset,
        uint16_t size,
        uint32_t auxiliary)
    {
        if (events == nullptr)
        {
            return;
        }

        const Event event = MakeEvent(
            EventType::System, phase, connectionId, command, multiplexId,
            fileId, fileOffset, size, 0, 0, auxiliary, 0);

        portENTER_CRITICAL(&traceMux);
        if (!frozen)
        {
            const bool sameOperation =
                activeOperation.phase == event.phase &&
                activeOperation.connectionId == event.connectionId &&
                activeOperation.command == event.command &&
                activeOperation.multiplexId == event.multiplexId &&
                activeOperation.fileId == event.fileId &&
                activeOperation.fileOffset == event.fileOffset &&
                activeOperation.size == event.size &&
                activeOperation.auxiliary == event.auxiliary;

            if (!sameOperation)
            {
                activeOperation = event;
            }
        }
        portEXIT_CRITICAL(&traceMux);
    }

    void ClearActive(uint16_t connectionId)
    {
        SetActive(Phase::Idle, connectionId);
    }

    void RecordHeap(uint16_t connectionId, uint32_t readCount)
    {
        if (events == nullptr)
        {
            return;
        }

        const size_t internalFree =
            heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        const size_t internalLargest =
            heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        const size_t internalMinimum =
            heap_caps_get_minimum_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        const size_t psramFree =
            heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);

        Record(
            EventType::Heap,
            Phase::Idle,
            connectionId,
            0,
            static_cast<uint16_t>(readCount & 0xFFFFU),
            static_cast<uint16_t>((readCount >> 16) & 0xFFFFU),
            static_cast<uint64_t>(internalFree),
            0,
            ClampDuration(internalLargest),
            static_cast<int32_t>(std::min<size_t>(internalMinimum, INT32_MAX)),
            static_cast<uint32_t>(std::min<size_t>(psramFree, UINT32_MAX)),
            static_cast<uint8_t>(readCount & 0xFF));
    }

    bool GetInfo(SnapshotHeader &header)
    {
        if (events == nullptr)
        {
            return false;
        }

        portENTER_CRITICAL(&traceMux);
        FillHeader(header);
        portEXIT_CRITICAL(&traceMux);
        return true;
    }

    bool Freeze(SnapshotHeader &header)
    {
        if (events == nullptr)
        {
            return false;
        }

        portENTER_CRITICAL(&traceMux);
        frozen = true;
        FillHeader(header);
        portEXIT_CRITICAL(&traceMux);
        return true;
    }

    bool CopySnapshotEvent(uint32_t chronologicalIndex, Event &event)
    {
        if (events == nullptr)
        {
            return false;
        }

        bool copied = false;
        portENTER_CRITICAL(&traceMux);
        if (frozen && chronologicalIndex < eventCount)
        {
            const uint32_t oldest = eventCount < capacity ? 0U : writeIndex;
            const uint32_t physicalIndex =
                (oldest + chronologicalIndex) % capacity;
            event = events[physicalIndex];
            copied = true;
        }
        portEXIT_CRITICAL(&traceMux);
        return copied;
    }

    void Clear()
    {
        if (events == nullptr)
        {
            return;
        }

        portENTER_CRITICAL(&traceMux);
        writeIndex = 0;
        eventCount = 0;
        totalRecorded = 0;
        frozen = false;
        activeOperation = Event{};
        portEXIT_CRITICAL(&traceMux);
    }
}

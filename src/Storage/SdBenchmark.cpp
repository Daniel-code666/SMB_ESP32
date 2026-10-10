#include "SdStorage.h"
#include "SdStorageConstants.h"

#include <cstdio>
#include <cstdint>

#include "esp_timer.h"
#include "esp_heap_caps.h"

namespace SdStorage
{
    bool BenchmarkRead()
    {
        printf(
            "\n=== SD READ BENCHMARK ===\n"
        );

        if (!IsMounted())
        {
            printf(
                "No hay una microSD montada\n"
            );

            return false;
        }

        FILE* file =
            fopen(
                SdStorageConstants::Paths::BENCHMARK_FILE,
                "rb"
            );

        if (file == nullptr)
        {
            printf(
                "No fue posible abrir: %s\n",
                SdStorageConstants::Paths::BENCHMARK_FILE
            );

            return false;
        }

        uint8_t* buffer =
            static_cast<uint8_t*>(
                heap_caps_malloc(
                    SdStorageConstants::Benchmark::BUFFER_SIZE,
                    MALLOC_CAP_DMA |
                    MALLOC_CAP_INTERNAL
                )
            );

        if (buffer == nullptr)
        {
            printf(
                "No fue posible reservar buffer DMA\n"
            );

            fclose(file);

            return false;
        }

        uint64_t totalBytesRead = 0;

        const int64_t startTime =
            esp_timer_get_time();

        while (true)
        {
            const size_t bytesRead =
                fread(
                    buffer,
                    1,
                    SdStorageConstants::Benchmark::BUFFER_SIZE,
                    file
                );

            totalBytesRead += bytesRead;

            if (
                bytesRead <
                SdStorageConstants::Benchmark::BUFFER_SIZE
            )
            {
                if (feof(file))
                {
                    break;
                }

                if (ferror(file))
                {
                    printf(
                        "Error durante la lectura\n"
                    );

                    heap_caps_free(buffer);
                    fclose(file);

                    return false;
                }
            }
        }

        const int64_t endTime =
            esp_timer_get_time();

        fclose(file);

        heap_caps_free(buffer);

        const double elapsedSeconds =
            static_cast<double>(
                endTime - startTime
            ) /
            1000000.0;

        const double megabytesRead =
            static_cast<double>(
                totalBytesRead
            ) /
            (1024.0 * 1024.0);

        const double megabytesPerSecond =
            elapsedSeconds > 0.0
                ? megabytesRead /
                    elapsedSeconds
                : 0.0;

        printf(
            "Bytes leídos: %llu\n",
            static_cast<unsigned long long>(
                totalBytesRead
            )
        );

        printf(
            "Datos leídos: %.2f MB\n",
            megabytesRead
        );

        printf(
            "Tiempo: %.2f segundos\n",
            elapsedSeconds
        );

        printf(
            "Velocidad: %.2f MB/s\n",
            megabytesPerSecond
        );

        printf(
            "=========================\n\n"
        );

        return true;
    }
}
#include "SdProfiler.h"

#include "SdStorage.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "ff.h"
#include "diskio_sdmmc.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace
{
    constexpr size_t IO_SIZE = 8 * 1024;
    constexpr size_t PROFILE_BYTES = 4 * 1024 * 1024;
    constexpr FSIZE_t PROFILE_OFFSET = 1024 * 1024;
    constexpr uint32_t BATCHES[] = {1, 2, 4, 8, 16};
    constexpr size_t MAX_SAMPLES = PROFILE_BYTES / IO_SIZE;
    constexpr uint32_t PROFILE_TASK_STACK_BYTES = 12 * 1024;
    bool profileRunning = false;
    portMUX_TYPE profileMux = portMUX_INITIALIZER_UNLOCKED;

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

    uint32_t Percentile(const uint32_t *sorted, size_t count, uint32_t percent)
    {
        if (count == 0) return 0;
        const size_t rank = ((count * percent) + 99U) / 100U;
        return sorted[rank == 0 ? 0 : std::min(rank - 1U, count - 1U)];
    }

    class ProfileGuard
    {
    public:
        ProfileGuard()
        {
            ff_sdmmc_set_read_batch_size(1);
            ff_sdmmc_enable_read_stats(true);
        }

        ~ProfileGuard()
        {
            Restore();
        }

        void Restore()
        {
            if (restored_) return;
            ff_sdmmc_set_read_batch_size(1);
            ff_sdmmc_enable_read_stats(false);
            restored_ = true;
        }

    private:
        bool restored_ = false;
    };

    struct Result
    {
        FRESULT fatResult = FR_OK;
        uint64_t bytes = 0;
        uint64_t elapsedUs = 0;
        uint32_t crc32 = 0;
        uint32_t sampleCount = 0;
        uint32_t p50Us = 0;
        uint32_t p95Us = 0;
        uint32_t p99Us = 0;
        uint32_t maximumUs = 0;
        ff_sdmmc_read_stats_t disk{};
    };

    Result RunMode(const char *path, uint32_t batch, uint8_t *buffer, uint32_t *samples)
    {
        Result result{};
        FIL file{};
        ff_sdmmc_set_read_batch_size(batch);

        result.fatResult = f_open(&file, path, FA_READ);
        if (result.fatResult != FR_OK) return result;

        result.fatResult = f_lseek(&file, PROFILE_OFFSET);
        if (result.fatResult != FR_OK)
        {
            f_close(&file);
            return result;
        }

        ff_sdmmc_reset_read_stats();
        uint32_t crc = 0xFFFFFFFFU;
        while (result.bytes < PROFILE_BYTES && result.sampleCount < MAX_SAMPLES)
        {
            const UINT wanted = static_cast<UINT>(
                std::min<uint64_t>(IO_SIZE, PROFILE_BYTES - result.bytes));
            UINT bytesRead = 0;
            const int64_t readStartedUs = esp_timer_get_time();
            result.fatResult = f_read(&file, buffer, wanted, &bytesRead);
            const uint32_t readUs = static_cast<uint32_t>(esp_timer_get_time() - readStartedUs);
            samples[result.sampleCount++] = readUs;
            result.elapsedUs += readUs;
            if (result.fatResult != FR_OK || bytesRead == 0) break;
            crc = Crc32Update(crc, buffer, bytesRead);
            result.bytes += bytesRead;
            if (bytesRead != wanted) break;
        }
        result.crc32 = crc ^ 0xFFFFFFFFU;
        f_close(&file);
        ff_sdmmc_get_read_stats(&result.disk);

        std::sort(samples, samples + result.sampleCount);
        result.p50Us = Percentile(samples, result.sampleCount, 50);
        result.p95Us = Percentile(samples, result.sampleCount, 95);
        result.p99Us = Percentile(samples, result.sampleCount, 99);
        result.maximumUs = result.sampleCount == 0 ? 0 : samples[result.sampleCount - 1];
        return result;
    }
}

namespace SdProfiler
{
    static bool Run()
    {
        if (!SdStorage::IsMounted())
        {
            printf("SD_PROFILE_ERROR SD_NOT_MOUNTED\n");
            return false;
        }

        char relativePath[512]{};
        if (!SdStorage::GetFirstIsoPath(relativePath, sizeof(relativePath)))
        {
            printf("SD_PROFILE_ERROR ISO_NOT_FOUND\n");
            return false;
        }

        char fatPath[520]{};
        const int pathLength = snprintf(fatPath, sizeof(fatPath), "0:/%s", relativePath);
        if (pathLength < 0 || pathLength >= static_cast<int>(sizeof(fatPath)))
        {
            printf("SD_PROFILE_ERROR PATH_TOO_LONG\n");
            return false;
        }

        uint8_t *buffer = static_cast<uint8_t *>(
            heap_caps_malloc(IO_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_DMA));
        uint32_t *samples = static_cast<uint32_t *>(
            heap_caps_malloc(MAX_SAMPLES * sizeof(uint32_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        if (buffer == nullptr || samples == nullptr)
        {
            if (buffer != nullptr) heap_caps_free(buffer);
            if (samples != nullptr) heap_caps_free(samples);
            printf("SD_PROFILE_ERROR NO_INTERNAL_RAM required=%u\n",
                   static_cast<unsigned>(IO_SIZE + MAX_SAMPLES * sizeof(uint32_t)));
            return false;
        }

        ProfileGuard guard;
        printf("SD_PROFILE_BEGIN file=%s offset=%llu bytes=%u io=%u normal_batch=1\n",
               relativePath, static_cast<unsigned long long>(PROFILE_OFFSET),
               static_cast<unsigned>(PROFILE_BYTES), static_cast<unsigned>(IO_SIZE));

        bool allValid = true;
        bool baselineSet = false;
        uint32_t baselineCrc = 0;
        for (const uint32_t batch : BATCHES)
        {
            const Result result = RunMode(fatPath, batch, buffer, samples);
            const bool complete = result.fatResult == FR_OK && result.bytes == PROFILE_BYTES;
            if (batch == 1 && complete)
            {
                baselineCrc = result.crc32;
                baselineSet = true;
            }
            const bool crcMatches = baselineSet && result.crc32 == baselineCrc;
            const bool valid = complete && crcMatches && result.disk.error_count == 0;
            const double kibPerSecond = result.elapsedUs == 0 ? 0.0 :
                static_cast<double>(result.bytes) * 1000000.0 /
                static_cast<double>(result.elapsedUs) / 1024.0;

            printf(
                "SD_PROFILE_RESULT batch=%lu valid=%u fatfs=%d bytes=%llu elapsed_us=%llu "
                "kib_s=%.1f p50_us=%lu p95_us=%lu p99_us=%lu max_us=%lu "
                "commands=%llu sectors=%llu errors=%lu last_error=0x%lX "
                "crc32=%08lX crc_match=%u\n",
                static_cast<unsigned long>(batch), valid ? 1U : 0U,
                static_cast<int>(result.fatResult), static_cast<unsigned long long>(result.bytes),
                static_cast<unsigned long long>(result.elapsedUs), kibPerSecond,
                static_cast<unsigned long>(result.p50Us), static_cast<unsigned long>(result.p95Us),
                static_cast<unsigned long>(result.p99Us), static_cast<unsigned long>(result.maximumUs),
                static_cast<unsigned long long>(result.disk.command_count),
                static_cast<unsigned long long>(result.disk.sector_count),
                static_cast<unsigned long>(result.disk.error_count),
                static_cast<unsigned long>(result.disk.last_error),
                static_cast<unsigned long>(result.crc32), crcMatches ? 1U : 0U);
            if (!valid) allValid = false;
        }

        heap_caps_free(samples);
        heap_caps_free(buffer);
        guard.Restore();
        printf("SD_PROFILE_END all_valid=%u restored_batch=1 stack_free_min=%u\n",
               allValid ? 1U : 0U,
               static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr)));
        return allValid;
    }

    static void ProfileTask(void *)
    {
        Run();
        portENTER_CRITICAL(&profileMux);
        profileRunning = false;
        portEXIT_CRITICAL(&profileMux);
        vTaskDelete(nullptr);
    }

    bool Start()
    {
        portENTER_CRITICAL(&profileMux);
        if (profileRunning)
        {
            portEXIT_CRITICAL(&profileMux);
            printf("SD_PROFILE_ERROR ALREADY_RUNNING\n");
            return false;
        }
        profileRunning = true;
        portEXIT_CRITICAL(&profileMux);

        const BaseType_t created = xTaskCreate(
            ProfileTask, "sd_profile", PROFILE_TASK_STACK_BYTES, nullptr, 1, nullptr);
        if (created != pdPASS)
        {
            portENTER_CRITICAL(&profileMux);
            profileRunning = false;
            portEXIT_CRITICAL(&profileMux);
            printf("SD_PROFILE_ERROR TASK_CREATE_FAILED stack=%lu\n",
                   static_cast<unsigned long>(PROFILE_TASK_STACK_BYTES));
            return false;
        }

        printf("SD_PROFILE_QUEUED stack=%lu\n",
               static_cast<unsigned long>(PROFILE_TASK_STACK_BYTES));
        return true;
    }

    bool IsRunning()
    {
        portENTER_CRITICAL(&profileMux);
        const bool running = profileRunning;
        portEXIT_CRITICAL(&profileMux);
        return running;
    }
}

#include "SystemInfo.h"
#include "SystemInfoConstants.h"

#include <cstdio>

#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_heap_caps.h"

namespace SystemInfo
{
    void Print()
    {
        esp_chip_info_t chipInfo{};
        esp_chip_info(&chipInfo);

        uint32_t flashSize = 0;
        const esp_err_t result = esp_flash_get_size(nullptr, &flashSize);

        const size_t internalFree = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);

        const size_t psramTotal = heap_caps_get_total_size(MALLOC_CAP_SPIRAM);

        const size_t psramFree = heap_caps_get_free_size(MALLOC_CAP_SPIRAM);

        if (result != ESP_OK)
        {
            printf("Unable to get flash size\n");
            return;
        }

        printf("%s", SystemInfoConstants::HEADER);

        printf("Chip: %s\n", SystemInfoConstants::CHIP_NAME);

        printf("CPU cores: %d\n", chipInfo.cores);

        printf("Flash: %lu MB\n", static_cast<unsigned long>(flashSize / SystemInfoConstants::BYTES_PER_MB));

        printf("Internal RAM free: %lu KB\n", static_cast<unsigned long>(internalFree / SystemInfoConstants::BYTES_PER_KB));

        printf("PSRAM total: %lu MB\n", static_cast<unsigned long>(psramTotal / SystemInfoConstants::BYTES_PER_MB));

        printf("PSRAM free: %lu MB\n", static_cast<unsigned long>(psramFree / SystemInfoConstants::BYTES_PER_MB));

        printf("%s", SystemInfoConstants::FOOTER);
    }
}
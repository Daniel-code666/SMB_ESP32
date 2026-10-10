#include "SdStorageInternal.h"
#include "SdStorageConstants.h"

#include <cstdio>

#include "esp_err.h"
#include "esp_vfs_fat.h"

namespace SdStorageInternal
{
    sdmmc_card_t* card = nullptr;
    bool mounted = false;

    bool Unmount()
    {
        if (!mounted)
        {
            return true;
        }

        printf("\n=== SD UNMOUNT ===\n");

        const esp_err_t result =
            esp_vfs_fat_sdcard_unmount(
                SdStorageConstants::Paths::MOUNT_POINT,
                card
            );

        if (result != ESP_OK)
        {
            printf(
                "Error desmontando SD: %s\n",
                esp_err_to_name(result)
            );

            return false;
        }

        card = nullptr;
        mounted = false;

        printf("SD desmontada correctamente\n");
        printf("==================\n\n");

        return true;
    }
}
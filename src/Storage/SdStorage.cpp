#include "SdStorage.h"
#include "SdStorageInternal.h"
#include "SdStorageConstants.h"

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <strings.h>
#include <sys/stat.h>
#include <dirent.h>

#include "esp_err.h"
#include "esp_vfs_fat.h"

#include "driver/sdmmc_host.h"

#include "sdmmc_cmd.h"

#include <climits>

namespace SdStorage
{
    bool Init()
    {
        if (SdStorageInternal::mounted)
        {
            printf(
                "SD ya se encuentra montada\n");

            return true;
        }

        printf("\n=== SD INIT ===\n");

        sdmmc_host_t host = SDMMC_HOST_DEFAULT();

        sdmmc_slot_config_t slotConfig = SDMMC_SLOT_CONFIG_DEFAULT();

        slotConfig.clk = SdStorageConstants::Pins::CLK;

        slotConfig.cmd = SdStorageConstants::Pins::CMD;

        slotConfig.d0 = SdStorageConstants::Pins::D0;

        slotConfig.d1 = SdStorageConstants::Pins::D1;

        slotConfig.d2 = SdStorageConstants::Pins::D2;

        slotConfig.d3 = SdStorageConstants::Pins::D3;

        slotConfig.width = SdStorageConstants::Mount::BUS_WIDTH;

        esp_vfs_fat_sdmmc_mount_config_t mountConfig{};

        mountConfig.format_if_mount_failed = false;

        mountConfig.max_files = SdStorageConstants::Mount::MAX_OPEN_FILES;

        mountConfig.allocation_unit_size = SdStorageConstants::Mount::ALLOCATION_UNIT_SIZE;

        SdStorageInternal::card = nullptr;

        const esp_err_t result =
            esp_vfs_fat_sdmmc_mount(
                SdStorageConstants::Paths::MOUNT_POINT,
                &host,
                &slotConfig,
                &mountConfig,
                &SdStorageInternal::card);

        if (result != ESP_OK)
        {
            SdStorageInternal::card = nullptr;
            SdStorageInternal::mounted = false;

            printf(
                "Error montando SD: %s\n",
                esp_err_to_name(result));

            return false;
        }

        SdStorageInternal::mounted = true;

        printf(
            "SD montada correctamente\n");

        sdmmc_card_print_info(
            stdout,
            SdStorageInternal::card);

        printf("================\n\n");

        return true;
    }

    bool IsMounted()
    {
        return SdStorageInternal::mounted;
    }

    bool IsIsoFile(const char *fileName)
    {
        const char *extension =
            strrchr(
                fileName,
                '.');

        return extension != nullptr &&
               strcasecmp(
                   extension,
                   ".iso") == 0;
    }

    size_t ListIsoFilesFromDirectory(
        const char *directoryPath,
        const char *label)
    {
        DIR *directory =
            opendir(
                directoryPath);

        if (directory == nullptr)
        {
            printf(
                "No fue posible abrir la carpeta: %s\n",
                directoryPath);

            return 0;
        }

        printf(
            "\n=== %s FILES ===\n",
            label);

        dirent *entry = nullptr;
        size_t fileCount = 0;

        while (
            (entry = readdir(directory)) != nullptr)
        {
            if (
                strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            if (!IsIsoFile(entry->d_name))
            {
                continue;
            }

            char fullPath[512];

            const int pathLength =
                snprintf(
                    fullPath,
                    sizeof(fullPath),
                    "%s/%s",
                    directoryPath,
                    entry->d_name);

            if (
                pathLength < 0 ||
                pathLength >=
                    static_cast<int>(
                        sizeof(fullPath)))
            {
                printf(
                    "Ruta demasiado larga: %s\n",
                    entry->d_name);

                continue;
            }

            uint64_t fileSize = 0;

            if (
                !SdStorage::GetFileSize(
                    fullPath,
                    fileSize))
            {
                continue;
            }

            const double sizeMb =
                static_cast<double>(
                    fileSize) /
                (1024.0 * 1024.0);

            printf(
                "[%zu] %s\n",
                fileCount + 1,
                entry->d_name);

            printf(
                "    Ruta:   %s\n",
                fullPath);

            printf(
                "    Tamaño: %llu bytes (%.2f MB)\n",
                static_cast<unsigned long long>(
                    fileSize),
                sizeMb);

            ++fileCount;
        }

        closedir(directory);

        printf(
            "Total %s: %zu\n",
            label,
            fileCount);

        printf(
            "=================\n");

        return fileCount;
    }

    bool GetFirstIsoPathFromDirectory(
        const char *directoryPath,
        const char *relativePrefix,
        char *outputPath,
        size_t outputPathSize)
    {
        DIR *directory =
            opendir(
                directoryPath);

        if (directory == nullptr)
        {
            return false;
        }

        dirent *entry = nullptr;

        while (
            (entry = readdir(directory)) != nullptr)
        {
            if (
                strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
            {
                continue;
            }

            if (!IsIsoFile(entry->d_name))
            {
                continue;
            }

            const int result =
                snprintf(
                    outputPath,
                    outputPathSize,
                    "%s/%s",
                    relativePrefix,
                    entry->d_name);

            if (
                result < 0 ||
                result >=
                    static_cast<int>(
                        outputPathSize))
            {
                closedir(directory);
                return false;
            }

            closedir(directory);
            return true;
        }

        closedir(directory);
        return false;
    }

    bool GetFileSize(const char *path, uint64_t &fileSize)
    {
        fileSize = 0;

        if (!SdStorageInternal::mounted)
        {
            printf("No hay una microSD montada\n");
            return false;
        }

        if (path == nullptr)
        {
            printf("Ruta de archivo invalida\n");
            return false;
        }

        // Convertimos "/sdcard/ISO/file.iso" -> "0:/ISO/file.iso"
        constexpr const char *mountPoint = SdStorageConstants::Paths::MOUNT_POINT;
        const size_t mountLength = strlen(mountPoint);

        if (strncmp(path, mountPoint, mountLength) != 0)
        {
            printf("Ruta fuera del punto de montaje: %s\n", path);
            return false;
        }

        char fatPath[512];

        const int resultLength = snprintf(
            fatPath,
            sizeof(fatPath),
            "0:%s",
            path + mountLength);

        if (resultLength < 0 || resultLength >= static_cast<int>(sizeof(fatPath)))
        {
            printf("Ruta FatFs demasiado larga\n");
            return false;
        }

        FILINFO fileInfo{};

        const FRESULT result = f_stat(fatPath, &fileInfo);

        if (result != FR_OK)
        {
            printf("Error f_stat (%d): %s\n", result, fatPath);
            return false;
        }

        fileSize = static_cast<uint64_t>(fileInfo.fsize);

        printf("sizeof(FSIZE_t): %zu bytes\n", sizeof(FSIZE_t));

        return true;
    }

    bool ListIsoFiles()
    {
        if (!SdStorageInternal::mounted)
        {
            printf(
                "No hay una microSD montada\n");

            return false;
        }

        printf("\n=== OPL ISO FILES ===\n");

        const size_t dvdCount =
            ListIsoFilesFromDirectory(
                SdStorageConstants::Paths::DVD_DIRECTORY,
                "DVD");

        const size_t cdCount =
            ListIsoFilesFromDirectory(
                SdStorageConstants::Paths::CD_DIRECTORY,
                "CD");

        printf(
            "\nTotal ISO: %zu\n",
            dvdCount + cdCount);

        printf(
            "=====================\n\n");

        return true;
    }

    bool GetFirstIsoPath(char *outputPath, size_t outputPathSize)
    {
        if (!SdStorageInternal::mounted)
        {
            return false;
        }

        if (
            outputPath == nullptr ||
            outputPathSize == 0)
        {
            return false;
        }

        if (
            GetFirstIsoPathFromDirectory(
                SdStorageConstants::Paths::DVD_DIRECTORY,
                "DVD",
                outputPath,
                outputPathSize))
        {
            return true;
        }

        if (
            GetFirstIsoPathFromDirectory(
                SdStorageConstants::Paths::CD_DIRECTORY,
                "CD",
                outputPath,
                outputPathSize))
        {
            return true;
        }

        return false;
    }
}
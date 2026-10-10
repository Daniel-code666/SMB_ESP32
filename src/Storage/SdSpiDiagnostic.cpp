#include "SdSpiDiagnostic.h"
#include "SdStorageConstants.h"

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "esp_err.h"
#include "driver/spi_master.h"
#include "driver/sdspi_host.h"
#include "sdmmc_cmd.h"

namespace
{
    constexpr spi_host_device_t SPI_HOST = SPI3_HOST;

    constexpr uint32_t TEST_SECTORS[] =
        {
            8199984,
            8199985,
            8199986,
            8199987,
            8199988,
            8199989,
            8199990,
            8199991,
            8199992,
            8199993,
            8199994,
            8199995,
            8199996,
            8199997,
            8199998,
            8199999,
            8200000,
            8200001,
            8200002,
            8200003,
            8200004,
            8200005,
            8200006,
            8200007,
            8200008,
            8200009,
            8200010,
            8200011,
            8200012,
            8200013,
            8200014,
            8200015};

    constexpr size_t TEST_SECTOR_COUNT =
        sizeof(TEST_SECTORS) / sizeof(TEST_SECTORS[0]);

    void PrintHex32(const uint8_t *data)
    {
        if (data == nullptr)
        {
            return;
        }

        for (int i = 0; i < 32; ++i)
        {
            printf("%02X", data[i]);

            if (i < 31)
            {
                printf(" ");
            }
        }

        printf("\n");
    }

    bool ReadSector(
        sdmmc_card_t *card,
        uint32_t sector,
        uint8_t *buffer)
    {
        const esp_err_t result =
            sdmmc_read_sectors(
                card,
                buffer,
                sector,
                1);

        if (result != ESP_OK)
        {
            printf(
                "ERROR leyendo sector %lu: %s\n",
                static_cast<unsigned long>(sector),
                esp_err_to_name(result));

            return false;
        }

        return true;
    }

    void ReadAndPrintSector(
        sdmmc_card_t *card,
        uint32_t sector,
        bool &success)
    {
        alignas(4) uint8_t buffer[512]{};

        if (!ReadSector(
                card,
                sector,
                buffer))
        {
            success = false;
            return;
        }

        printf(
            "Sector %lu data[0..31]: ",
            static_cast<unsigned long>(sector));

        PrintHex32(buffer);
    }
}

namespace SdSpiDiagnostic
{
    bool Run()
    {
        printf("\n=== SDSPI DIAGNOSTIC ===\n");

        printf(
            "Pins: SCK=%d MOSI=%d MISO=%d CS=%d\n",
            static_cast<int>(SdStorageConstants::Pins::CLK),
            static_cast<int>(SdStorageConstants::Pins::CMD),
            static_cast<int>(SdStorageConstants::Pins::D0),
            static_cast<int>(SdStorageConstants::Pins::D3));

        spi_bus_config_t busConfig{};
        busConfig.mosi_io_num = SdStorageConstants::Pins::CMD;
        busConfig.miso_io_num = SdStorageConstants::Pins::D0;
        busConfig.sclk_io_num = SdStorageConstants::Pins::CLK;
        busConfig.quadwp_io_num = -1;
        busConfig.quadhd_io_num = -1;
        busConfig.max_transfer_sz = 4096;

        esp_err_t result =
            spi_bus_initialize(
                SPI_HOST,
                &busConfig,
                SPI_DMA_CH_AUTO);

        if (result != ESP_OK)
        {
            printf(
                "ERROR spi_bus_initialize: %s\n",
                esp_err_to_name(result));

            return false;
        }

        result = sdspi_host_init();

        if (result != ESP_OK)
        {
            printf(
                "ERROR sdspi_host_init: %s\n",
                esp_err_to_name(result));

            spi_bus_free(SPI_HOST);
            return false;
        }

        sdspi_device_config_t deviceConfig =
            SDSPI_DEVICE_CONFIG_DEFAULT();

        deviceConfig.host_id = SPI_HOST;
        deviceConfig.gpio_cs = SdStorageConstants::Pins::D3;
        deviceConfig.gpio_cd = SDSPI_SLOT_NO_CD;
        deviceConfig.gpio_wp = SDSPI_SLOT_NO_WP;
        deviceConfig.gpio_int = SDSPI_SLOT_NO_INT;

        sdspi_dev_handle_t deviceHandle{};

        result =
            sdspi_host_init_device(
                &deviceConfig,
                &deviceHandle);

        if (result != ESP_OK)
        {
            printf(
                "ERROR sdspi_host_init_device: %s\n",
                esp_err_to_name(result));

            sdspi_host_deinit();
            spi_bus_free(SPI_HOST);
            return false;
        }

        sdmmc_host_t host = SDSPI_HOST_DEFAULT();
        host.slot = deviceHandle;
        host.max_freq_khz = 1000;

        sdmmc_card_t card{};

        result =
            sdmmc_card_init(
                &host,
                &card);

        if (result != ESP_OK)
        {
            printf(
                "ERROR sdmmc_card_init: %s\n",
                esp_err_to_name(result));

            sdspi_host_remove_device(deviceHandle);
            sdspi_host_deinit();
            spi_bus_free(SPI_HOST);
            return false;
        }

        printf("Tarjeta SDSPI inicializada correctamente\n");

        sdmmc_card_print_info(
            stdout,
            &card);

        printf("\n=== RAW SECTOR TEST ===\n");

        bool success = true;

        printf(
            "Lectura consecutiva de sectores 8199984..8200015\n");

        for (size_t i = 0; i < TEST_SECTOR_COUNT; ++i)
        {
            ReadAndPrintSector(
                &card,
                TEST_SECTORS[i],
                success);
        }

        printf("=======================\n");

        const esp_err_t removeResult =
            sdspi_host_remove_device(
                deviceHandle);

        if (removeResult != ESP_OK)
        {
            printf(
                "WARN sdspi_host_remove_device: %s\n",
                esp_err_to_name(removeResult));
        }

        const esp_err_t deinitResult =
            sdspi_host_deinit();

        if (deinitResult != ESP_OK)
        {
            printf(
                "WARN sdspi_host_deinit: %s\n",
                esp_err_to_name(deinitResult));
        }

        const esp_err_t freeBusResult =
            spi_bus_free(
                SPI_HOST);

        if (freeBusResult != ESP_OK)
        {
            printf(
                "WARN spi_bus_free: %s\n",
                esp_err_to_name(freeBusResult));
        }

        printf("=== END SDSPI DIAGNOSTIC ===\n\n");

        return success;
    }
}

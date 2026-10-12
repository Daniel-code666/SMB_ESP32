/*
 * SPDX-FileCopyrightText: 2017-2025 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#pragma once

#include <stdint.h>
#include "sd_protocol_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Enable/disable SD card status checking
 *
 * @param pdrv   drive number
 * @param enable mock ff_sdmmc_status function (return 0)
 */
void ff_sdmmc_set_disk_status_check(BYTE pdrv, bool enable);

/**
 * Register SD/MMC diskio driver
 *
 * @param pdrv  drive number
 * @param card  pointer to sdmmc_card_t structure describing a card; card should be initialized before calling f_mount.
 */
void ff_diskio_register_sdmmc(unsigned char pdrv, sdmmc_card_t* card);

/**
 * @brief Get the first registered drive number corresponding to a card
 *
 * @param card The card to get its drive number
 * @return Driver number to the card
 */
BYTE ff_diskio_get_pdrv_card(const sdmmc_card_t* card);

/**
 * Diagnostic-only control for SDMMC read grouping. The firmware keeps this at
 * one sector during normal operation. Values above one are intended only for
 * the offline, read-only SD profiler.
 */
void ff_sdmmc_set_read_batch_size(uint32_t sectors);
uint32_t ff_sdmmc_get_read_batch_size(void);

typedef struct {
    uint64_t command_count;
    uint64_t sector_count;
    uint32_t error_count;
    int32_t last_error;
} ff_sdmmc_read_stats_t;

void ff_sdmmc_enable_read_stats(bool enable);
void ff_sdmmc_reset_read_stats(void);
void ff_sdmmc_get_read_stats(ff_sdmmc_read_stats_t* stats);

#ifdef __cplusplus
}
#endif

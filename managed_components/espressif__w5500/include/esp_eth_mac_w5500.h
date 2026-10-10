/*
 * SPDX-FileCopyrightText: 2025-2026 Espressif Systems (Shanghai) CO LTD
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#pragma once

#include "esp_eth_com.h"
#include "esp_eth_mac_spi.h"
#include "wiznet_mac_common.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief W5500 specific configuration
 *
 */
typedef struct {
    eth_wiznet_config_t base;                           /*!< Common WIZnet configuration */
    // Additional W5500 specific configuration should be added here.
} eth_w5500_config_t;

/**
 * @brief Default W5500 specific configuration
 *
 */
#define ETH_W5500_DEFAULT_CONFIG(spi_host, spi_devcfg_p) \
    {                                                  \
        .base = {                                      \
            .int_gpio_num = 4,                         \
            .poll_period_ms = 0,                       \
            .spi_host_id = spi_host,                   \
            .spi_devcfg = spi_devcfg_p,                \
            .custom_spi_driver = ETH_DEFAULT_SPI,      \
        },                                             \
    }

/**
* @brief Create W5500 Ethernet MAC instance
*
* @param w5500_config: W5500 specific configuration
* @param mac_config: Ethernet MAC configuration
*
* @return
*      - instance: create MAC instance successfully
*      - NULL: create MAC instance failed because some error occurred
*/
esp_eth_mac_t *esp_eth_mac_new_w5500(const eth_w5500_config_t *w5500_config, const eth_mac_config_t *mac_config);

#ifdef __cplusplus
}
#endif

#include "EthernetManager.h"
#include "EthernetInternal.h"
#include "NetworkConstants.h"
#include "Diagnostics/TraceBuffer.h"

#include <cstdio>

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include "esp_err.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_netif_ip_addr.h"

#include "esp_eth.h"
#include "esp_eth_mac_w5500.h"
#include "esp_eth_phy_w5500.h"

#include "esp_mac.h"

namespace
{
    void EthernetEventHandler(
        void *,
        esp_event_base_t eventBase,
        int32_t eventId,
        void *)
    {
        if (eventBase != ETH_EVENT)
        {
            return;
        }

        switch (eventId)
        {
        case ETHERNET_EVENT_CONNECTED:
        {
            printf("Ethernet link UP\n");

            EthernetInternal::linkUp = true;

            bool autonegotiation = false;
            eth_speed_t speed = ETH_SPEED_10M;
            eth_duplex_t duplex = ETH_DUPLEX_HALF;
            const esp_err_t autonegResult = esp_eth_ioctl(
                EthernetInternal::ethHandle,
                ETH_CMD_G_AUTONEGO,
                &autonegotiation);
            const esp_err_t speedResult = esp_eth_ioctl(
                EthernetInternal::ethHandle,
                ETH_CMD_G_SPEED,
                &speed);
            const esp_err_t duplexResult = esp_eth_ioctl(
                EthernetInternal::ethHandle,
                ETH_CMD_G_DUPLEX_MODE,
                &duplex);
            const uint32_t linkInformation =
                (autonegotiation ? 1U : 0U) |
                (static_cast<uint32_t>(speed) << 8) |
                (static_cast<uint32_t>(duplex) << 16);
            const int32_t linkInformationResult =
                autonegResult == ESP_OK &&
                        speedResult == ESP_OK &&
                        duplexResult == ESP_OK
                    ? 1
                    : -1;

            TraceBuffer::Record(
                TraceBuffer::EventType::EthernetLink,
                TraceBuffer::Phase::Idle,
                0, 0, 0, 0, 0, 0, 0,
                linkInformationResult,
                linkInformation,
                0x01);

            break;
        }

        case ETHERNET_EVENT_DISCONNECTED:
        {
            printf("Ethernet link DOWN\n");

            EthernetInternal::linkUp = false;

            TraceBuffer::Record(
                TraceBuffer::EventType::EthernetLink,
                TraceBuffer::Phase::Idle,
                0, 0, 0, 0, 0, 0, 0,
                0,
                static_cast<uint32_t>(eventId));

            break;
        }

        case ETHERNET_EVENT_START:
        {
            printf("Ethernet iniciado\n");

            TraceBuffer::Record(
                TraceBuffer::EventType::EthernetLink,
                TraceBuffer::Phase::Idle,
                0, 0, 0, 0, 0, 0, 0,
                2,
                static_cast<uint32_t>(eventId));

            break;
        }

        case ETHERNET_EVENT_STOP:
        {
            printf("Ethernet detenido\n");

            EthernetInternal::linkUp = false;

            TraceBuffer::Record(
                TraceBuffer::EventType::EthernetLink,
                TraceBuffer::Phase::Idle,
                0, 0, 0, 0, 0, 0, 0,
                0,
                static_cast<uint32_t>(eventId),
                0x08);

            break;
        }

        default:
        {
            break;
        }
        }
    }

    bool ConfigureMac()
    {
        uint8_t mac[6]{};

        esp_err_t result =
            esp_read_mac(
                mac,
                ESP_MAC_BASE);

        if (result != ESP_OK)
        {
            printf(
                "Error obteniendo MAC base: %s\n",
                esp_err_to_name(result));

            return false;
        }

        // Locally administered + unicast.
        mac[0] |=
            NetworkConstants::Ethernet::Mac::LOCALLY_ADMINISTERED_BIT;

        mac[0] &=
            NetworkConstants::Ethernet::Mac::MULTICAST_BIT_MASK;

        result =
            esp_eth_ioctl(
                EthernetInternal::ethHandle,
                ETH_CMD_S_MAC_ADDR,
                mac);

        if (result != ESP_OK)
        {
            printf(
                "Error configurando MAC: %s\n",
                esp_err_to_name(result));

            return false;
        }

        printf(
            "MAC Ethernet: %02X:%02X:%02X:%02X:%02X:%02X\n",
            mac[0],
            mac[1],
            mac[2],
            mac[3],
            mac[4],
            mac[5]);

        return true;
    }

    bool ConfigureStaticIp()
    {
        if (EthernetInternal::ethNetif == nullptr)
        {
            printf(
                "ethNetif no inicializado\n");

            return false;
        }

        esp_err_t result =
            esp_netif_dhcpc_stop(
                EthernetInternal::ethNetif);

        if (
            result != ESP_OK &&
            result != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED)
        {
            printf(
                "Error deteniendo DHCP: %s\n",
                esp_err_to_name(result));

            return false;
        }

        esp_netif_ip_info_t ipInfo{};

        esp_netif_set_ip4_addr(
            &ipInfo.ip,
            NetworkConstants::Ethernet::Ip::ADDRESS_1,
            NetworkConstants::Ethernet::Ip::ADDRESS_2,
            NetworkConstants::Ethernet::Ip::ADDRESS_3,
            NetworkConstants::Ethernet::Ip::ADDRESS_4);

        esp_netif_set_ip4_addr(
            &ipInfo.netmask,
            NetworkConstants::Ethernet::Ip::MASK_1,
            NetworkConstants::Ethernet::Ip::MASK_2,
            NetworkConstants::Ethernet::Ip::MASK_3,
            NetworkConstants::Ethernet::Ip::MASK_4);

        esp_netif_set_ip4_addr(
            &ipInfo.gw,
            NetworkConstants::Ethernet::Ip::GATEWAY_1,
            NetworkConstants::Ethernet::Ip::GATEWAY_2,
            NetworkConstants::Ethernet::Ip::GATEWAY_3,
            NetworkConstants::Ethernet::Ip::GATEWAY_4);

        result =
            esp_netif_set_ip_info(
                EthernetInternal::ethNetif,
                &ipInfo);

        if (result != ESP_OK)
        {
            printf(
                "Error configurando IP: %s\n",
                esp_err_to_name(result));

            return false;
        }

        printf(
            "IP Ethernet: " IPSTR "\n",
            IP2STR(&ipInfo.ip));

        printf(
            "Mask: " IPSTR "\n",
            IP2STR(&ipInfo.netmask));

        printf(
            "Gateway: " IPSTR "\n",
            IP2STR(&ipInfo.gw));

        return true;
    }
}

const char* duplex_to_name(eth_duplex_t duplex) {
    switch (duplex) {
        case ETH_DUPLEX_HALF: return "HALF DUPLEX";
        case ETH_DUPLEX_FULL: return "FULL DUPLEX";
        default:              return "UNKNOWN";
    }
}

const char* speed_to_name(eth_speed_t speed) {
    switch (speed) {
        case ETH_SPEED_10M:  return "10 Mbps";
        case ETH_SPEED_100M: return "100 Mbps";
        default:             return "UNKNOWN";
    }
}

namespace EthernetManager
{
    bool Init()
    {
        printf(
            "\n=== ETHERNET INIT ===\n");

        esp_err_t result;

        result = esp_netif_init();

        if (
            result != ESP_OK &&
            result != ESP_ERR_INVALID_STATE)
        {
            printf(
                "Error esp_netif_init: %s\n",
                esp_err_to_name(result));

            return false;
        }

        result =
            esp_event_loop_create_default();

        if (
            result != ESP_OK &&
            result != ESP_ERR_INVALID_STATE)
        {
            printf(
                "Error creando event loop: %s\n",
                esp_err_to_name(result));

            return false;
        }

        result =
            gpio_install_isr_service(0);

        if (
            result != ESP_OK &&
            result != ESP_ERR_INVALID_STATE)
        {
            printf(
                "Error instalando GPIO ISR service: %s\n",
                esp_err_to_name(result));

            return false;
        }

        spi_bus_config_t busConfig{};

        busConfig.mosi_io_num =
            NetworkConstants::Ethernet::Pins::MOSI;

        busConfig.miso_io_num =
            NetworkConstants::Ethernet::Pins::MISO;

        busConfig.sclk_io_num =
            NetworkConstants::Ethernet::Pins::SCK;

        busConfig.quadwp_io_num = -1;
        busConfig.quadhd_io_num = -1;

        busConfig.max_transfer_sz =
            NetworkConstants::Ethernet::Spi::MAX_TRANSFER_SIZE;

        result =
            spi_bus_initialize(
                NetworkConstants::Ethernet::Spi::HOST,
                &busConfig,
                SPI_DMA_CH_AUTO);

        if (
            result != ESP_OK &&
            result != ESP_ERR_INVALID_STATE)
        {
            printf(
                "Error inicializando SPI: %s\n",
                esp_err_to_name(result));

            return false;
        }

        spi_device_interface_config_t spiDeviceConfig{};

        spiDeviceConfig.mode = 0;

        spiDeviceConfig.clock_speed_hz =
            NetworkConstants::Ethernet::Spi::CLOCK_SPEED_HZ;

        spiDeviceConfig.queue_size =
            NetworkConstants::Ethernet::Spi::QUEUE_SIZE;

        spiDeviceConfig.spics_io_num =
            NetworkConstants::Ethernet::Pins::CS;

        eth_w5500_config_t w5500Config =
            ETH_W5500_DEFAULT_CONFIG(
                NetworkConstants::Ethernet::Spi::HOST,
                &spiDeviceConfig);

        w5500Config.base.int_gpio_num =
            NetworkConstants::Ethernet::Pins::INTERRUPT;

        eth_mac_config_t macConfig =
            ETH_MAC_DEFAULT_CONFIG();

        macConfig.rx_task_stack_size =
            NetworkConstants::Ethernet::Mac::RX_TASK_STACK_SIZE;

        eth_phy_config_t phyConfig =
            ETH_PHY_DEFAULT_CONFIG();

        phyConfig.reset_gpio_num =
            NetworkConstants::Ethernet::Pins::RESET;

        esp_eth_mac_t *mac =
            esp_eth_mac_new_w5500(
                &w5500Config,
                &macConfig);

        if (mac == nullptr)
        {
            printf(
                "No fue posible crear MAC W5500\n");

            return false;
        }

        esp_eth_phy_t *phy =
            esp_eth_phy_new_w5500(
                &phyConfig);

        if (phy == nullptr)
        {
            printf(
                "No fue posible crear PHY W5500\n");

            mac->del(mac);

            return false;
        }

        esp_eth_config_t ethConfig =
            ETH_DEFAULT_CONFIG(
                mac,
                phy);

        result =
            esp_eth_driver_install(
                &ethConfig,
                &EthernetInternal::ethHandle);

        if (result != ESP_OK)
        {
            printf(
                "Error instalando Ethernet: %s\n",
                esp_err_to_name(result));

            return false;
        }

        if (!ConfigureMac())
        {
            return false;
        }

        {
            bool autoneg = false;

            result = esp_eth_ioctl(EthernetInternal::ethHandle, ETH_CMD_S_AUTONEGO, &autoneg);

            if (result != ESP_OK)
            {
                printf("Error desactivando autonegociacion: %s\n", esp_err_to_name(result));

                return false;
            }

            eth_speed_t speed = ETH_SPEED_100M;

            result = esp_eth_ioctl(EthernetInternal::ethHandle, ETH_CMD_S_SPEED, &speed);

            if (result != ESP_OK)
            {
                printf("Error configurando velocidad PHY: %s\n", esp_err_to_name(result));

                return false;
            }

            eth_duplex_t duplex = ETH_DUPLEX_FULL;

            result = esp_eth_ioctl(EthernetInternal::ethHandle, ETH_CMD_S_DUPLEX_MODE, &duplex);

            if (result != ESP_OK)
            {
                printf("Error configurando duplex PHY: %s\n", esp_err_to_name(result));

                return false;
            }

            printf("PHY forzado, autoneg OFF \n speed: %s, duplex: %s\n", speed_to_name(speed), duplex_to_name(duplex));
        }

        esp_netif_config_t netifConfig = ESP_NETIF_DEFAULT_ETH();

        EthernetInternal::ethNetif = esp_netif_new(&netifConfig);

        if (EthernetInternal::ethNetif == nullptr)
        {
            printf("No fue posible crear esp_netif\n");

            return false;
        }

        esp_eth_netif_glue_handle_t glue = esp_eth_new_netif_glue(EthernetInternal::ethHandle);

        if (glue == nullptr)
        {
            printf("No fue posible crear Ethernet netif glue\n");

            return false;
        }

        result = esp_netif_attach(EthernetInternal::ethNetif,glue);

        if (result != ESP_OK)
        {
            printf(
                "Error adjuntando netif: %s\n",
                esp_err_to_name(result));

            return false;
        }

        if (!ConfigureStaticIp())
        {
            return false;
        }

        result =
            esp_event_handler_register(
                ETH_EVENT,
                ESP_EVENT_ANY_ID,
                &EthernetEventHandler,
                nullptr);

        if (result != ESP_OK)
        {
            printf(
                "Error registrando eventos Ethernet: %s\n",
                esp_err_to_name(result));

            return false;
        }

        result =
            esp_eth_start(
                EthernetInternal::ethHandle);

        if (result != ESP_OK)
        {
            printf(
                "Error arrancando Ethernet: %s\n",
                esp_err_to_name(result));

            return false;
        }

        printf(
            "W5500 inicializado correctamente\n");

        printf(
            "=====================\n\n");

        return true;
    }

    bool TestConnection()
    {
        printf(
            "\n=== ETHERNET TEST ===\n");

        if (
            EthernetInternal::ethHandle ==
            nullptr)
        {
            printf(
                "Ethernet no ha sido inicializado\n");

            return false;
        }

        if (!EthernetInternal::linkUp)
        {
            printf(
                "W5500 inicializado, pero link DOWN\n");

            return false;
        }

        printf(
            "Ethernet link UP\n");

        printf(
            "=====================\n\n");

        return true;
    }
}

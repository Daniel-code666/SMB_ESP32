#pragma once

#include "esp_eth.h"
#include "esp_netif.h"

namespace EthernetInternal
{
    extern esp_eth_handle_t ethHandle;
    extern esp_netif_t* ethNetif;
    extern bool linkUp;
}
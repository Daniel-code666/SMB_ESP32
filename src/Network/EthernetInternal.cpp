#include "EthernetInternal.h"

namespace EthernetInternal
{
    esp_eth_handle_t ethHandle = nullptr;
    esp_netif_t* ethNetif = nullptr;
    bool linkUp = false;
}
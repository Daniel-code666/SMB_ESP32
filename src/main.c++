#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "System/SystemInfo.h"
#include "Storage/SdStorage.h"
#include "Network/EthernetManager.h"
#include "Network/TcpServer.h"
#include "SMB/SmbServer.h"
#include "Storage/SdSpiDiagnostic.h"

extern "C" void app_main()
{
    SystemInfo::Print();

    SdStorage::StartMonitor();

    if (!EthernetManager::Init())
    {
        printf("Error inicializando Ethernet\n");
        return;
    }

    vTaskDelay(pdMS_TO_TICKS(2000));

    EthernetManager::TestConnection();

    if (!TcpServer::Start())
    {
        printf("Error iniciando servidor TCP\n");
        return;
    }

    if (!SmbServer::Start())
    {
        printf("Error iniciando servidor SMB\n");
        return;
    }

    while (true)
    {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}
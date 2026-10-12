#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "System/SystemInfo.h"
#include "Storage/SdStorage.h"
#include "Network/EthernetManager.h"
#include "Network/TcpServer.h"
#include "SMB/SmbServer.h"
#include "Storage/SdSpiDiagnostic.h"
#include "Diagnostics/TraceBuffer.h"

extern "C" void app_main()
{
    SystemInfo::Print();

    if constexpr (TraceBuffer::ENABLED)
    {
        TraceBuffer::Init();
        if (!TraceBuffer::StartSerialConsole())
        {
            printf("METRICS: no fue posible iniciar la consola de captura\n");
        }
    }

    SdStorage::StartMonitor();

    if (!EthernetManager::Init())
    {
        printf("Error inicializando Ethernet\n");
        return;
    }

    vTaskDelay(pdMS_TO_TICKS(2000));

    EthernetManager::TestConnection();

    // El puerto auxiliar 5000 solo se usa para benchmark y descarga de trazas.
    // No reserva tarea ni buffers en la compilacion de juego.
    if constexpr (TraceBuffer::ENABLED)
    {
        if (!TcpServer::Start())
        {
            printf("Error iniciando servidor TCP\n");
            return;
        }
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

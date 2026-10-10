#include "TcpServer.h"
#include <cstdio>
#include <cstring>
#include <cerrno>
#include <cstdint>
#include <strings.h>
#include <cstdlib>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/tcp.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "Storage/SdStorage.h"
#include "Storage/SdStorageConstants.h"
#include "Network/NetworkConstants.h"
#include "ff.h"

namespace
{
    bool SendAll(int socket, const uint8_t* data, size_t length);
    bool SendFile(int clientSocket, const char* relativePath);
    bool BuildStoragePath(const char* relativePath, char* fullPath, size_t fullPathSize);
    const char* GetFileType(const char* path);
    bool SendBenchmark(int clientSocket, uint64_t totalBytes);
    NetworkConstants::Tcp::Protocol::Command ParseCommand(const char* request);
    int CreateListenSocket();
    void ConfigureClientSocket(int clientSocket);
    bool ReceiveRequest(int clientSocket, char* request, size_t requestSize);
    void HandleGet(int clientSocket, const char* request);
    void HandleGetFirstIso(int clientSocket);
    void HandleBench(int clientSocket, const char* request);
    void HandleUnknown(int clientSocket);
    void HandleRequest(int clientSocket, const char* request);
    void HandleClient(int clientSocket, const sockaddr_in& clientAddress);
    void ServerTask(void*);

    bool SendAll(int socket, const uint8_t* data, size_t length)
    {
        size_t totalSent = 0;
        while (totalSent < length)
        {
            const int sent = send(socket, data + totalSent, length - totalSent, 0);
            if (sent <= 0)
            {
                printf("Error enviando datos TCP: errno=%d\n", errno);
                return false;
            }
            totalSent += static_cast<size_t>(sent);
        }
        return true;
    }

    bool BuildStoragePath(const char* relativePath, char* fullPath, size_t fullPathSize)
    {
        if (relativePath == nullptr ||
            relativePath[0] == '\0' ||
            relativePath[0] == '/' ||
            strstr(relativePath, "..") != nullptr ||
            strchr(relativePath, '\\') != nullptr
        )
        {
            return false;
        }
        const int written = snprintf(fullPath, fullPathSize, "%s/%s", SdStorageConstants::Paths::MOUNT_POINT, relativePath);
        return written >= 0 && written < static_cast<int>(fullPathSize);
    }

    const char* GetFileType(const char* path)
    {
        const char* extension = strrchr(path, '.');
        if (extension == nullptr)
        {
            return NetworkConstants::Tcp::Protocol::TYPE_OTHER;
        }
        if (strcasecmp(extension, ".iso") == 0)
        {
            return NetworkConstants::Tcp::Protocol::TYPE_ISO;
        }
        if (
            strcasecmp(extension, ".mp3") == 0 ||
            strcasecmp(extension, ".wav") == 0 ||
            strcasecmp(extension, ".aac") == 0 ||
            strcasecmp(extension, ".ac3") == 0
        )
        {
            return NetworkConstants::Tcp::Protocol::TYPE_AUDIO;
        }
        if (
            strcasecmp(extension, ".avi") == 0 ||
            strcasecmp(extension, ".mp4") == 0 ||
            strcasecmp(extension, ".mpg") == 0 ||
            strcasecmp(extension, ".mpeg") == 0 ||
            strcasecmp(extension, ".mkv") == 0
        )
        {
            return NetworkConstants::Tcp::Protocol::TYPE_VIDEO;
        }
        return NetworkConstants::Tcp::Protocol::TYPE_OTHER;
    }

    bool SendFile(int clientSocket, const char* relativePath)
    {
        if (!SdStorage::IsMounted())
        {
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_SD_NOT_MOUNTED),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_SD_NOT_MOUNTED)
            );
            return false;
        }
        char path[NetworkConstants::Tcp::FILE_PATH_BUFFER_SIZE];
        if (!BuildStoragePath(relativePath, path, sizeof(path)))
        {
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_INVALID_PATH),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_INVALID_PATH)
            );
            return false;
        }
        uint64_t fileSize = 0;
        if (!SdStorage::GetFileSize(path, fileSize))
        {
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_FILE_NOT_FOUND),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_FILE_NOT_FOUND)
            );
            return false;
        }
        constexpr const char* mountPoint = SdStorageConstants::Paths::MOUNT_POINT;
        const size_t mountLength = strlen(mountPoint);
        if (strncmp(path, mountPoint, mountLength) != 0)
        {
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_INVALID_PATH),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_INVALID_PATH)
            );
            return false;
        }
        char fatPath[NetworkConstants::Tcp::FILE_PATH_BUFFER_SIZE];
        const int fatPathLength = snprintf(fatPath, sizeof(fatPath), "0:%s", path + mountLength);
        if (fatPathLength < 0 || fatPathLength >= static_cast<int>(sizeof(fatPath)))
        {
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_INVALID_PATH),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_INVALID_PATH)
            );
            return false;
        }
        FIL file{};
        const FRESULT openResult = f_open(&file, fatPath, FA_READ);
        if (openResult != FR_OK)
        {
            printf("Error f_open (%d): %s\n", openResult, fatPath);
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_OPEN_FILE),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_OPEN_FILE)
            );
            return false;
        }
        const char* fileType = GetFileType(path);
        const char* fileName = strrchr(path, '/');
        if (fileName != nullptr)
        {
            ++fileName;
        }
        else
        {
            fileName = path;
        }
        char header[NetworkConstants::Tcp::HEADER_BUFFER_SIZE];
        const int headerLength =
            snprintf(
                header,
                sizeof(header),
                NetworkConstants::Tcp::Protocol::FILE_HEADER_FORMAT,
                static_cast<unsigned long long>(fileSize),
                fileType,
                fileName
            );
        if (
            headerLength <= 0 ||
            headerLength >=
                static_cast<int>(sizeof(header)) ||
            !SendAll(clientSocket, reinterpret_cast<const uint8_t*>(header), static_cast<size_t>(headerLength))
        )
        {
            f_close(&file);
            return false;
        }
        uint8_t* buffer = static_cast<uint8_t*>(heap_caps_malloc(NetworkConstants::Tcp::FILE_BUFFER_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        if (buffer == nullptr)
        {
            printf("No fue posible reservar buffer TCP en RAM interna\n");
            f_close(&file);
            return false;
        }
        uint64_t totalSent = 0;
        const int64_t startTime = esp_timer_get_time();
        printf("\n=== TCP FILE TRANSFER ===\n");
        printf("Archivo: %s\n", path);
        printf("FatFs: %s\n", fatPath);
        printf("Tipo: %s\n", fileType);
        printf("Tamaño: %llu bytes\n", static_cast<unsigned long long>(fileSize));
        printf("Buffer: %zu KB\n", NetworkConstants::Tcp::FILE_BUFFER_SIZE / 1024);
        while (totalSent < fileSize)
        {
            const uint64_t remaining = fileSize - totalSent;
            const size_t bytesToRead =
                remaining <
                    NetworkConstants::Tcp::FILE_BUFFER_SIZE
                    ? static_cast<size_t>(remaining)
                    : NetworkConstants::Tcp::FILE_BUFFER_SIZE;
            UINT bytesRead = 0;
            const FRESULT readResult = f_read(&file, buffer, static_cast<UINT>(bytesToRead), &bytesRead);
            if (readResult != FR_OK)
            {
                printf("Error f_read (%d)\n", readResult);
                heap_caps_free(buffer);
                f_close(&file);
                return false;
            }
            if (bytesRead == 0)
            {
                printf("Fin inesperado del archivo\n");
                heap_caps_free(buffer);
                f_close(&file);
                return false;
            }
            if (!SendAll(clientSocket, buffer, bytesRead))
            {
                heap_caps_free(buffer);
                f_close(&file);
                return false;
            }
            totalSent += static_cast<uint64_t>(bytesRead);
        }
        const int64_t endTime = esp_timer_get_time();
        heap_caps_free(buffer);
        f_close(&file);
        const double elapsedSeconds =
            static_cast<double>(endTime - startTime) /
            1000000.0;
        const double megabytesSent =
            static_cast<double>(totalSent) /
            (1024.0 * 1024.0);
        const double speed =
            elapsedSeconds > 0.0
                ? megabytesSent /
                    elapsedSeconds
                : 0.0;
        printf("Bytes enviados: %llu\n", static_cast<unsigned long long>(totalSent));
        printf("Tiempo: %.2f segundos\n", elapsedSeconds);
        printf("Velocidad media TCP: %.2f MB/s\n", speed);
        printf("Transferencia finalizada\n");
        printf("=========================\n\n");
        return true;
    }

    bool SendBenchmark(int clientSocket, uint64_t totalBytes)
    {
        uint8_t* buffer = static_cast<uint8_t*>(heap_caps_malloc(NetworkConstants::Tcp::FILE_BUFFER_SIZE, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT));
        if (buffer == nullptr)
        {
            printf("No fue posible reservar buffer benchmark\n");
            return false;
        }
        memset(buffer, NetworkConstants::Tcp::Benchmark::DATA_PATTERN, NetworkConstants::Tcp::FILE_BUFFER_SIZE);
        char header[NetworkConstants::Tcp::HEADER_BUFFER_SIZE];
        const int headerLength = snprintf(header, sizeof(header), NetworkConstants::Tcp::Protocol::BENCH_HEADER_FORMAT, static_cast<unsigned long long>(totalBytes));
        if (
            headerLength <= 0 ||
            headerLength >=
                static_cast<int>(sizeof(header)) ||
            !SendAll(clientSocket, reinterpret_cast<const uint8_t*>(header), static_cast<size_t>(headerLength))
        )
        {
            heap_caps_free(buffer);
            return false;
        }
        /*
         * uint64_t es intencional.
         *
         * size_t es de 32 bits en ESP32-S3 y no
         * serviría para benchmarks mayores a 4 GiB.
         */
        uint64_t sentTotal = 0;
        const int64_t startTime = esp_timer_get_time();
        while (sentTotal < totalBytes)
        {
            const uint64_t remaining = totalBytes - sentTotal;
            const size_t chunk =
                remaining <
                    NetworkConstants::Tcp::FILE_BUFFER_SIZE
                    ? static_cast<size_t>(remaining)
                    : NetworkConstants::Tcp::FILE_BUFFER_SIZE;
            if (!SendAll(clientSocket, buffer, chunk))
            {
                heap_caps_free(buffer);
                return false;
            }
            sentTotal += static_cast<uint64_t>(chunk);
        }
        const int64_t endTime = esp_timer_get_time();
        heap_caps_free(buffer);
        const double seconds =
            static_cast<double>(endTime - startTime) /
            1000000.0;
        const double megabytes =
            static_cast<double>(sentTotal) /
            (1024.0 * 1024.0);
        const double speed =
            seconds > 0.0
                ? megabytes / seconds
                : 0.0;
        printf("Benchmark TCP: %.2f MB/s\n", speed);
        return true;
    }

    NetworkConstants::Tcp::Protocol::Command ParseCommand(const char* request)
    {
        using Command = NetworkConstants::Tcp::Protocol::Command;
        if (strcmp(request, NetworkConstants::Tcp::Protocol::GET_FIRST_ISO_COMMAND) == 0)
        {
            return Command::GetFirstIso;
        }
        if (strncmp(request, NetworkConstants::Tcp::Protocol::GET_COMMAND, NetworkConstants::Tcp::Protocol::GET_COMMAND_LENGTH) == 0)
        {
            return Command::Get;
        }
        if (strncmp(request, NetworkConstants::Tcp::Protocol::BENCH_COMMAND, NetworkConstants::Tcp::Protocol::BENCH_COMMAND_LENGTH) == 0)
        {
            return Command::Bench;
        }
        return Command::Unknown;
    }

    int CreateListenSocket()
    {
        int listenSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
        if (listenSocket < 0)
        {
            printf("Error creando socket TCP: errno=%d\n", errno);
            return -1;
        }
        int enable = 1;
        setsockopt(listenSocket, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable));
        sockaddr_in serverAddress{};
        serverAddress.sin_family = AF_INET;
        serverAddress.sin_port = htons(NetworkConstants::Tcp::PORT);
        serverAddress.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(listenSocket, reinterpret_cast<sockaddr*>(&serverAddress), sizeof(serverAddress)) != 0)
        {
            printf("Error bind TCP: errno=%d\n", errno);
            close(listenSocket);
            return -1;
        }
        if (listen(listenSocket, NetworkConstants::Tcp::LISTEN_BACKLOG) != 0)
        {
            printf("Error listen TCP: errno=%d\n", errno);
            close(listenSocket);
            return -1;
        }
        printf("Servidor TCP escuchando en puerto %u\n", NetworkConstants::Tcp::PORT);
        return listenSocket;
    }

    void ConfigureClientSocket(int clientSocket)
    {
        int noDelay = 1;
        setsockopt(clientSocket, IPPROTO_TCP, TCP_NODELAY, &noDelay, sizeof(noDelay));
    }

    bool ReceiveRequest(int clientSocket, char* request, size_t requestSize)
    {
        if (request == nullptr || requestSize < 2)
        {
            return false;
        }
        const int received = recv(clientSocket, request, requestSize - 1, 0);
        if (received <= 0)
        {
            printf("Cliente no envio una solicitud\n");
            return false;
        }
        request[received] = '\0';
        request[
            strcspn(request, "\r\n")
        ] = '\0';
        printf("Solicitud: %s\n", request);
        return true;
    }

    void HandleGet(int clientSocket, const char* request)
    {
        const char* relativePath = request + NetworkConstants::Tcp::Protocol::GET_COMMAND_LENGTH;
        SendFile(clientSocket, relativePath);
    }

    void HandleGetFirstIso(int clientSocket)
    {
        char isoPath[NetworkConstants::Tcp::FILE_PATH_BUFFER_SIZE]{};
        if (!SdStorage::GetFirstIsoPath(isoPath, sizeof(isoPath)))
        {
            printf("GETFIRSTISO: no se encontro ningun ISO\n");
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_FILE_NOT_FOUND),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_FILE_NOT_FOUND)
            );
            return;
        }
        printf("GETFIRSTISO: ISO encontrado: %s\n", isoPath);
        SendFile(clientSocket, isoPath);
    }

    void HandleBench(int clientSocket, const char* request)
    {
        const char* sizeText = request + NetworkConstants::Tcp::Protocol::BENCH_COMMAND_LENGTH;
        char* end = nullptr;
        const uint64_t totalBytes = strtoull(sizeText, &end, 10);
        printf("Benchmark solicitado: %llu bytes\n", static_cast<unsigned long long>(totalBytes));
        if (totalBytes == 0 || end == sizeText)
        {
            SendAll(
                clientSocket,
                reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_INVALID_BENCH_SIZE),
                strlen(NetworkConstants::Tcp::Protocol::ERROR_INVALID_BENCH_SIZE)
            );
            return;
        }
        SendBenchmark(clientSocket, totalBytes);
    }

    void HandleUnknown(int clientSocket)
    {
        SendAll(
            clientSocket,
            reinterpret_cast<const uint8_t*>(NetworkConstants::Tcp::Protocol::ERROR_UNKNOWN_COMMAND),
            strlen(NetworkConstants::Tcp::Protocol::ERROR_UNKNOWN_COMMAND)
        );
    }

    void HandleRequest(int clientSocket, const char* request)
    {
        using Command = NetworkConstants::Tcp::Protocol::Command;
        switch (ParseCommand(request))
        {
            case Command::Get:
            {
                HandleGet(clientSocket, request);
                break;
            }
            case Command::GetFirstIso:
            {
                HandleGetFirstIso(clientSocket);
                break;
            }
            case Command::Bench:
            {
                HandleBench(clientSocket, request);
                break;
            }
            case Command::Unknown:
            default:
            {
                HandleUnknown(clientSocket);
                break;
            }
        }
    }

    void HandleClient(int clientSocket, const sockaddr_in& clientAddress)
    {
        ConfigureClientSocket(clientSocket);
        char clientIp[INET_ADDRSTRLEN]{};
        inet_ntoa_r(clientAddress.sin_addr, clientIp, sizeof(clientIp));
        printf("Cliente conectado: %s:%u\n", clientIp, ntohs(clientAddress.sin_port));
        char request[NetworkConstants::Tcp::REQUEST_BUFFER_SIZE]{};
        if (ReceiveRequest(clientSocket, request, sizeof(request)))
        {
            HandleRequest(clientSocket, request);
        }
        shutdown(clientSocket, SHUT_RDWR);
        close(clientSocket);
        printf("Cliente desconectado\n");
    }

    void ServerTask(void*)
    {
        const int listenSocket = CreateListenSocket();
        if (listenSocket < 0)
        {
            vTaskDelete(nullptr);
            return;
        }
        while (true)
        {
            printf("Esperando cliente TCP...\n");
            sockaddr_in clientAddress{};
            socklen_t clientAddressLength = sizeof(clientAddress);
            const int clientSocket = accept(listenSocket, reinterpret_cast<sockaddr*>(&clientAddress), &clientAddressLength);
            if (clientSocket < 0)
            {
                printf("Error accept TCP: errno=%d\n", errno);
                continue;
            }
            HandleClient(clientSocket, clientAddress);
        }
    }
}

namespace TcpServer
{
    bool Start()
    {
        const BaseType_t result = xTaskCreate(
            ServerTask,
            NetworkConstants::Tcp::Task::NAME,
            NetworkConstants::Tcp::Task::STACK_SIZE,
            nullptr,
            NetworkConstants::Tcp::Task::PRIORITY,
            nullptr
        );
        if (result != pdPASS)
        {
            printf("No fue posible crear tarea TCP\n");
            return false;
        }
        return true;
    }
}

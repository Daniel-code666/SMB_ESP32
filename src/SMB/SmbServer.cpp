#include "SmbServer.h"
#include "SmbConstants.h"
#include "SmbProtocol.h"

#include <cerrno>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "esp_random.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "lwip/tcp.h"

namespace
{
    constexpr size_t NEGOTIATE_REQUEST_DATA_OFFSET =
        SmbProtocol::SMB1_HEADER_SIZE + 1 + sizeof(uint16_t);

    constexpr size_t SESSION_SETUP_RESPONSE_DATA_LENGTH = 3;

    // Resumen de rendimiento de READ_ANDX. No registra mensajes por sector.
    constexpr int64_t READ_PERF_INTERVAL_US = 5LL * 1000 * 1000;

    struct ReadPerformance
    {
        int64_t intervalStartUs = 0;
        uint64_t bytes = 0;
        uint64_t seekUs = 0;
        uint64_t readUs = 0;
        uint64_t sendUs = 0;
        uint32_t requests = 0;
    };

    ReadPerformance readPerformance{};

    // Metricas por conexion: sin imprimir un mensaje por lectura.
    struct ReadConnectionDiagnostics
    {
        int64_t connectedAtUs = 0;
        int64_t lastReadAtUs = 0;
        uint64_t firstOffset = 0;
        uint64_t lastOffset = 0;
        uint64_t lastReadEndOffset = 0;
        uint64_t bytesSent = 0;
        uint32_t readRequests = 0;
    };

    ReadConnectionDiagnostics readConnectionDiagnostics{};

    // Ultimas lecturas: sin imprimir datos en la ruta critica SMB.
    // El hash FNV-1a es solo una huella de diagnostico, no un CRC SDMMC.
    constexpr size_t RECENT_READ_COUNT = 16;

    struct RecentReadSignature
    {
        uint64_t offset = 0;
        uint32_t bytes = 0;
        uint32_t fnv1a = 0;
    };

    RecentReadSignature recentReads[RECENT_READ_COUNT]{};
    size_t recentReadWriteIndex = 0;
    size_t recentReadUsed = 0;

    uint32_t Fnv1a32(const uint8_t *data, size_t length)
    {
        uint32_t hash = 2166136261u;
        for (size_t i = 0; i < length; ++i)
        {
            hash ^= static_cast<uint32_t>(data[i]);
            hash *= 16777619u; // modulo 2^32 por aritmetica sin signo
        }
        return hash;
    }

    void RecordRecentRead(uint64_t offset, const uint8_t *data, size_t length)
    {
        auto &entry = recentReads[recentReadWriteIndex];
        entry.offset = offset;
        entry.bytes = static_cast<uint32_t>(length);
        entry.fnv1a = Fnv1a32(data, length);

        recentReadWriteIndex = (recentReadWriteIndex + 1) % RECENT_READ_COUNT;
        if (recentReadUsed < RECENT_READ_COUNT)
        {
            ++recentReadUsed;
        }
    }

    void PrintRecentReads()
    {
        printf("SMB DIAG ULTIMAS LECTURAS: n=%zu\n", recentReadUsed);
        const size_t oldest = (recentReadWriteIndex + RECENT_READ_COUNT - recentReadUsed)
            % RECENT_READ_COUNT;
        for (size_t i = 0; i < recentReadUsed; ++i)
        {
            const auto &entry = recentReads[(oldest + i) % RECENT_READ_COUNT];
            printf("SMB DIAG BLOQUE offset=%llu bytes=%lu fnv1a=%08lX\n",
                   static_cast<unsigned long long>(entry.offset),
                   static_cast<unsigned long>(entry.bytes),
                   static_cast<unsigned long>(entry.fnv1a));
        }
    }

    void RecordConnectionRead(uint64_t offset, size_t bytes)
    {
        auto &diag = readConnectionDiagnostics;
        if (diag.readRequests == 0)
        {
            diag.firstOffset = offset;
            printf("SMB DIAG: primera lectura de la conexion: offset=%llu, bytes=%zu\n",
                   static_cast<unsigned long long>(offset), bytes);
        }

        diag.lastOffset = offset;
        diag.lastReadEndOffset = offset + static_cast<uint64_t>(bytes);
        diag.lastReadAtUs = esp_timer_get_time();
        diag.bytesSent += static_cast<uint64_t>(bytes);
        ++diag.readRequests;
    }

    void PrintConnectionReadSummary()
    {
        const auto &diag = readConnectionDiagnostics;
        const int64_t nowUs = esp_timer_get_time();
        const int64_t durationMs = (nowUs - diag.connectedAtUs) / 1000;
        const int64_t idleMs = diag.lastReadAtUs > 0
            ? (nowUs - diag.lastReadAtUs) / 1000
            : -1;

        printf("SMB DIAG FIN: READ=%lu, bytes=%llu, primerOffset=%llu, "
               "ultimoOffset=%llu, finUltimaLectura=%llu, "
               "duracion=%lldms, sinLeer=%lldms\n",
               static_cast<unsigned long>(diag.readRequests),
               static_cast<unsigned long long>(diag.bytesSent),
               static_cast<unsigned long long>(diag.firstOffset),
               static_cast<unsigned long long>(diag.lastOffset),
               static_cast<unsigned long long>(diag.lastReadEndOffset),
               static_cast<long long>(durationMs),
               static_cast<long long>(idleMs));
    }

    void RecordReadPerformance(
        size_t bytes,
        int64_t seekUs,
        int64_t readUs,
        int64_t sendUs)
    {
        const int64_t nowUs = esp_timer_get_time();

        if (readPerformance.intervalStartUs == 0)
        {
            readPerformance.intervalStartUs = nowUs;
        }

        readPerformance.bytes += static_cast<uint64_t>(bytes);
        readPerformance.seekUs += static_cast<uint64_t>(seekUs);
        readPerformance.readUs += static_cast<uint64_t>(readUs);
        readPerformance.sendUs += static_cast<uint64_t>(sendUs);
        ++readPerformance.requests;

        const int64_t elapsedUs = nowUs - readPerformance.intervalStartUs;
        if (elapsedUs < READ_PERF_INTERVAL_US)
        {
            return;
        }

        const uint64_t elapsed = static_cast<uint64_t>(elapsedUs);
        const uint64_t kibPerSecond =
            (readPerformance.bytes * 1000000ULL) / (elapsed * 1024ULL);
        const uint64_t averageSeekUs =
            readPerformance.seekUs / readPerformance.requests;
        const uint64_t averageReadUs =
            readPerformance.readUs / readPerformance.requests;
        const uint64_t averageSendUs =
            readPerformance.sendUs / readPerformance.requests;

        printf(
            "SMB PERF: %llu KiB/s, %llu KiB, %lu READ, "
            "promedio seek/read/send=%llu/%llu/%llu us\n",
            static_cast<unsigned long long>(kibPerSecond),
            static_cast<unsigned long long>(readPerformance.bytes / 1024ULL),
            static_cast<unsigned long>(readPerformance.requests),
            static_cast<unsigned long long>(averageSeekUs),
            static_cast<unsigned long long>(averageReadUs),
            static_cast<unsigned long long>(averageSendUs));

        readPerformance = ReadPerformance{};
        readPerformance.intervalStartUs = nowUs;
    }

    struct OpenFile
    {
        bool inUse = false;
        uint16_t fid = 0;
        FIL file{};
        uint64_t size = 0;
    };

    OpenFile openFiles[SmbConstants::Files::MAX_OPEN_FILES]{};

    struct SearchContext
    {
        bool inUse = false;
        uint16_t sid = 1;
        char directory[SmbConstants::Limits::MAX_PATH_LENGTH]{};
        size_t nextEntryIndex = 0;
    };

    SearchContext searchContext{};

    void ResetSearchContext()
    {
        searchContext = SearchContext{};
    }

    bool IsVisibleDirectoryEntry(const FILINFO &fileInfo)
    {
        return
            fileInfo.fname[0] != '\0' &&
            strcmp(fileInfo.fname, ".") != 0 &&
            strcmp(fileInfo.fname, "..") != 0;
    }

    bool ReadDirectoryEntryAt(
        const char *directoryPath,
        size_t targetIndex,
        FILINFO &result,
        bool &hasMore)
    {
        result = FILINFO{};
        hasMore = false;

        if (
            directoryPath == nullptr ||
            directoryPath[0] == '\0')
        {
            return false;
        }

        FF_DIR directory{};

        const FRESULT openResult =
            f_opendir(
                &directory,
                directoryPath);

        if (openResult != FR_OK)
        {
            printf(
                "FIND: f_opendir fallo para %s, resultado=%d\n",
                directoryPath,
                static_cast<int>(openResult));

            return false;
        }

        FILINFO fileInfo{};
        FRESULT readResult = FR_OK;
        size_t visibleIndex = 0;
        bool found = false;

        while (true)
        {
            readResult =
                f_readdir(
                    &directory,
                    &fileInfo);

            if (readResult != FR_OK)
            {
                break;
            }

            if (fileInfo.fname[0] == '\0')
            {
                break;
            }

            if (!IsVisibleDirectoryEntry(fileInfo))
            {
                continue;
            }

            if (!found)
            {
                if (visibleIndex == targetIndex)
                {
                    result = fileInfo;
                    found = true;
                }

                ++visibleIndex;
                continue;
            }

            /*
             * Ya encontramos la entrada pedida. La siguiente entrada
             * visible basta para saber si EndOfSearch debe ser 0 o 1.
             */
            hasMore = true;
            break;
        }

        f_closedir(&directory);

        if (readResult != FR_OK)
        {
            printf(
                "FIND: f_readdir fallo para %s, resultado=%d\n",
                directoryPath,
                static_cast<int>(readResult));

            return false;
        }

        return found;
    }

    OpenFile *FindFreeOpenFile()
    {
        for (size_t i = 0; i < SmbConstants::Files::MAX_OPEN_FILES; ++i)
        {
            if (!openFiles[i].inUse)
            {
                openFiles[i].fid =
                    static_cast<uint16_t>(
                        SmbConstants::Files::FIRST_FILE_ID + i);

                return &openFiles[i];
            }
        }

        return nullptr;
    }

    OpenFile *FindOpenFileByFid(uint16_t fid)
    {
        for (auto &openFile : openFiles)
        {
            if (openFile.inUse && openFile.fid == fid)
            {
                return &openFile;
            }
        }

        return nullptr;
    }

    void ResetOpenFile(OpenFile &openFile)
    {
        openFile.inUse = false;
        openFile.fid = 0;
        openFile.size = 0;
        openFile.file = FIL{};
    }

    void CloseAllOpenFiles()
    {
        for (auto &openFile : openFiles)
        {
            if (!openFile.inUse)
            {
                continue;
            }

            f_close(&openFile.file);
            ResetOpenFile(openFile);
        }
    }

    bool SendAll(int socket, const uint8_t *data, size_t length);
    bool SendSmbPacket(int clientSocket, const uint8_t *smbData, size_t smbLength);
    bool ReceiveExact(int clientSocket, uint8_t *buffer, size_t length);
    bool ReceiveSmbPacket(int clientSocket, uint8_t *&smbBuffer, size_t &smbLength);

    uint16_t ReadLittleEndian16(const uint8_t *data)
    {
        return static_cast<uint16_t>(
            static_cast<uint16_t>(data[0]) |
            (static_cast<uint16_t>(data[1]) << 8));
    }

    uint32_t ReadLittleEndian32(const uint8_t *data)
    {
        return static_cast<uint32_t>(
            static_cast<uint32_t>(data[0]) |
            (static_cast<uint32_t>(data[1]) << 8) |
            (static_cast<uint32_t>(data[2]) << 16) |
            (static_cast<uint32_t>(data[3]) << 24));
    }

    void DumpHexBuffer(
        const char *label,
        const uint8_t *data,
        size_t length,
        size_t maximumLength = 128)
    {
        if (label == nullptr || data == nullptr)
        {
            return;
        }

        const size_t dumpLength =
            length < maximumLength ? length : maximumLength;

        printf("\n========== %s ==========\n", label);
        printf("Longitud total=%zu bytes, mostrando=%zu bytes\n", length, dumpLength);

        for (size_t offset = 0; offset < dumpLength; offset += 16)
        {
            printf("%04zX  ", offset);

            for (size_t column = 0; column < 16; ++column)
            {
                const size_t index = offset + column;
                if (index < dumpLength)
                {
                    printf("%02X ", data[index]);
                }
                else
                {
                    printf("   ");
                }
            }

            printf(" |");

            for (size_t column = 0; column < 16; ++column)
            {
                const size_t index = offset + column;
                if (index >= dumpLength)
                {
                    break;
                }

                const uint8_t value = data[index];
                printf("%c", value >= 32 && value <= 126 ? static_cast<char>(value) : '.');
            }

            printf("|\n");
        }

        if (dumpLength < length)
        {
            printf("... %zu bytes adicionales no mostrados ...\n", length - dumpLength);
        }

        printf("====================================\n\n");
    }

    bool ParseSmb1Packet(
        const uint8_t *buffer,
        size_t received,
        const SmbProtocol::Header *&header);

    int FindDialect(
        const uint8_t *dialectData,
        size_t dialectDataLength,
        const char *targetDialect);

    bool ParseNegotiateRequest(
        const uint8_t *smbBuffer,
        size_t smbLength,
        const uint8_t *&dialectData,
        size_t &dialectDataLength);

    bool ParseSessionSetupAndXRequest(
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::SessionSetupAndXRequestParameters *&parameters,
        const uint8_t *&data,
        size_t &dataLength);

    bool HandleLogoffAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleTreeDisconnect(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleOpenAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleNtCreateAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleReadAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleClose(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleCreateDirectory(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleNegotiate(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleSessionSetupAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleSmbCommand(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &header);

    bool HandleTreeConnectAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleEcho(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleTransaction2(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader);

    bool HandleQueryPathInformation(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader,
        const SmbProtocol::Transaction2RequestParameters &transactionParameters);

    bool HandleFindFirst2(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader,
        const SmbProtocol::Transaction2RequestParameters &transactionParameters);

    bool HandleFindNext2(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader,
        const SmbProtocol::Transaction2RequestParameters &transactionParameters);

    int CreateListenSocket();
    void ConfigureClientSocket(int clientSocket);
    void HandleClient(int clientSocket, const sockaddr_in &clientAddress);
    void ServerTask(void *);

    bool SendAll(int socket, const uint8_t *data, size_t length)
    {
        if (data == nullptr || length == 0)
        {
            return false;
        }

        size_t totalSent = 0;

        while (totalSent < length)
        {
            const size_t requested = length - totalSent;
            const int sent = send(socket, data + totalSent, requested, 0);

            if (sent <= 0)
            {
                printf(
                    "Error enviando datos SMB: sent=%d, errno=%d, enviados=%zu/%zu\n",
                    sent,
                    sent < 0 ? errno : 0,
                    totalSent,
                    length);
                return false;
            }

            totalSent += static_cast<size_t>(sent);
        }

        return true;
    }

    bool SendSmbPacket(
        int clientSocket,
        const uint8_t *smbData,
        size_t smbLength)
    {
        if (smbData == nullptr || smbLength == 0)
        {
            return false;
        }

        if (smbLength >
            SmbProtocol::DirectTcp::MAX_PAYLOAD_LENGTH)
        {
            printf(
                "Payload SMB demasiado grande: %zu bytes\n",
                smbLength);

            return false;
        }

        constexpr size_t directTcpHeaderSize =
            sizeof(SmbProtocol::DirectTcp::Header);

        const size_t packetLength =
            directTcpHeaderSize +
            smbLength;

        uint8_t *packet =
            static_cast<uint8_t *>(
                malloc(packetLength));

        if (packet == nullptr)
        {
            printf(
                "No fue posible reservar paquete SMB completo: %zu bytes\n",
                packetLength);

            return false;
        }

        auto *directTcpHeader =
            reinterpret_cast<
                SmbProtocol::DirectTcp::Header *>(
                packet);

        if (!SmbProtocol::DirectTcp::SetPayloadLength(
                *directTcpHeader,
                static_cast<uint32_t>(
                    smbLength)))
        {
            free(packet);
            return false;
        }

        memcpy(
            packet + directTcpHeaderSize,
            smbData,
            smbLength);

        const bool sent =
            SendAll(
                clientSocket,
                packet,
                packetLength);

        free(packet);

        return sent;
    }

    bool ReceiveExact(int clientSocket, uint8_t *buffer, size_t length)
    {
        if (buffer == nullptr || length == 0)
        {
            return false;
        }

        size_t totalReceived = 0;

        while (totalReceived < length)
        {
            const int received = recv(
                clientSocket,
                buffer + totalReceived,
                length - totalReceived,
                0);

            if (received == 0)
            {
                // FIN ordenado: el par remoto cerro su lado del socket.
                printf("SMB TCP: recv=0 (FIN del cliente), parcial=%zu/%zu\n",
                       totalReceived, length);
                return false;
            }
            if (received < 0)
            {
                // Error de recepcion, diferente de un cierre ordenado.
                const int socketErrno = errno;
                printf("SMB TCP: recv fallo, errno=%d, parcial=%zu/%zu\n",
                       socketErrno, totalReceived, length);
                return false;
            }

            totalReceived += static_cast<size_t>(received);
        }

        return true;
    }

    bool ReceiveSmbPacket(
        int clientSocket,
        uint8_t *&smbBuffer,
        size_t &smbLength)
    {
        smbBuffer = nullptr;
        smbLength = 0;

        SmbProtocol::DirectTcp::Header directTcpHeader{};

        if (!ReceiveExact(
                clientSocket,
                reinterpret_cast<uint8_t *>(&directTcpHeader),
                sizeof(directTcpHeader)))
        {
            return false;
        }

        if (directTcpHeader.type != SmbProtocol::DirectTcp::SESSION_MESSAGE)
        {
            printf(
                "Tipo Direct TCP inesperado: 0x%02X\n",
                directTcpHeader.type);

            return false;
        }

        smbLength = SmbProtocol::DirectTcp::GetPayloadLength(directTcpHeader);

        if (smbLength < SmbProtocol::SMB1_HEADER_SIZE)
        {
            printf("Longitud SMB invalida: %zu\n", smbLength);
            return false;
        }

        if (smbLength > SmbConstants::Buffer::RECEIVE_SIZE)
        {
            printf("Paquete SMB demasiado grande: %zu bytes\n", smbLength);
            return false;
        }

        smbBuffer = static_cast<uint8_t *>(malloc(smbLength));

        if (smbBuffer == nullptr)
        {
            printf(
                "No fue posible reservar buffer SMB de %zu bytes\n",
                smbLength);

            return false;
        }

        if (!ReceiveExact(clientSocket, smbBuffer, smbLength))
        {
            free(smbBuffer);
            smbBuffer = nullptr;
            smbLength = 0;
            return false;
        }

        return true;
    }

    bool ParseSmb1Packet(
        const uint8_t *buffer,
        size_t received,
        const SmbProtocol::Header *&header)
    {
        header = nullptr;

        if (buffer == nullptr)
        {
            return false;
        }

        if (received < SmbProtocol::SMB1_HEADER_SIZE)
        {
            printf("Header SMB1 incompleto\n");
            return false;
        }

        header = reinterpret_cast<const SmbProtocol::Header *>(buffer);

        if (!SmbProtocol::IsSmb1(*header))
        {
            printf(
                "Firma SMB invalida: %02X %02X %02X %02X\n",
                header->protocol[0],
                header->protocol[1],
                header->protocol[2],
                header->protocol[3]);

            header = nullptr;
            return false;
        }

        return true;
    }

    int FindDialect(
        const uint8_t *dialectData,
        size_t dialectDataLength,
        const char *targetDialect)
    {
        if (
            dialectData == nullptr ||
            targetDialect == nullptr ||
            dialectDataLength == 0)
        {
            return -1;
        }

        size_t offset = 0;
        int dialectIndex = 0;

        while (offset < dialectDataLength)
        {
            if (dialectData[offset] != SmbProtocol::Dialect::FORMAT)
            {
                printf(
                    "Formato de dialecto invalido en offset %zu: 0x%02X\n",
                    offset,
                    dialectData[offset]);

                return -1;
            }

            ++offset;

            const size_t stringStart = offset;

            while (
                offset < dialectDataLength &&
                dialectData[offset] != '\0')
            {
                ++offset;
            }

            if (offset >= dialectDataLength)
            {
                printf("Dialect string sin terminador NUL\n");
                return -1;
            }

            const size_t dialectLength = offset - stringStart;

            printf(
                "Dialecto [%d]: %.*s\n",
                dialectIndex,
                static_cast<int>(dialectLength),
                reinterpret_cast<const char *>(
                    dialectData + stringStart));

            const size_t targetLength = strlen(targetDialect);

            if (
                dialectLength == targetLength &&
                memcmp(
                    dialectData + stringStart,
                    targetDialect,
                    targetLength) == 0)
            {
                return dialectIndex;
            }

            ++offset;
            ++dialectIndex;

            if (
                dialectIndex >=
                static_cast<int>(
                    SmbConstants::Limits::MAX_DIALECTS))
            {
                printf("Cantidad maxima de dialectos excedida\n");
                return -1;
            }
        }

        return -1;
    }

    bool ParseNegotiateRequest(
        const uint8_t *smbBuffer,
        size_t smbLength,
        const uint8_t *&dialectData,
        size_t &dialectDataLength)
    {
        dialectData = nullptr;
        dialectDataLength = 0;

        if (
            smbBuffer == nullptr ||
            smbLength < NEGOTIATE_REQUEST_DATA_OFFSET)
        {
            return false;
        }

        const size_t wordCountOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        if (smbBuffer[wordCountOffset] != 0)
        {
            printf(
                "NEGOTIATE WordCount invalido: %u\n",
                smbBuffer[wordCountOffset]);

            return false;
        }

        const size_t byteCountOffset = wordCountOffset + 1;

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer + byteCountOffset);

        if (byteCount < 2)
        {
            printf(
                "NEGOTIATE ByteCount invalido: %u\n",
                byteCount);

            return false;
        }

        if (
            NEGOTIATE_REQUEST_DATA_OFFSET +
                byteCount >
            smbLength)
        {
            printf(
                "NEGOTIATE incompleto: ByteCount=%u, disponibles=%zu\n",
                byteCount,
                smbLength -
                    NEGOTIATE_REQUEST_DATA_OFFSET);

            return false;
        }

        dialectData =
            smbBuffer +
            NEGOTIATE_REQUEST_DATA_OFFSET;

        dialectDataLength = byteCount;

        return true;
    }

    bool ParseSessionSetupAndXRequest(
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::SessionSetupAndXRequestParameters *&parameters,
        const uint8_t *&data,
        size_t &dataLength)
    {
        parameters = nullptr;
        data = nullptr;
        dataLength = 0;

        constexpr size_t parametersOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t byteCountOffset =
            parametersOffset +
            sizeof(
                SmbProtocol::
                    SessionSetupAndXRequestParameters);

        constexpr size_t dataOffset =
            byteCountOffset +
            sizeof(uint16_t);

        if (
            smbBuffer == nullptr ||
            smbLength < dataOffset)
        {
            printf(
                "SESSION_SETUP_ANDX demasiado corto: %zu bytes\n",
                smbLength);

            return false;
        }

        parameters =
            reinterpret_cast<
                const SmbProtocol::
                    SessionSetupAndXRequestParameters *>(
                smbBuffer + parametersOffset);

        if (
            parameters->wordCount !=
            SmbProtocol::SessionSetup::
                REQUEST_WORD_COUNT)
        {
            printf(
                "SESSION_SETUP_ANDX WordCount invalido: %u\n",
                parameters->wordCount);

            parameters = nullptr;
            return false;
        }

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer + byteCountOffset);

        if (dataOffset + byteCount > smbLength)
        {
            printf(
                "SESSION_SETUP_ANDX incompleto: ByteCount=%u, disponibles=%zu\n",
                byteCount,
                smbLength - dataOffset);

            parameters = nullptr;
            return false;
        }

        const size_t passwordBytes =
            static_cast<size_t>(
                parameters->oemPasswordLength) +
            static_cast<size_t>(
                parameters->unicodePasswordLength);

        if (passwordBytes > byteCount)
        {
            printf(
                "SESSION_SETUP_ANDX longitudes de password invalidas: OEM=%u Unicode=%u ByteCount=%u\n",
                parameters->oemPasswordLength,
                parameters->unicodePasswordLength,
                byteCount);

            parameters = nullptr;
            return false;
        }

        data = smbBuffer + dataOffset;
        dataLength = byteCount;

        return true;
    }

    bool ParseTreeConnectAndXRequest(
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::TreeConnectAndXRequestParameters *&parameters,
        const char *&sharePath,
        const char *&service)
    {
        parameters = nullptr;
        sharePath = nullptr;
        service = nullptr;

        constexpr size_t parametersOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t byteCountOffset =
            parametersOffset +
            sizeof(SmbProtocol::TreeConnectAndXRequestParameters);

        constexpr size_t dataOffset =
            byteCountOffset +
            sizeof(uint16_t);

        if (
            smbBuffer == nullptr ||
            smbLength < dataOffset)
        {
            printf("TREE_CONNECT_ANDX demasiado corto\n");
            return false;
        }

        parameters =
            reinterpret_cast<
                const SmbProtocol::TreeConnectAndXRequestParameters *>(
                smbBuffer + parametersOffset);

        if (
            parameters->wordCount !=
            SmbProtocol::TreeConnect::REQUEST_WORD_COUNT)
        {
            printf(
                "TREE_CONNECT_ANDX WordCount invalido: %u\n",
                parameters->wordCount);

            return false;
        }

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer + byteCountOffset);

        if (dataOffset + byteCount > smbLength)
        {
            printf("TREE_CONNECT_ANDX ByteCount invalido\n");
            return false;
        }

        if (parameters->passwordLength > byteCount)
        {
            printf("TREE_CONNECT_ANDX PasswordLength invalido\n");
            return false;
        }

        const uint8_t *data =
            smbBuffer + dataOffset;

        const uint8_t *pathStart =
            data +
            parameters->passwordLength;

        const uint8_t *dataEnd =
            data +
            byteCount;

        const uint8_t *pathEnd =
            static_cast<const uint8_t *>(
                memchr(
                    pathStart,
                    '\0',
                    dataEnd - pathStart));

        if (pathEnd == nullptr)
        {
            printf("TREE_CONNECT_ANDX path sin terminador\n");
            return false;
        }

        sharePath =
            reinterpret_cast<const char *>(
                pathStart);

        const uint8_t *serviceStart =
            pathEnd + 1;

        if (serviceStart >= dataEnd)
        {
            printf("TREE_CONNECT_ANDX service ausente\n");
            return false;
        }

        const uint8_t *serviceEnd =
            static_cast<const uint8_t *>(
                memchr(
                    serviceStart,
                    '\0',
                    dataEnd - serviceStart));

        if (serviceEnd == nullptr)
        {
            printf("TREE_CONNECT_ANDX service sin terminador\n");
            return false;
        }

        service =
            reinterpret_cast<const char *>(
                serviceStart);

        return true;
    }

    bool SendSmbErrorResponse(
        int clientSocket,
        const SmbProtocol::Header &requestHeader,
        SmbProtocol::Status status)
    {
        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(uint8_t) +
            sizeof(uint16_t);

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<SmbProtocol::Header *>(response);

        SmbProtocol::SetSignature(*responseHeader);

        responseHeader->command = requestHeader.command;
        responseHeader->status = static_cast<uint32_t>(status);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 = requestHeader.flags2;
        responseHeader->pidHigh = requestHeader.pidHigh;
        responseHeader->treeId = requestHeader.treeId;
        responseHeader->processId = requestHeader.processId;
        responseHeader->userId = requestHeader.userId;
        responseHeader->multiplexId = requestHeader.multiplexId;

        uint8_t *wordCount =
            response + sizeof(SmbProtocol::Header);

        *wordCount = 0;

        uint8_t *byteCount =
            wordCount + sizeof(uint8_t);

        byteCount[0] = 0;
        byteCount[1] = 0;

        return SendSmbPacket(
            clientSocket,
            response,
            sizeof(response));
    }

    bool HandleFindNext2(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader,
        const SmbProtocol::Transaction2RequestParameters &transactionParameters)
    {
        if (
            transactionParameters.parameterCount <
            sizeof(SmbProtocol::FindNext2RequestParameters))
        {
            printf("TRANS2_FIND_NEXT2 parametros demasiado cortos\n");
            return false;
        }

        if (
            static_cast<size_t>(transactionParameters.parameterOffset) +
                transactionParameters.parameterCount >
            smbLength)
        {
            printf("TRANS2_FIND_NEXT2 ParameterOffset/Count invalido\n");
            return false;
        }

        const uint8_t *parameterData =
            smbBuffer +
            transactionParameters.parameterOffset;

        const auto *findParameters =
            reinterpret_cast<
                const SmbProtocol::FindNext2RequestParameters *>(
                parameterData);

        const uint8_t *resumeFileNameData =
            parameterData +
            sizeof(SmbProtocol::FindNext2RequestParameters);

        const size_t resumeFileNameLength =
            transactionParameters.parameterCount -
            sizeof(SmbProtocol::FindNext2RequestParameters);

        printf("TRANS2_FIND_NEXT2 recibido\n");
        printf("  SID=%u\n", findParameters->sid);
        printf("  SearchCount=%u\n", findParameters->searchCount);
        printf("  InformationLevel=0x%04X\n", findParameters->informationLevel);
        printf(
            "  ResumeKey=%lu\n",
            static_cast<unsigned long>(
                findParameters->resumeKey));
        printf("  Flags=0x%04X\n", findParameters->flags);
        printf("  ResumeFileName=");

        for (size_t i = 0; i < resumeFileNameLength; ++i)
        {
            const uint8_t character =
                resumeFileNameData[i];

            if (character == '\0')
            {
                break;
            }

            if (character >= 32 && character <= 126)
            {
                printf("%c", static_cast<char>(character));
            }
            else
            {
                printf("\\x%02X", character);
            }
        }

        printf("\n");

        if (
            findParameters->informationLevel !=
            SmbProtocol::FindFirst2::
                INFO_LEVEL_BOTH_DIRECTORY)
        {
            printf(
                "TRANS2_FIND_NEXT2 InformationLevel no soportado: 0x%04X\n",
                findParameters->informationLevel);

            return false;
        }

        FILINFO fileInfo{};
        bool hasMore = false;
        bool found = false;

        if (
            searchContext.inUse &&
            findParameters->sid == searchContext.sid)
        {
            found =
                ReadDirectoryEntryAt(
                    searchContext.directory,
                    searchContext.nextEntryIndex,
                    fileInfo,
                    hasMore);
        }
        else
        {
            printf(
                "TRANS2_FIND_NEXT2 sin contexto valido para SID=%u\n",
                findParameters->sid);
        }

        const size_t fileNameBytes =
            found
                ? strlen(fileInfo.fname)
                : 0;

        const size_t entrySize =
            found
                ? sizeof(
                      SmbProtocol::
                          FindFileBothDirectoryInfo) +
                      fileNameBytes
                : 0;

        constexpr uint16_t trans2ParameterCount =
            sizeof(
                SmbProtocol::
                    FindNext2ResponseParameters);

        const uint16_t trans2DataCount =
            static_cast<uint16_t>(
                entrySize);

        constexpr size_t fixedResponseSize =
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    Transaction2ResponseParameters) +
            sizeof(uint16_t);

        constexpr uint16_t parameterOffset =
            static_cast<uint16_t>(
                fixedResponseSize + 1);

        constexpr uint16_t dataOffset =
            static_cast<uint16_t>(
                parameterOffset +
                trans2ParameterCount +
                1);

        const size_t responseLength =
            found
                ? static_cast<size_t>(
                      dataOffset) +
                      trans2DataCount
                : static_cast<size_t>(
                      parameterOffset) +
                      trans2ParameterCount;

        uint8_t *response =
            static_cast<uint8_t *>(
                malloc(responseLength));

        if (response == nullptr)
        {
            printf(
                "No fue posible reservar respuesta FIND_NEXT2\n");

            return false;
        }

        memset(
            response,
            0,
            responseLength);

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    Transaction2);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::
                    Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *transactionResponse =
            reinterpret_cast<
                SmbProtocol::
                    Transaction2ResponseParameters *>(
                response +
                sizeof(
                    SmbProtocol::Header));

        transactionResponse->wordCount = 10;
        transactionResponse->totalParameterCount =
            trans2ParameterCount;
        transactionResponse->totalDataCount =
            trans2DataCount;
        transactionResponse->reserved = 0;
        transactionResponse->parameterCount =
            trans2ParameterCount;
        transactionResponse->parameterOffset =
            parameterOffset;
        transactionResponse->parameterDisplacement = 0;
        transactionResponse->dataCount =
            trans2DataCount;
        transactionResponse->dataOffset =
            found
                ? dataOffset
                : 0;
        transactionResponse->dataDisplacement = 0;
        transactionResponse->setupCount = 0;
        transactionResponse->reserved2 = 0;

        uint8_t *byteCountPosition =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    Transaction2ResponseParameters);

        const uint16_t byteCount =
            static_cast<uint16_t>(
                responseLength -
                fixedResponseSize);

        byteCountPosition[0] =
            static_cast<uint8_t>(
                byteCount & 0xFF);

        byteCountPosition[1] =
            static_cast<uint8_t>(
                (byteCount >> 8) & 0xFF);

        /*
         * Padding antes de los parametros TRANS2.
         */
        response[fixedResponseSize] = 0;

        auto *findResponse =
            reinterpret_cast<
                SmbProtocol::
                    FindNext2ResponseParameters *>(
                response +
                parameterOffset);

        findResponse->searchCount =
            found ? 1 : 0;

        findResponse->endOfSearch =
            (!found || !hasMore)
                ? 1
                : 0;

        findResponse->eaErrorOffset = 0;

        findResponse->lastNameOffset =
            found
                ? static_cast<uint16_t>(
                      sizeof(
                          SmbProtocol::
                              FindFileBothDirectoryInfo))
                : 0;

        if (found)
        {
            /*
             * Padding antes del bloque Data.
             */
            response[
                parameterOffset +
                trans2ParameterCount] = 0;

            auto *directoryInfo =
                reinterpret_cast<
                    SmbProtocol::
                        FindFileBothDirectoryInfo *>(
                    response +
                    dataOffset);

            directoryInfo->nextEntryOffset = 0;
            directoryInfo->fileIndex =
                static_cast<uint32_t>(
                    searchContext.nextEntryIndex);

            directoryInfo->creationTime = 0;
            directoryInfo->lastAccessTime = 0;
            directoryInfo->lastWriteTime = 0;
            directoryInfo->lastChangeTime = 0;

            const bool isDirectory =
                (fileInfo.fattrib & AM_DIR) != 0;

            directoryInfo->endOfFile =
                isDirectory
                    ? 0
                    : static_cast<uint64_t>(
                          fileInfo.fsize);

            directoryInfo->allocationSize =
                directoryInfo->endOfFile;

            directoryInfo->extFileAttributes =
                isDirectory
                    ? SmbProtocol::
                          QueryFileInformation::
                              ATTRIBUTE_DIRECTORY
                    : SmbProtocol::
                          QueryFileInformation::
                              ATTRIBUTE_NORMAL;

            directoryInfo->fileNameLength =
                static_cast<uint32_t>(
                    fileNameBytes);

            directoryInfo->eaSize = 0;
            directoryInfo->shortNameLength = 0;
            directoryInfo->reserved = 0;

            uint8_t *responseFileName =
                response +
                dataOffset +
                sizeof(
                    SmbProtocol::
                        FindFileBothDirectoryInfo);

            memcpy(
                responseFileName,
                fileInfo.fname,
                fileNameBytes);

            printf(
                "TRANS2_FIND_NEXT2 resultado: %s, tamaño=%llu, directorio=%s, quedan=%s\n",
                fileInfo.fname,
                static_cast<unsigned long long>(
                    fileInfo.fsize),
                isDirectory ? "si" : "no",
                hasMore ? "si" : "no");
        }

        const bool closeAfterRequest =
            (findParameters->flags & 0x0001u) != 0;

        if (
            found &&
            hasMore &&
            !closeAfterRequest)
        {
            ++searchContext.nextEntryIndex;
        }
        else
        {
            ResetSearchContext();
        }

        if (!SendSmbPacket(
                clientSocket,
                response,
                responseLength))
        {
            free(response);

            printf(
                "Error enviando TRANS2_FIND_NEXT2 response\n");

            return false;
        }

        free(response);

        if (found)
        {
            printf(
                "TRANS2_FIND_NEXT2 respondido correctamente: EndOfSearch=%u\n",
                hasMore ? 0u : 1u);
        }
        else
        {
            printf(
                "TRANS2_FIND_NEXT2 respondido: fin de busqueda\n");
        }

        return true;
    }

    bool HandleFindFirst2(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader,
        const SmbProtocol::Transaction2RequestParameters &transactionParameters)
    {
        if (
            transactionParameters.parameterCount <
            sizeof(SmbProtocol::FindFirst2RequestParameters))
        {
            printf("TRANS2_FIND_FIRST2 parametros demasiado cortos\n");
            return false;
        }

        if (
            static_cast<size_t>(transactionParameters.parameterOffset) +
                transactionParameters.parameterCount >
            smbLength)
        {
            printf("TRANS2_FIND_FIRST2 ParameterOffset/Count invalido\n");
            return false;
        }

        const uint8_t *parameterData =
            smbBuffer +
            transactionParameters.parameterOffset;

        const auto *findParameters =
            reinterpret_cast<
                const SmbProtocol::FindFirst2RequestParameters *>(
                parameterData);

        const uint8_t *fileNameData =
            parameterData +
            sizeof(SmbProtocol::FindFirst2RequestParameters);

        const size_t fileNameLength =
            transactionParameters.parameterCount -
            sizeof(SmbProtocol::FindFirst2RequestParameters);

        if (
            findParameters->informationLevel !=
            SmbProtocol::FindFirst2::
                INFO_LEVEL_BOTH_DIRECTORY)
        {
            printf(
                "TRANS2_FIND_FIRST2 InformationLevel no soportado: 0x%04X\n",
                findParameters->informationLevel);

            return false;
        }

        char searchPattern[
            SmbConstants::Limits::
                MAX_PATH_LENGTH]{};

        size_t patternLength = 0;

        while (
            patternLength < fileNameLength &&
            fileNameData[patternLength] != '\0' &&
            patternLength + 1 <
                sizeof(searchPattern))
        {
            searchPattern[patternLength] =
                static_cast<char>(
                    fileNameData[
                        patternLength]);

            ++patternLength;
        }

        searchPattern[patternLength] = '\0';

        printf("TRANS2_FIND_FIRST2 recibido\n");
        printf(
            "  SearchAttributes=0x%04X\n",
            findParameters->searchAttributes);
        printf(
            "  SearchCount=%u\n",
            findParameters->searchCount);
        printf(
            "  Flags=0x%04X\n",
            findParameters->flags);
        printf(
            "  InformationLevel=0x%04X\n",
            findParameters->informationLevel);
        printf(
            "  FileName=%s\n",
            searchPattern);

        char fatFsDirectory[
            SmbConstants::Limits::
                MAX_PATH_LENGTH]{};

        size_t outputPosition = 0;

        fatFsDirectory[outputPosition++] = '0';
        fatFsDirectory[outputPosition++] = ':';
        fatFsDirectory[outputPosition++] = '/';

        size_t inputPosition = 0;

        while (
            searchPattern[inputPosition] == '\\' ||
            searchPattern[inputPosition] == '/')
        {
            ++inputPosition;
        }

        while (
            searchPattern[inputPosition] != '\0' &&
            searchPattern[inputPosition] != '*')
        {
            if (
                outputPosition + 1 >=
                sizeof(fatFsDirectory))
            {
                printf(
                    "TRANS2_FIND_FIRST2 ruta demasiado larga\n");

                return false;
            }

            const char character =
                searchPattern[
                    inputPosition++];

            fatFsDirectory[outputPosition++] =
                character == '\\'
                    ? '/'
                    : character;
        }

        while (
            outputPosition > 3 &&
            fatFsDirectory[
                outputPosition - 1] == '/')
        {
            --outputPosition;
        }

        fatFsDirectory[outputPosition] = '\0';

        printf(
            "  FatFsDirectory=%s\n",
            fatFsDirectory);

        /*
         * OPL pide SearchCount=1 y continua la enumeracion mediante
         * FIND_NEXT2. Por eso debemos conservar un SID/contexto cuando
         * existe al menos una entrada adicional.
         */
        ResetSearchContext();

        FILINFO fileInfo{};
        bool hasMore = false;

        const bool found =
            ReadDirectoryEntryAt(
                fatFsDirectory,
                0,
                fileInfo,
                hasMore);

        if (!found)
        {
            printf(
                "TRANS2_FIND_FIRST2 sin resultados en %s\n",
                fatFsDirectory);

            if (!SendSmbErrorResponse(
                    clientSocket,
                    requestHeader,
                    SmbProtocol::Status::
                        NoSuchFile))
            {
                printf(
                    "Error enviando FIND_FIRST2 STATUS_NO_SUCH_FILE\n");

                return false;
            }

            printf(
                "TRANS2_FIND_FIRST2 respondido con STATUS_NO_SUCH_FILE\n");

            return true;
        }

        const size_t fileNameBytes =
            strlen(fileInfo.fname);

        const size_t entrySize =
            sizeof(
                SmbProtocol::
                    FindFileBothDirectoryInfo) +
            fileNameBytes;

        constexpr uint16_t trans2ParameterCount =
            sizeof(
                SmbProtocol::
                    FindFirst2ResponseParameters);

        const uint16_t trans2DataCount =
            static_cast<uint16_t>(
                entrySize);

        constexpr size_t fixedResponseSize =
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    Transaction2ResponseParameters) +
            sizeof(uint16_t);

        constexpr uint16_t parameterOffset =
            static_cast<uint16_t>(
                fixedResponseSize + 1);

        constexpr uint16_t dataOffset =
            static_cast<uint16_t>(
                parameterOffset +
                trans2ParameterCount +
                1);

        const size_t responseLength =
            static_cast<size_t>(
                dataOffset) +
            trans2DataCount;

        uint8_t *response =
            static_cast<uint8_t *>(
                malloc(responseLength));

        if (response == nullptr)
        {
            printf(
                "No fue posible reservar respuesta FIND_FIRST2\n");

            return false;
        }

        memset(
            response,
            0,
            responseLength);

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    Transaction2);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::
                    Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *transactionResponse =
            reinterpret_cast<
                SmbProtocol::
                    Transaction2ResponseParameters *>(
                response +
                sizeof(
                    SmbProtocol::Header));

        transactionResponse->wordCount = 10;
        transactionResponse->totalParameterCount =
            trans2ParameterCount;
        transactionResponse->totalDataCount =
            trans2DataCount;
        transactionResponse->reserved = 0;
        transactionResponse->parameterCount =
            trans2ParameterCount;
        transactionResponse->parameterOffset =
            parameterOffset;
        transactionResponse->parameterDisplacement = 0;
        transactionResponse->dataCount =
            trans2DataCount;
        transactionResponse->dataOffset =
            dataOffset;
        transactionResponse->dataDisplacement = 0;
        transactionResponse->setupCount = 0;
        transactionResponse->reserved2 = 0;

        uint8_t *byteCountPosition =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    Transaction2ResponseParameters);

        const uint16_t byteCount =
            static_cast<uint16_t>(
                responseLength -
                fixedResponseSize);

        byteCountPosition[0] =
            static_cast<uint8_t>(
                byteCount & 0xFF);

        byteCountPosition[1] =
            static_cast<uint8_t>(
                (byteCount >> 8) & 0xFF);

        /*
         * Padding antes de los parametros TRANS2.
         */
        response[fixedResponseSize] = 0;

        auto *findResponse =
            reinterpret_cast<
                SmbProtocol::
                    FindFirst2ResponseParameters *>(
                response +
                parameterOffset);

        findResponse->sid = 1;
        findResponse->searchCount = 1;

        findResponse->endOfSearch =
            hasMore ? 0 : 1;

        findResponse->eaErrorOffset = 0;

        findResponse->lastNameOffset =
            static_cast<uint16_t>(
                sizeof(
                    SmbProtocol::
                        FindFileBothDirectoryInfo));

        /*
         * Padding antes del bloque Data.
         */
        response[
            parameterOffset +
            trans2ParameterCount] = 0;

        auto *directoryInfo =
            reinterpret_cast<
                SmbProtocol::
                    FindFileBothDirectoryInfo *>(
                response +
                dataOffset);

        directoryInfo->nextEntryOffset = 0;
        directoryInfo->fileIndex = 0;

        directoryInfo->creationTime = 0;
        directoryInfo->lastAccessTime = 0;
        directoryInfo->lastWriteTime = 0;
        directoryInfo->lastChangeTime = 0;

        const bool isDirectory =
            (fileInfo.fattrib & AM_DIR) != 0;

        directoryInfo->endOfFile =
            isDirectory
                ? 0
                : static_cast<uint64_t>(
                      fileInfo.fsize);

        directoryInfo->allocationSize =
            directoryInfo->endOfFile;

        directoryInfo->extFileAttributes =
            isDirectory
                ? SmbProtocol::
                      QueryFileInformation::
                          ATTRIBUTE_DIRECTORY
                : SmbProtocol::
                      QueryFileInformation::
                          ATTRIBUTE_NORMAL;

        directoryInfo->fileNameLength =
            static_cast<uint32_t>(
                fileNameBytes);

        directoryInfo->eaSize = 0;
        directoryInfo->shortNameLength = 0;
        directoryInfo->reserved = 0;

        uint8_t *responseFileName =
            response +
            dataOffset +
            sizeof(
                SmbProtocol::
                    FindFileBothDirectoryInfo);

        memcpy(
            responseFileName,
            fileInfo.fname,
            fileNameBytes);

        printf(
            "TRANS2_FIND_FIRST2 resultado: %s, tamaño=%llu, directorio=%s, quedan=%s\n",
            fileInfo.fname,
            static_cast<unsigned long long>(
                fileInfo.fsize),
            isDirectory ? "si" : "no",
            hasMore ? "si" : "no");

        const bool closeAfterRequest =
            (findParameters->flags & 0x0001u) != 0;

        if (
            hasMore &&
            !closeAfterRequest)
        {
            searchContext.inUse = true;
            searchContext.sid = 1;
            searchContext.nextEntryIndex = 1;

            strncpy(
                searchContext.directory,
                fatFsDirectory,
                sizeof(
                    searchContext.directory) -
                    1);

            searchContext.directory[
                sizeof(
                    searchContext.directory) -
                1] = '\0';

            printf(
                "TRANS2_FIND_FIRST2 contexto abierto: SID=%u, siguienteIndice=%zu\n",
                searchContext.sid,
                searchContext.nextEntryIndex);
        }

        if (!SendSmbPacket(
                clientSocket,
                response,
                responseLength))
        {
            free(response);
            ResetSearchContext();

            printf(
                "Error enviando TRANS2_FIND_FIRST2 response\n");

            return false;
        }

        free(response);

        printf(
            "TRANS2_FIND_FIRST2 respondido correctamente: EndOfSearch=%u\n",
            hasMore ? 0u : 1u);

        return true;
    }

    bool HandleQueryPathInformation(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader,
        const SmbProtocol::Transaction2RequestParameters &transactionParameters)
    {
        if (
            transactionParameters.parameterCount < 7 ||
            static_cast<size_t>(transactionParameters.parameterOffset) +
                    transactionParameters.parameterCount >
                smbLength)
        {
            printf("TRANS2_QUERY_PATH_INFORMATION parametros invalidos\n");
            return false;
        }

        const uint8_t *queryParameters =
            smbBuffer +
            transactionParameters.parameterOffset;

        const uint16_t informationLevel =
            ReadLittleEndian16(queryParameters);

        const char *smbPath =
            reinterpret_cast<const char *>(
                queryParameters + 6);

        const size_t smbPathMaximumLength =
            transactionParameters.parameterCount - 6;

        const void *terminator =
            memchr(
                smbPath,
                '\0',
                smbPathMaximumLength);

        if (terminator == nullptr)
        {
            printf("TRANS2_QUERY_PATH_INFORMATION ruta sin terminador\n");
            return false;
        }

        const size_t smbPathLength =
            static_cast<const char *>(terminator) -
            smbPath;

        char fatFsPath[SmbConstants::Limits::MAX_PATH_LENGTH]{};

        size_t outputPosition = 0;

        fatFsPath[outputPosition++] = '0';
        fatFsPath[outputPosition++] = ':';
        fatFsPath[outputPosition++] = '/';

        size_t inputPosition = 0;

        while (
            inputPosition < smbPathLength &&
            (smbPath[inputPosition] == '\\' ||
             smbPath[inputPosition] == '/'))
        {
            ++inputPosition;
        }

        for (
            ;
            inputPosition < smbPathLength;
            ++inputPosition)
        {
            if (
                outputPosition + 1 >=
                sizeof(fatFsPath))
            {
                printf("TRANS2_QUERY_PATH_INFORMATION ruta demasiado larga\n");
                return false;
            }

            const char value =
                smbPath[inputPosition];

            fatFsPath[outputPosition++] =
                value == '\\'
                    ? '/'
                    : value;
        }

        fatFsPath[outputPosition] = '\0';

        if (strstr(fatFsPath, "..") != nullptr)
        {
            printf(
                "TRANS2_QUERY_PATH_INFORMATION ruta rechazada: %s\n",
                fatFsPath);

            return false;
        }

        printf(
            "TRANS2_QUERY_PATH_INFORMATION: SMB=%s, FatFs=%s\n",
            smbPath,
            fatFsPath);

        FILINFO fileInfo{};

        const FRESULT statResult =
            f_stat(
                fatFsPath,
                &fileInfo);

        if (statResult != FR_OK)
        {
            printf(
                "TRANS2_QUERY_PATH_INFORMATION f_stat fallo: %s, resultado=%d\n",
                fatFsPath,
                static_cast<int>(statResult));

            return false;
        }

        const bool isDirectory =
            (fileInfo.fattrib & AM_DIR) != 0;

        size_t trans2DataCount = 0;

        if (
            informationLevel ==
            SmbProtocol::QueryFileInformation::BASIC_INFO)
        {
            trans2DataCount =
                sizeof(SmbProtocol::QueryFileBasicInfo);
        }
        else if (
            informationLevel ==
            SmbProtocol::QueryFileInformation::STANDARD_INFO)
        {
            trans2DataCount =
                sizeof(SmbProtocol::QueryFileStandardInfo);
        }
        else
        {
            printf(
                "TRANS2_QUERY_PATH_INFORMATION InformationLevel no soportado: 0x%04X\n",
                informationLevel);

            return false;
        }

        constexpr uint16_t trans2ParameterCount =
            sizeof(uint16_t);

        constexpr size_t fixedResponseSize =
            sizeof(SmbProtocol::Header) +
            sizeof(SmbProtocol::Transaction2ResponseParameters) +
            sizeof(uint16_t);

        constexpr uint16_t parameterOffset =
            static_cast<uint16_t>(
                fixedResponseSize + 1);

        constexpr uint16_t dataOffset =
            static_cast<uint16_t>(
                parameterOffset +
                trans2ParameterCount +
                2);

        const size_t responseLength =
            dataOffset +
            trans2DataCount;

        uint8_t *response =
            static_cast<uint8_t *>(
                malloc(responseLength));

        if (response == nullptr)
        {
            printf(
                "No fue posible reservar respuesta TRANS2_QUERY_PATH_INFORMATION\n");

            return false;
        }

        memset(
            response,
            0,
            responseLength);

        auto *responseHeader =
            reinterpret_cast<SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::Transaction2);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *responseParameters =
            reinterpret_cast<
                SmbProtocol::Transaction2ResponseParameters *>(
                response +
                sizeof(SmbProtocol::Header));

        responseParameters->wordCount = 10;

        responseParameters->totalParameterCount =
            trans2ParameterCount;

        responseParameters->totalDataCount =
            static_cast<uint16_t>(
                trans2DataCount);

        responseParameters->reserved = 0;

        responseParameters->parameterCount =
            trans2ParameterCount;

        responseParameters->parameterOffset =
            parameterOffset;

        responseParameters->parameterDisplacement = 0;

        responseParameters->dataCount =
            static_cast<uint16_t>(
                trans2DataCount);

        responseParameters->dataOffset =
            dataOffset;

        responseParameters->dataDisplacement = 0;

        responseParameters->setupCount = 0;
        responseParameters->reserved2 = 0;

        uint8_t *byteCountPosition =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::Transaction2ResponseParameters);

        const uint16_t byteCount =
            static_cast<uint16_t>(
                responseLength -
                fixedResponseSize);

        byteCountPosition[0] =
            static_cast<uint8_t>(
                byteCount & 0xFF);

        byteCountPosition[1] =
            static_cast<uint8_t>(
                (byteCount >> 8) & 0xFF);

        response[fixedResponseSize] = 0;

        response[parameterOffset] = 0;
        response[parameterOffset + 1] = 0;

        if (
            informationLevel ==
            SmbProtocol::QueryFileInformation::BASIC_INFO)
        {
            auto *basicInfo =
                reinterpret_cast<
                    SmbProtocol::QueryFileBasicInfo *>(
                    response + dataOffset);

            basicInfo->creationTime = 0;
            basicInfo->lastAccessTime = 0;
            basicInfo->lastWriteTime = 0;
            basicInfo->changeTime = 0;

            basicInfo->fileAttributes =
                isDirectory
                    ? SmbProtocol::QueryFileInformation::
                          ATTRIBUTE_DIRECTORY
                    : SmbProtocol::QueryFileInformation::
                          ATTRIBUTE_NORMAL;
        }
        else
        {
            auto *standardInfo =
                reinterpret_cast<
                    SmbProtocol::QueryFileStandardInfo *>(
                    response + dataOffset);

            const uint64_t fileSize =
                isDirectory
                    ? 0
                    : static_cast<uint64_t>(
                          fileInfo.fsize);

            standardInfo->allocationSize =
                fileSize;

            standardInfo->endOfFile =
                fileSize;

            standardInfo->numberOfLinks = 1;
            standardInfo->deletePending = 0;

            standardInfo->directory =
                isDirectory ? 1 : 0;
        }

        printf(
            "TRANS2_QUERY_PATH_INFORMATION encontrado: %s, directorio=%s\n",
            fatFsPath,
            isDirectory ? "si" : "no");

        if (!SendSmbPacket(
                clientSocket,
                response,
                responseLength))
        {
            free(response);

            printf(
                "Error enviando TRANS2_QUERY_PATH_INFORMATION response\n");

            return false;
        }

        free(response);

        printf(
            "TRANS2_QUERY_PATH_INFORMATION respondido: "
            "InformationLevel=0x%04X, DataCount=%zu\n",
            informationLevel,
            trans2DataCount);

        return true;
    }

    bool HandleTransaction2(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        (void)clientSocket;
        (void)requestHeader;

        constexpr size_t parametersOffset = SmbProtocol::SMB1_HEADER_SIZE;

        if (
            smbBuffer == nullptr ||
            smbLength <
                parametersOffset +
                    sizeof(SmbProtocol::Transaction2RequestParameters))
        {
            printf("SMB_COM_TRANSACTION2 demasiado corto\n");
            return false;
        }

        const auto *parameters =
            reinterpret_cast<
                const SmbProtocol::Transaction2RequestParameters *>(
                smbBuffer + parametersOffset);

        if (
            parameters->wordCount <
            SmbProtocol::Transaction2::REQUEST_WORD_COUNT_MIN)
        {
            printf(
                "SMB_COM_TRANSACTION2 WordCount invalido: %u\n",
                parameters->wordCount);

            return false;
        }

        const uint8_t expectedWordCount =
            static_cast<uint8_t>(
                SmbProtocol::Transaction2::REQUEST_WORD_COUNT_MIN +
                parameters->setupCount);

        if (parameters->wordCount != expectedWordCount)
        {
            printf(
                "SMB_COM_TRANSACTION2 WordCount inconsistente: "
                "WordCount=%u, SetupCount=%u, esperado=%u\n",
                parameters->wordCount,
                parameters->setupCount,
                expectedWordCount);

            return false;
        }

        if (parameters->setupCount == 0)
        {
            printf("SMB_COM_TRANSACTION2 sin Setup\n");
            return false;
        }

        const size_t setupOffset =
            parametersOffset +
            sizeof(SmbProtocol::Transaction2RequestParameters);

        const size_t setupLength =
            static_cast<size_t>(parameters->setupCount) *
            sizeof(uint16_t);

        if (setupOffset + setupLength > smbLength)
        {
            printf("SMB_COM_TRANSACTION2 Setup incompleto\n");
            return false;
        }

        const uint16_t subcommand =
            ReadLittleEndian16(
                smbBuffer + setupOffset);

        if (
            parameters->parameterCount > 0 &&
            static_cast<size_t>(parameters->parameterOffset) +
                    parameters->parameterCount >
                smbLength)
        {
            printf(
                "SMB_COM_TRANSACTION2 ParameterOffset/Count invalido\n");

            return false;
        }

        if (
            parameters->dataCount > 0 &&
            static_cast<size_t>(parameters->dataOffset) +
                    parameters->dataCount >
                smbLength)
        {
            printf(
                "SMB_COM_TRANSACTION2 DataOffset/Count invalido\n");

            return false;
        }

        printf("SMB_COM_TRANSACTION2 recibido\n");

        printf(
            "  WordCount=%u\n",
            parameters->wordCount);

        printf(
            "  SetupCount=%u\n",
            parameters->setupCount);

        printf(
            "  Subcommand=0x%04X\n",
            subcommand);

        printf(
            "  TotalParameterCount=%u\n",
            parameters->totalParameterCount);

        printf(
            "  ParameterCount=%u\n",
            parameters->parameterCount);

        printf(
            "  ParameterOffset=%u\n",
            parameters->parameterOffset);

        printf(
            "  TotalDataCount=%u\n",
            parameters->totalDataCount);

        printf(
            "  DataCount=%u\n",
            parameters->dataCount);

        printf(
            "  DataOffset=%u\n",
            parameters->dataOffset);

        printf(
            "  MaxParameterCount=%u\n",
            parameters->maxParameterCount);

        printf(
            "  MaxDataCount=%u\n",
            parameters->maxDataCount);

        if (
            subcommand ==
            static_cast<uint16_t>(
                SmbProtocol::Transaction2::Subcommand::
                    QueryPathInformation))
        {
            return HandleQueryPathInformation(
                clientSocket,
                smbBuffer,
                smbLength,
                requestHeader,
                *parameters);
        }

        if (
            subcommand ==
            static_cast<uint16_t>(
                SmbProtocol::Transaction2::Subcommand::FindNext2))
        {
            return HandleFindNext2(
                clientSocket,
                smbBuffer,
                smbLength,
                requestHeader,
                *parameters);
        }

        if (
            subcommand ==
            static_cast<uint16_t>(
                SmbProtocol::Transaction2::Subcommand::FindFirst2))
        {
            return HandleFindFirst2(
                clientSocket,
                smbBuffer,
                smbLength,
                requestHeader,
                *parameters);
        }

        printf("Subcomando TRANSACTION2 aun no implementado: 0x%04X\n", subcommand);

        return false;
    }

    bool HandleEcho(int clientSocket, const uint8_t *smbBuffer, size_t smbLength, const SmbProtocol::Header &requestHeader)
    {
        constexpr size_t parametersOffset = SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t byteCountOffset = parametersOffset + sizeof(SmbProtocol::EchoRequestParameters);

        constexpr size_t dataOffset = byteCountOffset + sizeof(uint16_t);

        if (smbBuffer == nullptr || smbLength < dataOffset)
        {
            printf("SMB_COM_ECHO invalido\n");
            return false;
        }

        const auto *requestParameters = reinterpret_cast<const SmbProtocol::EchoRequestParameters *>(smbBuffer + parametersOffset);

        if (requestParameters->wordCount != 1)
        {
            printf("SMB_COM_ECHO WordCount invalido: %u\n", requestParameters->wordCount);

            return false;
        }

        const uint16_t byteCount = ReadLittleEndian16(smbBuffer + byteCountOffset);

        if (dataOffset + byteCount > smbLength)
        {
            printf(
                "SMB_COM_ECHO incompleto: ByteCount=%u\n",
                byteCount);

            return false;
        }

        const uint8_t *requestData =
            smbBuffer + dataOffset;

        const size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(SmbProtocol::EchoResponseParameters) +
            sizeof(uint16_t) +
            byteCount;

        uint8_t *response =
            static_cast<uint8_t *>(
                malloc(responseLength));

        if (response == nullptr)
        {
            printf(
                "No fue posible reservar respuesta SMB_COM_ECHO\n");

            return false;
        }

        memset(
            response,
            0,
            responseLength);

        auto *responseHeader =
            reinterpret_cast<SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::Echo);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *responseParameters =
            reinterpret_cast<
                SmbProtocol::EchoResponseParameters *>(
                response +
                sizeof(SmbProtocol::Header));

        responseParameters->wordCount = 1;

        responseParameters->sequenceNumber = 1;

        uint8_t *responseByteCount =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(SmbProtocol::EchoResponseParameters);

        responseByteCount[0] =
            static_cast<uint8_t>(
                byteCount & 0xFF);

        responseByteCount[1] =
            static_cast<uint8_t>(
                (byteCount >> 8) & 0xFF);

        if (byteCount > 0)
        {
            memcpy(
                responseByteCount +
                    sizeof(uint16_t),
                requestData,
                byteCount);
        }

        for (uint16_t sequenceNumber = 1; sequenceNumber <= requestParameters->echoCount; ++sequenceNumber)
        {
            responseParameters->sequenceNumber =
                sequenceNumber;

            if (!SendSmbPacket(
                    clientSocket,
                    response,
                    responseLength))
            {
                free(response);

                printf(
                    "Error enviando respuesta SMB_COM_ECHO\n");

                return false;
            }
        }

        free(response);

        printf("SMB_COM_ECHO respondido, EchoCount=%u, ByteCount=%u\n", requestParameters->echoCount, byteCount);

        return true;
    }

    bool HandleTreeConnectAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        const SmbProtocol::TreeConnectAndXRequestParameters *
            requestParameters = nullptr;

        const char *sharePath = nullptr;
        const char *service = nullptr;

        if (!ParseTreeConnectAndXRequest(
                smbBuffer,
                smbLength,
                requestParameters,
                sharePath,
                service))
        {
            return false;
        }

        printf(
            "TREE_CONNECT_ANDX: Path=%s, Service=%s\n",
            sharePath,
            service);

        const char *shareName =
            strrchr(
                sharePath,
                '\\');

        if (shareName == nullptr)
        {
            printf("TREE_CONNECT_ANDX: ruta UNC invalida\n");
            return false;
        }

        ++shareName;

        if (
            strcasecmp(
                shareName,
                SmbConstants::Share::NAME) != 0)
        {
            printf(
                "TREE_CONNECT_ANDX: share no reconocido: %s\n",
                shareName);

            return false;
        }

        constexpr size_t serviceLength =
            3;

        constexpr size_t fileSystemLength =
            4;

        constexpr size_t dataLength =
            serviceLength +
            fileSystemLength;

        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    TreeConnectAndXResponseParameters) +
            sizeof(uint16_t) +
            dataLength;

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    TreeConnectAndX);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            SmbConstants::Session::
                DEFAULT_TID;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *responseParameters =
            reinterpret_cast<
                SmbProtocol::
                    TreeConnectAndXResponseParameters *>(
                response +
                sizeof(SmbProtocol::Header));

        responseParameters->wordCount =
            SmbProtocol::TreeConnect::
                RESPONSE_WORD_COUNT;

        responseParameters->andXCommand =
            SmbProtocol::AndX::
                NO_FURTHER_COMMAND;

        responseParameters->andXReserved =
            SmbProtocol::AndX::
                RESERVED;

        responseParameters->andXOffset = 0;

        responseParameters->optionalSupport =
            SmbProtocol::TreeConnect::
                OPTIONAL_SUPPORT_NONE;

        uint8_t *byteCountPosition =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    TreeConnectAndXResponseParameters);

        byteCountPosition[0] =
            static_cast<uint8_t>(
                dataLength & 0xFF);

        byteCountPosition[1] =
            static_cast<uint8_t>(
                (dataLength >> 8) & 0xFF);

        uint8_t *responseData =
            byteCountPosition +
            sizeof(uint16_t);

        memcpy(
            responseData,
            SmbProtocol::TreeConnect::
                SERVICE_DISK,
            serviceLength);

        memcpy(
            responseData +
                serviceLength,
            SmbProtocol::TreeConnect::
                NATIVE_FILE_SYSTEM,
            fileSystemLength);

        printf(
            "TREE_CONNECT_ANDX aceptado: Share=%s, TID=%u\n",
            shareName,
            SmbConstants::Session::DEFAULT_TID);

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando TREE_CONNECT_ANDX response\n");

            return false;
        }

        printf(
            "SMB_COM_TREE_CONNECT_ANDX respondido correctamente\n");

        return true;
    }

    bool HandleCreateDirectory(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        constexpr size_t wordCountOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t byteCountOffset =
            wordCountOffset + sizeof(uint8_t);

        constexpr size_t dataOffset =
            byteCountOffset + sizeof(uint16_t);

        if (smbBuffer == nullptr || smbLength < dataOffset + 2)
        {
            printf("SMB_COM_CREATE_DIRECTORY demasiado corto\n");
            return false;
        }

        const uint8_t wordCount =
            smbBuffer[wordCountOffset];

        if (wordCount != 0)
        {
            printf(
                "SMB_COM_CREATE_DIRECTORY WordCount invalido: %u\n",
                wordCount);

            return false;
        }

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer + byteCountOffset);

        if (dataOffset + byteCount > smbLength || byteCount < 2)
        {
            printf(
                "SMB_COM_CREATE_DIRECTORY ByteCount invalido: %u\n",
                byteCount);

            return false;
        }

        const uint8_t *data =
            smbBuffer + dataOffset;

        /*
         * SMB_COM_CREATE_DIRECTORY usa un BufferFormat 0x04 seguido
         * por la ruta OEM terminada en NUL.
         */
        if (data[0] != 0x04)
        {
            printf(
                "SMB_COM_CREATE_DIRECTORY BufferFormat inesperado: 0x%02X\n",
                data[0]);

            return false;
        }

        const char *smbPath =
            reinterpret_cast<const char *>(
                data + 1);

        const size_t pathBytes =
            static_cast<size_t>(byteCount - 1);

        const void *terminator =
            memchr(
                smbPath,
                '\0',
                pathBytes);

        if (terminator == nullptr)
        {
            printf(
                "SMB_COM_CREATE_DIRECTORY ruta sin terminador NUL\n");

            return false;
        }

        const size_t smbPathLength =
            static_cast<const char *>(terminator) -
            smbPath;

        char fatFsPath[SmbConstants::Limits::MAX_PATH_LENGTH]{};

        size_t outputPosition = 0;

        fatFsPath[outputPosition++] = '0';
        fatFsPath[outputPosition++] = ':';
        fatFsPath[outputPosition++] = '/';

        size_t inputPosition = 0;

        while (
            inputPosition < smbPathLength &&
            (smbPath[inputPosition] == '\\' ||
             smbPath[inputPosition] == '/'))
        {
            ++inputPosition;
        }

        for (
            ;
            inputPosition < smbPathLength;
            ++inputPosition)
        {
            if (
                outputPosition + 1 >=
                sizeof(fatFsPath))
            {
                printf(
                    "SMB_COM_CREATE_DIRECTORY ruta demasiado larga\n");

                return false;
            }

            const char character =
                smbPath[inputPosition];

            fatFsPath[outputPosition++] =
                character == '\\'
                    ? '/'
                    : character;
        }

        fatFsPath[outputPosition] = '\0';

        if (
            fatFsPath[3] == '\0' ||
            strstr(fatFsPath, "..") != nullptr)
        {
            printf(
                "SMB_COM_CREATE_DIRECTORY ruta rechazada: %s\n",
                fatFsPath);

            return false;
        }

        printf("SMB_COM_CREATE_DIRECTORY recibido\n");
        printf("  SMBPath=%s\n", smbPath);
        printf("  FatFsPath=%s\n", fatFsPath);

        FILINFO fileInfo{};

        const FRESULT statResult =
            f_stat(
                fatFsPath,
                &fileInfo);

        bool directoryReady = false;

        if (statResult == FR_OK)
        {
            if ((fileInfo.fattrib & AM_DIR) != 0)
            {
                printf(
                    "SMB_COM_CREATE_DIRECTORY: directorio ya existe: %s\n",
                    fatFsPath);

                directoryReady = true;
            }
            else
            {
                printf(
                    "SMB_COM_CREATE_DIRECTORY: ya existe un archivo con esa ruta: %s\n",
                    fatFsPath);

                return SendSmbErrorResponse(
                    clientSocket,
                    requestHeader,
                    SmbProtocol::Status::AccessDenied);
            }
        }
        else
        {
            const FRESULT mkdirResult =
                f_mkdir(fatFsPath);

            if (mkdirResult == FR_OK)
            {
                printf(
                    "SMB_COM_CREATE_DIRECTORY: directorio creado: %s\n",
                    fatFsPath);

                directoryReady = true;
            }
            else
            {
                printf(
                    "SMB_COM_CREATE_DIRECTORY f_mkdir fallo: %s, resultado=%d\n",
                    fatFsPath,
                    static_cast<int>(mkdirResult));

                return SendSmbErrorResponse(
                    clientSocket,
                    requestHeader,
                    SmbProtocol::Status::AccessDenied);
            }
        }

        if (!directoryReady)
        {
            return false;
        }

        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(uint8_t) +
            sizeof(uint16_t);

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            requestHeader.command;

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        uint8_t *responseWordCount =
            response +
            sizeof(SmbProtocol::Header);

        *responseWordCount = 0;

        uint8_t *responseByteCount =
            responseWordCount +
            sizeof(uint8_t);

        responseByteCount[0] = 0;
        responseByteCount[1] = 0;

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando SMB_COM_CREATE_DIRECTORY response\n");

            return false;
        }

        printf(
            "SMB_COM_CREATE_DIRECTORY respondido correctamente\n");

        return true;
    }

    bool HandleClose(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        /*
         * SMB_COM_CLOSE (0x04)
         *
         * Request:
         *   WordCount = 3
         *   FID       = 2 bytes
         *   LastWriteTime = 4 bytes
         *   ByteCount = 0
         */
        constexpr size_t parametersOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t requestParametersSize =
            1 + 2 + 4;

        constexpr size_t byteCountOffset =
            parametersOffset +
            requestParametersSize;

        constexpr size_t minimumLength =
            byteCountOffset +
            sizeof(uint16_t);

        if (
            smbBuffer == nullptr ||
            smbLength < minimumLength)
        {
            printf(
                "SMB_COM_CLOSE demasiado corto: %zu bytes\n",
                smbLength);

            return false;
        }

        const uint8_t wordCount =
            smbBuffer[parametersOffset];

        if (wordCount != 3)
        {
            printf(
                "SMB_COM_CLOSE WordCount invalido: %u\n",
                wordCount);

            return false;
        }

        const uint16_t fid =
            ReadLittleEndian16(
                smbBuffer +
                parametersOffset +
                1);

        const uint32_t lastWriteTime =
            ReadLittleEndian32(
                smbBuffer +
                parametersOffset +
                3);

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer +
                byteCountOffset);

        if (
            byteCountOffset +
                sizeof(uint16_t) +
                byteCount >
            smbLength)
        {
            printf(
                "SMB_COM_CLOSE ByteCount invalido: %u\n",
                byteCount);

            return false;
        }

        printf("SMB_COM_CLOSE recibido\n");
        printf("  FID=%u\n", fid);
        printf(
            "  LastWriteTime=0x%08lX\n",
            static_cast<unsigned long>(
                lastWriteTime));
        printf("  ByteCount=%u\n", byteCount);

        OpenFile *openFile =
            FindOpenFileByFid(fid);

        if (openFile == nullptr)
        {
            printf(
                "SMB_COM_CLOSE FID invalido: %u\n",
                fid);

            return SendSmbErrorResponse(
                clientSocket,
                requestHeader,
                SmbProtocol::Status::InvalidHandle);
        }

        const FRESULT closeResult =
            f_close(
                &openFile->file);

        if (closeResult != FR_OK)
        {
            printf(
                "SMB_COM_CLOSE f_close fallo: FID=%u, resultado=%d\n",
                fid,
                static_cast<int>(
                    closeResult));

            return false;
        }

        ResetOpenFile(*openFile);

        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(uint8_t) +
            sizeof(uint16_t);

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            0x04;

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        uint8_t *responseWordCount =
            response +
            sizeof(SmbProtocol::Header);

        *responseWordCount = 0;

        uint8_t *responseByteCount =
            responseWordCount +
            sizeof(uint8_t);

        responseByteCount[0] = 0;
        responseByteCount[1] = 0;

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando SMB_COM_CLOSE response\n");

            return false;
        }

        printf(
            "SMB_COM_CLOSE respondido correctamente: FID=%u\n",
            fid);

        return true;
    }

    // void DebugFatFsSequentialRead(OpenFile &openFile)
    // {
    //     /*
    //      * Diagnóstico aislado de FatFs:
    //      *
    //      * - posiciona una sola vez al inicio;
    //      * - avanza exclusivamente con f_read();
    //      * - no usa f_lseek() entre bloques;
    //      * - imprime los primeros 32 bytes de los bloques que comienzan en
    //      *   0, 32768 y 34816.
    //      *
    //      * Esto permite distinguir un fallo de f_lseek() de un fallo más
    //      * profundo en el recorrido de clusters/sectores de exFAT.
    //      */
    //     constexpr UINT blockSize = 2048;
    //     constexpr FSIZE_t lastOffset = 34816;

    //     uint8_t buffer[blockSize]{};

    //     const FRESULT startSeekResult =
    //         f_lseek(
    //             &openFile.file,
    //             static_cast<FSIZE_t>(0));

    //     printf(
    //         "FATFS SEQ inicio: f_lseek(0)=%d, f_tell=%llu\n",
    //         static_cast<int>(startSeekResult),
    //         static_cast<unsigned long long>(
    //             f_tell(
    //                 &openFile.file)));

    //     if (startSeekResult != FR_OK)
    //     {
    //         return;
    //     }

    //     while (
    //         f_tell(&openFile.file) <= lastOffset)
    //     {
    //         const FSIZE_t blockOffset =
    //             f_tell(
    //                 &openFile.file);

    //         UINT bytesRead = 0;

    //         const FRESULT readResult =
    //             f_read(
    //                 &openFile.file,
    //                 buffer,
    //                 sizeof(buffer),
    //                 &bytesRead);

    //         if (readResult != FR_OK)
    //         {
    //             printf(
    //                 "FATFS SEQ f_read fallo: offset=%llu, resultado=%d\n",
    //                 static_cast<unsigned long long>(
    //                     blockOffset),
    //                 static_cast<int>(
    //                     readResult));

    //             break;
    //         }

    //         if (bytesRead == 0)
    //         {
    //             printf(
    //                 "FATFS SEQ EOF en offset=%llu\n",
    //                 static_cast<unsigned long long>(
    //                     blockOffset));

    //             break;
    //         }

    //         if (
    //             blockOffset == 0 ||
    //             blockOffset == 32768 ||
    //             blockOffset == 34816)
    //         {
    //             printf(
    //                 "FATFS SEQ offset=%llu, leidos=%u, f_tell=%llu, data:",
    //                 static_cast<unsigned long long>(
    //                     blockOffset),
    //                 static_cast<unsigned>(
    //                     bytesRead),
    //                 static_cast<unsigned long long>(
    //                     f_tell(
    //                         &openFile.file)));

    //             const size_t dumpLength =
    //                 bytesRead < 32
    //                     ? static_cast<size_t>(
    //                           bytesRead)
    //                     : 32;

    //             for (size_t i = 0; i < dumpLength; ++i)
    //             {
    //                 printf(
    //                     " %02X",
    //                     buffer[i]);
    //             }

    //             printf("\n");

    //             if (
    //                 blockOffset == 32768 &&
    //                 bytesRead >= 7)
    //             {
    //                 const bool hasIso9660Pvd =
    //                     buffer[0] == 0x01 &&
    //                     buffer[1] == 'C' &&
    //                     buffer[2] == 'D' &&
    //                     buffer[3] == '0' &&
    //                     buffer[4] == '0' &&
    //                     buffer[5] == '1' &&
    //                     buffer[6] == 0x01;

    //                 printf(
    //                     "FATFS SEQ PVD en 32768: %s\n",
    //                     hasIso9660Pvd
    //                         ? "si"
    //                         : "no");
    //             }
    //         }

    //         if (bytesRead < blockSize)
    //         {
    //             break;
    //         }
    //     }

    //     const FRESULT restoreResult =
    //         f_lseek(
    //             &openFile.file,
    //             static_cast<FSIZE_t>(0));

    //     printf(
    //         "FATFS SEQ posicion restaurada a 0: resultado=%d, f_tell=%llu\n",
    //         static_cast<int>(
    //             restoreResult),
    //         static_cast<unsigned long long>(
    //             f_tell(
    //                 &openFile.file)));
    // }

    bool HandleReadAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        /*
         * SMB_COM_READ_ANDX (0x2E), formato NT LM 0.12.
         *
         * WordCount = 12:
         *   AndXCommand      1
         *   AndXReserved     1
         *   AndXOffset       2
         *   FID              2
         *   OffsetLow        4
         *   MaxCount         2
         *   MinCount         2
         *   Timeout          4
         *   Remaining        2
         *   OffsetHigh       4
         */
        constexpr size_t parametersOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t requestParametersSize =
            1 + 1 + 1 + 2 + 2 + 4 + 2 + 2 + 4 + 2 + 4;

        constexpr size_t byteCountOffset =
            parametersOffset +
            requestParametersSize;

        constexpr size_t requestMinimumLength =
            byteCountOffset +
            sizeof(uint16_t);

        if (
            smbBuffer == nullptr ||
            smbLength < requestMinimumLength)
        {
            printf("SMB_COM_READ_ANDX demasiado corto: %zu bytes\n", smbLength);
            return false;
        }

        const uint8_t wordCount =
            smbBuffer[parametersOffset];

        if (wordCount != 12)
        {
            printf(
                "SMB_COM_READ_ANDX WordCount no soportado: %u\n",
                wordCount);

            return false;
        }

        const uint8_t *parameters =
            smbBuffer +
            parametersOffset;

        const uint16_t fid =
            ReadLittleEndian16(
                parameters + 5);

        const uint32_t offsetLow =
            ReadLittleEndian32(
                parameters + 7);

        const uint16_t maxCount =
            ReadLittleEndian16(
                parameters + 11);

        const uint32_t offsetHigh =
            ReadLittleEndian32(
                parameters + 21);

        const uint64_t fileOffset =
            (static_cast<uint64_t>(offsetHigh) << 32) |
            static_cast<uint64_t>(offsetLow);

        OpenFile *openFile =
            FindOpenFileByFid(fid);

        if (openFile == nullptr)
        {
            printf(
                "SMB_COM_READ_ANDX FID invalido: %u\n",
                fid);

            return SendSmbErrorResponse(
                clientSocket,
                requestHeader,
                SmbProtocol::Status::InvalidHandle);
        }

        size_t requestedBytes = static_cast<size_t>(maxCount);

        if (requestedBytes > SmbConstants::Files::MAX_READ_SIZE)
        {
            requestedBytes = SmbConstants::Files::MAX_READ_SIZE;
        }

        if (fileOffset >= openFile->size)
        {
            requestedBytes = 0;
        }
        else
        {
            const uint64_t available =
                openFile->size -
                fileOffset;

            if (
                static_cast<uint64_t>(
                    requestedBytes) >
                available)
            {
                requestedBytes =
                    static_cast<size_t>(
                        available);
            }
        }

        int64_t seekDurationUs = 0;
        int64_t readDurationUs = 0;

        if (requestedBytes > 0)
        {
            const int64_t seekStartUs = esp_timer_get_time();
            const FRESULT seekResult =
                f_lseek(
                    &openFile->file,
                    static_cast<FSIZE_t>(
                        fileOffset));
            seekDurationUs = esp_timer_get_time() - seekStartUs;

            if (seekResult != FR_OK)
            {
                printf(
                    "SMB_COM_READ_ANDX f_lseek fallo: offset=%llu, resultado=%d\n",
                    static_cast<unsigned long long>(
                        fileOffset),
                    static_cast<int>(
                        seekResult));

                return false;
            }

        }

        /*
         * READ_ANDX response, WordCount = 12.
         *
         * Después del header:
         *   WordCount            1
         *   AndXCommand          1
         *   AndXReserved         1
         *   AndXOffset           2
         *   Remaining            2
         *   DataCompactionMode   2
         *   Reserved             2
         *   DataLengthLow        2
         *   DataOffset           2
         *   DataLengthHigh       2
         *   Reserved2            8
         *   ByteCount            2
         *
         * Total fijo = 59 bytes. Usamos un byte de padding para que
         * los datos empiecen en offset 60 respecto al header SMB.
         */
        constexpr size_t responseParametersSize = 24;

        constexpr size_t responseByteCountOffset =
            sizeof(SmbProtocol::Header) +
            sizeof(uint8_t) +
            responseParametersSize;

        constexpr uint16_t responseDataOffset =
            static_cast<uint16_t>(
                responseByteCountOffset +
                sizeof(uint16_t) +
                1);

        const size_t responseLength =
            static_cast<size_t>(
                responseDataOffset) +
            requestedBytes;

        uint8_t *response =
            static_cast<uint8_t *>(
                malloc(responseLength));

        if (response == nullptr)
        {
            printf(
                "No fue posible reservar respuesta READ_ANDX de %zu bytes\n",
                responseLength);

            return false;
        }

        memset(
            response,
            0,
            responseLength);

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            0x2E;

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        uint8_t *responseParameters =
            response +
            sizeof(SmbProtocol::Header);

        responseParameters[0] = 12;
        responseParameters[1] =
            SmbProtocol::AndX::
                NO_FURTHER_COMMAND;
        responseParameters[2] =
            SmbProtocol::AndX::RESERVED;

        responseParameters[3] = 0;
        responseParameters[4] = 0;

        /*
         * Remaining, DataCompactionMode y Reserved quedan en cero.
         */
        const uint16_t dataLengthLow =
            static_cast<uint16_t>(
                requestedBytes & 0xFFFF);

        const uint16_t dataLengthHigh =
            static_cast<uint16_t>(
                (requestedBytes >> 16) & 0xFFFF);

        responseParameters[11] =
            static_cast<uint8_t>(
                dataLengthLow & 0xFF);
        responseParameters[12] =
            static_cast<uint8_t>(
                (dataLengthLow >> 8) & 0xFF);

        responseParameters[13] =
            static_cast<uint8_t>(
                responseDataOffset & 0xFF);
        responseParameters[14] =
            static_cast<uint8_t>(
                (responseDataOffset >> 8) & 0xFF);

        responseParameters[15] =
            static_cast<uint8_t>(
                dataLengthHigh & 0xFF);
        responseParameters[16] =
            static_cast<uint8_t>(
                (dataLengthHigh >> 8) & 0xFF);

        const uint16_t responseByteCount =
            static_cast<uint16_t>(
                requestedBytes + 1);

        response[responseByteCountOffset] =
            static_cast<uint8_t>(
                responseByteCount &
                0xFF);

        response[responseByteCountOffset + 1] =
            static_cast<uint8_t>(
                (responseByteCount >>
                 8) &
                0xFF);

        response[responseByteCountOffset +
                 sizeof(uint16_t)] = 0;

        UINT bytesRead = 0;

        if (requestedBytes > 0)
        {
            const int64_t readStartUs = esp_timer_get_time();
            const FRESULT readResult =
                f_read(
                    &openFile->file,
                    response +
                        responseDataOffset,
                    static_cast<UINT>(
                        requestedBytes),
                    &bytesRead);
            readDurationUs = esp_timer_get_time() - readStartUs;

            if (readResult != FR_OK)
            {
                printf(
                    "SMB_COM_READ_ANDX f_read fallo: resultado=%d\n",
                    static_cast<int>(
                        readResult));

                free(response);
                return false;
            }
        }

        /*
         * FatFs puede devolver menos bytes de los solicitados al llegar
         * al EOF. Ajustamos la respuesta al número real leído.
         */
        const size_t actualBytes =
            static_cast<size_t>(
                bytesRead);

        // Solo primera lectura por conexion: comprobar datos reales,
        // especialmente el PVD ISO9660 en el offset 32768.
        if (readConnectionDiagnostics.readRequests == 0)
        {
            const uint8_t *data = response + responseDataOffset;
            const bool isPvd =
                fileOffset == 32768 && actualBytes >= 7 &&
                data[0] == 0x01 && data[1] == 'C' &&
                data[2] == 'D' && data[3] == '0' &&
                data[4] == '0' && data[5] == '1' &&
                data[6] == 0x01;

            printf("SMB DIAG READ1: offset=%llu solicitados=%zu leidos=%zu PVD=%s data=",
                   static_cast<unsigned long long>(fileOffset),
                   requestedBytes, actualBytes, isPvd ? "si" : "no");

            const size_t shown = actualBytes < 16 ? actualBytes : 16;
            for (size_t i = 0; i < shown; ++i)
            {
                printf("%02X", static_cast<unsigned>(data[i]));
                if (i + 1 < shown) printf(" ");
            }
            printf("\n");
        }

        const uint16_t actualLow =
            static_cast<uint16_t>(
                actualBytes & 0xFFFF);

        const uint16_t actualHigh =
            static_cast<uint16_t>(
                (actualBytes >> 16) &
                0xFFFF);

        responseParameters[11] =
            static_cast<uint8_t>(
                actualLow & 0xFF);
        responseParameters[12] =
            static_cast<uint8_t>(
                (actualLow >> 8) & 0xFF);

        responseParameters[15] =
            static_cast<uint8_t>(
                actualHigh & 0xFF);
        responseParameters[16] =
            static_cast<uint8_t>(
                (actualHigh >> 8) & 0xFF);

        const uint16_t actualByteCount =
            static_cast<uint16_t>(
                actualBytes + 1);

        response[responseByteCountOffset] =
            static_cast<uint8_t>(
                actualByteCount &
                0xFF);

        response[responseByteCountOffset + 1] =
            static_cast<uint8_t>(
                (actualByteCount >>
                 8) &
                0xFF);

        const size_t actualResponseLength =
            static_cast<size_t>(
                responseDataOffset) +
            actualBytes;

        // Incluye creación de paquete Direct TCP y envío por socket.
        const int64_t sendStartUs = esp_timer_get_time();
        if (!SendSmbPacket(
                clientSocket,
                response,
                actualResponseLength))
        {
            printf(
                "Error enviando SMB_COM_READ_ANDX response\n");

            free(response);
            return false;
        }

        const int64_t sendDurationUs = esp_timer_get_time() - sendStartUs;
        // Guardar huella del bloque que acaba de aceptarse para envio TCP.
        // Se calcula antes de liberar response y no imprime nada por lectura.
        RecordRecentRead(fileOffset, response + responseDataOffset, actualBytes);
        free(response);

        RecordReadPerformance(
            actualBytes,
            seekDurationUs,
            readDurationUs,
            sendDurationUs);

        RecordConnectionRead(fileOffset, actualBytes);

        return true;
    }

    bool HandleLogoffAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        /*
         * SMB_COM_LOGOFF_ANDX (0x74)
         *
         * Request:
         *   SMB Header
         *   WordCount     = 2
         *   AndXCommand   = 1 byte
         *   AndXReserved  = 1 byte
         *   AndXOffset    = 2 bytes
         *   ByteCount     = 0
         *
         * Response:
         *   SMB Header
         *   WordCount     = 2
         *   AndXCommand   = 0xFF
         *   AndXReserved  = 0
         *   AndXOffset    = 0
         *   ByteCount     = 0
         */

        constexpr size_t parametersOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t parametersSize =
            1 + // WordCount
            1 + // AndXCommand
            1 + // AndXReserved
            2;  // AndXOffset

        constexpr size_t byteCountOffset =
            parametersOffset +
            parametersSize;

        constexpr size_t minimumLength =
            byteCountOffset +
            sizeof(uint16_t);

        if (
            smbBuffer == nullptr ||
            smbLength < minimumLength)
        {
            printf(
                "SMB_COM_LOGOFF_ANDX demasiado corto: %zu bytes\n",
                smbLength);

            return false;
        }

        const uint8_t wordCount =
            smbBuffer[parametersOffset];

        const uint8_t andXCommand =
            smbBuffer[parametersOffset + 1];

        const uint8_t andXReserved =
            smbBuffer[parametersOffset + 2];

        const uint16_t andXOffset =
            ReadLittleEndian16(
                smbBuffer +
                parametersOffset +
                3);

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer +
                byteCountOffset);

        printf("SMB_COM_LOGOFF_ANDX recibido\n");
        printf("  UID=%u\n", requestHeader.userId);
        printf("  WordCount=%u\n", wordCount);
        printf("  AndXCommand=0x%02X\n", andXCommand);
        printf("  AndXReserved=0x%02X\n", andXReserved);
        printf("  AndXOffset=%u\n", andXOffset);
        printf("  ByteCount=%u\n", byteCount);

        if (
            wordCount !=
            SmbProtocol::LogoffAndX::
                REQUEST_WORD_COUNT)
        {
            printf(
                "SMB_COM_LOGOFF_ANDX WordCount invalido: %u\n",
                wordCount);

            return false;
        }

        if (
            byteCount != 0 ||
            byteCountOffset +
                    sizeof(uint16_t) +
                    byteCount >
                smbLength)
        {
            printf(
                "SMB_COM_LOGOFF_ANDX ByteCount invalido: %u\n",
                byteCount);

            return false;
        }

        /*
         * Por ahora no soportamos comandos AndX encadenados.
         * OPL debería enviar 0xFF en este flujo.
         */
        if (
            andXCommand !=
            SmbProtocol::AndX::
                NO_FURTHER_COMMAND)
        {
            printf(
                "SMB_COM_LOGOFF_ANDX AndXCommand no soportado: 0x%02X\n",
                andXCommand);

            return false;
        }

        /*
         * LOGOFF invalida los recursos pertenecientes
         * a la sesión actual.
         *
         * Normalmente OPL ya habrá hecho CLOSE y
         * TREE_DISCONNECT antes, pero lo hacemos
         * también aquí de forma defensiva.
         */
        CloseAllOpenFiles();
        ResetSearchContext();

        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            1 + // WordCount
            1 + // AndXCommand
            1 + // AndXReserved
            2 + // AndXOffset
            2;  // ByteCount

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    LogoffAndX);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::
                    Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        /*
         * Mantenemos el UID de la solicitud en la respuesta.
         * La sesión deja de ser válida después de este comando,
         * pero la respuesta corresponde todavía a ese UID.
         */
        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        uint8_t *responseParameters =
            response +
            sizeof(SmbProtocol::Header);

        responseParameters[0] =
            SmbProtocol::LogoffAndX::
                RESPONSE_WORD_COUNT;

        responseParameters[1] =
            SmbProtocol::AndX::
                NO_FURTHER_COMMAND;

        responseParameters[2] =
            SmbProtocol::AndX::
                RESERVED;

        responseParameters[3] = 0;
        responseParameters[4] = 0;

        uint8_t *responseByteCount =
            responseParameters +
            parametersSize;

        responseByteCount[0] = 0;
        responseByteCount[1] = 0;

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando SMB_COM_LOGOFF_ANDX response\n");

            return false;
        }

        printf(
            "SMB_COM_LOGOFF_ANDX respondido correctamente\n");

        /*
         * No cerramos TCP nosotros.
         * Dejamos que OPL cierre o reutilice
         * la conexión según su flujo normal.
         */
        return true;
    }

    bool HandleTreeDisconnect(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        /*
         * SMB_COM_TREE_DISCONNECT (0x71)
         *
         * Request:
         *   SMB Header = 32 bytes
         *   WordCount  = 0
         *   ByteCount  = 0
         *
         * Response:
         *   SMB Header
         *   WordCount  = 0
         *   ByteCount  = 0
         */

        constexpr size_t wordCountOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t byteCountOffset =
            wordCountOffset +
            sizeof(uint8_t);

        constexpr size_t minimumLength =
            byteCountOffset +
            sizeof(uint16_t);

        if (
            smbBuffer == nullptr ||
            smbLength < minimumLength)
        {
            printf(
                "SMB_COM_TREE_DISCONNECT demasiado corto: %zu bytes\n",
                smbLength);

            return false;
        }

        const uint8_t wordCount =
            smbBuffer[wordCountOffset];

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer +
                byteCountOffset);

        printf("SMB_COM_TREE_DISCONNECT recibido\n");
        printf("  TID=%u\n", requestHeader.treeId);
        printf("  WordCount=%u\n", wordCount);
        printf("  ByteCount=%u\n", byteCount);

        if (
            wordCount !=
            SmbProtocol::TreeDisconnect::
                REQUEST_WORD_COUNT)
        {
            printf(
                "SMB_COM_TREE_DISCONNECT WordCount invalido: %u\n",
                wordCount);

            return false;
        }

        if (
            byteCount != 0 ||
            byteCountOffset +
                    sizeof(uint16_t) +
                    byteCount >
                smbLength)
        {
            printf(
                "SMB_COM_TREE_DISCONNECT ByteCount invalido: %u\n",
                byteCount);

            return false;
        }

        /*
         * Actualmente solo tenemos un tree/share por conexión.
         *
         * TREE_DISCONNECT invalida los recursos abiertos asociados
         * a ese tree, así que cerramos cualquier FID que haya quedado
         * abierto.
         *
         * En el flujo actual de OPL normalmente ya llega un CLOSE
         * antes de este comando, por lo que esto será un no-op.
         */
        CloseAllOpenFiles();
        ResetSearchContext();

        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(uint8_t) +
            sizeof(uint16_t);

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    TreeDisconnect);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::
                    Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        uint8_t *responseWordCount =
            response +
            sizeof(SmbProtocol::Header);

        *responseWordCount =
            SmbProtocol::TreeDisconnect::
                RESPONSE_WORD_COUNT;

        uint8_t *responseByteCount =
            responseWordCount +
            sizeof(uint8_t);

        responseByteCount[0] = 0;
        responseByteCount[1] = 0;

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando SMB_COM_TREE_DISCONNECT response\n");

            return false;
        }

        printf(
            "SMB_COM_TREE_DISCONNECT respondido correctamente\n");

        /*
         * IMPORTANTE:
         *
         * true mantiene viva la conexión TCP.
         * Ahora será OPL quien decida si:
         * - envía LOGOFF_ANDX,
         * - reutiliza la conexión,
         * - o cierra TCP por su cuenta.
         */
        return true;
    }

    bool HandleOpenAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        constexpr size_t parametersOffset =
            SmbProtocol::SMB1_HEADER_SIZE;

        constexpr size_t byteCountOffset =
            parametersOffset +
            sizeof(SmbProtocol::OpenAndXRequestParameters);

        constexpr size_t dataOffset =
            byteCountOffset +
            sizeof(uint16_t);

        if (
            smbBuffer == nullptr ||
            smbLength < dataOffset)
        {
            printf("SMB_COM_OPEN_ANDX demasiado corto: %zu bytes\n",
                   smbLength);

            return false;
        }

        const auto *parameters =
            reinterpret_cast<
                const SmbProtocol::OpenAndXRequestParameters *>(
                smbBuffer +
                parametersOffset);

        if (
            parameters->wordCount !=
            SmbProtocol::OpenAndX::REQUEST_WORD_COUNT)
        {
            printf(
                "SMB_COM_OPEN_ANDX WordCount invalido: %u\n",
                parameters->wordCount);

            return false;
        }

        const uint16_t byteCount =
            ReadLittleEndian16(
                smbBuffer +
                byteCountOffset);

        if (
            dataOffset +
                static_cast<size_t>(byteCount) >
            smbLength)
        {
            printf(
                "SMB_COM_OPEN_ANDX ByteCount invalido: %u\n",
                byteCount);

            return false;
        }

        if (byteCount == 0)
        {
            printf("SMB_COM_OPEN_ANDX sin nombre de archivo\n");
            return false;
        }

        /*
         * OPEN_ANDX coloca el nombre inmediatamente después
         * de ByteCount.
         *
         * No usa el BufferFormat 0x04 de SMB_COM_OPEN.
         */
        const uint8_t *fileNameData =
            smbBuffer +
            dataOffset;

        const bool unicode =
            (requestHeader.flags2 &
             static_cast<uint16_t>(
                 SmbProtocol::Flags2::Unicode)) != 0;

        printf("SMB_COM_OPEN_ANDX recibido\n");
        printf("  WordCount=%u\n",
               parameters->wordCount);

        printf(
            "  AndXCommand=0x%02X\n",
            parameters->andXCommand);

        printf(
            "  OpenFlags=0x%04X\n",
            parameters->openFlags);

        printf(
            "  DesiredAccess=0x%04X\n",
            parameters->desiredAccess);

        printf(
            "  SearchAttributes=0x%04X\n",
            parameters->searchAttributes);

        printf(
            "  FileAttributes=0x%04X\n",
            parameters->fileAttributes);

        printf(
            "  OpenFunction=0x%04X\n",
            parameters->openFunction);

        printf(
            "  ByteCount=%u\n",
            byteCount);

        printf(
            "  Unicode=%s\n",
            unicode
                ? "si"
                : "no");

        DumpHexBuffer("OPEN_ANDX REQUEST", smbBuffer, smbLength, 128);

        /*
         * Por ahora OPL está usando nombres OEM/no Unicode,
         * igual que ocurrió con NT_CREATE_ANDX.
         */
        if (unicode)
        {
            printf(
                "SMB_COM_OPEN_ANDX: nombres Unicode aun no implementados\n");

            return false;
        }

        const void *terminator =
            memchr(
                fileNameData,
                '\0',
                byteCount);

        if (terminator == nullptr)
        {
            printf(
                "SMB_COM_OPEN_ANDX nombre sin terminador NUL\n");

            return false;
        }

        const size_t fileNameLength =
            static_cast<
                const uint8_t *>(terminator) -
            fileNameData;

        printf("  FileName=%.*s\n",
               static_cast<int>(
                   fileNameLength),
               reinterpret_cast<
                   const char *>(fileNameData));

        char fatFsPath[SmbConstants::Limits::
                           MAX_PATH_LENGTH]{};

        size_t outputPosition = 0;

        fatFsPath[outputPosition++] = '0';
        fatFsPath[outputPosition++] = ':';
        fatFsPath[outputPosition++] = '/';

        size_t inputPosition = 0;

        while (
            inputPosition <
                fileNameLength &&
            (fileNameData[inputPosition] == '\\' ||
             fileNameData[inputPosition] == '/'))
        {
            ++inputPosition;
        }

        for (
            ;
            inputPosition <
            fileNameLength;
            ++inputPosition)
        {
            if (
                outputPosition + 1 >=
                sizeof(fatFsPath))
            {
                printf(
                    "SMB_COM_OPEN_ANDX ruta demasiado larga\n");

                return false;
            }

            const uint8_t character =
                fileNameData[inputPosition];

            fatFsPath[outputPosition++] =
                character == '\\'
                    ? '/'
                    : static_cast<char>(
                          character);
        }

        fatFsPath[outputPosition] = '\0';

        if (
            fatFsPath[3] == '\0' ||
            strstr(
                fatFsPath,
                "..") != nullptr)
        {
            printf(
                "SMB_COM_OPEN_ANDX ruta rechazada: %s\n",
                fatFsPath);

            return false;
        }

        printf(
            "  FatFsPath=%s\n",
            fatFsPath);

        FILINFO fileInfo{};

        const FRESULT statResult =
            f_stat(
                fatFsPath,
                &fileInfo);

        if (statResult != FR_OK)
        {
            printf(
                "OPEN_ANDX: archivo no encontrado: %s, f_stat=%d\n",
                fatFsPath,
                static_cast<int>(
                    statResult));

            if (!SendSmbErrorResponse(
                    clientSocket,
                    requestHeader,
                    SmbProtocol::Status::
                        NoSuchFile))
            {
                printf(
                    "Error enviando OPEN_ANDX NoSuchFile\n");

                return false;
            }

            printf(
                "SMB_COM_OPEN_ANDX respondido con STATUS_NO_SUCH_FILE\n");

            return true;
        }

        const bool isDirectory =
            (fileInfo.fattrib &
             AM_DIR) != 0;

        printf(
            "OPEN_ANDX encontrado: %s, tamaño=%llu, directorio=%s\n",
            fatFsPath,
            static_cast<
                unsigned long long>(
                fileInfo.fsize),
            isDirectory
                ? "si"
                : "no");

        /*
         * Para el caso actual de OPL solamente necesitamos
         * abrir ISOs como archivos.
         */
        if (isDirectory)
        {
            printf(
                "SMB_COM_OPEN_ANDX: apertura de directorios no soportada\n");

            return SendSmbErrorResponse(
                clientSocket,
                requestHeader,
                SmbProtocol::Status::
                    AccessDenied);
        }

        OpenFile *openFile =
            FindFreeOpenFile();

        if (openFile == nullptr)
        {
            printf(
                "SMB_COM_OPEN_ANDX: no hay FID disponibles\n");

            return false;
        }

        const FRESULT openResult =
            f_open(
                &openFile->file,
                fatFsPath,
                FA_READ);

        if (openResult != FR_OK)
        {
            printf(
                "SMB_COM_OPEN_ANDX: f_open fallo para %s, resultado=%d\n",
                fatFsPath,
                static_cast<int>(
                    openResult));

            ResetOpenFile(
                *openFile);

            return false;
        }

        openFile->inUse = true;

        openFile->size =
            static_cast<uint64_t>(
                fileInfo.fsize);

        printf(
            "SMB_COM_OPEN_ANDX: archivo abierto, FID=%u, tamaño=%llu\n",
            openFile->fid,
            static_cast<
                unsigned long long>(
                openFile->size));

        constexpr size_t responseLength =
            sizeof(
                SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    OpenAndXResponseParameters) +
            sizeof(uint16_t);

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    OpenAndX);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::
                    Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<
                    SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::
                    Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *responseParameters =
            reinterpret_cast<
                SmbProtocol::
                    OpenAndXResponseParameters *>(
                response +
                sizeof(
                    SmbProtocol::Header));

        responseParameters->wordCount =
            SmbProtocol::OpenAndX::
                RESPONSE_WORD_COUNT;

        responseParameters->andXCommand =
            SmbProtocol::AndX::
                NO_FURTHER_COMMAND;

        responseParameters->andXReserved =
            SmbProtocol::AndX::
                RESERVED;

        responseParameters->andXOffset =
            0;

        responseParameters->fid =
            openFile->fid;

        /*
         * MS-CIFS 2.2.4.41.2: si el cliente NO solicita atributos
         * (OpenFlags bit 0 = 0), los campos despues de FID deben ser 0.
         * El buffer response{} ya esta inicializado en cero.
         */
        constexpr uint16_t OPEN_ANDX_REQUEST_ATTRIBUTES = 0x0001;

        if ((parameters->openFlags & OPEN_ANDX_REQUEST_ATTRIBUTES) != 0)
        {
            responseParameters->fileAttributes =
                static_cast<uint16_t>(
                    SmbProtocol::QueryFileInformation::ATTRIBUTE_NORMAL);

            responseParameters->lastWriteTime = 0;
            responseParameters->fileDataSize =
                static_cast<uint32_t>(openFile->size & 0xFFFFFFFFULL);
            responseParameters->grantedAccess = parameters->desiredAccess;
            responseParameters->resourceType =
                SmbProtocol::OpenAndX::FILE_TYPE_DISK;
            responseParameters->nmPipeStatus = 0;
            responseParameters->openResult =
                SmbProtocol::OpenAndX::OPEN_ACTION_OPENED;
            responseParameters->serverFid = 0;
            responseParameters->reserved = 0;
        }

        uint8_t *byteCountPosition =
            response +
            sizeof(
                SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    OpenAndXResponseParameters);

        byteCountPosition[0] = 0;
        byteCountPosition[1] = 0;

        printf(
            "OPEN_ANDX response layout: SMBLength=%zu, ByteCount=0, FID=%u, "
            "FileDataSize=0x%08lX (%lu)\n",
            sizeof(response),
            openFile->fid,
            static_cast<unsigned long>(responseParameters->fileDataSize),
            static_cast<unsigned long>(responseParameters->fileDataSize));

        DumpHexBuffer(
            "OPEN_ANDX RESPONSE",
            response,
            sizeof(response),
            sizeof(response));

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando SMB_COM_OPEN_ANDX response\n");

            f_close(
                &openFile->file);

            ResetOpenFile(
                *openFile);

            return false;
        }

        printf(
            "SMB_COM_OPEN_ANDX respondido correctamente: FID=%u\n",
            openFile->fid);

        return true;
    }

    bool HandleNtCreateAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        constexpr size_t parametersOffset = SmbProtocol::SMB1_HEADER_SIZE;
        constexpr size_t byteCountOffset =
            parametersOffset +
            sizeof(SmbProtocol::NtCreateAndXRequestParameters);

        constexpr size_t dataOffset =
            byteCountOffset +
            sizeof(uint16_t);

        if (smbBuffer == nullptr || smbLength < dataOffset)
        {
            printf("SMB_COM_NT_CREATE_ANDX demasiado corto\n");
            return false;
        }

        const auto *parameters =
            reinterpret_cast<const SmbProtocol::NtCreateAndXRequestParameters *>(
                smbBuffer + parametersOffset);

        if (parameters->wordCount != SmbProtocol::NtCreateAndX::REQUEST_WORD_COUNT)
        {
            printf("SMB_COM_NT_CREATE_ANDX WordCount invalido: %u\n",
                   parameters->wordCount);
            return false;
        }

        const uint16_t byteCount =
            ReadLittleEndian16(smbBuffer + byteCountOffset);

        if (dataOffset + static_cast<size_t>(byteCount) > smbLength)
        {
            printf("SMB_COM_NT_CREATE_ANDX ByteCount invalido: %u\n",
                   byteCount);
            return false;
        }

        if (parameters->nameLength > byteCount)
        {
            printf("SMB_COM_NT_CREATE_ANDX NameLength invalido: %u, ByteCount=%u\n",
                   parameters->nameLength,
                   byteCount);
            return false;
        }

        const uint8_t *data = smbBuffer + dataOffset;

        const size_t paddingLength =
            static_cast<size_t>(byteCount) -
            parameters->nameLength;

        if (paddingLength > 1)
        {
            printf("SMB_COM_NT_CREATE_ANDX padding inesperado: %zu bytes\n",
                   paddingLength);
            return false;
        }

        const uint8_t *fileName = data + paddingLength;
        const size_t fileNameLength = parameters->nameLength;

        const bool unicode =
            (requestHeader.flags2 & 0x8000) != 0;

        printf("SMB_COM_NT_CREATE_ANDX recibido\n");
        printf("  WordCount=%u\n", parameters->wordCount);
        printf("  NameLength=%u\n", parameters->nameLength);
        printf("  ByteCount=%u\n", byteCount);
        printf("  Unicode=%s\n", unicode ? "si" : "no");
        printf("  DesiredAccess=0x%08lX\n",
               static_cast<unsigned long>(parameters->desiredAccess));
        printf("  ShareAccess=0x%08lX\n",
               static_cast<unsigned long>(parameters->shareAccess));
        printf("  CreateDisposition=0x%08lX\n",
               static_cast<unsigned long>(parameters->createDisposition));
        printf("  CreateOptions=0x%08lX\n",
               static_cast<unsigned long>(parameters->createOptions));
        printf("  ExtFileAttributes=0x%08lX\n",
               static_cast<unsigned long>(parameters->extFileAttributes));

        printf("  FileName=");

        if (unicode)
        {
            for (size_t i = 0; i + 1 < fileNameLength; i += 2)
            {
                const uint16_t character =
                    ReadLittleEndian16(fileName + i);

                if (character == 0)
                {
                    break;
                }

                if (character >= 32 && character <= 126)
                {
                    printf("%c", static_cast<char>(character));
                }
                else
                {
                    printf("\\u%04X", character);
                }
            }
        }
        else
        {
            for (size_t i = 0; i < fileNameLength; ++i)
            {
                const uint8_t character = fileName[i];

                if (character == 0)
                {
                    break;
                }

                if (character >= 32 && character <= 126)
                {
                    printf("%c", static_cast<char>(character));
                }
                else
                {
                    printf("\\x%02X", character);
                }
            }
        }

        printf("\n");

        if (unicode)
        {
            printf("NT_CREATE_ANDX: conversion Unicode a FatFs aun no implementada\n");
            return false;
        }

        char fatFsPath[SmbConstants::Limits::MAX_PATH_LENGTH]{};

        size_t outputPosition = 0;
        fatFsPath[outputPosition++] = '0';
        fatFsPath[outputPosition++] = ':';
        fatFsPath[outputPosition++] = '/';

        size_t inputPosition = 0;

        while (
            inputPosition < fileNameLength &&
            (fileName[inputPosition] == '\\' ||
             fileName[inputPosition] == '/'))
        {
            ++inputPosition;
        }

        for (; inputPosition < fileNameLength; ++inputPosition)
        {
            const uint8_t character = fileName[inputPosition];

            if (character == '\0')
            {
                break;
            }

            if (outputPosition + 1 >= sizeof(fatFsPath))
            {
                printf("NT_CREATE_ANDX: ruta demasiado larga\n");
                return false;
            }

            fatFsPath[outputPosition++] =
                character == '\\'
                    ? '/'
                    : static_cast<char>(character);
        }

        fatFsPath[outputPosition] = '\0';

        if (strstr(fatFsPath, "..") != nullptr)
        {
            printf("NT_CREATE_ANDX: ruta rechazada: %s\n",
                   fatFsPath);
            return false;
        }

        printf("  FatFsPath=%s\n", fatFsPath);

        FILINFO fileInfo{};

        const FRESULT statResult =
            f_stat(fatFsPath, &fileInfo);

        if (statResult != FR_OK)
        {
            printf("NT_CREATE_ANDX: archivo no encontrado: %s, f_stat=%d\n",
                   fatFsPath,
                   static_cast<int>(statResult));

            if (!SendSmbErrorResponse(
                    clientSocket,
                    requestHeader,
                    SmbProtocol::Status::NoSuchFile))
            {
                printf("Error enviando NT_CREATE_ANDX NoSuchFile\n");
                return false;
            }

            printf("SMB_COM_NT_CREATE_ANDX respondido con STATUS_NO_SUCH_FILE\n");
            return true;
        }

        const bool isDirectory =
            (fileInfo.fattrib & AM_DIR) != 0;

        printf(
            "NT_CREATE_ANDX encontrado: %s, tamaño=%llu, directorio=%s\n",
            fatFsPath,
            static_cast<unsigned long long>(fileInfo.fsize),
            isDirectory ? "si" : "no");

        if (isDirectory)
        {
            printf(
                "NT_CREATE_ANDX: apertura de directorios aun no implementada\n");

            return false;
        }

        OpenFile *openFile =
            FindFreeOpenFile();

        if (openFile == nullptr)
        {
            printf(
                "NT_CREATE_ANDX: no hay FID disponibles\n");

            return false;
        }

        const FRESULT openResult =
            f_open(
                &openFile->file,
                fatFsPath,
                FA_READ);

        if (openResult != FR_OK)
        {
            printf(
                "NT_CREATE_ANDX: f_open fallo para %s, resultado=%d\n",
                fatFsPath,
                static_cast<int>(openResult));

            ResetOpenFile(*openFile);
            return false;
        }

        openFile->inUse = true;
        openFile->size =
            static_cast<uint64_t>(
                fileInfo.fsize);

        printf(
            "NT_CREATE_ANDX: archivo abierto, FID=%u, tamaño=%llu\n",
            openFile->fid,
            static_cast<unsigned long long>(
                openFile->size));

        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    NtCreateAndXResponseParameters) +
            sizeof(uint16_t);

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    NtCreateAndX);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        responseHeader->flags =
            static_cast<uint8_t>(
                static_cast<SmbProtocol::Flags>(
                    requestHeader.flags) |
                SmbProtocol::Flags::Reply);

        responseHeader->flags2 =
            requestHeader.flags2;

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId =
            requestHeader.treeId;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            requestHeader.userId;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *responseParameters =
            reinterpret_cast<
                SmbProtocol::
                    NtCreateAndXResponseParameters *>(
                response +
                sizeof(SmbProtocol::Header));

        responseParameters->wordCount =
            SmbProtocol::NtCreateAndX::
                RESPONSE_WORD_COUNT;

        responseParameters->andXCommand =
            SmbProtocol::AndX::
                NO_FURTHER_COMMAND;

        responseParameters->andXReserved =
            SmbProtocol::AndX::RESERVED;

        responseParameters->andXOffset = 0;

        responseParameters->oplockLevel =
            SmbProtocol::NtCreateAndX::
                OPLOCK_LEVEL_NONE;

        responseParameters->fid =
            openFile->fid;

        responseParameters->createDisposition =
            SmbProtocol::NtCreateAndX::
                CREATE_ACTION_OPENED;

        responseParameters->createTime = 0;
        responseParameters->lastAccessTime = 0;
        responseParameters->lastWriteTime = 0;
        responseParameters->lastChangeTime = 0;

        responseParameters->extFileAttributes =
            SmbProtocol::QueryFileInformation::
                ATTRIBUTE_NORMAL;

        responseParameters->allocationSize =
            openFile->size;

        responseParameters->endOfFile =
            openFile->size;

        responseParameters->resourceType =
            SmbProtocol::NtCreateAndX::
                RESOURCE_TYPE_DISK;

        responseParameters->nmPipeStatus = 0;
        responseParameters->directory = 0;

        uint8_t *byteCountPosition =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    NtCreateAndXResponseParameters);

        byteCountPosition[0] = 0;
        byteCountPosition[1] = 0;

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando SMB_COM_NT_CREATE_ANDX response\n");

            f_close(&openFile->file);
            ResetOpenFile(*openFile);

            return false;
        }

        printf(
            "SMB_COM_NT_CREATE_ANDX respondido correctamente: FID=%u\n",
            openFile->fid);

        return true;
    }

    bool HandleNegotiate(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        const uint8_t *dialectData = nullptr;
        size_t dialectDataLength = 0;

        if (!ParseNegotiateRequest(
                smbBuffer,
                smbLength,
                dialectData,
                dialectDataLength))
        {
            printf(
                "Solicitud SMB_COM_NEGOTIATE invalida\n");

            return false;
        }

        const int dialectIndex = FindDialect(
            dialectData,
            dialectDataLength,
            SmbConstants::Negotiate::DIALECT);

        if (dialectIndex < 0)
        {
            printf(
                "Dialect '%s' no ofrecido por el cliente\n",
                SmbConstants::Negotiate::DIALECT);

            return false;
        }

        constexpr size_t challengeLength =
            SmbConstants::Negotiate::
                CHALLENGE_LENGTH;

        static_assert(
            challengeLength == 8,
            "SMB1 Non-Extended Security requiere challenge de 8 bytes");

        uint8_t challenge[challengeLength]{};

        esp_fill_random(
            challenge,
            sizeof(challenge));

        constexpr size_t negotiateDataLength =
            challengeLength + 1;

        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    NegotiateResponseParameters) +
            sizeof(uint16_t) +
            negotiateDataLength;

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::Negotiate);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        const auto requestFlags =
            static_cast<SmbProtocol::Flags>(
                requestHeader.flags);

        responseHeader->flags =
            static_cast<uint8_t>(
                requestFlags |
                SmbProtocol::Flags::Reply);

        const auto requestFlags2 =
            static_cast<SmbProtocol::Flags2>(
                requestHeader.flags2);

        SmbProtocol::Flags2 responseFlags2 =
            SmbProtocol::Flags2::None;

        if (SmbProtocol::HasFlag(
                requestFlags2,
                SmbProtocol::Flags2::LongNames))
        {
            responseFlags2 =
                responseFlags2 |
                SmbProtocol::Flags2::LongNames;
        }

        if (SmbProtocol::HasFlag(
                requestFlags2,
                SmbProtocol::Flags2::IsLongName))
        {
            responseFlags2 =
                responseFlags2 |
                SmbProtocol::Flags2::IsLongName;
        }

        if (SmbProtocol::HasFlag(
                requestFlags2,
                SmbProtocol::Flags2::NtStatus))
        {
            responseFlags2 =
                responseFlags2 |
                SmbProtocol::Flags2::NtStatus;
        }

        responseHeader->flags2 =
            static_cast<uint16_t>(
                responseFlags2);

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId = 0;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId = 0;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *parameters =
            reinterpret_cast<
                SmbProtocol::
                    NegotiateResponseParameters *>(
                response +
                sizeof(SmbProtocol::Header));

        parameters->wordCount = 17;

        parameters->dialectIndex =
            static_cast<uint16_t>(
                dialectIndex);

        parameters->securityMode =
            static_cast<uint8_t>(
                SmbProtocol::SecurityMode::
                    UserSecurity |
                SmbProtocol::SecurityMode::
                    EncryptPasswords);

        parameters->maxMpxCount =
            SmbConstants::Negotiate::
                MAX_MPX_COUNT;

        parameters->maxNumberVcs =
            SmbConstants::Negotiate::
                MAX_NUMBER_VCS;

        parameters->maxBufferSize =
            SmbConstants::Negotiate::
                MAX_BUFFER_SIZE;

        parameters->maxRawSize =
            SmbConstants::Negotiate::
                MAX_RAW_SIZE;

        parameters->sessionKey =
            SmbConstants::Negotiate::
                SESSION_KEY;

        const SmbProtocol::Capability
            capabilities =
                SmbProtocol::Capability::
                    LargeFiles |
                SmbProtocol::Capability::
                    NtSmbs |
                SmbProtocol::Capability::
                    Status32 |
                SmbProtocol::Capability::
                    NtFind |
                SmbProtocol::Capability::
                    LargeReadX;

        parameters->capabilities =
            static_cast<uint32_t>(
                capabilities);

        parameters->systemTime =
            (static_cast<uint64_t>(
                 SmbConstants::Negotiate::
                     SERVER_TIME_HIGH)
             << 32) |
            static_cast<uint64_t>(
                SmbConstants::Negotiate::
                    SERVER_TIME_LOW);

        parameters->serverTimeZone =
            SmbConstants::Negotiate::
                SERVER_TIME_ZONE;

        parameters->challengeLength =
            SmbConstants::Negotiate::
                CHALLENGE_LENGTH;

        uint8_t *byteCountPosition =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    NegotiateResponseParameters);

        const uint16_t byteCount =
            static_cast<uint16_t>(
                negotiateDataLength);

        byteCountPosition[0] =
            static_cast<uint8_t>(
                byteCount & 0xFF);

        byteCountPosition[1] =
            static_cast<uint8_t>(
                (byteCount >> 8) & 0xFF);

        uint8_t *responseData =
            byteCountPosition +
            sizeof(uint16_t);

        memcpy(
            responseData,
            challenge,
            sizeof(challenge));

        responseData[challengeLength] =
            '\0';

        printf(
            "SMB_COM_NEGOTIATE: dialecto seleccionado [%d] %s\n",
            dialectIndex,
            SmbConstants::Negotiate::DIALECT);

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando respuesta SMB_COM_NEGOTIATE\n");

            return false;
        }

        printf(
            "SMB_COM_NEGOTIATE respondido correctamente (%zu bytes)\n",
            sizeof(response));

        return true;
    }

    bool HandleSessionSetupAndX(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &requestHeader)
    {
        const SmbProtocol::
            SessionSetupAndXRequestParameters *
                requestParameters = nullptr;

        const uint8_t *requestData = nullptr;
        size_t requestDataLength = 0;

        if (!ParseSessionSetupAndXRequest(
                smbBuffer,
                smbLength,
                requestParameters,
                requestData,
                requestDataLength))
        {
            printf(
                "Solicitud SMB_COM_SESSION_SETUP_ANDX invalida\n");

            return false;
        }

        printf(
            "SESSION_SETUP_ANDX: OEM password=%u bytes, Unicode password=%u bytes, data=%zu bytes\n",
            requestParameters->oemPasswordLength,
            requestParameters->unicodePasswordLength,
            requestDataLength);

        printf(
            "SESSION_SETUP_ANDX: capabilities=0x%08lX\n",
            static_cast<unsigned long>(
                requestParameters->capabilities));

        if (!SmbConstants::Authentication::ALLOW_GUEST)
        {
            printf(
                "SESSION_SETUP_ANDX: acceso guest deshabilitado\n");

            return false;
        }

        /*
         * Respuesta clásica Non-Extended Security.
         *
         * En esta fase aceptamos la sesión como Guest y no
         * validamos la respuesta LM/NTLM enviada por el cliente.
         *
         * Los tres bytes de datos representan:
         * NativeOS="" + NativeLanMan="" + PrimaryDomain="".
         */
        constexpr size_t responseLength =
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    SessionSetupAndXResponseParameters) +
            sizeof(uint16_t) +
            SESSION_SETUP_RESPONSE_DATA_LENGTH;

        uint8_t response[responseLength]{};

        auto *responseHeader =
            reinterpret_cast<
                SmbProtocol::Header *>(
                response);

        SmbProtocol::SetSignature(
            *responseHeader);

        responseHeader->command =
            static_cast<uint8_t>(
                SmbProtocol::Command::
                    SessionSetupAndX);

        responseHeader->status =
            static_cast<uint32_t>(
                SmbProtocol::Status::Success);

        const auto requestFlags =
            static_cast<SmbProtocol::Flags>(
                requestHeader.flags);

        responseHeader->flags =
            static_cast<uint8_t>(
                requestFlags |
                SmbProtocol::Flags::Reply);

        const auto requestFlags2 =
            static_cast<SmbProtocol::Flags2>(
                requestHeader.flags2);

        SmbProtocol::Flags2 responseFlags2 =
            SmbProtocol::Flags2::None;

        if (SmbProtocol::HasFlag(
                requestFlags2,
                SmbProtocol::Flags2::LongNames))
        {
            responseFlags2 =
                responseFlags2 |
                SmbProtocol::Flags2::LongNames;
        }

        if (SmbProtocol::HasFlag(
                requestFlags2,
                SmbProtocol::Flags2::IsLongName))
        {
            responseFlags2 =
                responseFlags2 |
                SmbProtocol::Flags2::IsLongName;
        }

        if (SmbProtocol::HasFlag(
                requestFlags2,
                SmbProtocol::Flags2::NtStatus))
        {
            responseFlags2 =
                responseFlags2 |
                SmbProtocol::Flags2::NtStatus;
        }

        responseHeader->flags2 =
            static_cast<uint16_t>(
                responseFlags2);

        responseHeader->pidHigh =
            requestHeader.pidHigh;

        responseHeader->treeId = 0;

        responseHeader->processId =
            requestHeader.processId;

        responseHeader->userId =
            SmbConstants::Session::
                DEFAULT_UID;

        responseHeader->multiplexId =
            requestHeader.multiplexId;

        auto *responseParameters =
            reinterpret_cast<
                SmbProtocol::
                    SessionSetupAndXResponseParameters *>(
                response +
                sizeof(SmbProtocol::Header));

        responseParameters->wordCount =
            SmbProtocol::SessionSetup::
                RESPONSE_WORD_COUNT;

        responseParameters->andXCommand =
            SmbProtocol::AndX::
                NO_FURTHER_COMMAND;

        responseParameters->andXReserved =
            SmbProtocol::AndX::RESERVED;

        responseParameters->andXOffset = 0;

        responseParameters->action =
            SmbProtocol::SessionSetup::
                ACTION_LOGGED_IN_AS_GUEST;

        uint8_t *byteCountPosition =
            response +
            sizeof(SmbProtocol::Header) +
            sizeof(
                SmbProtocol::
                    SessionSetupAndXResponseParameters);

        const uint16_t byteCount =
            static_cast<uint16_t>(
                SESSION_SETUP_RESPONSE_DATA_LENGTH);

        byteCountPosition[0] =
            static_cast<uint8_t>(
                byteCount & 0xFF);

        byteCountPosition[1] =
            static_cast<uint8_t>(
                (byteCount >> 8) & 0xFF);

        /*
         * El buffer ya está inicializado a cero, por lo que
         * los 3 strings OEM quedan como cadenas vacías NUL.
         */
        printf(
            "SESSION_SETUP_ANDX: acceso Guest aceptado, UID=%u\n",
            SmbConstants::Session::DEFAULT_UID);

        if (!SendSmbPacket(
                clientSocket,
                response,
                sizeof(response)))
        {
            printf(
                "Error enviando respuesta SMB_COM_SESSION_SETUP_ANDX\n");

            return false;
        }

        printf(
            "SMB_COM_SESSION_SETUP_ANDX respondido correctamente (%zu bytes)\n",
            sizeof(response));

        return true;
    }

    bool HandleSmbCommand(
        int clientSocket,
        const uint8_t *smbBuffer,
        size_t smbLength,
        const SmbProtocol::Header &header)
    {
        /*
         * SMB_COM_CREATE_DIRECTORY = 0x00.
         * Se compara el byte crudo para no exigir todavía un cambio
         * adicional en SmbProtocol::Command.
         */
        if (header.command == 0x00)
        {
            return HandleCreateDirectory(
                clientSocket,
                smbBuffer,
                smbLength,
                header);
        }

        if (header.command == 0x04)
        {
            return HandleClose(
                clientSocket,
                smbBuffer,
                smbLength,
                header);
        }

        if (header.command == 0x2E)
        {
            return HandleReadAndX(
                clientSocket,
                smbBuffer,
                smbLength,
                header);
        }

        switch (SmbProtocol::GetCommand(header))
        {
        case SmbProtocol::Command::Negotiate:
            return HandleNegotiate(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::
            SessionSetupAndX:
            return HandleSessionSetupAndX(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::Echo:
            return HandleEcho(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::TreeConnectAndX:
            return HandleTreeConnectAndX(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::Transaction2:
            return HandleTransaction2(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::NtCreateAndX:
            return HandleNtCreateAndX(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::OpenAndX:
            return HandleOpenAndX(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::TreeDisconnect:
            return HandleTreeDisconnect(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        case SmbProtocol::Command::LogoffAndX:
            return HandleLogoffAndX(
                clientSocket,
                smbBuffer,
                smbLength,
                header);

        default:
            printf(
                "Comando SMB aun no implementado: 0x%02X\n",
                header.command);

            return false;
        }
    }

    int CreateListenSocket()
    {
        int listenSocket = socket(
            AF_INET,
            SOCK_STREAM,
            IPPROTO_IP);

        if (listenSocket < 0)
        {
            printf(
                "Error creando socket SMB: errno=%d\n",
                errno);

            return -1;
        }

        int enable = 1;

        setsockopt(
            listenSocket,
            SOL_SOCKET,
            SO_REUSEADDR,
            &enable,
            sizeof(enable));

        sockaddr_in serverAddress{};

        serverAddress.sin_family = AF_INET;

        serverAddress.sin_port =
            htons(SmbConstants::PORT);

        serverAddress.sin_addr.s_addr =
            htonl(INADDR_ANY);

        if (bind(
                listenSocket,
                reinterpret_cast<sockaddr *>(
                    &serverAddress),
                sizeof(serverAddress)) != 0)
        {
            printf(
                "Error bind SMB: errno=%d\n",
                errno);

            close(listenSocket);
            return -1;
        }

        if (listen(
                listenSocket,
                SmbConstants::LISTEN_BACKLOG) != 0)
        {
            printf(
                "Error listen SMB: errno=%d\n",
                errno);

            close(listenSocket);
            return -1;
        }

        printf(
            "Servidor SMB escuchando en puerto %u\n",
            SmbConstants::PORT);

        return listenSocket;
    }

    void ConfigureClientSocket(int clientSocket)
    {
        int noDelay = 1;

        setsockopt(
            clientSocket,
            IPPROTO_TCP,
            TCP_NODELAY,
            &noDelay,
            sizeof(noDelay));
    }

    void HandleClient(
        int clientSocket,
        const sockaddr_in &clientAddress)
    {
        ConfigureClientSocket(clientSocket);
        readPerformance = ReadPerformance{};
        readConnectionDiagnostics = ReadConnectionDiagnostics{};
        readConnectionDiagnostics.connectedAtUs = esp_timer_get_time();
        recentReadWriteIndex = 0;
        recentReadUsed = 0;

        char clientIp[INET_ADDRSTRLEN]{};

        inet_ntoa_r(
            clientAddress.sin_addr,
            clientIp,
            sizeof(clientIp));

        printf(
            "Cliente SMB conectado: %s:%u\n",
            clientIp,
            ntohs(clientAddress.sin_port));

        // Diagnostico: comprobar si OPL manda otra solicitud tras OPEN_ANDX.
        bool waitingForFirstRequestAfterOpenAndX = false;
        bool idleWarningPrinted = false;

        while (true)
        {
            // select() no consume datos TCP: solo comprueba si hay datos
            // antes de entrar en recv() (que puede bloquear indefinidamente).
            if (waitingForFirstRequestAfterOpenAndX ||
                readConnectionDiagnostics.readRequests > 0)
            {
                fd_set readSet;
                FD_ZERO(&readSet);
                FD_SET(clientSocket, &readSet);

                timeval timeout{};
                timeout.tv_sec = 10;

                const int ready = select(
                    clientSocket + 1, &readSet, nullptr, nullptr, &timeout);

                if (ready == 0)
                {
                    if (readConnectionDiagnostics.readRequests > 0)
                    {
                        // Una unica advertencia por periodo de inactividad.
                        if (!idleWarningPrinted)
                        {
                            const auto &diag = readConnectionDiagnostics;
                            const int64_t inactiveMs = diag.lastReadAtUs > 0
                                ? (esp_timer_get_time() - diag.lastReadAtUs) / 1000
                                : -1;

                            printf("SMB DIAG IDLE: 10s sin datos TCP; "
                                   "READ=%lu bytes=%llu ultimoOffset=%llu "
                                   "ultimoFin=%llu sinLeer=%lldms; socket abierto\n",
                                   static_cast<unsigned long>(diag.readRequests),
                                   static_cast<unsigned long long>(diag.bytesSent),
                                   static_cast<unsigned long long>(diag.lastOffset),
                                   static_cast<unsigned long long>(diag.lastReadEndOffset),
                                   static_cast<long long>(inactiveMs));
                            PrintRecentReads();
                            idleWarningPrinted = true;
                        }
                    }
                    else
                    {
                        printf("SMB DIAG: 10s sin nuevo paquete TCP tras OPEN_ANDX; socket abierto\n");
                    }
                    continue;
                }

                if (ready < 0)
                {
                    printf("SMB DIAG: select fallo, errno=%d\n", errno);
                    break;
                }
            }

            uint8_t *smbBuffer = nullptr;
            size_t smbLength = 0;

            if (!ReceiveSmbPacket(
                    clientSocket,
                    smbBuffer,
                    smbLength))
            {
                printf(
                    "Conexion SMB finalizada o error de recepcion\n");

                break;
            }

            idleWarningPrinted = false;

            const SmbProtocol::Header *header =
                nullptr;

            if (!ParseSmb1Packet(
                    smbBuffer,
                    smbLength,
                    header))
            {
                printf(
                    "No fue posible parsear paquete SMB1\n");

                free(smbBuffer);
                break;
            }

            // READ_ANDX se resume cada cinco segundos en SMB PERF.
            if (header->command != 0x2E)
            {
                printf(
                    "SMB1 recibido: comando=0x%02X, longitud=%zu, TID=%u, UID=%u, MID=%u\n",
                    header->command,
                    smbLength,
                    header->treeId,
                    header->userId,
                    header->multiplexId);
            }

            const uint8_t command = header->command;
            const bool keepConnection =
                HandleSmbCommand(
                    clientSocket,
                    smbBuffer,
                    smbLength,
                    *header);

            if (keepConnection)
            {
                if (command == 0x2D) // SMB_COM_OPEN_ANDX
                {
                    waitingForFirstRequestAfterOpenAndX = true;
                }
                else if (waitingForFirstRequestAfterOpenAndX)
                {
                    printf("SMB DIAG: siguiente comando tras OPEN_ANDX = 0x%02X\n", command);
                    waitingForFirstRequestAfterOpenAndX = false;
                }
            }

            free(smbBuffer);

            if (!keepConnection)
            {
                break;
            }
        }

        PrintConnectionReadSummary();
        CloseAllOpenFiles();
        ResetSearchContext();

        shutdown(
            clientSocket,
            SHUT_RDWR);

        close(clientSocket);

        printf(
            "Cliente SMB desconectado\n");
    }

    void ServerTask(void *)
    {
        const int listenSocket =
            CreateListenSocket();

        if (listenSocket < 0)
        {
            vTaskDelete(nullptr);
            return;
        }

        while (true)
        {
            printf(
                "Esperando cliente SMB...\n");

            sockaddr_in clientAddress{};

            socklen_t clientAddressLength =
                sizeof(clientAddress);

            const int clientSocket =
                accept(
                    listenSocket,
                    reinterpret_cast<sockaddr *>(
                        &clientAddress),
                    &clientAddressLength);

            if (clientSocket < 0)
            {
                printf(
                    "Error accept SMB: errno=%d\n",
                    errno);

                continue;
            }

            HandleClient(
                clientSocket,
                clientAddress);
        }
    }
}

namespace SmbServer
{
    bool Start()
    {
        const BaseType_t result =
            xTaskCreate(
                ServerTask,
                SmbConstants::Task::NAME,
                SmbConstants::Task::STACK_SIZE,
                nullptr,
                SmbConstants::Task::PRIORITY,
                nullptr);

        if (result != pdPASS)
        {
            printf(
                "No fue posible crear tarea SMB\n");

            return false;
        }

        return true;
    }
}

#pragma once

#include <cstddef>
#include <cstdint>

#include "driver/gpio.h"
#include "driver/spi_master.h"

#include "freertos/FreeRTOS.h"

namespace NetworkConstants
{
    namespace Ethernet
    {
        namespace Pins
        {
            constexpr gpio_num_t SCK = GPIO_NUM_5;
            constexpr gpio_num_t MOSI = GPIO_NUM_6;
            constexpr gpio_num_t MISO = GPIO_NUM_7;
            constexpr gpio_num_t CS = GPIO_NUM_8;
            constexpr gpio_num_t RESET = GPIO_NUM_9;
            constexpr gpio_num_t INTERRUPT = GPIO_NUM_10;
        }

        namespace Spi
        {
            constexpr spi_host_device_t HOST = SPI2_HOST;

            constexpr int CLOCK_SPEED_HZ =
                40 * 1000 * 1000;

            constexpr int QUEUE_SIZE = 16;

            constexpr int MAX_TRANSFER_SIZE = 4096;
        }

        namespace Mac
        {
            constexpr int RX_TASK_STACK_SIZE = 4096;

            constexpr uint8_t LOCALLY_ADMINISTERED_BIT = 0x02;
            constexpr uint8_t MULTICAST_BIT_MASK = 0xFE;
        }

        namespace Ip
        {
            constexpr uint8_t ADDRESS_1 = 169;
            constexpr uint8_t ADDRESS_2 = 254;
            constexpr uint8_t ADDRESS_3 = 72;
            constexpr uint8_t ADDRESS_4 = 77;

            constexpr uint8_t MASK_1 = 255;
            constexpr uint8_t MASK_2 = 255;
            constexpr uint8_t MASK_3 = 0;
            constexpr uint8_t MASK_4 = 0;

            constexpr uint8_t GATEWAY_1 = 0;
            constexpr uint8_t GATEWAY_2 = 0;
            constexpr uint8_t GATEWAY_3 = 0;
            constexpr uint8_t GATEWAY_4 = 0;
        }
    }

    namespace Tcp
    {
        constexpr uint16_t PORT = 5000;

        constexpr int LISTEN_BACKLOG = 1;

        constexpr size_t FILE_BUFFER_SIZE =
            32 * 1024;

        constexpr size_t REQUEST_BUFFER_SIZE =
            512;

        constexpr size_t FILE_PATH_BUFFER_SIZE =
            512;

        constexpr size_t HEADER_BUFFER_SIZE =
            96;

        namespace Task
        {
            constexpr const char *NAME =
                "tcp_server";

            constexpr uint32_t STACK_SIZE =
                6144;

            constexpr UBaseType_t PRIORITY =
                5;
        }

        namespace Benchmark
        {
            constexpr uint8_t DATA_PATTERN =
                0xA5;
        }

        namespace Protocol
        {
            enum class Command
            {
                Get,
                GetFirstIso,
                Bench,
                Unknown
            };

            constexpr const char *GET_COMMAND =
                "GET ";

            constexpr size_t GET_COMMAND_LENGTH =
                sizeof(GET_COMMAND) - 1;

            constexpr const char *GET_FIRST_ISO_COMMAND =
                "GETFIRSTISO";

            constexpr const char *BENCH_COMMAND =
                "BENCH ";

            constexpr size_t BENCH_COMMAND_LENGTH =
                sizeof(BENCH_COMMAND) - 1;

            constexpr const char *FILE_HEADER_FORMAT =
                "SIZE %llu\nTYPE %s\nNAME %s\n";

            constexpr const char *BENCH_HEADER_FORMAT =
                "SIZE %llu\nTYPE BENCH\n";

            constexpr const char *ERROR_SD_NOT_MOUNTED =
                "ERROR SD_NOT_MOUNTED\n";

            constexpr const char *ERROR_INVALID_PATH =
                "ERROR INVALID_PATH\n";

            constexpr const char *ERROR_FILE_NOT_FOUND =
                "ERROR FILE_NOT_FOUND\n";

            constexpr const char *ERROR_OPEN_FILE =
                "ERROR OPEN_FILE\n";

            constexpr const char *ERROR_INVALID_BENCH_SIZE =
                "ERROR INVALID_BENCH_SIZE\n";

            constexpr const char *ERROR_UNKNOWN_COMMAND =
                "ERROR UNKNOWN_COMMAND\n";

            constexpr const char *TYPE_ISO =
                "ISO";

            constexpr const char *TYPE_AUDIO =
                "AUDIO";

            constexpr const char *TYPE_VIDEO =
                "VIDEO";

            constexpr const char *TYPE_OTHER =
                "OTHER";

            constexpr const char *TYPE_BENCH =
                "BENCH";
        }
    }
}
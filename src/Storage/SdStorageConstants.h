#pragma once

#include <cstddef>

#include "driver/gpio.h"
#include "freertos/FreeRTOS.h"

namespace SdStorageConstants
{
    namespace Pins
    {
        constexpr gpio_num_t CLK = GPIO_NUM_12;
        constexpr gpio_num_t CMD = GPIO_NUM_11;

        constexpr gpio_num_t D0 = GPIO_NUM_13;
        constexpr gpio_num_t D1 = GPIO_NUM_14;
        constexpr gpio_num_t D2 = GPIO_NUM_15;
        constexpr gpio_num_t D3 = GPIO_NUM_16;

        constexpr gpio_num_t DETECT = GPIO_NUM_18;
        constexpr int INSERTED_LEVEL = 1;
    }

    namespace Paths
    {
        constexpr const char *MOUNT_POINT = "/sdcard";

        constexpr const char *DVD_DIRECTORY = "/sdcard/DVD";
        constexpr const char *CD_DIRECTORY = "/sdcard/CD";

        constexpr const char *VMC_DIRECTORY = "/sdcard/VMC";
        constexpr const char *CFG_DIRECTORY = "/sdcard/CFG";
        constexpr const char *ART_DIRECTORY = "/sdcard/ART";
        constexpr const char *THM_DIRECTORY = "/sdcard/THM";
        constexpr const char *LNG_DIRECTORY = "/sdcard/LNG";
        constexpr const char *CHT_DIRECTORY = "/sdcard/CHT";
        constexpr const char *APPS_DIRECTORY = "/sdcard/APPS";

        constexpr const char* BENCHMARK_FILE = "/sdcard/benchmark.bin";
    }

    namespace Mount
    {
        constexpr int BUS_WIDTH = 4;
        constexpr size_t MAX_OPEN_FILES = 5;
        constexpr size_t ALLOCATION_UNIT_SIZE = 16 * 1024;
    }

    namespace Benchmark
    {
        constexpr size_t BUFFER_SIZE = 64 * 1024;
    }

    namespace Monitor
    {
        constexpr uint32_t DEBOUNCE_MS = 200;
        constexpr uint32_t MOUNT_DELAY_MS = 500;
        constexpr uint32_t POLLING_INTERVAL_MS = 250;

        constexpr uint32_t TASK_STACK_SIZE = 4096;
        constexpr UBaseType_t TASK_PRIORITY = 5;

        constexpr const char *TASK_NAME = "sd_monitor";
    }
}
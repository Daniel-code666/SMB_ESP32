#pragma once

#include <cstddef>

namespace SystemInfoConstants
{
    constexpr const char* HEADER = "\n=== SYSTEM INFO ===\n";
    constexpr const char* FOOTER = "===================\n\n";

    constexpr const char* CHIP_NAME = "ESP32-S3";

    constexpr std::size_t BYTES_PER_KB = 1024;
    constexpr std::size_t BYTES_PER_MB = 1024 * 1024;
}
#pragma once
#include <cstdint>

namespace SdStorage
{
    bool Init();
    bool StartMonitor();
    bool IsMounted();
    bool GetFileSize(const char *path, uint64_t &fileSize);
    bool ListIsoFiles();
    bool GetFirstIsoPath(char* outputPath, size_t outputPathSize);
}
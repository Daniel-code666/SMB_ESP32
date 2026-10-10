#pragma once

#include "sdmmc_cmd.h"

namespace SdStorageInternal
{
    extern sdmmc_card_t* card;
    extern bool mounted;

    bool Unmount();
}
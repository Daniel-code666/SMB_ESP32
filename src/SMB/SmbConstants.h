#pragma once

#include <cstddef>
#include <cstdint>

#include "freertos/FreeRTOS.h"

namespace SmbConstants
{
    constexpr uint16_t PORT = 445;
    constexpr int LISTEN_BACKLOG = 1;

    namespace Task
    {
        constexpr const char *NAME = "smb_server";
        constexpr uint32_t STACK_SIZE = 8192;
        constexpr UBaseType_t PRIORITY = 5;
    }

    namespace Buffer
    {
        constexpr size_t RECEIVE_SIZE = 64 * 1024;
        constexpr size_t SEND_SIZE = 64 * 1024;
        constexpr size_t READ_SIZE = 32 * 1024;

        constexpr size_t PATH_SIZE = 512;
        constexpr size_t SHARE_NAME_SIZE = 32;
        constexpr size_t USER_NAME_SIZE = 32;
    }

    namespace Share
    {
        constexpr const char *NAME = "PS2SMB";
        constexpr const char *ROOT = "/sdcard";

        constexpr const char *DVD_DIRECTORY = "DVD";
        constexpr const char *CD_DIRECTORY = "CD";
        constexpr const char *VMC_DIRECTORY = "VMC";
        constexpr const char *CFG_DIRECTORY = "CFG";
        constexpr const char *ART_DIRECTORY = "ART";
        constexpr const char *THM_DIRECTORY = "THM";
        constexpr const char *LNG_DIRECTORY = "LNG";
        constexpr const char *CHT_DIRECTORY = "CHT";
        constexpr const char *APPS_DIRECTORY = "APPS";
    }

    namespace Authentication
    {
        constexpr const char *USERNAME = "guest";
        constexpr const char *PASSWORD = "";

        constexpr bool ALLOW_GUEST = true;
    }

    namespace Negotiate
    {
        constexpr const char *DIALECT = "NT LM 0.12";

        constexpr uint16_t MAX_MPX_COUNT = 1;
        constexpr uint16_t MAX_NUMBER_VCS = 1;

        constexpr uint32_t MAX_BUFFER_SIZE = 65535;
        constexpr uint32_t MAX_RAW_SIZE = 65535;

        constexpr uint32_t SESSION_KEY = 0;

        constexpr uint8_t CHALLENGE_LENGTH = 8;

        constexpr int16_t SERVER_TIME_ZONE = 0;

        constexpr uint32_t SERVER_TIME_LOW = 0;
        constexpr uint32_t SERVER_TIME_HIGH = 0;
    }

    namespace Session
    {
        constexpr uint16_t DEFAULT_UID = 1;
        constexpr uint16_t DEFAULT_TID = 1;

        constexpr uint16_t MAX_SESSIONS = 1;
        constexpr uint16_t MAX_TREE_CONNECTIONS = 1;
    }

    namespace Files
    {
        constexpr uint16_t FIRST_FILE_ID = 1;
        constexpr size_t MAX_OPEN_FILES = 4;

        constexpr uint32_t MAX_READ_SIZE = 32 * 1024;
    }

    namespace DirectTcp
    {
        constexpr size_t HEADER_SIZE = 4;
        constexpr uint8_t SESSION_MESSAGE = 0x00;

        constexpr uint32_t MAX_MESSAGE_SIZE =
            Buffer::RECEIVE_SIZE;
    }

    namespace Limits
    {
        constexpr size_t MAX_DIALECTS = 16;
        constexpr size_t MAX_DIALECT_LENGTH = 64;

        constexpr size_t MAX_PATH_LENGTH =
            Buffer::PATH_SIZE;

        constexpr size_t MAX_SHARE_NAME_LENGTH =
            Buffer::SHARE_NAME_SIZE;

        constexpr size_t MAX_USER_NAME_LENGTH =
            Buffer::USER_NAME_SIZE;
    }
}
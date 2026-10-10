#include "SdStorage.h"
#include "SdStorageInternal.h"
#include "SdStorageConstants.h"

#include <cstdio>

#include "esp_err.h"

#include "driver/gpio.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace
{
    TaskHandle_t monitorTaskHandle = nullptr;

    bool IsCardInserted()
    {
        return gpio_get_level(
            SdStorageConstants::Pins::DETECT
        ) == SdStorageConstants::Pins::INSERTED_LEVEL;
    }

    void MonitorTask(void*)
    {
        bool previousInserted =
            IsCardInserted();

        printf("Monitor SD iniciado\n");

        printf(
            "Estado inicial: %s\n",
            previousInserted
                ? "tarjeta insertada"
                : "sin tarjeta"
        );

        if (
            previousInserted &&
            !SdStorage::IsMounted()
        )
        {
            printf(
                "Tarjeta presente al iniciar monitor\n"
            );

            vTaskDelay(
                pdMS_TO_TICKS(
                    SdStorageConstants::Monitor::MOUNT_DELAY_MS
                )
            );

            if (SdStorage::Init())
            {
                SdStorage::ListIsoFiles();
            }
        }

        while (true)
        {
            const bool inserted =
                IsCardInserted();

            if (inserted != previousInserted)
            {
                vTaskDelay(
                    pdMS_TO_TICKS(
                        SdStorageConstants::Monitor::DEBOUNCE_MS
                    )
                );

                const bool confirmedInserted =
                    IsCardInserted();

                if (
                    confirmedInserted !=
                    previousInserted
                )
                {
                    if (confirmedInserted)
                    {
                        printf(
                            "\nMicroSD insertada\n"
                        );

                        vTaskDelay(
                            pdMS_TO_TICKS(
                                SdStorageConstants::Monitor::MOUNT_DELAY_MS
                            )
                        );

                        if (SdStorage::Init())
                        {
                            SdStorage::ListIsoFiles();
                        }
                    }
                    else
                    {
                        printf(
                            "\nMicroSD retirada\n"
                        );

                        SdStorageInternal::Unmount();
                    }

                    previousInserted =
                        confirmedInserted;
                }
            }

            vTaskDelay(
                pdMS_TO_TICKS(
                    SdStorageConstants::Monitor::POLLING_INTERVAL_MS
                )
            );
        }
    }
}

namespace SdStorage
{
    bool StartMonitor()
    {
        if (monitorTaskHandle != nullptr)
        {
            printf(
                "Monitor SD ya se encuentra iniciado\n"
            );

            return true;
        }

        gpio_config_t detectConfig{};

        detectConfig.pin_bit_mask =
            1ULL <<
            SdStorageConstants::Pins::DETECT;

        detectConfig.mode =
            GPIO_MODE_INPUT;

        detectConfig.pull_up_en =
            GPIO_PULLUP_ENABLE;

        detectConfig.pull_down_en =
            GPIO_PULLDOWN_DISABLE;

        detectConfig.intr_type =
            GPIO_INTR_DISABLE;

        const esp_err_t result =
            gpio_config(
                &detectConfig
            );

        if (result != ESP_OK)
        {
            printf(
                "Error configurando SD DET: %s\n",
                esp_err_to_name(result)
            );

            return false;
        }

        const BaseType_t taskResult =
            xTaskCreate(
                MonitorTask,
                SdStorageConstants::Monitor::TASK_NAME,
                SdStorageConstants::Monitor::TASK_STACK_SIZE,
                nullptr,
                SdStorageConstants::Monitor::TASK_PRIORITY,
                &monitorTaskHandle
            );

        if (taskResult != pdPASS)
        {
            monitorTaskHandle = nullptr;

            printf(
                "No fue posible crear tarea de monitoreo SD\n"
            );

            return false;
        }

        printf(
            "Tarea de monitoreo SD creada\n"
        );

        return true;
    }
}
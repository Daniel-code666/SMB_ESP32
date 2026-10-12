# Perfil automático de la microSD

Este diagnóstico compara distintas agrupaciones de lectura SDMMC sin usar
Linux, sin escribir en la microSD y sin cambiar el modo utilizado por SMB.

## Preparación

1. Grabe el firmware actual en el ESP32.
2. Deje insertada la microSD que contiene los juegos.
3. Apague o desconecte la PS2 y espere `Cliente SMB desconectado`.
4. Abra el capturador serial:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\capture_metrics_serial.ps1
```

5. Pulse `B`. También puede escribir manualmente `SD PROFILE`.

El comando primero muestra `SD_PROFILE_QUEUED` y ejecuta el trabajo en una
tarea temporal independiente de la consola de métricas. La captura empieza al
aparecer `SD_PROFILE_BEGIN` y el archivo se crea al recibir `SD_PROFILE_END`.

## Qué hace

- Selecciona el primer ISO encontrado en `DVD` o `CD`.
- Lee el mismo tramo de 4 MiB desde el offset de 1 MiB.
- Usa operaciones FatFs de 8 KiB.
- Compara agrupaciones de 1, 2, 4, 8 y 16 sectores SDMMC.
- Calcula rendimiento, P50, P95, P99, máximo y CRC32.
- No escribe datos ni activa una agrupación experimental para el juego.
- Restaura la lectura de un sector incluso si una prueba falla.
- Reserva temporalmente 12 KiB de pila para la tarea del perfil; se liberan al
  terminar. `stack_free_min` en `SD_PROFILE_END` indica el margen mínimo que
  quedó disponible durante la prueba.

La salida queda guardada automáticamente en:

```text
C:\Users\Administrador\OneDrive\Documentos\Documentos\Things\Proyecto SMB\DUMP\sd-profile.txt
```

Cada modalidad genera una línea `SD_PROFILE_RESULT`. `valid=1` requiere lectura
completa, cero errores y el mismo CRC32 que la referencia de un sector.

## Seguridad

No ejecute el perfil mientras exista una conexión SMB. El firmware rechazará el
comando con `SD_PROFILE_ERROR SMB_ACTIVE`. Si una modalidad multibloque genera
un error SDMMC, espere `SD_PROFILE_END` y reinicie el ESP32 antes de volver a
usar la PS2, aunque el modo de un sector se restaure automáticamente.

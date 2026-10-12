# Captura de métricas SMB para OPL

El firmware guarda las métricas en RAM. No escribe la traza en la microSD y no
imprime un mensaje por cada lectura SMB.

## Guía rápida de captura

### 1. Abrir el capturador

Conecte el ESP32 al PC por USB y ejecute el capturador antes de comenzar la
prueba. Si solo hay un puerto serie, se seleccionará automáticamente:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\capture_metrics_serial.ps1
```

Para indicar el puerto explícitamente:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\capture_metrics_serial.ps1 -Port COM3
```

Para consultar los puertos disponibles:

```powershell
[System.IO.Ports.SerialPort]::GetPortNames()
```

### 2. Comprobar la comunicación

Pulse `I`. Deben aparecer dos líneas similares a estas:

```text
-> METRICS INFO
METRICS_INFO active=1 count=... reads=... bytes=...
```

Si únicamente aparece `-> METRICS INFO`, el ESP no está recibiendo los comandos
o no tiene grabado el firmware con el receptor UART corregido.

### 3. Capturar una cinemática de cualquier juego

Los marcadores no dependen del nombre del juego. Repita esta secuencia para
God of War, Marvel o cualquier otra ISO:

1. Pulse `C` justo cuando comience la cinemática. Esta tecla borra la captura
   anterior, inicia una nueva y añade `CINEMATIC_START`.
2. Pulse `T` cada vez que observe un tirón. Puede pulsarla varias veces.
3. Pulse `E` al terminar la cinemática. Añade `CINEMATIC_END` y congela las
   métricas automáticamente.
4. Apague o reinicie la PS2, o desconecte su enlace Ethernet.
5. Espere el mensaje `Cliente SMB desconectado`.
6. Pulse `D` y espere hasta que aparezca `Captura guardada`.

Todo evento SMB registrado entre `CINEMATIC_START` y `CINEMATIC_END` pertenece
al intervalo observado. El analizador calcula un resumen específico para ese
intervalo. Los marcadores indican lo que se vio en pantalla; por sí solos no
atribuyen el stutter al servidor.

### 4. Capturar el arranque completo de cualquier juego

1. Pulse `S` antes de iniciar el juego.
2. Pulse `L` al comenzar la carga.
3. Opcionalmente pulse `V` en cada transición de color. Genera, en orden:
   magenta 1, verde, magenta 2 y amarillo.
4. Pulse `R` cuando el juego comience a ejecutarse.
5. Pulse `F` para congelar las métricas.
6. Cierre la conexión SMB, espere `Cliente SMB desconectado` y pulse `D`.

## Tabla completa de teclas

| Tecla | Comando enviado | Uso |
|---|---|---|
| `I` | `METRICS INFO` | Mostrar estado y comprobar comunicación. |
| `S` | `METRICS START` | Borrar la captura anterior e iniciar una nueva. |
| `F` | `METRICS FREEZE` | Congelar las métricas sin detener SMB. |
| `D` | `METRICS DUMP` | Descargar la captura; solo con SMB desconectado. |
| `L` | `MARK GAME_LOAD_START` | Inicio de carga de cualquier juego. |
| `V` | Siguiente pantalla | Magenta 1, verde, magenta 2 y amarillo, en ese orden. |
| `R` | `MARK GAME_RUNNING` | El juego comenzó a ejecutarse. |
| `C` | `METRICS START` + `MARK CINEMATIC_START` | Limpiar e iniciar una captura de cinemática. |
| `T` | `MARK CINEMATIC_STUTTER` | Tirón visible; puede pulsarse varias veces. |
| `E` | `MARK CINEMATIC_END` + `METRICS FREEZE` | Cerrar y congelar la captura de cinemática. |
| `P` | `MARK GAMEPLAY` | Marcar una sección de gameplay normal. |
| `B` | `SD PROFILE` | Ejecutar el perfil SD de solo lectura con SMB desconectado. |
| `H` | Ayuda | Volver a mostrar las teclas. |
| `Q` | Salir | Cerrar el capturador serial. |

## Advertencia importante sobre `D`

No pulse `D` mientras la PS2 esté conectada al servidor SMB. La descarga UART es
larga y puede interferir con las lecturas del juego. El firmware actual rechaza
el dump cuando detecta una conexión SMB activa:

```text
METRICS_ERROR SMB_ACTIVE use_F_then_disconnect_before_D
```

La secuencia segura siempre es:

```text
F -> apagar/reiniciar PS2 o desconectar Ethernet
  -> esperar "Cliente SMB desconectado"
  -> D
```

`F` solo congela los contadores y eventos. El servidor SMB continúa operando.

## Comandos que pueden escribirse manualmente

```text
METRICS INFO
METRICS START
METRICS FREEZE
METRICS DUMP
MARK GAME_LOAD_START
MARK SCREEN_MAGENTA_1
MARK SCREEN_GREEN
MARK SCREEN_MAGENTA_2
MARK SCREEN_YELLOW
MARK GAME_RUNNING
MARK CINEMATIC_START
MARK CINEMATIC_STUTTER
MARK CINEMATIC_END
MARK GAMEPLAY
SD PROFILE
```

Los nombres antiguos `MARVEL_*` y `GOW_*` siguen aceptándose únicamente para
mantener compatibilidad con capturas previas.

El uso y la interpretación del perfilador SD están documentados en
`SD_PROFILE.md`.

## Analizar el dump

El capturador guarda por defecto:

```text
C:\Users\Administrador\OneDrive\Documentos\Documentos\Things\Proyecto SMB\DUMP\smb-metrics.bin
```

Ejecute:

```powershell
python .\tools\decode_trace.py `
  "C:\Users\Administrador\OneDrive\Documentos\Documentos\Things\Proyecto SMB\DUMP\smb-metrics.bin" `
  -o "C:\Users\Administrador\OneDrive\Documentos\Documentos\Things\Proyecto SMB\DUMP\smb-metrics.csv"
```

Archivos generados:

| Archivo | Contenido |
|---|---|
| `smb-metrics.csv` | Línea temporal de operaciones, conexiones y marcadores. |
| `smb-metrics-slow.csv` | Operaciones y fases lentas. |
| `smb-metrics-throughput.csv` | Rendimiento en ventanas de 100, 500 y 1000 ms. |
| `smb-metrics-report.txt` | Contadores, tiempos, errores, percentiles y resumen del intervalo de cinemática. |

## Memoria utilizada por la instrumentación

- Buffer circular: 4096 eventos × 40 bytes = 163840 bytes de PSRAM.
- Eventos lentos: 64 × 40 bytes = 2560 bytes de PSRAM.
- Resumen e histogramas: menos de 1 KiB de RAM interna.
- Pila de la tarea serial: 4096 bytes.
- Buffer de recepción UART: 1024 bytes.

La caché activa de lectura anticipada volvió a 16 KiB después de descartar la
variante de 8 KiB como solución del stutter. Las versiones instrumentadas están
conservadas en:

- Perfilador SD actual y caché de 16 KiB: `reference/esp32-sdprofile-16k-1FFA58CF`.
- 8 KiB experimental: `reference/esp32-metrics-cache8k-08742B0B`.
- 16 KiB con marcadores genéricos: `reference/esp32-metrics-cache16k-2F669E93`.
- 64 KiB: `reference/esp32-metrics-cache64k-CA3EB30A`.

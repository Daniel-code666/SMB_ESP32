# Servidor SMB1 en ESP32-S3 para PS2 OPL

Servidor SMB1 experimental que permite a **Open PS2 Loader (OPL)** leer juegos
desde una microSD conectada a un ESP32-S3. La PS2 se comunica directamente por
Ethernet con un W5500, sin necesitar un PC, Linux, router ni servidor Samba
durante el uso normal.

El proyecto alcanzó su objetivo principal: OPL puede abrir las ISO, iniciar los
juegos y mantener el gameplay a una velocidad percibida como normal. La
limitación pendiente es el *stutter* durante cinemáticas, observado tanto en
vídeos pregrabados como en algunas secuencias renderizadas. Las pruebas indican
que no existe una corrección segura adicional dentro de la arquitectura actual.

## Estado del proyecto

**Prototipo funcional con limitaciones conocidas.**

Validado con OPL 4.42d y, entre otros, los siguientes juegos:

- Marvel Ultimate Alliance: inicia y el gameplay funciona correctamente.
- God of War: inicia y el gameplay funciona correctamente.
- Ambos presentan *stutter* durante cinemáticas.

El tiempo y el patrón de carga dependen del juego. Marvel mostró un arranque más
lento que God of War aun siendo una ISO menor, mientras que desde Samba en Linux
su arranque fue más rápido. Esto confirma que el tamaño de la ISO no basta para
predecir el rendimiento: también influyen el patrón de offsets, la frecuencia de
las solicitudes y la utilidad de la caché.

## Arquitectura

```text
┌─────────────┐  RJ45 directo  ┌─────────┐  SPI 40 MHz  ┌───────────┐  SDMMC 4-bit  ┌─────────┐
│ PS2 + OPL   │◄──────────────►│ W5500   │◄────────────►│ ESP32-S3  │◄─────────────►│ microSD │
│ SMB1 client │                │ Ethernet│               │ SMB server│                │ ISO     │
└─────────────┘                └─────────┘               └───────────┘                └─────────┘
```

El ESP32-S3 monta la microSD con FatFs, publica su raíz como el recurso SMB
`PS2SMB` y atiende a un único cliente en TCP 445. El W5500 trabaja mediante SPI
con DMA; la microSD utiliza el periférico SDMMC en bus de cuatro bits.

## Logros técnicos

- Implementación autónoma del subconjunto SMB1 que OPL necesita para negociar,
  conectarse, consultar rutas, abrir y leer archivos.
- Compatibilidad con el dialecto `NT LM 0.12`, sesión invitada y Direct TCP en
  el puerto 445.
- Lectura de ISO mayores de 2 GiB con offsets de 64 bits.
- Acceso directo PS2–ESP32-S3, sin un equipo intermedio durante el juego.
- Detección, montaje y desmontaje de la microSD.
- Caché *read-ahead* síncrona de 16 KiB.
- Reutilización de los buffers de recepción SMB y de respuesta `READ_ANDX`.
- Omisión de `f_lseek()` cuando la solicitud ya está cubierta por la caché.
- Envío TCP con `sendmsg()`, sin construir una copia contigua adicional, y
  `TCP_NODELAY` habilitado.
- Trazador binario en RAM, marcadores manuales, exportación a CSV y análisis de
  latencias para las campañas de diagnóstico.
- Firmware de juego separado de la instrumentación pesada: el trazador, la
  consola de métricas y el servidor TCP auxiliar están desactivados en la
  compilación estable.

## Hardware y conexiones

La asignación actual de GPIO es:

| Interfaz | Señal | GPIO ESP32-S3 |
|---|---|---:|
| W5500 | SCK | 5 |
| W5500 | MOSI | 6 |
| W5500 | MISO | 7 |
| W5500 | CS | 8 |
| W5500 | RESET | 9 |
| W5500 | INT | 10 |
| microSD SDMMC | CMD | 11 |
| microSD SDMMC | CLK | 12 |
| microSD SDMMC | D0 | 13 |
| microSD SDMMC | D1 | 14 |
| microSD SDMMC | D2 | 15 |
| microSD SDMMC | D3 | 16 |
| microSD | DETECT | 18 |

La alimentación depende del módulo W5500 y del adaptador microSD utilizados.
Debe respetarse la tensión admitida por cada placa y compartir tierra con el
ESP32-S3. Una alimentación insuficiente o ruidosa puede manifestarse como
reinicios, pérdidas del enlace Ethernet o errores de la tarjeta.

## Preparación de la microSD

OPL espera su estructura habitual en la raíz de la tarjeta:

```text
/
├── DVD/       # Juegos en DVD
├── CD/        # Juegos en CD
├── VMC/
├── CFG/
├── ART/
├── THM/
├── LNG/
├── CHT/
└── APPS/
```

Por ejemplo:

```text
/DVD/SLUS_213.74.Marvel Ultimate Alliance.iso
```

La tarjeta debe estar formateada con un sistema compatible con FatFs en esta
configuración. El firmware no formatea automáticamente una tarjeta cuyo montaje
falle.

## Configuración de red y OPL

El firmware usa una red estática y está pensado para un cable directo entre la
PS2 y el W5500:

| Parámetro | Valor |
|---|---|
| IP del servidor ESP32 | `169.254.72.77` |
| IP usada en la PS2 durante las pruebas | `169.254.72.78` |
| Máscara | `255.255.0.0` |
| Gateway | `0.0.0.0` |
| Puerto SMB | `445` |
| Recurso compartido | `PS2SMB` |
| Usuario | `guest` |
| Contraseña | vacía |

En OPL se deben introducir esos valores en la configuración de red/SMB y
seleccionar Ethernet como dispositivo de juegos. No se necesita un *switch* para
la operación normal; solo sería necesario para incorporar otro equipo a la red,
por ejemplo durante una captura externa.

## Compilación y carga

El proyecto utiliza PlatformIO con ESP-IDF:

- Plataforma: `espressif32 @ 7.0.1`
- Entorno: `esp32-s3-devkitc-1`
- Flash configurada: 16 MB
- Monitor serie: 115200 baudios

Compilar:

```powershell
platformio run
```

Cargar, reemplazando el puerto según el equipo:

```powershell
platformio run --target upload --upload-port COM5
```

Abrir el monitor serie:

```powershell
platformio device monitor --port COM5 --baud 115200
```

La última compilación conservada como referencia está en
[`reference/esp32-sync-optimized-C00A06C7`](reference/esp32-sync-optimized-C00A06C7).
Mantiene SDMMC en modo estable de un sector, caché síncrona de 16 KiB y no crea
una tarea de precarga.

## Subconjunto SMB implementado

El servidor no pretende ser una implementación general de Samba. Implementa las
operaciones requeridas por el flujo probado de OPL, entre ellas:

- `SMB_COM_NEGOTIATE`
- `SMB_COM_SESSION_SETUP_ANDX`
- `SMB_COM_TREE_CONNECT_ANDX`
- `SMB_COM_OPEN_ANDX`
- `SMB_COM_NT_CREATE_ANDX`
- `SMB_COM_READ_ANDX`
- `SMB_COM_CLOSE`
- `SMB_COM_TRANSACTION2` para consultas de ruta compatibles
- `SMB_COM_ECHO`
- creación de directorios, desconexión del árbol y cierre de sesión

La implementación es deliberadamente monocliente, con una sesión activa y un
máximo de cuatro archivos abiertos. Se acepta acceso invitado sin contraseña.

## Resultados del análisis de rendimiento

Las capturas instrumentadas permitieron separar varias hipótesis:

- Con caché de 64 KiB, un fallo de caché tenía una mediana cercana a 61 ms.
- Reducirla a 16 KiB bajó el P95 de los fallos a unos 17,3 ms.
- Con 8 KiB el P95 bajó a unos 10,3 ms, pero se duplicó aproximadamente la
  frecuencia de recarga y no mejoró la latencia media.
- Las capturas de 8 y 16 KiB mantuvieron aproximadamente 337–347 KiB/s de
  rendimiento SMB efectivo y el *stutter* siguió presente.
- Los primeros marcadores manuales de *stutter* no coincidieron con errores de
  FatFs, SDMMC o TCP; por tanto, no todos los tirones pueden atribuirse a una
  desconexión o lectura fallida.
- Activar el Modo 1 de OPL produjo una mejora visual parcial, pero no eliminó el
  problema.

El perfil aislado de la microSD mostró que agrupar sectores ofrece mucho más
rendimiento secuencial:

| Sectores por comando | Rendimiento medido |
|---:|---:|
| 1 | 1192,3 KiB/s |
| 2 | 2161,7 KiB/s |
| 4 | 3677,0 KiB/s |
| 8 | 6421,3 KiB/s |
| 16 | 9227,9 KiB/s |

Sin embargo, las lecturas multibloque fallaron durante el uso real en regiones
distintas de las ISO con errores SDMMC `0x107` y `0x109`. Un fallo podía dejar la
tarjeta o el controlador sin responder, por lo que el reintento inmediato y la
degradación a un sector no eran una recuperación segura. Esta optimización fue
retirada.

También se ensayó una segunda caché con precarga desde otra tarea. Aunque redujo
algo el *stutter*, produjo `ESP_ERR_TIMEOUT (0x107)` al alternar accesos SDMMC y
terminó desconectando la sesión. La precarga asíncrona está desactivada de forma
permanente en la versión de referencia.

## Limitaciones conocidas

- Las cinemáticas pueden reproducirse con audio/vídeo entrecortado y degradarse
  durante secuencias sostenidas.
- El gameplay de los títulos probados fue estable, pero esto no garantiza
  compatibilidad o rendimiento idéntico con todo el catálogo de PS2.
- La velocidad anunciada por Ethernet no representa el rendimiento útil: el
  recorrido incluye SMB1, TCP/lwIP, SPI hacia el W5500, copias de buffers, FatFs
  y SDMMC.
- La lectura SDMMC multibloque sería la mejora de mayor impacto teórico, pero no
  resultó estable con el hardware/controlador probado.
- Agregar concurrencia entre tareas para ocultar la latencia de lectura tampoco
  fue seguro con FatFs/SDMMC en esta implementación.
- El firmware no implementa SMB moderno, múltiples clientes, cifrado ni las
  funciones completas de un NAS.
- SMB1 no debe exponerse a Internet ni a una red que no sea de confianza.

En consecuencia, el límite observado no puede atribuirse únicamente a la CPU
del ESP32-S3. Es el resultado de la combinación completa: lectura estable de un
solo sector, FatFs/SDMMC, procesamiento SMB/TCP y transporte SPI mediante W5500.
Dentro de esas restricciones no se encontró una optimización adicional que
eliminara el *stutter* sin comprometer la estabilidad alcanzada.

## Diagnóstico y documentación adicional

- [`PERFORMANCE_AUDIT.md`](PERFORMANCE_AUDIT.md): evidencia, comparaciones de
  caché y experimentos descartados.
- [`METRICS.md`](METRICS.md): captura binaria, comandos UART, marcadores de
  cinemáticas y conversión a CSV.
- [`SD_PROFILE.md`](SD_PROFILE.md): uso y resultados del perfilador controlado de
  la microSD.
- [`tools/decode_trace.py`](tools/decode_trace.py): decodificación y generación
  del informe de una captura.
- [`tools/capture_metrics_serial.ps1`](tools/capture_metrics_serial.ps1): captura
  de métricas por UART en Windows.

La instrumentación detallada está desactivada por defecto mediante
`TraceBuffer::ENABLED = false`. Debe habilitarse únicamente para diagnósticos,
pues aumenta el consumo de RAM y no forma parte del firmware recomendado para
jugar.

## Organización del código

```text
src/
├── Diagnostics/  # Trazador y métricas en RAM
├── Network/      # W5500, red estática y servidor TCP auxiliar
├── SMB/          # Protocolo y servidor SMB1
├── Storage/      # SDMMC, FatFs, monitor y perfilador
└── System/       # Información del ESP32-S3
```

## Conclusión

El proyecto demuestra que un ESP32-S3 con W5500 y microSD puede reemplazar a un
servidor Samba para iniciar y ejecutar juegos de PS2 mediante OPL. Es una base
funcional y medible, no una sustitución de rendimiento equivalente a Samba en
Linux. Su principal logro es haber llevado el flujo completo —almacenamiento,
SMB1 y Ethernet— a un microcontrolador autónomo, identificando además con pruebas
repetibles dónde termina el margen seguro de optimización de esta arquitectura.

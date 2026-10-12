# Auditoría inicial de rendimiento (sin optimizaciones)

Este documento separa hechos demostrables en el código de hipótesis que necesitan una captura. No se modificó la lógica SMB, SDMMC ni las capacidades negociadas durante esta fase.

## Hechos observados en el código

- Cada `READ_ANDX` ejecuta `f_lseek()` antes de leer, incluso si el contenido solicitado ya está en la caché. La nueva métrica mide ese coste por separado.
- La lectura usa una caché anticipada de 64 KiB. En un fallo de caché se solicita a FatFs hasta 64 KiB; en un acierto se copia desde la caché. Se registran aciertos, fallos y patrón de offsets sin cambiar esa conducta.
- Se reserva y libera dinámicamente el buffer de respuesta de cada `READ_ANDX`.
- También se reserva y libera dinámicamente el buffer de cada solicitud SMB recibida.
- `SendSmbPacket()` usa `sendmsg()` con dos vectores para cabecera Direct TCP y cuerpo SMB; no crea una copia contigua adicional del paquete.
- El W5500 está configurado por SPI a 40 MHz, con DMA automático, cola de 16 y transferencia máxima declarada de 4096 bytes.
- `TCP_NODELAY` está activado para el socket SMB.
- La tarea SMB tiene prioridad FreeRTOS 5 y pila de 8192 bytes. El servidor auxiliar TCP también usa prioridad 5; la tarea de comandos de métricas usa prioridad 2.
- SDMMC se configura en modo high-speed y el juego conserva la lectura estable
  de un sector. Las lecturas agrupadas solo existen dentro del perfilador
  desconectado y nunca se activan automáticamente para SMB.
- El servidor SMB procesa una operación a la vez. `recv()`, `select()` y `sendmsg()` son llamadas potencialmente bloqueantes.

## Lo que las capturas podrán demostrar

- Si la demora de Marvel está dominada por tiempo activo del servidor o por intervalos sin solicitudes del cliente.
- Si Marvel genera más solicitudes por MiB, más saltos o más fallos de caché que God of War, independientemente del tamaño total del ISO.
- Si `f_lseek()`, `f_read()` o el envío TCP producen la cola larga de latencia P95/P99.
- Si el stutter de las cinemáticas de God of War coincide con caída de rendimiento, pausas SD/FatFs, envío bloqueado o ausencia de solicitudes del cliente.
- Si una cinemática fluida de Marvel presenta el mismo caudal pero menor jitter, lo cual la convierte en control útil.
- Si existen reconexiones, errores, lecturas parciales o múltiples llamadas `sendmsg()` para completar una respuesta.

## Hipótesis todavía no demostradas

- Fragmentación diferente de los ISO en FAT32.
- Patrón de acceso aleatorio de Marvel que reduzca la utilidad de la caché de 64 KiB.
- Pausas de SD/FatFs suficientes para vaciar el buffer audiovisual de God of War.
- Contrapresión TCP de la PS2 o límites del camino SPI/W5500.
- Coste significativo de las reservas dinámicas o de las copias de caché.
- Interferencia por prioridades o planificación de tareas FreeRTOS.

Estas hipótesis no deben convertirse en cambios hasta comparar las cuatro capturas descritas en `METRICS.md`.

## Primera captura real: cinemáticas con stutter

La captura `smb-metrics.bin` con CRC32 `D48778BE` contiene 17734 operaciones
`READ_ANDX` antes de congelarse:

- 0 errores FatFs, SDMMC o TCP antes del congelado.
- 0 lecturas o envíos TCP parciales.
- 16598 aciertos y 1136 fallos de la caché de 64 KiB.
- Mediana de operación con acierto: 2,27 ms.
- Mediana de operación con fallo: 60,99 ms.
- Los fallos aparecen aproximadamente cada 142 ms en los eventos recientes.
- Tiempo acumulado: `f_lseek` 3,14 s, `f_read` 66,49 s y envío 37,49 s.
- Envío TCP estable, sin parciales; mediana global próxima a 2 ms.

Por tanto queda demostrado un bloqueo periódico asociado al relleno síncrono de
64 KiB en `ReadFileCached`. Su impacto visual todavía debe confirmarse con mejores
marcadores, pero la frecuencia y duración son compatibles con stutter audiovisual
en distintos juegos. El error SDMMC `0x109` mostrado en consola ocurrió después de
congelar la captura, durante la descarga UART, y no aparece en los contadores del
período capturado. No debe atribuirse retroactivamente al stutter anterior.

## Prueba controlada de 16 KiB

Se reduce exclusivamente `READ_AHEAD_CACHE_SIZE` de 64 KiB a 16 KiB. La hipótesis
es reducir aproximadamente a una cuarta parte la duración de cada relleno, a
cambio de efectuar rellenos con mayor frecuencia. Se compararán latencia P95/P99,
rendimiento sostenido y percepción de las cinemáticas. La referencia de 64 KiB
queda preservada en `reference/esp32-metrics-cache64k-CA3EB30A`.

### Resultado observado con 16 KiB

La captura de una cinemática de Marvel registró 28,325 s útiles antes de una
desconexión por `FR_DISK_ERR`: 2736 READ_ANDX, 9.773.056 bytes entregados y
336,9 KiB/s efectivos. Los aciertos de caché promediaron 2,20 ms y los fallos
16,60 ms (P95 17,26 ms). Hubo 2047 aciertos y 689 fallos dentro del intervalo;
el stutter visual persistió. Los primeros 16 stutters marcados no tuvieron
errores FatFs, SD ni TCP asociados. El último coincidió con la lectura fallida
que cerró la conexión, por lo que ese evento final es distinto del stutter
recurrente.

Esto demuestra que reducir la pausa máxima respecto a 64 KiB no fue suficiente.
No demuestra todavía si una pausa aún menor puede beneficiar la reproducción.
La variante instrumentada de 16 KiB con marcadores genéricos queda preservada
en `reference/esp32-metrics-cache16k-2F669E93`.

## Prueba controlada de 8 KiB

Se cambia exclusivamente `READ_AHEAD_CACHE_SIZE` de 16 KiB a 8 KiB. Se espera
aproximadamente duplicar la frecuencia de recarga y reducir a la mitad su
duración. Deben compararse el stutter percibido, la latencia de los fallos de
caché, el rendimiento efectivo y cualquier error SD/FatFs. No se modifican SMB,
READ_ANDX, SDMMC ni la lectura sector por sector.

### Resultado observado con 8 KiB

La captura global conservó 7124 READ_ANDX y 25.530.368 bytes entregados durante
aproximadamente 71,843 s de actividad más gaps, equivalentes a 347,0 KiB/s. El
buffer reciente sobrescribió 3082 eventos y perdió `CINEMATIC_START`, pero los
contadores e histogramas globales permanecieron completos.

- Fallos de caché: 3550/7124 (49,83 %), frente a 25,2 % con 16 KiB.
- Fallo retenido: promedio 9,69 ms y P95 10,34 ms, frente a 16,60 ms y
  17,26 ms con 16 KiB.
- Acierto retenido: promedio 2,17 ms, prácticamente igual a 16 KiB.
- Latencia SMB global media: 5,93 ms, frente a 5,83 ms con 16 KiB.
- Rendimiento estimado: 347,0 KiB/s, frente a 336,9 KiB/s con 16 KiB.
- El stutter visual persistió.

El experimento confirma que 8 KiB reduce la cola de latencia, pero no resuelve
las cinemáticas y no mejora la latencia media. Por tanto, la duración aislada
del relleno de caché no parece ser la causa principal. La captura volvió a
terminar con un `FR_DISK_ERR` en una lectura de 4096 bytes y luego cerró SMB;
como la PS2 fue apagada en ese instante, la traza no permite establecer la
dirección causal, aunque un cierre Ethernet por sí solo no debería convertirse
en un error FatFs.

## Perfilador SD controlado

Tras descartar el tamaño de caché como causa principal, el firmware vuelve a
16 KiB e incorpora un perfil de solo lectura. El comando `SD PROFILE`, permitido
únicamente sin cliente SMB, compara en una sola ejecución agrupaciones de 1, 2,
4, 8 y 16 sectores sobre el mismo tramo del primer ISO. Valida CRC32, errores,
rendimiento y percentiles de operaciones FatFs de 8 KiB. El modo normal sigue
siendo un sector y se restaura automáticamente al finalizar. Ningún resultado
del perfil activa por sí mismo una optimización durante el juego.

### Resultado del perfil (2026-10-11)

Se leyó el mismo tramo de 4 MiB de `God of War.iso`, desde el offset de 1 MiB,
con operaciones FatFs de 8 KiB. Todas las modalidades terminaron completas,
sin errores SDMMC ni FatFs, y produjeron el mismo CRC32 `E8F0F442`.

| Sectores por comando | Comandos SD | Rendimiento | P50 `f_read` | P99 `f_read` | Máximo |
|---:|---:|---:|---:|---:|---:|
| 1 | 8192 | 1192,3 KiB/s | 6813 us | 7128 us | 8462 us |
| 2 | 4096 | 2161,7 KiB/s | 3762 us | 3920 us | 4488 us |
| 4 | 2048 | 3677,0 KiB/s | 2217 us | 2302 us | 2420 us |
| 8 | 1024 | 6421,3 KiB/s | 1260 us | 1323 us | 1561 us |
| 16 | 512 | 9227,9 KiB/s | 875 us | 918 us | 1199 us |

La agrupación de 16 sectores redujo un 93,75 % la cantidad de comandos y fue
7,74 veces más rápida que la lectura sector por sector en esta carga secuencial.
Esto demuestra un cuello de botella real en la modalidad de un sector y ofrece
una explicación técnicamente plausible para el stutter de vídeo. Aún no prueba
que 16 sectores sean estables en todos los offsets, archivos y duraciones: el
antecedente del error CRC `0x109` obliga a calificar el modo con una prueba más
amplia o a utilizar una estrategia con degradación segura antes de activarlo
durante el juego.

El perfil restauró correctamente el modo normal de un sector. La tarea temporal
de diagnóstico terminó con 9168 bytes de pila libres de un total de 12288.

### Experimento multibloque descartado

Se probó una variante que comenzaba con 16 sectores por comando y, ante un
error, reintentaba el bloque completo sector por sector antes de degradarse. En
la primera lectura de Marvel falló el sector físico 16785428 con `0x107`
(`ESP_ERR_TIMEOUT`). El propio comando de estado de la tarjeta también agotó su
tiempo y el reintento inmediato de un sector volvió a producir `0x107`.

Esto demuestra que un fallo multibloque puede dejar la tarjeta o el controlador
sin responder, por lo que un reintento local no constituye una recuperación
segura. Reinicializar SDMMC y remontar FatFs durante un `f_read()` invalidaría el
archivo abierto y la sesión SMB. La modalidad adaptativa queda retirada y no se
probarán tamaños 8, 4 o 2 durante el juego mediante ensayo y error.

El perfil desconectado había validado otra zona física perteneciente a God of
War; por tanto, su CRC correcto no demostraba estabilidad en todas las regiones
de la tarjeta. El firmware normal vuelve definitivamente a un sector por
comando. El binario se conserva en `reference/esp32-stable-sector1-0B493FA3`.

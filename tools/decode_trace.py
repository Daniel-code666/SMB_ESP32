#!/usr/bin/env python3
import argparse
import csv
import math
import statistics
import struct
import zlib
from collections import Counter
from pathlib import Path

EVENT = struct.Struct("<QQIiIHHHHBBBB")
HEADER = struct.Struct("<8sHHHHIIIIQQQII")
LATENCY = struct.Struct("<QQII24I")
SUMMARY_SCALARS = (
    "capture_started_us", "connections", "reconnections", "smb_operations",
    "read_requests", "requested_bytes", "delivered_bytes", "total_seek_us",
    "total_read_us", "total_send_us", "cache_hits", "cache_misses",
    "sequential_reads", "forward_jumps", "backward_jumps", "repeated_reads",
    "partial_reads", "tcp_partial_sends", "tcp_bytes_sent", "tcp_send_calls",
    "fatfs_errors", "tcp_errors",
    "sd_errors", "idle_over_100ms", "idle_over_500ms", "idle_over_1000ms",
    "ignored_while_frozen", "slow_events_seen", "slow_events_overwritten",
)
LATENCY_NAMES = ("smb", "seek", "read", "send", "client_gap")
SUMMARY_SIZE = len(SUMMARY_SCALARS) * 8 + len(LATENCY_NAMES) * LATENCY.size
EVENT_TYPES = {
    0: "NONE", 1: "SYSTEM", 2: "CONNECTION_OPEN", 3: "CONNECTION_CLOSE",
    4: "RECEIVE", 5: "SMB_REQUEST", 6: "SEEK", 7: "READ", 8: "SEND",
    9: "IDLE", 10: "LISTEN_PENDING", 11: "HEAP", 12: "ERROR",
    13: "SD_DETECT", 14: "ETHERNET_LINK", 15: "SMB_SERVER",
    16: "SMB_OPERATION", 17: "MARKER", 18: "FILE_OPEN", 19: "TCP_TRANSFER",
}
PHASES = {
    0: "IDLE", 1: "ACCEPT", 2: "WAIT_SOCKET", 3: "RECV_DIRECT_HEADER",
    4: "RECV_SMB_BODY", 5: "PARSE_REQUEST", 6: "DISPATCH", 7: "SEEK",
    8: "READ", 9: "BUILD_RESPONSE", 10: "SEND", 11: "CLOSE",
}
MARKERS = {
    1: "MARVEL_START", 2: "MARVEL_MAGENTA_1", 3: "MARVEL_GREEN",
    4: "MARVEL_MAGENTA_2", 5: "MARVEL_YELLOW", 6: "MARVEL_RUNNING",
    7: "MARVEL_CINEMATIC_START", 8: "MARVEL_CINEMATIC_END",
    16: "GOW_START", 17: "GOW_MAGENTA_1", 18: "GOW_GREEN",
    19: "GOW_MAGENTA_2", 20: "GOW_YELLOW", 21: "GOW_RUNNING",
    22: "GOW_CINEMATIC_START", 23: "GOW_STUTTER", 24: "GOW_CINEMATIC_END",
    32: "GAMEPLAY",
    33: "GAME_LOAD_START", 34: "SCREEN_MAGENTA_1", 35: "SCREEN_GREEN",
    36: "SCREEN_MAGENTA_2", 37: "SCREEN_YELLOW", 38: "GAME_RUNNING",
    39: "CINEMATIC_START", 40: "CINEMATIC_STUTTER", 41: "CINEMATIC_END",
}
FLAG_NAMES = (
    (1, "CACHE_HIT"), (2, "CACHE_MISS"), (4, "SEQUENTIAL"),
    (8, "FORWARD_JUMP"), (16, "BACKWARD_JUMP"), (32, "REPEATED"),
    (64, "PARTIAL"), (128, "ERROR"),
)


def unpack_event(data, offset=0):
    keys = ("timestamp_us", "file_offset", "duration_us", "result", "auxiliary",
            "connection_id", "mid", "fid", "size", "type", "command", "phase", "flags")
    return dict(zip(keys, EVENT.unpack_from(data, offset)))


def percentile(values, percent):
    if not values:
        return None
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percent / 100 * len(ordered)) - 1)]


def histogram_percentile(stats, percent):
    if not stats["count"]:
        return None
    target = math.ceil(stats["count"] * percent / 100)
    seen = 0
    for index, count in enumerate(stats["histogram"]):
        seen += count
        if seen >= target:
            return 0 if index == 0 else 2 ** (index + 1) - 1
    return 2 ** len(stats["histogram"])


def parse_summary(data, offset, size):
    if size != SUMMARY_SIZE:
        raise SystemExit(f"Tamaño de resumen no soportado: {size}, esperado={SUMMARY_SIZE}")
    values = struct.unpack_from(f"<{len(SUMMARY_SCALARS)}Q", data, offset)
    summary = dict(zip(SUMMARY_SCALARS, values))
    pos = offset + len(SUMMARY_SCALARS) * 8
    for name in LATENCY_NAMES:
        values = LATENCY.unpack_from(data, pos)
        summary[name] = {
            "count": values[0], "total_us": values[1], "minimum_us": values[2],
            "maximum_us": values[3], "histogram": values[4:],
        }
        pos += LATENCY.size
    return summary


def enrich(event, index, first_timestamp, collection):
    event["index"] = index
    event["collection"] = collection
    event["relative_ms"] = (event["timestamp_us"] - first_timestamp) / 1000.0
    event["type_name"] = EVENT_TYPES.get(event["type"], f"TYPE_{event['type']}")
    event["phase_name"] = PHASES.get(event["phase"], f"PHASE_{event['phase']}")
    event["command_hex"] = f"0x{event['command']:02X}"
    event["marker_name"] = MARKERS.get(event["command"], "") if event["type"] == 17 else ""
    event["flag_names"] = "|".join(name for bit, name in FLAG_NAMES if event["flags"] & bit)
    event["client_gap_us"] = event["auxiliary"] if event["type"] == 16 else ""
    event["requested_bytes"] = event["size"] if event["type"] == 16 and event["command"] == 0x2E else ""
    event["delivered_bytes"] = max(event["result"], 0) if event["type"] == 16 and event["command"] == 0x2E else ""
    event["path_hash"] = f"{event['auxiliary']:08X}" if event["type"] == 18 else ""
    return event


def write_csv(path, rows):
    columns = (
        "collection", "index", "relative_ms", "timestamp_us", "type_name", "phase_name",
        "marker_name", "connection_id", "command_hex", "mid", "fid", "file_offset",
        "requested_bytes", "delivered_bytes", "size", "duration_us", "client_gap_us",
        "result", "auxiliary", "flags", "flag_names", "path_hash",
    )
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader(); writer.writerows(rows)


def write_throughput(path, reads):
    with path.open("w", newline="", encoding="utf-8-sig") as stream:
        columns = ("window_ms", "start_ms", "end_ms", "requests", "bytes", "kib_per_s")
        writer = csv.DictWriter(stream, fieldnames=columns); writer.writeheader()
        if not reads:
            return
        origin = min(row["timestamp_us"] for row in reads)
        end = max(row["timestamp_us"] + row["duration_us"] for row in reads)
        for window_ms in (100, 500, 1000):
            window_us = window_ms * 1000
            buckets = {}
            for row in reads:
                bucket = (row["timestamp_us"] - origin) // window_us
                item = buckets.setdefault(bucket, [0, 0])
                item[0] += 1; item[1] += max(row["result"], 0)
            for bucket in range((end - origin) // window_us + 1):
                requests, byte_count = buckets.get(bucket, (0, 0))
                writer.writerow({
                    "window_ms": window_ms, "start_ms": bucket * window_ms,
                    "end_ms": (bucket + 1) * window_ms, "requests": requests,
                    "bytes": byte_count,
                    "kib_per_s": round(byte_count * 1000 / window_ms / 1024, 3),
                })


def write_report(path, header, summary, rows):
    operations = [r for r in rows if r["type"] == 16]
    markers = [r for r in rows if r["type"] == 17]
    wall_us = 0 if not operations else max(r["timestamp_us"] + r["duration_us"] for r in operations) - min(r["timestamp_us"] for r in operations)
    busy_us = sum(r["duration_us"] for r in operations)
    gaps_us = sum(r["auxiliary"] for r in operations)
    durations = [r["duration_us"] for r in operations]
    with path.open("w", encoding="utf-8") as out:
        p = lambda text="": print(text, file=out)
        p("INFORME DE MÉTRICAS SMB/OPL")
        p(f"Eventos recientes: {header['count']}/{header['capacity']}  sobrescritos: {header['overwritten']}")
        p(f"Eventos lentos conservados: {header['slow_count']}/{header['slow_capacity']}")
        p(f"Conexiones: {summary['connections']}  reconexiones: {summary['reconnections']}")
        p(f"Operaciones SMB: {summary['smb_operations']}  READ_ANDX: {summary['read_requests']}")
        p(f"Solicitados: {summary['requested_bytes']} bytes  entregados: {summary['delivered_bytes']} bytes")
        p(f"Tiempo observado entre operaciones retenidas: {wall_us/1e6:.3f} s")
        p(f"Tiempo activo SMB retenido: {busy_us/1e6:.3f} s")
        p(f"Gaps de cliente retenidos: {gaps_us/1e6:.3f} s")
        if wall_us: p(f"Fracción activa aproximada: {100*busy_us/wall_us:.1f}%")
        p(f"Totales internos READ: seek={summary['total_seek_us']/1e6:.3f}s read={summary['total_read_us']/1e6:.3f}s send={summary['total_send_us']/1e6:.3f}s")
        p(f"Caché: hits={summary['cache_hits']} misses={summary['cache_misses']}")
        p(f"Patrón: secuenciales={summary['sequential_reads']} adelante={summary['forward_jumps']} atrás={summary['backward_jumps']} repetidas={summary['repeated_reads']}")
        p(f"Parciales: read={summary['partial_reads']} tcp={summary['tcp_partial_sends']}")
        p(f"TCP enviado: {summary['tcp_bytes_sent']} bytes en {summary['tcp_send_calls']} llamadas sendmsg")
        p(f"Errores: FatFs={summary['fatfs_errors']} SD={summary['sd_errors']} TCP={summary['tcp_errors']}")
        p(f"Inactividad: >100ms={summary['idle_over_100ms']} >500ms={summary['idle_over_500ms']} >1000ms={summary['idle_over_1000ms']}")
        if durations:
            p("Latencia SMB exacta (eventos retenidos): " +
              f"promedio={statistics.mean(durations):.1f}us min={min(durations)}us max={max(durations)}us " +
              f"P50={percentile(durations,50)}us P95={percentile(durations,95)}us P99={percentile(durations,99)}us")
        for name in LATENCY_NAMES:
            stat = summary[name]
            avg = stat["total_us"] / stat["count"] if stat["count"] else 0
            p(f"{name}: n={stat['count']} promedio={avg:.1f}us min={stat['minimum_us']}us max={stat['maximum_us']}us " +
              f"P50≈{histogram_percentile(stat,50)}us P95≈{histogram_percentile(stat,95)}us P99≈{histogram_percentile(stat,99)}us")
        p("Marcadores:")
        for row in markers: p(f"  {row['relative_ms']:.3f} ms  {row['marker_name']}")
        starts = [r for r in markers if r["marker_name"] == "CINEMATIC_START"]
        ends = [r for r in markers if r["marker_name"] == "CINEMATIC_END"]
        if starts:
            start = starts[-1]
            end = next((r for r in ends if r["timestamp_us"] >= start["timestamp_us"]), None)
            if end:
                closes = [r for r in rows if r["type"] == 3 and r["timestamp_us"] >= start["timestamp_us"]]
                close = closes[0] if closes and closes[0]["timestamp_us"] < end["timestamp_us"] else None
                boundary = close if close else end
                segment = [r for r in operations if start["timestamp_us"] <= r["timestamp_us"] <= boundary["timestamp_us"]]
                segment_reads = [r for r in segment if r["command"] == 0x2E]
                segment_stutters = [r for r in markers if r["marker_name"] == "CINEMATIC_STUTTER" and start["timestamp_us"] <= r["timestamp_us"] <= boundary["timestamp_us"]]
                segment_us = boundary["timestamp_us"] - start["timestamp_us"]
                segment_busy_us = sum(r["duration_us"] for r in segment)
                segment_bytes = sum(max(r["result"], 0) for r in segment_reads)
                segment_hits = sum(bool(r["flags"] & 1) for r in segment_reads)
                segment_misses = sum(bool(r["flags"] & 2) for r in segment_reads)
                segment_errors = sum(bool(r["flags"] & 128) or r["result"] < 0 for r in segment)
                p("Intervalo de cinemática:")
                if close:
                    p("  captura truncada: la conexión SMB se cerró antes de CINEMATIC_END")
                p(f"  duración={segment_us/1e6:.3f}s operaciones={len(segment)} READ_ANDX={len(segment_reads)} bytes={segment_bytes}")
                p(f"  tiempo SMB activo={segment_busy_us/1e6:.3f}s caché_hits={segment_hits} caché_misses={segment_misses} errores={segment_errors} stutters_marcados={len(segment_stutters)}")
                if segment_us:
                    p(f"  rendimiento medio={segment_bytes * 1e6 / segment_us / 1024:.1f} KiB/s ocupación_SMB={100 * segment_busy_us / segment_us:.1f}%")
            else:
                p("Intervalo de cinemática: inicio presente, falta CINEMATIC_END.")
        commands = Counter(r["command"] for r in operations)
        p("Comandos SMB retenidos: " + ", ".join(f"0x{k:02X}={v}" for k, v in sorted(commands.items())))
        p("Nota: los percentiles con ≈ provienen de histogramas log2 globales; los exactos usan solo eventos aún retenidos.")


def main():
    parser = argparse.ArgumentParser(description="Decodifica y analiza métricas SMB del ESP32")
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("smb-metrics.csv"))
    args = parser.parse_args()
    data = args.input.read_bytes()
    crc_file = Path(str(args.input) + ".crc32")
    if crc_file.exists():
        expected_crc = int(crc_file.read_text(encoding="ascii").strip(), 16)
        actual_crc = zlib.crc32(data) & 0xFFFFFFFF
        if actual_crc != expected_crc:
            raise SystemExit(f"CRC inválido: archivo={actual_crc:08X}, esperado={expected_crc:08X}")
    if len(data) < HEADER.size: raise SystemExit("Archivo demasiado corto")
    if data[:8] == b"SMBTRC1\0": raise SystemExit("Traza v1 detectada; este analizador espera métricas v2")
    if data[:8] != b"SMBMTR2\0": raise SystemExit(f"Magic inesperado: {data[:8]!r}")
    values = HEADER.unpack_from(data, 0)
    keys = ("magic", "version", "header_size", "event_size", "summary_size",
            "capacity", "count", "slow_capacity", "slow_count", "total_recorded",
            "overwritten", "dropped", "frozen", "reserved")
    header = dict(zip(keys, values))
    if header["header_size"] != 104 or header["event_size"] != EVENT.size:
        raise SystemExit(f"Formato no soportado: header={header['header_size']} event={header['event_size']}")
    expected = header["header_size"] + header["summary_size"] + (header["count"] + header["slow_count"]) * EVENT.size
    if len(data) != expected: raise SystemExit(f"Longitud inválida: recibidos={len(data)}, esperados={expected}")
    summary = parse_summary(data, header["header_size"], header["summary_size"])
    pos = header["header_size"] + header["summary_size"]
    raw_events = [unpack_event(data, pos + i * EVENT.size) for i in range(header["count"])]
    pos += header["count"] * EVENT.size
    raw_slow = [unpack_event(data, pos + i * EVENT.size) for i in range(header["slow_count"])]
    timestamps = [r["timestamp_us"] for r in raw_events + raw_slow]
    first = min(timestamps) if timestamps else summary["capture_started_us"]
    rows = [enrich(r, i, first, "recent") for i, r in enumerate(raw_events)]
    slow_rows = [enrich(r, i, first, "slow") for i, r in enumerate(raw_slow)]
    args.output.parent.mkdir(parents=True, exist_ok=True)
    write_csv(args.output, rows)
    stem = args.output.with_suffix("")
    slow_path = Path(str(stem) + "-slow.csv")
    throughput_path = Path(str(stem) + "-throughput.csv")
    report_path = Path(str(stem) + "-report.txt")
    write_csv(slow_path, slow_rows)
    write_throughput(throughput_path, [r for r in rows if r["type"] == 16 and r["command"] == 0x2E])
    write_report(report_path, header, summary, rows)
    print(f"CSV: {args.output}\nLentos: {slow_path}\nRendimiento: {throughput_path}\nInforme: {report_path}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import argparse
import csv
import struct
from pathlib import Path


HEADER_PREFIX = struct.Struct("<8sHHHHIIQQII")
EVENT = struct.Struct("<QQIiIHHHHBBBB")

EVENT_TYPES = {
    0: "NONE",
    1: "SYSTEM",
    2: "CONNECTION_OPEN",
    3: "CONNECTION_CLOSE",
    4: "RECEIVE",
    5: "SMB_REQUEST",
    6: "SEEK",
    7: "READ",
    8: "SEND",
    9: "IDLE",
    10: "LISTEN_PENDING",
    11: "HEAP",
    12: "ERROR",
    13: "SD_DETECT",
    14: "ETHERNET_LINK",
    15: "SMB_SERVER",
}

PHASES = {
    0: "IDLE",
    1: "ACCEPT",
    2: "WAIT_SOCKET",
    3: "RECV_DIRECT_HEADER",
    4: "RECV_SMB_BODY",
    5: "PARSE_REQUEST",
    6: "DISPATCH",
    7: "SEEK",
    8: "READ",
    9: "BUILD_RESPONSE",
    10: "SEND",
    11: "CLOSE",
}


def unpack_event(data, offset=0):
    values = EVENT.unpack_from(data, offset)
    keys = (
        "timestamp_us", "file_offset", "duration_us", "result", "auxiliary",
        "connection_id", "mid", "fid", "size", "type", "command", "phase", "flags",
    )
    return dict(zip(keys, values))


def main():
    parser = argparse.ArgumentParser(description="Decodifica una traza SMB del ESP32")
    parser.add_argument("input", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("smb-trace.csv"))
    args = parser.parse_args()

    data = args.input.read_bytes()
    if len(data) < 88:
        raise SystemExit("Archivo demasiado corto para una cabecera de traza")

    fields = HEADER_PREFIX.unpack_from(data, 0)
    magic, version, header_size, event_size, _, capacity, count, total, overwritten, frozen, _ = fields
    if magic != b"SMBTRC1\0":
        raise SystemExit(f"Magic inesperado: {magic!r}")
    if header_size != 88 or event_size != EVENT.size:
        raise SystemExit(f"Formato no soportado: header={header_size}, event={event_size}")

    expected = header_size + count * event_size
    if len(data) != expected:
        raise SystemExit(f"Longitud inválida: recibidos={len(data)}, esperados={expected}")

    active = unpack_event(data, HEADER_PREFIX.size)
    print(
        f"version={version} count={count}/{capacity} total={total} "
        f"overwritten={overwritten} frozen={frozen}"
    )
    print(
        "active: "
        f"phase={PHASES.get(active['phase'], active['phase'])} "
        f"conn={active['connection_id']} cmd=0x{active['command']:02X} "
        f"mid={active['mid']} fid={active['fid']} "
        f"offset={active['file_offset']} size={active['size']}"
    )

    rows = []
    first_timestamp = None
    for index in range(count):
        event = unpack_event(data, header_size + index * event_size)
        if first_timestamp is None:
            first_timestamp = event["timestamp_us"]
        event["index"] = index
        event["relative_ms"] = (event["timestamp_us"] - first_timestamp) / 1000.0
        event["type_name"] = EVENT_TYPES.get(event["type"], f"TYPE_{event['type']}")
        event["phase_name"] = PHASES.get(event["phase"], f"PHASE_{event['phase']}")
        event["command_hex"] = f"0x{event['command']:02X}"
        if event["type"] == 11:
            event["heap_internal_free"] = event["file_offset"]
            event["heap_internal_largest"] = event["duration_us"]
            event["heap_internal_minimum"] = event["result"]
            event["heap_psram_free"] = event["auxiliary"]
            event["heap_read_count"] = event["mid"] | (event["fid"] << 16)
        else:
            event["heap_internal_free"] = ""
            event["heap_internal_largest"] = ""
            event["heap_internal_minimum"] = ""
            event["heap_psram_free"] = ""
            event["heap_read_count"] = ""
        rows.append(event)

    columns = (
        "index", "relative_ms", "timestamp_us", "type_name", "phase_name",
        "connection_id", "command_hex", "mid", "fid", "file_offset", "size",
        "duration_us", "result", "auxiliary", "flags", "heap_internal_free",
        "heap_internal_largest", "heap_internal_minimum", "heap_psram_free",
        "heap_read_count",
    )
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    print(f"CSV escrito en {args.output}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Replay captured official TFT WriteFile buffers to VEGA MI_03.

Only buffers copied from a prior official upload are accepted. The tool does
not generate a protocol packet and does not touch the WB32/Vial interface.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as w
import json
import subprocess
import time
from pathlib import Path

import hid

VID, PID, INTERFACE, USAGE_PAGE = 0x05AC, 0x024F, 3, 0xFF13
PACKET_SIZE = 4097
GENERIC_WRITE = 0x40000000
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997


class OVERLAPPED(ctypes.Structure):
    _fields_ = [
        ("Internal", ctypes.c_void_p),
        ("InternalHigh", ctypes.c_void_p),
        ("Offset", w.DWORD),
        ("OffsetHigh", w.DWORD),
        ("hEvent", w.HANDLE),
    ]


def load_packets(path: Path, handle: str | None) -> list[bytes]:
    packets = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if record.get("source") != "WriteFile" or record.get("length") != PACKET_SIZE:
            continue
        if handle and record.get("handle", "").lower() != handle.lower():
            continue
        data = bytes(record.get("data", []))
        if len(data) == PACKET_SIZE:
            packets.append(data)
    if not packets:
        raise SystemExit("В логе не найдено подходящих 4097-байтных WriteFile-буферов")
    return packets


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--handle", default="0x7c8")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()
    if not args.confirm:
        raise SystemExit("Нужен явный флаг --confirm")
    packets = load_packets(args.jsonl, args.handle)
    if len(packets) != 16:
        raise SystemExit(f"Ожидалось 16 пакетов одного слота, найдено {len(packets)}")

    devices = [d for d in hid.enumerate(VID, PID)
               if d.get("interface_number") == INTERFACE and d.get("usage_page") == USAGE_PAGE]
    if len(devices) != 1:
        raise SystemExit(f"VEGA MI_03 найден неоднозначно: {len(devices)}")
    path = devices[0]["path"].decode()
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.CreateFileW(path, GENERIC_WRITE, 3, None, 3, FILE_FLAG_OVERLAPPED, None)
    if handle in (0, -1):
        raise OSError(f"CreateFileW failed: {ctypes.GetLastError()}")

    pending = []
    try:
        for index, packet in enumerate(packets, 1):
            event = kernel32.CreateEventW(None, True, False, None)
            overlapped = OVERLAPPED()
            overlapped.hEvent = event
            buffer = ctypes.create_string_buffer(packet)
            written = w.DWORD(0)
            ok = kernel32.WriteFile(handle, buffer, len(packet), ctypes.byref(written), ctypes.byref(overlapped))
            error = ctypes.GetLastError()
            if not ok and error != ERROR_IO_PENDING:
                raise OSError(f"packet {index}: WriteFile failed: {error}")
            pending.append((event, overlapped, buffer))
            print(f"{index:02d}/16 queued ({'pending' if not ok else 'complete'})", flush=True)
            time.sleep(0.03)
        # Keep the handle and all buffers alive while the HID driver drains its queue.
        time.sleep(3.0)
    finally:
        for event, _, _ in pending:
            kernel32.CloseHandle(event)
        kernel32.CloseHandle(handle)


if __name__ == "__main__":
    main()

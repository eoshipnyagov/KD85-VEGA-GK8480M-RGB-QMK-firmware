#!/usr/bin/env python3
"""Replay captured official TFT WriteFile buffers to VEGA MI_02.

Only buffers copied from a prior official upload are accepted. The tool does
not generate a protocol packet and does not touch the WB32/Vial interface.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as w
import json
import struct
import subprocess
import time
from pathlib import Path

import hid

VID, PID, INTERFACE, USAGE_PAGE = 0x05AC, 0x024F, 2, 0xFF68
PACKET_SIZE = 4097
SLOT_SIZE = 65536
HEADER_SIZE = 256
WIDTH, HEIGHT = 240, 135
FRAME_SIZE = WIDTH * HEIGHT * 2
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


def gradient_packets(packets: list[bytes]) -> list[bytes]:
    """Replace only captured slots' RGB565 pixels with a 2D gradient."""
    if len(packets) % 16:
        raise ValueError("captured packet count must be a multiple of 16")
    pixels = bytearray(FRAME_SIZE)
    for y in range(HEIGHT):
        for x in range(WIDTH):
            red = x * 31 // (WIDTH - 1)
            green = y * 63 // (HEIGHT - 1)
            blue = (WIDTH - 1 - x) * 31 // (WIDTH - 1)
            value = (red << 11) | (green << 5) | blue
            struct.pack_into("<H", pixels, (y * WIDTH + x) * 2, value)
    output = []
    for start in range(0, len(packets), 16):
        block = b"".join(packet[1:] for packet in packets[start:start + 16])
        if len(block) != SLOT_SIZE:
            raise ValueError("captured slot must be exactly 64 KiB")
        block = block[:HEADER_SIZE] + bytes(pixels) + block[HEADER_SIZE + FRAME_SIZE:]
        output.extend(b"\x00" + block[offset:offset + 4096]
                      for offset in range(0, SLOT_SIZE, 4096))
    return output


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("jsonl", type=Path)
    parser.add_argument("--handle", default="0x7c8")
    parser.add_argument("--gradient", action="store_true", help="заменить пиксели на 2D RGB565-градиент")
    parser.add_argument("--confirm", action="store_true")
    args = parser.parse_args()
    if not args.confirm:
        raise SystemExit("Нужен явный флаг --confirm")
    packets = load_packets(args.jsonl, args.handle)
    if len(packets) % 16:
        raise SystemExit(f"Ожидалось целое число слотов по 16 пакетов, найдено {len(packets)}")
    if args.gradient:
        packets = gradient_packets(packets)
        print("Используется тестовый 2D RGB565-градиент", flush=True)

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

#!/usr/bin/env python3
"""Upload one TFT frame using the recovered official VEGA HID sequence.

The JSONL file is used only as a protocol template: service reports and the
64-KiB slot headers/tails are copied, while RGB565 pixels come from the input
image.  This is deliberately limited to one frame in the first iteration.
"""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as w
import json
import struct
import time
from pathlib import Path

import hid
from PIL import Image

VID, PID = 0x05AC, 0x024F
MI03_INTERFACE, MI03_USAGE = 3, 0xFF13
MI02_INTERFACE, MI02_USAGE = 2, 0xFF68
REPORT = 4097
SLOT = 65536
HEADER = 256
WIDTH, HEIGHT = 240, 135
PIXELS = WIDTH * HEIGHT * 2
PIXEL_START_ADJUST = -40  # calibration: observed common shift ≈ 20 pixels right
GENERIC_WRITE = 0x40000000
GENERIC_READ = 0x80000000
FILE_FLAG_OVERLAPPED = 0x40000000
ERROR_IO_PENDING = 997
WAIT_OBJECT_0 = 0
WAIT_TIMEOUT = 258
IOCTL_HID_GET_FEATURE = 0x000B0192


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", w.DWORD), ("OffsetHigh", w.DWORD), ("hEvent", w.HANDLE)]
def read_template(path: Path, frame_count: int) -> tuple[list[tuple[str, bytes]], list[bytes]]:
    events: list[tuple[str, bytes]] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        source = row.get("source")
        if source == "HidD_SetFeature" and row.get("length") == 65:
            data = bytes(row.get("data", []))
            if len(data) == 65:
                events.append(("feature", data))
        elif source == "WriteFile" and row.get("length") == REPORT:
            data = bytes(row.get("data", []))
            if len(data) == REPORT:
                events.append(("frame", data))
    frame_positions = [i for i, (kind, _) in enumerate(events) if kind == "frame"]
    needed = frame_count * 16
    if len(frame_positions) < needed:
        raise SystemExit(f"В шаблоне найдено только {len(frame_positions)} кадровых пакетов; нужно {needed}")
    # First official one-frame upload: retain the service sequence surrounding
    # the first 16 frame writes and ignore unrelated startup traffic.
    first = frame_positions[0]
    last = frame_positions[needed - 1]
    end = last + 1
    # The official uploader emits a final service report immediately after
    # the last data packet (04 02 in the captured one-frame session). Keep it:
    # this is the likely commit/activate step for the newly written slot.
    while end < len(events) and events[end][0] == "feature":
        end += 1
    selected = events[max(0, first - 32):end]
    if sum(kind == "frame" for kind, _ in selected) != needed:
        raise SystemExit(f"Не удалось выделить ровно {frame_count} слот(а/ов) из шаблона")
    return selected, [data for kind, data in selected if kind == "frame"]


def rgb565(image: Image.Image) -> bytes:
    image = image.convert("RGB").resize((WIDTH, HEIGHT), Image.Resampling.LANCZOS)
    out = bytearray(PIXELS)
    for y in range(HEIGHT):
        for x in range(WIDTH):
            r, g, b = image.getpixel((x, y))
            value = ((r * 31 // 255) << 11) | ((g * 63 // 255) << 5) | (b * 31 // 255)
            # The official capture starts with bytes 3D E7 for a light pixel;
            # interpreting that as little-endian RGB565 (0xE73D) matches the
            # source image. The TFT wire order is therefore low byte first.
            struct.pack_into("<H", out, (y * WIDTH + x) * 2, value)
    return bytes(out)


def replace_pixels(packets: list[bytes], pixel_frames: list[bytes]) -> list[bytes]:
    if len(packets) != len(pixel_frames) * 16:
        raise SystemExit("Число пакетов не соответствует числу кадров")
    # The stream has one global 256-byte GIF header, followed by contiguous
    # 64,800-byte RGB565 frames. There is no per-frame 256-byte header.
    stream = bytearray(b"".join(packet[1:] for packet in packets))
    for frame_index, pixels in enumerate(pixel_frames):
        start = HEADER + PIXEL_START_ADJUST + frame_index * PIXELS
        end = start + PIXELS
        if end > len(stream):
            raise SystemExit(f"Кадр {frame_index} выходит за пределы потока")
        stream[start + HEADER:start + HEADER + PIXELS] = pixels
    return [b"\x00" + bytes(stream[offset:offset + 4096])
            for offset in range(0, len(stream), 4096)]


def find_one(interface: int, usage: int):
    devices = [d for d in hid.enumerate(VID, PID)
               if d.get("interface_number") == interface and d.get("usage_page") == usage]
    if len(devices) != 1:
        raise SystemExit(f"Нужный HID-интерфейс не найден однозначно: {len(devices)}")
    return devices[0]


def read_input_report(kernel32, handle: int, timeout_ms: int = 1500) -> bytes:
    event = kernel32.CreateEventW(None, True, False, None)
    if not event:
        raise OSError(f"CreateEvent failed: {ctypes.GetLastError()}")
    ov = OVERLAPPED(); ov.hEvent = event
    # HIDClass expects the report-ID byte in the user buffer as well.
    buffer = ctypes.create_string_buffer(65)
    received = w.DWORD(0)
    try:
        ok = kernel32.ReadFile(handle, buffer, 65, ctypes.byref(received), ctypes.byref(ov))
        error = ctypes.GetLastError()
        if not ok and error != ERROR_IO_PENDING:
            raise OSError(f"ReadFile failed: {error}")
        status = kernel32.WaitForSingleObject(event, timeout_ms)
        if status == WAIT_TIMEOUT:
            kernel32.CancelIoEx(handle, ctypes.byref(ov))
            raise TimeoutError("MI_02 ACK timeout")
        if status != WAIT_OBJECT_0:
            raise OSError(f"WaitForSingleObject failed: {status}")
        if not kernel32.GetOverlappedResult(handle, ctypes.byref(ov), ctypes.byref(received), False):
            raise OSError(f"GetOverlappedResult failed: {ctypes.GetLastError()}")
        return bytes(buffer.raw[:received.value])
    finally:
        kernel32.CloseHandle(event)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("template", type=Path, help="JSONL-захват одной официальной загрузки")
    ap.add_argument("image", type=Path, help="PNG/JPG/GIF; используется первый кадр")
    ap.add_argument("--frame-count", type=int, choices=(1, 2, 3), default=1,
                    help="число кадров в сессии; для GIF берутся первые кадры")
    ap.add_argument("--confirm", action="store_true", help="разрешить запись в экран")
    ap.add_argument("--dry-run", action="store_true", help="только собрать и проверить пакеты")
    ap.add_argument("--no-ack", action="store_true", help="не читать ACK; только для диагностики с USBPcap")
    ap.add_argument("--retries", type=int, default=3, help="повторы пакета при таймауте ACK")
    ap.add_argument("--interval", type=float, default=0.03, help="пауза между HID-пакетами")
    args = ap.parse_args()
    sequence, captured = read_template(args.template, args.frame_count)
    source = Image.open(args.image)
    if getattr(source, "n_frames", 1) < args.frame_count:
        raise SystemExit(f"В изображении только {getattr(source, 'n_frames', 1)} кадр(а/ов)")
    pixel_frames = []
    for index in range(args.frame_count):
        source.seek(index)
        pixel_frames.append(rgb565(source.copy()))
    frames = replace_pixels(captured, pixel_frames)
    print(f"Шаблон: {args.frame_count} слот(а/ов), {sum(k == 'feature' for k, _ in sequence)} service-отчётов")
    print(f"Изображение: {args.image} -> {args.frame_count} кадр(а/ов), 240x135 RGB565")
    if args.dry_run:
        print("Пробный режим: устройство не изменялось")
        return
    if not args.confirm:
        raise SystemExit("Для записи нужен явный флаг --confirm")

    mi03 = find_one(MI03_INTERFACE, MI03_USAGE)
    mi02 = find_one(MI02_INTERFACE, MI02_USAGE)
    kernel32 = ctypes.windll.kernel32
    hidll = ctypes.windll.hid
    hidll.HidD_SetFeature.argtypes = [w.HANDLE, ctypes.c_void_p, w.ULONG]
    hidll.HidD_SetFeature.restype = w.BOOL
    hidll.HidD_GetFeature.argtypes = [w.HANDLE, ctypes.c_void_p, w.ULONG]
    hidll.HidD_GetFeature.restype = w.BOOL
    service_handle = kernel32.CreateFileW(mi03["path"].decode(), GENERIC_READ | GENERIC_WRITE,
                                          3, None, 3, 0, None)
    if service_handle in (0, -1):
        raise OSError(f"MI_03 CreateFileW failed: {ctypes.GetLastError()}")
    # Use synchronous writes. With an overlapped handle, closing the handle
    # after the nominal delay can cancel queued HID transfers before USBPcap
    # ever sees them.
    handle = kernel32.CreateFileW(mi02["path"].decode(), GENERIC_READ | GENERIC_WRITE,
                                  3, None, 3, 0, None)
    if handle in (0, -1):
        kernel32.CloseHandle(service_handle)
        raise OSError(f"MI_02 CreateFileW failed: {ctypes.GetLastError()}")
    read_handle = kernel32.CreateFileW(mi02["path"].decode(), GENERIC_READ, 3, None, 3,
                                       FILE_FLAG_OVERLAPPED, None)
    if read_handle in (0, -1):
        kernel32.CloseHandle(handle)
        kernel32.CloseHandle(service_handle)
        raise OSError(f"MI_02 read handle failed: {ctypes.GetLastError()}")

    frame_index = 0
    try:
        for kind, data in sequence:
            if kind == "feature":
                feature_buffer = ctypes.create_string_buffer(data)
                if not hidll.HidD_SetFeature(service_handle, feature_buffer, 65):
                    raise RuntimeError(f"MI_03 service report rejected: {ctypes.GetLastError()}")
                time.sleep(args.interval)
                response_buffer = ctypes.create_string_buffer(data)
                returned = w.DWORD(0)
                if not kernel32.DeviceIoControl(service_handle, IOCTL_HID_GET_FEATURE,
                                                response_buffer, 65,
                                                response_buffer, 65,
                                                ctypes.byref(returned), None):
                    raise RuntimeError(f"MI_03 IOCTL_HID_GET_FEATURE failed: {ctypes.GetLastError()}")
            else:
                packet = frames[frame_index]
                frame_index += 1
                buf = ctypes.create_string_buffer(packet)
                written = w.DWORD(0)
                attempts = 0
                while True:
                    attempts += 1
                    written = w.DWORD(0)
                    ok = kernel32.WriteFile(handle, buf, len(packet), ctypes.byref(written), None)
                    if not ok or written.value != len(packet):
                        raise OSError(f"MI_02 packet {frame_index}: WriteFile failed: {ctypes.GetLastError()}, written={written.value}")
                    if args.no_ack:
                        break
                    try:
                        ack = read_input_report(kernel32, read_handle)
                        payload = ack[1:] if ack[:1] == b"\x00" else ack
                        if len(payload) < 3 or payload[0:3] != bytes((1, 0x5A, 2)):
                            raise RuntimeError(f"MI_02 packet {frame_index}: unexpected ACK {bytes(ack).hex()}")
                        break
                    except TimeoutError:
                        if attempts > args.retries:
                            raise RuntimeError(f"MI_02 packet {frame_index}: ACK timeout after {attempts} attempts")
                        print(f"MI_02 packet {frame_index}: ACK timeout, retry {attempts}/{args.retries}", flush=True)
                time.sleep(args.interval)
        time.sleep(2.0)
        print("Загрузка одного кадра завершена")
    finally:
        kernel32.CloseHandle(handle)
        kernel32.CloseHandle(read_handle)
        kernel32.CloseHandle(service_handle)


if __name__ == "__main__":
    main()

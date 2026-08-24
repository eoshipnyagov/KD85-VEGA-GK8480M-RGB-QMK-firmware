#!/usr/bin/env python3
"""Replay one captured official TFT upload, including MI_03 service reports."""
from __future__ import annotations

import argparse
import ctypes
import ctypes.wintypes as w
import json
import time
from pathlib import Path

import hid

VID, PID = 0x05AC, 0x024F
PACKET = 4097


class OVERLAPPED(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_void_p), ("InternalHigh", ctypes.c_void_p),
                ("Offset", w.DWORD), ("OffsetHigh", w.DWORD), ("hEvent", w.HANDLE)]


def events(path: Path):
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("source") == "HidD_SetFeature" and row.get("length") == 65:
            rows.append(("feature", bytes(row.get("data", []))))
        elif row.get("source") == "WriteFile" and row.get("length") == PACKET:
            rows.append(("frame", bytes(row.get("data", []))))
    if not rows:
        raise SystemExit("В захвате не найдено подходящих событий")
    return rows


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("jsonl", type=Path)
    ap.add_argument("--confirm", action="store_true")
    args = ap.parse_args()
    if not args.confirm:
        raise SystemExit("Нужен явный флаг --confirm")
    sequence = events(args.jsonl)
    frame_count = sum(kind == "frame" for kind, _ in sequence)
    if frame_count != 32:
        raise SystemExit(f"Ожидалось 32 кадровых пакета, найдено {frame_count}")

    mi03 = [d for d in hid.enumerate(VID, PID)
            if d.get("interface_number") == 3 and d.get("usage_page") == 0xFF13]
    mi02 = [d for d in hid.enumerate(VID, PID)
            if d.get("interface_number") == 2 and d.get("usage_page") == 0xFF68]
    if len(mi03) != 1 or len(mi02) != 1:
        raise SystemExit(f"Интерфейсы не найдены однозначно: MI_03={len(mi03)}, MI_02={len(mi02)}")

    feature = hid.device()
    feature.open_path(mi03[0]["path"])
    feature.set_nonblocking(False)
    kernel32 = ctypes.windll.kernel32
    hid_handle = kernel32.CreateFileW(mi02[0]["path"].decode(), 0x40000000, 3, None, 3, 0x40000000, None)
    if hid_handle in (0, -1):
        feature.close()
        raise OSError(f"MI_02 CreateFileW failed: {ctypes.GetLastError()}")

    pending = []
    frame_index = 0
    try:
        for kind, data in sequence:
            if kind == "feature":
                result = feature.send_feature_report(data)
                if result < 0:
                    raise RuntimeError("MI_03 feature report rejected")
                print(f"MI_03 feature {data[1:4].hex()}", flush=True)
            else:
                frame_index += 1
                event = kernel32.CreateEventW(None, True, False, None)
                ov = OVERLAPPED(); ov.hEvent = event
                buf = ctypes.create_string_buffer(data)
                written = w.DWORD(0)
                ok = kernel32.WriteFile(hid_handle, buf, len(data), ctypes.byref(written), ctypes.byref(ov))
                error = ctypes.GetLastError()
                if not ok and error != 997:
                    raise OSError(f"MI_02 WriteFile failed: {error}")
                pending.append((event, ov, buf))
                print(f"MI_02 frame {frame_index}/32", flush=True)
                time.sleep(0.03)
        time.sleep(3)
    finally:
        for event, _, _ in pending:
            kernel32.CloseHandle(event)
        kernel32.CloseHandle(hid_handle)
        feature.close()


if __name__ == "__main__":
    main()

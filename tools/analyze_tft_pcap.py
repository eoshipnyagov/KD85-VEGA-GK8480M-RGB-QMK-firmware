#!/usr/bin/env python3
"""Passively decode the recovered KD85/VEGA TFT USB capture.

This tool only reads a pcap through tshark. It never opens a HID device and
cannot upload anything to the keyboard.
"""
from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

SLOT_SIZE = 0x10000
HEADER_SIZE = 0x100
WIDTH = 240
HEIGHT = 135
FRAME_SIZE = WIDTH * HEIGHT * 2


def tshark_rows(pcap: Path, display_filter: str, tshark: str):
    command = [
        tshark, "-r", str(pcap), "-Y", display_filter, "-T", "fields",
        "-e", "frame.number", "-e", "usbhid.data",
    ]
    try:
        output = subprocess.check_output(command, text=True, stderr=subprocess.STDOUT)
    except FileNotFoundError as exc:
        raise SystemExit("tshark не найден; укажите --tshark путь к tshark.exe") from exc
    except subprocess.CalledProcessError as exc:
        raise SystemExit(exc.output) from exc
    for line in output.splitlines():
        parts = line.split("\t", 1)
        if len(parts) != 2 or not parts[1]:
            continue
        yield int(parts[0]), bytes.fromhex(parts[1])


def decode_capture(pcap: Path, device: int, tshark: str):
    out_filter = (
        f"usb.device_address == {device} && usb.endpoint_address == 0x03 "
        "&& usb.transfer_type == 0x01"
    )
    in_filter = (
        f"usb.device_address == {device} && usb.endpoint_address == 0x84 "
        "&& usb.transfer_type == 0x01"
    )
    out_rows = list(tshark_rows(pcap, out_filter, tshark))
    in_rows = list(tshark_rows(pcap, in_filter, tshark))
    payload = b"".join(data for _, data in out_rows)
    if len(payload) % SLOT_SIZE:
        raise SystemExit(f"OUT payload {len(payload)} не кратен 64 KiB")

    blocks = []
    for index in range(len(payload) // SLOT_SIZE):
        block = payload[index * SLOT_SIZE:(index + 1) * SLOT_SIZE]
        header = block[:HEADER_SIZE]
        pixels = block[HEADER_SIZE:HEADER_SIZE + FRAME_SIZE]
        tail = block[HEADER_SIZE + FRAME_SIZE:]
        blocks.append({
            "index": index,
            "header_hex": header.hex(),
            "header_unique_bytes": sorted(set(header)),
            "pixel_bytes": len(pixels),
            "tail_bytes": len(tail),
            "tail_unique_bytes": sorted(set(tail)),
            "tail_all_ff": tail == b"\xff" * len(tail),
            "out_frames": [frame for frame, _ in out_rows[index * 16:(index + 1) * 16]],
        })
    ack_values = sorted({data.hex() for _, data in in_rows})
    return out_rows, in_rows, payload, blocks, ack_values


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("pcap", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=None)
    parser.add_argument("--device", type=int, default=4)
    parser.add_argument("--tshark", default=shutil.which("tshark") or r"C:\Program Files\Wireshark\tshark.exe")
    args = parser.parse_args()
    out_rows, in_rows, payload, blocks, ack_values = decode_capture(args.pcap, args.device, args.tshark)
    report = {
        "pcap": str(args.pcap),
        "device_address": args.device,
        "out_payload_bytes": len(payload),
        "out_records": len(out_rows),
        "in_records": len(in_rows),
        "slot_size": SLOT_SIZE,
        "header_size": HEADER_SIZE,
        "frame": {"width": WIDTH, "height": HEIGHT, "format": "RGB565", "bytes": FRAME_SIZE},
        "ack_unique": ack_values,
        "blocks": blocks,
        "active": False,
        "note": "Passive pcap analysis only; no HID handle is opened.",
    }
    if args.output:
        args.output.mkdir(parents=True, exist_ok=True)
        (args.output / "tft-analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        for index in range(len(payload) // SLOT_SIZE):
            block = payload[index * SLOT_SIZE:(index + 1) * SLOT_SIZE]
            (args.output / f"tft-block-{index:02d}.bin").write_bytes(block)
            (args.output / f"tft-frame-{index:02d}.rgb565").write_bytes(block[HEADER_SIZE:HEADER_SIZE + FRAME_SIZE])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

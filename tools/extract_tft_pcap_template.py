#!/usr/bin/env python3
"""Convert one clean USBPcap TFT upload into a replay template."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("pcap", type=Path)
    ap.add_argument("output", type=Path)
    ap.add_argument("--tshark", default=r"C:\Program Files\Wireshark\tshark.exe")
    ap.add_argument("--device", type=int, default=4)
    args = ap.parse_args()
    filt = f"usb.device_address == {args.device} && ((usb.endpoint_address == 0x00 && usb.data_len == 72) || (usb.endpoint_address == 0x03 && usb.data_len == 4096))"
    cmd = [args.tshark, "-r", str(args.pcap), "-Y", filt, "-T", "fields", "-e", "frame.number", "-e", "usb.endpoint_address", "-e", "usb.data_fragment", "-e", "usb.capdata"]
    rows = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT).splitlines()
    out = []
    for line in rows:
        parts = line.split("\t")
        if len(parts) < 4:
            continue
        number, endpoint, fragment, capdata = parts[:4]
        if endpoint == "0x00" and fragment:
            data = bytes.fromhex(fragment)
            out.append({"source": "HidD_SetFeature", "frame": int(number), "length": 65, "data": [0] + list(data)})
        elif endpoint == "0x03" and capdata:
            data = bytes.fromhex(capdata)
            if len(data) == 4096:
                out.append({"source": "WriteFile", "frame": int(number), "length": 4097, "data": [0] + list(data)})
    args.output.write_text("\n".join(json.dumps(row) for row in out) + "\n", encoding="utf-8")
    print(f"Извлечено: service={sum(r['source'] == 'HidD_SetFeature' for r in out)}, frames={sum(r['source'] == 'WriteFile' for r in out)}")


if __name__ == "__main__":
    main()

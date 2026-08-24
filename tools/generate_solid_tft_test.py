#!/usr/bin/env python3
"""Generate solid-color 240x135 TFT diagnostic frames."""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image

WIDTH, HEIGHT = 240, 135
COLORS = ((255, 0, 0), (0, 255, 0), (0, 0, 255))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("output", type=Path)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    frames = []
    names = ("red", "green", "blue")
    for index, (name, color) in enumerate(zip(names, COLORS), 1):
        image = Image.new("RGB", (WIDTH, HEIGHT), color)
        image.save(args.output / f"vega-solid-frame-{index:02d}-{name}.png")
        frames.append(image)
    frames[0].save(args.output / "vega-solid-3-frames.gif", save_all=True,
                   append_images=frames[1:], loop=0, duration=700,
                   disposal=2, optimize=False)
    print(args.output)


if __name__ == "__main__":
    main()

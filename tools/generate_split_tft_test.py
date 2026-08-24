#!/usr/bin/env python3
"""Generate half-screen diagnostic frames for TFT boundary testing."""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image

WIDTH, HEIGHT = 240, 135
PAIRS = (((255, 0, 0), (0, 0, 255)),
         ((0, 255, 0), (255, 255, 0)),
         ((255, 255, 255), (0, 0, 0)))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("output", type=Path)
    args = ap.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    frames = []
    for index, (left, right) in enumerate(PAIRS, 1):
        image = Image.new("RGB", (WIDTH, HEIGHT))
        px = image.load()
        for y in range(HEIGHT):
            for x in range(WIDTH):
                px[x, y] = left if x < WIDTH // 2 else right
        image.save(args.output / f"vega-split-frame-{index:02d}.png")
        frames.append(image)
    frames[0].save(args.output / "vega-split-3-frames.gif", save_all=True,
                   append_images=frames[1:], loop=0, duration=700,
                   disposal=2, optimize=False)
    print(args.output)


if __name__ == "__main__":
    main()

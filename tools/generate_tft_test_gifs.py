#!/usr/bin/env python3
"""Generate small deterministic GIFs for testing the VEGA 240x135 TFT."""
from __future__ import annotations

import argparse
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 240, 135


def frame(number: int, total: int, palette: tuple[tuple[int, int, int], tuple[int, int, int]]) -> Image.Image:
    image = Image.new("RGB", (WIDTH, HEIGHT))
    pixels = image.load()
    left, right = palette
    for y in range(HEIGHT):
        for x in range(WIDTH):
            t = x / (WIDTH - 1)
            r = int(left[0] * (1 - t) + right[0] * t)
            g = int(left[1] * (1 - t) + right[1] * t)
            b = int(left[2] * (1 - t) + right[2] * t)
            pixels[x, y] = (r, g, b)
    draw = ImageDraw.Draw(image)
    font = ImageFont.load_default()
    draw.rectangle((8, 8, 231, 126), outline="white", width=2)
    draw.text((18, 20), "KD85 VEGA TEST", fill="white", font=font)
    draw.text((18, 48), f"FRAME {number:02d}/{total:02d}", fill="white", font=font)
    draw.text((18, 76), "RGB565 240x135", fill="white", font=font)
    draw.ellipse((174, 43, 214, 83), outline="white", width=3)
    return image


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    one = frame(1, 1, ((20, 20, 180), (230, 30, 30)))
    two_a = frame(1, 2, ((20, 20, 180), (230, 30, 30)))
    two_b = frame(2, 2, ((10, 170, 40), (240, 190, 20)))
    three_a = frame(1, 3, ((20, 20, 180), (230, 30, 30)))
    three_b = frame(2, 3, ((10, 170, 40), (240, 190, 20)))
    three_c = frame(3, 3, ((170, 20, 180), (20, 210, 220)))
    one.save(args.output / "vega-test-1-frame.gif", save_all=True, loop=0, duration=700, disposal=2, optimize=False)
    two_a.save(args.output / "vega-test-2-frames.gif", save_all=True, append_images=[two_b], loop=0, duration=700, disposal=2, optimize=False)
    three_a.save(args.output / "vega-test-3-frames.gif", save_all=True, append_images=[three_b, three_c], loop=0, duration=700, disposal=2, optimize=False)
    one.save(args.output / "vega-test-frame-01.png")
    two_b.save(args.output / "vega-test-frame-02.png")
    three_c.save(args.output / "vega-test-frame-03.png")
    print(args.output)


if __name__ == "__main__":
    main()

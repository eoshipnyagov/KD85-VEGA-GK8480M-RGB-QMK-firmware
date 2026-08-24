"""Offline data structures for the recovered VEGA TFT transport.

Intentionally contains no USB/HID code. The returned blocks are for inspection,
testing and future review only; this module does not upload them.
"""
from __future__ import annotations

from dataclasses import dataclass

SLOT_SIZE = 0x10000
HEADER_SIZE = 0x100
WIDTH = 240
HEIGHT = 135
FRAME_SIZE = WIDTH * HEIGHT * 2
TAIL_SIZE = SLOT_SIZE - HEADER_SIZE - FRAME_SIZE


@dataclass(frozen=True)
class TftSlot:
    index: int
    header: bytes
    pixels_rgb565: bytes

    def encode(self) -> bytes:
        """Build one 64-KiB transport slot; does not transmit it."""
        if len(self.header) != HEADER_SIZE:
            raise ValueError("header must be exactly 256 bytes")
        if len(self.pixels_rgb565) != FRAME_SIZE:
            raise ValueError("RGB565 frame must be exactly 240x135x2 bytes")
        return self.header + self.pixels_rgb565 + (b"\xff" * TAIL_SIZE)


def split_capture(payload: bytes) -> list[TftSlot]:
    """Parse captured OUT bytes into slots without contacting any device."""
    if len(payload) % SLOT_SIZE:
        raise ValueError("capture length is not a multiple of 64 KiB")
    slots = []
    for index in range(len(payload) // SLOT_SIZE):
        block = payload[index * SLOT_SIZE:(index + 1) * SLOT_SIZE]
        slots.append(TftSlot(index, block[:HEADER_SIZE], block[HEADER_SIZE:HEADER_SIZE + FRAME_SIZE]))
    return slots

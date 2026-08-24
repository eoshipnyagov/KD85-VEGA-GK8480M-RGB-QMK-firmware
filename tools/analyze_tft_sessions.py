#!/usr/bin/env python3
"""Summarize captured TFT upload sessions and MI_03 service reports."""
from __future__ import annotations

import argparse
import json
from pathlib import Path


def read_rows(path: Path):
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    return rows


def summarize(path: Path) -> None:
    rows = read_rows(path)
    frame_indices = [i for i, row in enumerate(rows)
                     if row.get("source") == "WriteFile" and row.get("length") == 4097]
    if not frame_indices:
        print(f"{path}: no frame writes")
        return
    groups = [[frame_indices[0]]]
    for index in frame_indices[1:]:
        if index - groups[-1][-1] > 100:
            groups.append([])
        groups[-1].append(index)
    print(f"{path}: {len(groups)} session(s)")
    for session_no, indices in enumerate(groups, 1):
        lo, hi = indices[0], indices[-1]
        features = [row for row in rows[max(0, lo - 80):min(len(rows), hi + 80)]
                    if row.get("source") == "HidD_SetFeature" and row.get("length") == 65]
        print(f"  session {session_no}: frames={len(indices)} feature_reports={len(features)}")
        for feature in features:
            data = feature.get("data", [])
            if len(data) >= 4:
                print(f"    {bytes(data[:16]).hex(' ')}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("jsonl", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.jsonl:
        summarize(path)


if __name__ == "__main__":
    main()

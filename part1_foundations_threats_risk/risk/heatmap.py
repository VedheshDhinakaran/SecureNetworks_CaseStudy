#!/usr/bin/env python3
"""Draw inherent and residual 5x5 risk heat maps from risk_register.csv.

Bands (report Section 4.1): 1-4 Low, 5-9 Medium, 10-16 High, 20-25 Critical.

Usage:  python3 heatmap.py [--out-dir figures] [--text]
  --text   print the grids and a band summary without needing matplotlib
"""
from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
BANDS = [(20, "Critical", "#EF9A9A"), (10, "High", "#FFCC80"), (5, "Medium", "#FFF59D"), (1, "Low", "#C8E6C9")]


def band(score: int) -> tuple[str, str]:
    for floor, name, colour in BANDS:
        if score >= floor:
            return name, colour
    return "Low", BANDS[-1][2]


def load(path: Path) -> list[dict]:
    with open(path, newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    for r in rows:
        for k in ("likelihood", "impact", "residual_likelihood", "residual_impact"):
            r[k] = int(r[k])
        r["inherent"] = r["likelihood"] * r["impact"]
        r["residual"] = r["residual_likelihood"] * r["residual_impact"]
    return rows


def grid(rows, lk: str, ik: str) -> dict:
    cells = defaultdict(list)
    for r in rows:
        cells[(r[lk], r[ik])].append(r["id"])
    return cells


def print_text(rows) -> None:
    for title, lk, ik, sk in (("INHERENT", "likelihood", "impact", "inherent"),
                              ("RESIDUAL", "residual_likelihood", "residual_impact", "residual")):
        cells = grid(rows, lk, ik)
        print(f"\n{title} RISK (rows = likelihood 5..1, columns = impact 1..5)")
        for l in range(5, 0, -1):
            print(f"L{l} | " + " | ".join(f"{' '.join(cells.get((l, i), [])):14}" for i in range(1, 6)))
        counts = defaultdict(int)
        for r in rows:
            counts[band(r[sk])[0]] += 1
        print("   " + ", ".join(f"{b}: {counts[b]}" for _, b, _ in BANDS))


def draw(rows, out_dir: Path) -> list[Path]:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for title, lk, ik, fname in (("Inherent risk", "likelihood", "impact", "heatmap_inherent.png"),
                                 ("Residual risk", "residual_likelihood", "residual_impact", "heatmap_residual.png")):
        cells = grid(rows, lk, ik)
        fig, ax = plt.subplots(figsize=(4.6, 4.2), dpi=150)
        for l in range(1, 6):
            for i in range(1, 6):
                ax.add_patch(plt.Rectangle((i - 1, l - 1), 1, 1, facecolor=band(l * i)[1], edgecolor="white", lw=2))
                ids = cells.get((l, i), [])
                if ids:
                    text = "\n".join(" ".join(ids[k:k + 2]) for k in range(0, len(ids), 2))
                    ax.text(i - 0.5, l - 0.5, text, ha="center", va="center", fontsize=7)
        ax.set_xlim(0, 5); ax.set_ylim(0, 5)
        ax.set_xticks([x + 0.5 for x in range(5)], [str(x) for x in range(1, 6)])
        ax.set_yticks([y + 0.5 for y in range(5)], [str(y) for y in range(1, 6)])
        ax.set_xlabel("Impact"); ax.set_ylabel("Likelihood"); ax.set_title(title)
        ax.set_aspect("equal"); ax.tick_params(length=0)
        for side in ax.spines.values():
            side.set_visible(False)
        fig.tight_layout()
        path = out_dir / fname
        fig.savefig(path)
        plt.close(fig)
        written.append(path)
    return written


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--register", default=str(HERE / "risk_register.csv"))
    ap.add_argument("--out-dir", default=str(HERE / "figures"))
    ap.add_argument("--text", action="store_true")
    args = ap.parse_args()
    rows = load(Path(args.register))
    print_text(rows)
    if not args.text:
        for p in draw(rows, Path(args.out_dir)):
            print(f"wrote {p}")


if __name__ == "__main__":
    main()

#!/usr/bin/env python
"""Build the map outlines in app/static/geo/ from Natural Earth (public domain).

    python scripts/build_geo.py ne_50m_admin_0_countries.geojson ne_10m_admin_1_states_provinces.geojson

Sources (download once, they are not needed at runtime):
  https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_50m_admin_0_countries.geojson
  https://github.com/nvkelso/natural-earth-vector/blob/master/geojson/ne_10m_admin_1_states_provinces.geojson

The output is projected and simplified SVG path data (Equal Earth for the world, equirectangular for
Indonesia), so the browser only colours paths: no projection library, nothing loaded from a CDN.
Countries too small to see at world scale also get a dot (``c``).
"""
from __future__ import annotations

import json
import math
import sys
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "app" / "static" / "geo"

# --------------------------------------------------------------------------- projections
A1, A2, A3, A4 = 1.340264, -0.081106, 0.000893, 0.003796
M = math.sqrt(3) / 2


def equal_earth(lon: float, lat: float) -> tuple[float, float]:
    lam, phi = math.radians(lon), math.radians(lat)
    t = math.asin(M * math.sin(phi))
    t2, t6 = t * t, t ** 6
    x = 2 * math.sqrt(3) * lam * math.cos(t) / (3 * (9 * A4 * t6 * t2 + 7 * A3 * t6 + 3 * A2 * t2 + A1))
    y = t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
    return x, y


# --------------------------------------------------------------------------- geometry helpers
def _perp(p, a, b) -> float:
    (x, y), (x1, y1), (x2, y2) = p, a, b
    dx, dy = x2 - x1, y2 - y1
    if dx == dy == 0:
        return math.hypot(x - x1, y - y1)
    return abs(dy * x - dx * y + x2 * y1 - y2 * x1) / math.hypot(dx, dy)


def simplify(points: list[tuple[float, float]], tol: float) -> list[tuple[float, float]]:
    """Iterative Douglas-Peucker."""
    if len(points) < 4:
        return points
    keep = [False] * len(points)
    keep[0] = keep[-1] = True
    stack = [(0, len(points) - 1)]
    while stack:
        i, j = stack.pop()
        dmax, idx = 0.0, -1
        for k in range(i + 1, j):
            d = _perp(points[k], points[i], points[j])
            if d > dmax:
                dmax, idx = d, k
        if dmax > tol and idx > 0:
            keep[idx] = True
            stack += [(i, idx), (idx, j)]
    return [p for p, k in zip(points, keep, strict=True) if k]


def rings_of(geom: dict) -> list[list]:
    if geom["type"] == "Polygon":
        return list(geom["coordinates"])
    if geom["type"] == "MultiPolygon":
        return [r for poly in geom["coordinates"] for r in poly]
    return []


def path_for(rings, project, tol: float, min_size: float) -> tuple[str, tuple]:
    parts, xs, ys = [], [], []
    projected = []
    for ring in rings:
        pts = [project(lon, lat) for lon, lat in ring]
        rx, ry = [p[0] for p in pts], [p[1] for p in pts]
        size = max(max(rx) - min(rx), max(ry) - min(ry))
        projected.append((size, pts))
    projected.sort(key=lambda r: -r[0])
    for n, (size, pts) in enumerate(projected):
        if size < min_size and n > 0:  # drop specks, but keep at least the largest ring
            continue
        pts = simplify(pts, tol)
        if len(pts) < 3:
            continue
        xs += [p[0] for p in pts]
        ys += [p[1] for p in pts]
        d = "M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in pts) + "Z"
        parts.append(d.replace(".0,", ",").replace(".0L", "L").replace(".0Z", "Z"))
    if not parts and projected:  # a speck of a country: keep its largest ring as it is
        pts = projected[0][1]
        xs, ys = [p[0] for p in pts], [p[1] for p in pts]
        parts.append("M" + "L".join(f"{x:.1f},{y:.1f}" for x, y in pts) + "Z")
    bbox = (min(xs), min(ys), max(xs), max(ys)) if xs else (0, 0, 0, 0)
    return "".join(parts), bbox


# --------------------------------------------------------------------------- builders
def build_world(src: Path) -> dict:
    data = json.loads(src.read_text(encoding="utf-8"))
    xmax = equal_earth(180, 0)[0]
    ymax = equal_earth(0, 90)[1]
    width = 1000.0
    s = width / (2 * xmax)
    top, bottom = ymax * s, -equal_earth(0, -58)[1] * s  # crop Antarctica

    def project(lon, lat):
        x, y = equal_earth(lon, max(lat, -58))
        return x * s + width / 2, top - y * s

    by_code: dict[str, dict] = {}
    for f in data["features"]:
        p = f["properties"]
        code = p.get("ISO_A2_EH") if p.get("ISO_A2") in ("-99", "", None) else p.get("ISO_A2")
        if not code or code == "-99" or code == "AQ":
            continue
        e = by_code.setdefault(code, {"name": p.get("NAME_EN") or p.get("NAME"), "rings": []})
        e["rings"] += rings_of(f["geometry"])
    shapes = []
    for code, e in sorted(by_code.items()):
        d, (x0, y0, x1, y1) = path_for(e["rings"], project, tol=0.45, min_size=1.2)
        shape = {"id": code, "n": e["name"], "d": d}
        if max(x1 - x0, y1 - y0) < 5:
            shape["c"] = [round((x0 + x1) / 2, 1), round((y0 + y1) / 2, 1)]
        shapes.append(shape)
    return {"w": width, "h": round(top + bottom, 1), "source": "Natural Earth 1:50m (public domain)",
            "shapes": shapes}


def build_indonesia(src: Path) -> dict:
    data = json.loads(src.read_text(encoding="utf-8"))
    lon0, lon1, lat0, lat1 = 94.6, 141.4, -11.4, 6.4
    width = 1000.0
    k = width / (lon1 - lon0)

    def project(lon, lat):
        return (lon - lon0) * k, (lat1 - lat) * k

    shapes = []
    for f in data["features"]:
        p = f["properties"]
        if p.get("adm0_a3") != "IDN":
            continue
        code = p["iso_3166_2"]
        d, _ = path_for(rings_of(f["geometry"]), project, tol=0.55, min_size=1.5)
        shapes.append({"id": code, "n": p.get("name_id") or p.get("name"), "d": d})
    shapes.sort(key=lambda s: s["id"])
    return {"w": width, "h": round((lat1 - lat0) * k, 1), "source": "Natural Earth 1:10m admin-1 (public domain)",
            "shapes": shapes}


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 1
    OUT.mkdir(parents=True, exist_ok=True)
    for name, obj in (("world.json", build_world(Path(argv[0]))), ("indonesia.json", build_indonesia(Path(argv[1])))):
        path = OUT / name
        path.write_text(json.dumps(obj, separators=(",", ":"), ensure_ascii=False), encoding="utf-8")
        print(f"{path}: {len(obj['shapes'])} shapes, {path.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

/* JATMP dashboard globe: target countries (or Indonesian provinces in the National view) on an orthographic globe.
 *
 * <div class="globe" data-globe="world|indonesia" data-values="ID-of-json" data-top="ID-of-json" data-link="/feed?country={code}">
 *
 * Outlines are the same pre-projected Natural Earth paths the flat maps use (app/static/geo/*.json): world.json is
 * un-projected from Equal Earth and indonesia.json from equirectangular, so no extra data or library is needed.
 * The globe turns from one of the top 10 targets to the next and shows a callout for each. Drag to turn it,
 * hover for a country's count, click to open the feed, use the numbered buttons to jump to a target.
 * With prefers-reduced-motion it does not move on its own.
 */
(() => {
  "use strict";
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const VER = document.querySelector('link[rel="stylesheet"][href*="app.css"]')?.href.split("v=")[1] || "1";
  const D2R = Math.PI / 180;
  const MAP_PARENT_FALLBACK = { "ID-KU": "ID-KI", "ID-PS": "ID-PA", "ID-PT": "ID-PA", "ID-PE": "ID-PA", "ID-PD": "ID-PB" };
  const cache = {};
  const shapes = (name) => (cache[name] ||= fetch(`/static/geo/${name}.json?v=${VER}`, { credentials: "same-origin" })
    .then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); }));

  // ------------------------------------------------------------------ un-projecting the flat outlines
  const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796, M = Math.sqrt(3) / 2;
  function eeForward(lon, lat) {
    const t = Math.asin(M * Math.sin(lat * D2R)), t2 = t * t, t6 = t2 * t2 * t2;
    return [(2 * Math.sqrt(3) * lon * D2R * Math.cos(t)) / (3 * (9 * A4 * t6 * t2 + 7 * A3 * t6 + 3 * A2 * t2 + A1)),
            t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))];
  }
  function eeInverse(x, y) {  // Equal Earth -> [lon, lat] in degrees (Newton's method on y)
    let t = y;
    for (let i = 0; i < 12; i++) {
      const t2 = t * t, t6 = t2 * t2 * t2;
      const d = (t * (A1 + A2 * t2 + t6 * (A3 + A4 * t2)) - y) / (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2));
      t -= d;
      if (Math.abs(d) < 1e-9) break;
    }
    const t2 = t * t, t6 = t2 * t2 * t2;
    const lam = (M * x * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2))) / Math.cos(t);
    return [Math.max(-180, Math.min(180, lam / D2R)), Math.asin(Math.sin(t) / M) / D2R];
  }
  function unprojector(name, geo) {  // must mirror scripts/build_geo.py
    if (name === "indonesia") {
      const lon0 = 94.6, lat1 = 6.4, k = geo.w / (141.4 - 94.6);
      return (px, py) => [px / k + lon0, lat1 - py / k];
    }
    const xmax = eeForward(180, 0)[0], ymax = eeForward(0, 90)[1], s = geo.w / (2 * xmax), top = ymax * s;
    return (px, py) => eeInverse((px - geo.w / 2) / s, (top - py) / s);
  }
  const vec = (lon, lat) => {
    const l = lon * D2R, p = lat * D2R, c = Math.cos(p);
    return [c * Math.cos(l), c * Math.sin(l), Math.sin(p)];
  };

  // features: { id, name, rings: [{ ll: Float32Array lon,lat, v: Float32Array xyz, box }], centre: [lon, lat] }
  function toFeatures(name, geo) {
    const un = unprojector(name, geo);
    return geo.shapes.map((s) => {
      const rings = [];
      for (const part of s.d.split("M")) {
        const pts = part.replace(/Z/g, "").split("L").filter(Boolean).map((p) => p.split(",").map(Number));
        if (pts.length < 3) continue;
        const ll = new Float32Array(pts.length * 2), v = new Float32Array(pts.length * 3);
        let x0 = 999, y0 = 999, x1 = -999, y1 = -999;
        pts.forEach(([px, py], i) => {
          const [lon, lat] = un(px, py);
          ll[2 * i] = lon; ll[2 * i + 1] = lat;
          const [a, b, c] = vec(lon, lat);
          v[3 * i] = a; v[3 * i + 1] = b; v[3 * i + 2] = c;
          x0 = Math.min(x0, lon); x1 = Math.max(x1, lon); y0 = Math.min(y0, lat); y1 = Math.max(y1, lat);
        });
        rings.push({ ll, v, box: [x0, y0, x1, y1], n: pts.length });
      }
      // label point: mean direction of the largest ring (works across the antimeridian)
      let best = null;
      for (const r of rings) {
        const size = (r.box[2] - r.box[0]) * (r.box[3] - r.box[1]) * Math.cos(((r.box[1] + r.box[3]) / 2) * D2R);
        if (!best || size > best.size) best = { r, size };
      }
      let centre = [0, 0];
      if (best) {
        let a = 0, b = 0, c = 0;
        for (let i = 0; i < best.r.n; i++) { a += best.r.v[3 * i]; b += best.r.v[3 * i + 1]; c += best.r.v[3 * i + 2]; }
        centre = [Math.atan2(b, a) / D2R, Math.atan2(c, Math.hypot(a, b)) / D2R];
      }
      return { id: s.id, name: s.n, rings, centre };
    });
  }
  function graticule() {
    const lines = [];
    for (let lon = -180; lon < 180; lon += 30) {
      const v = []; for (let lat = -80; lat <= 80; lat += 4) v.push(vec(lon, lat)); lines.push(v);
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      const v = []; for (let lon = -180; lon <= 180; lon += 4) v.push(vec(lon, lat)); lines.push(v);
    }
    return lines;
  }
  function inRing(ll, n, lon, lat) {
    let inside = false;
    for (let i = 0, j = n - 1; i < n; j = i++) {
      const xi = ll[2 * i], yi = ll[2 * i + 1], xj = ll[2 * j], yj = ll[2 * j + 1];
      if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) inside = !inside;
    }
    return inside;
  }

  // ------------------------------------------------------------------ colours
  const cssVar = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  function rgb(c) {
    if (/^#[0-9a-f]{6}$/i.test(c)) return [1, 3, 5].map((i) => parseInt(c.slice(i, i + 2), 16));
    if (/^#[0-9a-f]{3}$/i.test(c)) return [1, 2, 3].map((i) => parseInt(c[i] + c[i], 16));
    const m = c.match(/\d+(\.\d+)?/g); return m ? m.slice(0, 3).map(Number) : [128, 128, 128];
  }
  const mix = (a, b, t) => `rgb(${a.map((x, i) => Math.round(x * t + b[i] * (1 - t))).join(",")})`;
  const rgba = (a, alpha) => `rgba(${a.join(",")},${alpha})`;
  const LEVELS = 5;
  const level = (v, max) => (v <= 0 ? 0 : Math.max(1, Math.ceil((LEVELS * Math.log1p(v)) / Math.log1p(max))));

  // ------------------------------------------------------------------ the widget
  async function mount(host) {
    const mode = host.dataset.globe;
    const read = (id) => { try { return JSON.parse(document.getElementById(id)?.textContent || "null"); } catch { return null; } };
    const values = read(host.dataset.values) || {};
    const top = (read(host.dataset.top) || []).slice(0, 10);
    const link = host.dataset.link || "";
    const unit = "items";
    const plural = (n) => `${n.toLocaleString()} ${n === 1 ? unit.replace(/s$/, "") : unit}`;
    let world, provinces = null;
    try {
      world = toFeatures("world", await shapes("world"));
      if (mode === "indonesia") provinces = toFeatures("indonesia", await shapes("indonesia"));
    } catch {
      host.innerHTML = '<div class="empty small">Map outlines could not be loaded.</div>';
      return;
    }
    const layer = provinces || world;  // the layer that carries the values
    const byId = Object.fromEntries(layer.map((f) => [f.id, f]));
    const max = Math.max(1, ...Object.values(values));
    const maxTop = Math.max(1, ...top.map((t) => t.count));
    const targets = top.map((t, i) => {
      const f = byId[t.shape || t.code] || byId[MAP_PARENT_FALLBACK[t.code]];
      return f ? { ...t, rank: i + 1, centre: f.centre } : null;
    }).filter(Boolean);
    const grat = graticule();

    // DOM: canvas, tooltip, callout, controls, stepper
    host.querySelector(".geo-loading")?.remove();
    const stage = document.createElement("div"); stage.className = "globe-stage";
    const canvas = document.createElement("canvas");
    canvas.setAttribute("role", "img"); canvas.setAttribute("aria-label", host.getAttribute("aria-label") || "Globe");
    canvas.tabIndex = 0;
    const tip = document.createElement("div"); tip.className = "geo-tip"; tip.hidden = true;
    const callout = document.createElement("div"); callout.className = "globe-callout"; callout.setAttribute("aria-live", "polite");
    const tools = document.createElement("div"); tools.className = "globe-tools";
    const btn = (label, title) => {
      const b = document.createElement("button"); b.type = "button"; b.className = "gbtn"; b.textContent = label;
      b.title = title; b.setAttribute("aria-label", title); tools.appendChild(b); return b;
    };
    const bPlay = btn(REDUCED ? "▶" : "❚❚", REDUCED ? "Play the tour" : "Pause the tour");
    const bIn = btn("+", "Zoom in"), bOut = btn("−", "Zoom out"), bReset = btn("⟲", "Reset view");
    stage.append(canvas, tip, callout, tools);
    const stepper = document.createElement("div"); stepper.className = "globe-steps"; stepper.setAttribute("role", "group");
    stepper.setAttribute("aria-label", mode === "indonesia" ? "Top 10 provinces" : "Top 10 countries");
    const stepBtns = targets.map((t, i) => {
      const b = document.createElement("button"); b.type = "button"; b.className = "gstep";
      b.innerHTML = `<b>${t.rank}</b>`; b.append(document.createTextNode(t.code.slice(-2)));
      b.title = `${t.name}: ${plural(t.count)}`;
      b.addEventListener("click", () => { pauseFor(12000); goTo(i); });
      stepper.appendChild(b); return b;
    });
    host.append(stage);
    if (targets.length) host.append(stepper);
    else { const e = document.createElement("div"); e.className = "muted small globe-empty"; e.textContent = mode === "indonesia" ? "No Indonesian provinces named in the last 30 days." : "No target countries named in the last 30 days."; host.append(e); }

    // view state
    const home = mode === "indonesia" ? { lon: 118, lat: -2, zoom: 2.7 } : { lon: targets[0]?.centre[0] ?? 20, lat: 15, zoom: 1 };
    const view = { ...home };
    let anim = null;         // { from, to, t0, dur }
    let idx = -1, hold = 0, pausedUntil = 0, playing = !REDUCED, hover = null, dragging = null;
    let vel = 0;             // spin momentum after a drag, degrees per frame
    let colors, W = 0, H = 0, dpr = 1;
    const ctx = canvas.getContext("2d");

    const readColors = () => {
      const sea = rgb(cssVar("--accent"));  // ocean and glow stay blue; the National view colours provinces warm
      const accent = rgb(cssVar(host.classList.contains("warm") ? "--series-2" : "--accent"));
      const base = rgb(cssVar("--surface-3")), s1 = rgb(cssVar("--surface-1")), s2 = rgb(cssVar("--surface-2"));
      colors = {
        accent: sea, ocean: mix(s2, s1, 0.6), oceanHi: mix(s2, sea, 0.9), rim: rgba(sea, 0.35), base: mix(base, s1, 0.9),
        land: mix(base, s1, 0.75), stroke: cssVar("--surface-1"), grid: rgba(rgb(cssVar("--text-muted")), 0.13),
        lv: [null, 0.3, 0.4, 0.58, 0.78, 1].map((t) => (t == null ? null : mix(accent, base, t))),
        ink: cssVar("--text-primary"), muted: cssVar("--text-muted"), hot: cssVar("--series-2"), s1: cssVar("--surface-1"),
      };
    };
    readColors();

    const resize = () => {
      const r = stage.getBoundingClientRect();
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      W = r.width; H = r.height;
      canvas.width = Math.round(W * dpr); canvas.height = Math.round(H * dpr);
      draw();
    };

    // orthographic projection around (view.lon, view.lat)
    let B; // basis
    const basis = () => {
      const l = view.lon * D2R, p = view.lat * D2R;
      B = { c: [Math.cos(p) * Math.cos(l), Math.cos(p) * Math.sin(l), Math.sin(p)],
            e: [-Math.sin(l), Math.cos(l), 0],
            n: [-Math.sin(p) * Math.cos(l), -Math.sin(p) * Math.sin(l), Math.cos(p)] };
    };
    const radius = () => (Math.min(W, H) / 2 - 16) * view.zoom;
    const cx = () => W / 2, cy = () => H / 2;
    function project(v, i, R, out) {
      const x = v[i] * B.e[0] + v[i + 1] * B.e[1] + v[i + 2] * B.e[2];
      const y = v[i] * B.n[0] + v[i + 1] * B.n[1] + v[i + 2] * B.n[2];
      const z = v[i] * B.c[0] + v[i + 1] * B.c[1] + v[i + 2] * B.c[2];
      out[0] = x; out[1] = y; out[2] = z;
      return z;
    }
    function unproject(sx, sy) {  // screen -> [lon, lat] or null off the globe
      const R = radius(), x = (sx - cx()) / R, y = (cy() - sy) / R, d = x * x + y * y;
      if (d > 1) return null;
      const z = Math.sqrt(1 - d);
      const p = [0, 1, 2].map((k) => x * B.e[k] + y * B.n[k] + z * B.c[k]);
      return [Math.atan2(p[1], p[0]) / D2R, Math.asin(Math.max(-1, Math.min(1, p[2]))) / D2R];
    }
    function hit(sx, sy) {
      const ll = unproject(sx, sy);
      if (!ll) return null;
      for (const f of layer) {
        for (const r of f.rings) {
          if (ll[0] < r.box[0] || ll[0] > r.box[2] || ll[1] < r.box[1] || ll[1] > r.box[3]) continue;
          if (inRing(r.ll, r.n, ll[0], ll[1])) return f;
        }
      }
      return null;
    }
    const tmp = [0, 0, 0];
    function tracePoly(r, R, X, Y) {  // fill path; points behind the horizon are pulled onto the rim
      let any = false;
      for (let i = 0; i < r.n; i++) {
        const z = project(r.v, 3 * i, R, tmp);
        let x = tmp[0], y = tmp[1];
        if (z > 0) any = true;
        else { const k = 1 / (Math.hypot(x, y) || 1); x *= k; y *= k; }
        const px = X + x * R, py = Y - y * R;
        i ? ctx.lineTo(px, py) : ctx.moveTo(px, py);
      }
      ctx.closePath();
      return any;
    }
    function screenOf(lon, lat) {
      const v = vec(lon, lat), R = radius();
      const z = project(v, 0, R, tmp);
      return { x: cx() + tmp[0] * R, y: cy() - tmp[1] * R, z };
    }

    function draw(now = performance.now()) {
      if (!W) return;
      basis();
      const R = radius(), X = cx(), Y = cy();
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, W, H);
      // atmosphere + ocean
      let g = ctx.createRadialGradient(X, Y, R * 0.92, X, Y, R * 1.12);
      g.addColorStop(0, colors.rim); g.addColorStop(1, rgba(colors.accent, 0));
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(X, Y, R * 1.12, 0, 2 * Math.PI); ctx.fill();
      g = ctx.createRadialGradient(X - R * 0.35, Y - R * 0.4, R * 0.1, X, Y, R);
      g.addColorStop(0, colors.oceanHi); g.addColorStop(1, colors.ocean);
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(X, Y, R, 0, 2 * Math.PI); ctx.fill();
      ctx.save(); ctx.beginPath(); ctx.arc(X, Y, R, 0, 2 * Math.PI); ctx.clip();
      // graticule
      ctx.strokeStyle = colors.grid; ctx.lineWidth = 1; ctx.beginPath();
      for (const line of grat) {
        let pen = false;
        for (const v of line) {
          const z = project(v, 0, R, tmp);
          if (z > 0) { const px = X + tmp[0] * R, py = Y - tmp[1] * R; pen ? ctx.lineTo(px, py) : ctx.moveTo(px, py); pen = true; } else pen = false;
        }
      }
      ctx.stroke();
      // land
      const paint = (feats, valued) => {
        for (const f of feats) {
          if (provinces && !valued && f.id === "ID") continue; // provinces are drawn instead
          const v = valued ? values[f.id] || 0 : 0;
          ctx.beginPath();
          let any = false;
          for (const r of f.rings) any = tracePoly(r, R, X, Y) || any;
          if (!any) continue;
          ctx.fillStyle = valued ? (v ? colors.lv[level(v, max)] : colors.land) : colors.base;
          ctx.fill("evenodd");
          ctx.strokeStyle = f === hover ? colors.ink : colors.stroke;
          ctx.lineWidth = f === hover ? 1.4 : 0.5;
          ctx.stroke();
        }
      };
      if (provinces) { paint(world, false); paint(provinces, true); } else paint(world, true);
      // sphere shading
      g = ctx.createRadialGradient(X - R * 0.3, Y - R * 0.35, R * 0.2, X, Y, R * 1.02);
      g.addColorStop(0, "rgba(255,255,255,0.05)"); g.addColorStop(0.7, "rgba(0,0,0,0)"); g.addColorStop(1, "rgba(0,0,0,0.28)");
      ctx.fillStyle = g; ctx.fillRect(X - R, Y - R, 2 * R, 2 * R);
      ctx.restore();
      // top-10 markers: pulsing rings, rank numbers; the current one is larger and named
      const t = REDUCED ? 0.35 : now / 1700;
      targets.forEach((m, i) => {
        const p = screenOf(m.centre[0], m.centre[1]);
        if (p.z <= 0.05) return;
        const cur = i === idx, size = 3 + 5 * Math.sqrt(m.count / maxTop);
        const phase = (t + i * 0.137) % 1;
        ctx.globalAlpha = Math.min(1, p.z * 3);
        ctx.strokeStyle = cur ? colors.hot : colors.ink; ctx.lineWidth = cur ? 2 : 1.2;
        for (const off of cur ? [0, 0.5] : [0]) {
          const ph = (phase + off) % 1;
          ctx.globalAlpha = Math.min(1, p.z * 3) * (1 - ph) * (cur ? 0.9 : 0.55);
          ctx.beginPath(); ctx.arc(p.x, p.y, size + ph * (cur ? 26 : 14), 0, 2 * Math.PI); ctx.stroke();
        }
        ctx.globalAlpha = Math.min(1, p.z * 3);
        ctx.fillStyle = cur ? colors.hot : colors.ink; ctx.strokeStyle = colors.s1; ctx.lineWidth = 2;
        ctx.beginPath(); ctx.arc(p.x, p.y, size, 0, 2 * Math.PI); ctx.fill(); ctx.stroke();
        ctx.font = `600 ${cur ? 12 : 10.5}px system-ui, sans-serif`; ctx.textBaseline = "middle";
        const label = cur ? `${m.rank}. ${m.name}` : String(m.rank);
        const tx = p.x + size + 5, tw = ctx.measureText(label).width;
        ctx.fillStyle = colors.s1; ctx.globalAlpha *= 0.75;
        ctx.fillRect(tx - 3, p.y - 8, tw + 6, 16);
        ctx.globalAlpha = Math.min(1, p.z * 3);
        ctx.fillStyle = cur ? colors.ink : colors.muted; ctx.fillText(label, tx, p.y);
      });
      ctx.globalAlpha = 1;
    }

    // ---------------------------------------------------------------- tour
    function setCallout(m) {
      callout.textContent = "";
      if (!m) { callout.hidden = true; return; }
      callout.hidden = false;
      const head = document.createElement("div"); head.className = "gc-head";
      const rank = document.createElement("span"); rank.className = "gc-rank"; rank.textContent = "#" + m.rank;
      const a = document.createElement("a"); a.href = link.replace("{code}", encodeURIComponent(m.code)); a.textContent = m.name;
      const n = document.createElement("span"); n.className = "gc-n"; n.textContent = plural(m.count);
      head.append(rank, a, n);
      callout.appendChild(head);
      if (m.related?.length) {
        const row = document.createElement("div"); row.className = "ent-row";
        for (const e of m.related) {
          const c = document.createElement("a"); c.className = "chip"; c.href = `/entities/${e.id}`;
          const k = document.createElement("span"); k.className = "t"; k.textContent = e.type;
          c.append(k, document.createTextNode(e.name)); row.appendChild(c);
        }
        callout.appendChild(row);
      }
    }
    function goTo(i) {
      if (!targets.length) return;
      idx = (i + targets.length) % targets.length;
      const m = targets[idx];
      stepBtns.forEach((b, k) => b.classList.toggle("on", k === idx));
      setCallout(m);
      // the target sits a little above the centre so the callout does not cover it
      const to = { lon: m.centre[0], lat: Math.max(-70, Math.min(70, m.centre[1] - 12 / view.zoom)), zoom: view.zoom };
      if (REDUCED) { Object.assign(view, to); draw(); return; }
      let dl = ((to.lon - view.lon + 540) % 360) - 180;  // shortest way round
      anim = { from: { ...view }, dl, to, t0: performance.now(), dur: 1500 };
      hold = performance.now() + 1500 + 4200;
      wake();
    }
    const pauseFor = (ms) => { pausedUntil = performance.now() + ms; };
    bPlay.addEventListener("click", () => {
      playing = !playing;
      bPlay.textContent = playing ? "❚❚" : "▶";
      const t = playing ? "Pause the tour" : "Play the tour";
      bPlay.title = t; bPlay.setAttribute("aria-label", t);
      if (playing) { pausedUntil = 0; hold = 0; if (REDUCED) goTo(idx + 1); }
      wake();
    });
    const zoomBy = (f) => { view.zoom = Math.max(0.8, Math.min(8, view.zoom * f)); pauseFor(8000); wake(); draw(); };
    bIn.addEventListener("click", () => zoomBy(1.4));
    bOut.addEventListener("click", () => zoomBy(1 / 1.4));
    bReset.addEventListener("click", () => { anim = null; Object.assign(view, home); idx = -1; setCallout(null); stepBtns.forEach((b) => b.classList.remove("on")); pauseFor(6000); wake(); draw(); });

    // ---------------------------------------------------------------- pointer
    canvas.addEventListener("pointerdown", (e) => {
      dragging = { x: e.clientX, y: e.clientY, lon: view.lon, lat: view.lat, moved: 0, last: e.clientX, t: performance.now() };
      canvas.setPointerCapture(e.pointerId);
      anim = null; vel = 0; pauseFor(10000);
    });
    canvas.addEventListener("pointermove", (e) => {
      const r = canvas.getBoundingClientRect(), sx = e.clientX - r.left, sy = e.clientY - r.top;
      if (dragging) {
        const k = 180 / (Math.PI * radius());
        const dx = e.clientX - dragging.x, dy = e.clientY - dragging.y;
        dragging.moved = Math.max(dragging.moved, Math.hypot(dx, dy));
        view.lon = dragging.lon - dx * k;
        view.lat = Math.max(-80, Math.min(80, dragging.lat + dy * k));
        const nowT = performance.now();
        vel = (-(e.clientX - dragging.last) * k) / Math.max(1, (nowT - dragging.t) / 16.7);
        dragging.last = e.clientX; dragging.t = nowT;
        tip.hidden = true;
        draw();
        return;
      }
      const f = hit(sx, sy);
      if (f !== hover) { hover = f; if (!running) draw(); }
      if (f) {
        const v = values[f.id] || 0;
        tip.textContent = `${f.name}: ${v ? plural(v) : "none"}`;
        tip.hidden = false;
        tip.style.left = Math.min(Math.max(sx + 12, 4), W - tip.offsetWidth - 4) + "px";
        tip.style.top = Math.max(sy - 34, 4) + "px";
        canvas.style.cursor = v && link ? "pointer" : "grab";
      } else { tip.hidden = true; canvas.style.cursor = "grab"; }
    });
    const endDrag = (e) => {
      if (!dragging) return;
      const click = dragging.moved < 4;
      dragging = null;
      if (!click) wake();  // let the spin coast
      else {
        vel = 0;
        const r = canvas.getBoundingClientRect(), f = hit(e.clientX - r.left, e.clientY - r.top);
        if (f && values[f.id] && link) location.href = link.replace("{code}", encodeURIComponent(f.id));
      }
    };
    canvas.addEventListener("pointerup", endDrag);
    canvas.addEventListener("pointercancel", () => { dragging = null; });
    canvas.addEventListener("pointerleave", () => { hover = null; tip.hidden = true; if (!running) draw(); });
    canvas.addEventListener("keydown", (e) => {
      const step = 10 / view.zoom;
      const k = { ArrowLeft: [-step, 0], ArrowRight: [step, 0], ArrowUp: [0, step], ArrowDown: [0, -step] }[e.key];
      if (k) { e.preventDefault(); view.lon += k[0]; view.lat = Math.max(-80, Math.min(80, view.lat + k[1])); pauseFor(10000); draw(); }
      else if (e.key === "+" || e.key === "=") zoomBy(1.4);
      else if (e.key === "-") zoomBy(1 / 1.4);
    });
    stage.addEventListener("pointerenter", () => pauseFor(1e9));
    stage.addEventListener("pointerleave", () => pauseFor(2500));

    // ---------------------------------------------------------------- frame loop (only while on screen)
    let running = false, onScreen = false;
    const ease = (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2);
    function frame(now) {
      if (!onScreen || document.hidden) { running = false; return; }
      if (anim) {
        const p = Math.min(1, (now - anim.t0) / anim.dur), e = ease(p);
        view.lon = anim.from.lon + anim.dl * e;
        view.lat = anim.from.lat + (anim.to.lat - anim.from.lat) * e;
        if (p >= 1) anim = null;
      } else if (!dragging && Math.abs(vel) > 0.01) {
        view.lon += vel; vel *= 0.95;
      } else if (!dragging && playing && now > pausedUntil) {
        if (targets.length) { if (now > hold) goTo(idx + 1); }
        else view.lon += 0.08;  // nothing to show: just turn slowly
      }
      draw(now);
      requestAnimationFrame(frame);
    }
    function wake() {
      if (REDUCED || running || !onScreen) return;
      running = true; requestAnimationFrame(frame);
    }
    new ResizeObserver(resize).observe(stage);
    new IntersectionObserver((es) => { onScreen = es.some((e) => e.isIntersecting); if (onScreen) wake(); }).observe(stage);
    document.addEventListener("visibilitychange", () => { if (!document.hidden) wake(); });
    const recolor = () => { readColors(); draw(); };
    window.addEventListener("jatmp-theme", recolor);
    matchMedia("(prefers-color-scheme: light)").addEventListener("change", recolor);
    resize();
    if (REDUCED && targets.length) goTo(0);
    else if (targets.length) { hold = performance.now() + 900; }
  }

  document.querySelectorAll(".globe[data-globe]").forEach(mount);
})();

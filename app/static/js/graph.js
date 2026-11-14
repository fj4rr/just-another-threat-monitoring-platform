/* JATMP relationship graph: a small force-directed SVG graph, no library and no CDN.
   <div data-graph="/api/items/12/graph"> is filled automatically. Click a node = side preview,
   double-click (or "o") = open its page, Enter = preview, drag = move, wheel / buttons = zoom.
   Layout: Fruchterman-Reingold with cooling, capped at 150 nodes by the API. */
(function () {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const IOC = new Set(["ip", "domain", "url", "md5", "sha1", "sha256"]);
  const KIND = {
    item: { color: "--series-1", r: 8, label: "Item" },
    malware: { color: "--series-2", r: 11, label: "Malware" },
    actor: { color: "--series-7", r: 11, label: "Threat actor" },
    cve: { color: "--series-4", r: 9, label: "CVE" },
    technique: { color: "--series-5", r: 7, label: "Technique" },
  };
  const VERDICT = { malicious: "--critical", suspicious: "--warning", clean: "--good" };

  const el = (name, attrs = {}, parent) => {
    const n = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (parent) parent.appendChild(n);
    return n;
  };
  const colorOf = (n) => css(IOC.has(n.kind) ? (VERDICT[n.verdict] || "--neutral-mark") : (KIND[n.kind] || KIND.item).color);
  const radiusOf = (n) => (n.center ? 14 : IOC.has(n.kind) ? 6 : (KIND[n.kind] || KIND.item).r);
  const short = (s, n = 24) => (s.length > n ? s.slice(0, n - 1) + "…" : s);

  // deterministic pseudo-random so the same graph always lays out the same way
  const rng = (seed) => () => ((seed = (seed * 1664525 + 1013904223) % 4294967296) / 4294967296);

  function initPositions(nodes) {
    const rand = rng(nodes.length * 7919 + 17);
    const order = ["item", "malware", "actor", "cve", "technique"];
    nodes.forEach((n, i) => {
      if (n.center) { n.x = 0; n.y = 0; return; }
      const ring = IOC.has(n.kind) ? 2.2 : 1 + order.indexOf(n.kind) * 0.25;
      const a = (i / nodes.length) * Math.PI * 2 + rand() * 0.6;
      n.x = Math.cos(a) * 120 * ring + (rand() - 0.5) * 20;
      n.y = Math.sin(a) * 120 * ring + (rand() - 0.5) * 20;
    });
  }

  function step(nodes, edges, k, temp) {
    for (const n of nodes) { n.dx = 0; n.dy = 0; }
    for (let i = 0; i < nodes.length; i++) {
      const a = nodes[i];
      for (let j = i + 1; j < nodes.length; j++) {
        const b = nodes[j];
        let dx = a.x - b.x, dy = a.y - b.y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 0.01) { dx = 0.1; dy = 0.1; d2 = 0.02; }
        const f = (k * k) / d2;
        a.dx += dx * f; a.dy += dy * f; b.dx -= dx * f; b.dy -= dy * f;
      }
    }
    for (const e of edges) {
      const a = e.s, b = e.t;
      const dx = a.x - b.x, dy = a.y - b.y;
      const d = Math.sqrt(dx * dx + dy * dy) || 0.1;
      const f = d / k;
      a.dx -= dx * f; a.dy -= dy * f; b.dx += dx * f; b.dy += dy * f;
    }
    for (const n of nodes) {
      if (n.center || n.fixed) continue;
      n.dx -= n.x * 0.02; n.dy -= n.y * 0.02; // gentle gravity keeps islands on screen
      const d = Math.sqrt(n.dx * n.dx + n.dy * n.dy) || 1;
      const m = Math.min(d, temp);
      n.x += (n.dx / d) * m; n.y += (n.dy / d) * m;
    }
  }

  function mount(host) {
    const url = host.dataset.graph;
    const card = host.closest(".graph-card") || host.parentElement;
    const legend = card.querySelector(".graph-legend");
    const moreBtn = card.querySelector("[data-graph-more]");
    let limit = Number(host.dataset.limit || 60);
    let view = { x: 0, y: 0, s: 1 };
    let svg, vp, data, nodes, edges, byId, raf;

    async function load() {
      host.classList.add("loading");
      try {
        const r = await fetch(`${url}?limit=${limit}`, { credentials: "same-origin" });
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        data = await r.json();
      } catch (err) {
        host.textContent = "";
        const p = document.createElement("div");
        p.className = "empty"; p.textContent = "Could not load the graph (" + err.message + ").";
        host.appendChild(p);
        return;
      } finally { host.classList.remove("loading"); }
      if (data.nodes.length < 2) {
        host.textContent = "";
        const p = document.createElement("div");
        p.className = "empty"; p.textContent = "Nothing linked yet: no entities, enrichment links or related items.";
        host.appendChild(p);
        return;
      }
      if (moreBtn) moreBtn.hidden = !(data.truncated && limit < 150);
      build();
    }

    function build() {
      cancelAnimationFrame(raf);
      nodes = data.nodes.map((n) => ({ ...n }));
      byId = new Map(nodes.map((n) => [n.id, n]));
      edges = data.edges.filter((e) => byId.has(e.source) && byId.has(e.target))
        .map((e) => ({ ...e, s: byId.get(e.source), t: byId.get(e.target) }));
      initPositions(nodes);
      host.textContent = "";
      svg = el("svg", { class: "graph-svg", role: "group", "aria-label": host.getAttribute("aria-label") || "Relationship graph" }, host);
      vp = el("g", { class: "viewport" }, svg);
      const gEdges = el("g", { class: "edges" }, vp);
      const gNodes = el("g", { class: "nodes" }, vp);
      for (const e of edges) {
        e.line = el("line", { class: `gedge k-${e.kind}` }, gEdges);
        el("title", {}, e.line).textContent = e.label;
      }
      for (const n of nodes) {
        const g = el("g", { class: "gnode" + (n.center ? " center" : ""), tabindex: "0", role: "button",
          "aria-label": `${n.kind}: ${n.label}. Enter to preview, O to open.` }, gNodes);
        const r = radiusOf(n);
        if (n.kind === "item") el("rect", { x: -r, y: -r, width: r * 2, height: r * 2, rx: 3 }, g);
        else if (IOC.has(n.kind)) el("rect", { x: -r, y: -r, width: r * 2, height: r * 2, transform: "rotate(45)" }, g);
        else el("circle", { r }, g);
        const t = el("text", { x: r + 4, y: 4 }, g);
        t.textContent = short(n.label, n.center ? 40 : 24);
        el("title", {}, g).textContent = `${n.kind}: ${n.label}` + (n.verdict ? ` (${n.verdict})` : "") + (n.source ? ` · ${n.source}` : "");
        n.g = g;
        bindNode(n);
      }
      paint();
      renderLegend();
      bindCanvas();
      const k = Math.sqrt((900 * 520) / nodes.length) * 0.75;
      let temp = 90, iter = 0;
      const total = 320;
      const frame = () => {
        const per = REDUCED ? total : 12;
        for (let i = 0; i < per && iter < total; i++, iter++) { step(nodes, edges, k, temp); temp *= 0.985; }
        draw();
        if (iter < total) raf = requestAnimationFrame(frame); else fit();
      };
      if (REDUCED) frame(); else { fit(); raf = requestAnimationFrame(frame); }
    }

    function paint() {
      for (const n of nodes) {
        const c = colorOf(n);
        n.g.querySelectorAll("circle, rect").forEach((s) => { s.setAttribute("fill", c); });
      }
    }

    function draw() {
      for (const e of edges) {
        e.line.setAttribute("x1", e.s.x); e.line.setAttribute("y1", e.s.y);
        e.line.setAttribute("x2", e.t.x); e.line.setAttribute("y2", e.t.y);
      }
      for (const n of nodes) n.g.setAttribute("transform", `translate(${n.x.toFixed(1)},${n.y.toFixed(1)})`);
    }

    function applyView() { vp.setAttribute("transform", `translate(${view.x},${view.y}) scale(${view.s})`); }

    function fit() {
      const w = host.clientWidth || 800, h = host.clientHeight || 480;
      let x0 = Infinity, y0 = Infinity, x1 = -Infinity, y1 = -Infinity;
      for (const n of nodes) { x0 = Math.min(x0, n.x); y0 = Math.min(y0, n.y); x1 = Math.max(x1, n.x); y1 = Math.max(y1, n.y); }
      const pad = 60;
      const s = Math.min(2, Math.max(0.2, Math.min(w / (x1 - x0 + pad * 2 || 1), h / (y1 - y0 + pad * 2 || 1))));
      view = { s, x: w / 2 - ((x0 + x1) / 2) * s, y: h / 2 - ((y0 + y1) / 2) * s };
      applyView();
    }

    function zoom(f, cx, cy) {
      const w = host.clientWidth, h = host.clientHeight;
      cx = cx ?? w / 2; cy = cy ?? h / 2;
      const s = Math.min(4, Math.max(0.15, view.s * f));
      view.x = cx - ((cx - view.x) * s) / view.s;
      view.y = cy - ((cy - view.y) * s) / view.s;
      view.s = s;
      applyView();
    }

    function highlight(n) {
      if (!n) { svg.classList.remove("focus"); nodes.forEach((m) => m.g.classList.remove("hi")); edges.forEach((e) => e.line.classList.remove("hi")); return; }
      svg.classList.add("focus");
      const near = new Set([n.id]);
      for (const e of edges) {
        const on = e.s === n || e.t === n;
        e.line.classList.toggle("hi", on);
        if (on) { near.add(e.s.id); near.add(e.t.id); }
      }
      nodes.forEach((m) => m.g.classList.toggle("hi", near.has(m.id)));
    }

    function toLocal(ev) {
      const r = svg.getBoundingClientRect();
      return { x: (ev.clientX - r.left - view.x) / view.s, y: (ev.clientY - r.top - view.y) / view.s };
    }

    function bindNode(n) {
      let down = null, moved = false;
      n.g.addEventListener("pointerdown", (ev) => {
        ev.stopPropagation();
        down = { x: ev.clientX, y: ev.clientY }; moved = false;
        n.g.setPointerCapture(ev.pointerId);
      });
      n.g.addEventListener("pointermove", (ev) => {
        if (!down) return;
        if (Math.abs(ev.clientX - down.x) + Math.abs(ev.clientY - down.y) > 4) moved = true;
        if (!moved) return;
        const p = toLocal(ev);
        n.x = p.x; n.y = p.y; n.fixed = true;
        draw();
      });
      n.g.addEventListener("pointerup", () => {
        if (down && !moved && window.JATMP?.openPreview) window.JATMP.openPreview(n.preview, n.g);
        down = null;
      });
      n.g.addEventListener("dblclick", () => { location.href = n.ref; });
      n.g.addEventListener("mouseenter", () => highlight(n));
      n.g.addEventListener("mouseleave", () => highlight(null));
      n.g.addEventListener("focus", () => highlight(n));
      n.g.addEventListener("blur", () => highlight(null));
      n.g.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") { ev.preventDefault(); window.JATMP?.openPreview?.(n.preview, n.g); }
        if (ev.key === "o" || ev.key === "O") location.href = n.ref;
      });
    }

    function bindCanvas() {
      let pan = null;
      svg.addEventListener("pointerdown", (ev) => { pan = { x: ev.clientX - view.x, y: ev.clientY - view.y }; svg.setPointerCapture(ev.pointerId); });
      svg.addEventListener("pointermove", (ev) => { if (!pan) return; view.x = ev.clientX - pan.x; view.y = ev.clientY - pan.y; applyView(); });
      svg.addEventListener("pointerup", () => { pan = null; });
      svg.addEventListener("wheel", (ev) => {
        ev.preventDefault();
        const r = svg.getBoundingClientRect();
        zoom(ev.deltaY < 0 ? 1.15 : 1 / 1.15, ev.clientX - r.left, ev.clientY - r.top);
      }, { passive: false });
    }

    function renderLegend() {
      if (!legend) return;
      legend.textContent = "";
      const kinds = new Set(nodes.map((n) => (IOC.has(n.kind) ? "ioc:" + (VERDICT[n.verdict] ? n.verdict : "other") : n.kind)));
      const add = (color, label, shape) => {
        const s = document.createElement("span");
        s.className = "lg";
        const sw = document.createElement("i");
        sw.className = "sw " + shape; sw.style.background = css(color);
        s.append(sw, document.createTextNode(label));
        legend.appendChild(s);
      };
      for (const [k, v] of Object.entries(KIND)) if (kinds.has(k)) add(v.color, v.label, k === "item" ? "sq" : "");
      for (const [v, c] of Object.entries(VERDICT)) if (kinds.has("ioc:" + v)) add(c, `IOC (${v})`, "dia");
      if (kinds.has("ioc:other")) add("--neutral-mark", "IOC (unknown / pending)", "dia");
    }

    card.addEventListener("click", (ev) => {
      const z = ev.target.closest("[data-graph-zoom]");
      if (z && svg) { const a = z.dataset.graphZoom; if (a === "fit") fit(); else zoom(a === "in" ? 1.25 : 0.8); }
      if (ev.target.closest("[data-graph-more]")) { limit = Math.min(150, limit * 2); load(); }
    });
    window.addEventListener("jatmp-theme", () => { if (nodes) { paint(); renderLegend(); } });
    load();
  }

  const start = () => document.querySelectorAll("[data-graph]").forEach(mount);
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();

/* JATMP choropleth maps (Geography page, dashboard card).
 *
 * <div class="geomap" data-map="world|indonesia" data-values="ID-of-a-json-script" data-link="/feed?country={code}"
 *      data-unit="items" aria-label="..."></div>
 *
 * Outlines are pre-projected SVG paths from Natural Earth (app/static/geo/*.json, built by scripts/build_geo.py),
 * so no projection library is needed. Values come from an inline <script type="application/json"> block.
 * Shapes with a value are links (keyboard focusable); a legend shows the scale.
 */
(() => {
  "use strict";
  const NS = "http://www.w3.org/2000/svg";
  const VER = document.querySelector('link[rel="stylesheet"][href*="app.css"]')?.href.split("v=")[1] || "1";
  const cache = {};
  const shapes = (name) => (cache[name] ||= fetch(`/static/geo/${name}.json?v=${VER}`, { credentials: "same-origin" })
    .then((r) => { if (!r.ok) throw new Error(r.status); return r.json(); }));
  const LEVELS = 5;
  const level = (v, max) => (v <= 0 ? 0 : Math.max(1, Math.ceil((LEVELS * Math.log1p(v)) / Math.log1p(max))));

  function el(tag, attrs = {}, parent) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (parent) parent.appendChild(n);
    return n;
  }

  function tooltip(host) {
    const tip = document.createElement("div");
    tip.className = "geo-tip";
    tip.hidden = true;
    host.appendChild(tip);
    return {
      show(text, evt) {
        tip.textContent = text;
        tip.hidden = false;
        const r = host.getBoundingClientRect();
        const x = (evt.clientX ?? r.left + r.width / 2) - r.left, y = (evt.clientY ?? r.top + 20) - r.top;
        tip.style.left = Math.min(Math.max(x + 12, 4), r.width - tip.offsetWidth - 4) + "px";
        tip.style.top = Math.max(y - 34, 4) + "px";
      },
      hide() { tip.hidden = true; },
    };
  }

  async function render(host) {
    let values = {};
    try { values = JSON.parse(document.getElementById(host.dataset.values)?.textContent || "{}"); } catch { /* empty map */ }
    const unit = host.dataset.unit || "items";
    const link = host.dataset.link || "";
    let geo;
    try { geo = await shapes(host.dataset.map); } catch (err) {
      host.innerHTML = '<div class="empty small">Map outlines could not be loaded.</div>';
      return;
    }
    const max = Math.max(1, ...Object.values(values));
    const svg = el("svg", { viewBox: `0 0 ${geo.w} ${geo.h}`, role: "img", class: "geo-svg",
                            "aria-label": host.getAttribute("aria-label") || "Map" });
    const tip = tooltip(host);
    const dots = [];
    for (const s of geo.shapes) {
      const v = values[s.id] || 0;
      const lvl = level(v, max);
      const label = `${s.n}: ${v ? v.toLocaleString() + " " + unit : "none"}`;
      let parent = svg;
      if (v && link) {
        parent = el("a", { href: link.replace("{code}", encodeURIComponent(s.id)), "aria-label": label }, svg);
      }
      const p = el("path", { d: s.d, class: `geo-shape lvl-${lvl}`, "data-code": s.id }, parent);
      el("title", {}, p).textContent = label;
      p.addEventListener("pointermove", (e) => tip.show(label, e));
      p.addEventListener("pointerleave", () => tip.hide());
      if (s.c && v) dots.push([s, v, lvl, label, parent]);
    }
    for (const [s, , lvl, label, parent] of dots) {  // tiny countries (Singapore, Bahrain...) as dots on top
      const c = el("circle", { cx: s.c[0], cy: s.c[1], r: 3.2, class: `geo-dot lvl-${lvl}` }, parent);
      el("title", {}, c).textContent = label;
      c.addEventListener("pointermove", (e) => tip.show(label, e));
      c.addEventListener("pointerleave", () => tip.hide());
    }
    host.querySelector(".geo-loading")?.remove();
    host.prepend(svg);
    const legend = document.createElement("div");
    legend.className = "geo-legend small muted";
    const span = (text, cls) => { const n = document.createElement("span"); if (cls) n.className = cls; n.textContent = text; legend.appendChild(n); };
    span("1");
    for (let i = 1; i <= LEVELS; i++) span("", `geo-sw lvl-${i}`);
    span(`${max.toLocaleString()} ${max === 1 ? unit.replace(/s$/, "") : unit}`);
    host.appendChild(legend);
  }

  document.querySelectorAll(".geomap[data-map]").forEach(render);
})();

/* JATMP motion layer: reveal-on-load, count-up KPIs, sparklines, threat radar, live refresh.
   Everything respects prefers-reduced-motion. Loaded after app.js. */
(function () {
  const J = window.JATMP;
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const esc = (s) => String(s).replace(/[<&>"]/g, (c) => ({ "<": "&lt;", "&": "&amp;", ">": "&gt;", '"': "&quot;" }[c]));
  const getJSON = async (url) => {
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) throw new Error(r.status);
    return r.json();
  };

  // staggered entrance for children of [data-reveal]
  J.reveal = (root = document) => {
    root.querySelectorAll("[data-reveal]").forEach((group) => {
      [...group.children].forEach((el, i) => {
        el.classList.add("reveal");
        el.style.setProperty("--i", Number(group.dataset.reveal || 0) + i);
      });
    });
  };

  // numbers count up from data-from to data-count
  J.countUp = (root = document) => {
    root.querySelectorAll("[data-count]").forEach((el) => {
      const target = Number(el.dataset.count) || 0;
      const from = Number(el.dataset.from || 0);
      if (REDUCED || target === from) { el.textContent = target.toLocaleString(); return; }
      const dur = 1300, t0 = performance.now();
      const step = (t) => {
        const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 4);
        el.textContent = Math.round(from + (target - from) * e).toLocaleString();
        if (p < 1) requestAnimationFrame(step);
      };
      requestAnimationFrame(step);
    });
  };

  // table meter bars grow in
  J.meters = (root = document) => {
    root.querySelectorAll(".meter > span[data-w]").forEach((s, i) => {
      s.style.width = s.dataset.w + "%";
      s.style.setProperty("--i", i);
    });
  };

  // small area sparkline that draws itself
  J.spark = (svg, values, color = "--series-1") => {
    if (!svg || !values || !values.length) return;
    const w = 200, h = 42, max = Math.max(...values, 1);
    const pts = values.map((v, i) => [(i / Math.max(values.length - 1, 1)) * w, h - 3 - (v / max) * (h - 8)]);
    const line = pts.map((p, i) => (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1)).join(" ");
    const c = css(color), id = "g" + Math.random().toString(36).slice(2, 8);
    svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
    svg.setAttribute("preserveAspectRatio", "none");
    svg.innerHTML =
      `<defs><linearGradient id="${id}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="${c}" stop-opacity=".32"/>` +
      `<stop offset="1" stop-color="${c}" stop-opacity="0"/></linearGradient></defs>` +
      `<path d="${line} L ${w} ${h} L 0 ${h} Z" fill="url(#${id})" class="spark-fill"/>` +
      `<path d="${line}" fill="none" stroke="${c}" stroke-width="1.6" vector-effect="non-scaling-stroke" pathLength="1" class="spark-line"/>`;
    const ln = svg.querySelector(".spark-line"), fill = svg.querySelector(".spark-fill");
    if (REDUCED) return;
    ln.style.strokeDasharray = "1"; ln.style.strokeDashoffset = "1";
    fill.style.opacity = "0"; fill.style.transition = "opacity 1s ease .8s";
    ln.style.transition = "stroke-dashoffset 1.6s cubic-bezier(.2,.7,.2,1) .2s";
    requestAnimationFrame(() => requestAnimationFrame(() => { ln.style.strokeDashoffset = "0"; fill.style.opacity = "1"; }));
  };

  // KPI sparklines from the daily timeline
  J.tileSparks = async () => {
    const svgs = document.querySelectorAll("svg.spark[data-series]");
    if (!svgs.length) return;
    const d = await getJSON("/api/stats/kpi_series?days=14");
    svgs.forEach((svg) => J.spark(svg, d[svg.dataset.series] || [], svg.dataset.color || "--series-1"));
  };

  // threat radar: trending families as blips; closer to centre = hotter, size = mentions
  J.radar = async (svg, legend) => {
    if (!svg) return;
    let rows = [];
    try { rows = await getJSON("/api/stats/trending?type=malware&limit=12"); } catch {}
    const tip = document.createElement("div");
    tip.className = "radar-tip";
    document.body.appendChild(tip);
    const period = 6;
    const draw = () => {
      const S = 400, C = S / 2, R = C - 18;
      svg.setAttribute("viewBox", `0 0 ${S} ${S}`);
      svg.style.setProperty("--period", period + "s");
      const accent = css("--series-1"), hot = css("--series-2"), surface = css("--surface-1");
      let html = `<defs>
        <radialGradient id="rg-bg"><stop offset="0" stop-color="${accent}" stop-opacity=".12"/><stop offset="1" stop-color="${accent}" stop-opacity="0"/></radialGradient>
        <linearGradient id="rg-sweep" gradientUnits="userSpaceOnUse" x1="${C - R * 0.64}" y1="${C - R * 0.77}" x2="${C}" y2="${C - R}">
          <stop offset="0" stop-color="${accent}" stop-opacity="0"/><stop offset="1" stop-color="${accent}" stop-opacity=".5"/></linearGradient>
      </defs><circle cx="${C}" cy="${C}" r="${R}" fill="url(#rg-bg)"/>`;
      [1, 0.75, 0.5, 0.25].forEach((f) => (html += `<circle class="ring" cx="${C}" cy="${C}" r="${R * f}"/>`));
      html += `<line class="axis" x1="${C - R}" y1="${C}" x2="${C + R}" y2="${C}"/><line class="axis" x1="${C}" y1="${C - R}" x2="${C}" y2="${C + R}"/>`;
      // 40° wedge trailing the leading edge, which starts pointing up and turns clockwise
      const a0 = -Math.PI / 2, a1 = a0 - (40 * Math.PI) / 180;
      html += `<g class="sweep"><path d="M ${C} ${C} L ${C + R * Math.cos(a1)} ${C + R * Math.sin(a1)} A ${R} ${R} 0 0 1 ${C + R * Math.cos(a0)} ${C + R * Math.sin(a0)} Z" fill="url(#rg-sweep)"/>` +
        `<line x1="${C}" y1="${C}" x2="${C}" y2="${C - R}" stroke="${accent}" stroke-width="1.5"/></g>`;
      if (!rows.length) {
        html += `<text x="${C}" y="${C + 30}" text-anchor="middle" class="lbl" style="--i:0">No trending families yet</text>`;
        svg.innerHTML = html;
        if (legend) legend.innerHTML = `<div class="muted small">Blips appear as malware families are mentioned.</div>`;
        return;
      }
      const max = Math.max(...rows.map((r) => r.score)), maxN = Math.max(...rows.map((r) => r.recent));
      const placed = [];
      rows.forEach((r, i) => {
        let h = 7;
        for (const ch of r.name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
        let deg = h % 360;
        // radius blends score (hotter = closer) with rank so tied scores still fan out
        const rank = rows.length > 1 ? i / (rows.length - 1) : 0;
        const rad = R * (0.14 + 0.78 * (0.55 * (1 - r.score / max) + 0.45 * rank));
        // nudge apart blips that would overlap
        for (let k = 0; k < 12 && placed.some((p) => Math.abs(p.deg - deg) < 14 && Math.abs(p.rad - rad) < 22); k++) deg = (deg + 17) % 360;
        placed.push({ deg, rad });
        const ang = ((deg - 90) * Math.PI) / 180;
        const x = C + rad * Math.cos(ang), y = C + rad * Math.sin(ang);
        const r0 = 3.5 + 4 * (r.recent / maxN);
        const col = r.is_new ? hot : accent;
        const d = ((deg / 360) * period).toFixed(2); // ping exactly when the sweep passes
        html += `<circle class="halo" cx="${x}" cy="${y}" stroke="${col}" style="--r0:${r0}px;--d:${d}s"/>` +
          `<circle class="blip" data-i="${i}" cx="${x}" cy="${y}" fill="${col}" stroke="${surface}" stroke-width="2" style="--r0:${r0}px;--d:${d}s"/>`;
        if (i < 6) {
          const right = x < C + R * 0.5;
          html += `<text class="lbl" x="${x + (right ? r0 + 7 : -(r0 + 7))}" y="${y + 4}" text-anchor="${right ? "start" : "end"}" style="--i:${i}">${esc(r.name)}</text>`;
        }
      });
      svg.innerHTML = html;
      svg.querySelectorAll(".blip").forEach((b) => {
        const r = rows[+b.dataset.i];
        b.addEventListener("mouseenter", () => {
          tip.innerHTML = `<strong>${esc(r.name)}</strong>${r.is_new ? " · new" : ""}<br>${esc(r.category || "other")} · ${r.recent} mention(s) in 7d · ${r.sources} source(s)<br>trend score ${r.score}`;
          tip.style.opacity = 1;
        });
        b.addEventListener("mousemove", (e) => { tip.style.left = e.clientX + 14 + "px"; tip.style.top = e.clientY + 14 + "px"; });
        b.addEventListener("mouseleave", () => (tip.style.opacity = 0));
        b.addEventListener("click", () => (location.href = `/entities/${r.id}`));
      });
      if (legend) {
        legend.innerHTML =
          `<div class="small"><span class="sw" style="background:${accent}"></span>trending` +
          `<span class="sw" style="background:${hot};margin-left:12px"></span>new this week</div>` +
          `<div class="muted small" style="margin-top:4px">Closer to centre = hotter · size = mentions</div>` +
          `<ol>${rows.slice(0, 8).map((r) => `<li><a href="/entities/${r.id}">${esc(r.name)}</a> <span class="muted small">${r.score}</span></li>`).join("")}</ol>`;
      }
    };
    draw();
    window.addEventListener("jatmp-theme", draw);
    J._radarRefresh = async () => {
      try { rows = await getJSON("/api/stats/trending?type=malware&limit=12"); draw(); } catch {}
    };
  };

  // refresh KPI numbers + radar periodically, with count-up between old and new values
  J.live = (intervalMs = 60000) => {
    const stamp = document.querySelector("[data-live-stamp]");
    const tick = async () => {
      try {
        const ov = await getJSON("/api/stats/overview?days=7");
        document.querySelectorAll("[data-kpi]").forEach((el) => {
          const v = ov[el.dataset.kpi];
          if (v === undefined || String(v) === el.dataset.count) return;
          el.dataset.from = el.dataset.count;
          el.dataset.count = v;
        });
        J.countUp();
        if (J._radarRefresh) J._radarRefresh();
        if (stamp) stamp.textContent = "updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
      } catch {}
    };
    setInterval(tick, intervalMs);
  };

  J.reveal();
  J.countUp();
  J.meters();
})();

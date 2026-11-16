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

  // threat radar: trending malware families, CVEs and threat actors as blips, one shape per type;
  // closer to the centre = hotter, size = mentions. Buttons [data-radar-type] show / hide a type.
  const RADAR_TYPES = {
    malware: { color: "--series-1", label: "malware family", limit: 8 },
    cve: { color: "--series-7", label: "vulnerability", limit: 6 },
    actor: { color: "--series-4", label: "threat actor", limit: 6 },
  };
  // shape centred on 0,0 with roughly the same visual weight as a circle of radius r
  const shapePath = (type, r) => {
    if (type === "cve") { const k = r * 1.3; return `M0 ${-k}L${k} 0L0 ${k}L${-k} 0Z`; }
    if (type === "actor") { const k = r * 1.35; return `M0 ${-k}L${k * 0.95} ${k * 0.7}L${-k * 0.95} ${k * 0.7}Z`; }
    return `M${-r} 0a${r} ${r} 0 1 0 ${2 * r} 0a${r} ${r} 0 1 0 ${-2 * r} 0Z`;
  };
  J.radar = async (svg, legend) => {
    if (!svg) return;
    const shown = new Set(Object.keys(RADAR_TYPES));
    let rows = [];
    const load = async () => {
      const lists = await Promise.all(Object.entries(RADAR_TYPES).map(([t, spec]) =>
        getJSON(`/api/stats/trending?type=${t}&limit=${spec.limit}`).then((l) => l.map((r) => ({ ...r, type: t }))).catch(() => [])));
      rows = lists.flat().sort((a, b) => b.score - a.score);
    };
    await load();
    const tip = document.createElement("div");
    tip.className = "radar-tip";
    document.body.appendChild(tip);
    const period = 6;
    const draw = () => {
      const S = 400, C = S / 2, R = C - 18;
      svg.setAttribute("viewBox", `0 0 ${S} ${S}`);
      svg.style.setProperty("--period", period + "s");
      const accent = css("--series-1"), surface = css("--surface-1"), ink = css("--text-primary");
      let html = `<defs>
        <radialGradient id="rg-bg"><stop offset="0" stop-color="${accent}" stop-opacity=".12"/><stop offset="1" stop-color="${accent}" stop-opacity="0"/></radialGradient>
        <linearGradient id="rg-sweep" gradientUnits="userSpaceOnUse" x1="${C - R * 0.64}" y1="${C - R * 0.77}" x2="${C}" y2="${C - R}">
          <stop offset="0" stop-color="${accent}" stop-opacity="0"/><stop offset="1" stop-color="${accent}" stop-opacity=".5"/></linearGradient>
      </defs><circle cx="${C}" cy="${C}" r="${R}" fill="url(#rg-bg)"/>`;
      [1, 0.75, 0.5, 0.25].forEach((f) => (html += `<circle class="ring" cx="${C}" cy="${C}" r="${R * f}"/>`));
      html += `<line class="axis" x1="${C - R}" y1="${C}" x2="${C + R}" y2="${C}"/><line class="axis" x1="${C}" y1="${C - R}" x2="${C}" y2="${C + R}"/>`;
      // axis key: distance from the centre is the trend score (hot inside, cooling outside)
      html += `<text class="axis-lbl" x="${C + 6}" y="${C + R - 6}" text-anchor="start">cooling</text>` +
        `<text class="axis-lbl" x="${C + 6}" y="${C + R * 0.5 + 4}" text-anchor="start">warm</text>` +
        `<text class="axis-lbl" x="${C + 6}" y="${C + 14}" text-anchor="start">hot</text>` +
        `<path class="axis-arrow" d="M ${C + R - 10} ${C + 20} L ${C + R - 10} ${C + 4} M ${C + R - 14} ${C + 9} L ${C + R - 10} ${C + 4} L ${C + R - 6} ${C + 9}"/>` +
        `<text class="axis-lbl" x="${C + R - 4}" y="${C + 32}" text-anchor="end">trend score</text>`;
      // 40° wedge trailing the leading edge, which starts pointing up and turns clockwise
      const a0 = -Math.PI / 2, a1 = a0 - (40 * Math.PI) / 180;
      html += `<g class="sweep"><path d="M ${C} ${C} L ${C + R * Math.cos(a1)} ${C + R * Math.sin(a1)} A ${R} ${R} 0 0 1 ${C + R * Math.cos(a0)} ${C + R * Math.sin(a0)} Z" fill="url(#rg-sweep)"/>` +
        `<line x1="${C}" y1="${C}" x2="${C}" y2="${C - R}" stroke="${accent}" stroke-width="1.5"/></g>`;
      const vis = rows.filter((r) => shown.has(r.type));
      if (!vis.length) {
        html += `<text x="${C}" y="${C + 30}" text-anchor="middle" class="lbl" style="--i:0">Nothing trending yet</text>`;
        svg.innerHTML = html;
        if (legend) legend.innerHTML = `<div class="muted small">Blips appear as families, CVEs and actors are mentioned.</div>`;
        return;
      }
      const max = Math.max(...vis.map((r) => r.score)), maxN = Math.max(...vis.map((r) => r.recent));
      const placed = [];
      vis.forEach((r, i) => {
        let h = 7;
        for (const ch of r.type + r.name) h = (h * 31 + ch.charCodeAt(0)) >>> 0;
        let deg = h % 360;
        // radius blends score (hotter = closer) with rank so tied scores still fan out
        const rank = vis.length > 1 ? i / (vis.length - 1) : 0;
        const rad = R * (0.14 + 0.78 * (0.55 * (1 - r.score / max) + 0.45 * rank));
        // nudge apart blips that would overlap
        for (let k = 0; k < 14 && placed.some((p) => Math.abs(p.deg - deg) < 14 && Math.abs(p.rad - rad) < 22); k++) deg = (deg + 17) % 360;
        placed.push({ deg, rad });
        const ang = ((deg - 90) * Math.PI) / 180;
        const x = C + rad * Math.cos(ang), y = C + rad * Math.sin(ang);
        const r0 = 3.5 + 4 * (r.recent / maxN);
        const col = css(RADAR_TYPES[r.type].color);
        const d = ((deg / 360) * period).toFixed(2); // ping exactly when the sweep passes
        html += `<circle class="halo" cx="${x}" cy="${y}" stroke="${col}" style="--r0:${r0}px;--d:${d}s"/>` +
          `<g transform="translate(${x.toFixed(1)} ${y.toFixed(1)})">` +
          (r.is_new ? `<circle class="new-ring" r="${(r0 + 4.5).toFixed(1)}" stroke="${ink}"/>` : "") +
          `<path class="blip" data-i="${i}" d="${shapePath(r.type, r0)}" fill="${col}" stroke="${surface}" stroke-width="2" style="--d:${d}s"/></g>`;
        if (i < 6) {
          const right = x < C + R * 0.5;
          html += `<text class="lbl" x="${x + (right ? r0 + 8 : -(r0 + 8))}" y="${y + 4}" text-anchor="${right ? "start" : "end"}" style="--i:${i}">${esc(r.name)}</text>`;
        }
      });
      svg.innerHTML = html;
      svg.querySelectorAll(".blip").forEach((b) => {
        const r = vis[+b.dataset.i];
        b.addEventListener("mouseenter", () => {
          const kind = r.type === "malware" ? (r.category || "other") + " malware" : r.type === "actor" ? `${r.category || "unclassified"} actor` : "vulnerability";
          tip.innerHTML = `<strong>${esc(r.name)}</strong>${r.is_new ? " · new this week" : ""}<br>${esc(kind)} · ${r.recent} mention(s) in 7d · ${r.sources} source(s)<br>trend score ${r.score}`;
          tip.style.opacity = 1;
        });
        b.addEventListener("mousemove", (e) => { tip.style.left = e.clientX + 14 + "px"; tip.style.top = e.clientY + 14 + "px"; });
        b.addEventListener("mouseleave", () => (tip.style.opacity = 0));
        b.addEventListener("click", () => (location.href = `/entities/${r.id}`));
      });
      if (legend) {
        const icon = (t) => `<svg class="shape-ico" viewBox="-8 -8 16 16" aria-hidden="true"><path d="${shapePath(t, 5)}" fill="${css(RADAR_TYPES[t].color)}"/></svg>`;
        legend.innerHTML =
          `<div class="key small">${Object.keys(RADAR_TYPES).map((t) => `<span>${icon(t)}${t === "cve" ? "CVE" : t === "actor" ? "actor" : "malware"}</span>`).join("")}` +
          `<span><svg class="shape-ico" viewBox="-8 -8 16 16" aria-hidden="true"><circle r="6" class="new-ring" stroke="${ink}"/></svg>new this week</span></div>` +
          `<div class="size-key small muted"><span class="dot" style="width:6px;height:6px"></span>` +
          `<span class="dot" style="width:12px;height:12px"></span>size = mentions</div>` +
          `<ol>${vis.slice(0, 8).map((r) => `<li>${icon(r.type)}<a href="/entities/${r.id}">${esc(r.name)}</a> <span class="muted small">${r.score}</span></li>`).join("")}</ol>`;
      }
    };
    draw();
    document.querySelectorAll("[data-radar-type]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const t = btn.dataset.radarType;
        if (shown.has(t) && shown.size === 1) return; // keep at least one type
        shown.has(t) ? shown.delete(t) : shown.add(t);
        btn.setAttribute("aria-pressed", String(shown.has(t)));
        draw();
      });
    });
    window.addEventListener("jatmp-theme", draw);
    J._radarRefresh = async () => { await load(); draw(); };
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

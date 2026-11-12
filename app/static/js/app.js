/* JATMP front-end helpers: CSRF-aware fetch, action buttons, theme, charts. */
(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";

  // ---------- theme
  const saved = (() => { try { return localStorage.getItem("jatmp-theme"); } catch { return null; } })();
  if (saved) document.documentElement.dataset.theme = saved;
  document.addEventListener("click", (e) => {
    const t = e.target.closest("[data-theme-toggle]");
    if (!t) return;
    const cur = document.documentElement.dataset.theme ||
      (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");
    const next = cur === "dark" ? "light" : "dark";
    document.documentElement.dataset.theme = next;
    try { localStorage.setItem("jatmp-theme", next); } catch {}
    window.dispatchEvent(new Event("jatmp-theme"));
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-menu]")) document.body.classList.toggle("nav-open");
  });

  // ---------- toast
  function toast(msg, ms = 4000) {
    const el = document.createElement("div");
    el.className = "toast";
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.remove(), ms);
  }

  async function api(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(body || {}),
      credentials: "same-origin",
    });
    let data = {};
    try { data = await res.json(); } catch {}
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }

  // <button data-post="/api/..." data-target="#el" data-busy="Working…" data-reload>
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-post]");
    if (!btn) return;
    e.preventDefault();
    const label = btn.innerHTML;
    btn.disabled = true;
    btn.textContent = btn.dataset.busy || "Working…";
    try {
      const data = await api(btn.dataset.post);
      if (btn.dataset.target && data.html) {
        document.querySelector(btn.dataset.target).innerHTML = data.html;
      }
      if (data.message) toast(data.message);
      if ("watching" in data) btn.dataset.watching = data.watching;
      if (btn.dataset.reload !== undefined) setTimeout(() => location.reload(), 600);
    } catch (err) {
      toast("Error: " + err.message, 6000);
    } finally {
      btn.disabled = false;
      btn.innerHTML = "watching" in btn.dataset
        ? (btn.dataset.watching === "true" ? "★ Watching" : "☆ Watch") : label;
    }
  });

  // ask form
  document.addEventListener("submit", async (e) => {
    const f = e.target.closest("[data-ask]");
    if (!f) return;
    e.preventDefault();
    const q = f.querySelector("[name=question]").value.trim();
    if (!q) return;
    const out = document.querySelector(f.dataset.ask);
    const btn = f.querySelector("button");
    btn.disabled = true;
    out.innerHTML = '<p class="muted">Thinking…</p>';
    try {
      const data = await api("/api/insights/ask", { question: q });
      out.innerHTML = data.html;
    } catch (err) {
      out.innerHTML = "";
      toast("Error: " + err.message, 6000);
    } finally { btn.disabled = false; }
  });

  // ---------- charts
  const css = (v) => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
  const SERIES = () => [1, 2, 3, 4, 5, 6, 7, 8].map((i) => css(`--series-${i}`));
  const charts = [];

  function baseOptions(extra = {}) {
    const grid = css("--grid"), muted = css("--text-muted"), text = css("--text-secondary");
    return Object.assign({
      responsive: true, maintainAspectRatio: false,
      animation: REDUCED ? false : {
        duration: 900, easing: "easeOutQuart",
        delay: (ctx) => (ctx.type === "data" && ctx.mode === "default" ? ctx.dataIndex * 18 + ctx.datasetIndex * 90 : 0),
      },
      interaction: { mode: "index", intersect: false },
      plugins: {
        legend: { labels: { color: text, boxWidth: 10, boxHeight: 10, usePointStyle: true, pointStyle: "rectRounded" } },
        tooltip: { backgroundColor: css("--surface-3"), titleColor: css("--text-primary"), bodyColor: css("--text-primary"),
                   borderColor: css("--border"), borderWidth: 1, padding: 10, boxPadding: 4 },
      },
      scales: {
        x: { grid: { color: grid, drawTicks: false }, border: { display: false }, ticks: { color: muted, maxRotation: 0, autoSkipPadding: 16 } },
        y: { grid: { color: grid, drawTicks: false }, border: { display: false }, ticks: { color: muted, precision: 0, padding: 6 }, beginAtZero: true },
      },
    }, extra);
  }

  function make(el, cfgFn) {
    if (!window.Chart || !el) return;
    const entry = { el, cfgFn, chart: null };
    const draw = () => {
      if (entry.chart) entry.chart.destroy();
      entry.chart = new Chart(el, cfgFn());
    };
    entry.draw = draw;
    charts.push(entry);
    // draw when scrolled into view so the entry animation is actually seen
    if (REDUCED || !("IntersectionObserver" in window)) { draw(); return entry; }
    const io = new IntersectionObserver((es) => {
      if (es.some((e) => e.isIntersecting)) { io.disconnect(); draw(); }
    }, { threshold: 0.15 });
    io.observe(el);
    return entry;
  }
  window.addEventListener("jatmp-theme", () => charts.forEach((c) => c.draw()));
  matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => charts.forEach((c) => c.draw()));

  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;

  async function getJSON(url) {
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }
  const shortDate = (s) => { const d = new Date(s + "T00:00:00"); return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }); };
  const emptyNote = (el, msg) => { el.parentElement.innerHTML = `<div class="empty">${msg}</div>`; };

  const JATMP = {
    toast, api,

    async timeline(el, days = 30) {
      const d = await getJSON(`/api/stats/timeline?days=${days}`);
      const total = Object.values(d.series).flat().reduce((a, b) => a + b, 0);
      if (!total) return emptyNote(el, "No items collected yet – run the collectors from Settings.");
      const names = { news: "News", social: "Social", intel: "Threat intel" };
      make(el, () => {
        const S = SERIES();
        const surface = css("--surface-1");
        return {
          type: "bar",
          data: { labels: d.labels.map(shortDate), datasets: ["news", "social", "intel"].map((k, i) => ({
            label: names[k], data: d.series[k], backgroundColor: S[i], borderColor: surface, borderWidth: { top: 2 },
            borderSkipped: false, borderRadius: 3, maxBarThickness: 18 })) },
          options: baseOptions({ scales: { ...baseOptions().scales, x: { ...baseOptions().scales.x, stacked: true },
                                           y: { ...baseOptions().scales.y, stacked: true } } }),
        };
      });
    },

    async trendLines(el, limit = 5, days = 30) {
      const d = await getJSON(`/api/stats/trending_timeline?limit=${limit}&days=${days}`);
      if (!d.series.length) return emptyNote(el, "No malware families detected yet.");
      make(el, () => {
        const S = SERIES();
        return {
          type: "line",
          data: { labels: d.labels.map(shortDate), datasets: d.series.map((s, i) => ({
            label: s.name, data: s.data, borderColor: S[i], backgroundColor: S[i], borderWidth: 2,
            pointRadius: 0, pointHoverRadius: 5, pointHoverBorderColor: css("--surface-1"), pointHoverBorderWidth: 2, cubicInterpolationMode: "monotone" })) },
          options: baseOptions(),
        };
      });
    },

    async hbar(el, url, { labelKey = "name", valueKey = "count", link = null, color = 1, empty = "No data yet." } = {}) {
      const rows = await getJSON(url);
      if (!rows.length) return emptyNote(el, empty);
      make(el, () => ({
        type: "bar",
        data: { labels: rows.map((r) => r[labelKey]), datasets: [{ label: "Mentions", data: rows.map((r) => r[valueKey]),
          backgroundColor: css(`--series-${color}`), borderRadius: 4, borderSkipped: "start", maxBarThickness: 16 }] },
        options: baseOptions({
          indexAxis: "y", interaction: { mode: "nearest", axis: "y", intersect: false },
          plugins: { ...baseOptions().plugins, legend: { display: false } },
          scales: { x: { ...baseOptions().scales.x, beginAtZero: true, ticks: { ...baseOptions().scales.x.ticks, precision: 0 } },
                    y: { ...baseOptions().scales.y, grid: { display: false }, ticks: { color: css("--text-secondary"), autoSkip: false } } },
          onClick: link ? (_e, els) => { if (els[0]) location.href = link(rows[els[0].index]); } : undefined,
          onHover: link ? (e, els) => { e.native.target.style.cursor = els[0] ? "pointer" : "default"; } : undefined,
        }),
      }));
    },

    async sources(el, days = 7) {
      const rows = await getJSON(`/api/stats/sources?days=${days}`);
      if (!rows.length) return emptyNote(el, "No items in this period.");
      const cats = ["news", "social", "intel"], names = { news: "News", social: "Social", intel: "Threat intel" };
      make(el, () => {
        const S = SERIES();
        return {
          type: "bar",
          data: { labels: rows.map((r) => r.name), datasets: cats.map((c, i) => ({
            label: names[c], data: rows.map((r) => (r.category === c ? r.count : null)), backgroundColor: S[i],
            borderRadius: 4, borderSkipped: "start", maxBarThickness: 14, grouped: false })) },
          options: baseOptions({
            indexAxis: "y", interaction: { mode: "nearest", axis: "y", intersect: false },
            plugins: { ...baseOptions().plugins, tooltip: { ...baseOptions().plugins.tooltip, filter: (i) => i.raw !== null } },
            scales: { x: { ...baseOptions().scales.x, beginAtZero: true },
                      y: { ...baseOptions().scales.y, grid: { display: false }, ticks: { color: css("--text-secondary"), autoSkip: false } } },
          }),
        };
      });
    },

    async iocs(el, days = 30) {
      const rows = await getJSON(`/api/stats/iocs?days=${days}`);
      if (!rows.length) return emptyNote(el, "No IOCs extracted yet.");
      make(el, () => {
        const surface = css("--surface-1");
        const ds = [["malicious", "Malicious", "--critical"], ["suspicious", "Suspicious", "--warning"], ["other", "Clean / unknown / pending", "--neutral-mark"]];
        return {
          type: "bar",
          data: { labels: rows.map((r) => r.type.toUpperCase()), datasets: ds.map(([k, label, v]) => ({
            label, data: rows.map((r) => r[k]), backgroundColor: css(v), borderColor: surface, borderWidth: { right: 2 },
            borderSkipped: false, borderRadius: 3, maxBarThickness: 16 })) },
          options: baseOptions({
            indexAxis: "y", interaction: { mode: "index", axis: "y", intersect: false },
            scales: { x: { ...baseOptions().scales.x, stacked: true }, y: { ...baseOptions().scales.y, stacked: true, grid: { display: false } } },
          }),
        };
      });
    },

    async entityLine(el, id, days = 60) {
      const d = await getJSON(`/api/entities/${id}/timeline?days=${days}`);
      make(el, () => ({
        type: "bar",
        data: { labels: d.labels.map(shortDate), datasets: [{ label: "Mentions", data: d.data,
          backgroundColor: css("--series-1"), borderRadius: 3, maxBarThickness: 12 }] },
        options: baseOptions({ plugins: { ...baseOptions().plugins, legend: { display: false } } }),
      }));
    },
  };
  window.JATMP = JATMP;
})();

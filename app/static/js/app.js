/* JATMP front-end helpers: CSRF-aware fetch, action buttons, theme, navigation, charts.
   No inline event handlers anywhere (strict CSP); behaviour is attached via data-attributes:
     [data-post]          POST to a JSON endpoint, show toast / inject HTML / reload
     [data-ask]           Q&A form
     [data-confirm]       confirm() before a form or button submits
     [data-autosubmit]    submit the parent form on change
     [data-copy-selector] copy the text of matching elements to the clipboard
     details.pop          modal-style popover (click backdrop / Esc / [data-pop-close] to close)
     [data-menu] / [data-nav-close]  mobile sidebar */
(function () {
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content || "";
  const REDUCED = matchMedia("(prefers-reduced-motion: reduce)").matches;

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

  // ---------- mobile navigation
  const setNav = (open) => {
    document.body.classList.toggle("nav-open", open);
    const bd = document.querySelector(".nav-backdrop");
    if (bd) bd.hidden = !open;
    document.querySelectorAll("[data-menu]").forEach((b) => b.setAttribute("aria-expanded", String(open)));
  };
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-menu]")) return setNav(!document.body.classList.contains("nav-open"));
    if (e.target.closest("[data-nav-close]")) return setNav(false);
    if (e.target.closest(".side .nav a")) setNav(false);
  });

  // ---------- back button (falls back to the dashboard when there is no history)
  document.addEventListener("click", (e) => {
    if (!e.target.closest("[data-back]")) return;
    e.preventDefault();
    if (history.length > 1 && document.referrer && new URL(document.referrer).origin === location.origin) history.back();
    else location.href = "/";
  });

  // ---------- keyboard: "/" focuses search, Esc closes overlays
  document.addEventListener("keydown", (e) => {
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "") ||
      document.activeElement?.isContentEditable;
    if (e.key === "/" && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
      const s = document.getElementById("global-search");
      if (s) { e.preventDefault(); s.focus(); s.select(); }
    }
    if (e.key === "Escape") {
      setNav(false);
      document.querySelectorAll("details.pop[open]").forEach((d) => d.removeAttribute("open"));
    }
  });

  // ---------- popovers (details.pop): one open at a time, backdrop click closes
  document.addEventListener("toggle", (e) => {
    const d = e.target;
    if (!(d instanceof HTMLDetailsElement) || !d.classList.contains("pop") || !d.open) return;
    document.querySelectorAll("details.pop[open]").forEach((o) => { if (o !== d) o.removeAttribute("open"); });
    const first = d.querySelector("input:not([type=hidden]), select, textarea, button:not([data-pop-close])");
    if (first) setTimeout(() => first.focus(), 0);
  }, true);
  document.addEventListener("click", (e) => {
    const close = e.target.closest("[data-pop-close]");
    if (close) { e.preventDefault(); close.closest("details.pop")?.removeAttribute("open"); return; }
    // a click on the <details> element itself (outside the card) is the backdrop
    if (e.target instanceof HTMLDetailsElement && e.target.classList.contains("pop")) e.target.removeAttribute("open");
  });

  // ---------- confirmations & auto-submit (replaces inline onclick/onsubmit/onchange)
  document.addEventListener("click", (e) => {
    const b = e.target.closest("button[data-confirm]");
    if (b && !confirm(b.dataset.confirm)) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true);
  document.addEventListener("submit", (e) => {
    const f = e.target.closest("form[data-confirm]");
    if (f && !confirm(f.dataset.confirm)) e.preventDefault();
  }, true);
  document.addEventListener("change", (e) => {
    const el = e.target.closest("[data-autosubmit]");
    if (el && el.form) el.form.requestSubmit ? el.form.requestSubmit() : el.form.submit();
  });

  // ---------- toast
  function toast(msg, ms = 4000) {
    const host = document.getElementById("toasts") || document.body;
    const el = document.createElement("div");
    el.className = "toast";
    el.textContent = msg;
    host.appendChild(el);
    setTimeout(() => { el.classList.add("out"); setTimeout(() => el.remove(), 250); }, ms);
  }

  // ---------- clipboard
  document.addEventListener("click", async (e) => {
    const b = e.target.closest("[data-copy-selector]");
    if (!b) return;
    e.preventDefault();
    const items = [...document.querySelectorAll(b.dataset.copySelector)].map((a) => a.textContent.trim()).filter(Boolean);
    if (!items.length) return toast("Nothing to copy");
    try {
      await navigator.clipboard.writeText(items.join("\n"));
      toast(`Copied ${items.length} ${b.dataset.copyLabel || "line"}(s)`);
    } catch { toast("Clipboard blocked by the browser", 5000); }
  });

  async function api(url, body) {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-CSRF-Token": csrf },
      body: JSON.stringify(body || {}),
      credentials: "same-origin",
    });
    let data = {};
    try { data = await res.json(); } catch {}
    if (res.status === 401) { location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search); throw new Error("login required"); }
    if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`);
    return data;
  }

  // <button data-post="/api/..." data-target="#el" data-busy="Working…" data-reload>
  document.addEventListener("click", async (e) => {
    const btn = e.target.closest("[data-post]");
    if (!btn || btn.disabled) return;
    e.preventDefault();
    const label = btn.innerHTML;
    btn.disabled = true;
    btn.setAttribute("aria-busy", "true");
    btn.textContent = btn.dataset.busy || "Working…";
    try {
      const data = await api(btn.dataset.post);
      if (btn.dataset.target && data.html) {
        const target = document.querySelector(btn.dataset.target);
        if (target) { target.innerHTML = data.html; target.classList.add("flash"); setTimeout(() => target.classList.remove("flash"), 1200); }
      }
      if (data.message) toast(data.message);
      if ("watching" in data) { btn.dataset.watching = data.watching; toast(data.watching ? "Added to your watchlist" : "Removed from your watchlist"); }
      if (btn.dataset.reload !== undefined) setTimeout(() => location.reload(), 600);
    } catch (err) {
      toast("Error: " + err.message, 6000);
    } finally {
      btn.disabled = false;
      btn.removeAttribute("aria-busy");
      btn.innerHTML = "watching" in btn.dataset
        ? (btn.dataset.watching === "true" ? "★ Watching" : "☆ Watch") : label;
    }
  });

  // ask form
  document.addEventListener("submit", async (e) => {
    const f = e.target.closest("[data-ask]");
    if (!f) return;
    e.preventDefault();
    const input = f.querySelector("[name=question]");
    const q = input.value.trim();
    if (!q) return;
    const out = document.querySelector(f.dataset.ask);
    const btn = f.querySelector("button");
    btn.disabled = true; btn.setAttribute("aria-busy", "true");
    out.innerHTML = '<p class="muted">Thinking…</p>';
    try {
      const data = await api("/api/insights/ask", { question: q });
      const qEl = document.createElement("p");
      qEl.className = "muted small"; qEl.textContent = "Q: " + q;
      out.innerHTML = data.html;
      out.prepend(qEl);
      input.value = "";
    } catch (err) {
      out.innerHTML = "";
      toast("Error: " + err.message, 6000);
    } finally { btn.disabled = false; btn.removeAttribute("aria-busy"); }
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
    if (!el) return;
    if (!window.Chart) { emptyNote(el, "Charts unavailable (Chart.js failed to load)."); return; }
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

  async function getJSON(url) {
    const r = await fetch(url, { credentials: "same-origin" });
    if (!r.ok) throw new Error(r.status);
    return r.json();
  }
  const shortDate = (s) => { const d = new Date(s + "T00:00:00"); return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }); };
  const emptyNote = (el, msg) => { const p = el.parentElement; p.innerHTML = ""; const d = document.createElement("div"); d.className = "empty"; d.textContent = msg; p.appendChild(d); };
  const guard = (fn) => async (el, ...args) => {
    if (!el) return;
    try { await fn(el, ...args); } catch (err) { emptyNote(el, "Could not load data (" + err.message + ")"); }
  };

  const JATMP = {
    toast, api,

    timeline: guard(async (el, days = 30) => {
      const d = await getJSON(`/api/stats/timeline?days=${days}`);
      const total = Object.values(d.series).flat().reduce((a, b) => a + b, 0);
      if (!total) return emptyNote(el, "No items collected yet – run the collectors from Settings.");
      const names = { news: "News", social: "Social", intel: "Threat intel" };
      make(el, () => {
        const S = SERIES();
        const surface = css("--surface-1");
        const base = baseOptions();
        return {
          type: "bar",
          data: { labels: d.labels.map(shortDate), datasets: ["news", "social", "intel"].map((k, i) => ({
            label: names[k], data: d.series[k], backgroundColor: S[i], borderColor: surface, borderWidth: { top: 2 },
            borderSkipped: false, borderRadius: 3, maxBarThickness: 18 })) },
          options: baseOptions({ scales: { x: { ...base.scales.x, stacked: true }, y: { ...base.scales.y, stacked: true } } }),
        };
      });
    }),

    trendLines: guard(async (el, limit = 5, days = 30) => {
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
    }),

    hbar: guard(async (el, url, { labelKey = "name", valueKey = "count", link = null, color = 1, empty = "No data yet." } = {}) => {
      const rows = await getJSON(url);
      if (!rows.length) return emptyNote(el, empty);
      make(el, () => {
        const base = baseOptions();
        return {
          type: "bar",
          data: { labels: rows.map((r) => r[labelKey]), datasets: [{ label: "Mentions", data: rows.map((r) => r[valueKey]),
            backgroundColor: css(`--series-${color}`), borderRadius: 4, borderSkipped: "start", maxBarThickness: 16 }] },
          options: baseOptions({
            indexAxis: "y", interaction: { mode: "nearest", axis: "y", intersect: false },
            plugins: { ...base.plugins, legend: { display: false } },
            scales: { x: { ...base.scales.x, beginAtZero: true, ticks: { ...base.scales.x.ticks, precision: 0 } },
                      y: { ...base.scales.y, grid: { display: false }, ticks: { color: css("--text-secondary"), autoSkip: false } } },
            onClick: link ? (_e, els) => { if (els[0]) location.href = link(rows[els[0].index]); } : undefined,
            onHover: link ? (e, els) => { e.native.target.style.cursor = els[0] ? "pointer" : "default"; } : undefined,
          }),
        };
      });
    }),

    sources: guard(async (el, days = 7, top = 12) => {
      const all = await getJSON(`/api/stats/sources?days=${days}`);
      if (!all.length) return emptyNote(el, "No items in this period.");
      const rows = all.slice(0, top);
      const rest = all.slice(top).reduce((a, r) => a + r.count, 0);
      // one row per source: give the canvas room instead of squeezing 50 labels into 200px
      el.parentElement.style.height = Math.max(200, rows.length * 26 + 70) + "px";
      const cats = ["news", "social", "intel"], names = { news: "News", social: "Social", intel: "Threat intel" };
      const short = (s) => (s.length > 26 ? s.slice(0, 24) + "…" : s);
      if (rest) {
        const note = document.createElement("div");
        note.className = "muted small"; note.style.marginTop = "6px";
        note.textContent = `${all.length - top} more source(s) with ${rest} item(s) not shown`;
        el.parentElement.after(note);
      }
      make(el, () => {
        const S = SERIES();
        const base = baseOptions();
        return {
          type: "bar",
          data: { labels: rows.map((r) => r.name), datasets: cats.map((c, i) => ({
            label: names[c], data: rows.map((r) => (r.category === c ? r.count : null)), backgroundColor: S[i],
            borderRadius: 4, borderSkipped: "start", maxBarThickness: 16, grouped: false })) },
          options: baseOptions({
            indexAxis: "y", interaction: { mode: "nearest", axis: "y", intersect: false },
            plugins: { ...base.plugins, tooltip: { ...base.plugins.tooltip, filter: (i) => i.raw !== null } },
            scales: { x: { ...base.scales.x, beginAtZero: true },
                      y: { ...base.scales.y, grid: { display: false },
                           ticks: { color: css("--text-secondary"), autoSkip: false, font: { size: 11 },
                                    callback: (_v, i) => short(rows[i].name) } } },
          }),
        };
      });
    }),

    iocs: guard(async (el, days = 30) => {
      const rows = await getJSON(`/api/stats/iocs?days=${days}`);
      if (!rows.length) return emptyNote(el, "No IOCs extracted yet.");
      make(el, () => {
        const surface = css("--surface-1");
        const base = baseOptions();
        const ds = [["malicious", "Malicious", "--critical"], ["suspicious", "Suspicious", "--warning"], ["other", "Clean / unknown / pending", "--neutral-mark"]];
        return {
          type: "bar",
          data: { labels: rows.map((r) => r.type.toUpperCase()), datasets: ds.map(([k, label, v]) => ({
            label, data: rows.map((r) => r[k]), backgroundColor: css(v), borderColor: surface, borderWidth: { right: 2 },
            borderSkipped: false, borderRadius: 3, maxBarThickness: 16 })) },
          options: baseOptions({
            indexAxis: "y", interaction: { mode: "index", axis: "y", intersect: false },
            scales: { x: { ...base.scales.x, stacked: true }, y: { ...base.scales.y, stacked: true, grid: { display: false } } },
          }),
        };
      });
    }),

    entityLine: guard(async (el, id, days = 60) => {
      const d = await getJSON(`/api/entities/${id}/timeline?days=${days}`);
      if (!d.data.some((v) => v > 0)) return emptyNote(el, `No mentions in the last ${days} days.`);
      make(el, () => {
        const base = baseOptions();
        return {
          type: "bar",
          data: { labels: d.labels.map(shortDate), datasets: [{ label: "Mentions", data: d.data,
            backgroundColor: css("--series-1"), borderRadius: 3, maxBarThickness: 12 }] },
          options: baseOptions({ plugins: { ...base.plugins, legend: { display: false } } }),
        };
      });
    }),
  };
  window.JATMP = JATMP;
})();

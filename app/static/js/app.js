/* JATMP front-end helpers: CSRF-aware fetch, action buttons, theme, navigation, charts.
   No inline event handlers anywhere (strict CSP); behaviour is attached via data-attributes:
     [data-post]          POST to a JSON endpoint, show toast / inject HTML / reload
     [data-ask]           Q&A form
     [data-confirm]       confirm() before a form or button submits
     [data-autosubmit]    submit the parent form on change
     [data-copy-selector] copy the text of matching elements to the clipboard
     details.pop          modal-style popover (click backdrop / Esc / [data-pop-close] to close)
     [data-menu] / [data-nav-close]  mobile sidebar
     a[data-preview]      open a partial-HTML preview in the side drawer ([data-preview-nav] = row for ↑/↓)
     [data-job-button] / [data-job-status]  disabled while a job runs / "Last · Next" + progress bar
     [data-notif-toggle]  notification center in the topbar (polled together with job status) */
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

  // ---------- sticky table headers sit right under the (sticky) topbar, whatever its height
  const topbar = document.querySelector(".topbar");
  if (topbar && "ResizeObserver" in window) {
    new ResizeObserver(() => document.documentElement.style.setProperty("--topbar-h", topbar.offsetHeight + "px"))
      .observe(topbar);
  }
  // a data table wider than its card falls back to horizontal scrolling (a sticky header needs the
  // wrapper not to be a scroll container, so this is decided per table, not per breakpoint)
  if ("ResizeObserver" in window) {
    const fit = (wrap) => {
      const t = wrap.querySelector("table");
      if (t) wrap.classList.toggle("scroll-x", t.scrollWidth > wrap.clientWidth + 1);
    };
    const ro = new ResizeObserver((es) => es.forEach((e) => fit(e.target)));
    document.querySelectorAll(".table-wrap.data-table").forEach((w) => { fit(w); ro.observe(w); });
  }

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
      // job buttons: poll fast for a while so the progress bar appears right away
      if (btn.dataset.jobButton) { pulse.boost = Date.now() + 20000; pollPulse(); }
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

  const typingIn = () => /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName || "") ||
    document.activeElement?.isContentEditable;

  // ---------- side preview drawer
  // A plain left-click on a[data-preview] opens a partial-HTML preview in the right-hand drawer.
  // Ctrl/Cmd/Shift/middle-click keep the normal href (new tab etc.). ?preview=item:12 is shareable.
  const drawer = document.getElementById("drawer");
  const dBody = document.getElementById("drawer-body");
  const dBackdrop = document.querySelector(".drawer-backdrop");
  const PREVIEW_RE = /^\/(items|entities)\/(\d+)\/preview$/;
  let dReturn = null, dCurrent = null, dReq = 0;

  const navLinks = () => [...document.querySelectorAll("main [data-preview-nav]")];
  const rowLink = (el) => (el?.hasAttribute("data-preview-nav") ? el : el?.closest("tr, .feed-item")?.querySelector("[data-preview-nav]")) || null;
  const markRow = (link) => {
    document.querySelectorAll(".is-previewed").forEach((r) => r.classList.remove("is-previewed"));
    link?.closest("tr")?.classList.add("is-previewed");
  };
  const setPreviewParam = (val) => {
    const u = new URL(location.href);
    if (val) u.searchParams.set("preview", val); else u.searchParams.delete("preview");
    history.replaceState(history.state, "", u.pathname + u.search + u.hash);
  };

  async function openPreview(url, origin) {
    const m = PREVIEW_RE.exec(url || "");
    if (!drawer || !m) return;
    const req = ++dReq;
    if (origin && !drawer.contains(origin)) { dReturn = origin; dCurrent = rowLink(origin); }
    const wasOpen = !drawer.hidden;
    drawer.hidden = false; dBackdrop.hidden = false;
    document.body.classList.add("drawer-open");
    dBody.classList.add("loading");
    if (!wasOpen) dBody.innerHTML = '<div class="empty">Loading…</div>';
    const full = document.getElementById("drawer-full");
    full.href = url.replace(/\/preview$/, "");
    markRow(dCurrent);
    if (!drawer.contains(document.activeElement)) drawer.focus({ preventScroll: true });
    try {
      const r = await fetch(url, { credentials: "same-origin", headers: { "X-Requested-With": "fetch" } });
      if (r.redirected && new URL(r.url).pathname === "/login") {
        location.href = "/login?next=" + encodeURIComponent(location.pathname + location.search); return;
      }
      if (!r.ok) throw new Error(r.status === 404 ? "not found" : `HTTP ${r.status}`);
      const html = await r.text();
      if (req !== dReq) return;
      dBody.innerHTML = html;
      dBody.scrollTop = 0;
      const meta = dBody.querySelector("[data-preview-meta]");
      document.getElementById("drawer-kind").textContent = meta?.dataset.kind ? `${meta.dataset.kind} preview` : "Preview";
      if (meta?.dataset.full) full.href = meta.dataset.full;
      setPreviewParam(`${m[1] === "items" ? "item" : "entity"}:${m[2]}`);
    } catch (err) {
      if (req !== dReq) return;
      dBody.innerHTML = "";
      const d = document.createElement("div");
      d.className = "empty"; d.textContent = `Could not load the preview (${err.message}).`;
      dBody.appendChild(d);
    } finally {
      if (req === dReq) dBody.classList.remove("loading");
    }
  }

  function closePreview() {
    if (!drawer || drawer.hidden) return;
    dReq++;
    drawer.hidden = true; dBackdrop.hidden = true;
    document.body.classList.remove("drawer-open");
    markRow(null);
    setPreviewParam("");
    const back = dReturn;
    dReturn = null;
    if (back && document.contains(back)) back.focus();
  }

  function stepPreview(delta) {
    const links = navLinks();
    if (!links.length) return;
    let i = links.indexOf(dCurrent);
    i = i < 0 ? (delta > 0 ? 0 : links.length - 1) : Math.min(links.length - 1, Math.max(0, i + delta));
    if (links[i] === dCurrent) return;
    dCurrent = links[i]; dReturn = links[i];
    (links[i].closest("tr") || links[i]).scrollIntoView({ block: "nearest", behavior: REDUCED ? "auto" : "smooth" });
    openPreview(links[i].dataset.preview, null);
  }

  document.addEventListener("click", (e) => {
    const a = e.target.closest("a[data-preview]");
    if (!a || !drawer || e.defaultPrevented) return;
    if (e.button !== 0 || e.ctrlKey || e.metaKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    openPreview(a.dataset.preview, a);
  });
  document.addEventListener("click", (e) => {
    if (e.target.closest("[data-drawer-close]")) { e.preventDefault(); closePreview(); return; }
    const step = e.target.closest("[data-drawer-step]");
    if (step) stepPreview(Number(step.dataset.drawerStep));
  });
  document.addEventListener("keydown", (e) => {
    if (!drawer || drawer.hidden) return;
    if (e.key === "Escape") { e.preventDefault(); e.stopPropagation(); closePreview(); return; }
    if (!typingIn() && !e.ctrlKey && !e.metaKey && !e.altKey && ["ArrowDown", "ArrowUp", "j", "k"].includes(e.key)) {
      e.preventDefault();
      stepPreview(e.key === "ArrowDown" || e.key === "j" ? 1 : -1);
      return;
    }
    if (e.key === "Tab") { // focus trap
      const f = [...drawer.querySelectorAll('a[href], button:not([disabled]), input, select, textarea, [tabindex]:not([tabindex="-1"])')]
        .filter((el) => el.offsetParent !== null);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && (document.activeElement === first || document.activeElement === drawer)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      else if (!drawer.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
    }
  }, true);
  { // deep link: ?preview=item:12 / entity:5
    const pm = /^(item|entity):(\d+)$/.exec(new URLSearchParams(location.search).get("preview") || "");
    if (pm && drawer) {
      const url = `/${pm[1] === "item" ? "items" : "entities"}/${pm[2]}/preview`;
      openPreview(url, document.querySelector(`main [data-preview="${url}"]`));
    }
  }

  // ---------- background jobs + notifications: one poll for both
  // every 60 s normally, every 2.5 s while a job runs (or right after a job button was pressed).
  const pulse = { timer: null, boost: 0, lastNotif: null, skew: 0 };
  const bell = document.querySelector("[data-notif-toggle]");
  const nPanel = document.getElementById("notif-panel");
  const nBadge = document.querySelector("[data-notif-badge]");

  const rel = (iso) => {
    if (!iso) return "";
    const s = Math.round((Date.parse(iso) - (Date.now() + pulse.skew)) / 1000);
    const a = Math.abs(s);
    const v = a < 45 ? null : a < 3600 ? `${Math.round(a / 60)} min` : a < 86400 ? `${Math.round(a / 3600)} h` : `${Math.round(a / 86400)} d`;
    if (!v) return s > 0 ? "in a moment" : "just now";
    return s > 0 ? `in ${v}` : `${v} ago`;
  };

  function renderJobs(jobs) {
    for (const [name, j] of Object.entries(jobs || {})) {
      document.querySelectorAll(`[data-job-button="${name}"]`).forEach((b) => {
        if (b.getAttribute("aria-busy") === "true") return;
        b.disabled = !!j.running;
      });
      document.querySelectorAll(`[data-job-status="${name}"]`).forEach((el) => {
        el.textContent = "";
        const line = document.createElement("div");
        if (j.running) {
          line.textContent = j.label || "Running…";
          el.appendChild(line);
          const bar = document.createElement("div");
          bar.className = "progress" + (j.total ? "" : " indeterminate");
          bar.setAttribute("role", "progressbar");
          bar.setAttribute("aria-label", j.label || "Progress");
          const fill = document.createElement("span");
          if (j.total) {
            const pct = Math.round((100 * j.done) / j.total);
            fill.style.width = pct + "%";
            bar.setAttribute("aria-valuenow", String(pct)); bar.setAttribute("aria-valuemin", "0"); bar.setAttribute("aria-valuemax", "100");
          }
          bar.appendChild(fill);
          el.appendChild(bar);
        } else {
          const parts = [];
          parts.push(j.last ? `Last: ${rel(j.last.finished_at)}` : "Last: never");
          if (j.next) parts.push(`Next: ${rel(j.next)}`);
          line.textContent = parts.join(" · ");
          if (j.last && j.last.status === "error") {
            const err = document.createElement("span");
            err.className = "err"; err.textContent = " · failed";
            err.title = j.last.message || "";
            line.appendChild(err);
          }
          if (j.last && j.last.summary) line.title = j.last.summary;
          el.appendChild(line);
        }
      });
    }
  }

  function renderBadge(n) {
    if (!bell || !n) return;
    nBadge.hidden = !n.unread;
    nBadge.textContent = n.unread > 99 ? "99+" : String(n.unread);
    bell.setAttribute("aria-label", n.unread ? `Notifications, ${n.unread} unread` : "Notifications");
    const latest = n.latest ? n.latest.id : 0;
    if (pulse.lastNotif === null) { pulse.lastNotif = latest; return; }
    if (latest > pulse.lastNotif) {
      pulse.lastNotif = latest;
      toast(n.latest.title, 6000);
      bell.classList.remove("ring"); void bell.offsetWidth; bell.classList.add("ring");
      if (!nPanel.hidden) loadNotifs();
    }
  }

  async function pollPulse() {
    clearTimeout(pulse.timer);
    let running = false;
    try {
      const d = await getJSON("/api/jobs/status");
      if (d.now) pulse.skew = Date.parse(d.now) - Date.now();
      renderJobs(d.jobs);
      renderBadge(d.notifications);
      running = Object.values(d.jobs || {}).some((j) => j.running);
    } catch {}
    const fast = running || pulse.boost > Date.now();
    pulse.timer = setTimeout(pollPulse, document.hidden ? 120000 : fast ? 2500 : 60000);
  }
  document.addEventListener("visibilitychange", () => { if (!document.hidden && bell) pollPulse(); });

  async function loadNotifs() {
    const list = document.getElementById("notif-list");
    try {
      const d = await getJSON("/api/notifications?limit=30");
      list.textContent = "";
      if (!d.items.length) {
        const e = document.createElement("div");
        e.className = "empty small"; e.textContent = "No notifications yet. Job results and alerts show up here.";
        list.appendChild(e);
      }
      for (const n of d.items) {
        const safeLink = typeof n.link === "string" && n.link.startsWith("/") && !n.link.startsWith("//");
        const row = document.createElement(safeLink ? "a" : "div");
        if (safeLink) row.href = n.link;
        row.className = "notif-row" + (n.unread ? " unread" : "");
        const dot = document.createElement("span");
        dot.className = "lvl " + (n.level || "info"); dot.title = n.level || "";
        const txt = document.createElement("div");
        const t = document.createElement("div"); t.className = "t"; t.textContent = n.title;
        txt.appendChild(t);
        if (n.body) { const b = document.createElement("div"); b.className = "b"; b.textContent = n.body; txt.appendChild(b); }
        const w = document.createElement("div"); w.className = "w"; w.textContent = rel(n.created_at); w.title = n.created_at;
        txt.appendChild(w);
        row.append(dot, txt);
        list.appendChild(row);
      }
      renderBadge({ unread: d.unread, latest: d.items[0] || null });
    } catch (err) {
      list.textContent = "";
      const e = document.createElement("div");
      e.className = "empty small"; e.textContent = "Could not load notifications (" + err.message + ")";
      list.appendChild(e);
    }
  }
  const setPanel = (open) => {
    if (!bell) return;
    nPanel.hidden = !open;
    bell.setAttribute("aria-expanded", String(open));
    if (open) loadNotifs();
  };
  document.addEventListener("click", async (e) => {
    if (!bell) return;
    if (e.target.closest("[data-notif-toggle]")) { setPanel(nPanel.hidden); return; }
    if (e.target.closest("[data-notif-close]")) { setPanel(false); bell.focus(); return; }
    if (e.target.closest("[data-notif-readall]")) {
      try { await api("/api/notifications/read"); await loadNotifs(); } catch (err) { toast("Error: " + err.message, 6000); }
      return;
    }
    if (!nPanel.hidden && !e.target.closest(".notif")) setPanel(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && bell && !nPanel.hidden) { setPanel(false); bell.focus(); }
  });
  if (bell) pollPulse();

  const JATMP = {
    toast, api, openPreview, closePreview, pollPulse,

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

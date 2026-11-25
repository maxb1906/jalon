// Jalon — UI web locale (JS vanilla, aucune dépendance externe).
"use strict";
(() => {
  const body = document.body;
  const TOKEN = body.dataset.token;
  let LANG = localStorage.getItem("jalon-lang") || body.dataset.lang;
  let CAT = {};
  let runId = null;
  let es = null;
  const $ = (id) => document.getElementById(id);

  const api = (path, params = {}) => {
    const u = new URL(path, location.origin);
    u.searchParams.set("t", TOKEN);
    u.searchParams.set("lang", LANG);
    for (const [k, v] of Object.entries(params)) u.searchParams.set(k, v);
    return u.toString();
  };

  // Rendu d'un message i18n {key, args} comme côté Go ({1}, {2}…, @clé).
  const tr = (m) => {
    if (!m || !m.key) return "";
    const f = CAT[m.key];
    const args = m.args || [];
    if (f === undefined) return [m.key, ...args].join(" ");
    return f.replace(/\{(\d+)\}/g, (all, n) => {
      let a = args[Number(n) - 1];
      if (a === undefined) return all;
      if (a.length > 1 && a[0] === "@" && CAT[a.slice(1)] !== undefined) a = CAT[a.slice(1)];
      return a;
    });
  };
  const t = (k, ...a) => tr({ key: k, args: a.map(String) });
  const icon = (s) => ({ ok: "✔", warn: "⚠", fail: "✖", info: "ℹ" }[s] || "·");

  const el = (tag, attrs = {}, ...kids) => {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs)) {
      if (k === "class") e.className = v; else if (k === "text") e.textContent = v; else e.setAttribute(k, v);
    }
    for (const k of kids) if (k != null) e.append(k instanceof Node ? k : document.createTextNode(k));
    return e;
  };

  function labels() {
    document.documentElement.lang = LANG;
    $("lang").value = LANG;
    $("ver").textContent = body.dataset.version;
    $("subtitle").textContent = t("web.subtitle");
    $("tab-run").textContent = t("web.tab_run");
    $("tab-history").textContent = t("web.tab_history");
    $("l-targets").textContent = t("web.targets");
    $("l-proto").textContent = t("web.proto");
    $("l-trace").textContent = t("web.trace_mode");
    $("l-notrace").textContent = t("web.no_trace");
    $("go").textContent = t("web.run");
    $("l-export").textContent = t("web.export") + " ";
    $("x-ticket").textContent = t("text.ticket");
    $("hq").placeholder = t("web.filter");
    $("hdiff").textContent = t("web.compare");
    $("h-date").textContent = t("web.date");
    $("h-target").textContent = t("col.target");
    $("h-verdict").textContent = t("col.verdict");
    $("hempty").textContent = t("cli.history_empty");
    $("readonly").textContent = t("web.readonly");
  }

  async function loadCatalog() {
    CAT = await (await fetch(api("/api/i18n"))).json();
    labels();
  }

  // ---------- Diagnostic ----------
  const state = { targets: [], cards: [] };

  function stepRow(s) {
    const notes = el("div", { class: "notes" });
    for (const n of s.notes || []) notes.append(el("div", { class: "note" }, el("span", { class: "ic s-" + n.status, text: icon(n.status) }), tr(n.msg)));
    return el("div", { class: "step" },
      el("span", { class: "s-" + (s.status || "skipped"), text: icon(s.status) }),
      el("span", { class: "layer", text: tr({ key: s.layer }) }),
      el("span", { class: "s-" + (s.status || "skipped") }, tr(s.summary)), notes);
  }

  function hopsTable(trc) {
    const tb = el("table", { class: "hops" });
    tb.append(el("tr", {}, ...["#", t("hop.host"), t("hop.loss"), "min", t("hop.avg"), "max", t("hop.jitter")].map((h) => el("th", { text: h }))));
    for (const h of trc.hops || []) {
      const name = h.addr ? (h.name ? `${h.name} (${h.addr})` : h.addr) + (h.asn ? " " + h.asn : "") : "*";
      const n = (v) => (h.recv ? v.toFixed(1) : "-");
      tb.append(el("tr", {}, ...[h.ttl, name, h.loss_pct.toFixed(0) + " %", n(h.min_ms), n(h.avg_ms), n(h.max_ms), n(h.jitter_ms)].map((v, i) => el("td", { class: i > 1 ? "num" : "", text: String(v) }))));
    }
    return tb;
  }

  function card(i) {
    if (!state.cards[i]) {
      const c = { root: el("div", { class: "card" }), verdict: el("div"), steps: el("div"), running: el("div", { class: "running" }), traces: el("div"), extra: el("div") };
      c.root.append(el("h2", { text: state.targets[i] }), c.verdict, c.steps, c.running, c.traces, c.extra);
      $("results").append(c.root);
      state.cards[i] = c;
    }
    return state.cards[i];
  }

  const gRunning = el("div", { class: "running" });
  function onEvent(e) {
    switch (e.type) {
      case "run_start":
        state.targets = e.targets || [];
        state.targets.forEach((_, i) => card(i));
        break;
      case "step_start":
        if (e.target < 0) { gRunning.textContent = "⟳ " + t("layer." + e.step_id); }
        else card(e.target).running.textContent = "⟳ " + t("tui.running", t(e.step_id === "tcp" ? "col.tcp" : e.step_id === "proto" ? "col.app" : "layer." + e.step_id));
        break;
      case "step":
        if (e.target < 0) { $("gsteps").append(stepRow(e.step)); gRunning.textContent = ""; }
        else { card(e.target).steps.append(stepRow(e.step)); card(e.target).running.textContent = ""; }
        break;
      case "trace_update": {
        const c = card(e.target);
        let box = c.traces.querySelector(`[data-mode="${e.trace.mode}"]`);
        if (!box) { box = el("div", { "data-mode": e.trace.mode }); c.traces.append(box); }
        box.replaceChildren(el("h3", { text: t("layer.trace_" + e.trace.mode) + " …" }), hopsTable(e.trace));
        break;
      }
      case "target_done": {
        const r = e.report, c = card(e.target), v = r.verdict;
        c.running.textContent = "";
        const vd = el("div", { class: "verdict s-" + v.status }, icon(v.status) + " " + tr(v.headline));
        if (v.status !== "ok" && v.findings && v.findings[0] && v.findings[0].advice) vd.append(el("div", { class: "advice", text: "→ " + tr(v.findings[0].advice) }));
        c.verdict.replaceChildren(vd);
        const others = (v.findings || []).filter((_, i) => i > 0 || v.status === "ok");
        if (others.length) c.verdict.append(el("ul", {}, ...others.map((f) => el("li", { class: "s-" + f.severity }, icon(f.severity) + " " + tr(f.msg)))));
        c.traces.replaceChildren();
        for (const trc of r.traces || []) if (trc.available && trc.hops) c.traces.append(el("h3", { text: t("layer.trace_" + trc.mode) }), hopsTable(trc));
        c.extra.replaceChildren();
        if (r.compare) {
          c.extra.append(el("h3", { text: t("text.changes", new Date(r.compare.previous_time).toLocaleString()) + (r.compare.same_network ? "" : " " + t("text.other_network")) }));
          const ch = r.compare.changes || [];
          if (!ch.length) c.extra.append(el("p", { class: "mut", text: t("text.no_changes") }));
          else c.extra.append(el("ul", {}, ...ch.map((x) => el("li", { class: "s-" + x.severity }, icon(x.severity) + " " + tr(x.msg)))));
        }
        break;
      }
      case "run_done":
        $("status").textContent = t("web.done");
        $("go").disabled = false;
        for (const [k, f] of [["x-html", "html"], ["x-md", "md"], ["x-json", "json"], ["x-ticket", "ticket"]]) {
          $(k).href = api("/api/report", { id: runId, format: f, download: f === "html" ? "0" : "1" });
        }
        $("exports").classList.remove("hidden");
        break;
    }
  }

  async function run(ev) {
    ev.preventDefault();
    const targets = $("targets").value.trim();
    if (!targets) return;
    if (es) es.close();
    state.targets = []; state.cards = [];
    $("results").replaceChildren();
    $("global").replaceChildren(el("div", { class: "card" }, el("h2", { text: t("text.common") }), el("div", { id: "gsteps" }), gRunning));
    $("exports").classList.add("hidden");
    $("go").disabled = true;
    $("status").textContent = t("web.running");
    const res = await fetch(api("/api/run"), {
      method: "POST", headers: { "Content-Type": "application/json", "X-Jalon-Token": TOKEN },
      body: JSON.stringify({ targets, proto: $("proto").value, trace_mode: $("trace_mode").value, no_trace: $("no_trace").checked, ipv4: $("ipv4").checked, ipv6: $("ipv6").checked, lang: LANG }),
    });
    if (!res.ok) { $("status").textContent = await res.text(); $("go").disabled = false; return; }
    runId = (await res.json()).id;
    es = new EventSource(api("/api/events", { id: runId }));
    es.onmessage = (m) => onEvent(JSON.parse(m.data));
    es.addEventListener("end", () => es.close());
  }

  // ---------- Historique ----------
  const selected = new Set();
  async function loadHistory() {
    const list = await (await fetch(api("/api/history", { q: $("hq").value }))).json();
    const tb = $("htable").querySelector("tbody");
    tb.replaceChildren();
    selected.clear(); $("hdiff").disabled = true;
    $("hempty").classList.toggle("hidden", list.length > 0);
    for (const m of list) {
      const cb = el("input", { type: "checkbox" });
      cb.onchange = () => { cb.checked ? selected.add(m.id) : selected.delete(m.id); $("hdiff").disabled = selected.size !== 2; };
      tb.append(el("tr", {},
        el("td", {}, cb), el("td", { text: new Date(m.time).toLocaleString() }), el("td", { text: m.raw }),
        el("td", { class: "s-" + m.status }, icon(m.status) + " " + m.text),
        el("td", {}, el("a", { href: api("/api/history/report", { id: m.id }), target: "_blank", text: t("web.open") }))));
    }
  }
  async function diff() {
    const [a, b] = [...selected];
    const d = await (await fetch(api("/api/diff", { a, b }))).json();
    const box = $("diff");
    box.classList.remove("hidden");
    box.replaceChildren(el("h2", { text: t("cli.diff_header", d.from, d.from_raw, d.to, d.to_raw) }));
    if (!d.same_target) box.append(el("p", { class: "s-warn", text: t("cli.diff_other_target") }));
    if (!d.same_network) box.append(el("p", { class: "mut", text: t("text.other_network") }));
    if (!d.changes.length) box.append(el("p", { class: "mut", text: t("text.no_changes") }));
    else box.append(el("ul", {}, ...d.changes.map((c) => el("li", { class: "s-" + c.severity }, icon(c.severity) + " " + c.text))));
    box.append(el("p", {}, d.from_verdict + " → " + d.to_verdict));
  }

  function show(view) {
    for (const v of ["run", "history"]) {
      $("view-" + v).classList.toggle("hidden", v !== view);
      $("tab-" + v).classList.toggle("on", v === view);
    }
    if (view === "history") loadHistory();
  }

  document.querySelectorAll(".tab").forEach((b) => (b.onclick = () => show(b.dataset.view)));
  $("form").onsubmit = run;
  $("hq").oninput = () => loadHistory();
  $("hdiff").onclick = diff;
  $("lang").onchange = async () => { LANG = $("lang").value; localStorage.setItem("jalon-lang", LANG); await loadCatalog(); };
  loadCatalog();
})();

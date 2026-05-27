/* =============================================================
   kedalab — app logic
   ============================================================= */
(() => {
  "use strict";
  const D = window.KEDA_DATA;
  const $ = (s, c = document) => c.querySelector(s);
  const $$ = (s, c = document) => Array.from(c.querySelectorAll(s));
  const phaseById = {};
  D.phases.forEach(p => (phaseById[p.id] = p));

  const isFile = location.protocol === "file:";
  let dataLoaded = false;
  const loaderErrors = [];

  function setPill(text, cls) {
    const el = document.getElementById("loaderPill");
    if (!el) return;
    el.textContent = text;
    el.classList.remove("ok", "err", "loading");
    if (cls) el.classList.add(cls);
  }
  setPill("⋯ kedaweb script started", "loading");

  // Recomputed every time after data loads/updates.
  let phaseCounts = {};
  let cveCount = 0;
  function recomputeStats() {
    phaseCounts = {};
    D.phases.forEach(p => (phaseCounts[p.id] = 0));
    D.techniques.forEach(t => (phaseCounts[t.p] = (phaseCounts[t.p] || 0) + 1));
    cveCount = D.techniques.filter(
      t => (t.tags || []).includes("cve") || /CVE-\d{4}-\d+/i.test(t.n)
    ).length;
  }
  recomputeStats(); // initial zero-fill so renders don't see undefined

  // ============================================================
  // kedalab loader — single source of truth = kedalab MDs
  // ============================================================
  async function fetchMd(path) {
    const res = await fetch("../" + path);
    if (!res.ok) throw new Error("HTTP " + res.status + " " + path);
    return res.text();
  }

  // Parse all markdown tables from a document. Returns [{ headers, rows }].
  function parseMdTables(md) {
    const tables = [];
    const lines = md.split(/\r?\n/);
    // CommonMark: \| inside a cell is a literal pipe. Sentinel-swap so split("|") keeps it.
    const PIPE_ESC = "";
    const splitCells = s => s
      .replace(/\\\|/g, PIPE_ESC)
      .replace(/^\|/, "").replace(/\|$/, "")
      .split("|").map(c => c.trim().replace(//g, "|"));
    let i = 0;
    while (i < lines.length) {
      const line = lines[i].trim();
      if (!line.startsWith("|")) { i++; continue; }
      const next = (lines[i + 1] || "").trim();
      if (!/^\|[\s|:\-]+\|$/.test(next)) { i++; continue; }
      const headers = splitCells(line);
      const rows = [];
      i += 2;
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        rows.push(splitCells(lines[i].trim()));
        i++;
      }
      tables.push({ headers, rows });
    }
    return tables;
  }

  // First `*.md` path in a cell (handles backticks).
  function extractFile(cell) {
    if (!cell) return null;
    const m = cell.match(/`([^`]+\.md)`/) || cell.match(/(?:^|\s)([\w][\w\-./]*\.md)\b/);
    return m ? m[1] : null;
  }

  // All `*.md` paths anywhere in a cell.
  function extractFiles(cell) {
    if (!cell) return [];
    const out = [];
    const re = /`([^`]+\.md)`/g;
    let m;
    while ((m = re.exec(cell)) !== null) out.push(m[1]);
    return out;
  }

  function cleanName(s) {
    return s
      .replace(/^\*\*/, "")
      .replace(/\*\*$/, "")
      .replace(/\\\|/g, "|")
      .trim();
  }

  // Map a root-relative file path → phase id (folder prefix).
  function phaseFromPath(file) {
    if (!file) return null;
    if (file.startsWith("00_Playbook/")) return "playbook";
    if (file.startsWith("06_Concepts/AI_ML/")) return "ai";
    if (file.startsWith("07_")) return "ai";
    if (file.startsWith("06_")) return "concepts";
    if (file.startsWith("05_")) return "tools";
    if (file.startsWith("04_")) return "windows";
    if (file.startsWith("03_")) return "linux";
    if (file.startsWith("02_")) return "initial";
    if (file.startsWith("01_")) return "recon";
    return null;
  }

  function deriveTags(name, file) {
    const tags = new Set();
    if (/CVE-\d{4}-\d+/i.test(name)) tags.add("cve");
    const p = phaseFromPath(file);
    if (p) tags.add(p);
    const base = (file.split("/").pop() || "").replace(/\.md$/i, "").toLowerCase();
    base.split(/[_\-]/).forEach(w => { if (w.length > 2) tags.add(w); });
    return Array.from(tags).slice(0, 5);
  }

  // Load TECHNIQUES_INDEX*.md → flat technique list.
  // The same file may appear in multiple tables (master index + phase-specific
  // tables in the same MD); dedupe by file path so Browser/Navigator show it once.
  async function loadTechniques() {
    const out = [];
    const seen = new Set();
    for (const src of ["TECHNIQUES_INDEX.md", "TECHNIQUES_INDEX_AI_ML.md"]) {
      let md;
      try { md = await fetchMd(src); }
      catch (e) { console.warn("[loader]", e.message); continue; }
      const tables = parseMdTables(md);
      for (const tbl of tables) {
        if (tbl.headers.length < 2) continue;
        for (const row of tbl.rows) {
          if (row.length < 2) continue;
          const file = extractFile(row[row.length - 1]);
          const name = cleanName(row[0]);
          if (!file || !name) continue;
          if (seen.has(file)) continue;
          const p = phaseFromPath(file);
          if (!p) continue;
          seen.add(file);
          out.push({ n: name, p, f: file, tags: deriveTags(name, file) });
        }
      }
    }
    return out;
  }

  // Extract a display title from a markdown source.
  // Strips fenced code blocks first so shell comments like `# [Attacker] …` inside
  // ```bash ... ``` aren't mistaken for the document title. Prefers H1; falls back
  // to the first H2 (kedalab convention is inconsistent — some files start with H2).
  function extractH1(md) {
    const stripped = md.replace(/```[\s\S]*?```/g, '');
    let m = stripped.match(/^#\s+(.+)$/m);
    if (!m) m = stripped.match(/^##\s+(.+)$/m);
    return m ? m[1].trim() : null;
  }

  // Scan README.md (and other sources) for `00_Playbook/*.md` references and
  // register each unique playbook as a technique node (phase = "playbook").
  // Playbooks aren't listed in TECHNIQUES_INDEX*.md, so we discover them here.
  async function loadPlaybookNodes() {
    const out = [];
    const seen = new Set();
    const sources = ["README.md", "TECHNIQUES_INDEX.md", "TECHNIQUES_INDEX_AI_ML.md"];
    for (const src of sources) {
      let md;
      try { md = await getMd(src); } catch (e) { continue; }
      const re = /(?:^|[^\w/])(00_Playbook\/[\w][\w\-.]*\.md)\b/g;
      let m;
      while ((m = re.exec(md)) !== null) {
        const f = m[1];
        if (seen.has(f)) continue;
        seen.add(f);
        let name = f.split("/").pop().replace(/\.md$/, "");
        try {
          const pmd = await getMd(f);
          const h1 = extractH1(pmd);
          if (h1) name = h1;
        } catch (e) { /* keep filename */ }
        out.push({ n: name, p: "playbook", f, tags: ["playbook"] });
      }
    }
    return out;
  }

  // Markdown cache to avoid refetching the same file.
  const _mdCache = new Map();
  async function getMd(file) {
    if (_mdCache.has(file)) return _mdCache.get(file);
    const md = await fetchMd(file);
    _mdCache.set(file, md);
    return md;
  }

  // ---- Full-text content index --------------------------------------------
  // file → lowercased markdown body. Populated lazily by ensureContentIndex()
  // so the top-bar search can match on body text in addition to name/tags/path.
  const _contentIndex = new Map();
  let _contentIndexBuilding = null;
  let _contentIndexBuilt = false;

  function ensureContentIndex() {
    if (_contentIndexBuilt || isFile) return Promise.resolve();
    if (_contentIndexBuilding) return _contentIndexBuilding;
    _contentIndexBuilding = (async () => {
      const files = Array.from(new Set(
        D.techniques.map(t => t.f).filter(Boolean)
      ));
      if (!files.length) { _contentIndexBuilt = true; return; }
      const total = files.length;
      let done = 0;
      setPill(`⋯ indexing 0/${total}`, "loading");
      let cursor = 0;
      const CONC = 8;
      async function worker() {
        while (cursor < files.length) {
          const f = files[cursor++];
          try {
            const md = await getMd(f);
            _contentIndex.set(f, md.toLowerCase());
          } catch (e) {
            _contentIndex.set(f, ""); // mark as fetched (failed) so we skip
          }
          done++;
          if (done === total || done % 20 === 0) {
            setPill(`⋯ indexing ${done}/${total}`, "loading");
          }
        }
      }
      await Promise.all(
        Array.from({ length: Math.min(CONC, files.length) }, worker)
      );
      _contentIndexBuilt = true;
      setLoadedPill();
      if (currentQuery) renderTechniques();
    })();
    return _contentIndexBuilding;
  }

  function shortLabel(file) {
    if (!file) return "";
    return file.split("/").pop().replace(/\.md$/, "").replace(/_/g, " ");
  }

  // ---- Quick Start: parse README's「最初に開くファイル」table ------------
  // Each row → { situation, file (first .md cited), note (free text after) }
  // The 「ドメインのみ」row points to recon → OS判定 (two files); we take the
  // first as the entry. Layout-wise this works fine because the row text still
  // mentions the second one.
  async function loadSituations() {
    let md;
    try { md = await getMd("README.md"); }
    catch { return []; }
    const tables = parseMdTables(md);
    let target = null;
    for (const t of tables) {
      const h0 = t.headers[0] || "";
      if (h0.includes("手元にある情報")) { target = t; break; }
    }
    if (!target) return [];
    return target.rows
      .map(row => {
        const situation = cleanName(row[0] || "");
        const cell = row[1] || "";
        const files = extractFiles(cell);
        const file = files[0];
        // Note = cell text with backticked paths replaced by their basename so
        // the flow narrative ("DNS列挙 で IP 特定 → OS判定 へ") stays readable.
        const note = cell
          .replace(/`([^`]+\.md)`/g, (_, p) =>
            p.split("/").pop().replace(/\.md$/, "")
          )
          .replace(/\s+/g, " ")
          .trim();
        return { situation, file, note };
      })
      .filter(r => r.situation && r.file);
  }

  // Pick an emoji/icon based on situation keywords.
  function iconForSituation(s) {
    const t = s.toLowerCase();
    if (t.includes("認証")) return "🔑";
    if (t.includes("ドメイン")) return "📁";
    if (t.includes("インターネット") || t.includes("露出")) return "📡";
    if (t.includes("web診断") || t.includes("網羅")) return "🔬";
    if (t.includes("web")) return "🌐";
    if (t.includes("linux")) return "🐧";
    if (t.includes("windows")) return "🪟";
    if (t.includes("内部") || t.includes("vlan")) return "🔌";
    if (t.includes("ip")) return "⚫";
    return "▣";
  }
  function colorForSituation(s) {
    const t = s.toLowerCase();
    if (t.includes("linux")) return "#ffb800";
    if (t.includes("windows")) return "#ff3d8a";
    if (t.includes("web診断") || t.includes("網羅")) return "#a78bfa";
    if (t.includes("web")) return "#00d4ff";
    if (t.includes("認証")) return "#64ffda";
    if (t.includes("ドメイン")) return "#ff00ff";
    if (t.includes("内部")) return "#a78bfa";
    if (t.includes("露出")) return "#ff3d8a";
    return "#00ff9c";
  }

  // Fetch a playbook MD, extract H1 + the「フロー概要」(or first fenced block,
  // or first paragraph) for preview purposes.
  async function loadPlaybookPreview(file) {
    const md = await getMd(file);
    const h1 = extractH1(md) || file.split("/").pop().replace(/\.md$/, "");

    // Look for any of: フロー概要 / 判定の優先順位 / 概要 — extract until the
    // next ## heading.
    const summarySections = ["フロー概要", "判定の優先順位", "概要", "案件開始条件の確認"];
    let summary = "";
    let summaryHeading = "";
    for (const name of summarySections) {
      const re = new RegExp("^##\\s+" + name + "\\s*$\\n([\\s\\S]*?)(?=^##\\s|\\Z)", "m");
      const m = md.match(re);
      if (m) { summaryHeading = name; summary = m[1].trim(); break; }
    }
    // Fallback: first non-quote paragraph after H1
    if (!summary) {
      const body = md.replace(/^#\s+.*$/m, "").trim();
      const para = body.split(/\n\n+/).find(p => !p.startsWith(">") && !p.startsWith("#"));
      if (para) summary = para.trim();
    }
    return { h1, summary, summaryHeading };
  }

  // ============================================================
   // Boot sequence
  // ============================================================
  const bootLines = [
    "[boot] kedalab terminal v1.0",
    "[boot] initializing kernel modules ........... [OK]",
    "[boot] mounting /knowledge_base .............. [OK]",
    "[boot] loading techniques catalog ............ [OK]",
    "[boot] indexing CVE database ................. [OK]",
    "[boot] loading playbooks ..................... [OK]",
    "[boot] linking AI red teaming module ......... [OK]",
    "[boot] starting matrix subsystem ............. [OK]",
    "",
    "    ██╗  ██╗███████╗██████╗  █████╗ ██╗      █████╗ ██████╗ ",
    "    ██║ ██╔╝██╔════╝██╔══██╗██╔══██╗██║     ██╔══██╗██╔══██╗",
    "    █████╔╝ █████╗  ██║  ██║███████║██║     ███████║██████╔╝",
    "    ██╔═██╗ ██╔══╝  ██║  ██║██╔══██║██║     ██╔══██║██╔══██╗",
    "    ██║  ██╗███████╗██████╔╝██║  ██║███████╗██║  ██║██████╔╝",
    "    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ",
    "",
    "[ok] welcome. press [ctrl+k] to search, [esc] to close."
  ];
  const bootEl = $("#boot-log");
  let bi = 0, ci = 0, current = "";
  function boot() {
    if (bi >= bootLines.length) {
      setTimeout(() => {
        $("#boot").classList.add("fade");
        setTimeout(() => $("#boot").remove(), 800);
        triggerReveal();
      }, 350);
      return;
    }
    const line = bootLines[bi];
    if (ci < line.length) {
      current += line[ci++];
      bootEl.innerHTML = render() + '<span class="cursor"></span>';
      const speed = line.startsWith("[boot]") || line.startsWith("[ok]") ? 6 : 2;
      setTimeout(boot, speed);
    } else {
      current += "\n";
      ci = 0;
      bi++;
      setTimeout(boot, line === "" ? 80 : 60);
    }
  }
  function render() {
    return current
      .replace(/\[OK\]/g, '<span style="color:#00ff9c">[OK]</span>')
      .replace(/\[boot\]/g, '<span style="color:#5b6f8a">[boot]</span>')
      .replace(/\[ok\]/g, '<span style="color:#00ff9c">[ok]</span>');
  }
  boot();

  // ============================================================
  // Render Quick Start (situation wizard)
  // ============================================================
  let qsActiveIdx = -1;

  function renderQuickstart() {
    const grid = $("#qsGrid");
    const expand = $("#qsExpand");
    const list = D.situations || [];

    if (!list.length) {
      const msg = isFile
        ? "⚠ file:// では Quick Start を取得できません — HTTP サーバ経由で開いてください"
        : !dataLoaded
          ? "› fetching README.md …"
          : (loaderErrors.length
              ? "✕ 読み込みエラー：" + escapeHtml(loaderErrors.join(" / "))
              : "状況テーブルが README.md に見つかりません（「最初に開くファイル」表を確認）");
      grid.innerHTML = `<div class="tb-empty" style="grid-column:1/-1">${msg}</div>`;
      expand.innerHTML = "";
      return;
    }

    grid.innerHTML = list.map((s, i) => {
      const c = colorForSituation(s.situation);
      const icon = iconForSituation(s.situation);
      const isActive = i === qsActiveIdx;
      const sub = shortLabel(s.file);
      return `
        <div class="qs-card${isActive ? ' active' : ''}" data-i="${i}" style="--qc: ${c};">
          <div class="qs-icon">${icon}</div>
          <div class="qs-title">${escapeHtml(s.situation)}</div>
          <div class="qs-sub">${escapeHtml(sub)}</div>
        </div>
      `;
    }).join("");

    $$(".qs-card", grid).forEach(el => {
      el.addEventListener("click", () => onQsCardClick(+el.dataset.i));
    });

    if (qsActiveIdx >= 0 && list[qsActiveIdx]) {
      renderQsPreview(qsActiveIdx);
    } else {
      expand.innerHTML = "";
    }
  }

  async function onQsCardClick(idx) {
    if (qsActiveIdx === idx) {
      // toggle off
      qsActiveIdx = -1;
    } else {
      qsActiveIdx = idx;
    }
    renderQuickstart();
    if (qsActiveIdx >= 0) {
      // smooth scroll the expand panel into view
      requestAnimationFrame(() => {
        const exp = $("#qsExpand");
        if (exp) exp.scrollIntoView({ behavior: "smooth", block: "nearest" });
      });
    }
  }

  async function renderQsPreview(idx) {
    const exp = $("#qsExpand");
    const s = (D.situations || [])[idx];
    if (!s || !exp) return;
    const color = colorForSituation(s.situation);
    exp.innerHTML = `
      <div class="qs-preview" style="--qc: ${color};">
        <div class="qs-pv-tag">RECOMMENDED PLAYBOOK</div>
        <div class="qs-pv-title">Loading …</div>
        <div class="qs-pv-file">${escapeHtml(s.file)}</div>
        <div class="qs-pv-loading">› fetching ${escapeHtml(s.file)} …</div>
      </div>
    `;

    try {
      const { h1, summary, summaryHeading } = await loadPlaybookPreview(s.file);
      // Truncate very long summaries
      let body = summary || "(本文を開いて全体を確認してください)";
      if (body.length > 1400) body = body.slice(0, 1400) + "\n\n… (省略)";

      const noteHtml = s.note
        ? `<p style="margin:8px 0 0;color:var(--fg-2);font-size:11px;">📌 ${escapeHtml(s.note)}</p>`
        : "";

      exp.innerHTML = `
        <div class="qs-preview" style="--qc: ${color};">
          <div class="qs-pv-tag">RECOMMENDED PLAYBOOK</div>
          <div class="qs-pv-title">${escapeHtml(h1)}</div>
          <div class="qs-pv-file">${escapeHtml(s.file)}</div>
          ${noteHtml}
          <div class="qs-pv-body">
            ${summaryHeading ? `<h4>## ${escapeHtml(summaryHeading)}</h4>` : ""}
            ${miniMarkdown(body)}
          </div>
          <div class="qs-pv-actions">
            <button class="qs-btn" data-act="open">📖 この Playbook を開く</button>
            <button class="qs-btn secondary" data-act="close">閉じる</button>
          </div>
        </div>
      `;
      $("[data-act='open']", exp).addEventListener("click", () => openMD(s.file));
      $("[data-act='close']", exp).addEventListener("click", () => onQsCardClick(idx));
    } catch (e) {
      exp.innerHTML = `
        <div class="qs-preview" style="--qc: ${color};">
          <div class="qs-pv-tag">PREVIEW UNAVAILABLE</div>
          <div class="qs-pv-title">${escapeHtml(s.file)}</div>
          <div class="qs-pv-body" style="color:var(--acc-r);">✕ ${escapeHtml(String(e.message || e))}</div>
          <div class="qs-pv-actions">
            <button class="qs-btn" data-act="open">📖 とにかく開く</button>
          </div>
        </div>
      `;
      $("[data-act='open']", exp).addEventListener("click", () => openMD(s.file));
    }
  }

  // Tiny markdown renderer for previews — handles code-blocks, lists,
  // bold/italic/inline-code. Reuses the same escaping rules.
  function miniMarkdown(src) {
    src = src.replace(/\r\n/g, "\n");

    // Fenced code blocks
    const fences = [];
    src = src.replace(/```([^\n]*)\n([\s\S]*?)```/g, (m, lang, code) => {
      fences.push(code);
      return `F${fences.length - 1}`;
    });

    // Escape HTML
    src = src.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");

    // Inline code
    src = src.replace(/`([^`]+)`/g, "<code>$1</code>");
    // Bold
    src = src.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    // Italic (only inside text, avoid breaking **bold**)
    src = src.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");

    // Bullet lists
    src = src.replace(/(?:^[ \t]*[-*]\s+.*\n?)+/gm, block => {
      const items = block.trim().split("\n").map(l => l.replace(/^[ \t]*[-*]\s+/, ""));
      return "<ul>" + items.map(i => `<li>${i}</li>`).join("") + "</ul>";
    });

    // Paragraphs
    const html = src.split(/\n{2,}/).map(chunk => {
      const t = chunk.trim();
      if (!t) return "";
      if (/^<(ul|ol|pre|h\d)/.test(t)) return t;
      if (/^F\d+/.test(t)) return t;
      return "<p>" + t.replace(/\n/g, "<br>") + "</p>";
    }).join("\n");

    // Restore code blocks
    return html.replace(/F(\d+)/g, (_, i) => {
      const code = fences[+i].replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
      return `<pre>${code}</pre>`;
    });
  }

  // ============================================================
  // Render raw index files
  // ============================================================
  function renderRaw() {
    const g = $("#rawGrid");
    g.innerHTML = D.indexFiles.map(it => `
      <div class="pb-card" data-file="${it.file}">
        <div class="pb-icon">📄</div>
        <div class="pb-body">
          <div class="pb-name">${it.name}</div>
          <div class="pb-entry" style="--p-c: var(--acc-v);">${it.desc}</div>
        </div>
      </div>
    `).join("");
    $$(".pb-card", g).forEach(el => {
      el.addEventListener("click", () => openMD(el.dataset.file));
    });
  }

  // ============================================================
  // Technique browser — filters + grid
  // ============================================================
  let currentPhase = "all";
  let currentQuery = "";

  function renderToolbar() {
    const tb = $("#tbToolbar");
    const total = D.techniques.length;
    const phases = [
      { id: "all", name: "All", color: "var(--fg-0)", count: total }
    ].concat(D.phases.map(p => ({
      id: p.id,
      name: p.name,
      color: p.color,
      count: phaseCounts[p.id]
    })));
    tb.innerHTML = phases.map(p => `
      <button class="filter-chip${p.id === currentPhase ? ' active' : ''}"
              data-phase="${p.id}"
              style="--chip-c: ${p.color};">
        ${p.name} <span class="badge">${p.count}</span>
      </button>
    `).join("");
    $$(".filter-chip", tb).forEach(b => {
      b.addEventListener("click", () => setFilter(b.dataset.phase));
    });
  }

  function setFilter(phaseId) {
    currentPhase = phaseId;
    renderToolbar();
    renderTechniques();
  }

  // Score = how well an entry matches the query.
  // 0 = excluded (a token didn't match anywhere). Higher = better match.
  // Weights: name 100 / file basename 80 / tags 50 / file path 30 / body 5.
  // All tokens must hit somewhere (preserves the previous all-tokens-required behavior).
  function scoreEntry(t, q) {
    if (!q) return 1;
    const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!tokens.length) return 1;
    const name = (t.n || "").toLowerCase();
    const fileFull = (t.f || "").toLowerCase();
    const fileBase = fileFull.split("/").pop();
    const tags = (t.tags || []).join(" ").toLowerCase();
    const body = _contentIndex.get(t.f) || "";
    let total = 0;
    for (const tok of tokens) {
      let s = 0;
      if (name.includes(tok))     s += 100;
      if (fileBase.includes(tok)) s += 80;
      if (tags.includes(tok))     s += 50;
      if (fileFull.includes(tok)) s += 30;
      if (body.includes(tok))     s += 5;
      if (s === 0) return 0;
      total += s;
    }
    return total;
  }

  function matchQuery(t, q) {
    return scoreEntry(t, q) > 0;
  }

  // Extract a ~120-char snippet around the earliest body hit, with all
  // matched tokens wrapped in <mark>. Returns "" if no body hit / no raw MD.
  // bodyRaw comes from _mdCache (original case); bodyLower from _contentIndex
  // (lowercased) is used to find positions.
  function bodySnippet(t, q) {
    if (!q) return "";
    const tokens = q.toLowerCase().split(/\s+/).filter(Boolean);
    if (!tokens.length) return "";
    const bodyLower = _contentIndex.get(t.f);
    if (!bodyLower) return "";
    const bodyRaw = _mdCache.get(t.f);
    // Length mismatch (rare: some Unicode lowercases change length) → bail out.
    if (!bodyRaw || bodyRaw.length !== bodyLower.length) return "";
    let earliest = -1, earlyTok = "";
    for (const tok of tokens) {
      const i = bodyLower.indexOf(tok);
      if (i < 0) continue;
      if (earliest < 0 || i < earliest) { earliest = i; earlyTok = tok; }
    }
    if (earliest < 0) return "";
    const ctxStart = Math.max(0, earliest - 60);
    const ctxEnd = Math.min(bodyRaw.length, earliest + earlyTok.length + 60);
    const win = bodyRaw.slice(ctxStart, ctxEnd);
    const winLower = bodyLower.slice(ctxStart, ctxEnd);
    const ranges = [];
    for (const tok of tokens) {
      let p = 0;
      while (p <= winLower.length - tok.length) {
        const i = winLower.indexOf(tok, p);
        if (i < 0) break;
        ranges.push([i, i + tok.length]);
        p = i + tok.length;
      }
    }
    ranges.sort((a, b) => a[0] - b[0]);
    const merged = [];
    for (const [s, e] of ranges) {
      const last = merged[merged.length - 1];
      if (last && s <= last[1]) last[1] = Math.max(last[1], e);
      else merged.push([s, e]);
    }
    let out = "";
    let cursor = 0;
    for (const [s, e] of merged) {
      out += escapeHtml(win.slice(cursor, s));
      out += "<mark>" + escapeHtml(win.slice(s, e)) + "</mark>";
      cursor = e;
    }
    out += escapeHtml(win.slice(cursor));
    out = out.replace(/[\r\n]+/g, " ").replace(/\s{2,}/g, " ").trim();
    return (ctxStart > 0 ? "…" : "") + out + (ctxEnd < bodyRaw.length ? "…" : "");
  }

  function renderTechniques() {
    const g = $("#tbGrid");
    const empty = $("#tbEmpty");
    const q = currentQuery;

    // Score & filter every technique row
    const scored = [];
    for (const t of D.techniques) {
      if (currentPhase !== "all" && t.p !== currentPhase) continue;
      const s = scoreEntry(t, q);
      if (s === 0) continue;
      scored.push({ t, s });
    }

    // Count badge: matched rows / total rows (preserves the previous semantic).
    const countEl = document.getElementById("browserCount");
    if (countEl) {
      countEl.textContent = D.techniques.length
        ? `${scored.length} / ${D.techniques.length}`
        : "—";
    }

    if (!scored.length) {
      g.innerHTML = "";
      empty.style.display = "block";
      empty.textContent = isFile
        ? "⚠ file:// では技術リストを取得できません — HTTP サーバ経由で開いてください"
        : (!dataLoaded
            ? "› fetching TECHNIQUES_INDEX.md …"
            : (loaderErrors.length
                ? "✕ 読み込みエラー：" + loaderErrors.join(" / ")
                : "該当なし — フィルタを解除するか別キーワードを試して"));
      return;
    }
    empty.style.display = "none";

    // Group matched rows by file. file → { p, sMax, hits[], tagSet }
    const fileMap = new Map();
    for (const { t, s } of scored) {
      let entry = fileMap.get(t.f);
      if (!entry) {
        entry = { f: t.f, p: t.p, sMax: 0, hits: [], tagSet: new Set() };
        fileMap.set(t.f, entry);
      }
      if (s > entry.sMax) entry.sMax = s;
      entry.hits.push({ n: t.n, s });
      (t.tags || []).forEach(x => entry.tagSet.add(x));
    }

    // Group file entries by phase id.
    const byPhase = new Map();
    for (const fe of fileMap.values()) {
      let arr = byPhase.get(fe.p);
      if (!arr) { arr = []; byPhase.set(fe.p, arr); }
      arr.push(fe);
    }
    // Sort files within each phase: by score desc when a query is active,
    // else alphabetically by path so the no-query view is stable.
    for (const arr of byPhase.values()) {
      if (q) arr.sort((a, b) => b.sMax - a.sMax || a.f.localeCompare(b.f));
      else arr.sort((a, b) => a.f.localeCompare(b.f));
    }

    // Render phases in D.phases order so 00→01→02→… stays consistent.
    const html = [];
    for (const p of D.phases) {
      const arr = byPhase.get(p.id);
      if (!arr || !arr.length) continue;
      const cards = arr.map(fe => renderFileCard(fe, p, q)).join("");
      html.push(
        `<div class="tb-group" data-phase="${p.id}" style="--tc: ${p.color};">` +
        `<div class="tb-group-head">` +
        `<span class="tb-group-code">${p.code}</span>` +
        `<span class="tb-group-name">${escapeHtml(p.name)}</span>` +
        `<span class="tb-group-count">${arr.length} 件</span>` +
        `</div>` +
        `<div class="tb-group-grid">${cards}</div>` +
        `</div>`
      );
    }
    g.innerHTML = html.join("");

    $$(".tech-card", g).forEach(el => {
      el.addEventListener("click", () => openMD(el.dataset.file));
    });
  }

  // Build a single card for a file with one or more matched technique hits.
  function renderFileCard(fe, p, q) {
    const title = shortLabel(fe.f);
    // Sort hits within the card by score desc (query-active) else input order.
    const hitsArr = q ? [...fe.hits].sort((a, b) => b.s - a.s) : fe.hits;
    const shown = hitsArr.slice(0, 6);
    const moreCount = hitsArr.length - shown.length;
    const hitsHtml = shown.map(h => `<li>${escapeHtml(h.n)}</li>`).join("");
    const moreHtml = moreCount > 0
      ? `<li class="tech-hits-more">+${moreCount} more</li>`
      : "";
    const tagsHtml = Array.from(fe.tagSet).slice(0, 4)
      .map(x => `<span class="tag">${escapeHtml(x)}</span>`).join("");
    const snippet = bodySnippet({ f: fe.f }, q);
    const snippetHtml = snippet ? `<div class="tech-snippet">${snippet}</div>` : "";
    return (
      `<div class="tech-card" data-file="${fe.f}" style="--tc: ${p.color};">` +
      `<div class="tech-name">${escapeHtml(title)}</div>` +
      `<ul class="tech-hits">${hitsHtml}${moreHtml}</ul>` +
      snippetHtml +
      `<div class="tech-meta">` +
      `<span class="tech-phase">${p.code} · ${escapeHtml(p.name)}</span>` +
      `<span class="tech-file">${escapeHtml(fe.f)}</span>` +
      `</div>` +
      `<div class="tech-tags">${tagsHtml}</div>` +
      `</div>`
    );
  }

  function escapeHtml(s) {
    return s.replace(/[&<>"']/g, c => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  // ============================================================
  // Navigator — MITRE-style matrix with focus highlighting
  // Edges = parsed from each MD's `## 関連技術` section
  // ============================================================
  const _edges = new Map(); // file -> { prev: [], next: [], related: [] }
  let _navLoaded = false;
  let _navFocus = null;

  function parseRelatedTech(file, md) {
    const baseDir = file.split("/").slice(0, -1).join("/");
    const out = { prev: [], next: [], related: [] };
    // Aggregate edges from ALL "関連技術" sections in the file (## ~ ######).
    // A file may have multiple: subsection-level relations + a file-level
    // closing section. Each section ends at the next heading of equal-or-higher level.
    const headRe = /^(#{2,6})\s+関連技術\s*$/gm;
    let hm;
    while ((hm = headRe.exec(md)) !== null) {
      const level = hm[1].length;
      const bodyStart = hm.index + hm[0].length;
      const tail = md.slice(bodyStart);
      const endRe = new RegExp("^#{1," + level + "}\\s+", "m");
      const em = tail.match(endRe);
      const section = em ? tail.slice(0, em.index) : tail;
      for (const line of section.split(/\n/)) {
        const t = line.trim();
        if (!t.startsWith("-")) continue;
        let bucket;
        // Label forms accepted:
        //   `- 前：…`         (canonical)
        //   `- 前（条件A）：…` (parenthesized qualifier — half- or full-width parens)
        //   `- 後（X）→ …`    (arrow separator instead of colon)
        // Separator: `:` `：` (U+FF1A) or `→` (U+2192).
        if (/^-\s*前(?:[（(][^）)]*[）)])?\s*[：:→]/.test(t)) bucket = out.prev;
        else if (/^-\s*後(?:[（(][^）)]*[）)])?\s*[：:→]/.test(t)) bucket = out.next;
        else if (/^-\s*関連(?:[（(][^）)]*[）)])?\s*[：:→]/.test(t)) bucket = out.related;
        else continue;
        const pathRe = /`([^`]+\.md)`/g;
        let pm;
        while ((pm = pathRe.exec(t)) !== null) {
          const raw = pm[1];
          let resolved;
          if (raw.startsWith("./") || raw.startsWith("../")) {
            resolved = resolvePath(baseDir, raw);
          } else if (raw.includes("/")) {
            resolved = raw;
          } else {
            resolved = baseDir ? baseDir + "/" + raw : raw;
          }
          if (!bucket.includes(resolved)) bucket.push(resolved);
        }
      }
    }
    return out;
  }

  async function buildEdgesIndex() {
    if (_edges.size > 0) return;
    // Pass 1: forward edges from known (TECHNIQUES_INDEX + playbook) techniques.
    for (const t of D.techniques) {
      const md = _mdCache.get(t.f);
      if (md) _edges.set(t.f, parseRelatedTech(t.f, md));
    }
    // Pass 2: auto-discover orphan files referenced from 関連技術 sections
    // (e.g. Concept files in 06_Concepts/ that aren't listed in any INDEX).
    // Fetch them, register as nodes, parse their edges. Iterate because an
    // orphan's own edges may surface further orphans.
    const tried = new Set(D.techniques.map(t => t.f));
    for (let pass = 0; pass < 4; pass++) {
      const known = new Set(D.techniques.map(t => t.f));
      const orphans = new Set();
      for (const [, e] of _edges) {
        for (const arr of [e.prev, e.next, e.related]) {
          for (const f of arr) {
            if (!known.has(f) && !tried.has(f) && phaseFromPath(f)) orphans.add(f);
          }
        }
      }
      if (!orphans.size) break;
      const list = Array.from(orphans);
      list.forEach(f => tried.add(f));
      await Promise.all(list.map(async f => {
        try { await getMd(f); } catch (e) { _mdCache.set(f, ""); }
      }));
      for (const f of list) {
        const md = _mdCache.get(f) || "";
        const p = phaseFromPath(f);
        let name = f.split("/").pop().replace(/\.md$/, "");
        const h1 = extractH1(md);
        if (h1) name = h1;
        D.techniques.push({ n: name, p, f, tags: [p, "auto"] });
        _edges.set(f, parseRelatedTech(f, md));
      }
    }
  }

  // Effective edges = forward (authoritative) + non-conflicting inverse.
  // If A.次 says B, B sees A as 前. If both A.次:B and B.次:A exist (which is
  // contradictory across files), A.次 wins from A's view, B.次 wins from B's.
  function effectiveEdges(file) {
    const fwd = _edges.get(file) || { prev: [], next: [], related: [] };
    const prev = new Set(fwd.prev);
    const next = new Set(fwd.next);
    const related = new Set(fwd.related);
    const claimed = f => prev.has(f) || next.has(f) || related.has(f);
    for (const [other, e] of _edges) {
      if (other === file || claimed(other)) {
        // forward already classifies this neighbour — skip inverse
        continue;
      }
      // other says `前：file` → other depends on file → from file's view, other is a `次` step
      if (e.prev.includes(file))       next.add(other);
      else if (e.next.includes(file))  prev.add(other);
      else if (e.related.includes(file)) related.add(other);
    }
    return {
      prev: Array.from(prev),
      next: Array.from(next),
      related: Array.from(related)
    };
  }

  function shortFileName(file) {
    return file.split("/").pop().replace(/\.md$/, "").replace(/_/g, " ");
  }

  function renderNavigatorMatrix() {
    const grid = document.getElementById("navMatrix");
    if (!grid) return;
    const byPhase = {};
    D.phases.forEach(p => (byPhase[p.id] = []));
    D.techniques.forEach(t => { if (byPhase[t.p]) byPhase[t.p].push(t); });
    // Sort by full path with numeric awareness:
    //  - "00_OS_Identification.md" / "01_Unknown_Tech_Research.md" come first by their prefix
    //  - subfolder files (ACE_Abuse/, AD_CS/, …) group together
    //  - within each group, files are alphabetical
    for (const id in byPhase) byPhase[id].sort((a, b) =>
      (a.f || "").localeCompare(b.f || "", "ja", { numeric: true, sensitivity: "base" })
    );

    grid.innerHTML = D.phases.map(p => {
      const list = byPhase[p.id] || [];
      const cells = list.map(t => `
        <button class="nav-cell" data-file="${escapeHtml(t.f)}" title="${escapeHtml(t.f)}">
          ${escapeHtml(t.n)}
        </button>
      `).join("");
      return `
        <div class="nav-col">
          <div class="nav-col-h" style="--col-c: ${p.color};">
            ${p.code} ${p.name.toUpperCase()}<span class="nav-col-count">${list.length}</span>
          </div>
          ${cells}
        </div>
      `;
    }).join("");

    grid.querySelectorAll(".nav-cell").forEach(c => {
      c.addEventListener("click", () => {
        const f = c.dataset.file;
        if (_navFocus === f) openMD(f);
        else setNavFocus(f);
      });
    });
    // Re-measure stage so scroll area matches the freshly rendered grid.
    _navNaturalW = 0; _navNaturalH = 0;
    if (typeof applyNavZoom === "function") {
      requestAnimationFrame(() => applyNavZoom(_navZoom));
    }
  }

  function setNavFocus(file) {
    _navFocus = file;
    const body = document.body;
    const cells = document.querySelectorAll(".nav-cell");
    if (!file) {
      body.classList.remove("has-nav-focus");
      cells.forEach(c => c.classList.remove("focused", "prev", "next", "related"));
      drawNavEdges(null);
      renderNavFocusPanel(null);
      return;
    }
    body.classList.add("has-nav-focus");
    const edges = effectiveEdges(file);
    const prev = new Set(edges.prev);
    const next = new Set(edges.next);
    const related = new Set(edges.related);
    cells.forEach(c => {
      c.classList.remove("focused", "prev", "next", "related");
      const f = c.dataset.file;
      if (f === file) c.classList.add("focused");
      else if (prev.has(f)) c.classList.add("prev");
      else if (next.has(f)) c.classList.add("next");
      else if (related.has(f)) c.classList.add("related");
      // Override search filter for focus + neighbours so edges can land on real
      // positions (display:none cells report offsetLeft/Top=0, which sends
      // lines into the top-left corner).
      if (f === file || prev.has(f) || next.has(f) || related.has(f)) {
        c.classList.remove("qfilter-out");
      }
    });
    drawNavEdges(file);
    renderNavFocusPanel(file);
    const focused = document.querySelector(".nav-cell.focused");
    if (focused) focused.scrollIntoView({ block: "center", behavior: "smooth" });
  }

  function drawNavEdges(file) {
    const svg = document.getElementById("navEdgeSvg");
    const matrix = document.getElementById("navMatrix");
    if (!svg || !matrix) return;
    while (svg.firstChild) svg.removeChild(svg.firstChild);
    if (!file) return;
    const W = matrix.offsetWidth, H = matrix.offsetHeight;
    if (!W || !H) return;
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    svg.style.width  = W + "px";
    svg.style.height = H + "px";
    const findCell = f =>
      matrix.querySelector('.nav-cell[data-file="' + f.replace(/"/g, '\\"') + '"]');
    const focused = findCell(file);
    if (!focused) return;
    const fx = focused.offsetLeft + focused.offsetWidth / 2;
    const fy = focused.offsetTop  + focused.offsetHeight / 2;
    const ns = "http://www.w3.org/2000/svg";
    const drawTo = (cell, color) => {
      if (!cell) return;
      const tx = cell.offsetLeft + cell.offsetWidth / 2;
      const ty = cell.offsetTop  + cell.offsetHeight / 2;
      const dx = tx - fx, dy = ty - fy;
      const horizontal = Math.abs(dx) >= Math.abs(dy);
      const c1x = horizontal ? fx + dx * 0.5 : fx;
      const c1y = horizontal ? fy            : fy + dy * 0.5;
      const c2x = horizontal ? tx - dx * 0.5 : tx;
      const c2y = horizontal ? ty            : ty - dy * 0.5;
      const p = document.createElementNS(ns, "path");
      p.setAttribute("d", `M ${fx} ${fy} C ${c1x} ${c1y}, ${c2x} ${c2y}, ${tx} ${ty}`);
      p.setAttribute("stroke", color);
      p.setAttribute("stroke-width", "1.6");
      p.setAttribute("opacity", "0.78");
      svg.appendChild(p);
    };
    const edges = effectiveEdges(file);
    edges.prev.forEach   (f => drawTo(findCell(f), "#00d4ff"));
    edges.next.forEach   (f => drawTo(findCell(f), "#ffb800"));
    edges.related.forEach(f => drawTo(findCell(f), "#00ff9c"));
  }

  function renderNavFocusPanel(file) {
    const panel = document.getElementById("navFocus");
    if (!panel) return;
    if (!file) {
      panel.className = "nav-focus empty";
      panel.innerHTML = "";
      return;
    }
    const t = D.techniques.find(x => x.f === file);
    const p = t ? phaseById[t.p] : null;
    const edges = effectiveEdges(file);
    const renderList = (arr, cls, label) => arr.length
      ? `<div class="nav-focus-section ${cls}">
           <h4>${label} (${arr.length})</h4>
           <div class="nav-focus-links">
             ${arr.map(f => {
               const tt = D.techniques.find(x => x.f === f);
               const name = tt ? tt.n : shortFileName(f);
               return `<a class="nav-focus-link" data-file="${escapeHtml(f)}">${escapeHtml(name)}<span class="nfl-path">${escapeHtml(f)}</span></a>`;
             }).join("")}
           </div>
         </div>`
      : "";
    panel.className = "nav-focus";
    panel.innerHTML = `
      <div class="nav-focus-title">${escapeHtml(t ? t.n : shortFileName(file))}</div>
      <div class="nav-focus-meta">
        ${p ? `<span style="color:${p.color}">${p.code} · ${p.name}</span> · ` : ""}${escapeHtml(file)}
      </div>
      ${renderList(edges.prev,    "prev",    "前 (predecessor)")}
      ${renderList(edges.next,    "next",    "後 (successor)")}
      ${renderList(edges.related, "related", "関連 (related)")}
      ${(edges.prev.length + edges.next.length + edges.related.length === 0)
        ? `<div style="color:var(--fg-2);font-size:11px;">(関連技術セクションなし、または空)</div>`
        : ""}
      <div class="nav-focus-actions">
        <button class="nav-focus-btn" data-act="open">📖 ファイルを開く</button>
        <button class="nav-focus-btn secondary" data-act="clear">✕ フォーカス解除</button>
      </div>
    `;
    panel.querySelector("[data-act='open']").addEventListener("click", () => openMD(file));
    panel.querySelector("[data-act='clear']").addEventListener("click", () => setNavFocus(null));
    panel.querySelectorAll(".nav-focus-link").forEach(a => {
      a.addEventListener("click", () => setNavFocus(a.dataset.file));
    });
  }

  async function ensureNavReady() {
    if (_navLoaded) return;
    const status = document.getElementById("navStatus");
    if (isFile) {
      if (status) status.textContent = "⚠ file:// では Navigator を構築できません — HTTP サーバ経由で開いてください";
      return;
    }
    if (!dataLoaded) {
      if (status) status.textContent = "› waiting for kedalab data …";
      // try once more after current microtask; the user can retry
      return;
    }
    if (status) status.textContent = "› fetching markdown for navigator … (初回のみ)";
    await ensureContentIndex();
    // Replace TECHNIQUES_INDEX per-row labels with the file's H1 (canonical title).
    // A single file often has many sub-technique rows in the index (e.g. Web_Enumeration.md
    // has rows like "robots.txt 隠しパス発見", "vhost ファジング", …); only the first row's
    // label survived dedup, which made files hard to find by name. The H1 covers the file as a whole.
    for (const t of D.techniques) {
      const md = _mdCache.get(t.f);
      if (!md) continue;
      const h1 = extractH1(md);
      if (h1) t.n = h1;
    }
    const beforeN = D.techniques.length;
    await buildEdgesIndex();
    const addedN = D.techniques.length - beforeN;
    // Orphan resolution may have added new techniques — refresh Browser counts
    if (addedN > 0) {
      recomputeStats();
      renderToolbar();
      renderTechniques();
    }
    renderNavigatorMatrix();
    _navLoaded = true;
    const linked = Array.from(_edges.values())
      .reduce((n, e) => n + e.prev.length + e.next.length + e.related.length, 0);
    if (status) status.textContent =
      `${D.techniques.length} files (incl. ${addedN} auto-discovered) · ${linked} edges parsed from 関連技術 sections`;
  }

  function enterNavMode() {
    document.body.classList.add("nav-mode");
    window.scrollTo({ top: 0, behavior: "instant" });
    ensureNavReady();
  }
  function exitNavMode() {
    document.body.classList.remove("nav-mode");
  }

  // Navigator zoom (CSS variable --nav-zoom; bar + Ctrl+wheel)
  const NAV_ZOOM_MIN = 0.4, NAV_ZOOM_MAX = 2.0, NAV_ZOOM_STEP = 0.1;
  let _navZoom = 1;
  let _navNaturalW = 0, _navNaturalH = 0;
  function measureNavMatrix() {
    const matrix = document.getElementById("navMatrix");
    const frame  = document.getElementById("navViewportFrame");
    if (!matrix || !frame) return;
    // Temporarily clear positioning/transform to measure natural layout size.
    const prevTransform = matrix.style.transform;
    const prevPosition  = matrix.style.position;
    const prevWidth     = matrix.style.width;
    matrix.style.transform = "none";
    matrix.style.position  = "static";
    matrix.style.width     = "";
    _navNaturalW = matrix.scrollWidth;
    _navNaturalH = matrix.scrollHeight;
    matrix.style.transform = prevTransform;
    matrix.style.position  = prevPosition;
    matrix.style.width     = prevWidth;
    matrix.style.width     = _navNaturalW + "px";
  }
  function applyNavZoom(z) {
    _navZoom = Math.max(NAV_ZOOM_MIN, Math.min(NAV_ZOOM_MAX, Math.round(z * 100) / 100));
    const vp = document.querySelector(".nav-viewport");
    if (vp) vp.style.setProperty("--nav-zoom", _navZoom);
    const pct = document.getElementById("navZoomPct");
    if (pct) pct.textContent = Math.round(_navZoom * 100) + "%";
    if (!_navNaturalW || !_navNaturalH) measureNavMatrix();
    const stage = document.getElementById("navScrollStage");
    if (stage && _navNaturalW && _navNaturalH) {
      stage.style.width  = (_navNaturalW * _navZoom) + "px";
      stage.style.height = (_navNaturalH * _navZoom) + "px";
    }
  }
  // Re-measure when matrix content changes (e.g., after data loads) or viewport resizes.
  window.addEventListener("resize", () => {
    _navNaturalW = 0; _navNaturalH = 0;
    if (document.body.classList.contains("nav-mode")) {
      applyNavZoom(_navZoom);
      if (_navFocus) drawNavEdges(_navFocus);
    }
  });
  const _navZoomBar = document.getElementById("navZoomBar");
  if (_navZoomBar) {
    _navZoomBar.addEventListener("click", e => {
      const btn = e.target.closest(".nav-zoom-btn");
      if (!btn) return;
      const act = btn.dataset.act;
      if (act === "in")    applyNavZoom(_navZoom + NAV_ZOOM_STEP);
      else if (act === "out")   applyNavZoom(_navZoom - NAV_ZOOM_STEP);
      else if (act === "reset") applyNavZoom(1);
    });
  }
  const _navFrame = document.getElementById("navViewportFrame");
  if (_navFrame) {
    _navFrame.addEventListener("wheel", e => {
      if (!e.ctrlKey) return;
      e.preventDefault();
      applyNavZoom(_navZoom + (e.deltaY < 0 ? NAV_ZOOM_STEP : -NAV_ZOOM_STEP));
    }, { passive: false });
    // Right-click drag = pan
    let panStartX = 0, panStartY = 0, panScrollL = 0, panScrollT = 0;
    let panning = false, panMoved = false;
    _navFrame.addEventListener("mousedown", e => {
      if (e.button !== 2) return;
      panning = true; panMoved = false;
      panStartX = e.clientX; panStartY = e.clientY;
      panScrollL = _navFrame.scrollLeft; panScrollT = _navFrame.scrollTop;
      _navFrame.style.cursor = "grabbing";
      e.preventDefault();
    });
    window.addEventListener("mousemove", e => {
      if (!panning) return;
      const dx = e.clientX - panStartX;
      const dy = e.clientY - panStartY;
      if (!panMoved && (Math.abs(dx) > 3 || Math.abs(dy) > 3)) panMoved = true;
      _navFrame.scrollLeft = panScrollL - dx;
      _navFrame.scrollTop  = panScrollT - dy;
    });
    window.addEventListener("mouseup", e => {
      if (!panning || e.button !== 2) return;
      panning = false;
      _navFrame.style.cursor = "";
    });
    // Suppress context menu only when an actual pan happened
    _navFrame.addEventListener("contextmenu", e => {
      if (panMoved) { e.preventDefault(); panMoved = false; }
    });
  }

  // Brand "KEDALAB" → ホームに戻る (exit nav-mode, scroll to top, clear hash)
  const _brandHome = document.getElementById("brandHome");
  if (_brandHome) {
    _brandHome.addEventListener("click", e => {
      e.preventDefault();
      if (document.body.classList.contains("nav-mode")) exitNavMode();
      if (location.hash) history.replaceState(null, "", location.pathname + location.search);
      window.scrollTo({ top: 0, behavior: "smooth" });
    });
  }

  // Wire nav links — Navigator entry toggles page mode; others exit it
  $$(".nav-link").forEach(a => {
    a.addEventListener("click", () => {
      if (a.dataset.page === "navigator") {
        // anchor href #navigator stays — let the hash update, but suppress
        // default scroll by handling visibility ourselves
        setTimeout(enterNavMode, 0);
      } else if (document.body.classList.contains("nav-mode")) {
        exitNavMode();
      }
    });
  });

  // In-page search box
  const _navSearchEl = document.getElementById("navSearch");
  if (_navSearchEl) {
    // When the filter changes while a focus is active, cell layout shifts —
    // re-run focus to keep neighbour cells visible (so they have non-zero
    // offsets) and redraw edges against the new layout.
    const reapplyFocusAfterFilter = () => {
      if (!_navFocus) return;
      const edges = effectiveEdges(_navFocus);
      const keep = new Set([_navFocus, ...edges.prev, ...edges.next, ...edges.related]);
      $$(".nav-cell").forEach(c => {
        if (keep.has(c.dataset.file)) c.classList.remove("qfilter-out");
      });
      requestAnimationFrame(() => drawNavEdges(_navFocus));
    };
    _navSearchEl.addEventListener("input", e => {
      const q = e.target.value.toLowerCase().trim();
      const toks = q.split(/\s+/).filter(Boolean);
      $$(".nav-cell").forEach(c => {
        if (!toks.length) { c.classList.remove("qfilter-out"); return; }
        const f = c.dataset.file;
        const body = _contentIndex.get(f) || "";
        const hay = (c.textContent + " " + f).toLowerCase();
        c.classList.toggle("qfilter-out", !toks.every(t => hay.includes(t) || body.includes(t)));
      });
      reapplyFocusAfterFilter();
    });
    _navSearchEl.addEventListener("keydown", e => {
      if (e.key === "Enter") {
        const first = document.querySelector(".nav-cell:not(.qfilter-out)");
        if (first) setNavFocus(first.dataset.file);
      } else if (e.key === "Escape") {
        e.target.value = "";
        $$(".nav-cell").forEach(c => c.classList.remove("qfilter-out"));
        reapplyFocusAfterFilter();
      }
    });
  }

  const _navClearBtn = document.getElementById("navClear");
  if (_navClearBtn) _navClearBtn.addEventListener("click", () => setNavFocus(null));

  // Auto-enter if URL hash is #navigator on load
  if (location.hash === "#navigator") {
    // wait for data so the matrix has techniques to render
    setTimeout(() => enterNavMode(), 100);
  }

  // ============================================================
  // Top search — uses palette
  // ============================================================
  $("#topSearch").addEventListener("input", e => {
    currentQuery = e.target.value;
    if (currentQuery) {
      expandCollapsible("browser");
      ensureContentIndex(); // background; re-renders when ready
    }
    renderTechniques();
    document.getElementById("browser").scrollIntoView({ behavior: "smooth", block: "start" });
  });

  // ---- collapsible section helpers ----
  function expandCollapsible(id) {
    const sec = document.getElementById(id);
    if (!sec || !sec.classList.contains("collapsible")) return;
    sec.dataset.collapsed = "false";
    const btn = sec.querySelector(".coll-header");
    if (btn) btn.setAttribute("aria-expanded", "true");
  }
  function bindCollapsibles() {
    $$(".collapsible .coll-header").forEach(btn => {
      btn.addEventListener("click", () => {
        const sec = btn.closest(".collapsible");
        const closed = sec.dataset.collapsed === "true";
        sec.dataset.collapsed = closed ? "false" : "true";
        btn.setAttribute("aria-expanded", closed ? "true" : "false");
      });
    });
    // Also: clicking a Chain or QuickStart phase chip should auto-expand Browser
  }
  bindCollapsibles();

  // intercept setFilter calls (from chain card / phase chip) so Browser opens
  const _origSetFilter = setFilter;
  setFilter = function (phaseId) {
    expandCollapsible("browser");
    _origSetFilter(phaseId);
  };

  // ============================================================
  // Cmd palette
  // ============================================================
  const palette = $("#palette");
  const paletteInput = $("#paletteInput");
  const paletteList = $("#paletteList");
  let paletteSel = 0;
  let paletteHits = [];

  function openPalette() {
    palette.classList.add("open");
    paletteInput.value = "";
    paletteSel = 0;
    paletteHits = D.techniques.slice(0, 40);
    drawPalette();
    setTimeout(() => paletteInput.focus(), 30);
  }
  function closePalette() {
    palette.classList.remove("open");
  }

  function drawPalette() {
    if (!paletteHits.length) {
      paletteList.innerHTML = `<div class="palette-empty">該当なし</div>`;
      return;
    }
    paletteList.innerHTML = paletteHits.slice(0, 40).map((t, i) => {
      const p = phaseById[t.p];
      return `
        <div class="palette-item ${i === paletteSel ? 'sel' : ''}" data-i="${i}">
          <span class="pi-name">${escapeHtml(t.n)}</span>
          <span class="pi-phase" style="color:${p.color}">${p.code}</span>
          <span class="pi-file">${t.f}</span>
        </div>
      `;
    }).join("");
    $$(".palette-item", paletteList).forEach(el => {
      el.addEventListener("click", () => {
        const t = paletteHits[+el.dataset.i];
        closePalette();
        openMD(t.f);
      });
      el.addEventListener("mouseenter", () => {
        paletteSel = +el.dataset.i;
        $$(".palette-item", paletteList).forEach(x => x.classList.remove("sel"));
        el.classList.add("sel");
      });
    });
  }

  paletteInput.addEventListener("input", e => {
    const q = e.target.value;
    paletteSel = 0;
    if (!q) {
      paletteHits = D.techniques.slice(0, 40);
    } else {
      // Score each entry, drop zeros, sort by score desc, then keep top 60.
      // Same ranking weights as the Browser scoring (scoreEntry).
      paletteHits = D.techniques
        .map(t => ({ t, s: scoreEntry(t, q) }))
        .filter(x => x.s > 0)
        .sort((a, b) => b.s - a.s)
        .slice(0, 60)
        .map(x => x.t);
    }
    drawPalette();
  });

  paletteInput.addEventListener("keydown", e => {
    if (e.key === "Escape") return closePalette();
    if (e.key === "ArrowDown") { e.preventDefault(); paletteSel = Math.min(paletteSel + 1, paletteHits.length - 1); drawPalette(); scrollSel(); }
    if (e.key === "ArrowUp")   { e.preventDefault(); paletteSel = Math.max(paletteSel - 1, 0); drawPalette(); scrollSel(); }
    if (e.key === "Enter") {
      const t = paletteHits[paletteSel];
      if (t) { closePalette(); openMD(t.f); }
    }
  });
  function scrollSel() {
    const el = $(".palette-item.sel", paletteList);
    if (el) el.scrollIntoView({ block: "nearest" });
  }

  document.addEventListener("keydown", e => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
      e.preventDefault();
      if (palette.classList.contains("open")) closePalette();
      else openPalette();
    }
    if (e.key === "Escape") {
      closePalette();
      closeModal();
    }
  });

  palette.addEventListener("click", e => {
    if (e.target === palette) closePalette();
  });

  // ============================================================
  // MD viewer
  // ============================================================
  const modal = $("#modal");
  const modalBody = $("#modalBody");
  const modalPath = $("#modalPath");
  $("#modalClose").addEventListener("click", closeModal);
  $("#modalBack").addEventListener("click", goBack);
  $("#modalNav").addEventListener("click", () => {
    const entry = docStack[docStack.length - 1];
    if (!entry) return;
    closeModal();
    enterNavMode();
    setTimeout(() => setNavFocus(entry.file), 200);
  });

  function wireSearchClear(inputId, clearId) {
    const input = $("#" + inputId);
    const clear = $("#" + clearId);
    if (!input || !clear) return;
    const update = () => { clear.hidden = !input.value; };
    input.addEventListener("input", update);
    clear.addEventListener("click", () => {
      input.value = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.focus();
    });
    update();
  }
  wireSearchClear("topSearch", "topSearchClear");
  wireSearchClear("navSearch", "navSearchClear");
  wireSearchClear("paletteInput", "paletteClear");
  modal.addEventListener("click", e => {
    if (e.target === modal) closeModal();
  });

  const docStack = [];

  function updateBackButton() {
    const btn = $("#modalBack");
    if (btn) btn.hidden = docStack.length <= 1;
  }

  function goBack() {
    if (docStack.length <= 1) return;
    docStack.pop();
    const prev = docStack[docStack.length - 1];
    openMD(prev.file, true, prev.scrollTop || 0);
  }

  function closeModal() {
    modal.classList.remove("open");
    modalBody.innerHTML = "";
    docStack.length = 0;
    updateBackButton();
  }

  async function openMD(file, isBack = false, restoreScroll = 0) {
    if (!file) return;
    modal.classList.add("open");
    if (!isBack) {
      if (docStack.length > 0) docStack[docStack.length - 1].scrollTop = modalBody.scrollTop;
      docStack.push({ file, scrollTop: 0 });
    }
    updateBackButton();
    const navBtn = $("#modalNav");
    if (navBtn) navBtn.hidden = !D.techniques.some(t => t.f === file);
    // breadcrumb-like path
    const parts = file.split("/");
    modalPath.innerHTML = parts.map((p, i) =>
      i === parts.length - 1 ? `<span class="seg-acc">${p}</span>` : p
    ).join(" / ");
    modalBody.innerHTML = `<div class="modal-loading">› fetching <code>${file}</code> …</div>`;

    // file:// vs http
    const isFile = location.protocol === "file:";
    if (isFile) {
      modalBody.innerHTML = `
        <div class="modal-error">
          <div style="font-size:18px;color:var(--acc-r);">⚠ file:// プロトコルでは fetch が制限されます</div>
          <p style="margin-top:18px;color:var(--fg-1);">ローカルHTTPサーバ経由で開いてください：</p>
          <code>python -m http.server 8000</code>
          <p style="margin-top:18px;color:var(--fg-2);font-size:11px;">
            （kedalab ルートで実行 → <code>http://localhost:8000/99_kedaweb/</code> を開く）
          </p>
          <p style="margin-top:24px;">代わりに <strong>GitHub / ローカル</strong>の原本：</p>
          <code>${file}</code>
        </div>
      `;
      return;
    }

    try {
      const url = "../" + file;
      const res = await fetch(url);
      if (!res.ok) throw new Error("HTTP " + res.status);
      const text = await res.text();
      modalBody.innerHTML = `<div class="md">${markdown(text)}</div>`;
      modalBody.scrollTop = restoreScroll;
      const baseDir = file.split("/").slice(0, -1).join("/");
      // linkify plain-text .md paths in the body (tables, code, sentences)
      linkifyMdPaths(modalBody, baseDir);
      // intercept explicit markdown links to open in modal
      $$("a", modalBody).forEach(a => {
        if (a.classList.contains("md-auto")) return; // already wired
        const href = a.getAttribute("href");
        if (href && href.endsWith(".md") && !href.startsWith("http")) {
          a.addEventListener("click", e => {
            e.preventDefault();
            let resolved;
            if (href.startsWith("./") || href.startsWith("../")) {
              resolved = resolvePath(baseDir, href);
            } else if (href.includes("/")) {
              resolved = href;
            } else {
              resolved = baseDir ? baseDir + "/" + href : href;
            }
            openMD(resolved);
          });
        }
      });
    } catch (err) {
      modalBody.innerHTML = `
        <div class="modal-error">
          <div style="font-size:18px;">✕ ファイルを読み込めませんでした</div>
          <p style="margin-top:14px;color:var(--fg-1);">${escapeHtml(String(err))}</p>
          <code>${file}</code>
        </div>
      `;
    }
  }

  // walk text nodes, replace ".md" path strings with clickable anchors
  function linkifyMdPaths(root, baseDir) {
    const SKIP = new Set(["A", "PRE", "SCRIPT", "STYLE"]);
    // matches: zero or more ./ or ../ prefixes, word/digit segments, ending in .md
    const RE = /(?:\.\.?\/)*(?:[\w][\w\-]*\/)*[\w][\w\-]*\.md\b/g;

    function walk(node) {
      if (node.nodeType === 1) {
        if (SKIP.has(node.tagName)) return;
        Array.from(node.childNodes).forEach(walk);
        return;
      }
      if (node.nodeType !== 3) return;
      const text = node.nodeValue;
      if (!RE.test(text)) return;
      RE.lastIndex = 0;

      const frag = document.createDocumentFragment();
      let lastIdx = 0;
      let m;
      while ((m = RE.exec(text)) !== null) {
        if (m.index > lastIdx) {
          frag.appendChild(document.createTextNode(text.slice(lastIdx, m.index)));
        }
        const raw = m[0];
        // resolve:
        //  - "./X.md" or "../X.md"           → relative to baseDir
        //  - "01_Foo/X.md" (top-level prefix) → root-relative
        //  - "X.md" (bare filename)           → same folder as the current file
        //    (matches WRITING_GUIDE: bare name is preferred for sibling references)
        let resolved;
        if (!raw.includes("/")) {
          resolved = baseDir ? baseDir + "/" + raw : raw;
        } else if (raw.startsWith("./") || raw.startsWith("../")) {
          resolved = resolvePath(baseDir, raw);
        } else {
          resolved = raw;
        }
        const a = document.createElement("a");
        a.className = "md-auto";
        a.href = "#";
        a.dataset.md = resolved;
        a.textContent = raw;
        a.title = "→ " + resolved;
        frag.appendChild(a);
        lastIdx = m.index + raw.length;
      }
      if (lastIdx < text.length) {
        frag.appendChild(document.createTextNode(text.slice(lastIdx)));
      }
      node.parentNode.replaceChild(frag, node);
    }

    walk(root);

    root.querySelectorAll("a.md-auto").forEach(a => {
      a.addEventListener("click", e => {
        e.preventDefault();
        openMD(a.dataset.md);
      });
    });
  }

  function resolvePath(base, rel) {
    if (rel.startsWith("./")) rel = rel.slice(2);
    const parts = (base ? base.split("/") : []).concat(rel.split("/"));
    const out = [];
    for (const p of parts) {
      if (p === "." || p === "") continue;
      if (p === "..") out.pop();
      else out.push(p);
    }
    return out.join("/");
  }

  // ============================================================
  // Minimal markdown renderer
  // ============================================================
  function markdown(src) {
    // normalize newlines
    src = src.replace(/\r\n/g, "\n");

    // extract fenced code blocks first (placeholder)
    const fences = [];
    src = src.replace(/```([^\n]*)\n([\s\S]*?)```/g, (m, lang, code) => {
      const idx = fences.length;
      fences.push({ lang: lang.trim(), code });
      return ` F${idx} `;
    });

    // tables: convert "| a | b |\n| --- |\n| ... |" blocks
    src = src.replace(/((?:^\|.*\|[ \t]*\n)+)/gm, block => {
      const lines = block.trim().split("\n").map(l => l.trim());
      if (lines.length < 2 || !/^\|[\s:|\-]+\|$/.test(lines[1])) return block;
      // CommonMark: \| inside a cell is a literal pipe. Sentinel-swap so split("|") doesn't break it.
      const PIPE_ESC = "";
      const rows = lines.filter((_, i) => i !== 1).map(l =>
        l.replace(/\\\|/g, PIPE_ESC)
         .replace(/^\|/, "").replace(/\|$/, "")
         .split("|").map(c => c.trim().split(PIPE_ESC).join("|"))
      );
      const head = rows[0];
      const body = rows.slice(1);
      let html = "<table><thead><tr>" + head.map(h => `<th>${inline(h)}</th>`).join("") + "</tr></thead>";
      html += "<tbody>" + body.map(r => "<tr>" + r.map(c => `<td>${inline(c)}</td>`).join("") + "</tr>").join("") + "</tbody></table>";
      // Preserve a trailing \n so the blank line that originally separated the
      // table from the next paragraph survives split(/\n{2,}/) below.
      return html + "\n";
    });

    // headers
    src = src.replace(/^#{6}\s+(.*)$/gm, (m, c) => "<h6>" + inline(c) + "</h6>");
    src = src.replace(/^#{5}\s+(.*)$/gm, (m, c) => "<h5>" + inline(c) + "</h5>");
    src = src.replace(/^####\s+(.*)$/gm, (m, c) => "<h4>" + inline(c) + "</h4>");
    src = src.replace(/^###\s+(.*)$/gm, (m, c) => "<h3>" + inline(c) + "</h3>");
    src = src.replace(/^##\s+(.*)$/gm, (m, c) => "<h2>" + inline(c) + "</h2>");
    src = src.replace(/^#\s+(.*)$/gm, (m, c) => "<h1>" + inline(c) + "</h1>");

    // hr
    src = src.replace(/^---+$/gm, "<hr>");

    // blockquotes (single line)
    src = src.replace(/^>\s?(.*)$/gm, (m, c) => "<blockquote>" + inline(c) + "</blockquote>");

    // lists
    // Captures bullet lines + any indented (>= 1 space) continuation lines.
    // CommonMark treats `  (example...)` directly under `- bullet` as part of
    // the bullet's paragraph. Without merging here, the continuation became
    // orphan text between </ul> and <ul>, losing inline() processing — so
    // backticks showed as literal characters and tables/lists got fragmented.
    function joinListItems(block, isOrdered) {
      const markerRe = isOrdered ? /^[ \t]*\d+\.\s+(.*)$/ : /^[ \t]*[-*]\s+(.*)$/;
      const items = [];
      let current = null;
      for (const line of block.split("\n")) {
        if (!line.length) continue;
        const m = line.match(markerRe);
        if (m) {
          if (current !== null) items.push(current);
          current = m[1];
        } else if (current !== null && /^[ \t]+\S/.test(line)) {
          current += " " + line.trim();
        }
      }
      if (current !== null) items.push(current);
      const tag = isOrdered ? "ol" : "ul";
      return `<${tag}>` + items.map(i => `<li>${inline(i)}</li>`).join("") + `</${tag}>\n`;
    }
    src = src.replace(
      /(?:^[ \t]*[-*]\s+[^\n]*(?:\n[ \t]+(?![-*]\s|\d+\.\s)[^\n]*)*\n?)+/gm,
      block => joinListItems(block, false)
    );
    src = src.replace(
      /(?:^[ \t]*\d+\.\s+[^\n]*(?:\n[ \t]+(?![-*]\s|\d+\.\s)[^\n]*)*\n?)+/gm,
      block => joinListItems(block, true)
    );

    // paragraphs — split on blank lines, wrap non-block lines
    const html = src.split(/\n{2,}/).map(chunk => {
      const t = chunk.trim();
      if (!t) return "";
      if (/^<(h\d|ul|ol|table|blockquote|hr|pre)/.test(t)) return chunk;
      if (/^ F\d+ /.test(t)) return chunk;
      // Defensive: chunk may contain a block element mid-text when markdown
      // source omits a blank line (e.g. **bold:**\n- item). Split it so
      // inline() does not escape the generated <ul>/<ol>/<table>.
      if (/<(ul|ol|table|blockquote|pre|h[1-6])\b/.test(t) || /<hr\s*\/?>/.test(t)) {
        const blockRe = /<(ul|ol|table|blockquote|pre|h[1-6])\b[^>]*>[\s\S]*?<\/\1>|<hr\s*\/?>/g;
        const parts = [];
        let last = 0;
        let m;
        while ((m = blockRe.exec(t)) !== null) {
          const before = t.slice(last, m.index).trim();
          if (before) parts.push("<p>" + inline(before.replace(/\n/g, " ")) + "</p>");
          parts.push(m[0]);
          last = m.index + m[0].length;
        }
        const after = t.slice(last).trim();
        if (after) parts.push("<p>" + inline(after.replace(/\n/g, " ")) + "</p>");
        return parts.join("\n");
      }
      return "<p>" + inline(t.replace(/\n/g, " ")) + "</p>";
    }).join("\n");

    // re-insert fences (highlight() handles HTML-escaping internally)
    return html.replace(/ F(\d+) /g, (_, i) => {
      const f = fences[+i];
      return `<pre><code class="lang-${escapeHtml(f.lang)}">${highlight(f.code, f.lang)}</code></pre>`;
    });
  }

  function inline(s) {
    // escape first
    s = s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    // inline code
    s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
    // bold
    s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    // italic
    s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
    // links
    s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
    // auto link
    s = s.replace(/(?<!["'>=])(https?:\/\/[^\s<]+)/g, '<a href="$1" target="_blank" rel="noopener">$1</a>');
    return s;
  }

  // Syntax highlighter — sentinel-based to avoid the classic
  // 'regex matches its own injected span markup' bug.
  // Strategy: run regex on RAW code, record matches as token table, replace
  // each match with a sentinel-wrapped index, escape HTML on the result,
  // then expand sentinels back into <span> markup.
  function highlight(code, lang) {
    const SENT_O = '', SENT_C = '';
    const tokens = [];
    function mark(re, color) {
      code = code.replace(re, m => {
        const idx = tokens.length;
        tokens.push({ color, text: m });
        return SENT_O + idx + SENT_C;
      });
    }
    // Strings first (so quote chars are consumed before keyword/comment matches).
    mark(/(\"([^\"\\\\]|\\\\.)*\"|'([^'\\\\]|\\\\.)*')/g, '#ffb800');
    // Line comments (bash/python '#').
    mark(/(#[^\n]*)/g, '#5b6f8a');
    if (lang) {
      const kw = {
        bash: /\b(if|then|fi|for|do|done|while|case|esac|in|echo|sudo|export|cd|ls|cat|grep|awk|sed|find|chmod|chown|mkdir|rm|cp|mv|tar|gzip|gunzip|wget|curl|nmap|nc|python3?|bash|sh)\b/g,
        python: /\b(def|class|import|from|return|if|elif|else|for|while|try|except|with|as|in|not|and|or|is|None|True|False|self|lambda|pass|break|continue|yield)\b/g,
        powershell: /\b(Get-|Set-|New-|Remove-|Add-|Invoke-|Where-Object|ForEach-Object|Select-|param|function|return|if|else|elseif|foreach|while|try|catch|finally)/g,
        sql: /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|UNION|GROUP|ORDER|BY|LIMIT|HAVING|AS|AND|OR|NOT|NULL|TRUE|FALSE|EXEC|EXECUTE)\b/gi
      };
      const reKw = kw[lang.toLowerCase()];
      if (reKw) mark(reKw, '#ff3d8a');
    }
    mark(/(CVE-\d{4}-\d+)/g, '#00d4ff');
    code = escapeHtml(code);
    return code.replace(new RegExp(SENT_O + '(\\d+)' + SENT_C, 'g'), (_, i) => {
      const t = tokens[+i];
      return `<span style="color:${t.color}">${escapeHtml(t.text)}</span>`;
    });
  }

  // ============================================================
  // Stat counters
  // ============================================================
  function animateCounters() {
    setStat("statTotal", D.techniques.length);
    setStat("statPhases", D.phases.length);
    setStat("statPlay", (D.playbookList || []).length);
    setStat("statCVE", cveCount);
    setStat("statAI", phaseCounts.ai);
  }
  function setStat(id, target) {
    const el = document.getElementById(id);
    if (!el) return;
    const duration = 1100;
    const start = performance.now();
    function step(t) {
      const k = Math.min((t - start) / duration, 1);
      const v = Math.floor(target * (1 - Math.pow(1 - k, 3)));
      el.textContent = v;
      if (k < 1) requestAnimationFrame(step);
      else el.textContent = target;
    }
    requestAnimationFrame(step);
  }

  // ============================================================
  // Reveal on scroll
  // ============================================================
  function triggerReveal() {
    const io = new IntersectionObserver(entries => {
      entries.forEach(e => {
        if (e.isIntersecting) {
          e.target.classList.add("in");
          io.unobserve(e.target);
        }
      });
    }, { threshold: 0.08 });
    $$(".reveal").forEach(el => io.observe(el));
  }

  // Footer meta is updated by updateFooter() inside renderAll().

  // ============================================================
  // Bootstrap — load kedalab data then render
  // ============================================================
  function showFileBanner() {
    if (!isFile) return;
    const banner = document.createElement("div");
    banner.style.cssText = `
      position: fixed; top: 60px; left: 0; right: 0; z-index: 95;
      background: rgba(255, 61, 138, 0.12);
      border-bottom: 1px solid rgba(255, 61, 138, 0.4);
      color: #ff3d8a; font-family: var(--mono); font-size: 12px;
      padding: 8px 16px; text-align: center;
    `;
    banner.innerHTML = `
      ⚠ <strong>file://</strong> プロトコルでは fetch がブロックされます — kedalab 内容は読み込めません。
      <code style="background:rgba(0,0,0,0.4);padding:1px 6px;border-radius:3px;color:#00ff9c;margin-left:4px">
        python -m http.server 8000
      </code> など、HTTP サーバ経由で開いてください。
    `;
    document.body.appendChild(banner);
  }

  async function loadKedalabData() {
    if (isFile) {
      setPill("⚠ file:// — no fetch", "err");
      return;
    }
    setPill("⋯ fetching TECHNIQUES_INDEX.md", "loading");
    try {
      D.techniques = await loadTechniques();
      console.log("[loader] techniques:", D.techniques.length);
    } catch (e) {
      console.warn("[loader] techniques failed:", e);
      loaderErrors.push("techniques: " + e.message);
    }
    try {
      const pbs = await loadPlaybookNodes();
      const existing = new Set(D.techniques.map(t => t.f));
      const added = pbs.filter(p => !existing.has(p.f));
      D.techniques = D.techniques.concat(added);
      console.log("[loader] playbook nodes:", pbs.length, "added:", added.length);
    } catch (e) {
      console.warn("[loader] playbooks failed:", e);
      loaderErrors.push("playbooks: " + e.message);
    }
    setPill("⋯ fetching README & playbooks", "loading");
    try {
      D.situations = await loadSituations();
      console.log("[loader] situations:", D.situations.length);
    } catch (e) {
      console.warn("[loader] situations failed:", e);
      loaderErrors.push("situations: " + e.message);
    }
    // Playbook cards = unique playbook files referenced by situations, in
    // first-appearance order, with H1 as label.
    const seen = new Set();
    const playbookFiles = (D.situations || [])
      .map(s => s.file)
      .filter(f => f && !seen.has(f) && seen.add(f));
    D.playbookList = await Promise.all(playbookFiles.map(async f => {
      let name = f.split("/").pop().replace(/\.md$/, "");
      try {
        const md = await getMd(f);
        const t = extractH1(md);
        if (t) name = t;
      } catch (e) { /* keep filename */ }
      return { name, file: f, entry: shortLabel(f), icon: "📋" };
    }));
    recomputeStats();
  }

  // Render everything. Safe to call before data loads — empty arrays just
  // produce a skeleton UI with "loading…" messages. Each renderer is wrapped
  // so one failing renderer cannot break the rest of the page.
  function safeCall(name, fn) {
    try { fn(); }
    catch (e) {
      console.error("[render:" + name + "]", e);
      loaderErrors.push(name + ": " + e.message);
    }
  }
  function renderAll() {
    safeCall("quickstart",  renderQuickstart);
    safeCall("raw",         renderRaw);
    safeCall("toolbar",     renderToolbar);
    safeCall("techniques",  renderTechniques);
    safeCall("footer",      updateFooter);
  }

  function updateFooter() {
    const meta = $("#footMeta");
    if (!meta) return;
    meta.textContent = dataLoaded
      ? `Techniques: ${D.techniques.length} · Phases: ${D.phases.length} · Playbooks: ${(D.playbookList || []).length}`
      : "› fetching kedalab/ …";
  }

  // 1) Synchronous initial render → user sees scaffolding immediately
  showFileBanner();
  renderAll();

  function setLoadedPill() {
    if (loaderErrors.length) {
      setPill("✕ " + loaderErrors.length + " err · ⟲ retry", "err");
    } else if (isFile) {
      setPill("⚠ file:// fallback", "err");
    } else {
      const t = D.techniques.length;
      const p = (D.playbookList || []).length;
      setPill(`✓ ${t} tech · ${p} pb · ⟲ reload`, "ok");
    }
  }

  // ---- post-load finalizer (re-usable for reload too) ----
  function finalizeLoad() {
    dataLoaded = true;
    renderAll();
    animateCounters();
    setLoadedPill();
    // If user already navigated to the Navigator page while data was loading,
    // kick off its build now that techniques are available.
    if (document.body.classList.contains("nav-mode")) ensureNavReady();
  }

  // 2) After kedalab data is loaded → re-render and animate stats
  loadKedalabData()
    .catch(e => {
      console.error("[loader] unexpected:", e);
      loaderErrors.push("unexpected: " + e.message);
    })
    .finally(finalizeLoad);

  // ---- click pill → invalidate cache and refetch everything ----
  let _reloading = false;
  async function reloadKedalabData() {
    if (_reloading || isFile) return;
    _reloading = true;
    loaderErrors.length = 0;
    _mdCache.clear();
    _contentIndex.clear();
    _contentIndexBuilt = false;
    _contentIndexBuilding = null;
    dataLoaded = false;
    setPill("⋯ reloading kedalab data", "loading");
    try { await loadKedalabData(); }
    catch (e) { loaderErrors.push("reload: " + e.message); }
    finalizeLoad();
    _reloading = false;
  }
  const pillEl = document.getElementById("loaderPill");
  if (pillEl) {
    pillEl.addEventListener("click", reloadKedalabData);
    pillEl.addEventListener("keydown", e => {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); reloadKedalabData(); }
    });
  }
})();

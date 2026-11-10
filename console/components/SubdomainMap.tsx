"use client";

// Subdomain mind-map — a pan/zoom tree of every host under a root domain, grouped by
// DNS zone / network / status, with pattern-folding + grid-wrapping so it stays readable
// from a handful of hosts to hundreds. Ported from the Redstrike dashboard's imperative
// SVG engine and driven by REAL engagement records (see lib/subdomainMap.ts). The whole
// engine runs imperatively inside one effect against the component's own container refs;
// React owns only the skeleton. A host-node click calls onSelectHost → the console's host
// drawer (the real-data stand-in for the dashboard's in-map subdomain drawer).

import { useEffect, useRef } from "react";
import { Plus, Minus, Maximize2, ChevronsUpDown, ChevronsDownUp } from "lucide-react";
import type { MMRecord } from "@/lib/subdomainMap";
import { SEVERITY } from "@/lib/theme";

const MM_ST: Record<string, { label: string; c: string; sub: string }> = {
  live: { label: "Live", c: "#22c55e", sub: "2xx" },
  redirect: { label: "Redirect", c: "#3b82f6", sub: "3xx" },
  auth: { label: "Login wall", c: "#f59e0b", sub: "401 · 403" },
  error: { label: "Error", c: "#f97316", sub: "4xx · 5xx" },
  takeover: { label: "Takeover risk", c: "#ef4444", sub: "dangling CNAME" },
  dead: { label: "No response", c: "#5f5f5f", sub: "no HTTP answer" },
  skip: { label: "Not probed", c: "#8f8f8f", sub: "out of scope" },
};
const MM_ST_ORDER = ["live", "redirect", "auth", "error", "takeover", "dead", "skip"];
const MM_NET: Record<string, { label: string; sub: string }> = {
  colo: { label: "Hosting / colo", sub: "public IPv4" },
  cloud: { label: "Cloud", sub: "cloud IP" },
  cdn: { label: "CDN edge", sub: "edge IP" },
  vendor: { label: "Third-party", sub: "CNAME" },
  priv: { label: "Private address", sub: "RFC 1918" },
  none: { label: "Unresolved", sub: "no address" },
};
const MM_NET_ORDER = ["colo", "cloud", "cdn", "vendor", "priv", "none"];

export interface SubdomainMapProps {
  records: MMRecord[];
  domains: string[];
  rootDomain: string;
  onSelectHost: (host: string) => void;
}

export function SubdomainMap({ records, domains, rootDomain, onSelectHost }: SubdomainMapProps) {
  const rootRef = useRef<HTMLDivElement>(null);
  // keep the latest onSelectHost without re-running the whole engine effect
  const selRef = useRef(onSelectHost);
  selRef.current = onSelectHost;

  useEffect(() => {
    const root = rootRef.current;
    if (!root) return;

    /* ---------- scoped DOM helpers ---------- */
    const NS = "http://www.w3.org/2000/svg";
    const $ = (s: string): any => root.querySelector(s);
    const $$ = (s: string): any[] => Array.from(root.querySelectorAll(s));
    const svgEl = (tag: string, attrs?: any, parent?: any): any => {
      const e = document.createElementNS(NS, tag);
      if (attrs) for (const k in attrs) e.setAttribute(k, attrs[k]);
      if (parent) parent.appendChild(e);
      return e;
    };
    const h = (tag: string, cls?: string, text?: any): any => {
      const e = document.createElement(tag);
      if (cls) e.className = cls;
      if (text != null) e.textContent = text;
      return e;
    };
    const clamp = (v: number, a: number, b: number) => Math.max(a, Math.min(b, v));
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const MM_MOD = /Mac|iPhone|iPad/.test(navigator.platform || "") ? "⌘" : "Ctrl";

    /* ---------- per-domain record index ---------- */
    const recordsByDom: Record<string, MMRecord[]> = {};
    for (const r of records) (recordsByDom[r.dom] || (recordsByDom[r.dom] = [])).push(r);

    /* ---------- constants ---------- */
    const MM_RH = 26, MM_GAP = 34, MM_CH = 7.2, MM_GRID = 14, MM_KMIN = 0.06, MM_KMAX = 2.5;
    const mmFmtN = (n: number) => (n >= 1000 ? (n / 1000).toFixed(1).replace(/\.0$/, "") + "k" : String(n));
    const mmSig = (lab: string) =>
      lab.replace(/[0-9a-f]{6,}/g, (s) => (/\d/.test(s) && /[a-f]/.test(s) ? "*" : s)).replace(/\d+/g, "#");
    const mmNat = (a: string, b: string) => a.localeCompare(b, "en", { numeric: true });
    const mmCols = (len: number) => clamp(Math.round(Math.sqrt(len / 3)), 2, 16);
    const mmGridKids = (n: any) => {
      if (n.kind === "root") return null;
      const lf = n.children.filter((c: any) => !c.children.length);
      return lf.length > MM_GRID ? lf : null;
    };

    const MM: any = {
      dom: recordsByDom[rootDomain] ? rootDomain : (domains[0] || rootDomain),
      group: "zone", q: "", hide: new Set(), open: new Map(), forced: new Set(),
      hits: [], hitSet: new Set(), hit: -1, fresh: new Set(),
      k: 1, tx: 0, ty: 0, tree: null, byId: new Map(), vis: [], els: new Map(),
      links: new Map(), trays: new Map(), hot: [], key: "", dirty: true, fitted: false,
      raf: 0, vraf: 0, focus: "@", sel: null, size: null,
    };
    const mmOpenKey = (id: string) => MM.key + "|" + id;
    const mmIsOpen = (n: any) =>
      n.kind === "root" || MM.forced.has(n.id) ||
      (MM.open.has(mmOpenKey(n.id)) ? MM.open.get(mmOpenKey(n.id)) : n.def);

    /* ---------- tooltip ---------- */
    let tipEl: any = null;
    const tipHide = () => { if (tipEl) tipEl.style.display = "none"; };
    const tipShow = (title: string, rows: any[], x: number, y: number) => {
      const view = $('[data-mm="view"]');
      if (!view) return;
      if (!tipEl) { tipEl = h("div", "mm-tip"); view.appendChild(tipEl); }
      tipEl.replaceChildren();
      tipEl.appendChild(h("div", "mm-tip-t", title));
      rows.forEach((r) => {
        const row = h("div", "mm-tip-r");
        const d = h("span", "mm-tip-d");
        if (r.color && r.color !== "transparent") d.style.background = r.color; else d.style.visibility = "hidden";
        row.append(d, h("span", "mm-tip-n", r.name), h("span", "mm-tip-v", r.value));
        tipEl.appendChild(row);
      });
      const rect = view.getBoundingClientRect();
      tipEl.style.display = "block";
      tipEl.style.left = Math.min(x - rect.left + 14, rect.width - tipEl.offsetWidth - 8) + "px";
      tipEl.style.top = Math.min(y - rect.top + 14, rect.height - tipEl.offsetHeight - 8) + "px";
    };

    /* ---------- tree ---------- */
    function mmBuild() {
      const dom = MM.dom, recs = (recordsByDom[dom] || []).filter((r: any) => !MM.hide.has(r.st));
      const by = new Map<string, any>();
      const mk = (id: string, kind: string, rel: string, parent: any) => {
        const n: any = { id, kind, rel, parent, children: [] };
        if (parent) parent.children.push(n);
        by.set(id, n);
        return n;
      };
      const rootN = mk("@", "root", dom, null);
      if (MM.group === "zone") {
        const ensure = (rel: string): any => {
          const id = rel + "." + dom;
          if (by.has(id)) return by.get(id);
          const i = rel.indexOf(".");
          return mk(id, "zone", rel, i < 0 ? rootN : ensure(rel.slice(i + 1)));
        };
        recs.forEach((r: any) => {
          if (r.rel === "@") { rootN.r = r; return; }
          const n = ensure(r.rel); n.kind = "host"; n.r = r;
        });
      } else {
        const keyOf = MM.group === "net" ? (r: any) => r.net : (r: any) => r.st;
        (MM.group === "net" ? MM_NET_ORDER : MM_ST_ORDER).forEach((k) => {
          const rs = recs.filter((r: any) => keyOf(r) === k);
          if (!rs.length) return;
          const g = mk("g:" + k, "group", k, rootN);
          rs.forEach((r: any) => { mk(r.host, "host", r.rel, g).r = r; });
        });
      }
      const fold = (n: any) => {
        n.children.forEach(fold);
        const bucket = new Map<string, any[]>();
        n.children.forEach((c: any) => {
          if (c.kind !== "host" || c.children.length) return;
          const s = mmSig(c.rel); if (s === c.rel) return;
          if (!bucket.has(s)) bucket.set(s, []);
          bucket.get(s)!.push(c);
        });
        bucket.forEach((list, s) => {
          if (list.length < 5) return;
          const set = new Set(list);
          n.children = n.children.filter((c: any) => !set.has(c));
          const p = mk(n.id + "|" + s, "pat", s, n);
          list.forEach((c: any) => { c.parent = p; });
          p.children = list.sort((a: any, b: any) => mmNat(a.rel, b.rel));
        });
        if (n.kind !== "root" || MM.group === "zone")
          n.children.sort((a: any, b: any) => (b.children.length > 0 ? 1 : 0) - (a.children.length > 0 ? 1 : 0) || mmNat(a.rel, b.rel));
      };
      fold(rootN);
      const af = new Map<string, any>();
      (recordsByDom[dom] || []).forEach((r: any) => { if (r.findings) af.set(r.host, r.findings); });
      const stat = (n: any) => {
        n.depth = n.parent ? n.parent.depth + 1 : 0;
        n.sc = {}; n.count = 0; n.nOut = 0; n.fi = n.r ? af.get(n.r.host) : null;
        if (n.r) { n.sc[n.r.st] = 1; n.count = 1; n.nOut = n.r.out ? 1 : 0; }
        n.children.forEach((c: any) => { stat(c); n.count += c.count; n.nOut += c.nOut; for (const k in c.sc) n.sc[k] = (n.sc[k] || 0) + c.sc[k]; });
        n.st = n.r ? n.r.st : n.kind === "group" && MM.group === "status" ? n.rel : MM_ST_ORDER.reduce((b, k) => ((n.sc[k] || 0) > (n.sc[b] || 0) ? k : b), "live");
        n.allOut = n.count > 0 && n.nOut === n.count;
        n.def = n.kind === "root" || n.kind === "group" || (n.kind !== "pat" && n.children.length <= 12);
      };
      stat(rootN);
      const rowsOf = (n: any): number => {
        if (!n.children.length || !n.def) return 1;
        const gk = mmGridKids(n);
        return (gk ? Math.ceil(gk.length / mmCols(gk.length)) + 1 : 0) +
          n.children.filter((c: any) => !gk || c.children.length).reduce((s: number, c: any) => s + rowsOf(c), 0);
      };
      const rl = rootN.children.filter((c: any) => !c.children.length), block = rl.length > MM_GRID ? rl : null;
      const items = block
        ? [...rootN.children.filter((c: any) => c.children.length).map((c: any) => [c]), block]
        : rootN.children.map((c: any) => [c]);
      const w = items.map((it: any) => (it === block ? Math.ceil(block.length / mmCols(block.length)) + 1 : rowsOf(it[0])));
      const tot = w.reduce((a: number, b: number) => a + b, 0);
      let acc = 0;
      items.forEach((it: any, i: number) => {
        const side = i === 0 || acc + w[i] / 2 <= tot / 2 ? 1 : -1;
        it.forEach((c: any) => { c.side = side; });
        acc += w[i];
      });
      rootN.block = block;
      MM.tree = rootN; MM.byId = by; MM.dirty = false;
    }
    function mmMatch() {
      const q = MM.q.trim().toLowerCase();
      MM.forced = new Set(); MM.hits = []; MM.hitSet = new Set(); MM.hit = -1;
      if (!q || !MM.tree) return;
      MM.byId.forEach((n: any) => {
        if (!n.r) return;
        const r = n.r;
        if (`${r.host} ${r.ip} ${r.src} ${r.note || ""}`.toLowerCase().includes(q)) {
          MM.hits.push(n); MM.hitSet.add(n.id);
          for (let a = n.parent; a; a = a.parent) MM.forced.add(a.id);
        }
      });
    }

    /* ---------- layout ---------- */
    function mmMeasure(n: any) {
      if (n.kind === "root") { n.la = n.rel; n.lb = "  " + mmFmtN(n.count); n.bd = []; n.cw = 30 + (n.la.length + n.lb.length) * 7.8; return; }
      if (n.kind === "group") { const m: any = MM.group === "net" ? MM_NET[n.rel] : MM_ST[n.rel]; n.la = m.label; n.lb = " " + m.sub; }
      else { const i = n.rel.indexOf("."); n.la = i < 0 ? n.rel : n.rel.slice(0, i); n.lb = i < 0 ? "" : n.rel.slice(i); }
      n.bd = [];
      if (n.r && n.r.seen != null && n.r.seen < 168) n.bd.push({ t: "new", c: "#22c55e", w: 30 });
      if (n.fi) n.bd.push({ t: String(n.fi.n), c: (SEVERITY as any)[n.fi.sev].color, w: 12 + String(n.fi.n).length * 6 });
      const br = n.children.length > 0, tw = (n.la.length + n.lb.length) * MM_CH, bw = n.bd.reduce((s: number, b: any) => s + b.w + 6, 0);
      n.tx0 = br ? 22 : 13;
      n.w = n.tx0 + tw + bw + (br ? 10 : 4);
      n.kn = br ? (mmIsOpen(n) ? "−" : mmFmtN(n.count - (n.r ? 1 : 0))) : "";
      n.kw = br ? Math.max(18, 8 + n.kn.length * 6.2) : 0;
      n.ow = br ? n.w + 6 + n.kw : n.w;
    }
    function mmLayout() {
      const rootN = MM.tree, vis = [rootN];
      let cur = 0;
      rootN.ax = 0; rootN.y = 0; rootN.dir = 0; rootN.cell = false; rootN.grid = null; mmMeasure(rootN);
      const grid = (n: any, gk: any[], ox: number, dir: number) => {
        const cols = mmCols(gk.length), rws = Math.ceil(gk.length / cols), top = cur + 8;
        gk.forEach(mmMeasure);
        const mw = Math.max(...gk.map((c: any) => c.ow)), cw = mw + 22;
        gk.forEach((c: any, i: number) => { c.dir = dir; c.cell = true; c.grid = null; c.ax = ox + dir * (12 + Math.floor(i / rws) * cw); c.y = top + (i % rws) * MM_RH + MM_RH / 2; vis.push(c); });
        n.grid = { cols, rows: rws, mw, kids: gk, dir };
        cur = top + rws * MM_RH + 14;
        return { y1: top + MM_RH / 2, y2: top + (rws - 1) * MM_RH + MM_RH / 2 };
      };
      const place = (n: any, ax: number, dir: number) => {
        n.ax = ax; n.dir = dir; n.cell = false; n.grid = null; mmMeasure(n); vis.push(n);
        if (!n.children.length || !mmIsOpen(n)) { n.y = cur + MM_RH / 2; cur += MM_RH; return; }
        const ox = ax + dir * (n.ow + MM_GAP), gk = mmGridKids(n), list = gk ? n.children.filter((c: any) => c.children.length) : n.children;
        list.forEach((c: any) => place(c, ox, dir));
        let y1 = list.length ? list[0].y : null, y2 = list.length ? list[list.length - 1].y : null;
        if (gk) { const g = grid(n, gk, ox, dir); if (y1 == null) y1 = g.y1; y2 = g.y2; } else cur += 6;
        n.y = (y1 + y2) / 2;
      };
      [1, -1].forEach((d) => {
        const start = vis.length, ox = d * (rootN.cw / 2 + MM_GAP + 6); cur = 0;
        rootN.children.filter((c: any) => c.side === d && !(rootN.block && rootN.block.includes(c))).forEach((c: any) => { place(c, ox, d); cur += 8; });
        if (rootN.block && rootN.block[0].side === d) { grid(rootN, rootN.block, ox, d); cur += 8; }
        const mid = (cur - 8) / 2;
        for (let i = start; i < vis.length; i++) vis[i].y -= mid;
      });
      vis.forEach((n: any, i: number) => { n.vi = i; });
      MM.vis = vis;
    }
    function mmBounds(list: any[]) {
      let x1 = Infinity, x2 = -Infinity, y1 = Infinity, y2 = -Infinity;
      list.forEach((n: any) => {
        const a = n.kind === "root" ? -n.cw / 2 : n.dir > 0 ? n.ax - 6 : n.ax - n.ow, b = n.kind === "root" ? n.cw / 2 : n.dir > 0 ? n.ax + n.ow : n.ax + 6;
        x1 = Math.min(x1, a); x2 = Math.max(x2, b); y1 = Math.min(y1, n.y - 14); y2 = Math.max(y2, n.y + 14);
      });
      return { x1, x2, y1, y2 };
    }

    /* ---------- view (pan / zoom) ---------- */
    const mmSize = (): [number, number] => { const v = $('[data-mm="view"]'); return v ? [v.clientWidth, v.clientHeight] : [0, 0]; };
    const mmVisW = () => mmSize()[0];
    function mmApply() {
      $('[data-mm="world"]').setAttribute("transform", `translate(${MM.tx.toFixed(1)},${MM.ty.toFixed(1)}) scale(${MM.k.toFixed(4)})`);
      const zl = $('[data-mm="zoom"]'); if (zl) zl.textContent = Math.round(MM.k * 100) + "%";
      const svg = $('[data-mm="svg"]'); svg.classList.toggle("far", MM.k < 0.5); svg.classList.toggle("vfar", MM.k < 0.24);
      let bs = 24 * MM.k; while (bs < 12) bs *= 2;
      const v = $('[data-mm="view"]'); v.style.backgroundSize = `${bs.toFixed(2)}px ${bs.toFixed(2)}px`; v.style.backgroundPosition = `${MM.tx.toFixed(1)}px ${MM.ty.toFixed(1)}px`;
    }
    function mmViewTo(k: number, tx: number, ty: number, anim?: boolean) {
      cancelAnimationFrame(MM.vraf);
      if (!anim || reduceMotion) { MM.k = k; MM.tx = tx; MM.ty = ty; mmApply(); return; }
      const f = { k: MM.k, tx: MM.tx, ty: MM.ty }, t0 = performance.now();
      const step = (now: number) => {
        const p = Math.min(1, (now - t0) / 380), q = 1 - Math.pow(1 - p, 3);
        MM.k = f.k + (k - f.k) * q; MM.tx = f.tx + (tx - f.tx) * q; MM.ty = f.ty + (ty - f.ty) * q; mmApply();
        if (p < 1) MM.vraf = requestAnimationFrame(step);
      };
      MM.vraf = requestAnimationFrame(step);
    }
    function mmFit(list: any[] | null, anim?: boolean) {
      const [W, H] = mmSize(); if (!W || !H || !MM.vis.length) return false;
      const b = mmBounds(list && list.length ? list : MM.vis);
      const k = clamp(Math.min(W / (b.x2 - b.x1 + 80), H / (b.y2 - b.y1 + 60)), MM_KMIN, list ? 1.25 : 1);
      mmViewTo(k, W / 2 - k * (b.x1 + b.x2) / 2, H / 2 - k * (b.y1 + b.y2) / 2, anim);
      return true;
    }
    function mmZoomAt(k: number, cx: number, cy: number, anim?: boolean) {
      k = clamp(k, MM_KMIN, MM_KMAX);
      const wx = (cx - MM.tx) / MM.k, wy = (cy - MM.ty) / MM.k;
      mmViewTo(k, cx - wx * k, cy - wy * k, anim);
    }
    const mmCx = (n: any) => (n.kind === "root" ? 0 : n.ax + n.dir * n.ow / 2);
    function mmCenter(n: any, k = MM.k, anim = true) { const [, H] = mmSize(); mmViewTo(k, mmVisW() / 2 - k * mmCx(n), H / 2 - k * n.y, anim); }
    function mmEnsure(n: any) {
      const [, H] = mmSize(), sx = MM.tx + MM.k * mmCx(n), sy = MM.ty + MM.k * n.y;
      if (sx < 60 || sx > mmVisW() - 60 || sy < 40 || sy > H - 40) mmCenter(n, Math.max(MM.k, 0.6));
    }
    function mmShowSubtree(n: any) {
      const list = MM.vis.filter((v: any) => { for (let a = v; a; a = a.parent) if (a === n) return true; return false; });
      const b = mmBounds(list), [W, H] = mmSize(), k = MM.k, pad = 24;
      const sx1 = MM.tx + k * b.x1, sx2 = MM.tx + k * b.x2, sy1 = MM.ty + k * b.y1, sy2 = MM.ty + k * b.y2;
      if (sx1 >= pad && sx2 <= W - pad && sy1 >= pad && sy2 <= H - pad) return;
      if (sx2 - sx1 > W - 2 * pad || sy2 - sy1 > H - 2 * pad) { mmFit(list, true); return; }
      const dx = sx1 < pad ? pad - sx1 : sx2 > W - pad ? W - pad - sx2 : 0, dy = sy1 < pad ? pad - sy1 : sy2 > H - pad ? H - pad - sy2 : 0;
      mmViewTo(k, MM.tx + dx, MM.ty + dy, true);
    }

    /* ---------- drawing ---------- */
    function mmFill(e: any) {
      const n = e.n, d = n.dir || 1, br = n.children.length > 0, open = br && mmIsOpen(n);
      const alarm = br && !open && (n.sc.takeover || 0) - (n.r && n.r.st === "takeover" ? 1 : 0) > 0;
      const sig = [n.kind, d, n.kn, n.la, n.lb, n.bd.map((b: any) => b.t).join(), n.st, n.allOut, alarm].join("|");
      if (e.sig === sig) return;
      e.sig = sig;
      const g = e.g; g.replaceChildren();
      if (n.kind === "root") {
        svgEl("rect", { class: "box", x: -n.cw / 2, y: -18, width: n.cw, height: 36, rx: 18 }, g);
        const t = svgEl("text", { x: 0, y: 0, "text-anchor": "middle", "dominant-baseline": "central" }, g);
        svgEl("tspan", {}, t).textContent = n.la; svgEl("tspan", { class: "cnt" }, t).textContent = n.lb;
        return;
      }
      const rx = d > 0 ? -4 : -n.w;
      svgEl("rect", { class: br ? "box" : "hit", x: rx, y: -11, width: n.w + 4, height: 22, rx: 11 }, g);
      const dot = svgEl("circle", { class: "dot" + (n.allOut ? " hollow" : ""), cx: d * (br ? 11 : 4), cy: 0, r: br ? 4 : 3.5 }, g);
      dot.style.setProperty("--c", (MM_ST[n.st] || MM_ST.live).c);
      if (alarm) svgEl("circle", { class: "alarm", cx: d * 11, cy: 0, r: 7.5 }, g);
      const t = svgEl("text", { x: d * n.tx0, y: 0, "text-anchor": d > 0 ? "start" : "end", "dominant-baseline": "central" }, g);
      svgEl("tspan", { class: "a" }, t).textContent = n.la;
      if (n.lb) svgEl("tspan", { class: "b" }, t).textContent = n.lb;
      let bx = d * (n.tx0 + (n.la.length + n.lb.length) * MM_CH + 6);
      n.bd.forEach((b: any) => {
        const bg = svgEl("g", { class: "bdg" }, g); bg.style.setProperty("--c", b.c);
        svgEl("rect", { x: d > 0 ? bx : bx - b.w, y: -8, width: b.w, height: 16, rx: 8 }, bg);
        svgEl("text", { x: bx + d * b.w / 2, y: 0.5, "dominant-baseline": "central" }, bg).textContent = b.t;
        bx += d * (b.w + 6);
      });
      if (br) {
        const kx = d * (n.w + 6), kg = svgEl("g", { class: "knob" }, g);
        svgEl("rect", { x: d > 0 ? kx : kx - n.kw, y: -9, width: n.kw, height: 18, rx: 9 }, kg);
        svgEl("text", { x: kx + d * n.kw / 2, y: 0.5, "dominant-baseline": "central" }, kg).textContent = n.kn;
      }
    }
    function mmClass(e: any) {
      const n = e.n, q = MM.hitSet.size > 0, cls = ["mm-n", n.kind, n.children.length ? "br" : "lf"];
      if (n.allOut) cls.push("out");
      if (q) { if (MM.hitSet.has(n.id)) cls.push("hit"); else if (n.kind !== "root" && !MM.forced.has(n.id)) cls.push("dim"); }
      if (MM.sel === n.id) cls.push("sel");
      if (MM.fresh.has(n.id)) cls.push("fresh");
      e.g.setAttribute("class", cls.join(" "));
      e.g.setAttribute("tabindex", n.id === MM.focus ? "0" : "-1");
      e.g.setAttribute("aria-level", String(n.depth + 1));
      if (n.children.length) e.g.setAttribute("aria-expanded", String(mmIsOpen(n))); else e.g.removeAttribute("aria-expanded");
      const name = n.kind === "root" ? n.rel : n.kind === "group" ? n.la : n.r ? n.r.host : `${n.rel}.${MM.dom}`;
      e.g.setAttribute("aria-label", `${name}${n.r ? `, ${(MM_ST[n.r.st] || MM_ST.live).label}${n.r.http ? " " + n.r.http : ""}` : ""}${n.children.length ? `, ${n.count - (n.r ? 1 : 0)} hosts below` : ""}${MM.hitSet.has(n.id) ? ", search match" : ""}`);
    }
    const mmLinkD = (x1: number, y1: number, x2: number, y2: number) => { const m = ((x1 + x2) / 2).toFixed(1); return `M${x1.toFixed(1)},${y1.toFixed(1)} C${m},${y1.toFixed(1)} ${m},${y2.toFixed(1)} ${x2.toFixed(1)},${y2.toFixed(1)}`; };
    const mmOut = (e: any, d: number) => (e.n.kind === "root" ? d * e.n.cw / 2 : d * e.n.ow);
    function mmDrawLinks() {
      MM.links.forEach((p: any, id: string) => {
        const e = MM.els.get(id), pe = e && e.n.parent && MM.els.get(e.n.parent.id);
        if (!e) { p.remove(); MM.links.delete(id); return; }
        if (!pe) { p.setAttribute("d", ""); return; }
        const d = e.n.dir || 1;
        p.setAttribute("d", mmLinkD(pe.x + mmOut(pe, d), pe.y, e.x, e.y));
        p.style.opacity = e.o < 1 ? e.o.toFixed(3) : "";
      });
      MM.trays.forEach((t: any, id: string) => {
        const pe = MM.els.get(id); if (!pe || !pe.n.grid) return;
        const n = pe.n, d = n.grid.dir;
        let x1 = Infinity, x2 = -Infinity, y1 = Infinity, y2 = -Infinity, o = 1;
        n.grid.kids.forEach((c: any) => { const ce = MM.els.get(c.id); if (!ce) return; x1 = Math.min(x1, ce.x); x2 = Math.max(x2, ce.x); y1 = Math.min(y1, ce.y); y2 = Math.max(y2, ce.y); o = Math.min(o, ce.o); });
        if (x1 === Infinity) return;
        const L = d > 0 ? x1 - 12 : x1 - n.grid.mw - 10, R = d > 0 ? x2 + n.grid.mw + 10 : x2 + 12, T = y1 - MM_RH / 2 - 4, B = y2 + MM_RH / 2 + 4;
        t.rect.setAttribute("x", L.toFixed(1)); t.rect.setAttribute("y", T.toFixed(1)); t.rect.setAttribute("width", Math.max(0, R - L).toFixed(1)); t.rect.setAttribute("height", Math.max(0, B - T).toFixed(1));
        t.rect.style.opacity = o < 1 ? o.toFixed(3) : "";
        t.path.setAttribute("d", mmLinkD(pe.x + mmOut(pe, d), pe.y, d > 0 ? L : R, (T + B) / 2));
      });
    }
    function mmReset() {
      cancelAnimationFrame(MM.raf); tipHide();
      $('[data-mm="nodes"]').replaceChildren(); $('[data-mm="links"]').replaceChildren(); $('[data-mm="trays"]').replaceChildren();
      MM.els.clear(); MM.links.clear(); MM.trays.clear(); MM.hot = []; MM.focus = "@";
    }
    function mmRender(anchor?: string) {
      if (!MM.tree) return;
      const ae = anchor && MM.els.get(anchor), before = ae ? { x: ae.x, y: ae.y } : null, first = MM.els.size === 0;
      mmLayout();
      const visSet = new Set(MM.vis.map((n: any) => n.id));
      if (before && anchor && visSet.has(anchor)) {
        const n = MM.byId.get(anchor), dx = n.ax - before.x, dy = n.y - before.y;
        if (dx || dy) { MM.els.forEach((e: any) => { e.x += dx; e.y += dy; }); cancelAnimationFrame(MM.vraf); MM.tx -= MM.k * dx; MM.ty -= MM.k * dy; mmApply(); }
      }
      if (!visSet.has(MM.focus)) {
        const old = MM.byId.get(MM.focus); let a = old && old.parent; while (a && !visSet.has(a.id)) a = a.parent;
        const had = document.activeElement && (document.activeElement as any).closest && (document.activeElement as any).closest('[data-mm="nodes"]');
        MM.focus = a ? a.id : "@";
        if (had) requestAnimationFrame(() => { const fe = MM.els.get(MM.focus); if (fe) fe.g.focus({ preventScroll: true }); });
      }
      const layN = $('[data-mm="nodes"]'), layL = $('[data-mm="links"]'), layT = $('[data-mm="trays"]');
      MM.vis.forEach((n: any) => {
        let e = MM.els.get(n.id);
        if (!e) {
          let a = n.parent; while (a && !MM.els.has(a.id)) a = a.parent;
          const from = a && MM.els.get(a.id);
          e = { g: svgEl("g", { "data-id": n.id, role: "treeitem" }), sig: "", x: from ? from.x : n.ax, y: from ? from.y : n.y, o: first || !from ? 1 : 0 };
          MM.els.set(n.id, e); layN.append(e.g);
        }
        e.n = n; e.exit = false; e.fx = e.x; e.fy = e.y; e.fo = e.o; e.tx = n.ax; e.ty = n.y; e.to = 1;
        mmFill(e); mmClass(e);
        if (n.kind !== "root" && !n.cell) { if (!MM.links.has(n.id)) MM.links.set(n.id, svgEl("path", { class: "mm-l" }, layL)); }
        else if (MM.links.has(n.id)) { MM.links.get(n.id).remove(); MM.links.delete(n.id); }
      });
      MM.els.forEach((e: any, id: string) => {
        if (visSet.has(id)) return;
        let a = e.n.parent; while (a && !visSet.has(a.id)) a = a.parent;
        const an = a && MM.byId.get(a.id);
        e.exit = true; e.fx = e.x; e.fy = e.y; e.fo = e.o; e.to = 0;
        e.tx = an ? an.ax + (an.kind === "root" ? 0 : an.dir * an.ow) : e.x; e.ty = an ? an.y : e.y;
      });
      MM.trays.forEach((t: any, id: string) => { const n = MM.byId.get(id); if (!n || !n.grid || !visSet.has(id)) { t.rect.remove(); t.path.remove(); MM.trays.delete(id); } });
      MM.vis.forEach((n: any) => { if (n.grid && !MM.trays.has(n.id)) MM.trays.set(n.id, { rect: svgEl("rect", { class: "mm-tray", rx: 12 }, layT), path: svgEl("path", { class: "mm-l" }, layL) }); });
      const lit = new Set<string>();
      MM.hits.forEach((n: any) => { for (let c = n; c && c.parent; c = c.parent) lit.add(c.cell ? "T:" + c.parent.id : c.id); });
      MM.links.forEach((p: any, id: string) => { const e = MM.els.get(id); p.setAttribute("class", "mm-l" + (e && e.n.allOut ? " out" : "") + (lit.has(id) ? " lit" : "")); });
      MM.trays.forEach((t: any, id: string) => { t.path.setAttribute("class", "mm-l" + (lit.has("T:" + id) ? " lit" : "")); });
      $('[data-mm="svg"]').classList.toggle("q", MM.hitSet.size > 0);
      MM.hot = [];
      const empty = $('[data-mm="empty"]'); if (empty) empty.hidden = MM.tree.children.length > 0;
      cancelAnimationFrame(MM.raf);
      const dur = first || reduceMotion || MM.els.size > 1500 ? 0 : 340, t0 = performance.now();
      const tick = (now: number) => {
        const p = dur ? Math.min(1, (now - t0) / dur) : 1, q = 1 - Math.pow(1 - p, 3);
        MM.els.forEach((e: any) => {
          e.x = e.fx + (e.tx - e.fx) * q; e.y = e.fy + (e.ty - e.fy) * q; e.o = e.fo + (e.to - e.fo) * q;
          e.g.setAttribute("transform", `translate(${e.x.toFixed(1)},${e.y.toFixed(1)})`);
          e.g.style.opacity = e.o < 1 ? e.o.toFixed(3) : "";
        });
        mmDrawLinks();
        if (p < 1) { MM.raf = requestAnimationFrame(tick); return; }
        MM.els.forEach((e: any, id: string) => { if (!e.exit) return; e.g.remove(); MM.els.delete(id); const l = MM.links.get(id); if (l) { l.remove(); MM.links.delete(id); } });
      };
      tick(t0);
      mmFoot();
    }
    function mmHot(id: string | null) {
      MM.hot.forEach((p: any) => p.classList.remove("hot")); MM.hot = [];
      for (let n = id && MM.byId.get(id); n && n.parent; n = n.parent) {
        const p = n.cell ? MM.trays.get(n.parent.id) && MM.trays.get(n.parent.id).path : MM.links.get(n.id);
        if (p) { p.classList.add("hot"); MM.hot.push(p); }
      }
    }

    /* ---------- panels around the map ---------- */
    function mmControls() {
      const sel = $('[data-mm="domain"]');
      if (sel) {
        if (sel.options.length !== domains.length) sel.replaceChildren(...domains.map((d) => { const o = h("option"); o.value = d; return o; }));
        [...sel.options].forEach((o: any) => { o.textContent = `${o.value} · ${(recordsByDom[o.value] || []).length} hosts`; });
        sel.value = MM.dom;
      }
      $$('[data-mm="group"] button').forEach((b: any) => b.setAttribute("aria-pressed", String(b.dataset.g === MM.group)));
      const sub = $('[data-mm="sub"]'); if (sub) sub.textContent = `${MM.dom} · by ${({ zone: "DNS zone", net: "network", status: "status" } as any)[MM.group]}`;
      const q = $('[data-mm="query"]'); if (q && q.value !== MM.q) q.value = MM.q;
      const hint = $('[data-mm="hint"]'); if (hint) hint.textContent = `Hold ${MM_MOD} and scroll to zoom`;
    }
    function mmLegend() {
      const host = $('[data-mm="legend"]'); if (!host) return;
      const cnt: any = {};
      (recordsByDom[MM.dom] || []).forEach((r: any) => { cnt[r.st] = (cnt[r.st] || 0) + 1; });
      const keys = MM_ST_ORDER.filter((k) => cnt[k]);
      if (host.dataset.k !== keys.join()) {
        host.dataset.k = keys.join(); host.replaceChildren();
        keys.forEach((k) => {
          const b = h("button", "mm-key" + (k === "skip" ? " hollow" : "")); b.type = "button"; b.dataset.st = k;
          b.style.setProperty("--c", MM_ST[k].c);
          b.append(h("i"), document.createTextNode(MM_ST[k].label), h("b"));
          b.addEventListener("click", () => { if (MM.hide.has(k)) MM.hide.delete(k); else MM.hide.add(k); MM.dirty = true; renderMindmap(); });
          host.append(b);
        });
        host.append(h("span", "mm-lg-note", "click a status to show or hide it"));
      }
      $$(".mm-key").forEach((b: any) => {
        const k = b.dataset.st, on = !MM.hide.has(k);
        b.setAttribute("aria-pressed", String(on)); b.querySelector("b").textContent = String(cnt[k] || 0);
        b.title = `${on ? "Hide" : "Show"} ${MM_ST[k].label.toLowerCase()} hosts (${MM_ST[k].sub})`;
      });
    }
    function mmHitsLabel() {
      const el = $('[data-mm="hits"]'); if (!el) return;
      const n = MM.hits.length;
      el.textContent = !MM.q.trim() ? "" : !n ? "no match" : MM.hit >= 0 ? `${MM.hit + 1} / ${n}` : `${n} found`;
    }
    function mmFoot() {
      const el = $('[data-mm="foot"]'); if (!el) return;
      const R = recordsByDom[MM.dom] || [], shown = R.filter((r: any) => !MM.hide.has(r.st)).length, touch = matchMedia("(pointer: coarse)").matches;
      el.replaceChildren(
        h("span", "", `${shown} of ${R.length} hosts · ${MM.vis.length} nodes drawn`),
        h("span", "", touch ? "Drag to pan · pinch to zoom · tap a branch to open it" : `Drag to pan · ${MM_MOD} + scroll to zoom · arrow keys move between nodes`),
      );
    }
    function renderMindmap() {
      mmControls();
      const key = MM.dom + "|" + MM.group;
      if (MM.dirty || !MM.tree || MM.key !== key) {
        const reset = MM.key !== key;
        MM.key = key; tipHide(); mmBuild();
        if (reset) { mmReset(); MM.fitted = false; }
        mmMatch(); mmHitsLabel();
      }
      mmLegend();
      mmRender();
      if (!MM.fitted) MM.fitted = mmFit(null, false);
    }

    /* ---------- actions ---------- */
    function mmSetFocus(id: string, ensure?: boolean, quiet?: boolean) {
      const prev = MM.els.get(MM.focus); if (prev) prev.g.setAttribute("tabindex", "-1");
      MM.focus = id;
      const e = MM.els.get(id); if (!e) return;
      e.g.setAttribute("tabindex", "0");
      if (!quiet) e.g.focus({ preventScroll: true });
      if (ensure) mmEnsure(e.n);
    }
    function mmToggle(n: any, open = !mmIsOpen(n)) {
      if (!n.children.length || n.kind === "root") return;
      MM.open.set(mmOpenKey(n.id), open);
      if (!open) MM.forced.delete(n.id);
      mmRender(n.id);
      if (open) mmShowSubtree(MM.byId.get(n.id));
    }
    function mmSetAll(open: boolean) {
      MM.byId.forEach((n: any) => { if (n.children.length && n.kind !== "root") MM.open.set(mmOpenKey(n.id), open); });
      if (!open) MM.forced.clear();
      mmRender(); mmFit(null, true);
    }
    function mmOpenHost(id: string) {
      const n = MM.byId.get(id), r = n && n.r ? n.r : null; if (!r) return;
      MM.sel = r.host; MM.els.forEach((e: any) => { if (!e.exit) mmClass(e); });
      selRef.current(r.host);
    }

    /* ---------- input ---------- */
    const cleanups: Array<() => void> = [];
    const on = (el: any, ev: string, fn: any, opts?: any) => { if (!el) return; el.addEventListener(ev, fn, opts); cleanups.push(() => el.removeEventListener(ev, fn, opts)); };

    const view = $('[data-mm="view"]'), svg = $('[data-mm="svg"]'), nodes = $('[data-mm="nodes"]');
    const ptr = new Map<number, { x: number; y: number }>();
    let drag: any = null, moved = false, hintT: any = 0, qT: any = 0;

    on(view, "pointerdown", (e: any) => {
      if (e.pointerType === "mouse" && e.button !== 0) return;
      cancelAnimationFrame(MM.vraf);
      ptr.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (ptr.size === 1) { drag = { x: e.clientX, y: e.clientY, tx: MM.tx, ty: MM.ty, live: false }; moved = false; }
      else if (ptr.size === 2) {
        const [a, b] = [...ptr.values()], r = view.getBoundingClientRect();
        drag = { pinch: true, d: Math.hypot(a.x - b.x, a.y - b.y) || 1, k: MM.k, wx: ((a.x + b.x) / 2 - r.left - MM.tx) / MM.k, wy: ((a.y + b.y) / 2 - r.top - MM.ty) / MM.k };
        moved = true; ptr.forEach((_v, id) => { try { view.setPointerCapture(id); } catch (_e) { /* noop */ } });
      }
    });
    on(view, "pointermove", (e: any) => {
      if (!ptr.has(e.pointerId) || !drag) return;
      ptr.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (drag.pinch) {
        if (ptr.size < 2) return;
        const [a, b] = [...ptr.values()], r = view.getBoundingClientRect();
        const k = clamp(drag.k * Math.hypot(a.x - b.x, a.y - b.y) / drag.d, MM_KMIN, MM_KMAX);
        MM.k = k; MM.tx = (a.x + b.x) / 2 - r.left - drag.wx * k; MM.ty = (a.y + b.y) / 2 - r.top - drag.wy * k; mmApply();
        return;
      }
      const dx = e.clientX - drag.x, dy = e.clientY - drag.y;
      if (!drag.live && Math.hypot(dx, dy) > 4) { drag.live = true; moved = true; try { view.setPointerCapture(e.pointerId); } catch (_e) { /* noop */ } view.classList.add("drag"); tipHide(); mmHot(null); }
      if (drag.live) { MM.tx = drag.tx + dx; MM.ty = drag.ty + dy; mmApply(); }
    });
    const up = (e: any) => {
      ptr.delete(e.pointerId);
      if (!ptr.size) { drag = null; view.classList.remove("drag"); return; }
      if (drag && drag.pinch) { const p = [...ptr.values()][0]; drag = { x: p.x, y: p.y, tx: MM.tx, ty: MM.ty, live: true }; }
    };
    on(view, "pointerup", up); on(view, "pointercancel", up);
    on(view, "click", (e: any) => {
      if (moved) { moved = false; return; }
      const g = e.target.closest && e.target.closest(".mm-n"), n = g && MM.byId.get(g.dataset.id);
      if (!n) return;
      mmSetFocus(n.id, false);
      if (n.kind === "root") { mmFit(null, true); return; }
      if (n.children.length && (!n.r || e.target.closest(".knob"))) mmToggle(n);
      else if (n.r) mmOpenHost(n.id);
    });
    on(view, "wheel", (e: any) => {
      if (!(e.ctrlKey || e.metaKey)) {
        const hint = $('[data-mm="hint"]'); if (hint) { hint.classList.add("show"); clearTimeout(hintT); hintT = setTimeout(() => hint.classList.remove("show"), 1100); }
        return;
      }
      e.preventDefault();
      const r = view.getBoundingClientRect();
      mmZoomAt(MM.k * Math.exp(-e.deltaY * (e.deltaMode === 1 ? 0.05 : 0.0022)), e.clientX - r.left, e.clientY - r.top, false);
    }, { passive: false });
    on(nodes, "pointerover", (e: any) => {
      if (drag && drag.live) return;
      const g = e.target.closest(".mm-n"), n = g && MM.byId.get(g.dataset.id); if (!n) return;
      mmHot(n.id);
      if (e.pointerType !== "mouse") return;
      if (n.r) {
        const r = n.r;
        tipShow(r.host, [
          { name: "Status", value: r.http ? `${(MM_ST[r.st] || MM_ST.live).label} · ${r.http}` : (MM_ST[r.st] || MM_ST.live).label, color: (MM_ST[r.st] || MM_ST.live).c },
          { name: "Resolves to", value: r.ip ? (r.ip.length > 34 ? r.ip.slice(0, 33) + "…" : r.ip) : "—", color: "transparent" },
          { name: "Found via", value: r.src, color: "transparent" },
        ], e.clientX, e.clientY);
      } else {
        const name = n.kind === "root" ? n.rel : n.kind === "group" ? n.la : `${n.rel}.${MM.dom}`;
        tipShow(`${name} · ${n.count} host${n.count === 1 ? "" : "s"}`, MM_ST_ORDER.filter((k) => n.sc[k]).map((k) => ({ name: MM_ST[k].label, value: String(n.sc[k]), color: MM_ST[k].c })), e.clientX, e.clientY);
      }
    });
    on(nodes, "pointerout", (e: any) => {
      const g = e.target.closest(".mm-n");
      if (g && e.relatedTarget && g.contains(e.relatedTarget)) return;
      mmHot(null); tipHide();
    });
    on(view, "pointerleave", () => { mmHot(null); tipHide(); });
    on(svg, "keydown", (e: any) => {
      const g = e.target.closest && e.target.closest(".mm-n"), n = g && MM.byId.get(g.dataset.id); if (!n) return;
      const [W, H] = mmSize();
      let to = null;
      switch (e.key) {
        case "ArrowDown": case "ArrowUp": to = MM.vis[clamp(n.vi + (e.key === "ArrowDown" ? 1 : -1), 0, MM.vis.length - 1)]; break;
        case "ArrowRight": case "ArrowLeft": {
          const d = e.key === "ArrowRight" ? 1 : -1;
          if (n.kind === "root") to = MM.vis.find((v: any) => v.parent === n && v.dir === d);
          else if (d === n.dir) { if (n.children.length && !mmIsOpen(n)) mmToggle(n, true); else if (n.children.length) to = MM.byId.get(n.id).children[0]; }
          else if (n.children.length && mmIsOpen(n)) mmToggle(n, false);
          else to = n.parent;
          break;
        }
        case "Enter": if (n.kind === "root") mmFit(null, true); else if (n.r) mmOpenHost(n.id); else mmToggle(n); break;
        case " ": if (n.children.length) mmToggle(n); break;
        case "Home": to = MM.tree; break;
        case "+": case "=": mmZoomAt(MM.k * 1.3, W / 2, H / 2, true); break;
        case "-": case "_": mmZoomAt(MM.k / 1.3, W / 2, H / 2, true); break;
        case "0": mmFit(null, true); break;
        default: return;
      }
      e.preventDefault();
      if (to) mmSetFocus(to.id, true);
    });
    on($('[data-mm="domain"]'), "change", (e: any) => { MM.dom = e.target.value; MM.q = ""; MM.dirty = true; renderMindmap(); });
    $$('[data-mm="group"] button').forEach((b: any) => on(b, "click", () => { if (MM.group === b.dataset.g) return; MM.group = b.dataset.g; MM.dirty = true; renderMindmap(); }));
    on($('[data-mm="query"]'), "input", (e: any) => {
      MM.q = e.target.value; clearTimeout(qT);
      qT = setTimeout(() => { mmMatch(); mmRender(); mmHitsLabel(); if (MM.hits.length) mmFit(MM.hits, true); else if (!MM.q.trim()) mmFit(null, true); }, 140);
    });
    on($('[data-mm="query"]'), "keydown", (e: any) => {
      if (e.key !== "Enter" || !MM.hits.length) return;
      e.preventDefault();
      const list = MM.hits.filter((n: any) => n.vi != null && MM.vis[n.vi] === n).sort((a: any, b: any) => a.vi - b.vi); if (!list.length) return;
      MM.hit = (MM.hit + (e.shiftKey ? -1 : 1) + list.length) % list.length;
      const n = list[MM.hit]; mmCenter(n, Math.max(MM.k, 1)); mmHot(n.id); mmHitsLabel();
    });
    on($('[data-mm="expand"]'), "click", () => mmSetAll(true));
    on($('[data-mm="collapse"]'), "click", () => mmSetAll(false));
    on($('[data-mm="in"]'), "click", () => { const [W, H] = mmSize(); mmZoomAt(MM.k * 1.3, W / 2, H / 2, true); });
    on($('[data-mm="out"]'), "click", () => { const [W, H] = mmSize(); mmZoomAt(MM.k / 1.3, W / 2, H / 2, true); });
    on($('[data-mm="zoombtn"]'), "click", () => { const [W, H] = mmSize(); mmZoomAt(1, W / 2, H / 2, true); });
    on($('[data-mm="fit"]'), "click", () => mmFit(null, true));

    const ro = new ResizeObserver(() => {
      const [W, H] = mmSize(); if (!W || !H) return;
      if (MM.size && (MM.size[0] !== W || MM.size[1] !== H)) { MM.tx += (W - MM.size[0]) / 2; MM.ty += (H - MM.size[1]) / 2; mmApply(); }
      MM.size = [W, H];
      if (!MM.fitted && MM.tree) MM.fitted = mmFit(null, false);
    });
    ro.observe(view);

    renderMindmap();

    return () => {
      cancelAnimationFrame(MM.raf); cancelAnimationFrame(MM.vraf);
      clearTimeout(hintT); clearTimeout(qT);
      ro.disconnect();
      cleanups.forEach((fn) => fn());
      // clear the imperatively-built SVG so a re-run of the effect starts clean
      ["nodes", "links", "trays", "legend", "foot"].forEach((k) => { const el = $(`[data-mm="${k}"]`); if (el) el.replaceChildren(); });
      if (tipEl) { tipEl.remove(); tipEl = null; }
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [records, domains, rootDomain]);

  const btn = "icon-btn grid h-8 w-8 place-items-center rounded-lg";
  return (
    <div ref={rootRef} className="mm-root">
      {/* control bar */}
      <div className="mb-3 flex flex-wrap items-center gap-2">
        {domains.length > 1 && (
          <select
            data-mm="domain"
            aria-label="Root domain"
            className="mm-dom h-9 rounded-full border border-line bg-card2 px-3 text-sm text-fg outline-none focus:border-fg/40"
          />
        )}
        <div data-mm="group" role="group" aria-label="Group subdomains by" className="inline-flex rounded-full border border-line bg-card2 p-0.5">
          {[
            { g: "zone", label: "By zone" },
            { g: "net", label: "By network" },
            { g: "status", label: "By status" },
          ].map((o) => (
            <button
              key={o.g}
              type="button"
              data-g={o.g}
              aria-pressed={o.g === "zone"}
              className="rounded-full px-2.5 py-1 text-xs font-medium text-muted transition hover:text-fg aria-pressed:bg-brand aria-pressed:text-brand-fg"
            >
              {o.label}
            </button>
          ))}
        </div>
        <label className="relative ml-auto flex items-center">
          <svg className="pointer-events-none absolute left-3 h-3.5 w-3.5 text-muted" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="7" /><path d="m21 21-4.3-4.3" /></svg>
          <input
            data-mm="query"
            type="search"
            placeholder="Find a host, IP or source…"
            aria-label="Find a subdomain"
            className="h-9 w-56 rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none placeholder:text-muted focus:border-fg/40"
          />
          <span data-mm="hits" aria-live="polite" className="ml-2 whitespace-nowrap font-mono text-[11.5px] text-faint" />
        </label>
      </div>

      {/* map panel */}
      <div className="mm-panel overflow-hidden rounded-xl border border-line bg-card">
        <div className="flex items-center justify-between gap-2 px-[18px] py-3">
          <div className="flex min-w-0 items-center gap-2 text-[15px] font-medium text-fg-strong">
            <span>Subdomain map</span>
            <span data-mm="sub" className="truncate font-mono text-[11px] font-normal text-faint" />
          </div>
          <div className="flex items-center gap-0.5">
            <button data-mm="expand" type="button" title="Expand everything" aria-label="Expand everything" className={btn}><ChevronsUpDown size={15} /></button>
            <button data-mm="collapse" type="button" title="Collapse to the first level" aria-label="Collapse to the first level" className={btn}><ChevronsDownUp size={15} /></button>
            <span className="mx-1.5 h-[18px] w-px bg-line" aria-hidden="true" />
            <button data-mm="out" type="button" title="Zoom out" aria-label="Zoom out" className={btn}><Minus size={15} /></button>
            <button data-mm="zoombtn" type="button" title="Reset zoom to 100%" className="icon-btn h-8 min-w-[52px] rounded-lg font-mono text-xs text-muted">100%</button>
            <button data-mm="in" type="button" title="Zoom in" aria-label="Zoom in" className={btn}><Plus size={15} /></button>
            <button data-mm="fit" type="button" title="Fit to view" aria-label="Fit to view" className={btn}><Maximize2 size={15} /></button>
          </div>
        </div>
        <div data-mm="legend" role="group" aria-label="Show or hide hosts by status" className="mm-legend" />
        <div data-mm="view" className="mm-view">
          <svg data-mm="svg" role="tree" aria-label="Subdomain mind map">
            <g data-mm="world"><g data-mm="trays" /><g data-mm="links" /><g data-mm="nodes" /></g>
          </svg>
          <div data-mm="hint" className="mm-hint" aria-hidden="true" />
          <div data-mm="empty" className="mm-empty" hidden>Every status is hidden. Turn one back on above.</div>
        </div>
        <div data-mm="foot" className="flex items-center justify-between gap-3 px-[18px] py-2.5 font-mono text-[11px] text-faint" />
      </div>
    </div>
  );
}

"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  KeyRound, PlugZap, Unplug, Loader2, CheckCircle2, LogIn, ExternalLink, X,
  ShieldCheck, Terminal, AlertTriangle,
} from "lucide-react";
import { useControl } from "./ControlProvider";
import type { ProviderAuth, SetAuthBody, LoginStatus } from "@/lib/control";
import { Select } from "@/components/ui/primitives";
import { cx } from "@/lib/format";
import { hexA } from "@/lib/theme";

/* ============================================================================
   Per-provider presentation — vendor, logo mono + tint, and a one-line blurb.
   The backend (`console_control.py` -> /api/auth) is the source of truth for
   which providers exist and whether each is a LIVE engine; this map only adds
   the visual identity. An unknown id falls back to a neutral card so a provider
   added server-side still renders.
   ========================================================================== */
interface ProviderMeta { vendor: string; mono: string; tint: string; blurb: string; }
const PROVIDER_META: Record<string, ProviderMeta> = {
  claude: {
    vendor: "Anthropic", mono: "CC", tint: "#d97757",
    blurb: "Agentic coding tool that lives in the terminal and drives the whole engagement. The live engine today.",
  },
  codex: {
    vendor: "OpenAI", mono: "CX", tint: "#10a37f",
    blurb: "Lightweight coding agent from OpenAI. Store a key now; it becomes a live engine once wired in.",
  },
  gemini: {
    vendor: "Google", mono: "G", tint: "#4285f4",
    blurb: "Google's open-source agent that brings Gemini models into the terminal. Stored for lab use.",
  },
  grok: {
    vendor: "xAI", mono: "Gk", tint: "#14b8a6",
    blurb: "xAI's Grok models, including the agentic grok-code-fast-1 coding model. Stored for lab use.",
  },
};
function metaFor(id: string, label: string): ProviderMeta {
  return PROVIDER_META[id] ?? {
    vendor: label, mono: label.slice(0, 2).toUpperCase(), tint: "#8a8f98",
    blurb: "External coding-agent runtime.",
  };
}

/* ---- real brand marks (single-path, 24×24; rendered in the provider's tint) --------------
   Claude · OpenAI · Google Gemini are the official simple-icons glyphs; Grok is xAI's mark.
   Keyed by the backend provider id (so `codex` shows the OpenAI logo, `grok` the xAI one). */
interface BrandLogo { path: string; fillRule?: "evenodd" | "nonzero"; }
const BRAND_LOGO: Record<string, BrandLogo> = {
  claude: {
    path: "m4.7144 15.9555 4.7174-2.6471.079-.2307-.079-.1275h-.2307l-.7893-.0486-2.6956-.0729-2.3375-.0971-2.2646-.1214-.5707-.1215-.5343-.7042.0546-.3522.4797-.3218.686.0608 1.5179.1032 2.2767.1578 1.6514.0972 2.4468.255h.3886l.0546-.1579-.1336-.0971-.1032-.0972L6.973 9.8356l-2.55-1.6879-1.3356-.9714-.7225-.4918-.3643-.4614-.1578-1.0078.6557-.7225.8803.0607.2246.0607.8925.686 1.9064 1.4754 2.4893 1.8336.3643.3035.1457-.1032.0182-.0728-.164-.2733-1.3539-2.4467-1.445-2.4893-.6435-1.032-.17-.6194c-.0607-.255-.1032-.4674-.1032-.7285L6.287.1335 6.6997 0l.9957.1336.419.3642.6192 1.4147 1.0018 2.2282 1.5543 3.0296.4553.8985.2429.8318.091.255h.1579v-.1457l.1275-1.706.2368-2.0947.2307-2.6957.0789-.7589.3764-.9107.7468-.4918.5828.2793.4797.686-.0668.4433-.2853 1.8517-.5586 2.9021-.3643 1.9429h.2125l.2429-.2429.9835-1.3053 1.6514-2.0643.7286-.8196.85-.9046.5464-.4311h1.0321l.759 1.1293-.34 1.1657-1.0625 1.3478-.8804 1.1414-1.2628 1.7-.7893 1.36.0729.1093.1882-.0183 2.8535-.607 1.5421-.2794 1.8396-.3157.8318.3886.091.3946-.3278.8075-1.967.4857-2.3072.4614-3.4364.8136-.0425.0304.0486.0607 1.5482.1457.6618.0364h1.621l3.0175.2247.7892.522.4736.6376-.079.4857-1.2142.6193-1.6393-.3886-3.825-.9107-1.3113-.3279h-.1822v.1093l1.0929 1.0686 2.0035 1.8092 2.5075 2.3314.1275.5768-.3218.4554-.34-.0486-2.2039-1.6575-.85-.7468-1.9246-1.621h-.1275v.17l.4432.6496 2.3436 3.5214.1214 1.0807-.17.3521-.6071.2125-.6679-.1214-1.3721-1.9246L14.38 17.959l-1.1414-1.9428-.1397.079-.674 7.2552-.3156.3703-.7286.2793-.6071-.4614-.3218-.7468.3218-1.4753.3886-1.9246.3157-1.53.2853-1.9004.17-.6314-.0121-.0425-.1397.0182-1.4328 1.9672-2.1796 2.9446-1.7243 1.8456-.4128.164-.7164-.3704.0667-.6618.4008-.5889 2.386-3.0357 1.4389-1.882.929-1.0868-.0062-.1579h-.0546l-6.3385 4.1164-1.1293.1457-.4857-.4554.0608-.7467.2307-.2429 1.9064-1.3114Z",
  },
  codex: {
    path: "M22.2819 9.8211a5.9847 5.9847 0 0 0-.5157-4.9108 6.0462 6.0462 0 0 0-6.5098-2.9A6.0651 6.0651 0 0 0 4.9807 4.1818a5.9847 5.9847 0 0 0-3.9977 2.9 6.0462 6.0462 0 0 0 .7427 7.0966 5.98 5.98 0 0 0 .511 4.9107 6.051 6.051 0 0 0 6.5146 2.9001A5.9847 5.9847 0 0 0 13.2599 24a6.0557 6.0557 0 0 0 5.7718-4.2058 5.9894 5.9894 0 0 0 3.9977-2.9001 6.0557 6.0557 0 0 0-.7475-7.0729zm-9.022 12.6081a4.4755 4.4755 0 0 1-2.8764-1.0408l.1419-.0804 4.7783-2.7582a.7948.7948 0 0 0 .3927-.6813v-6.7369l2.02 1.1686a.071.071 0 0 1 .038.052v5.5826a4.504 4.504 0 0 1-4.4945 4.4944zm-9.6607-4.1254a4.4708 4.4708 0 0 1-.5346-3.0137l.142.0852 4.783 2.7582a.7712.7712 0 0 0 .7806 0l5.8428-3.3685v2.3324a.0804.0804 0 0 1-.0332.0615L9.74 19.9502a4.4992 4.4992 0 0 1-6.1408-1.6464zM2.3408 7.8956a4.485 4.485 0 0 1 2.3655-1.9728V11.6a.7664.7664 0 0 0 .3879.6765l5.8144 3.3543-2.0201 1.1685a.0757.0757 0 0 1-.071 0l-4.8303-2.7865A4.504 4.504 0 0 1 2.3408 7.872zm16.5963 3.8558L13.1038 8.364 15.1192 7.2a.0757.0757 0 0 1 .071 0l4.8303 2.7913a4.4944 4.4944 0 0 1-.6765 8.1042v-5.6772a.79.79 0 0 0-.407-.667zm2.0107-3.0231l-.142-.0852-4.7735-2.7818a.7759.7759 0 0 0-.7854 0L9.409 9.2297V6.8974a.0662.0662 0 0 1 .0284-.0615l4.8303-2.7866a4.4992 4.4992 0 0 1 6.6802 4.66zM8.3065 12.863l-2.02-1.1638a.0804.0804 0 0 1-.038-.0567V6.0742a4.4992 4.4992 0 0 1 7.3757-3.4537l-.142.0805L8.704 5.459a.7948.7948 0 0 0-.3927.6813zm1.0976-2.3654l2.602-1.4998 2.6069 1.4998v2.9994l-2.5974 1.4997-2.6067-1.4997Z",
  },
  gemini: {
    path: "M11.04 19.32Q12 21.51 12 24q0-2.49.93-4.68.96-2.19 2.58-3.81t3.81-2.55Q21.51 12 24 12q-2.49 0-4.68-.93a12.3 12.3 0 0 1-3.81-2.58 12.3 12.3 0 0 1-2.58-3.81Q12 2.49 12 0q0 2.49-.96 4.68-.93 2.19-2.55 3.81a12.3 12.3 0 0 1-3.81 2.58Q2.49 12 0 12q2.49 0 4.68.96 2.19.93 3.81 2.55t2.55 3.81",
  },
  grok: {
    fillRule: "evenodd",
    path: "M9.27 15.29l7.978-5.897c.391-.29.95-.177 1.137.272.98 2.369.542 5.215-1.41 7.169-1.951 1.954-4.667 2.382-7.149 1.406l-2.711 1.257c3.889 2.661 8.611 2.003 11.562-.953 2.341-2.344 3.066-5.539 2.388-8.42l.006.007c-.983-4.232.242-5.924 2.75-9.383.06-.082.12-.164.179-.248l-3.301 3.305v-.01L9.267 15.292M7.623 16.723c-2.792-2.67-2.31-6.801.071-9.184 1.761-1.763 4.647-2.483 7.166-1.425l2.705-1.25a7.808 7.808 0 00-1.829-1A8.975 8.975 0 005.984 5.83c-2.533 2.536-3.33 6.436-1.962 9.764 1.022 2.487-.653 4.246-2.34 6.022-.599.63-1.199 1.259-1.682 1.925l7.62-6.815",
  },
};

/* The tinted logo tile — real brand mark when we have one, 2-char fallback otherwise. */
function ProviderLogo({ id, meta }: { id: string; meta: ProviderMeta }) {
  const brand = BRAND_LOGO[id];
  return (
    <span
      aria-hidden
      className="grid h-11 w-11 shrink-0 place-items-center rounded-[13px]"
      style={{ color: meta.tint, background: hexA(meta.tint, "1f"), border: `1px solid ${hexA(meta.tint, "55")}` }}
    >
      {brand ? (
        <svg viewBox="0 0 24 24" width="23" height="23" fill="currentColor" fillRule={brand.fillRule ?? "nonzero"} aria-hidden>
          <path d={brand.path} />
        </svg>
      ) : (
        <span className="font-mono text-[13px] font-semibold">{meta.mono}</span>
      )}
    </span>
  );
}

const METHOD_LABEL: Record<string, string> = {
  oauth_token: "OAuth token",
  api_key: "API key",
  login: "browser login",
};
const METHOD_ICON: Record<string, typeof KeyRound> = {
  oauth_token: ShieldCheck,
  api_key: KeyRound,
  login: Terminal,
};
const CUSTOM = "__custom__";

function firstUrl(s: string | undefined): string | null {
  const m = s?.match(/https?:\/\/[^\s"']+/);
  return m ? m[0] : null;
}

/* ---- model dropdown (shown once connected) ---- */
function ModelSelect({ id, p }: { id: string; p: ProviderAuth }) {
  const { setModel } = useControl();
  const current = p.model ?? "";
  const known = current && p.models.includes(current);
  const [sel, setSel] = useState(known ? current : current ? CUSTOM : p.models[0] ?? "");
  const [custom, setCustom] = useState(known ? "" : current);

  const apply = (v: string) => {
    if (v.trim()) void setModel(id, v.trim());
  };

  return (
    <div className="flex flex-wrap items-center gap-2">
      <span className="text-[11px] text-muted">model</span>
      <Select
        value={sel}
        onChange={(e) => {
          const v = e.target.value;
          setSel(v);
          if (v !== CUSTOM) apply(v);
        }}
        className="h-8 bg-card pr-7 text-xs"
      >
        {p.models.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
        <option value={CUSTOM}>Custom…</option>
      </Select>
      {sel === CUSTOM && (
        <input
          value={custom}
          onChange={(e) => setCustom(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && apply(custom)}
          onBlur={() => apply(custom)}
          placeholder="model id"
          className="h-8 w-44 rounded-lg border border-line bg-card px-2 text-xs outline-none placeholder:text-muted focus:border-brand/50"
        />
      )}
    </div>
  );
}

/* ---- browser-login flow (click connect) ---- */
function LoginFlow({ id, onDone }: { id: string; onDone: () => void }) {
  const { startLogin, pollLogin, submitLoginCode } = useControl();
  const [st, setSt] = useState<LoginStatus | null>(null);
  const [code, setCode] = useState("");
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);
  const [stopped, setStopped] = useState(false); // login ended without connecting (do NOT auto-respawn)
  const onDoneRef = useRef(onDone);
  onDoneRef.current = onDone;
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const aliveRef = useRef(true);

  const clear = () => {
    if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
  };

  // Start (or restart) the login ONCE — never from an effect that re-runs on every parent
  // render. A login that ends without connecting sets `stopped` and waits for an explicit
  // retry, so a failed/expired code can't spin up an endless chain of fresh logins.
  const begin = useCallback(() => {
    setStopped(false);
    setSent(false);
    setCode("");
    setSt(null);
    void (async () => {
      const s = await startLogin(id);
      if (aliveRef.current) setSt(s);
    })();
    clear();
    timer.current = setInterval(async () => {
      const s = await pollLogin(id);
      if (!aliveRef.current) return;
      if (s) setSt(s);
      if (s && s.connected) {
        clear();
        onDoneRef.current();
      } else if (s && !s.running) {
        clear();
        setStopped(true);
      }
    }, 2000);
  }, [id, startLogin, pollLogin]);

  useEffect(() => {
    aliveRef.current = true;
    begin();
    return () => {
      aliveRef.current = false;
      clear();
    };
  }, [begin]);

  // Prefer the backend's clean extracted URL; fall back to scraping the output.
  const url = st?.url ?? firstUrl(st?.output);
  const failed = st && st.ok === false;

  const send = async () => {
    if (!code.trim()) return;
    setSending(true);
    const ok = await submitLoginCode(id, code.trim());
    setSending(false);
    if (ok) {
      setCode("");
      setSent(true);
    }
  };

  return (
    <div className="mt-3 rounded-lg border border-line bg-card2/60 p-3 text-xs">
      {stopped ? (
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="text-amber-400">The login ended before completing.</span>
          <button
            onClick={begin}
            className="inline-flex h-7 items-center gap-1.5 rounded-lg border border-brand/40 bg-brand/10 px-2.5 text-xs font-medium text-fg transition hover:brightness-110"
          >
            <LogIn size={12} /> Try again
          </button>
        </div>
      ) : (
        <div className="flex items-center gap-2 text-muted">
          <Loader2 size={13} className="animate-spin text-brand" />
          {url
            ? "Open the authorization page, approve, then paste the code it shows back here."
            : "Starting the provider login…"}
        </div>
      )}
      {!stopped && url && (
        <a
          href={url}
          target="_blank"
          rel="noreferrer"
          className="mt-2 inline-flex items-center gap-1.5 rounded-lg border border-brand/40 bg-brand/10 px-2.5 py-1 text-xs font-medium text-fg transition hover:brightness-110"
        >
          <ExternalLink size={12} /> Open authorization page
        </a>
      )}
      {!stopped && url && (
        <div className="mt-2 flex flex-col gap-2 sm:flex-row">
          <input
            value={code}
            onChange={(e) => setCode(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void send()}
            placeholder="Paste the code from the authorization page"
            autoComplete="off"
            spellCheck={false}
            className="h-8 flex-1 rounded-lg border border-line bg-card px-2 text-xs outline-none placeholder:text-muted focus:border-brand/50"
          />
          <button
            onClick={() => void send()}
            disabled={sending || !code.trim()}
            className={cx(
              "inline-flex h-8 items-center justify-center gap-1.5 rounded-lg bg-brand px-3 text-xs font-medium text-brand-fg transition hover:brightness-110",
              (sending || !code.trim()) && "cursor-not-allowed opacity-60",
            )}
          >
            {sending ? <Loader2 size={13} className="animate-spin" /> : <PlugZap size={13} />} Submit code
          </button>
        </div>
      )}
      {!stopped && sent && !st?.connected && (
        <p className="mt-2 text-muted">Code submitted — finishing the handshake…</p>
      )}
      {st?.output && (
        <pre className="scroll-thin mt-2 max-h-28 overflow-auto whitespace-pre-wrap rounded bg-card p-2 text-[11px] text-muted">
          {st.output}
        </pre>
      )}
      {failed && (
        <p className="mt-2 text-amber-400">
          The CLI login couldn’t start here. Use a key instead, or run the login once in a terminal — the console
          auto-detects it.
        </p>
      )}
    </div>
  );
}

/* ---- key / token entry ---- */
function KeyForm({ id, p, onDone }: { id: string; p: ProviderAuth; onDone: () => void }) {
  const { setProviderAuth } = useControl();
  const [method, setMethod] = useState(p.methods[0]);
  const [value, setValue] = useState("");
  const [working, setWorking] = useState(false);

  const submit = async () => {
    if (!value.trim()) return;
    setWorking(true);
    const body: SetAuthBody = { method, value: value.trim() };
    const ok = await setProviderAuth(id, body);
    setWorking(false);
    if (ok) {
      setValue("");
      onDone();
    }
  };

  return (
    <div className="mt-3 flex flex-col gap-2">
      {p.methods.length > 1 && (
        <div className="flex gap-1">
          {p.methods.map((m) => (
            <button
              key={m}
              onClick={() => setMethod(m)}
              className={cx(
                "h-7 rounded-lg border px-2.5 text-[11px] font-medium transition",
                method === m ? "border-brand/50 bg-brand/10 text-fg" : "border-line bg-card text-muted hover:text-fg",
              )}
            >
              {METHOD_LABEL[m] ?? m}
            </button>
          ))}
        </div>
      )}
      <div className="flex flex-col gap-2 sm:flex-row">
        <div className="relative flex-1">
          <KeyRound size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
          <input
            type="password"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void submit()}
            placeholder={METHOD_LABEL[method] ?? "secret"}
            autoComplete="off"
            className="h-9 w-full rounded-lg border border-line bg-card pl-8 pr-2 text-sm outline-none placeholder:text-muted focus:border-brand/50"
          />
        </div>
        <button
          onClick={() => void submit()}
          disabled={working || !value.trim()}
          className={cx(
            "inline-flex h-9 items-center justify-center gap-1.5 rounded-lg bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110",
            (working || !value.trim()) && "cursor-not-allowed opacity-60",
          )}
        >
          {working ? <Loader2 size={14} className="animate-spin" /> : <PlugZap size={14} />} Connect
        </button>
      </div>
    </div>
  );
}

/* ---- the dashboard-style runtime card ---- */
function ProviderCard({ id, p }: { id: string; p: ProviderAuth }) {
  const { disconnectProvider } = useControl();
  const [mode, setMode] = useState<"none" | "login" | "key">("none");
  const [working, setWorking] = useState(false);
  const meta = metaFor(id, p.label);

  // "needs attention" == connected through a CLI login we don't own (can't disconnect here)
  const attention = p.connected && !p.can_disconnect;
  const MethodIcon = METHOD_ICON[p.via ?? "api_key"] ?? KeyRound;

  const disconnect = async () => {
    setWorking(true);
    await disconnectProvider(id);
    setWorking(false);
    setMode("none");
  };

  return (
    <div
      className={cx(
        "relative flex min-w-0 flex-col gap-3.5 rounded-[18px] border p-[18px] transition",
        p.connected
          ? "busy-top border-emerald-500/30 bg-emerald-500/[0.03]"
          : "border-fg/10 hover:border-fg/25",
      )}
    >
      {/* top: logo · name/vendor · status pill */}
      <div className="flex items-center gap-3">
        <ProviderLogo id={id} meta={meta} />
        <div className="min-w-0 flex-1">
          <div className="truncate text-[15px] font-medium text-fg-strong">{p.label}</div>
          <div className="truncate text-[12.5px] text-muted">{meta.vendor}</div>
        </div>
        {p.connected ? (
          <span
            className={cx(
              "inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-0.5 text-[11px] font-medium",
              attention
                ? "border border-amber-500/30 bg-amber-500/10 text-amber-400"
                : "border border-emerald-500/30 bg-emerald-500/10 text-emerald-400",
            )}
          >
            {attention ? <AlertTriangle size={12} /> : <CheckCircle2 size={12} />}
            {attention ? "Detected" : "Connected"}
          </span>
        ) : (
          <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-line bg-card2 px-2.5 py-0.5 text-[11px] font-medium text-muted">
            Not connected
          </span>
        )}
      </div>

      {/* description */}
      <p className="line-clamp-2 min-h-[40px] text-[13px] leading-relaxed text-muted">{meta.blurb}</p>

      {/* connected → the credential facts, dashboard-style stat tiles */}
      {p.connected && (
        <div className="grid grid-cols-3 gap-2">
          <div className="min-w-0 rounded-xl border border-line px-2.5 py-2">
            <b className="block truncate text-sm font-semibold text-fg-strong">{METHOD_LABEL[p.via ?? ""] ?? "—"}</b>
            <span className="text-[11px] text-muted">auth method</span>
          </div>
          <div className="min-w-0 rounded-xl border border-line px-2.5 py-2">
            <b className="block truncate font-mono text-sm font-semibold text-fg-strong">{p.masked ?? (p.via === "login" ? "CLI" : "—")}</b>
            <span className="text-[11px] text-muted">credential</span>
          </div>
          <div className="min-w-0 rounded-xl border border-line px-2.5 py-2">
            <b className="block truncate text-sm font-semibold text-fg-strong">{p.source ?? "—"}</b>
            <span className="text-[11px] text-muted">source</span>
          </div>
        </div>
      )}

      {/* connected via a CLI login we don't own → honest hint instead of a dead Disconnect */}
      {attention && (
        <div className="flex items-start gap-2 rounded-xl border border-amber-500/25 bg-amber-500/[0.06] px-3 py-2 text-[12px] leading-relaxed text-amber-400/90">
          <AlertTriangle size={14} className="mt-0.5 shrink-0" />
          <span>
            Connected via the {p.label} CLI’s own login (detected on disk). The console never deletes CLI credentials —
            to disconnect, log out with the {p.label} CLI or unmount its config directory.
          </span>
        </div>
      )}

      {/* connected → model dropdown */}
      {p.connected && p.models.length > 0 && <ModelSelect id={id} p={p} />}

      {/* footer: method + engine chips · action */}
      <div className="mt-auto flex flex-wrap items-center justify-between gap-2.5 pt-1">
        <div className="flex min-w-0 flex-wrap items-center gap-1.5">
          <span className="inline-flex items-center gap-1 rounded-md border border-line bg-card2 px-1.5 py-0.5 text-[10.5px] font-medium text-muted">
            <MethodIcon size={11} /> {p.connected ? METHOD_LABEL[p.via ?? ""] ?? "connected" : p.methods.map((m) => METHOD_LABEL[m] ?? m).join(" · ")}
          </span>
          <span
            className={cx(
              "rounded-md px-1.5 py-0.5 text-[10.5px] font-medium",
              p.live ? "bg-emerald-500/15 text-emerald-400" : "bg-amber-500/15 text-amber-400",
            )}
          >
            {p.live ? "live engine" : "lab only"}
          </span>
        </div>

        {p.connected ? (
          p.can_disconnect ? (
            <button
              onClick={() => void disconnect()}
              disabled={working}
              className="inline-flex h-8 shrink-0 items-center gap-1.5 rounded-lg border border-line bg-card px-3 text-xs font-medium text-muted transition hover:border-brand/40 hover:text-fg disabled:opacity-50"
            >
              {working ? <Loader2 size={13} className="animate-spin" /> : <Unplug size={13} />} Disconnect
            </button>
          ) : null
        ) : (
          <div className="flex shrink-0 items-center gap-1.5">
            {p.can_login && (
              <button
                onClick={() => setMode((m) => (m === "login" ? "none" : "login"))}
                className={cx(
                  "inline-flex h-8 items-center gap-1.5 rounded-lg border px-3 text-xs font-medium transition",
                  mode === "login" ? "border-brand/50 bg-brand/10 text-fg" : "border-line bg-card text-fg hover:border-brand/40",
                )}
              >
                <LogIn size={13} /> Log in
              </button>
            )}
            <button
              onClick={() => setMode((m) => (m === "key" ? "none" : "key"))}
              className={cx(
                "inline-flex h-8 items-center gap-1.5 rounded-lg border px-3 text-xs font-medium transition",
                mode === "key" ? "border-brand/50 bg-brand/10 text-fg" : "border-line bg-card text-muted hover:text-fg",
              )}
            >
              <KeyRound size={13} /> Use a key
            </button>
            {mode !== "none" && (
              <button onClick={() => setMode("none")} className="grid h-8 w-8 place-items-center rounded-lg text-muted hover:text-fg">
                <X size={14} />
              </button>
            )}
          </div>
        )}
      </div>

      {/* not connected → the chosen flow */}
      {!p.connected && mode === "login" && <LoginFlow id={id} onDone={() => setMode("none")} />}
      {!p.connected && mode === "key" && <KeyForm id={id} p={p} onDone={() => setMode("none")} />}
    </div>
  );
}

/* ---- the provider grid (dashboard g-conn layout) ---- */
export function ConnectionsGrid() {
  const { auth } = useControl();
  const providers = Object.entries(auth?.providers ?? {});

  if (providers.length === 0) {
    return <p className="text-sm text-muted">Loading providers…</p>;
  }

  return (
    <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
      {providers.map(([id, p]) => (
        <ProviderCard key={id} id={id} p={p} />
      ))}
    </div>
  );
}

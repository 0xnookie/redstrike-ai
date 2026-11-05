"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  KeyRound, PlugZap, Unplug, Loader2, Bot, CheckCircle2, LogIn, ExternalLink, X,
} from "lucide-react";
import { useControl } from "./ControlProvider";
import type { ProviderAuth, SetAuthBody, LoginStatus } from "@/lib/control";
import { Card } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

const METHOD_LABEL: Record<string, string> = {
  oauth_token: "OAuth token",
  api_key: "API key",
  login: "browser login",
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
      <select
        value={sel}
        onChange={(e) => {
          const v = e.target.value;
          setSel(v);
          if (v !== CUSTOM) apply(v);
        }}
        className="h-8 rounded-lg border border-line bg-card px-2 text-xs outline-none focus:border-brand/50"
      >
        {p.models.map((m) => (
          <option key={m} value={m}>
            {m}
          </option>
        ))}
        <option value={CUSTOM}>Custom…</option>
      </select>
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
          The CLI login couldn’t start here. Use a key below instead, or run the login once in a terminal — the console
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

/* ---- one provider ---- */
function ProviderRow({ id, p }: { id: string; p: ProviderAuth }) {
  const { disconnectProvider } = useControl();
  const [mode, setMode] = useState<"none" | "login" | "key">("none");
  const [working, setWorking] = useState(false);

  const disconnect = async () => {
    setWorking(true);
    await disconnectProvider(id);
    setWorking(false);
    setMode("none");
  };

  return (
    <div className="rounded-xl border border-line bg-card2/40 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="grid h-7 w-7 place-items-center rounded-lg bg-brand/10 text-brand">
            <Bot size={15} />
          </span>
          <span className="text-sm font-medium">{p.label}</span>
          <span
            className={cx(
              "rounded px-1.5 py-0.5 text-[10px] font-medium",
              p.live ? "bg-emerald-500/15 text-emerald-400" : "bg-amber-500/15 text-amber-400",
            )}
          >
            {p.live ? "live engine" : "lab only"}
          </span>
        </div>

        {p.connected ? (
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1 text-xs text-emerald-400">
              <CheckCircle2 size={13} /> {METHOD_LABEL[p.via ?? ""] ?? "connected"}
              {p.masked && <span className="text-muted"> · {p.masked}</span>}
            </span>
            {p.can_disconnect && (
              <button
                onClick={() => void disconnect()}
                disabled={working}
                className="inline-flex h-7 items-center gap-1 rounded-lg border border-line bg-card px-2 text-[11px] text-muted transition hover:border-brand/40 hover:text-fg disabled:opacity-50"
              >
                <Unplug size={12} /> Disconnect
              </button>
            )}
          </div>
        ) : (
          <div className="flex items-center gap-1.5">
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

      {/* connected via a CLI login we don't own → honest hint instead of a dead Disconnect */}
      {p.connected && !p.can_disconnect && (
        <p className="mt-2 text-[11px] text-muted">
          Connected via the {p.label} CLI’s own login (detected on disk). The console never deletes CLI
          credentials — to disconnect, log out with the {p.label} CLI or unmount its config directory.
        </p>
      )}

      {/* connected → model dropdown */}
      {p.connected && p.models.length > 0 && (
        <div className="mt-3">
          <ModelSelect id={id} p={p} />
        </div>
      )}

      {/* not connected → the chosen flow */}
      {!p.connected && mode === "login" && <LoginFlow id={id} onDone={() => setMode("none")} />}
      {!p.connected && mode === "key" && <KeyForm id={id} p={p} onDone={() => setMode("none")} />}
    </div>
  );
}

export function LlmConnectCard() {
  const { auth, conn } = useControl();
  if (conn !== "ready") return null;
  const providers = Object.entries(auth?.providers ?? {});

  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">Connect an LLM</h2>
        <span className="text-[11px] text-muted">
          engine: <code className="rounded bg-card2 px-1 py-0.5">{auth?.engine ?? "claude-code"}</code>
        </span>
      </div>
      {providers.length === 0 ? (
        <p className="text-xs text-muted">Loading providers…</p>
      ) : (
        <div className="space-y-2">
          {providers.map(([id, p]) => (
            <ProviderRow key={id} id={id} p={p} />
          ))}
        </div>
      )}
      <p className="mt-3 text-[11px] text-muted">
        Click <strong>Log in</strong> to connect through the provider’s own browser flow, or <strong>Use a key</strong> to
        paste one. Credentials are held only in the control-plane process (localhost, token-gated) and inherited by
        launched runs — never written to disk. Claude is the live engine today; Codex/Gemini can be stored but aren’t
        live engines yet.
      </p>
    </Card>
  );
}

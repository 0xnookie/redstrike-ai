"use client";

import { useState } from "react";
import { KeyRound, PlugZap, Unplug, Loader2, Bot, CheckCircle2, ChevronDown } from "lucide-react";
import { useControl } from "./ControlProvider";
import type { ProviderAuth, SetAuthBody } from "@/lib/control";
import { Card } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

const METHOD_LABEL: Record<string, string> = {
  oauth_token: "OAuth token",
  api_key: "API key",
};

function ProviderRow({ id, p }: { id: string; p: ProviderAuth }) {
  const { setProviderAuth, disconnectProvider } = useControl();
  const [method, setMethod] = useState(p.methods[0]);
  const [value, setValue] = useState("");
  const [model, setModel] = useState(p.model ?? "");
  const [open, setOpen] = useState(false);
  const [working, setWorking] = useState(false);

  const submit = async () => {
    if (!value.trim()) return;
    setWorking(true);
    const body: SetAuthBody = { method, value: value.trim() };
    if (id === "claude" && model.trim()) body.model = model.trim();
    const ok = await setProviderAuth(id, body);
    setWorking(false);
    if (ok) {
      setValue("");
      setOpen(false);
    }
  };

  const disconnect = async () => {
    setWorking(true);
    await disconnectProvider(id);
    setWorking(false);
  };

  const showForm = open || !p.connected;

  return (
    <div className="rounded-xl border border-line bg-card2/40 p-3">
      <div className="flex items-center justify-between gap-2">
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
            <button
              onClick={() => setOpen((o) => !o)}
              className="inline-flex h-7 items-center gap-1 rounded-lg border border-line bg-card px-2 text-[11px] text-muted transition hover:text-fg"
            >
              Change <ChevronDown size={11} className={cx("transition", open && "rotate-180")} />
            </button>
            <button
              onClick={() => void disconnect()}
              disabled={working}
              className="inline-flex h-7 items-center gap-1 rounded-lg border border-line bg-card px-2 text-[11px] text-muted transition hover:border-brand/40 hover:text-fg disabled:opacity-50"
            >
              <Unplug size={12} /> Disconnect
            </button>
          </div>
        ) : (
          <span className="text-xs text-muted">not connected</span>
        )}
      </div>

      {showForm && (
        <div className="mt-3 flex flex-col gap-2">
          {p.methods.length > 1 && (
            <div className="flex gap-1">
              {p.methods.map((m) => (
                <button
                  key={m}
                  onClick={() => setMethod(m)}
                  className={cx(
                    "h-7 rounded-lg border px-2.5 text-[11px] font-medium transition",
                    method === m
                      ? "border-brand/50 bg-brand/10 text-fg"
                      : "border-line bg-card text-muted hover:text-fg",
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
            {id === "claude" && (
              <input
                value={model}
                onChange={(e) => setModel(e.target.value)}
                placeholder="model (e.g. claude-opus-5-5)"
                className="h-9 w-full rounded-lg border border-line bg-card px-2.5 text-sm outline-none placeholder:text-muted focus:border-brand/50 sm:w-56"
              />
            )}
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
      )}
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
        Keys are held only in the control-plane process (localhost, token-gated) and inherited by launched runs —
        never written to disk, and cleared on restart. Claude is the live engine today; Codex/Gemini can be stored
        but aren’t live engines yet.
      </p>
    </Card>
  );
}

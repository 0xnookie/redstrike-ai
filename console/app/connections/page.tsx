"use client";

import { useEffect } from "react";
import Link from "next/link";
import { PlugZap, Cpu, FlaskConical, Bot, Share2 } from "lucide-react";
import { useControl } from "@/components/control/ControlProvider";
import { ConnectCard } from "@/components/control/ConnectCard";
import { ConnectionsGrid } from "@/components/control/ConnectionsView";
import { Kpi, ViewHead } from "@/components/ui/primitives";

export default function ConnectionsPage() {
  const { conn, auth, refreshAuth } = useControl();

  // the plane may have been connected on another view — pull a fresh snapshot on mount
  useEffect(() => {
    if (conn === "ready") void refreshAuth();
  }, [conn, refreshAuth]);

  const providers = Object.values(auth?.providers ?? {});
  const total = providers.length;
  const connected = providers.filter((p) => p.connected).length;
  const liveConnected = providers.filter((p) => p.connected && p.live).length;
  const labConnected = providers.filter((p) => p.connected && !p.live).length;
  const engine = auth?.engine ?? "claude-code";

  return (
    <>
      <ViewHead
        crumb="redstrike / connections"
        title="Agent Connections"
        live={conn === "ready" && connected > 0}
        sub={
          conn === "ready"
            ? `${connected} of ${total} runtimes connected · engine ${engine}`
            : "control plane offline — connect it to manage runtimes"
        }
        actions={
          <Link
            href="/orchestration"
            className="inline-flex h-10 items-center gap-2 rounded-full border border-line px-4 text-sm font-medium text-fg transition hover:border-fg/30"
          >
            <Share2 size={15} /> Live orchestration
          </Link>
        }
      />

      <p className="-mt-2 mb-5 max-w-3xl text-sm text-muted">
        Bring your own coding-agent runtime. Connect the opt-in control plane, then give the launched agents an engine —
        a subscription login or an API key. Credentials are held only in the control-plane process (localhost,
        token-gated) and inherited by launched runs — never written to disk. Launch and steer engagements from the{" "}
        <Link href="/engagements" className="text-fg underline-offset-2 hover:underline">Engagements</Link> view.
      </p>

      {/* control plane — slim bar when ready, connect/offline UI otherwise */}
      <ConnectCard />

      {conn === "ready" && (
        <>
          <div className="mt-5 grid grid-cols-2 gap-3.5 lg:grid-cols-4">
            <Kpi
              label="Connected runtimes"
              value={connected}
              suffix={`of ${total}`}
              color={connected > 0 ? "#22c55e" : undefined}
              icon={<PlugZap size={16} />}
              note="providers with a credential"
            />
            <Kpi
              label="Live engines"
              value={liveConnected}
              icon={<Cpu size={16} />}
              note="ready to launch runs"
            />
            <Kpi
              label="Lab-only connected"
              value={labConnected}
              icon={<FlaskConical size={16} />}
              note="stored · not a live engine yet"
            />
            <Kpi
              label="Active engine"
              value={<code className="text-[22px] tracking-tight">{engine}</code>}
              icon={<Bot size={16} />}
              note="runtime launched runs use"
            />
          </div>

          <div className="mt-6">
            <ConnectionsGrid />
          </div>

          <p className="mt-4 text-[12px] leading-relaxed text-muted">
            Click <strong className="text-fg">Log in</strong> to connect through the provider’s own browser flow, or{" "}
            <strong className="text-fg">Use a key</strong> to paste one. Claude is the live engine today; Codex, Gemini
            and Grok can be stored but aren’t live engines yet.
          </p>
        </>
      )}
    </>
  );
}

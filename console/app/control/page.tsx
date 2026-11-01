"use client";

import { ShieldAlert } from "lucide-react";
import { PageHeader, Pill } from "@/components/ui/primitives";
import { ControlProvider, useControl } from "@/components/control/ControlProvider";
import { ConnectCard } from "@/components/control/ConnectCard";
import { LaunchPanel } from "@/components/control/LaunchPanel";
import { RunStream } from "@/components/control/RunStream";
import { ApprovalsPanel } from "@/components/control/ApprovalsPanel";

function ControlInner() {
  const { conn } = useControl();

  return (
    <>
      <PageHeader
        title="Control plane"
        subtitle="Launch and steer an autonomous engagement from the console."
        actions={<Pill label="Experimental" color="#f59e0b" />}
      />

      <div className="space-y-3">
        <ConnectCard />

        {conn === "ready" && (
          <>
            {/* security posture reminder — the plane runs real offensive tooling */}
            <div className="flex items-start gap-2.5 rounded-xl border border-amber-500/30 bg-amber-500/[0.06] p-3 text-xs text-muted">
              <ShieldAlert size={15} className="mt-0.5 shrink-0 text-amber-400" />
              <p>
                Launching runs real offensive tooling via the same <code className="rounded bg-card2 px-1 py-0.5 text-[11px]">redstrike</code>{" "}
                CLI as the terminal — bound to localhost, token-gated, autonomous only. The scope gate still applies and every command
                outside your allowlist defers for approval; nothing here bypasses a gate.
              </p>
            </div>

            <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
              <div className="lg:row-span-2">
                <LaunchPanel />
              </div>
              <RunStream />
              <ApprovalsPanel />
            </div>
          </>
        )}
      </div>
    </>
  );
}

export default function ControlPage() {
  return (
    <ControlProvider>
      <ControlInner />
    </ControlProvider>
  );
}

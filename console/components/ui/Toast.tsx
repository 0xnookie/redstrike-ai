"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState } from "react";
import { CircleCheck, CircleAlert } from "lucide-react";
import { cx } from "@/lib/format";

type Tone = "ok" | "warn";
type ToastFn = (message: string, tone?: Tone) => void;

const ToastCtx = createContext<ToastFn>(() => {});

/** One action-confirmation toast at a time (a newer one replaces the current), bottom-right,
 *  above the status bar. Announced politely to screen readers. */
export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [msg, setMsg] = useState("");
  const [tone, setTone] = useState<Tone>("ok");
  const [show, setShow] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const toast = useCallback<ToastFn>((message, t = "ok") => {
    setMsg(message);
    setTone(t);
    setShow(true);
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => setShow(false), 2600);
  }, []);

  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  return (
    <ToastCtx.Provider value={toast}>
      {children}
      <div className={cx("toast", show && "show")} role="status" aria-live="polite">
        {tone === "ok"
          ? <CircleCheck size={16} className="shrink-0 text-emerald-500" />
          : <CircleAlert size={16} className="shrink-0 text-amber-500" />}
        <span className="min-w-0">{msg}</span>
      </div>
    </ToastCtx.Provider>
  );
}

export const useToast = () => useContext(ToastCtx);

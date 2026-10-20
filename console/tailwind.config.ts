import type { Config } from "tailwindcss";

/** Theme tokens live as RGB channels in globals.css (:root / .dark) so every
 *  color supports Tailwind's alpha modifier (e.g. bg-brand/10). */
const withAlpha = (v: string) => `rgb(var(${v}) / <alpha-value>)`;

const config: Config = {
  darkMode: "class",
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
    "./lib/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        bg: withAlpha("--bg"),
        card: withAlpha("--card"),
        card2: withAlpha("--card2"),
        line: withAlpha("--line"),
        fg: withAlpha("--fg"),
        muted: withAlpha("--muted"),
        sidebar: withAlpha("--sidebar"),
        brand: {
          DEFAULT: withAlpha("--brand"),
          fg: withAlpha("--brand-fg"),
        },
      },
      fontFamily: {
        sans: ["var(--font-sans, ui-sans-serif)", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
        pixel: ["var(--font-pixel)", "ui-monospace", "monospace"],
      },
      borderRadius: {
        xl: "0.875rem",
        "2xl": "1.125rem",
      },
      boxShadow: {
        card: "0 1px 2px 0 rgb(0 0 0 / 0.03), 0 1px 3px 0 rgb(0 0 0 / 0.04)",
        pop: "0 10px 30px -12px rgb(0 0 0 / 0.25)",
      },
      keyframes: {
        "fade-in": { from: { opacity: "0", transform: "translateY(4px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        "slide-in": { from: { transform: "translateX(100%)" }, to: { transform: "translateX(0)" } },
        "pulse-soft": { "0%,100%": { opacity: "1" }, "50%": { opacity: "0.4" } },
      },
      animation: {
        "fade-in": "fade-in 0.2s ease-out",
        "slide-in": "slide-in 0.25s cubic-bezier(0.22,1,0.36,1)",
        "pulse-soft": "pulse-soft 1.8s ease-in-out infinite",
      },
    },
  },
  plugins: [],
};

export default config;

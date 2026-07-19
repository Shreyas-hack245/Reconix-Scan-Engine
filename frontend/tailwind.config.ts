import type { Config } from "tailwindcss";

// Design tokens for the Reconix Scan Engine dashboard: a graphite/
// "security operations center" palette with a signal-amber accent
// (deliberately not the generic near-black + acid-green pairing),
// pairing a monospace data face for URLs/IDs/evidence with a clean
// grotesk for UI chrome.
export default {
    darkMode: "class",
    content: ["./index.html", "./src/**/*.{ts,tsx}"],
    theme: {
        extend: {
            colors: {
                bg: "#0B0C0F",
                panel: "#15171C",
                panel2: "#1B1E25",
                border: "#262931",
                text: "#E8E9ED",
                muted: "#8B909C",
                accent: {
                    DEFAULT: "#FFB020",
                    dim: "#8A5E17",
                    fg: "#1A1200",
                },
                severity: {
                    critical: "#EF4444",
                    high: "#F97316",
                    medium: "#EAB308",
                    low: "#3B82F6",
                    info: "#8B909C",
                },
            },
            fontFamily: {
                sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
                mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
            },
            borderRadius: {
                DEFAULT: "8px",
                lg: "12px",
            },
            boxShadow: {
                panel: "0 1px 2px rgba(0,0,0,0.4)",
            },
            keyframes: {
                sweep: {
                    "0%": { transform: "rotate(0deg)" },
                    "100%": { transform: "rotate(360deg)" },
                },
                pulseSoft: {
                    "0%, 100%": { opacity: "1" },
                    "50%": { opacity: "0.5" },
                },
            },
            animation: {
                sweep: "sweep 3s linear infinite",
                "pulse-soft": "pulseSoft 2s ease-in-out infinite",
            },
        },
    },
    plugins: [],
} satisfies Config;
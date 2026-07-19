// Risk summary panel for a scan: a radial "sweep" gauge showing the
// aggregate 0-100 risk score (this dashboard's signature element, tying
// back to Reconix's reconnaissance/radar concept) plus a per-severity
// finding breakdown.

import { SEVERITY_LABELS, SEVERITY_ORDER, type Severity } from "@/types";

interface RiskSummaryProps {
    riskScore: number;
    counts: Record<Severity, number>;
    endpointsDiscovered: number;
    pagesCrawled: number;
}

const SEVERITY_HEX: Record<Severity, string> = {
    critical: "#EF4444",
    high: "#F97316",
    medium: "#EAB308",
    low: "#3B82F6",
    info: "#8B909C",
};

function riskLabel(score: number): { label: string; color: string } {
    if (score >= 75) return { label: "Critical Risk", color: "#EF4444" };
    if (score >= 50) return { label: "High Risk", color: "#F97316" };
    if (score >= 25) return { label: "Moderate Risk", color: "#EAB308" };
    if (score > 0) return { label: "Low Risk", color: "#3B82F6" };
    return { label: "No Findings", color: "#8B909C" };
}

function RiskGauge({ score }: { score: number }) {
    const size = 180;
    const stroke = 14;
    const radius = (size - stroke) / 2;
    const circumference = 2 * Math.PI * radius;
    const clamped = Math.max(0, Math.min(100, score));
    const offset = circumference - (clamped / 100) * circumference;
    const { label, color } = riskLabel(score);

    return (
        <div className="flex flex-col items-center">
            <div className="relative" style={{ width: size, height: size }}>
                <svg width={size} height={size} className="-rotate-90">
                    <circle
                        cx={size / 2}
                        cy={size / 2}
                        r={radius}
                        fill="none"
                        stroke="#262931"
                        strokeWidth={stroke}
                    />
                    <circle
                        cx={size / 2}
                        cy={size / 2}
                        r={radius}
                        fill="none"
                        stroke={color}
                        strokeWidth={stroke}
                        strokeLinecap="round"
                        strokeDasharray={circumference}
                        strokeDashoffset={offset}
                        style={{ transition: "stroke-dashoffset 0.8s ease, stroke 0.8s ease" }}
                    />
                </svg>
                <div className="absolute inset-0 flex flex-col items-center justify-center">
                    <span className="font-mono text-4xl font-bold text-text">{clamped.toFixed(0)}</span>
                    <span className="text-[11px] uppercase tracking-wider text-muted">/ 100</span>
                </div>
            </div>
            <span className="mt-3 text-sm font-semibold" style={{ color }}>
                {label}
            </span>
        </div>
    );
}

export function RiskSummary({ riskScore, counts, endpointsDiscovered, pagesCrawled }: RiskSummaryProps) {
    const total = SEVERITY_ORDER.reduce((sum, sev) => sum + (counts[sev] ?? 0), 0);

    return (
        <div className="panel p-6">
            <h2 className="mb-4 text-sm font-semibold uppercase tracking-wider text-muted">Risk Summary</h2>
            <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-start sm:justify-between">
                <RiskGauge score={riskScore} />

                <div className="w-full flex-1">
                    <div className="grid grid-cols-2 gap-3 sm:grid-cols-1">
                        {SEVERITY_ORDER.map((sev) => {
                            const count = counts[sev] ?? 0;
                            const pct = total > 0 ? (count / total) * 100 : 0;
                            return (
                                <div key={sev} className="flex items-center gap-3">
                                    <span className="w-16 shrink-0 text-xs font-semibold" style={{ color: SEVERITY_HEX[sev] }}>
                                        {SEVERITY_LABELS[sev]}
                                    </span>
                                    <div className="h-2 flex-1 overflow-hidden rounded-full bg-panel2">
                                        <div
                                            className="h-full rounded-full transition-all duration-700"
                                            style={{ width: `${pct}%`, backgroundColor: SEVERITY_HEX[sev] }}
                                        />
                                    </div>
                                    <span className="w-6 shrink-0 text-right font-mono text-xs text-muted">{count}</span>
                                </div>
                            );
                        })}
                    </div>

                    <div className="mt-5 flex gap-6 border-t border-border pt-4 text-xs text-muted">
                        <div>
                            <div className="font-mono text-lg text-text">{pagesCrawled}</div>
                            <div>Pages Crawled</div>
                        </div>
                        <div>
                            <div className="font-mono text-lg text-text">{endpointsDiscovered}</div>
                            <div>Endpoints Discovered</div>
                        </div>
                        <div>
                            <div className="font-mono text-lg text-text">{total}</div>
                            <div>Total Findings</div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
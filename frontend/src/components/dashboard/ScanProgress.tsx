// Scan pipeline progress indicator: shows which stage a scan is
// currently in (Pending -> Crawling -> Scanning -> Completed/Failed).

import { CheckCircle2, CircleDashed, Loader2, XCircle } from "lucide-react";
import type { Scan } from "@/types";

const STAGES: { key: Scan["status"]; label: string }[] = [
    { key: "pending", label: "Queued" },
    { key: "crawling", label: "Crawling" },
    { key: "scanning", label: "Scanning" },
    { key: "completed", label: "Complete" },
];

function stageIndex(status: Scan["status"]): number {
    if (status === "failed" || status === "cancelled") return -1;
    return STAGES.findIndex((s) => s.key === status);
}

export function ScanProgress({ scan }: { scan: Scan }) {
    const currentIndex = stageIndex(scan.status);
    const isTerminalFailure = scan.status === "failed" || scan.status === "cancelled";

    return (
        <div className="panel p-6">
            <div className="mb-5 flex items-center justify-between">
                <h2 className="text-sm font-semibold uppercase tracking-wider text-muted">Scan Progress</h2>
                <span className="mono-id break-all">{scan.target_url}</span>
            </div>

            {isTerminalFailure ? (
                <div className="flex items-center gap-3 rounded border border-severity-critical/30 bg-severity-critical/10 p-4">
                    <XCircle className="h-5 w-5 shrink-0 text-severity-critical" />
                    <div>
                        <div className="text-sm font-semibold text-severity-critical">
                            {scan.status === "failed" ? "Scan Failed" : "Scan Cancelled"}
                        </div>
                        {scan.error_message && (
                            <div className="mt-1 font-mono text-xs text-muted">{scan.error_message}</div>
                        )}
                    </div>
                </div>
            ) : (
                <div className="flex items-center">
                    {STAGES.map((stage, i) => {
                        const isDone = i < currentIndex || scan.status === "completed";
                        const isActive = i === currentIndex && scan.status !== "completed";
                        return (
                            <div key={stage.key} className="flex flex-1 items-center last:flex-none">
                                <div className="flex flex-col items-center gap-2">
                                    {isDone ? (
                                        <CheckCircle2 className="h-6 w-6 text-emerald-400" />
                                    ) : isActive ? (
                                        <Loader2 className="h-6 w-6 animate-spin text-accent" />
                                    ) : (
                                        <CircleDashed className="h-6 w-6 text-border" />
                                    )}
                                    <span
                                        className={`text-xs font-medium ${isDone || isActive ? "text-text" : "text-muted"}`}
                                    >
                                        {stage.label}
                                    </span>
                                </div>
                                {i < STAGES.length - 1 && (
                                    <div
                                        className={`mx-2 h-0.5 flex-1 rounded ${i < currentIndex ? "bg-emerald-400" : "bg-border"}`}
                                    />
                                )}
                            </div>
                        );
                    })}
                </div>
            )}

            <div className="mt-6 grid grid-cols-3 gap-4 border-t border-border pt-4 text-xs text-muted">
                <div>
                    <div className="font-mono text-base text-text">{scan.pages_crawled}</div>
                    <div>Pages Crawled</div>
                </div>
                <div>
                    <div className="font-mono text-base text-text">{scan.endpoints_discovered}</div>
                    <div>Endpoints</div>
                </div>
                <div>
                    <div className="font-mono text-base text-text">{scan.findings_count}</div>
                    <div>Findings</div>
                </div>
            </div>
        </div>
    );
}
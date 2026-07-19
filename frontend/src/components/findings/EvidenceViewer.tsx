// Renders a finding's evidence and safe proof-of-concept in a
// structured, read-only viewer (request/response/impact/verification).

import { AlertTriangle, ShieldCheck } from "lucide-react";
import type { SafePoc } from "@/types";

export function EvidenceViewer({ evidence, safePoc }: { evidence: string; safePoc: SafePoc | null }) {
    return (
        <div className="space-y-4">
            <div>
                <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Evidence</div>
                <p className="rounded border border-border bg-bg p-3 text-sm text-text/90">{evidence}</p>
            </div>

            {safePoc && (
                <div className="rounded border border-border bg-bg">
                    <div className="flex items-center gap-2 border-b border-border bg-panel2 px-3 py-2">
                        <ShieldCheck className="h-4 w-4 text-emerald-400" />
                        <span className="text-xs font-semibold uppercase tracking-wide text-emerald-400">
                            Safe Proof of Concept -- non-destructive, detection only
                        </span>
                    </div>

                    <div className="space-y-3 p-3">
                        <div>
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
                                Example Request
                            </div>
                            <pre className="overflow-x-auto rounded bg-panel2 p-2.5 font-mono text-xs text-text">
                                {safePoc.example_request}
                            </pre>
                        </div>

                        <div>
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
                                Example Vulnerable Response
                            </div>
                            <pre className="overflow-x-auto rounded bg-panel2 p-2.5 font-mono text-xs text-text">
                                {safePoc.example_response}
                            </pre>
                        </div>

                        <div className="grid gap-3 sm:grid-cols-2">
                            <div>
                                <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
                                    Expected Safe Output
                                </div>
                                <p className="text-xs text-text/90">{safePoc.expected_safe_output}</p>
                            </div>
                            <div>
                                <div className="mb-1 flex items-center gap-1 text-[11px] font-semibold uppercase tracking-wide text-severity-high">
                                    <AlertTriangle className="h-3.5 w-3.5" /> Impact
                                </div>
                                <p className="text-xs text-text/90">{safePoc.impact}</p>
                            </div>
                        </div>

                        <div>
                            <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide text-muted">
                                Verification Steps
                            </div>
                            <ol className="list-inside list-decimal space-y-1 text-xs text-text/90">
                                {safePoc.verification_steps.map((step, i) => (
                                    <li key={i}>{step}</li>
                                ))}
                            </ol>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
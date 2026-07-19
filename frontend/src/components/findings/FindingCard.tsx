// A single expandable finding card: severity, title, URL/parameter,
// OWASP/CVSS mapping, confidence, and (when expanded) the full risk
// explanation, business impact, remediation, and safe PoC.

import { useState } from "react";
import { ChevronDown, ChevronUp, TriangleAlert } from "lucide-react";
import { Badge, SeverityBadge } from "@/components/ui/Badge";
import { EvidenceViewer } from "@/components/findings/EvidenceViewer";
import type { Finding } from "@/types";

const SEVERITY_BORDER: Record<Finding["severity"], string> = {
    critical: "border-l-severity-critical",
    high: "border-l-severity-high",
    medium: "border-l-severity-medium",
    low: "border-l-severity-low",
    info: "border-l-severity-info",
};

export function FindingCard({ finding }: { finding: Finding }) {
    const [expanded, setExpanded] = useState(false);

    return (
        <div className={`panel border-l-4 ${SEVERITY_BORDER[finding.severity]} overflow-hidden`}>
            <button
                onClick={() => setExpanded((v) => !v)}
                className="flex w-full items-start justify-between gap-4 p-4 text-left"
            >
                <div className="min-w-0 flex-1">
                    <div className="mb-1.5 flex flex-wrap items-center gap-2">
                        <SeverityBadge severity={finding.severity} />
                        {finding.owasp_category && <Badge>{finding.owasp_category}</Badge>}
                        {finding.cvss_score !== null && <Badge>CVSS {finding.cvss_score.toFixed(1)}</Badge>}
                        {finding.is_false_positive && (
                            <Badge className="border-severity-medium/30 bg-severity-medium/15 text-severity-medium">
                                <TriangleAlert className="mr-1 h-3 w-3" /> verify: low confidence
                            </Badge>
                        )}
                    </div>
                    <h3 className="text-sm font-semibold text-text">{finding.title}</h3>
                    <div className="mt-1 truncate font-mono text-xs text-muted">
                        {finding.method} {finding.url}
                        {finding.parameter && <span className="text-accent"> ?{finding.parameter}</span>}
                    </div>
                </div>

                <div className="flex shrink-0 items-center gap-3">
                    <div className="text-right">
                        <div className="font-mono text-sm text-text">{(finding.confidence * 100).toFixed(0)}%</div>
                        <div className="text-[10px] uppercase text-muted">confidence</div>
                    </div>
                    {expanded ? (
                        <ChevronUp className="h-5 w-5 text-muted" />
                    ) : (
                        <ChevronDown className="h-5 w-5 text-muted" />
                    )}
                </div>
            </button>

            {expanded && (
                <div className="space-y-4 border-t border-border p-4">
                    {finding.risk_explanation && (
                        <div>
                            <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                                Risk Explanation
                            </div>
                            <p className="text-sm text-text/90">{finding.risk_explanation}</p>
                        </div>
                    )}

                    {finding.business_impact && (
                        <div>
                            <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
                                Business Impact
                            </div>
                            <p className="text-sm text-text/90">{finding.business_impact}</p>
                        </div>
                    )}

                    <EvidenceViewer evidence={finding.evidence} safePoc={finding.safe_poc} />

                    {finding.remediation && (
                        <div>
                            <div className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-emerald-400">
                                Remediation
                            </div>
                            <p className="whitespace-pre-line text-sm text-text/90">{finding.remediation}</p>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}
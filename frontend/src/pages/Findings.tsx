import { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import * as api from "@/lib/api";
import type { FindingListResponse } from "@/types";
import { FindingCard } from "@/components/findings/FindingCard";
import { ArrowLeft, Radar, AlertTriangle, ShieldCheck } from "lucide-react";

export default function Findings() {
    const { scanId } = useParams<{ scanId: string }>();
    const [scanTarget, setScanTarget] = useState<string>("");
    const [findingsData, setFindingsData] = useState<FindingListResponse | null>(null);
    const [selectedSeverity, setSelectedSeverity] = useState<string>(""); // "" means All
    const [includeFalsePositives, setIncludeFalsePositives] = useState<boolean>(true);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const fetchFindings = useCallback(async (showLoading = false) => {
        if (!scanId) return;
        if (showLoading) setLoading(true);
        try {
            // Get scan to show the target URL in header
            const scan = await api.getScan(scanId);
            setScanTarget(scan.target_url);

            // Get findings
            const data = await api.listFindings(scanId, {
                severity: selectedSeverity || undefined,
                includeFalsePositives,
            });
            setFindingsData(data);
            setError(null);
        } catch (err: any) {
            setError(err.message || "Failed to load findings");
        } finally {
            if (showLoading) setLoading(false);
        }
    }, [scanId, selectedSeverity, includeFalsePositives]);

    useEffect(() => {
        fetchFindings(true);
    }, [fetchFindings]);

    if (loading && !findingsData) {
        return (
            <div className="flex min-h-[50vh] flex-col items-center justify-center text-muted">
                <Radar className="h-10 w-10 animate-spin text-accent mb-2" />
                <span className="text-sm">Loading vulnerabilities...</span>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex min-h-[50vh] flex-col items-center justify-center text-severity-critical">
                <AlertTriangle className="h-10 w-10 mb-2" />
                <h3 className="text-base font-bold text-text mb-1">Findings Error</h3>
                <p className="text-sm text-muted">{error}</p>
                <button onClick={() => fetchFindings(true)} className="btn-secondary mt-4">
                    Retry
                </button>
            </div>
        );
    }

    // Tab items helper
    const severities: { key: string; label: string; count: number; colorClass: string }[] = [
        {
            key: "",
            label: "All",
            count: findingsData ? findingsData.total : 0,
            colorClass: "border-border hover:border-text text-text"
        },
        {
            key: "critical",
            label: "Critical",
            count: findingsData?.critical_count ?? 0,
            colorClass: "border-severity-critical/20 hover:border-severity-critical/50 text-severity-critical"
        },
        {
            key: "high",
            label: "High",
            count: findingsData?.high_count ?? 0,
            colorClass: "border-severity-high/20 hover:border-severity-high/50 text-severity-high"
        },
        {
            key: "medium",
            label: "Medium",
            count: findingsData?.medium_count ?? 0,
            colorClass: "border-severity-medium/20 hover:border-severity-medium/50 text-severity-medium"
        },
        {
            key: "low",
            label: "Low",
            count: findingsData?.low_count ?? 0,
            colorClass: "border-severity-low/20 hover:border-severity-low/50 text-severity-low"
        },
        {
            key: "info",
            label: "Info",
            count: findingsData?.info_count ?? 0,
            colorClass: "border-severity-info/20 hover:border-severity-info/50 text-severity-info"
        }
    ];

    const findings = findingsData?.findings ?? [];

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                    <Link to={`/scans/${scanId}`} className="btn-secondary p-2.5 rounded" title="Back to Scan details">
                        <ArrowLeft className="h-4 w-4" />
                    </Link>
                    <div>
                        <h1 className="text-xl font-bold text-text">Vulnerability Findings</h1>
                        <p className="text-xs text-muted font-mono mt-0.5">{scanTarget}</p>
                    </div>
                </div>
            </div>

            {/* Filter Bar */}
            <div className="panel p-4 flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
                {/* Severity tabs */}
                <div className="flex flex-wrap gap-2">
                    {severities.map((tab) => {
                        const isActive = selectedSeverity === tab.key;
                        const activeClass = isActive
                            ? "bg-panel2 border-accent text-accent"
                            : "bg-panel border-border text-muted";
                        return (
                            <button
                                key={tab.key}
                                onClick={() => setSelectedSeverity(tab.key)}
                                className={`flex items-center gap-1.5 rounded border px-3 py-1.5 text-xs font-semibold uppercase tracking-wider transition ${activeClass}`}
                            >
                                <span>{tab.label}</span>
                                <span className={`rounded-full px-1.5 py-0.2 text-[10px] font-bold border border-border bg-panel`}>
                                    {tab.count}
                                </span>
                            </button>
                        );
                    })}
                </div>

                {/* Filters */}
                <div className="flex items-center gap-3 border-t border-border pt-4 md:border-t-0 md:pt-0">
                    <label className="flex items-center gap-2 text-xs font-semibold text-muted uppercase tracking-wider cursor-pointer">
                        <input
                            type="checkbox"
                            checked={includeFalsePositives}
                            onChange={(e) => setIncludeFalsePositives(e.target.checked)}
                            className="rounded border-border bg-bg text-accent focus:ring-0 cursor-pointer h-4 w-4"
                        />
                        <span>Show low confidence</span>
                    </label>
                </div>
            </div>

            {/* Findings List */}
            {loading ? (
                <div className="flex flex-col items-center justify-center p-12 text-muted">
                    <Radar className="h-8 w-8 animate-spin text-accent mb-2" />
                    <span className="text-sm">Updating findings list...</span>
                </div>
            ) : findings.length === 0 ? (
                <div className="panel p-12 text-center text-muted">
                    <ShieldCheck className="mx-auto h-12 w-12 text-emerald-400/80 mb-3" />
                    <h3 className="text-sm font-semibold text-text mb-1">No Findings Found</h3>
                    <p className="text-xs">
                        {selectedSeverity
                            ? `No vulnerabilities with ${selectedSeverity} severity were detected.`
                            : "Clean scan! No vulnerabilities detected on this target."}
                    </p>
                </div>
            ) : (
                <div className="space-y-4">
                    {findings.map((finding) => (
                        <FindingCard key={finding.id} finding={finding} />
                    ))}
                </div>
            )}
        </div>
    );
}

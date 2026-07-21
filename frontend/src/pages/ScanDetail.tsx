import { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import * as api from "@/lib/api";
import type { Scan, FindingListResponse } from "@/types";
import { ScanProgress } from "@/components/dashboard/ScanProgress";
import { RiskSummary } from "@/components/dashboard/RiskSummary";
import {
    Radar,
    ArrowLeft,
    ShieldAlert,
    History,
    FileJson,
    FileText,
    Globe,
    Clock,
    Download,
    AlertTriangle
} from "lucide-react";

export default function ScanDetail() {
    const { scanId } = useParams<{ scanId: string }>();
    const [scan, setScan] = useState<Scan | null>(null);
    const [findingsSummary, setFindingsSummary] = useState<FindingListResponse | null>(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);

    const fetchScanData = useCallback(async (showLoading = false) => {
        if (!scanId) return;
        if (showLoading) setLoading(true);
        try {
            const [scanData, findingsData] = await Promise.all([
                api.getScan(scanId),
                api.listFindings(scanId),
            ]);
            setScan(scanData);
            setFindingsSummary(findingsData);
            setError(null);
        } catch (err: any) {
            setError(err.message || "Failed to load scan details");
        } finally {
            if (showLoading) setLoading(false);
        }
    }, [scanId]);

    // Initial load
    useEffect(() => {
        fetchScanData(true);
    }, [fetchScanData]);

    // Polling for active scans
    useEffect(() => {
        if (!scan) return;
        const isRunning =
            scan.status === "pending" || scan.status === "crawling" || scan.status === "scanning";
        if (!isRunning) return;

        const interval = setInterval(() => {
            fetchScanData(false);
        }, 3000);

        return () => clearInterval(interval);
    }, [scan, fetchScanData]);

    const handleDownloadReport = async (format: "json" | "markdown" | "html" | "pdf") => {
        if (!scanId) return;
        setDownloadingFormat(format);
        try {
            const blob = await api.downloadReport(scanId, format);
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `reconix_report_${scanId}.${format === "markdown" ? "md" : format}`;
            a.style.display = "none";
            document.body.appendChild(a);
            a.click();
            setTimeout(() => {
                window.URL.revokeObjectURL(url);
                a.remove();
            }, 100);
        } catch (err: any) {
            alert(err.message || `Failed to download ${format} report`);
        } finally {
            setDownloadingFormat(null);
        }
    };

    if (loading) {
        return (
            <div className="flex min-h-[50vh] flex-col items-center justify-center text-muted">
                <Radar className="h-10 w-10 animate-spin text-accent mb-2" />
                <span className="text-sm">Loading assessment details...</span>
            </div>
        );
    }

    if (error || !scan) {
        return (
            <div className="flex min-h-[50vh] flex-col items-center justify-center text-severity-critical">
                <AlertTriangle className="h-10 w-10 mb-2" />
                <h3 className="text-base font-bold text-text mb-1">Scan Details Error</h3>
                <p className="text-sm text-muted">{error || "Scan not found."}</p>
                <Link to="/" className="btn-secondary mt-6 flex items-center gap-2">
                    <ArrowLeft className="h-4 w-4" /> Back to Dashboard
                </Link>
            </div>
        );
    }

    const severityCounts = {
        critical: findingsSummary?.critical_count ?? 0,
        high: findingsSummary?.high_count ?? 0,
        medium: findingsSummary?.medium_count ?? 0,
        low: findingsSummary?.low_count ?? 0,
        info: findingsSummary?.info_count ?? 0,
    };

    const getDuration = () => {
        if (!scan.started_at) return null;
        const start = new Date(scan.started_at).getTime();
        const end = scan.completed_at ? new Date(scan.completed_at).getTime() : Date.now();
        const diffSec = Math.floor((end - start) / 1000);
        if (diffSec < 60) return `${diffSec}s`;
        const diffMin = Math.floor(diffSec / 60);
        return `${diffMin}m ${diffSec % 60}s`;
    };

    return (
        <div className="space-y-6">
            {/* Navigation and Title */}
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                    <Link to="/" className="btn-secondary p-2.5 rounded" title="Back to Scans">
                        <ArrowLeft className="h-4 w-4" />
                    </Link>
                    <div>
                        <div className="flex items-center gap-2">
                            <h1 className="text-xl font-bold text-text truncate max-w-sm sm:max-w-md">
                                {scan.target_url}
                            </h1>
                        </div>
                        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-muted mt-1">
                            <span className="font-mono">{scan.id}</span>
                            {getDuration() && (
                                <span className="flex items-center gap-1">
                                    <Clock className="h-3.5 w-3.5" /> {getDuration()}
                                </span>
                            )}
                        </div>
                    </div>
                </div>

                <div className="flex flex-wrap items-center gap-2">
                    <Link to={`/scans/${scan.id}/findings`} className="btn-primary">
                        <ShieldAlert className="h-4 w-4" /> View Findings
                    </Link>
                    <Link to={`/scans/${scan.id}/audit`} className="btn-secondary">
                        <History className="h-4 w-4" /> Audit Log
                    </Link>
                </div>
            </div>

            {/* Dashboards */}
            <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
                <ScanProgress scan={scan} />
                <RiskSummary
                    riskScore={scan.risk_score}
                    counts={severityCounts}
                    endpointsDiscovered={scan.endpoints_discovered}
                    pagesCrawled={scan.pages_crawled}
                />
            </div>

            {/* Download Reports Panel */}
            <div className="panel p-6">
                <h2 className="text-sm font-semibold uppercase tracking-wider text-muted mb-4">Export Vulnerability Reports</h2>
                <p className="text-xs text-muted mb-6">
                    Download professional, stakeholder-ready reports detailing the crawl, detected vulnerabilities, CVSS risk classification, and tailored AI remediation instructions.
                </p>

                <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
                    <button
                        onClick={() => handleDownloadReport("pdf")}
                        className="btn-secondary flex flex-col items-center justify-center p-6 gap-2 hover:border-accent group"
                        disabled={downloadingFormat !== null}
                    >
                        <FileText className="h-8 w-8 text-severity-critical group-hover:scale-105 transition" />
                        <span className="text-xs font-semibold">PDF Report</span>
                        {downloadingFormat === "pdf" ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                            <Download className="h-3.5 w-3.5 text-muted group-hover:text-text" />
                        )}
                    </button>

                    <button
                        onClick={() => handleDownloadReport("html")}
                        className="btn-secondary flex flex-col items-center justify-center p-6 gap-2 hover:border-accent group"
                        disabled={downloadingFormat !== null}
                    >
                        <Globe className="h-8 w-8 text-accent group-hover:scale-105 transition" />
                        <span className="text-xs font-semibold">HTML Report</span>
                        {downloadingFormat === "html" ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                            <Download className="h-3.5 w-3.5 text-muted group-hover:text-text" />
                        )}
                    </button>

                    <button
                        onClick={() => handleDownloadReport("markdown")}
                        className="btn-secondary flex flex-col items-center justify-center p-6 gap-2 hover:border-accent group"
                        disabled={downloadingFormat !== null}
                    >
                        <FileText className="h-8 w-8 text-severity-low group-hover:scale-105 transition" />
                        <span className="text-xs font-semibold">Markdown</span>
                        {downloadingFormat === "markdown" ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                            <Download className="h-3.5 w-3.5 text-muted group-hover:text-text" />
                        )}
                    </button>

                    <button
                        onClick={() => handleDownloadReport("json")}
                        className="btn-secondary flex flex-col items-center justify-center p-6 gap-2 hover:border-accent group"
                        disabled={downloadingFormat !== null}
                    >
                        <FileJson className="h-8 w-8 text-severity-info group-hover:scale-105 transition" />
                        <span className="text-xs font-semibold">Raw JSON</span>
                        {downloadingFormat === "json" ? (
                            <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                            <Download className="h-3.5 w-3.5 text-muted group-hover:text-text" />
                        )}
                    </button>
                </div>
            </div>
        </div>
    );
}

function Loader2({ className = "" }: { className?: string }) {
    return <Radar className={`text-accent animate-spin ${className}`} />;
}

import { useEffect, useState, useCallback } from "react";
import { useParams, Link } from "react-router-dom";
import * as api from "@/lib/api";
import type { AuditLogEntry } from "@/types";
import { AuditLogTable } from "@/components/audit/AuditLogTable";
import { ArrowLeft, Radar, AlertTriangle, RefreshCw, ChevronLeft, ChevronRight } from "lucide-react";

const LIMIT_OPTIONS = [50, 100, 200];

export default function AuditTrail() {
    const { scanId } = useParams<{ scanId: string }>();
    const [scanTarget, setScanTarget] = useState<string>("");
    const [entries, setEntries] = useState<AuditLogEntry[]>([]);
    const [total, setTotal] = useState(0);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);

    // Filters & Pagination
    const [selectedModule, setSelectedModule] = useState<string>("");
    const [limit, setLimit] = useState(100);
    const [offset, setOffset] = useState(0);

    const fetchAuditLogs = useCallback(async (showLoading = false) => {
        if (!scanId) return;
        if (showLoading) setLoading(true);
        try {
            const scan = await api.getScan(scanId);
            setScanTarget(scan.target_url);

            const data = await api.listAuditLog(scanId, {
                module: selectedModule || undefined,
                limit,
                offset,
            });
            setEntries(data.entries);
            setTotal(data.total);
            setError(null);
        } catch (err: any) {
            setError(err.message || "Failed to load audit logs");
        } finally {
            if (showLoading) setLoading(false);
        }
    }, [scanId, selectedModule, limit, offset]);

    useEffect(() => {
        fetchAuditLogs(true);
    }, [fetchAuditLogs]);

    const handlePrevPage = () => {
        if (offset - limit >= 0) {
            setOffset(offset - limit);
        }
    };

    const handleNextPage = () => {
        if (offset + limit < total) {
            setOffset(offset + limit);
        }
    };

    // Reset page index on limit/module filter change
    useEffect(() => {
        setOffset(0);
    }, [limit, selectedModule]);

    if (loading && entries.length === 0) {
        return (
            <div className="flex min-h-[50vh] flex-col items-center justify-center text-muted">
                <Radar className="h-10 w-10 animate-spin text-accent mb-2" />
                <span className="text-sm">Loading audit trails...</span>
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex min-h-[50vh] flex-col items-center justify-center text-severity-critical">
                <AlertTriangle className="h-10 w-10 mb-2" />
                <h3 className="text-base font-bold text-text mb-1">Audit Trail Error</h3>
                <p className="text-sm text-muted">{error}</p>
                <button onClick={() => fetchAuditLogs(true)} className="btn-secondary mt-4">
                    Retry
                </button>
            </div>
        );
    }

    const startIdx = offset + 1;
    const endIdx = Math.min(offset + limit, total);

    return (
        <div className="space-y-6">
            {/* Header */}
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div className="flex items-center gap-3">
                    <Link to={`/scans/${scanId}`} className="btn-secondary p-2.5 rounded" title="Back to Scan Details">
                        <ArrowLeft className="h-4 w-4" />
                    </Link>
                    <div>
                        <h1 className="text-xl font-bold text-text">Security Audit Trail</h1>
                        <p className="text-xs text-muted font-mono mt-0.5">{scanTarget}</p>
                    </div>
                </div>

                <div>
                    <button
                        onClick={() => fetchAuditLogs(true)}
                        className="btn-secondary flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wider"
                        disabled={loading}
                    >
                        <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
                        Refresh Logs
                    </button>
                </div>
            </div>

            {/* Filter and Control Bar */}
            <div className="panel p-4 flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                {/* Module selection */}
                <div className="flex items-center gap-3">
                    <span className="text-xs font-semibold text-muted uppercase tracking-wider">Module Filter:</span>
                    <select
                        value={selectedModule}
                        onChange={(e) => setSelectedModule(e.target.value)}
                        className="input-field max-w-[180px] bg-panel border-border text-xs py-1"
                    >
                        <option value="">All Modules</option>
                        <option value="crawler">Crawler</option>
                        <option value="xss">XSS Scanner</option>
                        <option value="sqli">SQLi Scanner</option>
                        <option value="ssrf">SSRF Scanner</option>
                        <option value="rce">RCE Scanner</option>
                        <option value="idor">IDOR Scanner</option>
                        <option value="csrf">CSRF Scanner</option>
                        <option value="headers">Headers Scanner</option>
                        <option value="cookies">Cookies Scanner</option>
                        <option value="cors">CORS Scanner</option>
                        <option value="redirect">Redirect Scanner</option>
                        <option value="upload">Upload Scanner</option>
                        <option value="clickjacking">Clickjacking</option>
                        <option value="access_control">Access Control</option>
                        <option value="directory_traversal">Dir Traversal</option>
                        <option value="info_disclosure">Info Disclosure</option>
                    </select>
                </div>

                {/* Page Size & Stats */}
                <div className="flex flex-wrap items-center gap-4 text-xs font-semibold uppercase tracking-wider text-muted">
                    <div className="flex items-center gap-2">
                        <span>Show:</span>
                        <select
                            value={limit}
                            onChange={(e) => setLimit(Number(e.target.value))}
                            className="input-field bg-panel border-border text-xs py-1 px-2"
                        >
                            {LIMIT_OPTIONS.map((opt) => (
                                <option key={opt} value={opt}>
                                    {opt} rows
                                </option>
                            ))}
                        </select>
                    </div>

                    <div className="font-mono lowercase text-[11px]">
                        {total > 0 ? `${startIdx}-${endIdx} of ${total} entries` : "0 entries"}
                    </div>
                </div>
            </div>

            {/* Audit Log Table */}
            {loading ? (
                <div className="flex flex-col items-center justify-center p-12 text-muted">
                    <Radar className="h-8 w-8 animate-spin text-accent mb-2" />
                    <span className="text-sm">Refreshing log rows...</span>
                </div>
            ) : (
                <div className="space-y-4">
                    <AuditLogTable entries={entries} />

                    {/* Pagination buttons */}
                    {total > limit && (
                        <div className="flex items-center justify-end gap-2">
                            <button
                                onClick={handlePrevPage}
                                disabled={offset === 0}
                                className="btn-secondary px-3 py-1.5 flex items-center gap-1 text-xs"
                            >
                                <ChevronLeft className="h-4 w-4" /> Previous
                            </button>
                            <button
                                onClick={handleNextPage}
                                disabled={offset + limit >= total}
                                className="btn-secondary px-3 py-1.5 flex items-center gap-1 text-xs"
                            >
                                Next <ChevronRight className="h-4 w-4" />
                            </button>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
}

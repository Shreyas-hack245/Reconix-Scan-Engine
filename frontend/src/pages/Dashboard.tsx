import { useEffect, useState, useCallback } from "react";
import { Link } from "react-router-dom";
import * as api from "@/lib/api";
import type { ScanSummary, ScanCreatePayload } from "@/types";
import { NewScanForm } from "@/components/scans/NewScanForm";
import { Radar, Trash2, Shield, Eye, Calendar, AlertTriangle } from "lucide-react";

export default function Dashboard() {
    const [scans, setScans] = useState<ScanSummary[]>([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState<string | null>(null);
    const [isSubmitting, setIsSubmitting] = useState(false);

    const fetchScans = useCallback(async (showLoading = false) => {
        if (showLoading) setLoading(true);
        try {
            const data = await api.listScans();
            setScans(data.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()));
            setError(null);
        } catch (err: any) {
            setError(err.message || "Failed to load scans");
        } finally {
            if (showLoading) setLoading(false);
        }
    }, []);

    // Initial load
    useEffect(() => {
        fetchScans(true);
    }, [fetchScans]);

    // Polling for active scans (every 5 seconds if there are running scans)
    useEffect(() => {
        const hasActiveScans = scans.some(
            (s) => s.status === "pending" || s.status === "crawling" || s.status === "scanning"
        );
        if (!hasActiveScans) return;

        const interval = setInterval(() => {
            fetchScans(false);
        }, 5000);

        return () => clearInterval(interval);
    }, [scans, fetchScans]);

    const handleCreateScan = async (payload: ScanCreatePayload) => {
        setIsSubmitting(true);
        try {
            await api.createScan(payload);
            await fetchScans(false);
        } catch (err: any) {
            throw new Error(err.message || "Failed to launch scan");
        } finally {
            setIsSubmitting(false);
        }
    };

    const handleDeleteScan = async (id: string, e: React.MouseEvent) => {
        e.preventDefault();
        if (!confirm("Are you sure you want to delete this scan and all its findings?")) return;
        try {
            await api.deleteScan(id);
            setScans((prev) => prev.filter((s) => s.id !== id));
        } catch (err: any) {
            alert(err.message || "Failed to delete scan");
        }
    };

    const getStatusStyle = (status: string) => {
        switch (status) {
            case "completed":
                return "border-emerald-500/25 bg-emerald-500/10 text-emerald-400";
            case "failed":
                return "border-severity-critical/25 bg-severity-critical/10 text-severity-critical";
            case "cancelled":
                return "border-muted/25 bg-muted/10 text-muted";
            case "pending":
                return "border-severity-low/25 bg-severity-low/10 text-severity-low animate-pulse-soft";
            case "crawling":
            case "scanning":
                return "border-accent/25 bg-accent/10 text-accent animate-pulse-soft";
            default:
                return "border-border bg-panel2 text-text";
        }
    };

    const getRiskScoreColor = (score: number) => {
        if (score >= 75) return "text-severity-critical";
        if (score >= 50) return "text-severity-high";
        if (score >= 25) return "text-severity-medium";
        if (score > 0) return "text-severity-low";
        return "text-muted";
    };

    return (
        <div className="space-y-8">
            {/* Header */}
            <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
                <div>
                    <h1 className="text-2xl font-bold tracking-tight text-text">Security Scan Center</h1>
                    <p className="text-sm text-muted mt-1">Configure, launch, and monitor automated vulnerability assessments.</p>
                </div>
            </div>

            {/* Launch Form */}
            <NewScanForm onSubmit={handleCreateScan} isSubmitting={isSubmitting} />

            {/* Scans List */}
            <div className="panel overflow-hidden">
                <div className="border-b border-border bg-panel2 px-6 py-4 flex items-center justify-between">
                    <h2 className="text-sm font-semibold uppercase tracking-wider text-muted">Scan History</h2>
                    <span className="text-xs text-muted font-mono">{scans.length} Scan{scans.length !== 1 ? "s" : ""}</span>
                </div>

                {loading ? (
                    <div className="flex flex-col items-center justify-center p-12 text-muted">
                        <Radar className="h-8 w-8 animate-spin text-accent mb-2" />
                        <span className="text-sm">Loading security scans...</span>
                    </div>
                ) : error ? (
                    <div className="flex flex-col items-center justify-center p-12 text-severity-critical">
                        <AlertTriangle className="h-8 w-8 mb-2" />
                        <span className="text-sm font-medium">{error}</span>
                        <button onClick={() => fetchScans(true)} className="btn-secondary mt-4 text-xs">
                            Try Again
                        </button>
                    </div>
                ) : scans.length === 0 ? (
                    <div className="p-12 text-center text-muted">
                        <Shield className="mx-auto h-12 w-12 text-border mb-3" />
                        <h3 className="text-sm font-semibold text-text mb-1">No Scans Found</h3>
                        <p className="text-xs">Submit a target URL above to start your first vulnerability assessment.</p>
                    </div>
                ) : (
                    <div className="overflow-x-auto">
                        <table className="w-full border-collapse text-left text-sm">
                            <thead>
                                <tr className="border-b border-border bg-panel2/50 text-xs font-semibold uppercase tracking-wider text-muted">
                                    <th className="px-6 py-3">Target Address</th>
                                    <th className="px-6 py-3">Status</th>
                                    <th className="px-6 py-3">Findings</th>
                                    <th className="px-6 py-3">Risk Score</th>
                                    <th className="px-6 py-3">Created</th>
                                    <th className="px-6 py-3 text-right">Actions</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-border">
                                {scans.map((scan) => (
                                    <tr key={scan.id} className="hover:bg-panel2/30 transition">
                                        <td className="px-6 py-4 font-medium max-w-xs sm:max-w-md truncate">
                                            <Link
                                                to={`/scans/${scan.id}`}
                                                className="text-text hover:text-accent font-semibold transition"
                                            >
                                                {scan.target_url}
                                            </Link>
                                            <div className="text-[10px] text-muted font-mono mt-0.5 truncate">{scan.id}</div>
                                        </td>
                                        <td className="px-6 py-4">
                                            <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-bold uppercase tracking-wider ${getStatusStyle(scan.status)}`}>
                                                {scan.status}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 font-mono text-text">
                                            {scan.findings_count}
                                        </td>
                                        <td className="px-6 py-4 font-mono font-bold">
                                            <span className={getRiskScoreColor(scan.risk_score)}>
                                                {scan.risk_score.toFixed(0)}
                                            </span>
                                        </td>
                                        <td className="px-6 py-4 text-xs text-muted">
                                            <div className="flex items-center gap-1.5">
                                                <Calendar className="h-3.5 w-3.5" />
                                                <span>
                                                    {new Date(scan.created_at).toLocaleDateString()} {new Date(scan.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                                                </span>
                                            </div>
                                        </td>
                                        <td className="px-6 py-4 text-right">
                                            <div className="flex items-center justify-end gap-2">
                                                <Link
                                                    to={`/scans/${scan.id}`}
                                                    className="rounded p-1.5 text-muted hover:bg-panel2 hover:text-text transition"
                                                    title="View Scan Details"
                                                >
                                                    <Eye className="h-4 w-4" />
                                                </Link>
                                                <button
                                                    onClick={(e) => handleDeleteScan(scan.id, e)}
                                                    className="rounded p-1.5 text-muted hover:bg-panel2 hover:text-severity-critical transition"
                                                    title="Delete Scan"
                                                >
                                                    <Trash2 className="h-4 w-4" />
                                                </button>
                                            </div>
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </div>
    );
}

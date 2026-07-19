// Tabular audit trail viewer: every request Reconix Scan Engine made
// during a scan, with timestamp, module, method, URL, status, duration.

import type { AuditLogEntry } from "@/types";

function statusColor(code: number | null): string {
    if (code === null) return "text-muted";
    if (code >= 500) return "text-severity-critical";
    if (code >= 400) return "text-severity-high";
    if (code >= 300) return "text-severity-medium";
    return "text-emerald-400";
}

export function AuditLogTable({ entries }: { entries: AuditLogEntry[] }) {
    if (entries.length === 0) {
        return (
            <div className="panel flex flex-col items-center justify-center gap-2 p-12 text-center">
                <p className="text-sm text-muted">No audit log entries yet.</p>
            </div>
        );
    }

    return (
        <div className="panel overflow-hidden">
            <div className="max-h-[70vh] overflow-auto">
                <table className="w-full text-left text-xs">
                    <thead className="sticky top-0 bg-panel2 text-muted">
                        <tr>
                            <th className="px-3 py-2 font-semibold uppercase tracking-wide">Timestamp</th>
                            <th className="px-3 py-2 font-semibold uppercase tracking-wide">Module</th>
                            <th className="px-3 py-2 font-semibold uppercase tracking-wide">Method</th>
                            <th className="px-3 py-2 font-semibold uppercase tracking-wide">URL</th>
                            <th className="px-3 py-2 font-semibold uppercase tracking-wide">Status</th>
                            <th className="px-3 py-2 text-right font-semibold uppercase tracking-wide">Duration</th>
                        </tr>
                    </thead>
                    <tbody>
                        {entries.map((entry) => (
                            <tr key={entry.id} className="border-t border-border hover:bg-panel2/50">
                                <td className="whitespace-nowrap px-3 py-2 font-mono text-muted">
                                    {new Date(entry.timestamp).toLocaleTimeString()}
                                </td>
                                <td className="px-3 py-2">
                                    <span className="rounded bg-panel2 px-1.5 py-0.5 font-mono text-accent">{entry.module}</span>
                                </td>
                                <td className="px-3 py-2 font-mono text-text">{entry.method}</td>
                                <td className="max-w-[420px] truncate px-3 py-2 font-mono text-text/80" title={entry.url}>
                                    {entry.url}
                                </td>
                                <td className={`px-3 py-2 font-mono font-semibold ${statusColor(entry.response_code)}`}>
                                    {entry.response_code ?? "-"}
                                </td>
                                <td className="px-3 py-2 text-right font-mono text-muted">{entry.duration_ms.toFixed(0)}ms</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
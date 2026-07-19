// Form for launching a new scan against a target URL, with collapsible
// advanced options (depth/page/rate limits) defaulted to safe values.

import { useState } from "react";
import { ChevronDown, ChevronUp, Radar } from "lucide-react";
import type { ScanCreatePayload } from "@/types";

interface NewScanFormProps {
    onSubmit: (payload: ScanCreatePayload) => Promise<void>;
    isSubmitting: boolean;
}

export function NewScanForm({ onSubmit, isSubmitting }: NewScanFormProps) {
    const [targetUrl, setTargetUrl] = useState("");
    const [showAdvanced, setShowAdvanced] = useState(false);
    const [maxDepth, setMaxDepth] = useState(3);
    const [maxPages, setMaxPages] = useState(200);
    const [requestsPerSecond, setRequestsPerSecond] = useState(5);
    const [maxConcurrent, setMaxConcurrent] = useState(5);
    const [respectRobots, setRespectRobots] = useState(true);
    const [error, setError] = useState<string | null>(null);

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);

        if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
            setError("Target URL must start with http:// or https://");
            return;
        }

        try {
            await onSubmit({
                target_url: targetUrl,
                max_depth: maxDepth,
                max_pages: maxPages,
                requests_per_second: requestsPerSecond,
                max_concurrent_requests: maxConcurrent,
                respect_robots: respectRobots,
            });
            setTargetUrl("");
        } catch (err) {
            setError(err instanceof Error ? err.message : "Failed to start scan");
        }
    };

    return (
        <form onSubmit={handleSubmit} className="panel p-6">
            <div className="mb-4 flex items-center gap-2">
                <Radar className="h-5 w-5 text-accent" />
                <h2 className="text-sm font-semibold uppercase tracking-wider text-muted">Launch New Scan</h2>
            </div>

            <div className="flex flex-col gap-3 sm:flex-row">
                <input
                    type="text"
                    required
                    placeholder="https://example.com"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    className="input-field flex-1"
                />
                <button type="submit" disabled={isSubmitting} className="btn-primary whitespace-nowrap">
                    {isSubmitting ? "Starting Scan..." : "Start Scan"}
                </button>
            </div>

            {error && <p className="mt-2 text-xs text-severity-critical">{error}</p>}

            <button
                type="button"
                onClick={() => setShowAdvanced((v) => !v)}
                className="mt-4 flex items-center gap-1 text-xs font-medium text-muted hover:text-text"
            >
                {showAdvanced ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
                Advanced options
            </button>

            {showAdvanced && (
                <div className="mt-3 grid grid-cols-2 gap-4 border-t border-border pt-4 sm:grid-cols-4">
                    <label className="flex flex-col gap-1 text-xs text-muted">
                        Max Crawl Depth
                        <input
                            type="number"
                            min={0}
                            max={10}
                            value={maxDepth}
                            onChange={(e) => setMaxDepth(Number(e.target.value))}
                            className="input-field"
                        />
                    </label>
                    <label className="flex flex-col gap-1 text-xs text-muted">
                        Max Pages
                        <input
                            type="number"
                            min={1}
                            max={2000}
                            value={maxPages}
                            onChange={(e) => setMaxPages(Number(e.target.value))}
                            className="input-field"
                        />
                    </label>
                    <label className="flex flex-col gap-1 text-xs text-muted">
                        Requests / Second
                        <input
                            type="number"
                            min={0.5}
                            max={50}
                            step={0.5}
                            value={requestsPerSecond}
                            onChange={(e) => setRequestsPerSecond(Number(e.target.value))}
                            className="input-field"
                        />
                    </label>
                    <label className="flex flex-col gap-1 text-xs text-muted">
                        Max Concurrent
                        <input
                            type="number"
                            min={1}
                            max={50}
                            value={maxConcurrent}
                            onChange={(e) => setMaxConcurrent(Number(e.target.value))}
                            className="input-field"
                        />
                    </label>
                    <label className="col-span-2 flex items-center gap-2 text-xs text-muted sm:col-span-4">
                        <input
                            type="checkbox"
                            checked={respectRobots}
                            onChange={(e) => setRespectRobots(e.target.checked)}
                            className="h-4 w-4 rounded border-border bg-bg accent-amber-500"
                        />
                        Respect robots.txt disallow rules
                    </label>
                </div>
            )}
        </form>
    );
}
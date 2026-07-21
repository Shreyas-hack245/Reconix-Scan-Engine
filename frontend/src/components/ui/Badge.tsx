import React from "react";
import { type Severity, SEVERITY_LABELS } from "@/types";

interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
    children: React.ReactNode;
    className?: string;
}

export function Badge({ children, className = "", ...props }: BadgeProps) {
    return (
        <span
            className={`inline-flex items-center rounded border border-border bg-panel2 px-2 py-0.5 text-xs font-semibold text-text transition-colors ${className}`}
            {...props}
        >
            {children}
        </span>
    );
}

const SEVERITY_CLASSES: Record<Severity, string> = {
    critical: "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
    high: "bg-severity-high/15 text-severity-high border-severity-high/30",
    medium: "bg-severity-medium/15 text-severity-medium border-severity-medium/30",
    low: "bg-severity-low/15 text-severity-low border-severity-low/30",
    info: "bg-severity-info/15 text-severity-info border-severity-info/30",
};

interface SeverityBadgeProps {
    severity: Severity;
    className?: string;
}

export function SeverityBadge({ severity, className = "" }: SeverityBadgeProps) {
    const badgeClass = SEVERITY_CLASSES[severity] || SEVERITY_CLASSES.info;
    return (
        <span
            className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-extrabold uppercase tracking-wider ${badgeClass} ${className}`}
        >
            {SEVERITY_LABELS[severity] || severity}
        </span>
    );
}

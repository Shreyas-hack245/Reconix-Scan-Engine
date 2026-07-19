// Shared TypeScript types for the Reconix Scan Engine dashboard.
// These mirror the backend's Pydantic schemas (app/schemas/*.py) so the
// frontend and API stay in sync.

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type VulnerabilityType =
    | "xss"
    | "sqli"
    | "ssrf"
    | "rce"
    | "command_injection"
    | "auth_issue"
    | "broken_access_control"
    | "idor"
    | "open_redirect"
    | "csrf"
    | "info_disclosure"
    | "directory_traversal"
    | "security_headers"
    | "cookie_security"
    | "file_upload"
    | "clickjacking"
    | "cors_misconfiguration";

export type ScanStatus =
    | "pending"
    | "crawling"
    | "scanning"
    | "completed"
    | "failed"
    | "cancelled";

export type UserRole = "admin" | "analyst" | "viewer";

export interface User {
    id: string;
    email: string;
    full_name: string;
    role: UserRole;
    is_active: boolean;
    created_at: string;
}

export interface AuthToken {
    access_token: string;
    token_type: string;
    expires_in_minutes: number;
}

export interface ScanCreatePayload {
    target_url: string;
    max_depth: number;
    max_pages: number;
    requests_per_second: number;
    max_concurrent_requests: number;
    respect_robots: boolean;
}

export interface ScanSummary {
    id: string;
    target_url: string;
    status: ScanStatus;
    findings_count: number;
    risk_score: number;
    created_at: string;
    completed_at: string | null;
}

export interface Scan {
    id: string;
    owner_id: string;
    target_url: string;
    status: ScanStatus;
    max_depth: number;
    max_pages: number;
    pages_crawled: number;
    endpoints_discovered: number;
    findings_count: number;
    risk_score: number;
    error_message: string | null;
    created_at: string;
    started_at: string | null;
    completed_at: string | null;
}

export interface SafePoc {
    example_request: string;
    example_response: string;
    expected_safe_output: string;
    impact: string;
    verification_steps: string[];
}

export interface Finding {
    id: string;
    scan_id: string;
    vulnerability_type: VulnerabilityType;
    severity: Severity;
    title: string;
    url: string;
    method: string;
    parameter: string | null;
    evidence: string;
    confidence: number;
    is_false_positive: boolean;
    cvss_score: number | null;
    owasp_category: string | null;
    risk_explanation: string | null;
    business_impact: string | null;
    developer_explanation: string | null;
    remediation: string | null;
    safe_poc: SafePoc | null;
    created_at: string;
}

export interface FindingListResponse {
    total: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
    info_count: number;
    findings: Finding[];
}

export interface AuditLogEntry {
    id: string;
    scan_id: string;
    timestamp: string;
    url: string;
    method: string;
    module: string;
    response_code: number | null;
    finding_id: string | null;
    duration_ms: number;
    notes: string | null;
}

export interface AuditLogPage {
    total: number;
    entries: AuditLogEntry[];
}

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABELS: Record<Severity, string> = {
    critical: "Critical",
    high: "High",
    medium: "Medium",
    low: "Low",
    info: "Info",
};
// Typed API client for the Reconix Scan Engine backend.
// All requests go through `/api`, which Vite proxies to the FastAPI
// backend in development (see vite.config.ts).

import type {
    AuditLogPage,
    AuthToken,
    Finding,
    FindingListResponse,
    Scan,
    ScanCreatePayload,
    ScanSummary,
    User,
} from "@/types";

const API_BASE = "/api";
const TOKEN_STORAGE_KEY = "reconix_access_token";

export function getStoredToken(): string | null {
    return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setStoredToken(token: string | null): void {
    if (token) {
        localStorage.setItem(TOKEN_STORAGE_KEY, token);
    } else {
        localStorage.removeItem(TOKEN_STORAGE_KEY);
    }
}

export class ApiError extends Error {
    status: number;
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
        this.name = "ApiError";
    }
}

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const token = getStoredToken();
    const headers = new Headers(options.headers);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    if (options.body && !(options.body instanceof FormData) && !headers.has("Content-Type")) {
        headers.set("Content-Type", "application/json");
    }

    const response = await fetch(`${API_BASE}${path}`, { ...options, headers });

    if (!response.ok) {
        let detail = response.statusText;
        try {
            const body = await response.json();
            detail = body.detail ?? detail;
        } catch {
            // response body was not JSON; fall back to statusText
        }
        throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
    }

    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
}

// --- Auth ---

export async function login(email: string, password: string): Promise<AuthToken> {
    const form = new URLSearchParams();
    form.set("username", email);
    form.set("password", password);

    const response = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: form.toString(),
    });

    if (!response.ok) {
        const body = await response.json().catch(() => ({ detail: response.statusText }));
        throw new ApiError(response.status, body.detail ?? "Login failed");
    }

    return (await response.json()) as AuthToken;
}

export async function register(
    email: string,
    password: string,
    fullName: string
): Promise<User> {
    return request<User>("/auth/register", {
        method: "POST",
        body: JSON.stringify({ email, password, full_name: fullName }),
    });
}

export async function getCurrentUser(): Promise<User> {
    return request<User>("/auth/me");
}

// --- Scans ---

export async function listScans(): Promise<ScanSummary[]> {
    return request<ScanSummary[]>("/scans/");
}

export async function createScan(payload: ScanCreatePayload): Promise<Scan> {
    return request<Scan>("/scans/", {
        method: "POST",
        body: JSON.stringify(payload),
    });
}

export async function getScan(scanId: string): Promise<Scan> {
    return request<Scan>(`/scans/${scanId}`);
}

export async function deleteScan(scanId: string): Promise<void> {
    return request<void>(`/scans/${scanId}`, { method: "DELETE" });
}

// --- Findings ---

export async function listFindings(
    scanId: string,
    opts: { severity?: string; includeFalsePositives?: boolean } = {}
): Promise<FindingListResponse> {
    const params = new URLSearchParams();
    if (opts.severity) params.set("severity", opts.severity);
    if (opts.includeFalsePositives === false) params.set("include_false_positives", "false");
    const qs = params.toString();
    return request<FindingListResponse>(`/findings/${scanId}${qs ? `?${qs}` : ""}`);
}

export async function getFinding(findingId: string): Promise<Finding> {
    return request<Finding>(`/findings/detail/${findingId}`);
}

// --- Audit ---

export async function listAuditLog(
    scanId: string,
    opts: { module?: string; limit?: number; offset?: number } = {}
): Promise<AuditLogPage> {
    const params = new URLSearchParams();
    if (opts.module) params.set("module", opts.module);
    if (opts.limit) params.set("limit", String(opts.limit));
    if (opts.offset) params.set("offset", String(opts.offset));
    const qs = params.toString();
    return request<AuditLogPage>(`/audit/${scanId}${qs ? `?${qs}` : ""}`);
}

// --- Reports ---

export function reportDownloadUrl(scanId: string, format: "json" | "markdown" | "html" | "pdf"): string {
    return `${API_BASE}/reports/${scanId}/${format}`;
}

export async function downloadReport(scanId: string, format: "json" | "markdown" | "html" | "pdf"): Promise<Blob> {
    const token = getStoredToken();
    const headers = new Headers();
    if (token) headers.set("Authorization", `Bearer ${token}`);

    const response = await fetch(reportDownloadUrl(scanId, format), { headers });
    if (!response.ok) {
        throw new ApiError(response.status, `Failed to download ${format} report`);
    }
    return response.blob();
}
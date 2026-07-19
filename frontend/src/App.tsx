// Root application shell for the Reconix Scan Engine dashboard: auth
// provider, top navigation, and route table.

import { NavLink, Navigate, Route, Routes } from "react-router-dom";
import { LogOut, Radar, ShieldAlert } from "lucide-react";
import { AuthProvider, useAuth } from "@/hooks/useAuth";
import Dashboard from "@/pages/Dashboard";
import ScanDetail from "@/pages/ScanDetail";
import Findings from "@/pages/Findings";
import AuditTrail from "@/pages/AuditTrail";
import Login from "@/pages/Login";

function ProtectedRoute({ children }: { children: React.ReactNode }) {
    const { isAuthenticated, isLoading } = useAuth();

    if (isLoading) {
        return (
            <div className="flex h-screen items-center justify-center text-muted">
                <Radar className="h-6 w-6 animate-spin text-accent" />
            </div>
        );
    }

    if (!isAuthenticated) return <Navigate to="/login" replace />;
    return <>{children}</>;
}

function TopNav() {
    const { user, logout } = useAuth();

    const linkClass = ({ isActive }: { isActive: boolean }) =>
        `flex items-center gap-1.5 rounded px-3 py-1.5 text-sm font-medium transition ${isActive ? "bg-panel2 text-accent" : "text-muted hover:text-text"
        }`;

    return (
        <header className="sticky top-0 z-10 border-b border-border bg-bg/95 backdrop-blur">
            <div className="mx-auto flex max-w-6xl items-center justify-between px-6 py-3">
                <div className="flex items-center gap-2">
                    <Radar className="h-5 w-5 text-accent" />
                    <span className="font-mono text-sm font-bold tracking-tight text-text">RECONIX</span>
                    <span className="hidden text-xs text-muted sm:inline">Scan Engine</span>
                </div>

                <nav className="flex items-center gap-1">
                    <NavLink to="/" end className={linkClass}>
                        <ShieldAlert className="h-4 w-4" /> Scans
                    </NavLink>
                </nav>

                {user && (
                    <div className="flex items-center gap-3">
                        <div className="text-right">
                            <div className="text-xs font-medium text-text">{user.full_name || user.email}</div>
                            <div className="text-[10px] uppercase tracking-wide text-muted">{user.role}</div>
                        </div>
                        <button
                            onClick={logout}
                            className="rounded p-2 text-muted hover:bg-panel2 hover:text-severity-critical"
                            title="Log out"
                        >
                            <LogOut className="h-4 w-4" />
                        </button>
                    </div>
                )}
            </div>
        </header>
    );
}

function AppShell() {
    const { isAuthenticated } = useAuth();

    return (
        <div className="min-h-screen bg-bg">
            {isAuthenticated && <TopNav />}
            <main className="mx-auto max-w-6xl px-6 py-8">
                <Routes>
                    <Route path="/login" element={<Login />} />
                    <Route
                        path="/"
                        element={
                            <ProtectedRoute>
                                <Dashboard />
                            </ProtectedRoute>
                        }
                    />
                    <Route
                        path="/scans/:scanId"
                        element={
                            <ProtectedRoute>
                                <ScanDetail />
                            </ProtectedRoute>
                        }
                    />
                    <Route
                        path="/scans/:scanId/findings"
                        element={
                            <ProtectedRoute>
                                <Findings />
                            </ProtectedRoute>
                        }
                    />
                    <Route
                        path="/scans/:scanId/audit"
                        element={
                            <ProtectedRoute>
                                <AuditTrail />
                            </ProtectedRoute>
                        }
                    />
                    <Route path="*" element={<Navigate to="/" replace />} />
                </Routes>
            </main>
        </div>
    );
}

export default function App() {
    return (
        <AuthProvider>
            <AppShell />
        </AuthProvider>
    );
}
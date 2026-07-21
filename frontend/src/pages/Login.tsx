import { useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { Radar, AlertCircle } from "lucide-react";

export default function Login() {
    const { isAuthenticated, login, register } = useAuth();
    const [isRegister, setIsRegister] = useState(false);
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [fullName, setFullName] = useState("");
    const [error, setError] = useState<string | null>(null);
    const [loading, setLoading] = useState(false);

    if (isAuthenticated) {
        return <Navigate to="/" replace />;
    }

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError(null);
        setLoading(true);
        try {
            if (isRegister) {
                if (!fullName.trim()) {
                    throw new Error("Full name is required");
                }
                await register(email, password, fullName);
            } else {
                await login(email, password);
            }
        } catch (err: any) {
            setError(err.message || "Authentication failed");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="flex min-h-[80vh] items-center justify-center px-4">
            <div className="w-full max-w-md">
                <div className="mb-8 text-center">
                    <div className="inline-flex h-12 w-12 items-center justify-center rounded-lg bg-panel2 border border-border mb-4">
                        <Radar className="h-6 w-6 text-accent animate-pulse-soft" />
                    </div>
                    <h1 className="font-mono text-2xl font-bold tracking-wider text-text">RECONIX</h1>
                    <p className="text-xs text-muted uppercase tracking-widest mt-1">AI-Powered Vulnerability Scanner</p>
                </div>

                <div className="panel p-6 sm:p-8">
                    <h2 className="text-lg font-bold text-text mb-6">
                        {isRegister ? "Create Analyst Account" : "Log In to Dashboard"}
                    </h2>

                    {error && (
                        <div className="mb-4 flex items-center gap-2 rounded border border-severity-critical/30 bg-severity-critical/15 p-3 text-sm text-severity-critical">
                            <AlertCircle className="h-4 w-4 shrink-0" />
                            <span>{error}</span>
                        </div>
                    )}

                    <form onSubmit={handleSubmit} className="space-y-4">
                        {isRegister && (
                            <div>
                                <label className="block text-xs font-semibold text-muted uppercase tracking-wider mb-1">
                                    Full Name
                                </label>
                                <input
                                    type="text"
                                    required
                                    value={fullName}
                                    onChange={(e) => setFullName(e.target.value)}
                                    placeholder="Jane Doe"
                                    className="input-field"
                                    disabled={loading}
                                />
                            </div>
                        )}

                        <div>
                            <label className="block text-xs font-semibold text-muted uppercase tracking-wider mb-1">
                                Email Address
                            </label>
                            <input
                                type="email"
                                required
                                value={email}
                                onChange={(e) => setEmail(e.target.value)}
                                placeholder="analyst@reconix.local"
                                className="input-field"
                                disabled={loading}
                            />
                        </div>

                        <div>
                            <label className="block text-xs font-semibold text-muted uppercase tracking-wider mb-1">
                                Password
                            </label>
                            <input
                                type="password"
                                required
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                placeholder="••••••••"
                                className="input-field"
                                disabled={loading}
                            />
                        </div>

                        <button type="submit" className="btn-primary w-full mt-2" disabled={loading}>
                            {loading ? (
                                <span className="flex items-center gap-2">
                                    <Radar className="h-4 w-4 animate-spin" />
                                    Authenticating...
                                </span>
                            ) : (
                                <span>{isRegister ? "Register" : "Sign In"}</span>
                            )}
                        </button>
                    </form>

                    <div className="mt-6 text-center border-t border-border pt-4">
                        <button
                            onClick={() => {
                                setIsRegister(!isRegister);
                                setError(null);
                            }}
                            className="text-xs text-muted hover:text-accent font-medium transition"
                            type="button"
                            disabled={loading}
                        >
                            {isRegister
                                ? "Already have an account? Sign in here"
                                : "Don't have an account? Register here"}
                        </button>
                    </div>
                </div>
            </div>
        </div>
    );
}

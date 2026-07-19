// Authentication context/hook for the Reconix Scan Engine dashboard.
// Wraps the API client's token storage in a React context so any
// component can read the current user or trigger login/logout.

import React, { createContext, useCallback, useContext, useEffect, useState } from "react";
import * as api from "@/lib/api";
import type { User } from "@/types";

interface AuthContextValue {
  user: User | null;
  isLoading: boolean;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  register: (email: string, password: string, fullName: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const loadCurrentUser = useCallback(async () => {
    if (!api.getStoredToken()) {
      setUser(null);
      setIsLoading(false);
      return;
    }
    try {
      const currentUser = await api.getCurrentUser();
      setUser(currentUser);
    } catch {
      api.setStoredToken(null);
      setUser(null);
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadCurrentUser();
  }, [loadCurrentUser]);

  const login = useCallback(async (email: string, password: string) => {
    const token = await api.login(email, password);
    api.setStoredToken(token.access_token);
    const currentUser = await api.getCurrentUser();
    setUser(currentUser);
  }, []);

  const register = useCallback(async (email: string, password: string, fullName: string) => {
    await api.register(email, password, fullName);
    await login(email, password);
  }, [login]);

  const logout = useCallback(() => {
    api.setStoredToken(null);
    setUser(null);
  }, []);

  return (
    <AuthContext.Provider value={{ user, isLoading, isAuthenticated: !!user, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within an AuthProvider");
  return ctx;
}
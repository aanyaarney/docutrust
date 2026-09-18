import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';
import { authApi, tokenStorage } from '../api/client';
import type { LoginResponse } from '../api/types';

const PROFILE_STORAGE_KEY = 'docutrust.profile';

interface AuthState {
  user: LoginResponse | null;
  isAuthenticated: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthState | undefined>(undefined);

function readStoredProfile(): LoginResponse | null {
  try {
    const raw = localStorage.getItem(PROFILE_STORAGE_KEY);
    if (!raw || !tokenStorage.get()) {
      return null;
    }
    return JSON.parse(raw) as LoginResponse;
  } catch {
    // Corrupted or unavailable storage: treat as signed out rather than crash.
    return null;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<LoginResponse | null>(readStoredProfile);

  const login = useCallback(async (email: string, password: string) => {
    const response = await authApi.login(email, password);
    tokenStorage.set(response.token);
    try {
      localStorage.setItem(PROFILE_STORAGE_KEY, JSON.stringify(response));
    } catch {
      // Non-fatal; the session continues in memory.
    }
    setUser(response);
  }, []);

  const logout = useCallback(() => {
    tokenStorage.clear();
    try {
      localStorage.removeItem(PROFILE_STORAGE_KEY);
    } catch {
      // Nothing useful to do.
    }
    setUser(null);
  }, []);

  const value = useMemo<AuthState>(
    () => ({ user, isAuthenticated: user !== null, login, logout }),
    [user, login, logout],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthState {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}

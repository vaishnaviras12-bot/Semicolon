import React, { createContext, useContext, useState, useEffect } from 'react';
import { loginApi, registerApi, getMeApi } from '../api';

const AuthContext = createContext(null);
const USER_KEY = 'semicolon_user';
const TOKEN_KEY = 'ecdat_token';

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const raw = localStorage.getItem(USER_KEY);
      return raw ? JSON.parse(raw) : null;
    } catch {
      return null;
    }
  });

  const [loading, setLoading] = useState(true);

  // Validate existing session token on mount
  useEffect(() => {
    let isMounted = true;
    async function initAuth() {
      const token = localStorage.getItem(TOKEN_KEY);
      if (!token) {
        if (isMounted) setLoading(false);
        return;
      }
      try {
        const me = await getMeApi();
        if (isMounted && me) {
          setUser(me);
          localStorage.setItem(USER_KEY, JSON.stringify(me));
        }
      } catch (err) {
        console.warn('Session token expired or invalid:', err);
        if (isMounted) {
          localStorage.removeItem(TOKEN_KEY);
          localStorage.removeItem(USER_KEY);
          setUser(null);
        }
      } finally {
        if (isMounted) setLoading(false);
      }
    }

    initAuth();
    return () => { isMounted = false; };
  }, []);

  const login = async (email, password) => {
    const data = await loginApi(email, password);
    if (data.access_token && data.user) {
      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      setUser(data.user);
      return data.user;
    }
    throw new Error('Authentication failed');
  };

  const register = async (name, email, password) => {
    const data = await registerApi(name, email, password);
    if (data.access_token && data.user) {
      localStorage.setItem(TOKEN_KEY, data.access_token);
      localStorage.setItem(USER_KEY, JSON.stringify(data.user));
      setUser(data.user);
      return data.user;
    }
    throw new Error('Registration failed');
  };

  const logout = () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, loading, login, register, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider');
  return ctx;
}

export function nameFromEmail(email) {
  if (!email) return 'User';
  const local = email.split('@')[0] || 'there';
  const first = local.split(/[.\-_0-9]+/).filter(Boolean)[0] || local;
  return first.charAt(0).toUpperCase() + first.slice(1);
}

export function initials(name) {
  if (!name) return 'US';
  const parts = name.trim().split(/\s+/);
  if (parts.length === 1) return parts[0].slice(0, 2).toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

import React from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { useScan } from '../context/ScanContext.jsx';
import { Loader2 } from 'lucide-react';

export default function ProtectedRoute({ children }) {
  const { user, loading: authLoading } = useAuth();
  const { scanLoading } = useScan();
  const location = useLocation();

  if (authLoading || scanLoading) {
    return (
      <div
        style={{
          position: 'fixed',
          inset: 0,
          zIndex: 9999,
          background: '#0a0d12',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 16,
          color: '#e8eaef',
          fontFamily: "'Switzer', system-ui, sans-serif"
        }}
      >
        <Loader2 size={36} className="animate-spin" style={{ color: '#c9a227' }} />
        <span style={{ fontSize: 13.5, letterSpacing: '0.06em', color: '#8a93a3' }}>
          Hydrating cryptographic workspace...
        </span>
      </div>
    );
  }

  if (!user) {
    return <Navigate to="/login" replace state={{ from: location.pathname + location.hash }} />;
  }
  return children;
}

import React from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, Upload, LogIn } from 'lucide-react';
import { useAuth, initials } from '../context/AuthContext.jsx';
import { useScan } from '../context/ScanContext.jsx';
import { formatDateTime } from '../utils/datetime.js';

export default function Activity() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const { scansList } = useScan();

  return (
    <div className="sc-page">
      <style>{`
        .sc-page {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border: #262e3a; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e; --gold: #c9a227;
          background: var(--bg); color: var(--text-primary); min-height: 100vh;
          font-family: 'Switzer', system-ui, sans-serif;
        }
        .sc-page *, .sc-page *::before, .sc-page *::after { box-sizing: border-box; }
        .sc-wrap { max-width: 720px; margin: 0 auto; padding: 40px 32px 100px; }
        .sc-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: var(--text-secondary); font-size: 13px; cursor: pointer; padding: 0; margin-bottom: 28px; font-family: inherit; }
        .sc-back:hover { color: var(--gold); }
        .sc-header { display: flex; align-items: center; gap: 14px; margin-bottom: 36px; }
        .sc-avatar { width: 46px; height: 46px; border-radius: 999px; background: rgba(201,162,39,0.14); color: var(--gold); display: flex; align-items: center; justify-content: center; font-family: 'IBM Plex Mono', monospace; font-weight: 600; font-size: 15px; }
        .sc-title { font-family: 'Clash Display', sans-serif; font-size: 26px; font-weight: 600; margin: 0; }
        .sc-sub { font-size: 13px; color: var(--text-secondary); margin: 3px 0 0; }
        .sc-timeline { border-top: 1px solid var(--border-soft); }
        .sc-item { display: flex; gap: 14px; padding: 16px 0; border-bottom: 1px solid var(--border-soft); }
        .sc-item-icon { width: 34px; height: 34px; border-radius: 8px; background: var(--surface-2); color: var(--gold); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
        .sc-item-title { font-size: 14px; margin: 0; }
        .sc-item-detail { font-size: 12.5px; color: var(--text-secondary); margin: 3px 0 0; }
        .sc-item-time { font-size: 11.5px; color: var(--text-faint); margin-left: auto; white-space: nowrap; padding-top: 2px; }
      `}</style>

      <div className="sc-wrap">
        <button className="sc-back" onClick={() => navigate(-1)}><ArrowLeft size={14} /> Back</button>
        <div className="sc-header">
          <span className="sc-avatar">{user ? initials(user.name) : 'G'}</span>
          <div>
            <h1 className="sc-title">Profile activity</h1>
            <p className="sc-sub">Recent scan activity for {user ? user.name : 'your'} account</p>
          </div>
        </div>
        <div className="sc-timeline">
          {scansList.length === 0 ? (
            <p style={{ padding: '24px 0', color: 'var(--text-secondary)', fontSize: 13 }}>No recent scan activity found.</p>
          ) : (
            scansList.map((s) => (
              <div className="sc-item" key={s.scan_id}>
                <span className="sc-item-icon"><Upload size={16} /></span>
                <div>
                  <p className="sc-item-title">Scanned {s.target_name}</p>
                  <p className="sc-item-detail">
                    {s.summary?.total_artifacts || 0} artifacts found · {s.summary?.shor_count || 0} quantum-vulnerable · Top band: {s.summary?.top_risk_band || 'safe'}
                  </p>
                </div>
                <span className="sc-item-time">
                  {formatDateTime(s.created_at)}
                </span>
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}

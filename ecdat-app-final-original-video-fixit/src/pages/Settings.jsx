import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, User, Lock, Bell, ScanLine, FileText, Eye, Check } from 'lucide-react';
import { useAuth } from '../context/AuthContext.jsx';

function Toggle({ checked, onChange, label }) {
  return (
    <label className="st-toggle-row">
      <span>{label}</span>
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        className={`st-toggle ${checked ? 'on' : ''}`}
        onClick={() => onChange(!checked)}
      >
        <span className="st-toggle-knob" />
      </button>
    </label>
  );
}

export default function Settings() {
  const navigate = useNavigate();
  const { user, login } = useAuth();
  const [name, setName] = useState(user?.name || '');
  const [saved, setSaved] = useState(false);

  const [notifWeekly, setNotifWeekly] = useState(true);
  const [notifCritical, setNotifCritical] = useState(true);
  const [notifProduct, setNotifProduct] = useState(false);

  const [scanAuto, setScanAuto] = useState(false);
  const [scanDepth, setScanDepth] = useState('standard');

  const [reportFormat, setReportFormat] = useState('pdf');
  const [reportIncludeGraph, setReportIncludeGraph] = useState(true);

  const [highContrast, setHighContrast] = useState(false);
  const [reducedMotion, setReducedMotion] = useState(false);

  const saveProfile = (e) => {
    e.preventDefault();
    if (user && name.trim()) login({ ...user, name: name.trim() });
    setSaved(true);
    window.setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="st-page">
      <style>{`
        .st-page {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border: #262e3a; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e; --gold: #c9a227;
          background: var(--bg); color: var(--text-primary); min-height: 100vh;
          font-family: 'Switzer', system-ui, sans-serif;
        }
        .st-page *, .st-page *::before, .st-page *::after { box-sizing: border-box; }
        .st-wrap { max-width: 720px; margin: 0 auto; padding: 40px 32px 100px; }
        .st-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: var(--text-secondary); font-size: 13px; cursor: pointer; padding: 0; margin-bottom: 28px; font-family: inherit; }
        .st-back:hover { color: var(--gold); }
        .st-title { font-family: 'Clash Display', sans-serif; font-size: 28px; font-weight: 600; margin: 0 0 36px; }
        .st-section { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 22px; margin-bottom: 16px; }
        .st-section-head { display: flex; align-items: center; gap: 10px; margin-bottom: 16px; }
        .st-section-head svg { color: var(--gold); }
        .st-section-head h2 { font-size: 15px; font-weight: 600; margin: 0; }
        .st-field { margin-bottom: 14px; }
        .st-field:last-child { margin-bottom: 0; }
        .st-field label { display: block; font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; }
        .st-field input, .st-field select {
          width: 100%; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px;
          padding: 9px 11px; font-size: 13.5px; color: var(--text-primary); font-family: inherit;
        }
        .st-field input:focus, .st-field select:focus { outline: none; border-color: var(--gold); }
        .st-save-btn {
          display: inline-flex; align-items: center; gap: 7px; background: var(--gold); color: #191308;
          font-weight: 600; font-size: 13px; padding: 9px 18px; border-radius: 6px; border: none; cursor: pointer;
          font-family: inherit; margin-top: 6px;
        }
        .st-save-btn:hover { filter: brightness(1.07); }
        .st-saved { font-size: 12.5px; color: var(--teal, #3fb8af); display: inline-flex; align-items: center; gap: 5px; margin-left: 12px; }
        .st-row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
        .st-toggle-row { display: flex; align-items: center; justify-content: space-between; padding: 9px 0; font-size: 13.5px; cursor: pointer; }
        .st-toggle { width: 38px; height: 22px; border-radius: 999px; background: var(--surface-2); border: 1px solid var(--border); position: relative; cursor: pointer; flex-shrink: 0; }
        .st-toggle.on { background: rgba(201,162,39,0.3); border-color: var(--gold); }
        .st-toggle-knob { position: absolute; top: 2px; left: 2px; width: 16px; height: 16px; border-radius: 999px; background: var(--text-faint); transition: transform 0.15s ease, background 0.15s ease; }
        .st-toggle.on .st-toggle-knob { transform: translateX(16px); background: var(--gold); }
        @media (max-width: 560px) { .st-row-2 { grid-template-columns: 1fr; } }
      `}</style>

      <div className="st-wrap">
        <button className="st-back" onClick={() => navigate(-1)}><ArrowLeft size={14} /> Back</button>
        <h1 className="st-title">Account settings</h1>

        <form className="st-section" onSubmit={saveProfile}>
          <div className="st-section-head"><User size={16} /><h2>Profile details</h2></div>
          <div className="st-row-2">
            <div className="st-field">
              <label htmlFor="st-name">Full name</label>
              <input id="st-name" type="text" value={name} onChange={(e) => setName(e.target.value)} />
            </div>
            <div className="st-field">
              <label htmlFor="st-email">Email</label>
              <input id="st-email" type="email" value={user?.email || ''} disabled />
            </div>
          </div>
          <button type="submit" className="st-save-btn"><Check size={14} /> Save profile</button>
          {saved && <span className="st-saved"><Check size={13} /> Saved</span>}
        </form>

        <div className="st-section">
          <div className="st-section-head"><Lock size={16} /><h2>Password &amp; security</h2></div>
          <div className="st-row-2">
            <div className="st-field">
              <label htmlFor="st-pw-current">Current password</label>
              <input id="st-pw-current" type="password" placeholder="••••••••••••" />
            </div>
            <div className="st-field">
              <label htmlFor="st-pw-new">New password</label>
              <input id="st-pw-new" type="password" placeholder="••••••••••••" />
            </div>
          </div>
          <button type="button" className="st-save-btn"><Check size={14} /> Update password</button>
        </div>

        <div className="st-section">
          <div className="st-section-head"><Bell size={16} /><h2>Notifications</h2></div>
          <Toggle checked={notifWeekly} onChange={setNotifWeekly} label="Weekly risk-summary digest" />
          <Toggle checked={notifCritical} onChange={setNotifCritical} label="Immediate alert on critical findings" />
          <Toggle checked={notifProduct} onChange={setNotifProduct} label="Product news and updates" />
        </div>

        <div className="st-section">
          <div className="st-section-head"><ScanLine size={16} /><h2>Scan preferences</h2></div>
          <Toggle checked={scanAuto} onChange={setScanAuto} label="Automatically re-scan flagged files weekly" />
          <div className="st-field" style={{ marginTop: 12 }}>
            <label htmlFor="st-depth">Default scan depth</label>
            <select id="st-depth" value={scanDepth} onChange={(e) => setScanDepth(e.target.value)}>
              <option value="quick">Quick — algorithms and certificates only</option>
              <option value="standard">Standard — includes keys and protocols</option>
              <option value="deep">Deep — includes container image inspection</option>
            </select>
          </div>
        </div>

        <div className="st-section">
          <div className="st-section-head"><FileText size={16} /><h2>Report preferences</h2></div>
          <div className="st-field">
            <label htmlFor="st-format">Default report format</label>
            <select id="st-format" value={reportFormat} onChange={(e) => setReportFormat(e.target.value)}>
              <option value="pdf">PDF</option>
              <option value="json">JSON (for CI/CD integration)</option>
            </select>
          </div>
          <Toggle checked={reportIncludeGraph} onChange={setReportIncludeGraph} label="Include topology graph in reports" />
        </div>

        <div className="st-section">
          <div className="st-section-head"><Eye size={16} /><h2>Theme &amp; accessibility</h2></div>
          <Toggle checked={highContrast} onChange={setHighContrast} label="High-contrast mode" />
          <Toggle checked={reducedMotion} onChange={setReducedMotion} label="Reduce motion and animations" />
        </div>
      </div>
    </div>
  );
}

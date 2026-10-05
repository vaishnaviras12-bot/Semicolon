import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import {
  ShieldAlert, Database, Gauge, Lightbulb, History, FileText,
  Wrench, Clock, FileCheck2,
} from 'lucide-react';
import Splash from './Splash.jsx';
import { useScan } from '../context/ScanContext.jsx';

const NAV_SECTIONS = [
  { key: 'risk-analysis', label: 'Risk Analysis', icon: ShieldAlert, kind: 'anchor', anchor: 'sec-risk-analysis' },
  { key: 'inventory', label: 'Crypto Inventory', icon: Database, kind: 'anchor', anchor: 'sec-inventory' },
  { key: 'pqc', label: 'PQC Readiness', icon: Gauge, kind: 'anchor', anchor: 'sec-pqc' },
  { key: 'recommend', label: 'Recommendation', icon: Lightbulb, kind: 'anchor', anchor: 'sec-recommend' },
  { key: 'remediator', label: 'PQC Remediation', icon: Wrench, kind: 'route', to: '/remediator' },
  { key: 'mosca', label: 'Mosca Timeline', icon: Clock, kind: 'route', to: '/mosca-timeline' },
  { key: 'compliance', label: 'Compliance & CBOM Reports', icon: FileCheck2, kind: 'route', to: '/compliance-reports' },
  { key: 'recent', label: 'Recent Scans', icon: History, kind: 'anchor', anchor: 'sec-recent' },
  { key: 'reports', label: 'Quick PDF report', icon: FileText, kind: 'anchor', anchor: 'sec-reports' },
];

export default function Sidebar({ activeKey }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { sidebarOpen } = useScan();
  const [splashing, setSplashing] = useState(false);

  const goAnchor = (anchor) => {
    if (location.pathname === '/dashboard') {
      document.getElementById(anchor)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    } else {
      navigate(`/dashboard#${anchor}`);
    }
  };

  return (
    <aside className={`sc-sidebar ${sidebarOpen ? '' : 'closed'}`}>
      <style>{`
        .sc-sidebar {
          width: 246px; flex-shrink: 0; background: var(--surface-1);
          border-right: 1px solid var(--border-soft); padding: 22px 14px;
          display: flex; flex-direction: column; gap: 22px;
          overflow: hidden auto; transition: width 0.18s ease, padding 0.18s ease, opacity 0.15s ease;
          max-height: 100vh; position: sticky; top: 0;
        }
        .sc-sidebar.closed { width: 0; padding-left: 0; padding-right: 0; opacity: 0; border-right: none; }
        .sc-brand {
          display: flex; align-items: center; gap: 9px; padding: 0 8px;
          background: none; border: none; cursor: pointer; font-family: inherit; width: 100%; white-space: nowrap;
        }
        .sc-brand:hover span { color: var(--gold); }
        .sc-brand svg { flex-shrink: 0; }
        .sc-brand span { font-size: 15px; font-weight: 600; letter-spacing: 0.06em; font-family: 'Clash Display', 'Switzer', sans-serif; }
        .sc-nav { display: flex; flex-direction: column; gap: 2px; }
        .sc-nav-item {
          display: flex; align-items: center; gap: 9px; padding: 9px 10px;
          border-radius: 6px; font-size: 13px; color: var(--text-secondary);
          cursor: pointer; border: none; background: none; width: 100%; text-align: left; font-family: inherit;
        }
        .sc-nav-item:hover { background: var(--surface-2); color: var(--text-primary); }
        .sc-nav-item.active { background: var(--gold-soft); color: var(--gold); }
        .sc-nav-divider { height: 1px; background: var(--border-soft); margin: 4px 8px; }
      `}</style>

      {splashing && <Splash duration={1100} onFinish={() => { setSplashing(false); navigate('/'); }} />}

      <button className="sc-brand" onClick={() => setSplashing(true)}>
        <svg width="22" height="22" viewBox="0 0 24 24" fill="none">
          <polygon points="12,2 21,7 21,17 12,22 3,17 3,7" stroke="var(--gold)" strokeWidth="1.4" />
          <circle cx="12" cy="12" r="2.6" fill="var(--gold)" />
        </svg>
        <span>SEMICOLON</span>
      </button>

      <nav className="sc-nav">
        {NAV_SECTIONS.map((item) => {
          const Icon = item.icon;
          if (item.kind === 'route') {
            return (
              <button
                key={item.key}
                className={`sc-nav-item ${activeKey === item.key ? 'active' : ''}`}
                onClick={() => navigate(item.to)}
              >
                <Icon size={16} />{item.label}
              </button>
            );
          }
          return (
            <button key={item.key} className="sc-nav-item" onClick={() => goAnchor(item.anchor)}>
              <Icon size={16} />{item.label}
            </button>
          );
        })}
      </nav>
    </aside>
  );
}

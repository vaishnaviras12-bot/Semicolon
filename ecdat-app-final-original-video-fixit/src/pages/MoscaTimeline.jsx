import React, { useState, useMemo } from 'react';
import { Link } from 'react-router-dom';
import Sidebar from '../components/Sidebar.jsx';
import ProfileMenu from '../components/ProfileMenu.jsx';
import { useScan } from '../context/ScanContext.jsx';
import { computeBreach, BREACH_STATUS_LABEL, BREACH_STATUS_COLOR } from '../utils/mosca.js';
import {
  Sun, Moon, PanelLeft, ShieldAlert, ArrowRight, RotateCcw, Info, KeyRound,
} from 'lucide-react';

function BreachBar({ requiredUntil, qday, status, scaleMax, height = 40 }) {
  const pct = (v) => Math.max(0, Math.min(100, (v / scaleMax) * 100));

  const q25Pct = pct(qday.p25);
  const q50Pct = pct(qday.p50);
  const q75Pct = pct(qday.p75);
  const reqPct = pct(requiredUntil);

  const qBandWidth = Math.max(0, q75Pct - q25Pct);

  const ticks = useMemo(() => {
    const step = scaleMax > 30 ? 10 : 5;
    const list = [];
    for (let t = 0; t <= scaleMax; t += step) {
      list.push(t);
    }
    return list;
  }, [scaleMax]);

  return (
    <div className="mo-timeline-wrap" style={{ margin: '20px 0 14px' }}>
      {/* Top Label Badge for X+Y Marker */}
      <div className="mo-timeline-badge-row" style={{ position: 'relative', height: 28, marginBottom: 6 }}>
        <div
          className="mo-xy-badge"
          style={{
            position: 'absolute',
            left: `${reqPct}%`,
            transform: 'translateX(-50%)',
            transition: 'left 0.15s ease-out',
            whiteSpace: 'nowrap',
            fontSize: 11.5,
            fontWeight: 600,
            padding: '3px 9px',
            borderRadius: 5,
            background: 'var(--surface-2)',
            border: '1px solid var(--border)',
            color: 'var(--text-primary)',
            boxShadow: '0 2px 8px rgba(0,0,0,0.3)',
            zIndex: 4
          }}
        >
          Required Safe (X+Y): <span style={{ color: 'var(--gold)', fontFamily: 'IBM Plex Mono, monospace' }}>{requiredUntil.toFixed(1)}y</span>
        </div>
      </div>

      {/* Main Bar Track */}
      <div className="mo-bar-track-outer" style={{ position: 'relative' }}>
        <div className="mo-bar-track" style={{ height, position: 'relative', borderRadius: 8, background: 'var(--surface-2)', overflow: 'hidden' }}>
          {/* Required Safe Progress Fill */}
          <div
            className={`mo-bar-required status-${status}`}
            style={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              left: 0,
              width: `${reqPct}%`,
              transition: 'width 0.15s ease-out',
              borderRadius: '8px 0 0 8px'
            }}
          />

          {/* Q-Day Estimated Window (Z Range: P25 - P75) */}
          <div
            className="mo-bar-band"
            style={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              left: `${q25Pct}%`,
              width: `${qBandWidth}%`,
              background: 'rgba(201,162,39,0.22)',
              borderLeft: '1px dashed rgba(201,162,39,0.6)',
              borderRight: '1px dashed rgba(201,162,39,0.6)',
              pointerEvents: 'none',
              zIndex: 1
            }}
          />

          {/* Q-Day Median Marker Line (P50) */}
          <div
            className="mo-bar-qday-p50"
            style={{
              position: 'absolute',
              top: 0,
              bottom: 0,
              left: `${q50Pct}%`,
              width: 2,
              background: 'rgba(201,162,39,0.85)',
              pointerEvents: 'none',
              zIndex: 2
            }}
          />
        </div>

        {/* Dynamic Vertical X+Y Marker Line */}
        <div
          className="mo-bar-marker-xy"
          style={{
            position: 'absolute',
            top: -5,
            bottom: -5,
            left: `${reqPct}%`,
            width: 3,
            background: '#ffffff',
            borderRadius: 2,
            boxShadow: '0 0 10px rgba(255,255,255,0.9), 0 0 5px var(--gold)',
            transition: 'left 0.15s ease-out',
            zIndex: 5,
            pointerEvents: 'none'
          }}
        />
      </div>

      {/* Timeline Ruler Ticks */}
      <div className="mo-ticks-row" style={{ position: 'relative', height: 22, marginTop: 8 }}>
        {ticks.map((t) => (
          <div
            key={t}
            style={{
              position: 'absolute',
              left: `${pct(t)}%`,
              transform: 'translateX(-50%)',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center'
            }}
          >
            <div style={{ width: 1, height: 6, background: 'var(--border)' }} />
            <span style={{ fontSize: 10.5, color: 'var(--text-faint)', fontFamily: 'IBM Plex Mono, monospace', marginTop: 2 }}>
              {t}y
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function MoscaTimeline() {
  const {
    theme, toggleTheme, sidebarOpen, toggleSidebar,
    scanState, hndlList, signatureOnlyList,
    portfolioShelfLife, setPortfolioShelfLife, portfolioMigrationYears, setPortfolioMigrationYears,
    qdayDist, setQdayDist, resetMoscaOverrides,
    portfolioBreach,
  } = useScan();

  const scaleMax = useMemo(() => {
    const raw = Math.max(qdayDist.p75 || 21, portfolioBreach.requiredUntil || 10, 20);
    return Math.ceil(raw * 1.15);
  }, [portfolioBreach, qdayDist]);

  return (
    <div className="mo-shell" data-theme={theme}>
      <style>{`
        .mo-shell {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border: #262e3a; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e;
          --gold: #c9a227; --gold-soft: rgba(201,162,39,0.14);
          --crimson: #c1503a; --teal: #3fb8af;
          font-family: 'Switzer', 'Inter', system-ui, sans-serif;
          background: var(--bg); color: var(--text-primary);
          min-height: 100vh; display: flex; width: 100%; box-sizing: border-box;
        }
        .mo-shell[data-theme="light"] {
          --bg: #f4f2ec; --surface-1: #ffffff; --surface-2: #ece9e0;
          --border: #dad6c9; --border-soft: #e4e1d6;
          --text-primary: #1b1d22; --text-secondary: #5b5e66; --text-faint: #8b8d93;
          --gold: #9c7a14; --gold-soft: rgba(156,122,20,0.12);
          --crimson: #a63f2b; --teal: #227a70;
        }
        .mo-shell *, .mo-shell *::before, .mo-shell *::after { box-sizing: border-box; }
        .mo-display { font-family: 'Clash Display', 'Switzer', sans-serif; }
        .mo-mono { font-family: 'IBM Plex Mono', monospace; }
        .mo-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
        .mo-topbar {
          display: flex; align-items: center; justify-content: space-between;
          padding: 18px 28px; border-bottom: 1px solid var(--border-soft);
          position: sticky; top: 0; background: var(--bg); z-index: 5;
        }
        .mo-topbar h1 { font-size: 21px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
        .mo-top-actions { display: flex; align-items: center; gap: 14px; }
        .mo-theme-btn {
          width: 32px; height: 32px; border-radius: 7px; border: 1px solid var(--border);
          background: var(--surface-1); color: var(--text-secondary); cursor: pointer;
          display: flex; align-items: center; justify-content: center;
        }
        .mo-theme-btn:hover { color: var(--gold); border-color: var(--gold); }
        .mo-content { padding: 22px 28px 60px; overflow-x: hidden; }
        .mo-empty {
          border: 1px dashed var(--border); border-radius: 10px; padding: 60px 24px;
          text-align: center; color: var(--text-secondary);
        }
        .mo-empty h2 { color: var(--text-primary); font-size: 17px; margin: 0 0 10px; }
        .mo-empty p { font-size: 13.5px; max-width: 440px; margin: 0 auto 18px; line-height: 1.6; }
        .mo-empty-btn {
          display: inline-flex; align-items: center; gap: 8px; background: var(--gold); color: #191308;
          font-weight: 600; font-size: 13.5px; padding: 10px 20px; border-radius: 7px; text-decoration: none;
        }
        .mo-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 18px; margin-bottom: 14px; }
        .mo-card h2 { font-size: 14px; font-weight: 500; margin: 0 0 6px; }
        .mo-card-sub { font-size: 12.5px; color: var(--text-secondary); margin: 0 0 14px; line-height: 1.55; }

        .mo-formula { font-size: 13px; text-align: center; padding: 10px; background: var(--surface-2); border-radius: 8px; margin-bottom: 4px; }
        .mo-formula b { color: var(--gold); }

        .mo-qday-row { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)) auto; gap: 12px; align-items: end; }
        .mo-field label { display: block; font-size: 11px; color: var(--text-faint); margin-bottom: 5px; text-transform: uppercase; letter-spacing: 0.04em; }
        .mo-field input {
          width: 100%; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px;
          padding: 8px 10px; color: var(--text-primary); font-family: 'IBM Plex Mono', monospace; font-size: 13px;
        }
        .mo-reset-btn {
          display: flex; align-items: center; gap: 6px; font-size: 12.5px; padding: 9px 14px; border-radius: 7px;
          border: 1px solid var(--border); background: var(--surface-2); color: var(--text-secondary); cursor: pointer; font-family: inherit; white-space: nowrap;
        }
        .mo-reset-btn:hover { color: var(--gold); border-color: var(--gold); }
        .mo-qday-note { display: flex; gap: 7px; font-size: 11.5px; color: var(--text-faint); margin-top: 10px; line-height: 1.6; }

        .mo-bar-track { position: relative; border-radius: 8px; background: var(--surface-2); overflow: hidden; }
        .mo-bar-band { position: absolute; top: 0; bottom: 0; background: rgba(201,162,39,0.20); }
        .mo-bar-marker { position: absolute; top: 0; bottom: 0; width: 2px; background: var(--gold); }
        .mo-bar-required { position: absolute; top: 0; bottom: 0; left: 0; border-radius: 8px 0 0 8px; opacity: 0.9; }
        .status-safe { background: var(--teal); }
        .status-breach-possible { background: var(--gold); }
        .status-breach-median { background: #d9772e; }
        .status-breach-likely { background: var(--crimson); }

        .mo-rank-row { display: grid; grid-template-columns: 150px 1fr 130px; gap: 12px; align-items: center; padding: 8px 0; border-top: 1px solid var(--border-soft); }
        .mo-rank-row:first-of-type { border-top: none; }
        .mo-rank-asset { font-size: 12.5px; font-weight: 600; }
        .mo-rank-status { font-size: 11.5px; text-align: right; white-space: nowrap; }

        .mo-asset-card { border: 1px solid var(--border-soft); border-radius: 10px; padding: 18px; margin-bottom: 14px; background: var(--surface-1); transition: border-color 0.15s ease; }
        .mo-asset-card:hover { border-color: var(--border); }
        .mo-asset-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
        .mo-asset-title { font-size: 15px; font-weight: 600; margin: 0 0 3px; }
        .mo-asset-sub { font-size: 12px; color: var(--text-faint); margin: 0; }
        .mo-asset-status { font-size: 11.5px; padding: 4px 10px; border-radius: 999px; white-space: nowrap; }

        .mo-sliders { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin: 14px 0; }
        .mo-slider-field label { display: flex; justify-content: space-between; font-size: 12px; color: var(--text-secondary); margin-bottom: 6px; }
        .mo-slider-field label b { color: var(--text-primary); }
        .mo-slider-field input[type="range"] { width: 100%; accent-color: var(--gold); }

        .mo-numbers-row { display: flex; gap: 18px; flex-wrap: wrap; font-size: 12px; color: var(--text-secondary); margin-top: 10px; }
        .mo-numbers-row b { color: var(--text-primary); }
        .mo-explain { font-size: 12.5px; color: var(--text-secondary); line-height: 1.6; margin-top: 12px; padding-top: 12px; border-top: 1px solid var(--border-soft); }

        .mo-sig-list { display: flex; flex-direction: column; gap: 8px; }
        .mo-sig-row { display: flex; align-items: center; gap: 10px; font-size: 12.5px; color: var(--text-secondary); padding: 8px 0; border-top: 1px solid var(--border-soft); }
        .mo-sig-row:first-of-type { border-top: none; }
        .mo-sig-row svg { flex-shrink: 0; color: var(--text-faint); }

        @media (max-width: 980px) {
          .mo-qday-row { grid-template-columns: 1fr 1fr; }
          .mo-sliders { grid-template-columns: 1fr; }
          .mo-rank-row { grid-template-columns: 110px 1fr 90px; }
        }
      `}</style>

      <Sidebar activeKey="mosca" />

      <div className="mo-main">
        <header className="mo-topbar">
          <h1 className="mo-display">Mosca Timeline</h1>
          <div className="mo-top-actions">
            <button className="mo-theme-btn" onClick={toggleTheme} aria-label="Toggle dark mode">
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button className="mo-theme-btn" onClick={toggleSidebar} aria-label="Toggle sidebar">
              <PanelLeft size={15} />
            </button>
            <ProfileMenu />
          </div>
        </header>

        <div className="mo-content">
          {scanState !== 'complete' ? (
            <div className="mo-empty">
              <ShieldAlert size={30} style={{ color: 'var(--text-faint)', marginBottom: 14 }} />
              <h2>No scan loaded yet</h2>
              <p>The Mosca Timeline models breach windows for this scan's findings. Run a scan on the dashboard first.</p>
              <Link to="/dashboard#sec-upload" className="mo-empty-btn">Go scan a file <ArrowRight size={14} /></Link>
            </div>
          ) : (
            <>
              <div className="mo-card">
                <h2>Mosca's inequality</h2>
                <div className="mo-formula mo-mono">
                  <b>X</b> (data shelf-life) + <b>Y</b> (migration time) &gt; <b>Z</b> (time to Q-Day) → breach
                </div>
                <p className="mo-card-sub" style={{ marginTop: 10, marginBottom: 0 }}>
                  Z is modeled as a range, not a date — quantum-threat timeline estimates vary widely even among
                  experts. Everything below recomputes live: drag Y down (faster migration) and watch the breach
                  window shrink or close.
                </p>
              </div>

              <div className="mo-card">
                <h2>Q-Day distribution (years from today)</h2>
                <p className="mo-card-sub">
                  Illustrative — shaped like the kind of range published expert-survey estimates (e.g. the Global
                  Risk Institute's Quantum Threat Timeline) produce. Replace with your own organization's risk-register
                  numbers.
                </p>
                <div className="mo-qday-row">
                  <div className="mo-field">
                    <label>P25 — earliest plausible</label>
                    <input type="number" min="1" max="60" value={qdayDist.p25}
                      onChange={(e) => setQdayDist({ ...qdayDist, p25: +e.target.value })} />
                  </div>
                  <div className="mo-field">
                    <label>P50 — median estimate</label>
                    <input type="number" min="1" max="60" value={qdayDist.p50}
                      onChange={(e) => setQdayDist({ ...qdayDist, p50: +e.target.value })} />
                  </div>
                  <div className="mo-field">
                    <label>P75 — later / optimistic</label>
                    <input type="number" min="1" max="60" value={qdayDist.p75}
                      onChange={(e) => setQdayDist({ ...qdayDist, p75: +e.target.value })} />
                  </div>
                  <button className="mo-reset-btn" onClick={resetMoscaOverrides}><RotateCcw size={13} /> Reset all</button>
                </div>
                <div className="mo-qday-note"><Info size={13} style={{ flexShrink: 0, marginTop: 1 }} />
                  Keep P25 ≤ P50 ≤ P75 for the band below to render sensibly. Resetting also clears every per-asset override below.
                </div>
              </div>

              <div className="mo-asset-card">
                <div className="mo-asset-head">
                  <div>
                    <h3 className="mo-asset-title">Full inventory — breach window</h3>
                    <p className="mo-asset-sub mo-mono">One common X and Y for every HNDL-relevant asset, not a value per artifact.</p>
                  </div>
                  <span className="mo-asset-status" style={{ color: BREACH_STATUS_COLOR[portfolioBreach.status], background: `${BREACH_STATUS_COLOR[portfolioBreach.status]}22` }}>
                    {BREACH_STATUS_LABEL[portfolioBreach.status]}
                  </span>
                </div>

                <BreachBar requiredUntil={portfolioBreach.requiredUntil} qday={qdayDist} status={portfolioBreach.status} scaleMax={scaleMax} />

                <div className="mo-sliders">
                  <div className="mo-slider-field">
                    <label>X — data shelf-life <b>{portfolioShelfLife} yrs</b></label>
                    <input type="range" min="0" max="30" step="1" value={portfolioShelfLife}
                      onChange={(e) => setPortfolioShelfLife(+e.target.value)} />
                  </div>
                  <div className="mo-slider-field">
                    <label>Y — migration time <b>{portfolioMigrationYears.toFixed(1)} yrs</b></label>
                    <input type="range" min="0" max="15" step="0.5" value={portfolioMigrationYears}
                      onChange={(e) => setPortfolioMigrationYears(+e.target.value)} />
                  </div>
                </div>

                <div className="mo-numbers-row">
                  <span>Required safe until: <b>{portfolioBreach.requiredUntil.toFixed(1)}y</b></span>
                  <span>Breach @ P25: <b>{portfolioBreach.atP25 > 0 ? `+${portfolioBreach.atP25.toFixed(1)}y` : 'safe'}</b></span>
                  <span>Breach @ P50 (Z): <b>{portfolioBreach.atP50 > 0 ? `+${portfolioBreach.atP50.toFixed(1)}y` : 'safe'}</b></span>
                  <span>Breach @ P75: <b>{portfolioBreach.atP75 > 0 ? `+${portfolioBreach.atP75.toFixed(1)}y` : 'safe'}</b></span>
                </div>
                <p className="mo-explain">
                  The full inventory ({portfolioShelfLife} yrs shelf-life + {portfolioMigrationYears.toFixed(1)} yrs to migrate ={' '}
                  {portfolioBreach.requiredUntil.toFixed(1)} yrs) needs to stay confidential until year{' '}
                  {portfolioBreach.requiredUntil.toFixed(1)}. Q-Day (Z) is estimated between {qdayDist.p25} and{' '}
                  {qdayDist.p75} years out (median {qdayDist.p50}). {portfolioBreach.atP50 > 0
                    ? `That's a breach of roughly ${portfolioBreach.atP50.toFixed(1)} years in the median scenario — migrating faster (drag Y left) shrinks this window.`
                    : 'That comes in before the median Q-Day estimate, so the inventory is on track at the current pace.'}
                </p>
              </div>

              {/* TASK 6A — Per-Asset HNDL Breach Analysis Table */}
              <PerAssetHndlTable
                hndlList={hndlList}
                qdayDist={qdayDist}
              />

              {/* TASK 6B — Signature-Only Findings Forgery Risk Section */}
              <SignatureForgerySection
                signatureOnlyList={signatureOnlyList}
                qdayDist={qdayDist}
              />
            </>
          )}
        </div>
      </div>
    </div>
  );
}

function PerAssetHndlTable({ hndlList, qdayDist }) {
  const [assetOverrides, setAssetOverrides] = useState({});
  const [expandedAssetId, setExpandedAssetId] = useState(null);
  const [search, setSearch] = useState('');
  const [statusFilter, setStatusFilter] = useState('all');
  const [sortCol, setSortCol] = useState('urgencyRank');
  const [sortDir, setSortDir] = useState('asc');

  const computedAssets = useMemo(() => {
    return (hndlList || []).map((f) => {
      const defaultX = f.mosca_x ?? (f.dataClassification?.shelfLifeYears || (f.sensitivity === 'Critical' ? 15 : f.sensitivity === 'High' ? 10 : 5));
      const defaultY = f.mosca_y ?? 1.0;
      const override = assetOverrides[f.id] || {};
      const x = override.x !== undefined ? override.x : defaultX;
      const y = override.y !== undefined ? override.y : defaultY;
      const breach = computeBreach(x, y, qdayDist);
      const isDualUse = Boolean(f.is_dual_use || f.isDualUse);

      let urgencyRank = 4;
      if (breach.atP25 > 0) urgencyRank = 1;
      else if (breach.atP50 > 0) urgencyRank = 2;
      else if (breach.atP75 > 0) urgencyRank = 3;

      return {
        ...f,
        assetName: f.asset || (f.file_path ? f.file_path.split(/[/\\]/).pop() : 'Asset'),
        location: f.location || f.file_path || '—',
        x,
        y,
        defaultX,
        defaultY,
        requiredUntil: breach.requiredUntil,
        breach,
        urgencyRank,
        isDualUse,
        hasOverride: override.x !== undefined || override.y !== undefined,
      };
    });
  }, [hndlList, assetOverrides, qdayDist]);

  const p50BreachCount = useMemo(() => {
    return computedAssets.filter((a) => a.breach.atP50 > 0).length;
  }, [computedAssets]);

  const filteredAssets = useMemo(() => {
    return computedAssets
      .filter((a) => {
        if (search) {
          const q = search.toLowerCase();
          const match = a.assetName.toLowerCase().includes(q) ||
            String(a.algorithm).toLowerCase().includes(q) ||
            a.location.toLowerCase().includes(q);
          if (!match) return false;
        }
        if (statusFilter === 'p25') return a.breach.atP25 > 0;
        if (statusFilter === 'p50') return a.breach.atP50 > 0;
        if (statusFilter === 'p75') return a.breach.atP75 > 0;
        if (statusFilter === 'safe') return a.breach.status === 'safe';
        return true;
      })
      .sort((a, b) => {
        let valA = a[sortCol];
        let valB = b[sortCol];
        if (sortCol === 'breachP50') {
          valA = a.breach.atP50;
          valB = b.breach.atP50;
        }
        if (typeof valA === 'string') {
          return sortDir === 'asc' ? valA.localeCompare(valB) : valB.localeCompare(valA);
        }
        return sortDir === 'asc' ? (valA > valB ? 1 : -1) : (valA < valB ? 1 : -1);
      });
  }, [computedAssets, search, statusFilter, sortCol, sortDir]);

  const handleSort = (col) => {
    if (sortCol === col) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'));
    } else {
      setSortCol(col);
      setSortDir('asc');
    }
  };

  const updateOverride = (id, field, val) => {
    setAssetOverrides((prev) => ({
      ...prev,
      [id]: {
        ...prev[id],
        [field]: +val,
      },
    }));
  };

  const resetOverride = (id) => {
    setAssetOverrides((prev) => {
      const next = { ...prev };
      delete next[id];
      return next;
    });
  };

  return (
    <div className="mo-card">
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10, marginBottom: 6 }}>
        <h2 style={{ margin: 0 }}>Per-asset breach analysis</h2>
        <span className="mo-mono" style={{ fontSize: 12.5, fontWeight: 600, color: p50BreachCount > 0 ? 'var(--crimson)' : 'var(--teal)', background: p50BreachCount > 0 ? 'rgba(193,80,58,0.12)' : 'rgba(63,184,175,0.12)', padding: '4px 12px', borderRadius: 999 }}>
          {p50BreachCount} of {computedAssets.length} assets breach the window at P50 (Z = {qdayDist.p50}y)
        </span>
      </div>
      <p className="mo-card-sub">
        Each HNDL-relevant asset evaluated against the Q-Day distribution above. The common window above uses the worst case; this table shows where each asset stands individually so you can decide what to migrate first.
      </p>

      {/* Filter controls */}
      <div style={{ display: 'flex', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
        <input
          type="text"
          placeholder="Filter assets by name, algorithm or file location..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          style={{
            flex: 1, minWidth: 220, background: 'var(--surface-2)', border: '1px solid var(--border)',
            borderRadius: 6, padding: '7px 12px', color: 'var(--text-primary)', fontSize: 13,
          }}
        />
        <select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          style={{
            background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 6,
            padding: '7px 12px', color: 'var(--text-primary)', fontSize: 13, cursor: 'pointer',
          }}
        >
          <option value="all">All statuses ({computedAssets.length})</option>
          <option value="p25">Breached at P25 ({computedAssets.filter(a => a.breach.atP25 > 0).length})</option>
          <option value="p50">Breached at P50 ({computedAssets.filter(a => a.breach.atP50 > 0).length})</option>
          <option value="p75">Breached at P75 ({computedAssets.filter(a => a.breach.atP75 > 0).length})</option>
          <option value="safe">Safe across all scenarios ({computedAssets.filter(a => a.breach.status === 'safe').length})</option>
        </select>
      </div>

      {/* Per-Asset Table */}
      <div style={{ overflowX: 'auto' }}>
        <table className="sd-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-soft)', textAlign: 'left' }}>
              <th style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => handleSort('assetName')}>Asset &amp; Location</th>
              <th style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => handleSort('algorithm')}>Algorithm</th>
              <th style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => handleSort('x')}>X (Shelf)</th>
              <th style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => handleSort('y')}>Y (Migr)</th>
              <th style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => handleSort('requiredUntil')}>X+Y</th>
              <th style={{ padding: '8px 10px' }}>P25 ({qdayDist.p25}y)</th>
              <th style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => handleSort('breachP50')}>P50 ({qdayDist.p50}y)</th>
              <th style={{ padding: '8px 10px' }}>P75 ({qdayDist.p75}y)</th>
              <th style={{ padding: '8px 10px', cursor: 'pointer' }} onClick={() => handleSort('urgencyRank')}>Status</th>
            </tr>
          </thead>
          <tbody>
            {filteredAssets.length === 0 ? (
              <tr><td colSpan="9" style={{ padding: '20px 10px', textAlign: 'center', color: 'var(--text-faint)' }}>No matching HNDL-relevant assets found.</td></tr>
            ) : (
              filteredAssets.map((a) => {
                const isExpanded = expandedAssetId === a.id;
                return (
                  <React.Fragment key={a.id}>
                    <tr
                      onClick={() => setExpandedAssetId(isExpanded ? null : a.id)}
                      style={{
                        cursor: 'pointer', borderBottom: '1px solid var(--border-soft)',
                        background: isExpanded ? 'var(--surface-2)' : 'transparent',
                        transition: 'background 0.15s ease',
                      }}
                    >
                      <td style={{ padding: '10px' }}>
                        <div className="mo-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.assetName}</div>
                        <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>{a.location}</div>
                        {a.isDualUse && (
                          <span style={{ fontSize: 10, color: 'var(--gold)', background: 'var(--gold-soft)', padding: '1px 5px', borderRadius: 3, marginTop: 2, display: 'inline-block' }}>
                            dual-use — confirm usage
                          </span>
                        )}
                        {a.hasOverride && (
                          <span style={{ fontSize: 10, color: 'var(--teal)', background: 'rgba(63,184,175,0.15)', padding: '1px 5px', borderRadius: 3, marginTop: 2, marginLeft: 4, display: 'inline-block' }}>
                            what-if overridden
                          </span>
                        )}
                      </td>
                      <td className="mo-mono" style={{ padding: '10px' }}>{a.algorithm}</td>
                      <td className="mo-mono" style={{ padding: '10px' }}>{a.x}y</td>
                      <td className="mo-mono" style={{ padding: '10px' }}>{a.y}y</td>
                      <td className="mo-mono" style={{ padding: '10px', fontWeight: 600, color: 'var(--gold)' }}>{a.requiredUntil.toFixed(1)}y</td>
                      <td style={{ padding: '10px' }}>
                        <BreachBadge margin={a.breach.atP25} />
                      </td>
                      <td style={{ padding: '10px' }}>
                        <BreachBadge margin={a.breach.atP50} highlight />
                      </td>
                      <td style={{ padding: '10px' }}>
                        <BreachBadge margin={a.breach.atP75} />
                      </td>
                      <td style={{ padding: '10px' }}>
                        <span className="mo-asset-status" style={{ color: BREACH_STATUS_COLOR[a.breach.status], background: `${BREACH_STATUS_COLOR[a.breach.status]}22`, fontSize: 11, padding: '3px 8px' }}>
                          {BREACH_STATUS_LABEL[a.breach.status]}
                        </span>
                      </td>
                    </tr>

                    {/* What-if override inline panel */}
                    {isExpanded && (
                      <tr style={{ background: 'var(--surface-2)' }}>
                        <td colSpan="9" style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)' }}>
                          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                            <span style={{ fontWeight: 600, fontSize: 13, color: 'var(--gold)' }}>
                              What-if override for {a.assetName} only
                            </span>
                            <span style={{ fontSize: 11.5, color: 'var(--text-faint)' }}>
                              Does not alter the headline portfolio sliders above.
                            </span>
                          </div>
                          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr auto', gap: 16, alignItems: 'center' }}>
                            <div>
                              <label style={{ display: 'block', fontSize: 11.5, color: 'var(--text-secondary)', marginBottom: 4 }}>
                                X — Asset secrecy shelf-life: <b>{a.x} yrs</b>
                              </label>
                              <input
                                type="range" min="0" max="30" step="1" value={a.x}
                                onChange={(e) => updateOverride(a.id, 'x', e.target.value)}
                                style={{ width: '100%', accentColor: 'var(--gold)' }}
                              />
                            </div>
                            <div>
                              <label style={{ display: 'block', fontSize: 11.5, color: 'var(--text-secondary)', marginBottom: 4 }}>
                                Y — Asset migration effort: <b>{a.y.toFixed(1)} yrs</b>
                              </label>
                              <input
                                type="range" min="0" max="15" step="0.5" value={a.y}
                                onChange={(e) => updateOverride(a.id, 'y', e.target.value)}
                                style={{ width: '100%', accentColor: 'var(--gold)' }}
                              />
                            </div>
                            <div>
                              <button
                                className="mo-reset-btn"
                                style={{ padding: '6px 12px', fontSize: 12 }}
                                onClick={(e) => { e.stopPropagation(); resetOverride(a.id); }}
                              >
                                <RotateCcw size={12} /> Reset asset
                              </button>
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function BreachBadge({ margin, highlight }) {
  const isBreached = margin > 0;
  const color = isBreached ? (highlight ? 'var(--crimson)' : 'var(--gold)') : 'var(--teal)';
  const bg = isBreached ? (highlight ? 'rgba(193,80,58,0.18)' : 'rgba(201,162,39,0.15)') : 'rgba(63,184,175,0.15)';
  const label = isBreached ? `Breached (+${margin.toFixed(1)}y)` : `Safe (${margin.toFixed(1)}y)`;
  return (
    <span style={{ color, background: bg, fontSize: 11, fontWeight: 600, padding: '3px 7px', borderRadius: 4, whiteSpace: 'nowrap' }}>
      {label}
    </span>
  );
}

function SignatureForgerySection({ signatureOnlyList, qdayDist }) {
  const sortedSignatureAssets = useMemo(() => {
    return (signatureOnlyList || []).map((f) => {
      const alg = String(f.algorithm || '').toUpperCase();
      const purposeLower = String(f.purpose || f.type || '').toLowerCase();
      let trustLifetime = 'Medium (~5y trust)';
      let rank = 2;

      if (purposeLower.includes('root') || purposeLower.includes('ca') || purposeLower.includes('firmware') || purposeLower.includes('doc')) {
        trustLifetime = 'Long (10-20y trust anchor)';
        rank = 1;
      } else if (purposeLower.includes('tls') || purposeLower.includes('cert') || purposeLower.includes('jwt') || purposeLower.includes('session')) {
        trustLifetime = 'Short (1-2y cert)';
        rank = 3;
      }

      const y = f.mosca_y ?? 1.0;
      const marginP50 = qdayDist.p50 - y;

      return {
        ...f,
        assetName: f.asset || (f.file_path ? f.file_path.split(/[/\\]/).pop() : 'Signature Asset'),
        location: f.location || f.file_path || '—',
        purposeLabel: f.purpose || (alg.includes('ECDSA') ? 'Digital Signature / Code Signing' : 'Authentication / Certificate Signing'),
        trustLifetime,
        migrationY: y,
        marginP50,
        rank,
      };
    }).sort((a, b) => a.rank - b.rank);
  }, [signatureOnlyList, qdayDist]);

  if (!sortedSignatureAssets.length) return null;

  return (
    <div id="sec-signature-risk" className="mo-card" style={{ borderLeft: '3px solid var(--gold)', background: 'var(--surface-1)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
        <KeyRound size={20} style={{ color: 'var(--gold)', flexShrink: 0 }} />
        <h2 style={{ margin: 0 }}>Signature-only findings — forgery risk (separate from HNDL)</h2>
      </div>
      <p className="mo-card-sub" style={{ marginTop: 8, lineHeight: 1.6 }}>
        Signature keys do not encrypt data, so there is no stored ciphertext to harvest and no harvest-now-decrypt-later exposure. The risk begins only once a quantum computer can derive the private key (Shor's algorithm) and forge signatures, such as fake certificates, malicious signed firmware or backdated documents. Nothing is decrypted retroactively.
      </p>

      <div style={{ overflowX: 'auto', marginTop: 14 }}>
        <table className="sd-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12.5 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-soft)', textAlign: 'left' }}>
              <th style={{ padding: '8px 10px' }}>Asset &amp; Location</th>
              <th style={{ padding: '8px 10px' }}>Algorithm</th>
              <th style={{ padding: '8px 10px' }}>What it signs / Purpose</th>
              <th style={{ padding: '8px 10px' }}>Trust Lifetime</th>
              <th style={{ padding: '8px 10px' }}>Migration Time (Y)</th>
              <th style={{ padding: '8px 10px' }}>Y vs Q-Day (P50 = {qdayDist.p50}y)</th>
              <th style={{ padding: '8px 10px' }}>Action &amp; Deadline</th>
            </tr>
          </thead>
          <tbody>
            {sortedSignatureAssets.map((a) => (
              <tr key={a.id} style={{ borderBottom: '1px solid var(--border-soft)' }}>
                <td style={{ padding: '10px' }}>
                  <div className="mo-mono" style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{a.assetName}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-faint)' }}>{a.location}</div>
                </td>
                <td className="mo-mono" style={{ padding: '10px' }}>{a.algorithm}</td>
                <td style={{ padding: '10px', color: 'var(--text-secondary)' }}>{a.purposeLabel}</td>
                <td style={{ padding: '10px' }}>
                  <span style={{ fontSize: 11.5, fontWeight: 600, color: a.rank === 1 ? 'var(--crimson)' : 'var(--text-primary)' }}>
                    {a.trustLifetime}
                  </span>
                </td>
                <td className="mo-mono" style={{ padding: '10px' }}>{a.migrationY.toFixed(1)}y</td>
                <td style={{ padding: '10px' }}>
                  <span className="mo-mono" style={{ fontSize: 11.5, color: a.marginP50 > 0 ? 'var(--teal)' : 'var(--crimson)' }}>
                    Margin: {a.marginP50.toFixed(1)}y before P50
                  </span>
                </td>
                <td style={{ padding: '10px' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 11, fontWeight: 600, color: '#191308', background: 'var(--gold)', padding: '3px 8px', borderRadius: 4, whiteSpace: 'nowrap' }}>
                      Migrate before Q-Day
                    </span>
                    <Link to="/remediator" style={{ fontSize: 11.5, color: 'var(--gold)' }}>Remediate →</Link>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

import React, { useRef, useEffect, useMemo, useCallback, useState } from 'react';
import { Link, useLocation } from 'react-router-dom';
import ForceGraph2D from 'react-force-graph-2d';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import jsPDF from 'jspdf';
import ProfileMenu from '../components/ProfileMenu.jsx';
import Sidebar from '../components/Sidebar.jsx';
import { useScan } from '../context/ScanContext.jsx';
import {
  BAND_LABEL, BAND_ORDER, BAND_COLOR, BAND_COLOR_LIGHT, BAND_DEADLINE,
  GRAPH_NODES, GRAPH_LINKS, getRiskComparison, getBandCounts,
  deriveKeySize, computeQARS, deriveLayer, deriveSensitivity, deriveExposure, deriveQuantumThreat,
  computeOverallRiskScore, riskScoreBand,
} from '../data/findings.js';
import {
  Upload, RefreshCw, Moon, Sun, ArrowRight, Bell,
  Loader2, Download, PanelLeft, Wrench, Clock, FileCheck2, Trash2, AlertTriangle, CheckCircle2,
} from 'lucide-react';
import { getScanReminders, updateReminderAck } from '../api/index.js';
import { formatDateTime, formatDate, daysAgo } from '../utils/datetime.js';

// ---------------------------------------------------------------------------
// Findings, bands, and the topology graph now live in src/data/findings.js —
// the single shared model the Remediator, Mosca Timeline, and Compliance
// Reports pages also read from, instead of Dashboard-only mock data.
// ---------------------------------------------------------------------------

const ENGINE_STAGES = [
  { title: 'Discovery engine', desc: 'Finds algorithms, protocols, certificates, keys, and libraries across code, containers, and certificates.' },
  { title: 'Analysis engine', desc: 'Classifies each finding, removes duplicates, and gives it context — what it is and where it lives.' },
  { title: 'Risk engine', desc: 'Scores severity, flags Shor-vulnerable crypto, and prioritizes what needs fixing first.' },
  { title: 'Recommendation engine', desc: 'Matches every finding to a NIST-standardized replacement, with two fallbacks and a migration-effort estimate.' },
];
const DATA_SOURCES = ['Source code (Git repos, ZIP uploads)', 'Network endpoints', 'Certificates', 'Container images'];
// Kept accurate to what's actually implemented today, not the eventual plan —
// Tree-sitter is a planned upgrade for JS/TS and C/C++, not yet wired in.
const SCANNER_TECH = [
  { lang: 'Python', method: 'Python AST --> AST-based crypto detection' },
  { lang: 'Java', method: 'Semgrep/pattern rules --> Pattern-based detection' },
  { lang: 'JavaScript / TypeScript', method: 'Tree-sitter --> Syntax-tree based detection' },
  { lang: 'C / C++', method: 'Tree-sitter --> Syntax-tree based detection' },
  { lang: 'Certificates', method: 'OpenSSL CLI —-> PEM, CRT, CER, DER, P12, PFX' },
  { lang: 'Containers', method: 'Docker CLI --> image inspection' },
  {lang: 'Binaries', method: '⁠Static binary analysis → pefile, pyelftools, imports/exports, and crypto strings' },
  { lang: 'Hardwares', method: 'Architecture / dependency evidence → Artefact extraction (No physical inspection)' },
  { lang: 'Cloud/ laC / Configurations', method: 'Static config parsing → Crypto APl/resource identification --> Evidence extraction & normalization' },
];

const REMINDER_DAYS = 7;

export function resolveRecommendation(f) {
  const algStr = String(f?.algorithm || '');
  const resStatus = String(f?.resolution_status || f?.resolutionStatus || '').toLowerCase();
  const purposeStr = String(f?.purpose || '').toLowerCase();
  const familyStr = String(f?.family || '').toLowerCase();
  const b = f?.risk_band || f?.band || 'safe';
  const artifactType = String(f?.artifact_type || f?.artifactType || '').toLowerCase();

  const getHybridText = (rawHybrid, defaultText) => {
    if (!rawHybrid || rawHybrid === 'N/A') return defaultText;
    if (rawHybrid.startsWith('N/A — ')) return rawHybrid.replace('N/A — ', 'Not applicable — ');
    if (rawHybrid.startsWith('N/A')) return defaultText;
    return rawHybrid;
  };

  // 1. Library-Only Findings (resolution_status === "library-only", artifact_type === "library", or algorithm containing "(library-only)")
  if (
    resStatus === 'library-only' ||
    artifactType === 'library' ||
    algStr.toLowerCase().includes('(library-only)')
  ) {
    return {
      primary: 'Usage Not Detected',
      hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable — Usage Not Detected'),
      risk: 'Not Assessed',
      priority: 'Informational',
      isLibraryOnly: true,
    };
  }

  // 2. Pure Hash Functions (MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA-3, etc.)
  if (familyStr === 'hash' || purposeStr === 'hashing' || ['MD5', 'SHA1', 'SHA-1', 'SHA256', 'SHA-256', 'SHA384', 'SHA-384', 'SHA512', 'SHA-512', 'SHA3', 'BLAKE'].some((k) => algStr.toUpperCase().includes(k))) {
    if (['MD5', 'SHA1', 'SHA-1'].some((k) => algStr.toUpperCase().includes(k))) {
      const p = f?.recommendation?.primary;
      const primaryVal = (p && p !== 'No change needed' && p !== 'Manual Cryptographic Review Required' && p !== 'Usage Not Detected') ? p : 'SHA-256 / SHA-384';
      return {
        primary: primaryVal,
        hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable — Hash function'),
        risk: BAND_LABEL[b] || 'Safe',
        priority: b === 'safe' ? 'Low' : (b.charAt(0).toUpperCase() + b.slice(1)),
        isLibraryOnly: false,
      };
    }
    return {
      primary: (f?.recommendation?.primary && f.recommendation.primary !== 'Usage Not Detected') ? f.recommendation.primary : 'SHA-384 / SHA-512',
      hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable — Hash function'),
      risk: BAND_LABEL[b] || 'Safe',
      priority: 'Safe',
      isLibraryOnly: false,
    };
  }

  // 3. Symmetric Ciphers & MACs (DES, 3DES, AES, HMAC, ChaCha20, Poly1305, CMAC)
  if (familyStr === 'mac' || purposeStr === 'mac' || purposeStr === 'authentication' || algStr.toUpperCase().includes('HMAC') || algStr.toUpperCase().includes('POLY1305') || algStr.toUpperCase().includes('CMAC')) {
    return {
      primary: (f?.recommendation?.primary && f.recommendation.primary !== 'Usage Not Detected') ? f.recommendation.primary : 'HMAC-SHA256 (Quantum Safe)',
      hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable — Message Authentication Code'),
      risk: BAND_LABEL[b] || 'Safe',
      priority: 'Safe',
      isLibraryOnly: false,
    };
  }

  if (familyStr === 'symmetric' || ['AES', 'CHACHA', 'DES', '3DES', 'RC4'].some((k) => algStr.toUpperCase().includes(k))) {
    if (algStr.toUpperCase().includes('DES')) {
      return {
        primary: 'AES-256-GCM',
        hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable — Symmetric cipher'),
        risk: BAND_LABEL[b] || 'High',
        priority: 'High',
        isLibraryOnly: false,
      };
    }
    return {
      primary: (f?.recommendation?.primary && f.recommendation.primary !== 'Usage Not Detected') ? f.recommendation.primary : 'AES-256-GCM',
      hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable — Symmetric cipher'),
      risk: BAND_LABEL[b] || 'Safe',
      priority: b === 'safe' ? 'Low' : (b.charAt(0).toUpperCase() + b.slice(1)),
      isLibraryOnly: false,
    };
  }

  // 4. Asymmetric / Shor-Vulnerable Algorithms (RSA, ECC, ECDSA, ECDH, X25519, Ed25519, DH, DSA)
  if (f?.shor_vulnerable || ['RSA', 'ECC', 'ECDSA', 'ECDH', 'DH', 'ED25519', 'X25519', 'DSA'].some((k) => algStr.toUpperCase().includes(k))) {
    if (purposeStr === 'signing' || purposeStr === 'signature_verification') {
      return {
        primary: 'ML-DSA-65 (NIST FIPS 204)',
        hybrid: 'ECDSA-P256 + ML-DSA-65',
        risk: BAND_LABEL[b] || 'High',
        priority: b === 'safe' ? 'High' : (b.charAt(0).toUpperCase() + b.slice(1)),
        isLibraryOnly: false,
      };
    }
    if (purposeStr === 'key_establishment' || purposeStr === 'key_exchange' || purposeStr === 'encryption') {
      return {
        primary: 'ML-KEM-768 (NIST FIPS 203)',
        hybrid: 'X25519 + ML-KEM-768',
        risk: BAND_LABEL[b] || 'High',
        priority: b === 'safe' ? 'High' : (b.charAt(0).toUpperCase() + b.slice(1)),
        isLibraryOnly: false,
      };
    }
    // Unresolved / unknown purpose -> Automated Default ML-KEM-768
    return {
      primary: 'ML-KEM-768 (NIST FIPS 203)',
      hybrid: 'X25519 + ML-KEM-768',
      risk: BAND_LABEL[b] || 'Moderate',
      priority: b === 'safe' ? 'Moderate' : (b.charAt(0).toUpperCase() + b.slice(1)),
      isLibraryOnly: false,
    };
  }

  // 5. Default fallback for safe / non-asymmetric findings
  if (b === 'safe') {
    return {
      primary: 'No change needed',
      hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable — Quantum Safe'),
      risk: BAND_LABEL[b] || 'Safe',
      priority: 'Safe',
      isLibraryOnly: false,
    };
  }

  const prim = f?.recommendation?.primary;
  const validPrim = (prim && prim !== 'Manual Cryptographic Review Required' && prim !== 'Usage Not Detected') ? prim : 'NIST PQC Target';
  return {
    primary: validPrim,
    hybrid: getHybridText(f?.recommendation?.hybrid, 'Not applicable'),
    risk: BAND_LABEL[b] || 'Low',
    priority: b.charAt(0).toUpperCase() + b.slice(1),
    isLibraryOnly: false,
  };
}

export default function Dashboard() {
  const location = useLocation();
  const {
    theme, toggleTheme, sidebarOpen, toggleSidebar,
    scanState, scanProgress, scanStageText, activeScanId, activeFileName, activeScanDate, scanError, beginScan,
    loadScanResults, removeScanById,
    findings, operationalFindings, libraryOnlyFindings, sortedFindings, actionable, shorCount, readinessScore,
    worstBreach, scansList,
  } = useScan();

  const [activeReminders, setActiveReminders] = useState([]);

  const fetchReminders = useCallback(() => {
    if (activeScanId) {
      getScanReminders(activeScanId)
        .then((res) => setActiveReminders(res.reminders || []))
        .catch(() => setActiveReminders([]));
    } else {
      setActiveReminders([]);
    }
  }, [activeScanId]);

  useEffect(() => {
    fetchReminders();
  }, [fetchReminders]);

  const handleToggleReminder = async (reminderId, currentAck) => {
    const nextState = !currentAck;
    // Optimistic UI update
    setActiveReminders((prev) =>
      prev.map((r) =>
        r.id === reminderId
          ? { ...r, acknowledged: nextState, acknowledged_at: nextState ? new Date().toISOString() : null }
          : r
      )
    );
    try {
      await updateReminderAck(activeScanId, reminderId, nextState);
      fetchReminders();
    } catch (err) {
      console.error('Failed to update reminder acknowledgement:', err);
      fetchReminders();
    }
  };

  const graphWrapRef = useRef(null);
  const fgRef = useRef(null);
  const [graphSize, setGraphSize] = useState({ width: 640, height: 350 });
  const [hoverNode, setHoverNode] = useState(null);
  const fileInputRef = useRef(null);
  const [changedFlags, setChangedFlags] = useState({});

  useEffect(() => {
    function measure() {
      if (graphWrapRef.current) setGraphSize({ width: graphWrapRef.current.clientWidth, height: 350 });
    }
    measure();
    window.addEventListener('resize', measure);
    return () => window.removeEventListener('resize', measure);
  }, []);

  // Default force-graph physics
  useEffect(() => {
    if (fgRef.current) {
      fgRef.current.d3Force('charge')?.strength(-170);
      fgRef.current.d3Force('link')?.distance(64);
    }
  }, []);
  const handleGraphEngineStop = useCallback(() => {
    fgRef.current?.zoomToFit(400, 36);
  }, []);

  useEffect(() => {
    if (location.hash) {
      const id = location.hash.replace('#', '');
      let attempts = 0;
      const tryScroll = () => {
        const el = document.getElementById(id);
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else if (attempts < 15) {
          attempts++;
          setTimeout(tryScroll, 100);
        }
      };
      tryScroll();
    }
  }, [location.hash]);

  const graphData = useMemo(() => {
    const list = Array.isArray(operationalFindings) ? operationalFindings : [];
    if (list.length === 0) return { nodes: [], links: [] };
    const nodes = [];
    const links = [];
    const nodeSet = new Set();

    list.forEach((f, idx) => {
      const locPath = f.location || f.file_path || f.asset || `Asset-${idx}`;
      const locName = String(locPath).split('/').pop() || locPath;
      const algName = f.algorithm || 'Cryptographic asset';
      const algNodeId = `alg-${idx}`;
      const band = f.risk_band || f.band || 'safe';

      if (!nodeSet.has(locPath)) {
        nodeSet.add(locPath);
        nodes.push({ id: locPath, name: locName, type: 'location', risk: band });
      }

      if (!nodeSet.has(algNodeId)) {
        nodeSet.add(algNodeId);
        nodes.push({ id: algNodeId, name: algName, type: 'algorithm', risk: band });
        links.push({ source: locPath, target: algNodeId });
      }
    });

    return { nodes, links };
  }, [operationalFindings]);

  const recentScans = useMemo(() => {
    if (!scansList || scansList.length === 0) return [];
    return scansList.slice(0, 4).map((s) => ({
      file: s.target_name,
      time: new Date(s.created_at).toLocaleDateString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' }),
      band: s.summary?.top_risk_band || 'safe',
    }));
  }, [scansList]);

  const sortedPreviousScans = useMemo(() => {
    if (!scansList || scansList.length === 0) return [];
    return scansList.map((s) => ({
      id: s.scan_id,
      file: s.target_name,
      scannedDaysAgo: Math.max(0, Math.floor((new Date() - new Date(s.created_at)) / (1000 * 60 * 60 * 24))),
      topBand: s.summary?.top_risk_band || 'safe',
    }));
  }, [scansList]);

  const bandColors = theme === 'light' ? BAND_COLOR_LIGHT : BAND_COLOR;
  const riskComparison = useMemo(() => getRiskComparison(operationalFindings), [operationalFindings]);
  const bandCounts = useMemo(() => getBandCounts(operationalFindings), [operationalFindings]);
  const overallRiskScore = useMemo(() => computeOverallRiskScore(operationalFindings), [operationalFindings]);
  const overallRiskBand = riskScoreBand(overallRiskScore);
  const toggleChanged = (id) => setChangedFlags((prev) => ({ ...prev, [id]: !prev[id] }));


  const paintNode = useCallback(
    (node, ctx, globalScale) => {
      const isHovered = hoverNode?.id === node.id;
      const r = isHovered ? 6.5 : 5;
      ctx.beginPath();
      ctx.arc(node.x, node.y, r, 0, 2 * Math.PI, false);
      ctx.fillStyle = bandColors[node.risk] || bandColors.safe;
      ctx.fill();
      ctx.lineWidth = isHovered ? 1.8 : 1;
      ctx.strokeStyle = theme === 'light' ? 'rgba(0,0,0,0.25)' : 'rgba(255,255,255,0.3)';
      ctx.stroke();

      // Labels only render on hover (or when zoomed in a lot) — with 16 nodes,
      // always-on labels just overlap into an illegible mess at default zoom.
      if (isHovered || globalScale > 2.2) {
        const fontSize = Math.max((10 / globalScale) * 1.6, 3.4);
        ctx.font = `${isHovered ? '600 ' : ''}${fontSize}px 'IBM Plex Mono', monospace`;
        const label = node.name;
        const textWidth = ctx.measureText(label).width;
        const padX = 3;
        ctx.fillStyle = theme === 'light' ? 'rgba(244,242,236,0.9)' : 'rgba(10,13,18,0.88)';
        ctx.fillRect(node.x - textWidth / 2 - padX, node.y + r + 1, textWidth + padX * 2, fontSize + 3);
        ctx.textAlign = 'center';
        ctx.textBaseline = 'top';
        ctx.fillStyle = isHovered
          ? (theme === 'light' ? '#1b1d22' : '#e8eaef')
          : (theme === 'light' ? '#5b5e66' : '#8a93a3');
        ctx.fillText(label, node.x, node.y + r + 2);
      }
    },
    [bandColors, theme, hoverNode]
  );

  const handleUploadClick = () => fileInputRef.current?.click();
  const handleFileChange = (e) => {
    const f = e.target.files?.[0];
    if (f) beginScan(f);
  };
  const runLiveScan = () => beginScan('live-network-scan.json');

  const scrollToSection = (anchor) => {
    document.getElementById(anchor)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  };

  const handleDownloadReport = () => {
    const doc = new jsPDF();
    let y = 20;
    doc.setFontSize(18);
    doc.text('Semicolon — Cryptographic Risk Report', 14, y); y += 10;
    doc.setFontSize(10);
    doc.text(`File: ${activeFileName || '—'}`, 14, y); y += 6;
    doc.text(`Scanned: ${activeScanDate || '—'}`, 14, y); y += 6;
    doc.text(`PQC readiness score: ${readinessScore}/100`, 14, y); y += 12;

    doc.setFontSize(13);
    doc.text('Findings by band', 14, y); y += 8;
    doc.setFontSize(9);
    BAND_ORDER.forEach((band) => {
      doc.text(`${BAND_LABEL[band]}: ${findings.filter((f) => (f.risk_band || f.band) === band).length}`, 14, y);
      y += 6;
    });
    y += 6;

    doc.setFontSize(13);
    doc.text('Findings & recommendations', 14, y); y += 8;
    doc.setFontSize(8);
    sortedFindings.forEach((f) => {
      if (y > 280) { doc.addPage(); y = 20; }
      const b = f.risk_band || f.band || 'safe';
      const assetStr = f.asset || f.algorithm;
      const rec = resolveRecommendation(f);
      doc.text(`${assetStr}  |  ${f.algorithm}  |  ${BAND_LABEL[b]}  |  Rec: ${rec.primary}  |  Hybrid: ${rec.hybrid}`, 14, y);
      y += 6;
    });

    doc.setFontSize(7);
    doc.text('Generated by Semicolon. Results are risk-informed estimates, not a guarantee — confirm with expert review before acting.', 14, 292);
    doc.save(`semicolon-report-${(activeFileName || 'scan').replace(/[^a-z0-9.-]/gi, '_')}.pdf`);
  };

  return (
    <div className="sentinel-dash" data-theme={theme}>
      <style>{`

        .sentinel-dash {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border: #262e3a; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e;
          --gold: #c9a227; --gold-soft: rgba(201,162,39,0.14);
          --crimson: #c1503a; --teal: #3fb8af;
          font-family: 'Switzer', 'Inter', system-ui, sans-serif;
          background: var(--bg); color: var(--text-primary);
          min-height: 100vh; display: flex; width: 100%; box-sizing: border-box;
        }
        .sentinel-dash[data-theme="light"] {
          --bg: #f4f2ec; --surface-1: #ffffff; --surface-2: #ece9e0;
          --border: #dad6c9; --border-soft: #e4e1d6;
          --text-primary: #1b1d22; --text-secondary: #5b5e66; --text-faint: #8b8d93;
          --gold: #9c7a14; --gold-soft: rgba(156,122,20,0.12);
          --crimson: #a63f2b; --teal: #227a70;
        }
        .sentinel-dash *, .sentinel-dash *::before, .sentinel-dash *::after { box-sizing: border-box; }
        .sd-display { font-family: 'Clash Display', 'Switzer', sans-serif; }
        .sd-mono { font-family: 'IBM Plex Mono', monospace; }

        .sd-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
        .sd-topbar {
          display: flex; align-items: center; justify-content: space-between;
          padding: 18px 28px; border-bottom: 1px solid var(--border-soft);
          position: sticky; top: 0; background: var(--bg); z-index: 5;
        }
        .sd-topbar h1 { font-size: 21px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
        .sd-top-actions { display: flex; align-items: center; gap: 14px; }
        .sd-theme-btn {
          width: 32px; height: 32px; border-radius: 7px; border: 1px solid var(--border);
          background: var(--surface-1); color: var(--text-secondary); cursor: pointer;
          display: flex; align-items: center; justify-content: center;
        }
        .sd-theme-btn:hover { color: var(--gold); border-color: var(--gold); }

        .sd-content { padding: 22px 28px 48px; overflow-x: hidden; }
        .sd-scroll-target { scroll-margin-top: 84px; }

        .sd-stats-row { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 14px; margin-bottom: 14px; }
        .sd-stat-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 16px; }
        .sd-stat-label { font-size: 12px; color: var(--text-secondary); margin: 0 0 8px; }
        .sd-stat-value { font-size: 26px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
        .sd-stat-value.accent-risk { color: var(--crimson); }

        .sd-grid { display: grid; grid-template-columns: minmax(0,1.6fr) minmax(0,1fr); gap: 14px; margin-bottom: 14px; }
        .sd-grid-narrow-left { grid-template-columns: minmax(280px,0.82fr) minmax(0,1.58fr); align-items: stretch; }
        .sd-risk-left-col { display: grid; grid-template-rows: minmax(176px,0.84fr) minmax(192px,1fr); gap: 14px; }
        .sd-risk-score-card {
          margin-bottom: 0; display: flex; flex-direction: column;
          align-items: flex-start; justify-content: center; gap: 8px; min-height: 176px;
        }
        .sd-risk-score-body { display: flex; align-items: baseline; gap: 4px; }
        .sd-risk-score-num { font-size: clamp(42px,4vw,56px); font-weight: 600; line-height: 0.95; }
        .sd-risk-score-max { font-size: 14px; color: var(--text-secondary); }
        .sd-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 18px; margin-bottom: 14px; }
        .sd-card h2 { font-size: 14px; font-weight: 500; margin: 0 0 14px; }
        .sd-card-sub { font-size: 12.5px; color: var(--text-secondary); margin: -8px 0 14px; line-height: 1.5; }
        .sd-graph-card { min-height: 430px; margin-bottom: 0; }
        .sd-graph-wrap { border-radius: 8px; overflow: hidden; background: var(--bg); }

        .sd-donut-row { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
        .sd-legend { display: flex; flex-direction: column; gap: 6px; }
        .sd-legend-item { display: flex; align-items: center; gap: 7px; font-size: 12px; color: var(--text-secondary); }
        .sd-legend-dot { width: 8px; height: 8px; border-radius: 999px; flex-shrink: 0; }

        .sd-upload-card { padding: 36px 24px; }
        .sd-upload-zone {
          border: 1.5px dashed var(--border); border-radius: 12px; padding: 40px 24px;
          display: flex; flex-direction: column; align-items: center; text-align: center;
          max-width: 640px; margin: 0 auto; color: var(--text-faint); transition: border-color 0.15s ease;
        }
        .sd-upload-zone:hover { border-color: var(--gold); }
        .sd-upload-zone-title { font-size: 14px; color: var(--text-secondary); margin: 14px 0 22px; }
        .sd-actions-row { flex-direction: row; gap: 14px; }
        .sd-action-btn-lg { padding: 13px 26px; font-size: 14.5px; }
        .sd-actions { display: flex; flex-direction: column; gap: 10px; }
        .sd-action-btn {
          display: flex; align-items: center; justify-content: center; gap: 8px;
          padding: 10px 14px; border-radius: 7px; font-size: 13.5px; font-weight: 500;
          cursor: pointer; font-family: inherit; border: 1px solid var(--border);
          background: var(--surface-2); color: var(--text-primary); text-decoration: none;
        }
        .sd-action-btn.primary { background: var(--gold); color: #191308; border-color: var(--gold); }
        .sd-action-btn.primary:hover { filter: brightness(1.07); }
        .sd-action-btn:not(.primary):hover { border-color: var(--gold); color: var(--gold); }
        .sd-action-btn:disabled { opacity: 0.55; cursor: not-allowed; }
        .sd-action-btn .spin { animation: sd-spin 0.9s linear infinite; }
        @keyframes sd-spin { to { transform: rotate(360deg); } }
        .sd-upload-note { font-size: 11.5px; color: var(--text-faint); text-align: center; margin: 0; }

        .sd-pipeline { display: flex; align-items: flex-start; gap: 16px; margin-top: 4px; flex-wrap: wrap; }
        .sd-pipeline-step { flex: 1 1 180px; min-width: 180px; }
        .sd-pipeline-num { font-size: 11px; color: var(--gold); }
        .sd-pipeline-step h3 { font-size: 14px; font-weight: 600; margin: 6px 0 6px; }
        .sd-pipeline-step p { font-size: 12.5px; color: var(--text-secondary); line-height: 1.5; margin: 0; }
        .sd-pipeline-arrow { color: var(--text-faint); margin-top: 22px; flex-shrink: 0; }
        .sd-sources-row { margin-top: 18px; }
        .sd-source-tag {
          display: inline-block; font-size: 11.5px; padding: 5px 10px; border: 1px solid var(--border);
          border-radius: 999px; color: var(--text-secondary); margin: 0 6px 6px 0;
        }

        .sd-table-wrap { overflow-x: auto; margin-top: 14px; }
        .sd-table { width: 100%; border-collapse: collapse; font-size: 13px; }
        .sd-table th {
          text-align: left; font-weight: 500; color: var(--text-secondary); font-size: 11px;
          text-transform: uppercase; letter-spacing: 0.04em; padding: 8px 10px; border-bottom: 1px solid var(--border-soft);
          white-space: nowrap;
        }
        .sd-table td { padding: 10px; border-bottom: 1px solid var(--border-soft); white-space: nowrap; }
        .sd-table-loc { color: var(--text-faint); font-size: 12px; }

        .sd-band-row { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 16px; }
        .sd-band-chip { flex: 1; min-width: 60px; background: var(--surface-2); border-radius: 8px; padding: 10px; display: flex; flex-direction: column; gap: 3px; }
        .sd-band-dot { width: 8px; height: 8px; border-radius: 999px; }
        .sd-band-count { font-size: 18px; }
        .sd-band-label { font-size: 10.5px; color: var(--text-secondary); }
        .sd-band-list-row { display: flex; align-items: center; justify-content: space-between; padding: 7px 0; border-top: 1px solid var(--border-soft); }
        .sd-band-pill { font-size: 11px; padding: 3px 9px; border-radius: 5px; font-weight: 500; white-space: nowrap; }

        .sd-pqc-summary-row { display: flex; align-items: center; gap: 28px; margin-bottom: 16px; flex-wrap: wrap; }
        .sd-pqc-note { font-size: 12px; color: var(--text-faint); line-height: 1.55; margin: 14px 0 0; }
        .sd-readiness-ring { position: relative; width: 96px; height: 96px; flex-shrink: 0; margin-left: auto; }
        .sd-readiness-ring svg { transform: rotate(-90deg); }
        .sd-readiness-ring-label {
          position: absolute; inset: 0; display: flex; flex-direction: column; align-items: center; justify-content: center;
        }
        .sd-readiness-ring-pct { font-family: 'Clash Display', sans-serif; font-size: 20px; font-weight: 600; line-height: 1; }
        .sd-readiness-ring-sub { font-size: 9px; color: var(--text-secondary); margin-top: 3px; letter-spacing: 0.03em; }
        @media (max-width: 620px) {
          .sd-readiness-ring { margin-left: 0; }
        }

        .sd-alarm-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 10px; padding: 12px 0; border-top: 1px solid var(--border-soft); }
        .sd-alarm-check { display: flex; align-items: center; gap: 10px; cursor: pointer; }
        .sd-alarm-check input { accent-color: var(--gold); width: 15px; height: 15px; flex-shrink: 0; }
        .sd-alarm-right { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
        .sd-reminder { display: flex; align-items: center; gap: 5px; font-size: 11.5px; color: var(--crimson); background: rgba(193,80,58,0.12); padding: 4px 9px; border-radius: 5px; white-space: nowrap; }

        .sd-scan-row { display: flex; align-items: center; justify-content: space-between; padding: 12px 0; border-top: 1px solid var(--border-soft); }
        .sd-scan-row:first-of-type { border-top: none; }
        .sd-scan-file { font-size: 13.5px; margin: 0; }
        .sd-scan-time { font-size: 11.5px; color: var(--text-faint); margin: 2px 0 0; }

        .sd-empty-state {
          border: 1px dashed var(--border); border-radius: 10px; padding: 48px 24px;
          text-align: center; color: var(--text-secondary); margin-bottom: 14px;
        }
        .sd-empty-state svg { color: var(--text-faint); margin-bottom: 14px; }
        .sd-empty-state h2 { font-size: 17px; color: var(--text-primary); margin: 0 0 8px; font-weight: 600; }
        .sd-empty-state p { font-size: 13.5px; max-width: 420px; margin: 0 auto; line-height: 1.6; }
        .sd-empty-state .spin { animation: sd-spin 1s linear infinite; }

        .sd-reports-row { display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 14px; }
        .sd-reports-meta { font-size: 12.5px; color: var(--text-secondary); line-height: 1.7; }
        .sd-reports-meta b { color: var(--text-primary); font-weight: 600; }

        .sd-feature-row { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 12px; margin-top: 4px; }
        .sd-feature-card {
          display: block; padding: 16px; border: 1px solid var(--border-soft); border-radius: 10px;
          background: var(--surface-2); text-decoration: none; color: var(--text-primary);
        }
        .sd-feature-card:hover { border-color: var(--gold); }
        .sd-feature-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--gold-soft); color: var(--gold); display: flex; align-items: center; justify-content: center; margin-bottom: 10px; }
        .sd-feature-title { font-size: 13.5px; font-weight: 600; margin: 0 0 4px; }
        .sd-feature-desc { font-size: 12px; color: var(--text-secondary); margin: 0; line-height: 1.5; }
        .sd-breach-banner {
          display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
          background: rgba(193,80,58,0.1); border: 1px solid rgba(193,80,58,0.3); border-radius: 10px;
          padding: 14px 18px; margin-bottom: 14px; font-size: 13px; color: var(--text-primary);
        }
        .sd-breach-banner b { color: var(--crimson); }

        @media (max-width: 980px) {
          .sd-stats-row { grid-template-columns: repeat(2, minmax(0,1fr)); }
          .sd-grid { grid-template-columns: 1fr; }
          .sd-risk-left-col { grid-template-columns: repeat(2, minmax(0,1fr)); grid-template-rows: none; }
          .sd-risk-score-card { min-height: 168px; }
          .sd-feature-row { grid-template-columns: 1fr; }
        }
        @media (max-width: 620px) {
          .sd-content { padding: 18px 16px 36px; }
          .sd-risk-left-col { grid-template-columns: 1fr; }
          .sd-risk-score-card { min-height: 154px; }
          .sd-donut-row { gap: 12px; }
        }
      `}</style>

      <Sidebar />

      <div className="sd-main">
        <header className="sd-topbar">
          <h1 className="sd-display">Dashboard</h1>
          <div className="sd-top-actions">
            <button className="sd-theme-btn" onClick={toggleTheme} aria-label="Toggle dark mode">
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button className="sd-theme-btn" onClick={toggleSidebar} aria-label="Toggle sidebar">
              <PanelLeft size={15} />
            </button>
            <ProfileMenu />
          </div>
        </header>

        <div className="sd-content">
          {scanState === 'complete' && worstBreach && worstBreach.atP50 > 0 && (
            <div className="sd-breach-banner">
              <span>
                <b>HNDL exposure detected</b> — the worst-case tracked asset breaches its required secrecy window by
                roughly <b>{worstBreach.atP50.toFixed(1)} years</b> in the median Q-Day scenario.
              </span>
              <Link to="/mosca-timeline" className="sd-action-btn primary" style={{ padding: '8px 14px', fontSize: 12.5 }}>
                Open Mosca Timeline <ArrowRight size={13} />
              </Link>
            </div>
          )}

          <div className="sd-card">
            <h2>How Semicolon works</h2>
            <div className="sd-pipeline">
              {ENGINE_STAGES.map((stage, i) => (
                <React.Fragment key={stage.title}>
                  <div className="sd-pipeline-step">
                    <span className="sd-pipeline-num sd-mono">{String(i + 1).padStart(2, '0')}</span>
                    <h3>{stage.title}</h3>
                    <p>{stage.desc}</p>
                  </div>
                  {i < ENGINE_STAGES.length - 1 && <ArrowRight size={16} className="sd-pipeline-arrow" />}
                </React.Fragment>
              ))}
            </div>
            <div className="sd-sources-row">
              {DATA_SOURCES.map((s) => <span key={s} className="sd-source-tag sd-mono">{s}</span>)}
            </div>
            <div className="sd-table-wrap">
              <table className="sd-table">
                <thead><tr><th>Coverage</th><th>Detection method</th></tr></thead>
                <tbody>
                  {SCANNER_TECH.map((s) => (
                    <tr key={s.lang}><td>{s.lang}</td><td className="sd-table-loc">{s.method}</td></tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className="sd-card">
            <h2>Beyond discovery</h2>
            <p className="sd-card-sub">Once a scan completes, three linked tools turn findings into action.</p>
            <div className="sd-feature-row">
              <Link to="/remediator" className="sd-feature-card">
                <div className="sd-feature-icon"><Wrench size={16} /></div>
                <p className="sd-feature-title">PQC Remediation</p>
                <p className="sd-feature-desc">Real before/after patches per finding, with a rationale, a breaking-change score, and a draft PR — not a silent auto-apply.</p>
              </Link>
              <Link to="/mosca-timeline" className="sd-feature-card">
                <div className="sd-feature-icon"><Clock size={16} /></div>
                <p className="sd-feature-title">Mosca Timeline</p>
                <p className="sd-feature-desc"> Inventory breach-window modeling against a Q-Day probability range — not a single confident year.</p>
              </Link>
              <Link to="/compliance-reports" className="sd-feature-card">
                <div className="sd-feature-icon"><FileCheck2 size={16} /></div>
                <p className="sd-feature-title">Compliance & CBOM Reports</p>
                <p className="sd-feature-desc">CycloneDX CBOM, NIST/CNSA framework mapping, and a signed evidence bundle for auditors.</p>
              </Link>
            </div>
          </div>

          <div id="sec-upload" className="sd-card sd-scroll-target sd-upload-card">
            <h2 style={{ textAlign: 'center' }}>Scan a file</h2>
            <p className="sd-card-sub" style={{ textAlign: 'center', margin: '-8px auto 20px', maxWidth: 480 }}>
              Upload a config, cert, key, or code file, or a backend-generated CBOM JSON to carry its fix-it suggestions into the Remediator.
            </p>
            <div className="sd-upload-zone">
              <Upload size={30} />
              <p className="sd-upload-zone-title">Drag a file here, or choose an option below</p>
              <div className="sd-actions sd-actions-row">
                <button className="sd-action-btn primary sd-action-btn-lg" onClick={handleUploadClick} disabled={scanState === 'scanning'}>
                  <Upload size={16} /> Upload file
                </button>
                <input ref={fileInputRef} type="file" onChange={handleFileChange} style={{ display: 'none' }} />
                <button className="sd-action-btn sd-action-btn-lg" onClick={runLiveScan} disabled={scanState === 'scanning'}>
                  <RefreshCw size={16} className={scanState === 'scanning' ? 'spin' : ''} />
                  {scanState === 'scanning' ? 'Scanning…' : 'Run live scan'}
                </button>
              </div>
              <p className="sd-upload-note">
                Select a source file, ZIP archive, certificate, or Dockerfile to trigger a real scan on the backend.
              </p>
            </div>
          </div>

          {scanState === 'scanning' && (
            <div className="sd-empty-state">
              <Loader2 size={30} className="spin" />
              <h2>Scanning {activeFileName}… ({scanProgress}%)</h2>
              <p>{scanStageText}</p>
            </div>
          )}

          {scanState === 'error' && (
            <div className="sd-card" style={{ borderColor: 'var(--crimson)', background: 'rgba(193,80,58,0.1)' }}>
              <h2 style={{ color: 'var(--crimson)' }}>Scan Error</h2>
              <p className="sd-card-sub" style={{ color: 'var(--text-primary)' }}>{scanError || 'An error occurred during scan execution.'}</p>
            </div>
          )}

          {scanState === 'complete' && (
            <>
              <div className="sd-stats-row">
                <StatCard label="Scanned file" value={activeFileName} small />
                <StatCard label="Scan date" value={activeScanDate} small />
                <StatCard label="Critical findings" value={operationalFindings.filter((f) => (f.risk_band || f.band) === 'critical').length} accent="risk" />
                <StatCard label="High findings" value={operationalFindings.filter((f) => (f.risk_band || f.band) === 'high').length} />
              </div>

              <div id="sec-risk-analysis" className="sd-scroll-target">
                <div className="sd-grid sd-grid-narrow-left">
                  <div className="sd-risk-left-col">
                    <div id="sec-risk-score" className="sd-card sd-risk-score-card">
                      <h2>Overall risk score</h2>
                      <div className="sd-risk-score-body">
                        <span className="sd-risk-score-num sd-display" style={{ color: bandColors[overallRiskBand] }}>{overallRiskScore}</span>
                        <span className="sd-risk-score-max">/100</span>
                      </div>
                      <span className="sd-band-pill" style={{ color: bandColors[overallRiskBand], background: `${bandColors[overallRiskBand]}22` }}>
                        {BAND_LABEL[overallRiskBand]} overall
                      </span>
                    </div>

                    <div id="sec-risk-breakdown" className="sd-card sd-scroll-target" style={{ marginBottom: 0, flex: 1 }}>
                      <h2>Risk breakdown</h2>
                      <div className="sd-donut-row">
                        <PieChart width={92} height={92}>
                          <Pie data={riskComparison} dataKey="current" nameKey="label" innerRadius={28} outerRadius={44} startAngle={90} endAngle={-270} stroke="none">
                            {riskComparison.map((entry) => <Cell key={entry.band} fill={bandColors[entry.band]} />)}
                          </Pie>
                        </PieChart>
                        <div className="sd-legend">
                          {riskComparison.map((entry) => (
                            <div className="sd-legend-item" key={entry.band}>
                              <span className="sd-legend-dot" style={{ background: bandColors[entry.band] }} />
                              {entry.label} · {entry.current}
                            </div>
                          ))}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div id="sec-topology" className="sd-card sd-graph-card sd-scroll-target" style={{ marginBottom: 0 }}>
                    <h2>Cryptographic asset topology</h2>
                    <p className="sd-card-sub" style={{ marginTop: -6 }}>Hover a node for its name — labels stay hidden by default so 16 assets don't overlap into noise.</p>
                    <div className="sd-graph-wrap" ref={graphWrapRef}>
                      <ForceGraph2D
                        ref={fgRef}
                        graphData={graphData}
                        width={graphSize.width}
                        height={graphSize.height}
                        backgroundColor="rgba(0,0,0,0)"
                        nodeLabel={(n) => `${n.name} — ${BAND_LABEL[n.risk]}`}
                        linkColor={() => (theme === 'light' ? 'rgba(27,29,34,0.18)' : 'rgba(138,147,163,0.28)')}
                        nodeCanvasObject={paintNode}
                        onNodeHover={setHoverNode}
                        onEngineStop={handleGraphEngineStop}
                        nodeRelSize={5}
                        cooldownTicks={90}
                        linkDirectionalParticles={0}
                      />
                    </div>
                  </div>
                </div>

                <div className="sd-grid">
                  <div id="sec-risk-dashboard" className="sd-card sd-scroll-target" style={{ marginBottom: 0 }}>
                    <h2>Risk dashboard</h2>
                    <p className="sd-card-sub">Findings ranked by urgency, so your team knows what to handle first.</p>
                    <div className="sd-band-row">
                      {BAND_ORDER.map((band) => (
                        <div className="sd-band-chip" key={band}>
                          <span className="sd-band-dot" style={{ background: bandColors[band] }} />
                          <span className="sd-band-count sd-display">{operationalFindings.filter((f) => (f.risk_band || f.band) === band).length}</span>
                          <span className="sd-band-label">{BAND_LABEL[band]}</span>
                        </div>
                      ))}
                    </div>
                    <div>
                      {sortedFindings.slice(0, 4).map((f) => {
                        const b = f.risk_band || f.band || 'safe';
                        return (
                          <div className="sd-band-list-row" key={f.id}>
                            <span className="sd-mono" style={{ fontSize: 12.5 }}>{f.asset || f.algorithm}</span>
                            <span className="sd-band-pill" style={{ color: bandColors[b], background: `${bandColors[b]}22` }}>{BAND_LABEL[b]}</span>
                          </div>
                        );
                      })}
                    </div>
                  </div>

                  <div id="sec-risk-bar-graph" className="sd-card sd-scroll-target" style={{ marginBottom: 0 }}>
                    <h2>Findings by risk level</h2>
                    <p className="sd-card-sub">How many findings sit in each band right now.</p>
                    <ResponsiveContainer width="100%" height={220}>
                      <BarChart
                        layout="vertical"
                        data={bandCounts}
                        margin={{ top: 4, right: 24, left: 4, bottom: 0 }}
                      >
                        <CartesianGrid stroke={theme === 'light' ? '#dad6c9' : '#1b2129'} horizontal={false} />
                        <XAxis type="number" allowDecimals={false} tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} />
                        <YAxis type="category" dataKey="label" tick={{ fill: 'var(--text-secondary)', fontSize: 11 }} axisLine={false} tickLine={false} width={68} />
                        <Tooltip
                          contentStyle={{ background: 'var(--surface-1)', border: '1px solid var(--border)', borderRadius: 8, fontSize: 12 }}
                          labelStyle={{ color: 'var(--text-primary)' }}
                        />
                        <Bar dataKey="count" name="Findings" radius={[0, 4, 4, 0]} barSize={18}>
                          {bandCounts.map((entry) => <Cell key={entry.band} fill={bandColors[entry.band]} />)}
                        </Bar>
                      </BarChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              </div>

              <div id="sec-inventory" className="sd-card sd-scroll-target">
                <h2>Crypto inventory</h2>
                <p className="sd-card-sub">
                  Every cryptographic asset Semicolon found in this scan, mapped to where it lives. QARS is the
                  Quantum-Adjusted Risk Score — band urgency, Shor-breakability, and detector confidence in one number.
                </p>
                <div className="sd-table-wrap">
                  <table className="sd-table">
                    <thead>
                      <tr>
                        <th>Asset</th><th>Type</th><th>Algorithm</th><th>Band</th><th>QARS</th>
                        <th>Sensitivity</th><th>Exposure</th><th>Layer</th><th>Vulnerable to</th><th>Location</th><th>Confidence</th>
                      </tr>
                    </thead>
                    <tbody>
                      {operationalFindings
                        .filter((f) => f.algorithm && f.algorithm.toUpperCase() !== 'UNSPECIFIED')
                        .map((f) => {
                          const qars = computeQARS(f);
                          const qarsBand = riskScoreBand(qars);
                          const b = f.risk_band || f.band || 'safe';
                          const assetFileName = f.asset || (f.file_path ? f.file_path.split(/[/\\]/).pop() : (f.location ? f.location.split(/[/\\]/).pop() : 'File'));
                          const typeName = f.type || f.artifact_type || 'Algorithm';
                          const locName = f.location || f.file_path || '—';
                          const confVal = typeof f.confidence === 'number' && !isNaN(f.confidence) ? f.confidence : null;
                          return (
                            <tr key={f.id}>
                              <td className="sd-mono" style={{ fontWeight: 600 }}>{assetFileName}</td>
                              <td>{typeName}</td>
                              <td className="sd-mono">{f.algorithm}</td>
                              <td><span className="sd-band-pill" style={{ color: bandColors[b], background: `${bandColors[b]}22` }}>{BAND_LABEL[b]}</span></td>
                              <td className="sd-mono" style={{ color: bandColors[qarsBand], fontWeight: 600 }}>{qars}</td>
                              <td>{deriveSensitivity(f)}</td>
                              <td className="sd-table-loc">{deriveExposure(f)}</td>
                              <td className="sd-table-loc">{deriveLayer(f)}</td>
                              <td className="sd-table-loc" style={{ whiteSpace: 'normal', minWidth: 200 }}>{deriveQuantumThreat(f)}</td>
                              <td className="sd-mono sd-table-loc">{locName}</td>
                              <td className="sd-mono">{confVal !== null ? confVal.toFixed(2) : '—'}</td>
                            </tr>
                          );
                        })}
                    </tbody>
                  </table>
                </div>
              </div>

              {libraryOnlyFindings && libraryOnlyFindings.length > 0 && (
                <div id="sec-library-only" className="sd-card sd-scroll-target">
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: 10 }}>
                    <h2>Cryptographic-Capable Libraries &amp; Dependencies</h2>
                    <span className="sd-band-pill" style={{ color: '#8a93a3', background: 'rgba(138, 147, 163, 0.18)', marginLeft: 'auto' }}>
                      Included in CBOM / CycloneDX
                    </span>
                  </div>
                  <p className="sd-card-sub" style={{ marginTop: 4, marginBottom: 4 }}>
                    Packages, libraries, or image manifests detected during scanning where no direct operational algorithm usage was attributable. These dependencies are included in the CBOM / CycloneDX export.
                  </p>
                  <p className="sd-card-sub" style={{ marginTop: 0, marginBottom: 14, color: 'var(--text-faint)', fontSize: 12 }}>
                    Note: Library-only dependencies are omitted from operational risk rankings and are not counted in the PQC readiness score.
                  </p>
                  <div className="sd-table-wrap">
                    <table className="sd-table">
                      <thead>
                        <tr>
                          <th>Package / Asset</th>
                          <th>Category</th>
                          <th>Version &amp; Source Manifest</th>
                          <th>Observed Usage &amp; Status</th>
                          <th>Detection Source</th>
                          <th>Location</th>
                        </tr>
                      </thead>
                      <tbody>
                        {libraryOnlyFindings.map((f, idx) => {
                          const assetName = f.asset || f.library || f.algorithm || `Library #${idx + 1}`;
                          const locName = f.location || f.file_path || '—';
                          const manifestName = f.manifest_file || (locName !== '—' ? locName.split(/[/\\]/).pop() : 'manifest');
                          const versionStr = f.version || f.package_version || f.version_str || 'Detected version';
                          const versionManifest = `${versionStr} (${manifestName})`;
                          const sources = Array.isArray(f.detection_sources) ? f.detection_sources.join(', ') : (f.detection_method || 'manifest scanner');
                          return (
                            <tr key={f.id || `lib-${idx}`}>
                              <td className="sd-mono" style={{ fontWeight: 600 }}>{assetName}</td>
                              <td>{f.cbom_category || 'Library'}</td>
                              <td className="sd-mono" style={{ fontSize: 12 }}>{versionManifest}</td>
                              <td>
                                <span className="sd-band-pill" style={{ color: '#8a93a3', background: 'rgba(138, 147, 163, 0.18)' }}>
                                  Usage Not Detected (library-only)
                                </span>
                              </td>
                              <td className="sd-mono sd-table-loc">{sources}</td>
                              <td className="sd-mono sd-table-loc">{locName}</td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              <div id="sec-pqc" className="sd-card sd-scroll-target">
                <h2>PQC readiness</h2>
                <p className="sd-card-sub">Quantum-vulnerable cryptography — broken outright by Shor's algorithm, not just weakened.</p>
                <div className="sd-pqc-summary-row">
                  <div>
                    <p className="sd-stat-value sd-display">{readinessScore}<span style={{ fontSize: 14, color: 'var(--text-secondary)', fontWeight: 400 }}>/100</span></p>
                    <p className="sd-stat-label">Overall readiness score</p>
                  </div>
                  <div>
                    <p className="sd-stat-value sd-display" style={{ color: 'var(--teal)' }}>{operationalFindings.length - shorCount}</p>
                    <p className="sd-stat-label">Assets safe</p>
                  </div>
                  <div>
                    <p className="sd-stat-value sd-display" style={{ color: 'var(--crimson)' }}>{shorCount}</p>
                    <p className="sd-stat-label">Assets action required</p>
                  </div>
                  <ReadinessRing percent={readinessScore} />
                </div>
                <p className="sd-pqc-note">
                  RSA and ECC/ECDSA are fully broken by a sufficiently powerful quantum computer. AES-256 is only
                  weakened by Grover's algorithm, not broken, so fully-safe assets aren't counted as needing action.
                  Per-asset recommended actions live in <a href="#sec-recommend" style={{ color: 'var(--gold)' }}>Recommendation</a> below;
                  for a step-by-step patch and rationale, see <Link to="/remediator" style={{ color: 'var(--gold)' }}>PQC Remediation</Link>.
                </p>
              </div>

              <div id="sec-recommend" className="sd-card sd-scroll-target">
                <h2>Recommendation</h2>
                <p className="sd-card-sub">
                  Every finding matched to a NIST-standardized replacement, with two fallbacks so one unavailable
                  algorithm doesn't stall the plan. Confidence scores live in Crypto Inventory above.
                </p>
                <div className="sd-table-wrap">
                  <table className="sd-table">
                    <thead>
                      <tr>
                        <th>File</th>
                        <th>Algorithm</th>
                        <th>Risk</th>
                        <th>Recommended PQC Migration</th>
                        <th>Hybrid Recommendation</th>
                        <th>Priority</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sortedFindings
                        .filter((f) => f.algorithm && f.algorithm.toUpperCase() !== 'UNSPECIFIED')
                        .map((f) => {
                          const b = f.risk_band || f.band || 'safe';
                          const assetFileName = f.asset || (f.file_path ? f.file_path.split(/[/\\]/).pop() : (f.location ? f.location.split(/[/\\]/).pop() : 'File'));
                          const rec = resolveRecommendation(f);
                          const riskLabel = rec.risk || BAND_LABEL[b];
                          const riskColor = rec.isLibraryOnly ? '#8a93a3' : bandColors[b];
                          const riskBg = rec.isLibraryOnly ? 'rgba(138, 147, 163, 0.15)' : `${bandColors[b]}22`;
                          return (
                            <tr key={f.id}>
                              <td className="sd-mono" style={{ fontWeight: 600 }}>{assetFileName}</td>
                              <td className="sd-mono sd-table-loc">{f.algorithm}</td>
                              <td><span className="sd-band-pill" style={{ color: riskColor, background: riskBg }}>{riskLabel}</span></td>
                              <td className="sd-mono">{rec.primary}</td>
                              <td className="sd-mono">{rec.hybrid}</td>
                              <td>{rec.priority}</td>
                            </tr>
                          );
                        })}
                    </tbody>
                  </table>
                </div>
              </div>

              <div id="sec-reports" className="sd-card sd-scroll-target">
                <h2>Reports</h2>
                <div className="sd-reports-row">
                  <div className="sd-reports-meta">
                    <div><b>{activeFileName}</b> — scanned {activeScanDate}</div>
                    <div>{findings.length} findings · {shorCount} quantum-vulnerable · readiness {readinessScore}/100</div>
                  </div>
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <button className="sd-action-btn" onClick={handleDownloadReport}>
                      <Download size={15} /> Quick PDF
                    </button>
                    <Link to="/compliance-reports" className="sd-action-btn primary">
                      <FileCheck2 size={15} /> Compliance &amp; CBOM Reports
                    </Link>
                  </div>
                </div>
              </div>
            </>
          )}

          <div id="sec-recent" className="sd-card sd-scroll-target">
            <h2>Recent scans</h2>
            <p className="sd-card-sub">Your persistent scan history. Select a scan to view its findings or delete it.</p>
            {scansList.length === 0 ? (
              <p className="sd-card-sub" style={{ margin: 0 }}>No scans recorded for your account yet. Upload a project file to begin.</p>
            ) : (
              scansList.map((scan) => {
                const isCurrent = activeScanId === scan.scan_id;
                const topBand = scan.summary?.top_risk_band || 'safe';
                const count = scan.summary?.total_artifacts || 0;
                const dateStr = formatDateTime(scan.created_at);
                return (
                  <div key={scan.scan_id} className="sd-scan-row" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 14px', borderRadius: 6, background: isCurrent ? 'var(--surface-2)' : 'transparent', border: isCurrent ? '1px solid var(--gold)' : '1px solid var(--hairline-soft)', marginBottom: 8 }}>
                    <div>
                      <p className="sd-scan-file sd-mono" style={{ fontWeight: 600, margin: 0, color: 'var(--text)' }}>
                        {scan.target_name} {isCurrent && <span style={{ fontSize: 11, color: 'var(--gold)', marginLeft: 8 }}>(Active)</span>}
                      </p>
                      <p className="sd-scan-time" style={{ fontSize: 11.5, color: 'var(--text-muted)', margin: '4px 0 0' }}>
                        {dateStr} · {count} finding{count !== 1 ? 's' : ''}
                      </p>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span className="sd-band-pill" style={{ color: bandColors[topBand] || bandColors.safe, background: `${bandColors[topBand] || bandColors.safe}22` }}>
                        {BAND_LABEL[topBand] || 'Safe'}
                      </span>
                      {!isCurrent && (
                        <button
                          className="sd-action-btn"
                          style={{ padding: '4px 10px', fontSize: 12 }}
                          onClick={() => loadScanResults(scan.scan_id, scan.target_name)}
                        >
                          View
                        </button>
                      )}
                      <button
                        className="sd-action-btn"
                        style={{ padding: '4px 8px', fontSize: 12, color: 'var(--crimson)', borderColor: 'rgba(193,80,58,0.3)' }}
                        title="Delete scan"
                        onClick={async () => {
                          if (window.confirm(`Are you sure you want to delete scan "${scan.target_name}"?`)) {
                            await removeScanById(scan.scan_id);
                          }
                        }}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {activeScanId && activeReminders.length > 0 && (() => {
            const completedCount = activeReminders.filter((r) => r.acknowledged).length;
            return (
              <div id="sec-reminders" className="sd-card sd-scroll-target">
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <h2 style={{ margin: 0 }}>Active Scan Reminders &amp; Action Items</h2>
                  <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--gold)', background: 'var(--gold-soft)', padding: '3px 10px', borderRadius: 999 }}>
                    {completedCount} of {activeReminders.length} completed
                  </span>
                </div>
                <p className="sd-card-sub" style={{ marginBottom: 16 }}>
                  Actionable migration items for high-risk and Shor-vulnerable cryptographic findings in the active scan.
                </p>
                {activeReminders.map((rem) => {
                  const b = (rem.risk_band || 'safe').toLowerCase();
                  const isAck = Boolean(rem.acknowledged);
                  return (
                    <div
                      className="sd-alarm-row"
                      key={rem.id}
                      style={{
                        display: 'flex',
                        alignItems: 'flex-start',
                        justifyContent: 'space-between',
                        padding: '14px 16px',
                        borderRadius: 8,
                        border: isAck ? '1px solid var(--teal)' : '1px solid var(--border-soft)',
                        marginBottom: 10,
                        background: isAck ? 'rgba(63, 184, 175, 0.06)' : 'var(--surface-2)',
                        opacity: isAck ? 0.75 : 1,
                        transition: 'all 0.2s ease',
                      }}
                    >
                      <div style={{ flex: 1, paddingRight: 16 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                          {isAck ? (
                            <CheckCircle2 size={16} style={{ color: 'var(--teal)', flexShrink: 0 }} />
                          ) : (
                            <AlertTriangle size={16} style={{ color: bandColors[b] || 'var(--gold)', flexShrink: 0 }} />
                          )}
                          <span
                            className="sd-mono"
                            style={{
                              fontWeight: 600,
                              fontSize: 13.5,
                              color: isAck ? 'var(--text-secondary)' : 'var(--text-primary)',
                              textDecoration: isAck ? 'line-through' : 'none',
                            }}
                          >
                            {rem.title}
                          </span>
                        </div>
                        <p style={{ margin: 0, fontSize: 12.5, color: 'var(--text-secondary)', textDecoration: isAck ? 'line-through' : 'none' }}>
                          {rem.message}
                        </p>
                        <p style={{ margin: '6px 0 0', fontSize: 12, color: 'var(--gold)', fontWeight: 500 }}>
                          Action: {rem.action_required}
                        </p>

                        <div style={{ marginTop: 12, display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
                          <label
                            htmlFor={`rem-check-${rem.id}`}
                            style={{
                              display: 'inline-flex',
                              alignItems: 'center',
                              gap: 7,
                              cursor: 'pointer',
                              fontSize: 12.5,
                              fontWeight: 600,
                              color: isAck ? 'var(--teal)' : 'var(--text-primary)',
                              userSelect: 'none',
                            }}
                          >
                            <input
                              type="checkbox"
                              id={`rem-check-${rem.id}`}
                              checked={isAck}
                              onChange={() => handleToggleReminder(rem.id, isAck)}
                              style={{ cursor: 'pointer', accentColor: 'var(--gold)', width: 16, height: 16 }}
                            />
                            I've updated my code
                          </label>

                          {isAck && (
                            <>
                              {rem.acknowledged_at && (
                                <span style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                                  Marked: {formatDateTime(rem.acknowledged_at)}
                                </span>
                              )}
                              <button
                                className="sd-action-btn"
                                style={{ padding: '3px 10px', fontSize: 11.5, color: 'var(--gold)', borderColor: 'var(--gold)' }}
                                onClick={() => {
                                  const el = document.getElementById('sec-upload');
                                  if (el) el.scrollIntoView({ behavior: 'smooth', block: 'start' });
                                }}
                              >
                                Re-scan to verify your changes
                              </button>
                            </>
                          )}
                        </div>
                      </div>
                      <div style={{ textAlign: 'right', flexShrink: 0 }}>
                        <span className="sd-band-pill" style={{ color: bandColors[b] || bandColors.safe, background: `${bandColors[b] || bandColors.safe}22` }}>
                          {BAND_LABEL[b] || b.toUpperCase()}
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })()}
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, suffix, accent, small }) {
  return (
    <div className="sd-stat-card">
      <p className="sd-stat-label">{label}</p>
      <p className={`sd-stat-value sd-display ${accent === 'risk' ? 'accent-risk' : ''}`} style={small ? { fontSize: 16 } : undefined}>
        {value}
        {suffix && <span style={{ fontSize: 14, color: 'var(--text-secondary)', fontWeight: 400 }}>{suffix}</span>}
      </p>
    </div>
  );
}

// Circular progress ring/dial for the PQC readiness percentage — replaces
// the old per-asset readiness table with a single at-a-glance visual.
function ReadinessRing({ percent, size = 96, stroke = 9 }) {
  const clamped = Math.max(0, Math.min(100, percent || 0));
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (clamped / 100) * circumference;
  const color = clamped >= 70 ? 'var(--teal)' : clamped >= 40 ? 'var(--gold)' : 'var(--crimson)';
  return (
    <div className="sd-readiness-ring" role="img" aria-label={`PQC readiness ${clamped} percent`}>
      <svg width={size} height={size}>
        <circle cx={size / 2} cy={size / 2} r={radius} stroke="var(--surface-2)" strokeWidth={stroke} fill="none" />
        <circle
          cx={size / 2} cy={size / 2} r={radius} stroke={color} strokeWidth={stroke} fill="none"
          strokeDasharray={circumference} strokeDashoffset={offset} strokeLinecap="round"
          style={{ transition: 'stroke-dashoffset 0.6s ease' }}
        />
      </svg>
      <div className="sd-readiness-ring-label">
        <span className="sd-readiness-ring-pct sd-display">{clamped}%</span>
        <span className="sd-readiness-ring-sub">PQC ready</span>
      </div>
    </div>
  );
}

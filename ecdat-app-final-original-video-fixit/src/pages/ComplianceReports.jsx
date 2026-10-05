import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import jsPDF from 'jspdf';
import JSZip from 'jszip';
import Sidebar from '../components/Sidebar.jsx';
import ProfileMenu from '../components/ProfileMenu.jsx';
import { useScan } from '../context/ScanContext.jsx';
import {
  Sun, Moon, PanelLeft, ShieldAlert, ArrowRight, Download, FileJson,
  FileSpreadsheet, FileArchive, ShieldCheck, Lock, ChevronDown, ChevronRight,
  CheckCircle2, XCircle, AlertTriangle, HelpCircle, FileText,
} from 'lucide-react';

function downloadBlob(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

async function sha256Hex(text) {
  if (!(typeof crypto !== 'undefined' && crypto.subtle)) return 'unavailable-in-this-context';
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, '0')).join('');
}

function buildExecutiveNarrative(ctx) {
  const { readinessScore, shorCount, findings, worstBreach, activeFileName, activeScanDate, complianceData } = ctx;
  const compSummary = complianceData?.summary || {};
  const safeFindings = Array.isArray(findings) ? findings : [];
  const lines = [
    `Executive PQC & Compliance Summary — ${activeFileName || 'scan'} (${activeScanDate || 'undated'})`,
    '',
    `This scan evaluated ${safeFindings.length} cryptographic findings, ${shorCount} of which are vulnerable to Shor's algorithm.`,
    `Overall Post-Quantum Cryptography Readiness Score: ${readinessScore}/100.`,
    '',
    compSummary.compliance_percentage !== undefined
      ? `Compliance Assessment Score: ${compSummary.compliance_percentage}% (${compSummary.passed || 0} Passed, ${compSummary.failed || 0} Failed, ${compSummary.partial || 0} Partial across ${compSummary.total_controls || 0} controls).`
      : 'Compliance assessment evaluation complete.',
    '',
    worstBreach && worstBreach.atP50 > 0
      ? `Confidentiality Exposure Window: Breached by approximately ${worstBreach.atP50.toFixed(1)} years at median Q-Day estimate.`
      : `Confidentiality Exposure Window: Within safe operational margin under current Q-Day models.`,
    '',
    'This audit brief is generated directly from backend discovery and risk engine evaluation data.',
  ];
  return lines.join('\n');
}

export default function ComplianceReports() {
  const {
    theme, toggleTheme, sidebarOpen, toggleSidebar,
    scanState, findings, cbom, cyclonedx, complianceData, actionable, readinessScore, shorCount,
    activeFileName, activeScanDate, remediationStatus, patchChoice,
    worstBreach, reportHistory, addReportRecord,
  } = useScan();

  const [signerName, setSignerName] = useState('');
  const [signerRole, setSignerRole] = useState('');
  const [signing, setSigning] = useState(false);
  const [bundling, setBundling] = useState(false);
  const [matrixOpen, setMatrixOpen] = useState(true);
  const [cbomViewOpen, setCbomViewOpen] = useState(true);

  const cleanFileName = (activeFileName || 'scan_target').replace(/[^a-z0-9.-]/gi, '_');

  const downloadCbomJson = () => {
    if (!cbom) return alert("CBOM data is not available for this scan.");
    downloadBlob(`semicolon-cbom-${cleanFileName}.json`, JSON.stringify(cbom, null, 2), 'application/json');
  };

  const downloadCycloneDxJson = () => {
    if (!cyclonedx && !cbom) return alert("CycloneDX export is not available for this scan.");
    downloadBlob(`semicolon-cyclonedx-${cleanFileName}.json`, JSON.stringify(cyclonedx || cbom, null, 2), 'application/json');
  };

  const downloadComplianceJson = () => {
    if (!complianceData) return alert("Compliance assessment is not available for this scan.");
    downloadBlob(`semicolon-compliance-${cleanFileName}.json`, JSON.stringify(complianceData, null, 2), 'application/json');
  };

  const downloadCbomPdf = () => {
    if (!cbom) return alert("CBOM data is not available for this scan.");
    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text('Cryptographic Bill of Materials (CBOM) Report', 14, 20);
    doc.setFontSize(10);
    doc.text(`Target: ${activeFileName || 'Scanned Target'} | Date: ${activeScanDate || 'Latest'}`, 14, 28);
    doc.text(`CBOM Entry ID / Serial: ${cbom.cbom_metadata?.serialNumber || cbom.serialNumber || 'N/A'}`, 14, 34);

    let y = 46;
    doc.setFontSize(11);
    doc.text('CBOM Cryptographic Assets:', 14, y);
    y += 8;

    const entries = cbom.cbom_entries || cbom.components || [];
    doc.setFontSize(9);
    entries.forEach((entry, idx) => {
      if (y > 275) { doc.addPage(); y = 20; }
      const name = entry.name || entry.algorithm || `Asset #${idx + 1}`;
      const alg = entry.algorithm || entry.cryptoProperties?.algorithmProperties?.parameterSetIdentifier || 'N/A';
      const cat = entry.cbom_category || entry.cryptoProperties?.assetType || 'cryptographic-asset';
      const occurrences = entry.occurrence_count || (entry.evidence?.occurrences ? entry.evidence.occurrences.length : 1);
      
      doc.text(`${idx + 1}. ${name} (${alg}) | Type: ${cat} | Occurrences: ${occurrences}`, 14, y);
      y += 6;
    });

    doc.save(`semicolon-cbom-report-${cleanFileName}.pdf`);
  };

  const downloadCompliancePdf = () => {
    if (!complianceData) return alert("Compliance assessment is not available for this scan.");
    const compSummary = complianceData.summary || {};
    const compFindings = complianceData.findings || [];

    const doc = new jsPDF();
    doc.setFontSize(16);
    doc.text('Post-Quantum Cryptography Compliance Assessment Report', 14, 20);
    doc.setFontSize(10);
    doc.text(`Target: ${activeFileName || 'Scanned Target'} | Date: ${activeScanDate || 'Latest'}`, 14, 28);
    doc.text(`Overall Compliance Score: ${compSummary.compliance_percentage}%`, 14, 34);
    doc.text(`Total Controls Evaluated: ${compSummary.total_controls} (Passed: ${compSummary.passed}, Failed: ${compSummary.failed}, Partial: ${compSummary.partial})`, 14, 40);

    let y = 52;
    doc.setFontSize(11);
    doc.text('Evaluated Control Findings:', 14, y);
    y += 8;

    doc.setFontSize(8.5);
    compFindings.forEach((item, idx) => {
      if (y > 270) { doc.addPage(); y = 20; }
      doc.text(`[${item.control_id}] ${item.control_name} (${item.framework}) — Status: ${item.status}`, 14, y);
      y += 5;
      const details = doc.splitTextToSize(`Asset: ${item.algorithm} | Location: ${item.location} | Reason: ${item.reason}`, 180);
      details.forEach((d) => {
        if (y > 275) { doc.addPage(); y = 20; }
        doc.text(d, 18, y);
        y += 4.5;
      });
      y += 3;
    });

    doc.save(`semicolon-compliance-report-${cleanFileName}.pdf`);
  };

  const downloadEngineeringCsv = () => {
    const header = ['id', 'asset', 'algorithm', 'band', 'confidence', 'location', 'effortHours', 'breakingChangeRisk', 'patchChoice', 'status'];
    const rows = (actionable || findings).map((f) => [
      f.id, f.asset || f.algorithm, f.algorithm, f.risk_band || f.band || 'safe', f.confidence ?? 0.8,
      f.location || f.file_path || '—', f.remediation?.effortHours ?? f.migration_effort_hours ?? '', f.remediation?.breakingChangeRisk ?? f.breaking_change_risk ?? '',
      patchChoice[f.id] || 'bridge', remediationStatus[f.id] || 'pending',
    ]);
    const csv = [header, ...rows].map((r) => r.map((v) => `"${String(v).replace(/"/g, '""')}"`).join(',')).join('\n');
    downloadBlob(`semicolon-engineering-detail-${cleanFileName}.csv`, csv, 'text/csv');
  };

  const downloadEvidenceBundle = async () => {
    setBundling(true);
    try {
      const zip = new JSZip();
      const narrative = buildExecutiveNarrative({ readinessScore, shorCount, findings, worstBreach, activeFileName, activeScanDate, complianceData });
      const findingsJson = JSON.stringify(findings, null, 2);
      const cbomJson = cbom ? JSON.stringify(cbom, null, 2) : '{}';
      const cyclonedxJson = cyclonedx ? JSON.stringify(cyclonedx, null, 2) : cbomJson;
      const complianceJson = complianceData ? JSON.stringify(complianceData, null, 2) : '{}';

      zip.file('findings.json', findingsJson);
      zip.file('cbom.json', cbomJson);
      zip.file('cyclonedx.json', cyclonedxJson);
      zip.file('compliance.json', complianceJson);
      zip.file('executive-summary.txt', narrative);

      const manifest = {
        generatedAt: new Date().toISOString(),
        tool: 'Semicolon Cryptographic Discovery & Analysis Tool v1.0.0',
        scanFile: activeFileName,
        scanDate: activeScanDate,
        files: [
          { name: 'findings.json', sha256: await sha256Hex(findingsJson) },
          { name: 'cbom.json', sha256: await sha256Hex(cbomJson) },
          { name: 'cyclonedx.json', sha256: await sha256Hex(cyclonedxJson) },
          { name: 'compliance.json', sha256: await sha256Hex(complianceJson) },
          { name: 'executive-summary.txt', sha256: await sha256Hex(narrative) },
        ],
      };
      zip.file('manifest.json', JSON.stringify(manifest, null, 2));

      const blob = await zip.generateAsync({ type: 'blob' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `semicolon-evidence-bundle-${cleanFileName}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } finally {
      setBundling(false);
    }
  };

  const signReport = async () => {
    if (!signerName.trim() || !signerRole.trim()) return;
    setSigning(true);
    try {
      const canonical = JSON.stringify({
        timestamp: new Date().toISOString(), readinessScore, shorCount,
        worstBreachP50: worstBreach?.atP50 ?? null, findingCount: Array.isArray(findings) ? findings.length : 0,
        complianceScore: complianceData?.summary?.compliance_percentage ?? null,
        signer: signerName.trim(), role: signerRole.trim(),
      });
      const hash = await sha256Hex(canonical);
      addReportRecord({
        id: `rep-${Date.now()}`, kind: 'attestation', timestamp: new Date().toLocaleString(),
        signer: signerName.trim(), role: signerRole.trim(), hash,
      });
    } finally {
      setSigning(false);
    }
  };

  const compSummary = complianceData?.summary;
  const compFindings = complianceData?.findings || [];
  const cbomEntries = cbom?.cbom_entries || cbom?.components || [];

  return (
    <div className="cr-shell" data-theme={theme}>
      <style>{`
        .cr-shell {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border: #262e3a; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e;
          --gold: #c9a227; --gold-soft: rgba(201,162,39,0.14);
          --crimson: #c1503a; --teal: #3fb8af;
          font-family: 'Switzer', 'Inter', system-ui, sans-serif;
          background: var(--bg); color: var(--text-primary);
          min-height: 100vh; display: flex; width: 100%; box-sizing: border-box;
        }
        .cr-shell[data-theme="light"] {
          --bg: #f4f2ec; --surface-1: #ffffff; --surface-2: #ece9e0;
          --border: #dad6c9; --border-soft: #e4e1d6;
          --text-primary: #1b1d22; --text-secondary: #5b5e66; --text-faint: #8b8d93;
          --gold: #9c7a14; --gold-soft: rgba(156,122,20,0.12);
          --crimson: #a63f2b; --teal: #227a70;
        }
        .cr-shell *, .cr-shell *::before, .cr-shell *::after { box-sizing: border-box; }
        .cr-display { font-family: 'Clash Display', 'Switzer', sans-serif; }
        .cr-mono { font-family: 'IBM Plex Mono', monospace; }
        .cr-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
        .cr-topbar {
          display: flex; align-items: center; justify-content: space-between;
          padding: 18px 28px; border-bottom: 1px solid var(--border-soft);
          position: sticky; top: 0; background: var(--bg); z-index: 5;
        }
        .cr-topbar h1 { font-size: 21px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
        .cr-top-actions { display: flex; align-items: center; gap: 14px; }
        .cr-theme-btn {
          width: 32px; height: 32px; border-radius: 7px; border: 1px solid var(--border);
          background: var(--surface-1); color: var(--text-secondary); cursor: pointer;
          display: flex; align-items: center; justify-content: center;
        }
        .cr-theme-btn:hover { color: var(--gold); border-color: var(--gold); }
        .cr-content { padding: 22px 28px 60px; overflow-x: hidden; }
        .cr-empty {
          border: 1px dashed var(--border); border-radius: 10px; padding: 60px 24px;
          text-align: center; color: var(--text-secondary);
        }
        .cr-empty h2 { color: var(--text-primary); font-size: 17px; margin: 0 0 10px; }
        .cr-empty p { font-size: 13.5px; max-width: 440px; margin: 0 auto 18px; line-height: 1.6; }
        .cr-empty-btn {
          display: inline-flex; align-items: center; gap: 8px; background: var(--gold); color: #191308;
          font-weight: 600; font-size: 13.5px; padding: 10px 20px; border-radius: 7px; text-decoration: none;
        }
        .cr-local-note {
          display: flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-faint);
          background: var(--surface-2); border-radius: 8px; padding: 10px 14px; margin-bottom: 14px;
        }
        .cr-stats-row { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 14px; margin-bottom: 14px; }
        .cr-stat-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 16px; }
        .cr-stat-label { font-size: 12px; color: var(--text-secondary); margin: 0 0 8px; }
        .cr-stat-value { font-size: 24px; font-weight: 600; margin: 0; }
        .cr-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 18px; margin-bottom: 14px; }
        .cr-card h2 { font-size: 14.5px; font-weight: 600; margin: 0 0 6px; display: flex; align-items: center; gap: 8px; }
        .cr-card-sub { font-size: 12.5px; color: var(--text-secondary); margin: 0 0 14px; line-height: 1.55; }

        .cr-report-grid { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 12px; }
        .cr-report-card { border: 1px solid var(--border-soft); border-radius: 10px; padding: 16px; background: var(--surface-2); transition: border-color 0.15s ease, transform 0.15s ease; }
        .cr-report-card:hover { border-color: var(--gold); transform: translateY(-2px); }
        .cr-report-icon { width: 32px; height: 32px; border-radius: 8px; background: var(--gold-soft); color: var(--gold); display: flex; align-items: center; justify-content: center; margin-bottom: 10px; }
        .cr-report-title { font-size: 13.5px; font-weight: 600; margin: 0 0 6px; }
        .cr-report-desc { font-size: 12px; color: var(--text-secondary); margin: 0 0 14px; line-height: 1.55; }
        .cr-report-btn {
          display: flex; align-items: center; justify-content: center; gap: 8px; width: 100%; padding: 9px 14px;
          border-radius: 7px; font-size: 12.5px; font-weight: 500; cursor: pointer; font-family: inherit;
          border: 1px solid var(--gold); background: var(--gold); color: #191308;
        }
        .cr-report-btn:hover { filter: brightness(1.07); }
        .cr-report-btn:disabled { opacity: 0.6; cursor: wait; }

        .cr-toggle-head { display: flex; align-items: center; justify-content: space-between; cursor: pointer; }
        .cr-table-wrap { overflow-x: auto; margin-top: 12px; }
        .cr-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
        .cr-table th { text-align: left; font-weight: 500; color: var(--text-secondary); font-size: 10.5px; text-transform: uppercase; letter-spacing: 0.04em; padding: 7px 10px; border-bottom: 1px solid var(--border-soft); white-space: nowrap; }
        .cr-table td { padding: 9px 10px; border-bottom: 1px solid var(--border-soft); }
        .cr-status-pill { font-size: 10.5px; padding: 2px 8px; border-radius: 5px; font-weight: 600; }
        .cr-status-pill.passed { color: var(--teal); background: rgba(63,184,175,0.14); }
        .cr-status-pill.failed { color: var(--crimson); background: rgba(193,80,58,0.14); }
        .cr-status-pill.partial { color: var(--gold); background: rgba(201,162,39,0.14); }
        .cr-disclaimer { font-size: 11.5px; color: var(--text-faint); margin-top: 10px; line-height: 1.6; }

        .cr-sign-row { display: grid; grid-template-columns: 1fr 1fr auto; gap: 10px; align-items: end; }
        .cr-field label { display: block; font-size: 11px; color: var(--text-faint); margin-bottom: 5px; text-transform: uppercase; letter-spacing: 0.04em; }
        .cr-field input {
          width: 100%; background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px;
          padding: 8px 10px; color: var(--text-primary); font-size: 13px; font-family: inherit;
        }
        .cr-sign-btn {
          padding: 9px 18px; border-radius: 7px; border: 1px solid var(--gold); background: var(--gold);
          color: #191308; font-weight: 600; font-size: 13px; cursor: pointer; white-space: nowrap;
        }
        .cr-sign-btn:disabled { opacity: 0.6; cursor: not-allowed; }
        .cr-history-row { display: flex; align-items: center; justify-content: space-between; gap: 10px; padding: 10px 0; border-top: 1px solid var(--border-soft); font-size: 12.5px; flex-wrap: wrap; }
        .cr-history-row:first-of-type { border-top: none; }
        .cr-history-hash { color: var(--text-faint); }

        @media (max-width: 980px) {
          .cr-stats-row { grid-template-columns: repeat(2, minmax(0,1fr)); }
          .cr-report-grid { grid-template-columns: 1fr; }
          .cr-sign-row { grid-template-columns: 1fr; }
        }
      `}</style>

      <Sidebar activeKey="compliance" />

      <div className="cr-main">
        <header className="cr-topbar">
          <h1 className="cr-display">Compliance &amp; CBOM Reports</h1>
          <div className="cr-top-actions">
            <button className="cr-theme-btn" onClick={toggleTheme} aria-label="Toggle dark mode">
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button className="cr-theme-btn" onClick={toggleSidebar} aria-label="Toggle sidebar">
              <PanelLeft size={15} />
            </button>
            <ProfileMenu />
          </div>
        </header>

        <div className="cr-content">
          {scanState !== 'complete' ? (
            <div className="cr-empty">
              <ShieldAlert size={30} style={{ color: 'var(--text-faint)', marginBottom: 14 }} />
              <h2>No scan loaded yet</h2>
              <p>Reports and compliance assessments are generated from a completed scan. Please upload and scan a target file first.</p>
              <Link to="/dashboard#sec-upload" className="cr-empty-btn">Go scan a file <ArrowRight size={14} /></Link>
            </div>
          ) : (
            <>
              <div className="cr-local-note">
                <Lock size={13} /> Official single-origin backend CBOM and Compliance assessment pipeline active.
              </div>

              <div className="cr-stats-row">
                <div className="cr-stat-card">
                  <p className="cr-stat-label">PQC Readiness Score</p>
                  <p className="cr-stat-value cr-display">{readinessScore}/100</p>
                </div>
                <div className="cr-stat-card">
                  <p className="cr-stat-label">Compliance Assessment</p>
                  <p className="cr-stat-value cr-display" style={{ color: compSummary ? (compSummary.compliance_percentage >= 70 ? 'var(--teal)' : 'var(--crimson)') : 'inherit' }}>
                    {compSummary ? `${compSummary.compliance_percentage}%` : 'N/A'}
                  </p>
                </div>
                <div className="cr-stat-card">
                  <p className="cr-stat-label">Quantum-Vulnerable Assets</p>
                  <p className="cr-stat-value cr-display" style={{ color: 'var(--crimson)' }}>{shorCount}</p>
                </div>
                <div className="cr-stat-card">
                  <p className="cr-stat-label">Confidentiality Window</p>
                  <p className="cr-stat-value cr-display" style={{ color: worstBreach && worstBreach.atP50 > 0 ? 'var(--crimson)' : 'var(--teal)' }}>
                    {worstBreach ? (worstBreach.atP50 > 0 ? `+${worstBreach.atP50.toFixed(1)}y breach` : 'Safe') : 'N/A'}
                  </p>
                </div>
              </div>

              {/* Downloadable Reports Section */}
              <div className="cr-card">
                <h2><FileJson size={15} /> Backend Reports &amp; Export Formats</h2>
                <p className="cr-card-sub">Export authentic backend-generated CBOM, CycloneDX, Compliance assessments, and Auditor Evidence Bundles.</p>
                <div className="cr-report-grid">
                  <div className="cr-report-card">
                    <div className="cr-report-icon"><FileJson size={16} /></div>
                    <p className="cr-report-title">Authoritative CBOM JSON</p>
                    <p className="cr-report-desc">Full Cryptographic Bill of Materials generated directly by ECDAT backend engine.</p>
                    <div style={{ display: 'flex', gap: 6, flexDirection: 'column' }}>
                      <button className="cr-report-btn" onClick={downloadCbomJson}><Download size={14} /> Download CBOM JSON</button>
                      <button className="cr-report-btn" style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-primary)' }} onClick={downloadCbomPdf}>
                        <FileText size={14} /> CBOM PDF Report
                      </button>
                    </div>
                  </div>

                  <div className="cr-report-card">
                    <div className="cr-report-icon"><ShieldCheck size={16} /></div>
                    <p className="cr-report-title">CycloneDX 1.6 Export</p>
                    <p className="cr-report-desc">Standardized CycloneDX JSON format with cryptoProperties and NIST quantum fields.</p>
                    <button className="cr-report-btn" onClick={downloadCycloneDxJson}><Download size={14} /> Download CycloneDX JSON</button>
                  </div>

                  <div className="cr-report-card">
                    <div className="cr-report-icon"><ShieldAlert size={16} /></div>
                    <p className="cr-report-title">Compliance Assessment</p>
                    <p className="cr-report-desc">Detailed NSA CNSA 2.0 &amp; NIST SP 800-57 framework evaluation report.</p>
                    <div style={{ display: 'flex', gap: 6, flexDirection: 'column' }}>
                      <button className="cr-report-btn" onClick={downloadComplianceJson}><Download size={14} /> Download Compliance JSON</button>
                      <button className="cr-report-btn" style={{ background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-primary)' }} onClick={downloadCompliancePdf}>
                        <FileText size={14} /> Compliance PDF Report
                      </button>
                    </div>
                  </div>
                </div>
              </div>

              {/* Auditor Evidence & Engineering CSV */}
              <div className="cr-card">
                <h2><FileArchive size={15} /> Auditor Evidence &amp; CSV Bundles</h2>
                <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
                  <button className="cr-report-btn" style={{ maxWidth: 280 }} onClick={downloadEvidenceBundle} disabled={bundling}>
                    <Download size={14} /> {bundling ? 'Bundling evidence…' : 'Download evidence bundle (.zip)'}
                  </button>
                  <button className="cr-report-btn" style={{ maxWidth: 240, background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-primary)' }} onClick={downloadEngineeringCsv}>
                    <FileSpreadsheet size={14} /> Engineering Detail CSV
                  </button>
                </div>
              </div>

              {/* Authoritative Backend CBOM View */}
              <div className="cr-card">
                <h2 className="cr-toggle-head" onClick={() => setCbomViewOpen((o) => !o)}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {cbomViewOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    Backend Cryptographic Bill of Materials (CBOM)
                  </span>
                </h2>
                {cbomViewOpen && (
                  !cbom ? (
                    <p className="cr-card-sub" style={{ marginTop: 10, color: 'var(--crimson)' }}>CBOM data is not available for this scan.</p>
                  ) : (
                    <>
                      <p className="cr-card-sub">Authoritative CBOM generated by <code>ECDAT-main/cbom/cbom_generator.py</code>.</p>
                      <div className="cr-table-wrap">
                        <table className="cr-table">
                          <thead>
                            <tr>
                              <th>Asset / Entry ID</th>
                              <th>Algorithm</th>
                              <th>Category</th>
                              <th>Library / Service</th>
                              <th>Occurrences</th>
                              <th>Locations</th>
                            </tr>
                          </thead>
                          <tbody>
                            {cbomEntries.map((entry, idx) => {
                              const entryId = entry.cbom_entry_id || entry.id || `entry-${idx + 1}`;
                              const alg = entry.algorithm || 'N/A';
                              const category = entry.cbom_category || 'cryptographic-asset';
                              const lib = entry.library || '—';
                              const occ = entry.occurrence_count || (entry.occurrences ? entry.occurrences.length : 1);
                              const files = entry.files_affected ? entry.files_affected.join(', ') : (entry.file_path || '—');
                              return (
                                <tr key={idx}>
                                  <td className="cr-mono" style={{ fontWeight: 600 }}>{entryId}</td>
                                  <td className="cr-mono">{alg}</td>
                                  <td>{category}</td>
                                  <td>{lib}</td>
                                  <td>{occ}</td>
                                  <td className="cr-mono" style={{ fontSize: 11 }}>{files}</td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )
                )}
              </div>

              {/* Authoritative Backend Compliance Assessment */}
              <div className="cr-card">
                <h2 className="cr-toggle-head" onClick={() => setMatrixOpen((o) => !o)}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {matrixOpen ? <ChevronDown size={15} /> : <ChevronRight size={15} />}
                    Compliance Assessment Controls &amp; Framework Matrix
                  </span>
                </h2>
                {matrixOpen && (
                  !complianceData ? (
                    <p className="cr-card-sub" style={{ marginTop: 10, color: 'var(--crimson)' }}>Compliance assessment is not available for this scan.</p>
                  ) : (
                    <>
                      <p className="cr-card-sub">Dynamic control verification against NSA CNSA 2.0, NIST SP 800-57, and FIPS 203/204 Standards.</p>
                      <div className="cr-table-wrap">
                        <table className="cr-table">
                          <thead>
                            <tr>
                              <th>Control ID</th>
                              <th>Control Name</th>
                              <th>Framework</th>
                              <th>Status</th>
                              <th>Algorithm</th>
                              <th>Location / Asset</th>
                              <th>Reason &amp; Remediation</th>
                            </tr>
                          </thead>
                          <tbody>
                            {compFindings.map((c, idx) => {
                              const st = (c.status || 'Unknown').toLowerCase();
                              return (
                                <tr key={idx}>
                                  <td className="cr-mono" style={{ fontWeight: 600 }}>{c.control_id}</td>
                                  <td style={{ fontWeight: 500 }}>{c.control_name}</td>
                                  <td>{c.framework}</td>
                                  <td>
                                    <span className={`cr-status-pill ${st === 'passed' ? 'passed' : st === 'failed' ? 'failed' : 'partial'}`}>
                                      {c.status}
                                    </span>
                                  </td>
                                  <td className="cr-mono">{c.algorithm}</td>
                                  <td className="cr-mono" style={{ fontSize: 11 }}>{c.location}</td>
                                  <td style={{ fontSize: 11.5, minWidth: 220 }}>
                                    <div>{c.reason}</div>
                                    <div style={{ color: 'var(--gold)', marginTop: 3 }}><b>Fix:</b> {c.remediation}</div>
                                  </td>
                                </tr>
                              );
                            })}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )
                )}
              </div>

              {/* Sign-off & Attestation */}
              <div className="cr-card">
                <h2>Sign-off &amp; Attestation</h2>
                <p className="cr-card-sub">Records a locally-computed SHA-256 hash of this scan's findings and compliance score with signature attestation.</p>
                <div className="cr-sign-row">
                  <div className="cr-field"><label>Name</label><input value={signerName} onChange={(e) => setSignerName(e.target.value)} placeholder="Jane Doe" /></div>
                  <div className="cr-field"><label>Role</label><input value={signerRole} onChange={(e) => setSignerRole(e.target.value)} placeholder="CISO / Auditor" /></div>
                  <button className="cr-sign-btn" onClick={signReport} disabled={signing || !signerName.trim() || !signerRole.trim()}>
                    {signing ? 'Signing…' : 'Sign & save report'}
                  </button>
                </div>
                {!!(Array.isArray(reportHistory) && reportHistory.length) && (
                  <div style={{ marginTop: 14 }}>
                    {reportHistory.map((r) => (
                      <div className="cr-history-row" key={r.id}>
                        <span><b>{r.signer}</b> ({r.role})</span>
                        <span>{r.timestamp}</span>
                        <span className="cr-history-hash cr-mono">sha256:{r.hash.slice(0, 16)}…</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Single shared data model for the whole app.
//
// This file is the "no silos" rule made literal: the Dashboard, the AI Code
// Remediator, the Mosca Timeline, and the Compliance & CBOM Reports page
// all import FINDINGS (and nothing else) from here. A finding's remediation
// content, its effort estimate, and its HNDL applicability are defined once,
// so a number can't drift between screens the way it would with four
// separate mock datasets.
//
// Two ideas recur throughout this file and are worth stating up front:
//
// 1. "Quantum-vulnerable" is not "broken today." Every rationale below is
//    written in terms of what a *future* cryptographically-relevant quantum
//    computer (CRQC) could do, not what's exploitable right now.
//
// 2. HNDL ("Harvest Now, Decrypt Later") only applies to confidentiality —
//    to data that gets encrypted and could be recorded today for later
//    decryption. It does NOT apply to pure signature/authentication keys
//    (an SSH host key, a code-signing key): there's no ciphertext to harvest
//    for those, only a future forgery risk once a CRQC exists. Findings are
//    tagged `hndlRelevant` accordingly, and the Mosca Timeline only plots
//    the ones where it actually applies — a distinction the reference demo
//    this app is competing with did not make.
// ---------------------------------------------------------------------------

export const BAND_COLOR = { safe: '#3fb8af', low: '#5b8ba8', moderate: '#c9a227', high: '#d9772e', critical: '#c1503a' };
export const BAND_COLOR_LIGHT = { safe: '#227a70', low: '#3f6a85', moderate: '#9c7a14', high: '#b8631f', critical: '#a63f2b' };
export const BAND_LABEL = { safe: 'Safe', low: 'Low', moderate: 'Moderate', high: 'High', critical: 'Critical' };
export const BAND_RANK = { critical: 4, high: 3, moderate: 2, low: 1, safe: 0 };
export const BAND_ORDER = ['critical', 'high', 'moderate', 'low', 'safe'];
export const BAND_STATUS = { critical: 'Urgent migration', high: 'Urgent migration', moderate: 'Plan migration', low: 'Monitor', safe: 'Safe' };
export const BAND_DEADLINE = { critical: '30 days', high: '60 days', moderate: '180 days', low: 'Next review cycle', safe: '—' };

// ---------------------------------------------------------------------------
// Derived per-finding fields for the Crypto Inventory table — computed from
// the fields already on each finding rather than duplicated as separate
// hand-maintained data, so they can't drift out of sync with band/algorithm.
// ---------------------------------------------------------------------------

// Helper to distinguish library-only dependencies from operational algorithm findings
export function isLibraryOnlyFinding(f) {
  if (!f) return false;
  const resStatus = String(f.resolution_status || f.resolutionStatus || '').toLowerCase();
  const artifactType = String(f.artifact_type || f.artifactType || '').toLowerCase();
  const algStr = String(f.algorithm || '').toLowerCase();
  return (
    resStatus === 'library-only' ||
    artifactType === 'library' ||
    algStr.includes('(library-only)')
  );
}

// "RSA-2048" -> "2048-bit". Protocol-version findings (e.g. "TLS 1.2") have
// no key size of their own, so they render as "—".
export function deriveKeySize(f) {
  if (!f) return '—';
  if (f.key_size) return `${f.key_size}-bit`;
  const m = String(f.algorithm || '').match(/(\d{3,4})/);
  return m ? `${m[1]}-bit` : '—';
}

// QARS — Quantum-Adjusted Risk Score (0-100). Blends how urgent the band is,
// whether the finding is actually Shor-breakable (not just outdated), and
// how confident the detector is that the finding is real.
export function computeQARS(f) {
  if (!f) return 0;
  if (typeof f.risk_score === 'number' && !isNaN(f.risk_score)) {
    return Math.max(0, Math.min(100, Math.round(f.risk_score)));
  }
  const band = f.risk_band || f.band || 'safe';
  const isShor = Boolean(f.shor_vulnerable || f.shorVulnerable);
  const confidence = typeof f.confidence === 'number' && !isNaN(f.confidence) ? f.confidence : 0.8;
  const rank = BAND_RANK[band] ?? 0;
  const score = rank * 20 + (isShor ? 10 : 0) + Math.round(confidence * 10);
  return Math.max(0, Math.min(100, score));
}

// Where the asset sits in the data lifecycle.
export function deriveLayer(f) {
  if (!f) return 'In transit';
  if (f.layer) {
    if (f.layer === 'in_use') return 'In use';
    if (f.layer === 'at_rest') return 'At rest';
    if (f.layer === 'in_transit') return 'In transit';
    return f.layer;
  }
  if (f.type === 'Algorithm' || f.artifact_type === 'algorithm') return 'In use';
  if (f.type === 'SSH key' || f.type === 'Key' || f.artifact_type === 'key') return 'At rest';
  return 'In transit'; // Certificate, Protocol
}

// How sensitive the data behind this asset is — from its data classification
// where one exists, with sane fallbacks for signature-only / key-material
// findings that carry no dataClassification.
export function deriveSensitivity(f) {
  if (!f) return 'Low';
  if (f.sensitivity) {
    const s = String(f.sensitivity).toLowerCase();
    if (s === 'critical') return 'Critical';
    if (s === 'high') return 'High';
    if (s === 'moderate' || s === 'medium') return 'Medium';
    if (s === 'low') return 'Low';
  }
  const label = f.dataClassification?.label || '';
  if (/financial|payment|customer|account|session|auth/i.test(label)) return 'High';
  if (/internal/i.test(label)) return 'Medium';
  if (/cache|short-lived/i.test(label)) return 'Low';
  if (f.asset === 'kms-master-key') return 'Critical';
  if (f.type === 'SSH key' || f.type === 'Algorithm') return 'Medium';
  return 'Low';
}

// Internal-only vs. internet-facing — informs blast radius.
const EXPOSURE_BY_ASSET = {
  'payments.internal': 'External-facing',
  'legacy-portal.crt': 'External-facing',
  'legacy-build-key': 'Internal-only',
  'deploy-key-01': 'Internal-only',
  'auth-service': 'External-facing',
  'internal-mesh.pem': 'Internal-only',
  'internal-cache': 'Internal-only',
  'database-proxy': 'Internal-only',
  'kms-master-key': 'Internal-only',
};
export function deriveExposure(f) {
  if (!f) return 'Internal-only';
  if (f.exposure_type) {
    return f.exposure_type === 'external' ? 'External-facing' : 'Internal-only';
  }
  return EXPOSURE_BY_ASSET[f.asset] || 'Internal-only';
}

// Which quantum algorithm actually threatens this asset — Shor breaks
// key-exchange/signature outright, Grover only weakens symmetric crypto
// (AES-256 stays safe against it), and classical-only findings aren't a
// quantum-algorithm concern at all.
export function deriveQuantumThreat(f) {
  if (!f) return 'None — classical weakness only';
  if (f.vulnerableSurface === 'symmetric' || f.quantum_class === 'grover') return "Grover's algorithm (weakened only — AES-256 remains safe)";
  if (f.shor_vulnerable || f.shorVulnerable) return "Shor's algorithm";
  return 'None — classical weakness only';
}

// Counts per band, in fixed critical→safe order, for the risk bar chart.
export function getBandCounts(findings = FINDINGS) {
  if (!Array.isArray(findings)) return BAND_ORDER.map((band) => ({ band, label: BAND_LABEL[band], count: 0 }));
  return BAND_ORDER.map((band) => ({
    band,
    label: BAND_LABEL[band],
    count: findings.filter((f) => (f.risk_band || f.band || 'safe') === band).length
  }));
}

// Single 0-100 "Overall risk score" for the whole inventory — the mean QARS
// across every finding, so one freshly-critical asset moves it visibly but
// doesn't singlehandedly dominate it the way "worst case" framing would.
export function computeOverallRiskScore(findings = FINDINGS) {
  if (!Array.isArray(findings) || !findings.length) return 0;
  const scores = findings.map((f) => computeQARS(f)).filter((s) => typeof s === 'number' && !isNaN(s));
  if (!scores.length) return 0;
  return Math.round(scores.reduce((sum, s) => sum + s, 0) / scores.length);
}

// Maps a 0-100 score back onto the band palette so the risk-score square can
// reuse the same colors as everything else.
export function riskScoreBand(score) {
  if (score >= 81) return 'critical';
  if (score >= 61) return 'high';
  if (score >= 41) return 'moderate';
  if (score >= 21) return 'low';
  return 'safe';
}

// Mock cryptographic-asset dependency graph — node risk values are kept in
// sync with FINDINGS wherever the same asset appears in both.
export const GRAPH_NODES = [];
export const GRAPH_LINKS = [];
export const FINDINGS = [];

// Findings that actually need action, ranked by urgency — the same filter
// the Dashboard's "PQC readiness" and "Recommendation" sections use,
// reused here so the Remediator and Mosca Timeline never diverge from it.
export function actionableFindings(findings = FINDINGS) {
  if (!Array.isArray(findings)) return [];
  return [...findings]
    .filter((f) => (f.risk_band || f.band || 'safe') !== 'safe')
    .sort((a, b) => (BAND_RANK[b.risk_band || b.band || 'safe'] || 0) - (BAND_RANK[a.risk_band || a.band || 'safe'] || 0));
}

// Only the subset where Mosca's inequality actually applies (see file header).
export function hndlFindings(findings = FINDINGS) {
  return actionableFindings(findings).filter((f) => {
    const isSig = Boolean(f.signature_only || f.signatureOnly);
    const isHndl = Boolean(f.hndl_relevant || f.hndlRelevant);
    return isHndl && !isSig;
  });
}
export function signatureOnlyFindings(findings = FINDINGS) {
  return actionableFindings(findings).filter((f) => {
    const isSig = Boolean(f.signature_only || f.signatureOnly);
    const isHndl = Boolean(f.hndl_relevant || f.hndlRelevant);
    return isSig || !isHndl;
  });
}

// Projection used by the Dashboard's "before vs. after" bar graph — an
// estimate for planning, not a guarantee, exactly as labeled in the UI.
const PROJECTED_AFTER_FIXES = { safe: 7, low: 1, moderate: 1, high: 0, critical: 0 };
export function getRiskComparison(findings = FINDINGS) {
  if (!Array.isArray(findings)) return BAND_ORDER.slice().reverse().map((band) => ({ band, label: BAND_LABEL[band], current: 0, projected: PROJECTED_AFTER_FIXES[band] || 0 }));
  return BAND_ORDER.slice().reverse().map((band) => ({
    band, label: BAND_LABEL[band],
    current: findings.filter((f) => (f.risk_band || f.band || 'safe') === band).length,
    projected: PROJECTED_AFTER_FIXES[band] || 0,
  }));
}

// ---------------------------------------------------------------------------
// Rough translation from "engineering hours to build the fix" to
// "organizational time to actually roll it out". Coordinated PQC rollouts
// carry planning, vendor/dependency, and staged-deployment overhead well
// beyond the raw coding hours, so this is a fixed minimum plus a
// risk-scaled multiplier on the effort hours — a starting point to
// override in the Mosca Timeline, not a forecast.
// ---------------------------------------------------------------------------
const MIN_ROLLOUT_YEARS = 0.5;
const RISK_MULTIPLIER = { low: 1, medium: 2, high: 3.5 };
const WORK_HOURS_PER_MONTH = 160;

export function estimateMigrationYears(effortHours, breakingChangeRisk) {
  if (!effortHours && effortHours !== 0) return null;
  const engineeringMonths = effortHours / WORK_HOURS_PER_MONTH;
  const rolloutYears = (engineeringMonths / 12) * (RISK_MULTIPLIER[breakingChangeRisk] || 1.5);
  return +(MIN_ROLLOUT_YEARS + rolloutYears).toFixed(2);
}

// ---------------------------------------------------------------------------
// Q-Day: modeled as a probability range, never a single confident year.
// The shape below is illustrative — built to look like the kind of
// expert-survey estimates published by groups such as the Global Risk
// Institute's Quantum Threat Timeline report — not a specific citation.
// Swap in your own organization's risk-register numbers; the simulator
// treats these as editable inputs, not fixed truth.
// ---------------------------------------------------------------------------
export const QDAY_DISTRIBUTION_YEARS_FROM_NOW = { p25: 8, p50: 13, p75: 21 };

// ---------------------------------------------------------------------------
// Compliance mapping tables (Compliance & CBOM Reports page).
// Dates and control IDs reflect publicly published NIST/NSA guidance as
// commonly summarized; both bodies have refined these over time, so treat
// this as a starting map and confirm against the current official advisory
// before using it as evidence in a real audit.
// ---------------------------------------------------------------------------
export const NIST_800_53_CONTROLS = [
  { id: 'SC-8', title: 'Transmission Confidentiality and Integrity', appliesTo: ['key-exchange', 'protocol-version'] },
  { id: 'SC-12', title: 'Cryptographic Key Establishment and Management', appliesTo: ['key-exchange', 'signature'] },
  { id: 'SC-13', title: 'Cryptographic Protection', appliesTo: ['key-exchange', 'signature', 'protocol-version'] },
  { id: 'SC-17', title: 'Public Key Infrastructure Certificates', appliesTo: ['signature'] },
  { id: 'IA-7', title: 'Cryptographic Module Authentication', appliesTo: ['signature'] },
];

export const CNSA2_MILESTONES = [
  { category: 'Software & firmware signing', preferBy: 2025, exclusiveBy: 2030 },
  { category: 'Web browsers, servers & cloud services', preferBy: 2025, exclusiveBy: 2033 },
  { category: 'Traditional networking equipment', preferBy: 2026, exclusiveBy: 2030 },
  { category: 'National security systems (general)', preferBy: 2027, exclusiveBy: 2033 },
];

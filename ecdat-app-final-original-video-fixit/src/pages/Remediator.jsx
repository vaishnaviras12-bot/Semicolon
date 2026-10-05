import React, { useState, useMemo, useEffect } from 'react';
import { Link } from 'react-router-dom';
import Sidebar from '../components/Sidebar.jsx';
import ProfileMenu from '../components/ProfileMenu.jsx';
import { useScan } from '../context/ScanContext.jsx';
import { BAND_LABEL, BAND_COLOR, BAND_COLOR_LIGHT } from '../data/findings.js';
import { runFindingPqcPrototype } from '../api/index.js';
import {
  Sun, Moon, PanelLeft, Search, GitBranch, Copy, Check, ShieldAlert,
  Clock, ArrowRight, AlertCircle, CheckCircle2, Circle, Code2, ChevronDown, ChevronUp,
  FlaskConical, Cpu, CheckCircle, XCircle, HelpCircle,
} from 'lucide-react';

const STATUS_OPTIONS = [
  { key: 'pending', label: 'Pending' },
  { key: 'pr-drafted', label: 'PR drafted' },
  { key: 'merged', label: 'Merged' },
];
const STATUS_ICON = { pending: Circle, 'pr-drafted': AlertCircle, merged: CheckCircle2 };

const safeString = (value) => (typeof value === 'string' ? value : (value != null ? String(value) : ''));

function normalizeRemediation(finding) {
  if (!finding) return null;
  
  const raw = finding.remediation || finding.recommendation || {};
  const diff = raw.remediation_diff || raw.remediationDiff || {};

  const primary = safeString(raw.primary || finding.recommendation?.primary || 'NIST PQC Target');
  const hybrid = safeString(raw.hybrid || finding.recommendation?.hybrid || '');
  const fallback = safeString(raw.fallback || finding.recommendation?.fallback || '');
  const reason = safeString(raw.reason || finding.recommendation?.reason || 'Standardize on NIST PQC standards.');
  const libraryNotes = safeString(raw.library_notes || raw.libraryNotes || finding.recommendation?.library_notes || 'OpenSSL 3.4+ / liboqs / BouncyCastle 1.77+');

  const effortHours = (
    typeof diff.effort_hours === 'number' ? diff.effort_hours :
    (typeof diff.effortHours === 'number' ? diff.effortHours :
    (typeof raw.effort_hours === 'number' ? raw.effort_hours :
    (typeof raw.effortHours === 'number' ? raw.effortHours :
    (typeof finding.migration_effort_hours === 'number' ? finding.migration_effort_hours : 16))))
  );

  const breakingChangeRisk = safeString(
    diff.breaking_change_risk || diff.breakingChangeRisk ||
    raw.breaking_change_risk || raw.breakingChangeRisk ||
    finding.breaking_change_risk || 'medium'
  );

  const isShor = Boolean(finding.shor_vulnerable || finding.shorVulnerable);
  const loc = safeString(finding.location || finding.file_path || 'source');
  const algName = safeString(finding.algorithm || finding.asset || 'cryptographic asset');

  const beforeCode = safeString(diff.before) || safeString(finding.code_snippet) || `# ${algName} in ${loc}`;
  const afterCode = safeString(diff.after) || `// Hybrid bridge for ${algName}\n// Upgrade to ${primary}`;

  const breakingChangeReasons = Array.isArray(raw.breakingChangeReasons)
    ? raw.breakingChangeReasons
    : [
        `Validate the PQC provider, certificate lifecycle, protocol interoperability, test coverage, and staged rollout with the owning team.`
      ];

  return {
    attackModel: isShor ? 'Shor' : finding.quantum_class === 'grover' ? 'Grover' : 'Classical',
    rationale: reason,
    breakingChangeRisk: breakingChangeRisk,
    effortHours: effortHours,
    breakingChangeReasons: breakingChangeReasons,
    bridge: {
      title: `Hybrid Bridge: ${primary}`,
      available: true,
      summary: hybrid ? `Wrap current ${algName} call with hybrid fallback to ${hybrid}.` : `Wrap current ${algName} call with hybrid fallback to ${primary}.`,
      library: libraryNotes,
      before: beforeCode,
      after: afterCode,
      notes: libraryNotes || null
    },
    full: {
      title: `Full PQC Migration: ${primary}`,
      available: true,
      summary: `Replace ${algName} completely with ${primary}.`,
      library: libraryNotes,
      before: beforeCode,
      after: safeString(diff.after) || `// Full PQC replacement of ${algName} with ${primary}`,
      notes: libraryNotes || null
    }
  };
}

function buildPrDescription(finding, choiceKey) {
  if (!finding) return null;
  const rem = normalizeRemediation(finding);
  if (!rem) return null;
  const patch = rem[choiceKey] || rem.bridge || {};
  const assetName = safeString(finding.asset || finding.algorithm || 'crypto-asset');
  const slug = assetName.replace(/[^a-z0-9]+/gi, '-').toLowerCase() || 'asset';
  const branch = `pqc/${safeString(finding.id || 'finding')}-${slug}`;
  const lines = [
    `## ${safeString(patch.title) || 'PQC Remediation Patch'}`,
    '',
    `**Asset:** \`${assetName}\` (${safeString(finding.type || finding.artifact_type || 'Algorithm')}, ${safeString(finding.algorithm || 'N/A')})`,
    `**Finding:** ${safeString(finding.id)} — ${BAND_LABEL[finding.risk_band || finding.band] || 'Finding'} — ${safeString(finding.location || finding.file_path || '—')}`,
    '',
    '### Why',
    safeString(rem.rationale) || 'Post-Quantum Cryptography transition recommended.',
    '',
    '### What this patch does',
    safeString(patch.summary) || 'Apply post-quantum cryptographic remediation patch.',
    '',
    '### Reviewer checklist',
    '- [ ] Backward compatible with clients/peers that haven\'t migrated yet',
    '- [ ] Interop tested against at least one unpatched peer, if applicable',
    '- [ ] Existing tests pass; new coverage added for the changed path',
    `- [ ] Breaking-change risk (${safeString(rem.breakingChangeRisk) || 'medium'}) reviewed: ${(rem.breakingChangeReasons || []).join(' ') || 'n/a'}`,
    '- [ ] Rollback plan confirmed before enabling in production',
    '',
    `_Estimated effort: ~${rem.effortHours ?? 16}h. Drafted by PQC Remediation — human review required before merge._`,
  ];
  return { branch, body: lines.join('\n') };
}

function testStub(finding) {
  if (!finding) return '';
  const assetName = safeString(finding.asset || finding.algorithm || 'asset');
  const lang = safeString(finding.language);
  const algName = safeString(finding.algorithm || 'N/A');
  if (/python|nginx|yaml/i.test(lang)) {
    const slug = assetName.replace(/[^a-z0-9]+/gi, '_').toLowerCase() || 'asset';
    return `def test_${slug}_handshake_uses_hybrid_group():\n    """Fails until the PQC hybrid group is actually negotiated."""\n    negotiated = get_negotiated_group("${assetName}")\n    assert negotiated in {"X25519MLKEM768", "X25519MLKEM1024"}, negotiated`;
  }
  return `test("${assetName} rotates off the flagged algorithm", () => {\n  expect(negotiatedAlgorithm("${assetName}")).not.toBe("${algName}");\n});`;
}

function CodeBlock({ label, tone, code }) {
  const [copied, setCopied] = useState(false);
  if (!code) return null;
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard API unavailable — no-op
    }
  };
  return (
    <div className={`rem-code-block ${tone}`}>
      <div className="rem-code-head">
        <span>{label}</span>
        <button className="rem-copy-btn" onClick={copy}>{copied ? <Check size={12} /> : <Copy size={12} />} {copied ? 'Copied' : 'Copy'}</button>
      </div>
      <pre><code>{code}</code></pre>
    </div>
  );
}

function PatchPanel({ finding, kind }) {
  if (!finding) return null;
  const rem = normalizeRemediation(finding);
  const patch = rem?.[kind] || rem?.bridge;
  if (!patch) return (
    <div className="rem-patch-card">
      <p className="rem-patch-summary" style={{ fontStyle: 'italic', color: 'var(--text-faint)' }}>
        Not provided by recommendation engine for this option.
      </p>
    </div>
  );
  return (
    <div className="rem-patch-card">
      <div className="rem-patch-head">
        <h3>{patch.title || 'PQC Migration Option'}</h3>
        <span className={`rem-avail-pill ${patch.available ? 'yes' : 'no'}`}>
          {patch.available ? 'Ready to apply' : 'Not available upstream yet'}
        </span>
      </div>
      {patch.summary ? (
        <p className="rem-patch-summary">{patch.summary}</p>
      ) : (
        <p className="rem-patch-summary" style={{ fontStyle: 'italic', color: 'var(--text-faint)' }}>
          Summary not provided by recommendation engine.
        </p>
      )}
      {patch.library && <p className="rem-patch-lib"><b>Library / tooling:</b> {patch.library}</p>}
      {(patch.before || patch.after) ? (
        <div className="rem-code-grid">
          <CodeBlock label="BEFORE — DETECTED" tone="before" code={patch.before} />
          <CodeBlock label="AFTER — SUGGESTED" tone="after" code={patch.after} />
        </div>
      ) : (
        <p className="rem-patch-summary" style={{ fontStyle: 'italic', color: 'var(--text-faint)' }}>
          Code diff not provided by recommendation engine.
        </p>
      )}
      {patch.notes && <p className="rem-patch-notes">{patch.notes}</p>}
    </div>
  );
}

function splitFixSuggestion(suggestion) {
  const [explanation, example] = String(suggestion || '').split(/\s*Example:\s*/i, 2);
  return { explanation: explanation.trim(), code: example?.trim() || null };
}

function FixSuggestionPanel({ finding }) {
  if (!finding) return null;
  const normRec = normalizeRemediation(finding);
  const { explanation, code } = splitFixSuggestion(finding?.fixSuggestion || normRec?.rationale);
  const detectedAt = `${safeString(finding?.location || finding?.file_path || 'file')}${finding?.lineNumber ? `:${finding.lineNumber}` : ''}`;
  
  const recText = safeString(
    finding?.fixSuggestion ? explanation : (
      normRec?.rationale || (finding?.recommendation?.primary ? `Use a PQC library like liboqs-java for ${finding.recommendation.primary} instead of ${finding.algorithm}.` : 'Migrate to FIPS 203/204 PQC target.')
    )
  );

  const beforeCode = normRec?.bridge?.before || safeString(finding?.sourceSnippet) || `# ${finding?.algorithm || 'Cryptographic Asset'} in ${detectedAt}`;
  const afterCode = code || normRec?.bridge?.after || `// Upgrade ${finding?.algorithm || 'Asset'} to PQC Target\n// KeyPairGenerator kpg = KeyPairGenerator.getInstance("${finding?.recommendation?.primary || 'ML-KEM-768'}");`;

  return (
    <section className="rem-fix-panel" aria-label="Suggested code fix">
      <div className="rem-fix-heading">
        <div>
          <p className="rem-fix-kicker">BACKEND-GENERATED FIX-IT SUGGESTION</p>
          <h3>Suggested Fix</h3>
        </div>
        <span className="rem-fix-source">From CBOM</span>
      </div>
      <p className="rem-fix-explanation">{recText}</p>
      <div className="rem-code-grid">
        <CodeBlock label="BEFORE — DETECTED" tone="before" code={beforeCode} />
        <CodeBlock label="AFTER — SUGGESTED" tone="after" code={afterCode} />
      </div>
      <p className="rem-fix-disclaimer">Code-level starting point — full migration involves certificate reissuance, protocol updates, and testing across your stack.</p>
      <div className="rem-fix-checklist">
        <p>Detected: <b>{finding?.algorithm || 'Asset'}</b> in <span className="rem-mono">{detectedAt}</span></p>
        <ul>
          <li><CheckCircle2 size={13} style={{ color: 'var(--teal)' }} /> Code fix: shown above</li>
          <li><Circle size={13} /> Certificate reissuance (org-level)</li>
          <li><Circle size={13} /> Protocol renegotiation (org-level)</li>
          <li><Circle size={13} /> Testing &amp; rollout</li>
        </ul>
      </div>
    </section>
  );
}

function ExperimentalPrototypePanel({ finding, scanId }) {
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);

  if (!finding) return null;

  const targetAlg = safeString(finding.algorithm || 'RSA-2048');
  const algUpper = targetAlg.toUpperCase();
  const familyLower = safeString(finding.family).toLowerCase();
  const purposeLower = safeString(finding.purpose).toLowerCase();
  const recPrimaryRaw = safeString(finding.recommendation?.primary || finding.recommendation_json?.primary || '').trim();

  const isHash = familyLower === 'hash' || purposeLower.includes('hash') || ['SHA-1', 'SHA1', 'MD5', 'SHA-224', 'SHA-256', 'SHA-384', 'SHA-512', 'SHA3', 'BLAKE'].some(h => algUpper.includes(h));
  const isSymmetric = familyLower === 'symmetric' || purposeLower === 'encryption' || ['AES', 'CHACHA', '3DES', 'DES', 'BLOWFISH', 'RC4'].some(s => algUpper.includes(s));
  const isMac = familyLower === 'mac' || purposeLower === 'mac' || ['HMAC', 'POLY1305', 'CMAC'].some(m => algUpper.includes(m));
  const isUnknown = purposeLower === 'unknown' || purposeLower === 'ambiguous' || purposeLower === '' || recPrimaryRaw.includes('Manual Cryptographic Review Required');

  let recLabel = 'Recommended PQC:';
  if (isHash || isSymmetric || isMac) {
    recLabel = 'Recommended Replacement:';
  }

  let recommendedPqc = recPrimaryRaw;
  if (isHash && (!recommendedPqc || recommendedPqc.includes('ML-') || recommendedPqc.includes('Manual'))) {
    recommendedPqc = 'SHA-256 / SHA-384';
  } else if (isSymmetric && (!recommendedPqc || recommendedPqc.includes('ML-') || recommendedPqc.includes('Manual'))) {
    recommendedPqc = 'AES-256-GCM';
  } else if (isMac && (!recommendedPqc || recommendedPqc.includes('ML-') || recommendedPqc.includes('Manual'))) {
    recommendedPqc = 'HMAC-SHA256';
  } else if (isUnknown || !recommendedPqc || recommendedPqc.includes('Manual')) {
    recommendedPqc = 'ML-KEM-768 (NIST FIPS 203)';
  }

  const isAutomatedMapping = !isHash && !isSymmetric && !isMac && isUnknown;

  const handleRun = async () => {
    setRunning(true);
    setResult(null);
    try {
      const res = await runFindingPqcPrototype(scanId || 'active', finding.id);
      setResult(res);
    } catch (err) {
      setResult({
        status: 'failed',
        message: 'Error executing PQC prototype endpoint.',
        reason: err.message || String(err),
      });
    } finally {
      setRunning(false);
    }
  };

  return (
    <section className="rem-proto-panel" aria-label="Experimental PQC Prototype">
      <div className="rem-proto-head">
        <div>
          <p className="rem-proto-kicker"><FlaskConical size={13} style={{ verticalAlign: 'middle', marginRight: 4 }} /> EXPERIMENTAL PQC PROTOTYPE</p>
          <h3>Open Quantum Safe (liboqs) Prototype</h3>
        </div>
        <span className="rem-proto-badge">EXPERIMENTAL / PROTOTYPE ONLY</span>
      </div>
      
      <p className="rem-proto-desc">
        Prototype the recommended PQC algorithm using Open Quantum Safe <code>liboqs</code> to evaluate how the proposed migration would work.
      </p>

      <div className="rem-proto-notice">
        <Cpu size={13} /> Does not modify the scanned application or production cryptographic configuration.
      </div>

      <div className="rem-proto-meta-grid">
        <div><span className="rem-proto-label">Detected:</span> <code className="rem-mono">{targetAlg}</code></div>
        <div><span className="rem-proto-label">{recLabel}</span> <code className="rem-mono" style={{ color: 'var(--gold)' }}>{recommendedPqc}</code></div>
        <div><span className="rem-proto-label">Prototype Library:</span> <code className="rem-mono">liboqs</code></div>
      </div>

      {isAutomatedMapping && (
        <div style={{ marginTop: 10, padding: '10px 12px', borderRadius: 6, background: 'rgba(168, 85, 247, 0.08)', border: '1px solid rgba(168, 85, 247, 0.25)', fontSize: 12, color: 'var(--text-secondary)' }}>
          <b style={{ color: 'var(--purple)', display: 'block', marginBottom: 2 }}>Automated Experimental Mapping</b>
          The operational purpose of this {targetAlg} finding was not explicitly resolved from available evidence. ECDAT uses ML-KEM-768 as the automated experimental migration target. This prototype does not modify the scanned application.
        </div>
      )}

      <div style={{ marginTop: 14 }}>
        <button className="rem-proto-run-btn" onClick={handleRun} disabled={running}>
          <FlaskConical size={14} /> {running ? 'Running PQC prototype…' : 'Run Experimental Prototype'}
        </button>
      </div>

      {result && (
        <div className="rem-proto-results">
          {(result.status === 'passed' || result.status === 'success') && (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div className="rem-proto-verified-banner" style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 14px', background: 'rgba(63,184,175,0.12)', border: '1px solid rgba(63,184,175,0.35)', borderRadius: 8 }}>
                <CheckCircle2 size={22} style={{ color: 'var(--teal)', flexShrink: 0 }} />
                <div>
                  <h4 style={{ margin: 0, color: 'var(--teal)', fontSize: 14.5, fontWeight: 700, letterSpacing: '0.02em' }}>
                    ✓ EXECUTION VERIFIED
                  </h4>
                  <p style={{ margin: '2px 0 0', fontSize: 12, color: 'var(--text-secondary)' }}>
                    Real liboqs execution completed
                  </p>
                </div>
              </div>

              {result.hybrid_note && (
                <div>
                  <span className="rem-mono" style={{ fontSize: 11, padding: '3px 9px', borderRadius: 4, background: 'var(--gold-soft)', color: 'var(--gold)' }}>
                    {result.hybrid_note}
                  </span>
                </div>
              )}

              {(() => {
                const algUpper = String(result.algorithm || recommendedPqc || '').toUpperCase();
                const opMode = String(result.operation || '').toLowerCase();
                const isKem = opMode === 'encapsulate_decapsulate' || opMode.includes('kem') || /ML-KEM|KYBER|FRODOKEM|NTRU/.test(algUpper);
                const isSig = opMode === 'sign_verify' || opMode.includes('sig') || /ML-DSA|DILITHIUM|SLH-DSA|FALCON/.test(algUpper) || !isKem;

                const val = result.validation || {};
                const met = result.metrics || {};

                return (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 12, background: 'var(--surface-1)', padding: '10px 14px', borderRadius: 8, border: '1px solid var(--border-soft)' }}>
                      <div>
                        <span className="rem-proto-label" style={{ fontSize: 11 }}>Algorithm</span>
                        <div className="rem-mono" style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginTop: 2 }}>
                          {result.algorithm || recommendedPqc}
                        </div>
                      </div>
                      <div>
                        <span className="rem-proto-label" style={{ fontSize: 11 }}>Operation</span>
                        <div className="rem-mono" style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginTop: 2 }}>
                          {isKem ? 'Key Encapsulation / Decapsulation' : 'Digital Signature (Sign / Verify)'}
                        </div>
                      </div>
                    </div>

                    {/* Execution Proof Section */}
                    <div>
                      <span className="rem-proto-label" style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8, display: 'block' }}>
                        Execution Proof
                      </span>
                      <div className="rem-proto-val-grid">
                        {val.key_generation != null && (
                          <div className={`rem-val-item ${val.key_generation ? 'pass' : 'fail'}`}>
                            {val.key_generation ? <CheckCircle size={13} /> : <XCircle size={13} />} Key Pair Generated
                          </div>
                        )}

                        {isKem && (
                          <>
                            {val.encapsulation != null && (
                              <div className={`rem-val-item ${val.encapsulation ? 'pass' : 'fail'}`}>
                                {val.encapsulation ? <CheckCircle size={13} /> : <XCircle size={13} />} Encapsulation Completed
                              </div>
                            )}
                            {val.decapsulation != null && (
                              <div className={`rem-val-item ${val.decapsulation ? 'pass' : 'fail'}`}>
                                {val.decapsulation ? <CheckCircle size={13} /> : <XCircle size={13} />} Decapsulation Completed
                              </div>
                            )}
                            {(val.shared_secret_match != null || val.shared_secret_verified != null) && (
                              <div className={`rem-val-item ${(val.shared_secret_match ?? val.shared_secret_verified) ? 'pass' : 'fail'}`}>
                                {(val.shared_secret_match ?? val.shared_secret_verified) ? <CheckCircle size={13} /> : <XCircle size={13} />} {(val.shared_secret_match ?? val.shared_secret_verified) ? 'Shared Secret Matched' : 'Shared Secret Match Failed'}
                              </div>
                            )}
                          </>
                        )}

                        {isSig && !isKem && (
                          <>
                            {val.signing != null && (
                              <div className={`rem-val-item ${val.signing ? 'pass' : 'fail'}`}>
                                {val.signing ? <CheckCircle size={13} /> : <XCircle size={13} />} Message Signed
                              </div>
                            )}
                            {val.verification != null && (
                              <div className={`rem-val-item ${val.verification ? 'pass' : 'fail'}`}>
                                {val.verification ? <CheckCircle size={13} /> : <XCircle size={13} />} Signature Verified
                              </div>
                            )}
                          </>
                        )}
                      </div>
                    </div>

                    {/* Measured Metrics Section */}
                    {met && Object.keys(met).length > 0 && (
                      <div>
                        <span className="rem-proto-label" style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 8, display: 'block' }}>
                          Measured Metrics
                        </span>
                        <div className="rem-proto-metrics-grid">
                          {met.key_generation_ms != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Key Generation</span>
                              <span className="rem-metric-val rem-mono">{met.key_generation_ms} ms</span>
                            </div>
                          )}
                          {isKem && met.encapsulation_ms != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Encapsulation</span>
                              <span className="rem-metric-val rem-mono">{met.encapsulation_ms} ms</span>
                            </div>
                          )}
                          {isKem && met.decapsulation_ms != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Decapsulation</span>
                              <span className="rem-metric-val rem-mono">{met.decapsulation_ms} ms</span>
                            </div>
                          )}
                          {isSig && !isKem && (met.signing_ms ?? met.sign_ms) != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Signing</span>
                              <span className="rem-metric-val rem-mono">{met.signing_ms ?? met.sign_ms} ms</span>
                            </div>
                          )}
                          {isSig && !isKem && (met.verification_ms ?? met.verify_ms) != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Verification</span>
                              <span className="rem-metric-val rem-mono">{met.verification_ms ?? met.verify_ms} ms</span>
                            </div>
                          )}
                          {met.public_key_bytes != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Public Key Size</span>
                              <span className="rem-metric-val rem-mono">{met.public_key_bytes} B</span>
                            </div>
                          )}
                          {isKem && met.ciphertext_bytes != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Ciphertext Size</span>
                              <span className="rem-metric-val rem-mono">{met.ciphertext_bytes} B</span>
                            </div>
                          )}
                          {isKem && met.shared_secret_bytes != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Shared Secret Size</span>
                              <span className="rem-metric-val rem-mono">{met.shared_secret_bytes} B</span>
                            </div>
                          )}
                          {isSig && !isKem && met.signature_bytes != null && (
                            <div className="rem-metric-card">
                              <span className="rem-metric-label">Signature Size</span>
                              <span className="rem-metric-val rem-mono">{met.signature_bytes} B</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    <div style={{ marginTop: 2, fontSize: 11, color: 'var(--text-faint)' }}>
                      Engine: <code className="rem-mono">{result.library || 'liboqs'}</code>
                    </div>
                  </div>
                );
              })()}
            </div>
          )}

          {result.status === 'not_applicable' && (
            <div className="rem-proto-unavail" style={{ borderLeftColor: 'var(--teal)' }}>
              <h4 style={{ margin: '0 0 4px', color: 'var(--teal)', fontSize: 13 }}>
                <CheckCircle2 size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Prototype Not Applicable for Hash Functions
              </h4>
              <p style={{ margin: '0 0 6px', fontSize: 12, color: 'var(--text-secondary)' }}>{result.reason || result.message}</p>
              <p style={{ margin: 0, fontSize: 11, color: 'var(--text-faint)' }}>{result.setup_info}</p>
            </div>
          )}

          {result.status === 'unavailable' && (
            <div className="rem-proto-unavail">
              <h4 style={{ margin: '0 0 4px', color: 'var(--gold)', fontSize: 13 }}>
                <HelpCircle size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> liboqs unavailable
              </h4>
              <p style={{ margin: '0 0 6px', fontSize: 12, color: 'var(--text-secondary)' }}>
                The experimental prototype could not be executed in this environment.
              </p>
              <p style={{ margin: '0 0 6px', fontSize: 11.5, color: 'var(--text-faint)' }}>
                <b>Reason:</b> {result.reason || 'liboqs is not installed/configured in the current environment.'}
              </p>
              <p style={{ margin: 0, fontSize: 11, color: 'var(--teal)' }}>
                The scanned application was NOT modified.
              </p>
            </div>
          )}

          {result.status === 'unsupported' && (
            <div className="rem-proto-unavail" style={{ borderLeftColor: 'var(--gold)' }}>
              <h4 style={{ margin: '0 0 4px', color: 'var(--gold)', fontSize: 13 }}>
                <AlertCircle size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> PQC Prototype Requires Review
              </h4>
              <p style={{ margin: '0 0 6px', fontSize: 12, color: 'var(--text-secondary)' }}>{result.reason || result.message}</p>
              <p style={{ margin: 0, fontSize: 11, color: 'var(--text-faint)' }}>{result.setup_info}</p>
            </div>
          )}

          {result.status === 'needs_review' && (
            <div className="rem-proto-unavail" style={{ borderLeftColor: 'var(--purple)' }}>
              <h4 style={{ margin: '0 0 4px', color: 'var(--purple)', fontSize: 13 }}>
                <AlertCircle size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> Manual Purpose Resolution Required
              </h4>
              <p style={{ margin: '0 0 6px', fontSize: 12, color: 'var(--text-secondary)' }}>{result.reason || result.message}</p>
              {Array.isArray(result.candidate_algorithms) && result.candidate_algorithms.length > 0 && (
                <p style={{ margin: '0 0 6px', fontSize: 11.5, color: 'var(--text-primary)' }}>
                  <b>Candidate PQC Algorithms:</b> {result.candidate_algorithms.join(', ')}
                </p>
              )}
              <p style={{ margin: 0, fontSize: 11, color: 'var(--text-faint)' }}>{result.setup_info}</p>
            </div>
          )}

          {result.status === 'failed' && (
            <div className="rem-proto-unavail" style={{ borderLeftColor: 'var(--crimson)' }}>
              <h4 style={{ margin: '0 0 4px', color: 'var(--crimson)', fontSize: 13 }}>
                <XCircle size={14} style={{ verticalAlign: 'middle', marginRight: 4 }} /> ✕ EXECUTION FAILED
              </h4>
              <p style={{ margin: '0 0 4px', fontSize: 12, color: 'var(--text-secondary)' }}>The liboqs prototype execution did not pass validation.</p>
              <p style={{ margin: 0, fontSize: 11, color: 'var(--crimson)' }}>{result.reason || result.message}</p>
            </div>
          )}
        </div>
      )}
    </section>
  );
}

export default function Remediator() {
  const {
    theme, toggleTheme, sidebarOpen, toggleSidebar,
    scanState, actionable, activeScanId, patchChoice, setChoice, remediationStatus, setStatus,
    totalEffortHours, remediatedCount,
  } = useScan();

  const bandColors = theme === 'light' ? BAND_COLOR_LIGHT : BAND_COLOR;
  const [query, setQuery] = useState('');
  const [selectedId, setSelectedId] = useState(null);
  const [prOpen, setPrOpen] = useState(false);
  const [prCopied, setPrCopied] = useState(false);
  const [fixOpen, setFixOpen] = useState(true);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list = Array.isArray(actionable) ? actionable : [];
    if (!q) return list;
    return list.filter((f) => `${safeString(f.asset)} ${safeString(f.algorithm)} ${safeString(f.location || f.file_path)}`.toLowerCase().includes(q));
  }, [actionable, query]);

  useEffect(() => {
    if (!selectedId && filtered.length) setSelectedId(filtered.find((f) => f.fixSuggestion)?.id || filtered[0].id);
  }, [filtered, selectedId]);

  useEffect(() => {
    setPrOpen(false);
    setPrCopied(false);
  }, [selectedId]);

  const selected = actionable.find((f) => f.id === selectedId) || null;

  if (selected) {
    console.log("REMEDIATION FINDING", selected.id, selected.recommendation);
    console.log("REMEDIATION DIFF", selected.recommendation?.remediation_diff);
  }

  const remediationData = useMemo(() => {
    return normalizeRemediation(selected);
  }, [selected]);

  const choice = selected ? (patchChoice[selected.id] || 'bridge') : null;
  const pr = selected && choice && remediationData ? buildPrDescription(selected, choice) : null;
  
  const copyPr = async () => {
    if (!pr) return;
    try {
      await navigator.clipboard.writeText(`git checkout -b ${pr.branch}\n\n${pr.body}`);
      setPrCopied(true);
      window.setTimeout(() => setPrCopied(false), 1500);
    } catch { /* no-op */ }
  };

  return (
    <div className="rem-shell" data-theme={theme}>
      <style>{`
        .rem-shell {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border: #262e3a; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e;
          --gold: #c9a227; --gold-soft: rgba(201,162,39,0.14);
          --crimson: #c1503a; --teal: #3fb8af; --purple: #a855f7;
          font-family: 'Switzer', 'Inter', system-ui, sans-serif;
          background: var(--bg); color: var(--text-primary);
          min-height: 100vh; display: flex; width: 100%; box-sizing: border-box;
        }
        .rem-shell[data-theme="light"] {
          --bg: #f4f2ec; --surface-1: #ffffff; --surface-2: #ece9e0;
          --border: #dad6c9; --border-soft: #e4e1d6;
          --text-primary: #1b1d22; --text-secondary: #5b5e66; --text-faint: #8b8d93;
          --gold: #9c7a14; --gold-soft: rgba(156,122,20,0.12);
          --crimson: #a63f2b; --teal: #227a70; --purple: #7e22ce;
        }
        .rem-shell *, .rem-shell *::before, .rem-shell *::after { box-sizing: border-box; }
        .rem-display { font-family: 'Clash Display', 'Switzer', sans-serif; }
        .rem-mono { font-family: 'IBM Plex Mono', monospace; }
        .rem-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
        .rem-topbar {
          display: flex; align-items: center; justify-content: space-between;
          padding: 18px 28px; border-bottom: 1px solid var(--border-soft);
          position: sticky; top: 0; background: var(--bg); z-index: 5;
        }
        .rem-topbar h1 { font-size: 21px; font-weight: 600; margin: 0; letter-spacing: -0.01em; }
        .rem-top-actions { display: flex; align-items: center; gap: 14px; }
        .rem-theme-btn {
          width: 32px; height: 32px; border-radius: 7px; border: 1px solid var(--border);
          background: var(--surface-1); color: var(--text-secondary); cursor: pointer;
          display: flex; align-items: center; justify-content: center;
        }
        .rem-theme-btn:hover { color: var(--gold); border-color: var(--gold); }
        .rem-content { padding: 22px 28px 90px; overflow-x: hidden; }
        .rem-empty {
          border: 1px dashed var(--border); border-radius: 10px; padding: 60px 24px;
          text-align: center; color: var(--text-secondary);
        }
        .rem-empty h2 { color: var(--text-primary); font-size: 17px; margin: 0 0 10px; }
        .rem-empty p { font-size: 13.5px; max-width: 440px; margin: 0 auto 18px; line-height: 1.6; }
        .rem-empty-btn {
          display: inline-flex; align-items: center; gap: 8px; background: var(--gold); color: #191308;
          font-weight: 600; font-size: 13.5px; padding: 10px 20px; border-radius: 7px; text-decoration: none;
        }

        .rem-layout { display: grid; grid-template-columns: 320px minmax(0,1fr); gap: 16px; align-items: start; }
        .rem-list-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 14px; }
        .rem-search {
          display: flex; align-items: center; gap: 8px; background: var(--surface-2); border: 1px solid var(--border-soft);
          border-radius: 7px; padding: 8px 10px; margin-bottom: 10px;
        }
        .rem-search input { border: none; background: none; outline: none; color: var(--text-primary); font-size: 13px; width: 100%; font-family: inherit; }
        .rem-search svg { color: var(--text-faint); flex-shrink: 0; }
        .rem-finding-item {
          width: 100%; text-align: left; padding: 10px; border-radius: 8px; border: 1px solid transparent;
          background: none; cursor: pointer; font-family: inherit; margin-bottom: 4px; display: block;
          transition: background 0.15s ease, border-color 0.15s ease;
        }
        .rem-finding-item:hover { background: var(--surface-2); }
        .rem-finding-item.active { background: var(--gold-soft); border-color: var(--gold); }
        .rem-finding-top { display: flex; align-items: center; justify-content: space-between; gap: 8px; margin-bottom: 4px; }
        .rem-finding-asset { font-size: 13px; font-weight: 600; color: var(--text-primary); }
        .rem-finding-meta { font-size: 11.5px; color: var(--text-faint); }
        .rem-band-pill { font-size: 10.5px; padding: 2px 8px; border-radius: 5px; font-weight: 500; white-space: nowrap; }
        .rem-hndl-tag { font-size: 10px; color: var(--text-faint); display: flex; align-items: center; gap: 4px; margin-top: 4px; }

        .rem-detail-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 22px; }
        .rem-detail-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; flex-wrap: wrap; margin-bottom: 6px; }
        .rem-detail-title { font-size: 18px; font-weight: 600; margin: 0 0 4px; }
        .rem-detail-sub { font-size: 12.5px; color: var(--text-faint); margin: 0; }
        .rem-status-select { display: flex; gap: 6px; }
        .rem-status-btn {
          display: flex; align-items: center; gap: 5px; font-size: 11.5px; padding: 5px 10px; border-radius: 6px;
          border: 1px solid var(--border); background: var(--surface-2); color: var(--text-secondary); cursor: pointer; font-family: inherit;
        }
        .rem-status-btn.active { border-color: var(--gold); color: var(--gold); background: var(--gold-soft); }

        .rem-rationale {
          background: var(--surface-2); border-radius: 8px; padding: 14px; margin: 16px 0; font-size: 12.5px;
          line-height: 1.65; color: var(--text-secondary); border: 1px solid var(--border-soft);
        }
        .rem-rationale b { color: var(--text-primary); }
        .rem-flags { display: flex; gap: 8px; flex-wrap: wrap; margin: 12px 0 6px; align-items: center; }
        .rem-flag { font-size: 11px; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); color: var(--text-secondary); }
        .rem-flag.risk-medium { color: var(--gold); border-color: var(--gold); }
        .rem-flag.risk-high { color: var(--crimson); border-color: var(--crimson); }
        .rem-reasons { font-size: 12px; color: var(--text-faint); margin: 6px 0 0; padding-left: 18px; line-height: 1.6; }

        .rem-fix-panel { margin: 18px 0; border: 1px solid rgba(63,184,175,0.38); background: rgba(63,184,175,0.06); border-radius: 10px; padding: 16px; }
        .rem-fix-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
        .rem-fix-heading h3 { margin: 3px 0 0; font-size: 15px; color: var(--text-primary); }
        .rem-fix-kicker { margin: 0; font-size: 10.5px; color: var(--teal); letter-spacing: 0.08em; font-family: 'IBM Plex Mono', monospace; font-weight: 600; }
        .rem-fix-source { color: var(--teal); background: rgba(63,184,175,0.14); padding: 3px 9px; border-radius: 999px; font-size: 10.5px; font-weight: 500; }
        .rem-fix-explanation { font-size: 13px; color: var(--text-primary); margin: 10px 0 14px; line-height: 1.55; }
        .rem-fix-disclaimer { border-left: 3px solid var(--gold); color: var(--text-secondary); font-size: 12px; line-height: 1.55; margin: 14px 0; padding: 8px 12px; background: var(--surface-2); }
        .rem-fix-checklist { margin-top: 14px; font-size: 12px; color: var(--text-secondary); }
        .rem-fix-checklist p { margin: 0 0 8px; }
        .rem-fix-checklist ul { list-style: none; padding: 0; margin: 0; display: grid; gap: 6px; }
        .rem-fix-checklist li { display: flex; align-items: center; gap: 8px; }

        .rem-code-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin: 6px 0; }
        .rem-code-block { border-radius: 8px; overflow: hidden; border: 1px solid var(--border-soft); }
        .rem-code-block.before { border-color: rgba(193,80,58,0.35); }
        .rem-code-block.after { border-color: rgba(63,184,175,0.35); }
        .rem-code-head {
          display: flex; align-items: center; justify-content: space-between; font-size: 10.5px; padding: 6px 12px;
          text-transform: uppercase; letter-spacing: 0.04em; font-family: 'IBM Plex Mono', monospace; font-weight: 600;
        }
        .rem-code-block.before .rem-code-head { background: rgba(193,80,58,0.14); color: var(--crimson); }
        .rem-code-block.after .rem-code-head { background: rgba(63,184,175,0.14); color: var(--teal); }
        .rem-copy-btn { display: flex; align-items: center; gap: 4px; background: none; border: none; color: inherit; cursor: pointer; font-family: inherit; font-size: 10.5px; }
        .rem-code-block pre { margin: 0; padding: 12px; overflow-x: auto; background: var(--surface-2); }
        .rem-code-block code { font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; line-height: 1.6; color: var(--text-primary); white-space: pre; }

        /* Experimental PQC Prototype Panel */
        .rem-proto-panel {
          margin: 20px 0; border: 1px solid rgba(168, 85, 247, 0.4); background: rgba(168, 85, 247, 0.05);
          border-radius: 10px; padding: 18px;
        }
        .rem-proto-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
        .rem-proto-head h3 { margin: 3px 0 0; font-size: 15px; color: var(--text-primary); }
        .rem-proto-kicker { margin: 0; font-size: 10.5px; color: var(--purple); letter-spacing: 0.08em; font-family: 'IBM Plex Mono', monospace; font-weight: 600; }
        .rem-proto-badge { color: var(--purple); background: rgba(168, 85, 247, 0.14); padding: 3px 9px; border-radius: 999px; font-size: 10.5px; font-weight: 600; }
        .rem-proto-desc { font-size: 12.5px; color: var(--text-secondary); margin: 8px 0; line-height: 1.55; }
        .rem-proto-notice { font-size: 11.5px; color: var(--text-faint); margin-bottom: 12px; display: flex; align-items: center; gap: 6px; }
        .rem-proto-meta-grid { display: flex; gap: 18px; font-size: 12px; background: var(--surface-2); padding: 10px 14px; border-radius: 8px; flex-wrap: wrap; }
        .rem-proto-label { color: var(--text-faint); margin-right: 4px; }
        .rem-proto-run-btn {
          display: inline-flex; align-items: center; gap: 8px; padding: 9px 18px; border-radius: 7px;
          background: var(--purple); color: #ffffff; font-weight: 600; font-size: 12.5px; border: none; cursor: pointer;
        }
        .rem-proto-run-btn:disabled { opacity: 0.6; cursor: wait; }
        .rem-proto-results { margin-top: 14px; background: var(--surface-2); border-radius: 8px; padding: 14px; border: 1px solid var(--border-soft); }
        .rem-proto-res-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
        .rem-proto-status-pill { font-size: 11px; padding: 3px 9px; border-radius: 5px; font-weight: 700; text-transform: uppercase; }
        .rem-proto-status-pill.passed { background: rgba(63,184,175,0.2); color: var(--teal); }
        .rem-proto-status-pill.failed { background: rgba(193,80,58,0.2); color: var(--crimson); }
        .rem-proto-status-pill.unavailable { background: rgba(201,162,39,0.2); color: var(--gold); }
        .rem-proto-status-pill.needs_review { background: rgba(168,85,247,0.2); color: var(--purple); }
        .rem-proto-val-grid { display: flex; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
        .rem-val-item { font-size: 12px; display: flex; align-items: center; gap: 5px; color: var(--teal); }
        .rem-proto-metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-top: 10px; }
        .rem-metric-card { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 6px; padding: 8px 10px; display: flex; flex-direction: column; }
        .rem-metric-label { font-size: 10.5px; color: var(--text-faint); }
        .rem-metric-val { font-size: 13px; font-weight: 600; color: var(--gold); margin-top: 2px; }
        .rem-proto-unavail { border-left: 3px solid var(--gold); padding: 10px 12px; background: var(--surface-1); border-radius: 4px; }

        .rem-actions-row { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 18px; }
        .rem-action-btn {
          display: flex; align-items: center; gap: 8px; padding: 10px 16px; border-radius: 7px; font-size: 13px; font-weight: 500;
          cursor: pointer; font-family: inherit; border: 1px solid var(--border); background: var(--surface-2); color: var(--text-primary); text-decoration: none;
        }
        .rem-action-btn.primary { background: var(--gold); color: #191308; border-color: var(--gold); font-weight: 600; }
        .rem-action-btn:hover { border-color: var(--gold); color: var(--gold); }
        .rem-action-btn.primary:hover { color: #191308; filter: brightness(1.07); }

        .rem-pr-panel { margin-top: 14px; border: 1px solid var(--border-soft); border-radius: 10px; overflow: hidden; }
        .rem-pr-head { display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; background: var(--surface-2); font-size: 12.5px; }
        .rem-pr-body { padding: 14px; background: var(--bg); }
        .rem-pr-body pre { margin: 0; font-family: 'IBM Plex Mono', monospace; font-size: 11.5px; line-height: 1.6; white-space: pre-wrap; color: var(--text-secondary); }

        .rem-test-stub { margin-top: 18px; }
        .rem-test-stub h4 { font-size: 12.5px; color: var(--text-secondary); margin: 0 0 8px; font-weight: 500; }

        .rem-summary-bar {
          position: sticky; bottom: 0; margin-top: 18px; background: var(--surface-1); border: 1px solid var(--border-soft);
          border-radius: 10px; padding: 14px 18px; display: flex; align-items: center; justify-content: space-between;
          flex-wrap: wrap; gap: 10px; font-size: 13px;
        }
        .rem-summary-bar b { color: var(--gold); }

        @media (max-width: 980px) {
          .rem-layout { grid-template-columns: 1fr; }
          .rem-code-grid { grid-template-columns: 1fr; }
        }
      `}</style>

      <Sidebar activeKey="remediator" />

      <div className="rem-main">
        <header className="rem-topbar">
          <h1 className="rem-display">PQC Remediation</h1>
          <div className="rem-top-actions">
            <button className="rem-theme-btn" onClick={toggleTheme} aria-label="Toggle dark mode">
              {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
            </button>
            <button className="rem-theme-btn" onClick={toggleSidebar} aria-label="Toggle sidebar">
              <PanelLeft size={15} />
            </button>
            <ProfileMenu />
          </div>
        </header>

        <div className="rem-content">
          {scanState !== 'complete' ? (
            <div className="rem-empty">
              <ShieldAlert size={30} style={{ color: 'var(--text-faint)', marginBottom: 14 }} />
              <h2>No scan loaded yet</h2>
              <p>The Remediator works from a completed scan's findings. Run a scan on the dashboard first, then come back here for per-finding patches.</p>
              <Link to="/dashboard#sec-upload" className="rem-empty-btn">Go scan a file <ArrowRight size={14} /></Link>
            </div>
          ) : (
            <>
              <div className="rem-layout">
                {/* Left Finding List */}
                <div className="rem-list-card">
                  <div className="rem-search">
                    <Search size={14} />
                    <input placeholder="Filter findings…" value={query} onChange={(e) => setQuery(e.target.value)} />
                  </div>
                  {filtered.map((f) => {
                    const status = remediationStatus[f.id] || 'pending';
                    const StatusIcon = STATUS_ICON[status];
                    const b = f.risk_band || f.band || 'safe';
                    const assetName = f.asset || f.algorithm || f.id || 'Asset';
                    const confVal = typeof f.confidence === 'number' ? f.confidence : 0.8;
                    const isHndl = Boolean(f.hndl_relevant || f.hndlRelevant);
                    return (
                      <button
                        key={f.id}
                        className={`rem-finding-item ${selectedId === f.id ? 'active' : ''}`}
                        onClick={() => setSelectedId(f.id)}
                      >
                        <div className="rem-finding-top">
                          <span className="rem-finding-asset">{assetName}</span>
                          <span className="rem-band-pill" style={{ color: bandColors[b], background: `${bandColors[b]}22` }}>{BAND_LABEL[b]}</span>
                        </div>
                        <div className="rem-finding-meta rem-mono">{f.algorithm} · confidence {confVal.toFixed(2)}</div>
                        <div className="rem-hndl-tag">
                          <StatusIcon size={11} /> {STATUS_OPTIONS.find((s) => s.key === status)?.label} {!isHndl ? ' · signature-only' : ''}
                        </div>
                      </button>
                    );
                  })}
                  {!filtered.length && <p style={{ fontSize: 12.5, color: 'var(--text-faint)', padding: 10 }}>No findings match that filter.</p>}
                </div>

                {/* Right Remediation Workspace */}
                {selected && remediationData ? (
                  <div className="rem-detail-card">
                    <div className="rem-detail-head">
                      <div>
                        <h2 className="rem-detail-title rem-display">{selected.asset || selected.algorithm}</h2>
                        <p className="rem-detail-sub rem-mono">{selected.algorithm} · confidence {typeof selected.confidence === 'number' ? selected.confidence.toFixed(2) : '0.80'} · {selected.location || selected.file_path || '—'}</p>
                      </div>
                      <div className="rem-status-select">
                        {STATUS_OPTIONS.map((opt) => (
                          <button
                            key={opt.key}
                            className={`rem-status-btn ${(remediationStatus[selected.id] || 'pending') === opt.key ? 'active' : ''}`}
                            onClick={() => setStatus(selected.id, opt.key)}
                          >
                            {opt.label}
                          </button>
                        ))}
                      </div>
                    </div>

                    <div className="rem-rationale">
                      {(selected.hndlRelevant || selected.hndl_relevant) && !selected.signatureOnly && !selected.signature_only ? (
                        <>
                          <Clock size={13} style={{ flexShrink: 0, display: 'inline', marginRight: 6 }} />
                          This finding feeds the Mosca Timeline — it's a confidentiality/key-exchange exposure with real stored-traffic risk.
                        </>
                      ) : (
                        <>
                          <ShieldAlert size={13} style={{ flexShrink: 0, display: 'inline', marginRight: 6 }} />
                          Signature-forgery risk: signature keys do not encrypt data, so there is no stored ciphertext to harvest. The risk is forgery post-Q-Day.{' '}
                          <Link to="/mosca-timeline#sec-signature-risk" style={{ color: 'var(--gold)', textDecoration: 'underline', marginLeft: 4 }}>
                            See Signature Forgery Risk on Mosca Timeline →
                          </Link>
                        </>
                      )}
                    </div>

                    <div className="rem-flags">
                      <span className={`rem-flag risk-${safeString(remediationData.breakingChangeRisk || 'medium')}`}>
                        Breaking-change risk: {safeString(remediationData.breakingChangeRisk) || 'Not specified'}
                      </span>
                      <span className="rem-flag">
                        ~{remediationData.effortHours != null ? `${remediationData.effortHours}h` : 'Not specified'} estimated effort
                      </span>
                    </div>
                    {!!(Array.isArray(remediationData.breakingChangeReasons) && remediationData.breakingChangeReasons.length) && (
                      <ul className="rem-reasons">
                        {remediationData.breakingChangeReasons.map((r, i) => <li key={i}>• {r}</li>)}
                      </ul>
                    )}

                    {/* Toggle Fix Suggestion */}
                    <div className="rem-actions-row" style={{ marginTop: 16 }}>
                      <button className="rem-action-btn" onClick={() => setFixOpen((open) => !open)}>
                        <Code2 size={15} /> {fixOpen ? 'Hide suggested fix' : 'View suggested fix'} {fixOpen ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
                      </button>
                    </div>

                    {/* Backend Fix Suggestion */}
                    {fixOpen && <FixSuggestionPanel finding={selected} />}

                    {/* Experimental PQC Prototype Section */}
                    <ExperimentalPrototypePanel finding={selected} scanId={activeScanId} />

                    {/* Scaffolded Test Section */}
                    <div className="rem-test-stub">
                      <h4>Scaffolded test (illustrative)</h4>
                      <CodeBlock label={/python|nginx|yaml/i.test(selected.language) ? 'test_*.py' : 'TEST.SPEC.JS'} tone="after" code={testStub(selected)} />
                    </div>

                    {/* Action Buttons */}
                    <div className="rem-actions-row">
                      <button className="rem-action-btn primary" onClick={() => setPrOpen((o) => !o)}>
                        <GitBranch size={15} /> {prOpen ? 'Hide' : 'Generate'} branch + PR description
                      </button>
                      <Link to="/mosca-timeline" className="rem-action-btn">
                        <Clock size={15} /> See effect on breach window <ArrowRight size={13} />
                      </Link>
                    </div>

                    {prOpen && pr && (
                      <div className="rem-pr-panel">
                        <div className="rem-pr-head">
                          <span className="rem-mono">git checkout -b {pr.branch}</span>
                          <button className="rem-copy-btn" onClick={copyPr} style={{ color: 'var(--gold)' }}>
                            {prCopied ? <Check size={12} /> : <Copy size={12} />} {prCopied ? 'Copied' : 'Copy branch + PR body'}
                          </button>
                        </div>
                        <div className="rem-pr-body"><pre>{pr.body}</pre></div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="rem-detail-card" style={{ textAlign: 'center', padding: '60px 24px', color: 'var(--text-secondary)' }}>
                    <HelpCircle size={30} style={{ color: 'var(--text-faint)', marginBottom: 14 }} />
                    <h3>Select a finding to view PQC remediation</h3>
                    <p style={{ fontSize: 13, maxWidth: 400, margin: '0 auto' }}>Select a cryptographic finding from the inventory list on the left to inspect PQC patch recommendations and run experimental prototypes.</p>
                  </div>
                )}
              </div>

              <div className="rem-summary-bar">
                <span>Portfolio effort: <b>{totalEffortHours}h</b> across {actionable.length} findings</span>
                <span><b>{remediatedCount}</b> of {actionable.length} marked merged</span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}

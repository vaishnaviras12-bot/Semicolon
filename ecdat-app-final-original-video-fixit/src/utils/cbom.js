// Maps the CBOM contract produced by the ECDAT backend into the shape used by
// the dashboard and Remediator. `fix_suggestion` is deliberately kept as the
// backend returned it: the UI separates its explanation and code only for
// presentation, without rewriting the recommendation.

const RISK_BY_ALGORITHM = {
  RSA: 'high',
  MD5: 'critical',
  'SHA-1': 'high',
  DES: 'high',
  '3DES': 'high',
};

const SHOR_VULNERABLE = new Set(['RSA', 'ECC', 'ECDSA', 'EC', 'DSA']);

function basename(path = '') {
  const parts = String(path).split('/');
  return parts[parts.length - 1] || 'Detected crypto asset';
}

function languageFromPath(path = '') {
  const lower = String(path).toLowerCase();
  if (lower.endsWith('.py')) return 'Python';
  if (lower.endsWith('.java')) return 'Java';
  if (lower.endsWith('.js') || lower.endsWith('.ts')) return 'JavaScript / TypeScript';
  if (lower.endsWith('.c') || lower.endsWith('.cpp') || lower.endsWith('.h')) return 'C / C++';
  return 'Unknown';
}

function riskFor(component) {
  if (component.recommendation?.already_quantum_safe) return 'safe';
  return RISK_BY_ALGORITHM[component.algorithm] || 'moderate';
}

function remediationFor(component, occurrence, band) {
  const isShor = SHOR_VULNERABLE.has(String(component.algorithm).toUpperCase());
  const recommended = component.recommendation?.recommended_alternative || 'Review the recommended replacement with the platform owner.';
  const rationale = component.recommendation?.rationale || 'This cryptographic component needs engineering review before production remediation.';
  const hasFix = Boolean(component.fix_suggestion);

  return {
    attackModel: isShor ? 'Shor' : 'classical-only',
    rationale,
    breakingChangeRisk: band === 'critical' ? 'high' : band === 'high' ? 'medium' : 'low',
    breakingChangeReasons: hasFix
      ? ['The backend supplied a code-level starting point. Validate library availability, compatibility, and rollout requirements before making a production change.']
      : ['No code-level template was returned for this algorithm/language combination. Review the recommendation with the owning team.'],
    effortHours: 16,
    bridge: {
      available: hasFix,
      title: hasFix ? 'Backend-guided code change' : 'No code template available',
      summary: hasFix ? 'Open Suggested Fix below to review the exact example attached to this CBOM component.' : recommended,
      library: null,
      before: occurrence?.code_snippet || null,
      after: null,
      notes: null,
    },
    full: {
      available: false,
      title: 'Organization-level migration required',
      summary: 'Plan certificate, protocol, interoperability, testing, and rollout work with the owning team.',
      library: null,
      before: null,
      after: null,
      notes: null,
    },
  };
}

export function isCbomOutput(value) {
  return Boolean(value && Array.isArray(value.components));
}

export function cbomToFindings(cbom) {
  return cbom.components
    .filter((component) => component?.algorithm && component.algorithm !== 'UNSPECIFIED')
    .map((component, index) => {
      const occurrence = component.occurrences?.[0] || {};
      const band = riskFor(component);
      const algorithm = component.key_size ? `${component.algorithm}-${component.key_size}` : component.algorithm;
      const location = occurrence.file_path || component.files_affected?.[0] || 'Unknown location';
      const algUpper = String(component.algorithm || '').toUpperCase();
      const purposeLower = String(component.purpose || '').toLowerCase();
      const isStrictlySigAlg = ['ECDSA', 'DSA', 'ED25519', 'ED448'].some((k) => algUpper.includes(k));
      const isSigPurpose = purposeLower.includes('sign') && !purposeLower.includes('encrypt') && !purposeLower.includes('exchange');

      const signatureOnly = component.signature_only ?? (isStrictlySigAlg || (algUpper.includes('RSA') && isSigPurpose));
      const hndlRelevant = component.hndl_relevant ?? (isShor && !signatureOnly && component.cbom_category !== 'Hash Function');

      return {
        id: component.cbom_entry_id || `cbom-${index}`,
        asset: basename(location),
        type: component.cbom_category || 'Cryptographic component',
        algorithm,
        sourceAlgorithm: component.algorithm,
        confidence: occurrence.confidence ?? component.max_confidence ?? 0,
        location,
        lineNumber: occurrence.line_number ?? null,
        language: languageFromPath(location),
        sourceSnippet: occurrence.code_snippet || null,
        fixSuggestion: component.fix_suggestion || null,
        fromCbom: true,
        shorVulnerable: isShor,
        signatureOnly: Boolean(signatureOnly),
        hndlRelevant: Boolean(hndlRelevant) && !signatureOnly,
        band,
        recommendation: {
          primary: component.recommendation?.recommended_alternative || 'Manual review required',
          fallback: '—',
          fallback2: '—',
          effort: 'To be estimated',
        },
        vulnerableSurface: isShor ? (signatureOnly ? 'signature-forgery' : 'key-exchange') : 'classical-weakness',
        dataClassification: null,
        remediation: remediationFor(component, occurrence, band),
      };
    });
}

// ---------------------------------------------------------------------------
// Mosca's inequality, modeled honestly:
//
//   X = required data secrecy shelf-life (years)
//   Y = time needed to migrate this asset (years)
//   Z = time until a cryptographically-relevant quantum computer exists (years)
//
// The classic formulation treats Z as a single date. We treat it as a
// distribution (p25 / p50 / p75) because that's what the underlying expert
// surveys actually produce, and presenting a point estimate implies far more
// certainty than anyone studying this actually has. "Breach window" below is
// computed at each percentile rather than once.
// ---------------------------------------------------------------------------

// requiredUntil = X + Y: the year (offset from today) until which this
// asset's data must stay confidential, accounting for how long migration
// itself will take.
export function requiredUntilYears(shelfLifeYears, migrationYears) {
  return (shelfLifeYears || 0) + (migrationYears || 0);
}

// Breach window at a given Q-Day estimate: how many years past the point
// where confidentiality was required, adversary decryption capability
// arrives. Zero or negative means safe at that percentile.
export function breachWindowAt(requiredUntil, qDayYears) {
  return +(requiredUntil - qDayYears).toFixed(2);
}

// Full three-scenario breakdown for one asset against a Q-Day distribution.
export function computeBreach(shelfLifeYears, migrationYears, qdayDist) {
  const requiredUntil = requiredUntilYears(shelfLifeYears, migrationYears);
  const atP25 = breachWindowAt(requiredUntil, qdayDist.p25); // pessimistic: quantum arrives soonest
  const atP50 = breachWindowAt(requiredUntil, qdayDist.p50);
  const atP75 = breachWindowAt(requiredUntil, qdayDist.p75); // optimistic: quantum arrives latest
  let status = 'safe';
  if (atP75 > 0) status = 'breach-likely'; // at risk even in the optimistic scenario
  else if (atP50 > 0) status = 'breach-median'; // at risk in the median scenario
  else if (atP25 > 0) status = 'breach-possible'; // only at risk in the pessimistic scenario
  return { requiredUntil, atP25, atP50, atP75, status };
}

export const BREACH_STATUS_LABEL = {
  safe: 'Safe across all scenarios',
  'breach-possible': 'At risk only if Q-Day arrives early',
  'breach-median': 'At risk in the median scenario',
  'breach-likely': 'At risk even in the optimistic scenario',
};
export const BREACH_STATUS_COLOR = {
  safe: '#3fb8af',
  'breach-possible': '#c9a227',
  'breach-median': '#d9772e',
  'breach-likely': '#c1503a',
};

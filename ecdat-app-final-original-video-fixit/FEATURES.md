# New features: PQC Remediation, Mosca HNDL Timeline, Compliance & CBOM Reports

## Round 2 — senior-engineer review fixes

A follow-up pass fixed issues found by reading the actual rendered app (not just the
source) side by side with the code:

- **Renamed "AI Code Remediator" → "PQC Remediation"** everywhere (nav, page title,
  Dashboard feature card, generated PR text) — the feature is a deterministic
  lookup against pre-written patch templates, not a model, so it shouldn't be
  called AI.
- **Removed fabricated stats from the Home page.** "1,204 assets scanned," "LIVE ON
  THIS INSTANCE — 3,918 total scans" etc. were hardcoded, disconnected from any
  data — a real credibility problem next to the rest of the app's careful hedging.
  Replaced with numbers actually computed from `data/findings.js`, labeled as
  example-scan data, plus an honest "How it works" pipeline section.
- **Fixed a factual error in the blog**: the 2011 RSA SecurID remediation cost was
  reported as "$66 billion" — the real, sourced figure is $66 million (EMC's
  disclosed Q2 2011 cost). Off by 1000x in an otherwise carefully-cited article.
- **Fixed citation-numbering drift between the blog and the References page** — the
  blog cited a source as `[7]` that the References page listed as `[6]`. Both pages
  now read from one shared `data/references.js`, the same "no silos" pattern used
  for findings.
- **Fixed the topology graph's overlapping labels** — 16 nodes with always-on text
  labels rendered as illegible noise. Labels now only draw on hover (or heavy
  zoom), with a legibility backdrop; force strength, link distance, and
  auto-fit-to-view were also tuned.
- **Fixed the Recommendation Engine's ambiguous "Finding" column** — it showed only
  the algorithm name, and two different findings share `RSA-1024` and two share
  `ECDSA P-256`, so rows were indistinguishable. Now shows the asset name too.
- **Moved font loading out of 20 duplicated render-blocking `@import`s** (one or two
  per page) **into `index.html`**, loaded once.
- **Added real route protection.** `/dashboard` and the three feature pages were
  reachable by URL with no login at all, despite the site's entire CTA being "Sign
  in." Added a `ProtectedRoute` guard; login now redirects back to wherever the
  person was trying to go.
- **Fixed a dead nav link pair**: "New Scan" and "Previous Scan" in the top nav both
  pointed at the same route. Now point at their respective dashboard sections.
- **Tuned the Mosca Timeline's default numbers** — every asset showed "safe" out of
  the box, which is a weak opening for a tool whose whole point is showing breach
  risk. `payments.internal`'s shelf-life was adjusted to a still-realistic 15 years
  (long-horizon financial data retention), which now visibly breaches at the
  median Q-Day estimate by default.
- **Added an app-wide error boundary.** A throw from the graph canvas, `jsPDF`, or
  `JSZip` used to unmount the whole React tree into a blank white page; it now shows
  a recovery screen.
- **Accessibility baseline**: visible keyboard focus rings on every interactive
  element (`:focus-visible`), `prefers-reduced-motion` support (no lifts, slides, or
  smooth-scroll for users who opt out), and smooth anchor scrolling otherwise.
- **Hero preview card** on the Home page, rendered from the same `FINDINGS` the
  Dashboard uses (readiness score and top four findings by urgency), so the first
  thing a visitor sees is the real product surface, not a stock graphic.
- **Removed a leftover echo of the fake stat** ("before the other 1,203") from the
  blog's closing section.
- **Visual pass**: hover/lift transitions on cards across the Home, Remediator,
  Mosca Timeline, and Compliance pages; active-link highlighting in the top nav;
  the Home hero's decorative background div (previously empty — no image, no
  effect) now renders an actual dot-grid pattern; capability cards on Home are now
  real links to their pages instead of static boxes; footer rebuilt with real
  navigation instead of one static line.

---

Three pages were added to the existing Semicolon (ECDAT) app — `/remediator`,
`/mosca-timeline`, and `/compliance-reports` — plus the shared plumbing they all
read from. Nothing about the existing Dashboard's behavior changed from a user's
perspective; it now also links out to the three new pages and shows a breach-window
banner when relevant.

## What's new, file by file

- `src/data/findings.js` — the single shared data model. `FINDINGS` now carries, for
  every non-safe finding, a `remediation` object (rationale, attack model, a hybrid
  "bridge" patch, a "full" PQC patch, breaking-change risk, and an hour estimate), a
  `vulnerableSurface` + `hndlRelevant` flag, and a `dataClassification` (shelf-life)
  where HNDL applies. Also holds the NIST SP 800-53 and CNSA 2.0 mapping tables and
  the Q-Day distribution.
- `src/utils/mosca.js` — pure functions implementing Mosca's inequality against a
  three-point Q-Day distribution instead of a single date.
- `src/context/ScanContext.jsx` — the runtime half of "one data model, no silos":
  scan state, theme, remediation choices/status, Mosca overrides, and report history
  all live here, so navigating between pages never loses or diverges state. This is
  also where migration-years-per-finding and breach-window-per-finding are computed
  exactly once and consumed everywhere.
- `src/components/Sidebar.jsx` — extracted from the Dashboard so all four pages
  share one nav.
- `src/pages/Remediator.jsx`, `MoscaTimeline.jsx`, `ComplianceReports.jsx` — the
  three new features.
- Everything runs client-side. There is no network call anywhere in the new code —
  PDF, CSV, JSON, and ZIP generation all happen in the browser via `jspdf`, `jszip`,
  and the Web Crypto API, which is what "all reports are generated entirely in this
  browser" in the Compliance page actually refers to.

## How each feature improves on a naive baseline

**PQC Remediation.** A naive version flags "RSA is broken," offers one hard-swap
patch, and applies it silently. This one separates *quantum-vulnerable* from
*exploitable-today* in every rationale, and — critically — separates *key-exchange*
findings (real HNDL/confidentiality risk) from *signature-only* findings like SSH
host keys (no stored ciphertext to harvest, so no HNDL risk, only future forgery
risk). For key-exchange findings it offers a real, currently-deployable hybrid patch
(X25519+ML-KEM-768/1024) alongside a full-migration option; for signature findings
where no stable hybrid PQC scheme exists yet in mainstream tooling (OpenSSH SSH host
keys, most service-mesh CAs), it says so honestly instead of inventing code, and
gives the real interim mitigation instead (confirm hybrid KEX is active, rotate the
weak key). Nothing auto-applies to a workspace; the output is a branch name, a PR
description with a reviewer checklist, and a scaffolded test.

**Mosca HNDL Timeline.** A naive version applies one formula and one confident
breach year to every finding, including signature keys where the model doesn't even
apply. This one (a) only plots findings where `hndlRelevant` is true, with
signature-only findings shown separately with an explanation of why they're
excluded; (b) models Q-Day as a P25/P50/P75 band, not a point estimate, and renders
it as an uncertainty range against each asset's required-secrecy point; (c) derives
Y live from the Remediator's per-finding effort and breaking-change risk rather than
a guess, with a slider to override it and watch the breach window resize in real
time; and (d) ranks every HNDL-relevant asset side by side instead of showing one
generic industry preset.

**Compliance & CBOM Reports.** A naive version exports one static PDF. This one
generates a schema-shaped CycloneDX 1.6 CBOM (cryptographic-asset components with
`algorithmProperties`, classical and post-quantum security levels), a coverage
matrix against both NIST SP 800-53 control families and NSA CNSA 2.0 migration
milestones, and three distinct outputs (executive PDF, engineering CSV, and a
zipped auditor evidence bundle with a SHA-256 checksum manifest computed via the Web
Crypto API). The readiness score, worst-case breach window, and remediation status
shown are pulled live from `ScanContext` at generation time — re-open the page after
changing a patch choice on the Remediator and the numbers are current, not cached.
Sign-off records a hash of the report's numbers plus signer/role/timestamp, kept as
a versioned history rather than a single overwritten file.

## Honest limitations, stated rather than hidden

- The scanner itself is still a fixed demo dataset (`FINDINGS` in `data/findings.js`)
  — this work extends what happens *after* a scan, not the scanner.
- The CBOM output is a defensible subset of the CycloneDX 1.6 crypto-asset schema,
  not something validated against the official JSON Schema (no network access was
  available to run one here) — treat it as a strong starting point, not a
  certified-compliant artifact.
- The CNSA 2.0 dates and NIST SP 800-53 control mappings reflect commonly published
  summaries; both bodies revise guidance, so the report explicitly tells the reader
  to confirm against the current official advisory before using it as audit evidence.
- The Q-Day distribution defaults are illustrative, clearly labeled as such, and
  fully editable — they are a placeholder for your organization's real risk-register
  numbers, not a forecast.

## Known limits after Round 2

- **Route protection is UX gating, not security.** Login is a client-side mock
  (`AuthContext` + localStorage), so anyone can open devtools and set a user. Real
  access control needs a backend session; this only makes the "Sign in" flow mean
  something in the demo.
- **The login page keeps its own typography** (Space Grotesk + Inter) rather than
  the Clash Display + Switzer used everywhere else. Fonts for both are now loaded
  once in `index.html`; unifying the look is a design decision left to you.
- **Nothing here was run through `npm run build`** (no registry access in the
  authoring environment). Pure-JS files pass Node's parser; JSX files were reviewed
  by hand and for bracket balance. Do a first `npm install && npm run dev` and check
  the browser console before demoing.

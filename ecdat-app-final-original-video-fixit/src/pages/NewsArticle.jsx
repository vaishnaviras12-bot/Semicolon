import React from 'react';
import { Link } from 'react-router-dom';
import { ArrowLeft } from 'lucide-react';
import TopBar from '../components/TopBar.jsx';
import { getReference } from '../data/references.js';

// IDs from data/references.js actually cited inline in this article, in the
// order they should appear in the footer — kept separate from the full
// reference list on /references, which includes sources not cited here.
const CITED_IDS = [1, 2, 3, 4, 6];

export default function NewsArticle() {
  return (
    <div className="na-page">
      <style>{`
        .na-page {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border-soft: #1b2129; --text-primary: #e8eaef; --text-secondary: #8a93a3;
          --text-faint: #545e6e; --gold: #c9a227;
          background: var(--bg); color: var(--text-primary); min-height: 100vh;
          font-family: 'Switzer', system-ui, sans-serif;
        }
        .na-page *, .na-page *::before, .na-page *::after { box-sizing: border-box; }
        .na-wrap { max-width: 760px; margin: 0 auto; padding: 48px 32px 110px; }
        .na-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: var(--text-secondary); font-size: 13px; text-decoration: none; margin-bottom: 30px; }
        .na-back:hover { color: var(--gold); }
        .na-eyebrow { font-size: 12px; letter-spacing: 0.14em; color: var(--gold); text-transform: uppercase; }
        .na-title { font-family: 'Clash Display', sans-serif; font-size: 36px; font-weight: 600; line-height: 1.15; margin: 14px 0 14px; }
        .na-dek { font-size: 15.5px; color: var(--text-secondary); line-height: 1.65; margin: 0 0 36px; }
        .na-toc { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 18px 22px; margin-bottom: 44px; }
        .na-toc p { font-size: 11px; letter-spacing: 0.08em; text-transform: uppercase; color: var(--text-faint); margin: 0 0 10px; }
        .na-toc ol { margin: 0; padding-left: 18px; font-size: 13px; line-height: 1.9; color: var(--text-secondary); }
        .na-toc a { color: var(--text-secondary); text-decoration: none; }
        .na-toc a:hover { color: var(--gold); }
        .na-section { margin-bottom: 44px; scroll-margin-top: 30px; }
        .na-section h2 { font-family: 'Clash Display', sans-serif; font-size: 22px; font-weight: 600; margin: 0 0 16px; }
        .na-section p { font-size: 15px; line-height: 1.75; color: var(--text-secondary); margin: 0 0 16px; }
        .na-section p b { color: var(--text-primary); font-weight: 600; }
        .na-section ul { margin: 0 0 16px; padding-left: 20px; }
        .na-section li { font-size: 15px; line-height: 1.7; color: var(--text-secondary); margin-bottom: 8px; }
        .na-cite { color: var(--gold); text-decoration: none; font-size: 0.85em; vertical-align: super; }
        .na-cite:hover { text-decoration: underline; }
        .na-note {
          font-size: 13px; color: var(--text-faint); line-height: 1.65; background: var(--surface-1);
          border-left: 2px solid var(--gold); padding: 12px 16px; margin: 20px 0; border-radius: 0 6px 6px 0;
        }
        .na-refs { border-top: 1px solid var(--border-soft); padding-top: 28px; margin-top: 50px; }
        .na-refs h2 { font-family: 'Clash Display', sans-serif; font-size: 18px; font-weight: 600; margin: 0 0 16px; }
        .na-refs ol { margin: 0; padding-left: 20px; font-size: 12.5px; color: var(--text-faint); line-height: 1.9; }
        .na-refs a { color: var(--text-faint); }
        .na-refs a:hover { color: var(--gold); }
        .na-refs-link { display: inline-block; margin-top: 20px; font-size: 13px; color: var(--gold); text-decoration: none; }
        .na-refs-link:hover { text-decoration: underline; }
        .na-mono { font-family: 'IBM Plex Mono', monospace; }
      `}</style>

      <TopBar variant="public" />

      <div className="na-wrap">
        <Link to="/" className="na-back"><ArrowLeft size={14} /> Back to home</Link>

        <span className="na-eyebrow na-mono">NEWS · MISSION &amp; APPROACH</span>
        <h1 className="na-title">Why cryptographic discovery is the migration problem nobody's solved yet</h1>
        <p className="na-dek">
          An inside look at the problem Semicolon is built for, the research it draws on, and how discovery,
          risk scoring, and post-quantum readiness fit together into one workflow.
        </p>

        <div className="na-toc">
          <p>In this article</p>
          <ol>
            <li><a href="#problem">The problem we're solving</a></li>
            <li><a href="#impact">Real-world impact: why this matters</a></li>
            <li><a href="#different">What makes Semicolon different</a></li>
            <li><a href="#workflow">Workflow: input to output</a></li>
            <li><a href="#architecture">Architecture</a></li>
            <li><a href="#privacy">Security and privacy</a></li>
            <li><a href="#risk-engine">The risk engine</a></li>
            <li><a href="#pqc">Post-quantum cryptography</a></li>
            <li><a href="#story">Our story</a></li>
          </ol>
        </div>

        <section className="na-section" id="problem">
          <h2>1. The problem we're solving</h2>
          <p>
            Most organizations cannot answer a simple question: <b>where, exactly, does our cryptography live?</b>{' '}
            Algorithms and keys accumulate across codebases, containers, certificates, and infrastructure config
            over years, added by different teams for different reasons, and rarely documented as a single
            inventory. This isn't negligence so much as a structural gap — cryptography is everyone's
            responsibility in the moment and no one's job to track over time.
          </p>
          <p>
            The consequence is <b>hidden dependency</b>. A single certificate or key can be relied on by services
            nobody remembers connecting to it, so a routine rotation can silently break something three layers
            away. Migrating away from a weak or deprecated algorithm compounds this: the CARAF framework's
            authors point out that migration isn't just a config change — hashed data, for instance, can't be
            "re-hashed" in place, so a move to a new hashing algorithm often means running two algorithms in
            parallel or forcing a password reset across every affected account
            <a href="#ref3" className="na-cite">[3]</a>. Real transitions bear this out: the industry-wide move
            from SHA-1 to SHA-2 took roughly a decade <a href="#ref3" className="na-cite">[3]</a>.
          </p>
          <p>
            Quantum computing adds a second, sharper dimension to this gap. Shor's algorithm doesn't just weaken
            RSA, elliptic-curve cryptography, and finite-field Diffie–Hellman — it breaks them outright once a
            cryptographically relevant quantum computer exists <a href="#ref1" className="na-cite">[1]</a>
            <a href="#ref4" className="na-cite">[4]</a>. Grover's algorithm, by contrast, only delivers a
            quadratic speed-up against symmetric ciphers like AES, effectively halving the exponent rather than
            eliminating security <a href="#ref2" className="na-cite">[2]</a>. That means two cryptographic
            assets can look equally "old" in an inventory while facing completely different levels of quantum
            urgency — and most discovery tools don't draw that distinction at all.
          </p>
        </section>

        <section className="na-section" id="impact">
          <h2>2. Real-world impact: why this matters</h2>
          <p>
            <b>Operational disruption</b> from cryptographic transitions is not hypothetical. When Let's Encrypt
            found a bug affecting how it had validated roughly three million certificates, it had to revoke and
            reissue them on a tight deadline <a href="#ref3" className="na-cite">[3]</a>. RSA's 2011 SecurID
            breach cost parent company EMC a disclosed $66 million in remediation in a single quarter alone
            <a href="#ref3" className="na-cite">[3]</a>. Neither incident involved quantum computers — they're
            reminders of how expensive crypto changes are even under ordinary, well-understood circumstances.
          </p>
          <p>
            <b>Compliance risk</b> is rising in parallel. The EU's Coordinated Implementation Roadmap for
            post-quantum cryptography sets a 2030 deadline for systems classified as high-risk, and frameworks
            like NIS2 increasingly expect continuous risk assessment that accounts for emerging technology, even
            where quantum threats aren't named explicitly <a href="#ref1" className="na-cite">[1]</a>.
          </p>
          <p>
            <b>Long-lived sensitive data</b> is where the two pressures meet. Mosca's widely cited inequality
            frames this precisely: if the number of years data must stay confidential (X) plus the number of
            years needed to migrate it (Y) exceeds the number of years until a quantum computer capable of
            breaking it arrives (Z), confidentiality is already lost — even if that quantum computer doesn't
            exist yet <a href="#ref3" className="na-cite">[3]</a><a href="#ref4" className="na-cite">[4]</a>.
            This is the mechanism behind "harvest now, decrypt later": an adversary records encrypted traffic
            today and simply waits.
          </p>
          <p>
            The response the research consistently points to is <b>crypto-agility</b> — the ability to replace a
            cryptographic primitive quickly, cheaply, and with acceptable risk, treated as its own category of
            business risk alongside compliance and supply-chain risk, rather than an occasional emergency project
            <a href="#ref3" className="na-cite">[3]</a>.
          </p>
        </section>

        <section className="na-section" id="different">
          <h2>3. What makes Semicolon different</h2>
          <p>
            Plenty of tools can tell you "this file uses RSA." That's necessary but not sufficient. Semicolon is
            built around a longer chain: <b>discovery → cryptographic inventory → contextual risk scoring →
            prioritized recommendations → PQC readiness → exportable reporting</b> — because an algorithm name on
            its own doesn't tell a security team what to do next.
          </p>
          <p>
            <b>Contextual scoring</b> means the same algorithm can score differently depending on where it's
            used — an internal batch job and a public-facing certificate carrying the same weak cipher are not
            equally urgent. This mirrors the direction of recent academic risk-scoring work, which extends simple
            timeline-based models into multi-factor scores incorporating sensitivity and exposure, not just "is
            this algorithm old" <a href="#ref1" className="na-cite">[1]</a>, and — in the most directly relevant
            extension — evaluates risk separately for data in transit, in use, and at rest, since each faces a
            different mix of Shor- and Grover-type threats
            <a href="#ref2" className="na-cite">[2]</a>.
          </p>
          <p>
            <b>Prioritized, not just enumerated.</b> CARAF's central argument is that crypto-agility risk is a
            function of both timeline and cost — <i>Risk = Timeline × Cost</i> — so migration effort has to be
            weighed alongside urgency, not treated as a flat checklist
            <a href="#ref3" className="na-cite">[3]</a>. Semicolon's recommendations carry an estimated migration
            effort alongside the priority ranking for exactly this reason.
          </p>
        </section>

        <section className="na-section" id="workflow">
          <h2>4. Workflow: input to output</h2>
          <p>The path from a file to a closed-out fix follows one consistent sequence:</p>
          <ul>
            <li><b>Upload file</b> — a source repository, a ZIP archive, a certificate, or a live network scan.</li>
            <li><b>Scan and discover assets</b> — the discovery engine finds algorithms, protocols, certificates, keys, and libraries.</li>
            <li><b>Classify algorithms and confidence</b> — each finding is typed and given a confidence score reflecting how certain the detector is.</li>
            <li><b>Risk engine</b> — findings are scored for urgency using the factors described in Section 7.</li>
            <li><b>PQC readiness</b> — findings are checked against Shor-vulnerability and mapped to a readiness picture.</li>
            <li><b>Recommendations</b> — each risky finding gets a primary replacement algorithm plus two fallbacks, so one unavailable option doesn't stall the plan.</li>
            <li><b>PQC Remediation</b> — risky findings get a real hybrid ("bridge") patch and a full-migration patch side by side, with a breaking-change estimate and a draft PR rather than a silent auto-apply.</li>
            <li><b>Mosca Timeline</b> — remediation effort feeds the migration-time variable in Mosca's inequality for the full inventory, plotted against a Q-Day probability range rather than one confident date.</li>
            <li><b>Compliance &amp; CBOM reporting</b> — a CycloneDX CBOM, a framework coverage matrix, and a hashed, signed evidence bundle, all reflecting the current state of the scan above rather than a stale export.</li>
          </ul>
        </section>

        <section className="na-section" id="architecture">
          <h2>5. Architecture</h2>
          <p>
            Semicolon is designed as a modular pipeline rather than one monolithic scanner, so each stage can be
            improved independently:
          </p>
          <ul>
            <li><b>Ingestion / scanning</b> — accepts source code, archives, certificates, and network-facing endpoints as input.</li>
            <li><b>Cryptographic discovery</b> — identifies algorithms, protocols, keys, and libraries within that input.</li>
            <li><b>Inventory normalization</b> — de-duplicates findings and classifies them into consistent categories (algorithm, key, certificate, protocol).</li>
            <li><b>Risk engine</b> — scores each finding for urgency and quantum vulnerability.</li>
            <li><b>Recommendation engine</b> — maps risky findings to replacement algorithms with two fallback options.</li>
            <li><b>Reporting</b> — compiles findings, scores, and recommendations into exportable output.</li>
            <li><b>Dashboard</b> — the user-facing layer tying all of the above together.</li>
          </ul>
          <p className="na-note">
            This describes the intended modular design of the system, not a verified audit of what any specific
            build currently implements — treat it as an architectural principle the product is built toward,
            not a claim about deployed internals.
          </p>
        </section>

        <section className="na-section" id="privacy">
          <h2>6. Security and privacy</h2>
          <p>Semicolon is designed around a small set of privacy-by-design principles:</p>
          <ul>
            <li><b>Least privilege</b> — components only get the access they need to do their specific job.</li>
            <li><b>Encrypted handling</b> — data in motion and at rest within the pipeline is intended to be encrypted.</li>
            <li><b>Auditability</b> — actions and scoring decisions should be traceable after the fact.</li>
            <li><b>Secure report access</b> — exported reports are meant to be reachable only by people authorized to see them.</li>
            <li><b>Data minimization</b> — collect what's needed for discovery and scoring, not more.</li>
          </ul>
          <p className="na-note">
            These are design principles the product is built around, not claims verified by independent
            implementation audit — the two are worth keeping distinct, and we'd rather say that plainly than
            imply a certification that hasn't happened.
          </p>
        </section>

        <section className="na-section" id="risk-engine">
          <h2>7. The risk engine</h2>
          <p>Risk prioritization considers several factors together, rather than any single one in isolation:</p>
          <ul>
            <li>the cryptographic algorithm itself, and its known weaknesses;</li>
            <li>key strength or configuration, where that information is available;</li>
            <li>exposure — how reachable or interceptable the asset is;</li>
            <li>asset criticality — how much depends on it;</li>
            <li>detection confidence — how sure the scanner is that a finding is real;</li>
            <li>migration urgency — how much runway remains before action is needed;</li>
            <li>quantum vulnerability specifically — whether the primitive is Shor-broken or only Grover-weakened.</li>
          </ul>
          <p>
            This combination follows the same logic as the multi-factor academic risk-scoring work described
            above — timeline, sensitivity, and exposure combined into one score rather than assessed separately
            <a href="#ref1" className="na-cite">[1]</a>, with an explicit adjustment so that strong symmetric
            encryption isn't treated with the same urgency as a quantum-broken public-key algorithm
            <a href="#ref2" className="na-cite">[2]</a>.
          </p>
          <p className="na-note">
            Risk engine output is decision support, not a substitute for expert security review. A score is a
            starting point for a conversation with a security professional, not a final verdict.
          </p>
        </section>

        <section className="na-section" id="pqc">
          <h2>8. Post-quantum cryptography</h2>
          <p>
            <b>Inventory first.</b> You cannot migrate what you haven't found — this is the starting premise of
            NIST's own post-quantum migration guidance project <a href="#ref6" className="na-cite">[6]</a>, and
            it's why discovery is the first stage of Semicolon's pipeline rather than an afterthought.
          </p>
          <p>
            <b>Prioritized migration planning</b> matters because fixing one thing rarely finishes the job.
            Recent layer-specific risk-scoring research found that hardening storage encryption reduced overall
            system risk substantially, but the highest-risk layer simply shifted to transport — the total risk
            didn't disappear, the bottleneck moved <a href="#ref2" className="na-cite">[2]</a>. Migration planning
            has to expect that pattern, not treat any single fix as the finish line.
          </p>
          <p>
            <b>Crypto-agility</b> — the ability to swap primitives with limited operational impact
            <a href="#ref3" className="na-cite">[3]</a> — and <b>interoperability</b>, often via hybrid schemes
            that combine a classical algorithm with a post-quantum one during the transition period, are both
            treated in the literature as necessary bridges rather than optional extras.
          </p>
          <p>
            <b>Ongoing monitoring</b> is the last piece, because none of the underlying numbers are fixed.
            Estimates of how soon a cryptographically relevant quantum computer will exist get revised as
            research progresses, and risk-scoring researchers explicitly recommend annual re-validation of these
            models rather than a one-time assessment <a href="#ref1" className="na-cite">[1]</a>.
          </p>
        </section>

        <section className="na-section" id="story">
          <h2>9. Our story</h2>
          <p>
            Semicolon started from a simple frustration: cryptographic risk is usually described in the abstract
            — "quantum computers will break RSA" — without a practical path from that fact to a prioritized list
            of what to actually fix first, in a specific codebase, this week. The research is there. The
            standards are being finalized. What was missing was the connective tissue between "here's a paper
            about quantum risk scoring" and "here's the one certificate on your infrastructure you should
            replace before all the rest."
          </p>
          <p>
            Semicolon exists to turn opaque cryptographic exposure into a practical, prioritized migration path —
            not by inventing new cryptography, but by making the cryptography that already exists visible,
            scored, and actionable.
          </p>
        </section>

        <div className="na-refs">
          <h2>References cited in this article</h2>
          <ol>
            {CITED_IDS.map((id) => {
              const ref = getReference(id);
              if (!ref) return null;
              return (
                <li key={ref.id} id={`ref${ref.id}`}>
                  {ref.authors}. {ref.title}. <i>{ref.venue}</i>.{' '}
                  <a href={ref.url} target="_blank" rel="noopener noreferrer">{ref.url.replace(/^https?:\/\//, '')}</a>
                </li>
              );
            })}
          </ol>
          <Link to="/references" className="na-refs-link">See the full reference list →</Link>
        </div>
      </div>
    </div>
  );
}

import React, { useState, useMemo } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import {
  FileSearch, Gauge, Share2, FileCheck2, ArrowRight, Clock, Wrench,
  Upload, Search, Download,
} from 'lucide-react';
import Splash from '../components/Splash.jsx';
import TopBar from '../components/TopBar.jsx';
import { useScan } from '../context/ScanContext.jsx';
import heroSecurityVideo from '../assets/hero-security.mp4';

const CAPABILITIES = [
  { icon: FileSearch, title: 'Discover assets', to: '/dashboard#sec-upload', desc: 'Scan a codebase, certificate, or config file to find every algorithm, key, and protocol in use — including the ones nobody remembers deploying.' },
  { icon: Gauge, title: 'Score quantum risk', to: '/dashboard#sec-pqc', desc: 'Every finding gets a risk band and a confidence score — and Shor-broken crypto is never conflated with merely-outdated crypto.' },
  { icon: Clock, title: 'Simulate the breach window', to: '/mosca-timeline', desc: "Run Mosca's inequality against a Q-Day probability range, not one confident date, and watch the window shrink as migration speeds up." },
  { icon: Wrench, title: 'Remediate with a real patch', to: '/remediator', desc: 'Every risky finding gets a hybrid bridge patch and a full-migration patch, with a rationale and a breaking-change estimate — never a silent auto-apply.' },
  { icon: FileCheck2, title: 'Generate compliance reports', to: '/compliance-reports', desc: 'Export a CycloneDX CBOM, a NIST/CNSA coverage matrix, and a hashed, signed evidence bundle for auditors.' },
  { icon: Share2, title: 'Map dependencies', to: '/dashboard#sec-topology', desc: 'See which services rely on which certificates and keys, so fixing one thing doesn\u2019t silently break another.' },
];

const PIPELINE = [
  { icon: Upload, title: 'Scan', desc: 'Upload a codebase or run a live scan to discover every cryptographic asset.' },
  { icon: Search, title: 'Score', desc: 'Each finding is risk-banded and checked for quantum vulnerability specifically.' },
  { icon: Wrench, title: 'Remediate', desc: 'Pick a hybrid or full PQC patch per finding, with the breaking-change cost shown upfront.' },
  { icon: Download, title: 'Report', desc: 'Export a CBOM and a signed evidence bundle that reflect the current state, live.' },
];

function ReadMoreBlock({ eyebrow, title, short, long }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="rm-block">
      <span className="rm-eyebrow">{eyebrow}</span>
      <h3 className="rm-title">{title}</h3>
      <p className="rm-text">{short}</p>
      {open && <p className="rm-text rm-extra">{long}</p>}
      <button className="rm-btn" onClick={() => setOpen((o) => !o)}>
        {open ? 'Show less' : 'Read more'} <ArrowRight size={13} style={{ transform: open ? 'rotate(90deg)' : 'none', transition: 'transform 0.15s' }} />
      </button>
    </div>
  );
}

export default function Home() {
  const navigate = useNavigate();
  const [showSplash, setShowSplash] = useState(true);
  const { scanState, findings } = useScan();
  const scanned = scanState === 'complete';

  const demoStats = useMemo(() => {
    const safeFindings = Array.isArray(findings) ? findings : [];
    if (!scanned || !safeFindings.length) return { total: 0, quantumVulnerable: 0, pqcCount: 0, pqcList: '' };
    const total = safeFindings.length;
    const quantumVulnerable = safeFindings.filter((f) => Boolean(f.shor_vulnerable || f.shorVulnerable)).length;
    const pqcAlgos = new Set();
    safeFindings.forEach((f) => {
      [f?.recommendation?.primary, f?.recommendation?.fallback].forEach((v) => {
        if (v && /^(ML-KEM|ML-DSA|SLH-DSA|FN-DSA)/.test(v)) pqcAlgos.add(v.split(' ')[0]);
      });
    });
    return { total, quantumVulnerable, pqcCount: pqcAlgos.size, pqcList: Array.from(pqcAlgos).join(', ') };
  }, [scanned, findings]);

  return (
    <div className="sentinel-home">
      <style>{`

        .sentinel-home {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border: #262e3a; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e;
          --gold: #c9a227; --gold-soft: rgba(201,162,39,0.14);
          --crimson: #c1503a; --teal: #3fb8af;
          background: var(--bg); color: var(--text-primary);
          font-family: 'Switzer', system-ui, sans-serif;
          min-height: 100vh;
        }
        .sentinel-home *, .sentinel-home *::before, .sentinel-home *::after { box-sizing: border-box; }
        .sh-display { font-family: 'Clash Display', sans-serif; }
        .sh-mono { font-family: 'IBM Plex Mono', monospace; }
        .sh-section { max-width: 1100px; margin: 0 auto; padding: 80px 32px; }

        /* The video is deliberately muted/inline so it can start without a click.
           Layered overlays protect contrast for the security-critical headline. */
        .sh-hero {
          position: relative; overflow: hidden;
          padding: 124px 32px 88px; text-align: left;
          background: radial-gradient(circle at 25% 20%, #10151d 0%, var(--bg) 60%);
          border-bottom: 1px solid var(--border-soft);
          min-height: 540px; display: flex; align-items: center;
        }
        .sh-hero-video-slot { position: absolute; inset: 0; z-index: 0; overflow: hidden; }
        .sh-hero-video-slot video { width: 100%; height: 100%; object-fit: cover; object-position: center; }
        .sh-hero-video-overlay {
          position: absolute; inset: 0; z-index: 1;
          background:
            linear-gradient(90deg, rgba(10,13,18,0.94) 0%, rgba(10,13,18,0.78) 44%, rgba(10,13,18,0.30) 100%),
            linear-gradient(180deg, rgba(10,13,18,0.24) 0%, rgba(10,13,18,0.76) 100%);
        }
        .sh-hero-inner { max-width: 1100px; margin: 0 auto; position: relative; z-index: 2; width: 100%; }
        .sh-hero-bg {
          position: absolute; inset: 0; opacity: 0.5; pointer-events: none; z-index: 0;
          background-image: radial-gradient(rgba(201,162,39,0.35) 1px, transparent 1px);
          background-size: 26px 26px;
          -webkit-mask-image: radial-gradient(ellipse 70% 60% at 20% 15%, #000 0%, transparent 75%);
          mask-image: radial-gradient(ellipse 70% 60% at 20% 15%, #000 0%, transparent 75%);
        }
        .sh-eyebrow {
          font-size: 12px; letter-spacing: 0.16em; color: var(--gold); text-transform: uppercase;
          margin-bottom: 18px; display: inline-block;
        }
        .sh-h1 { font-size: clamp(38px, 5.1vw, 64px); line-height: 1.06; font-weight: 600; letter-spacing: -0.02em; max-width: 760px; margin: 0 0 20px; }
        .sh-hero-sub { font-size: 16px; color: #c1c8d2; max-width: 560px; line-height: 1.6; margin: 0 0 30px; }
        .sh-hero-actions { display: flex; gap: 14px; }
        .sh-btn-primary {
          display: inline-flex; align-items: center; gap: 8px;
          background: var(--gold); color: #191308; font-weight: 600; font-size: 14px;
          padding: 12px 22px; border-radius: 7px; text-decoration: none; transition: filter 0.15s ease, transform 0.15s ease;
        }
        .sh-btn-primary:hover { filter: brightness(1.08); transform: translateY(-1px); }
        .sh-btn-secondary {
          display: inline-flex; align-items: center; gap: 8px;
          border: 1px solid var(--border); color: var(--text-primary); font-size: 14px;
          padding: 12px 22px; border-radius: 7px; text-decoration: none; transition: border-color 0.15s ease, color 0.15s ease, transform 0.15s ease;
        }
        .sh-btn-secondary:hover { border-color: var(--gold); color: var(--gold); transform: translateY(-1px); }

        /* Stats strips */
        .sh-stats { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 18px; }
        .sh-stat-box { background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 26px 22px; transition: border-color 0.15s ease, transform 0.15s ease; }
        .sh-stat-box:hover { border-color: var(--border); transform: translateY(-2px); }
        .sh-stat-label { font-size: 13px; color: var(--text-secondary); margin: 0 0 10px; }
        .sh-stat-value { font-size: 34px; font-weight: 600; margin: 0; }
        .sh-stat-note { font-size: 12px; color: var(--text-faint); margin: 14px 2px 0; line-height: 1.6; }

        /* Pipeline */
        .sh-pipeline { display: grid; grid-template-columns: repeat(4, minmax(0,1fr)); gap: 0; margin-top: 40px; position: relative; }
        .sh-pipeline-step { position: relative; padding: 0 18px 0 0; }
        .sh-pipeline-num { font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: var(--gold); }
        .sh-pipeline-icon {
          width: 40px; height: 40px; border-radius: 9px; background: var(--gold-soft); color: var(--gold);
          display: flex; align-items: center; justify-content: center; margin: 10px 0 14px;
        }
        .sh-pipeline-step h3 { font-size: 15.5px; font-weight: 600; margin: 0 0 8px; }
        .sh-pipeline-step p { font-size: 13px; color: var(--text-secondary); line-height: 1.6; margin: 0; }
        .sh-pipeline-arrow { display: none; }

        /* Why Sentinel */
        .sh-why-grid { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 28px; margin-top: 40px; }
        .rm-block { }
        .rm-eyebrow { font-size: 11px; letter-spacing: 0.1em; color: var(--gold); text-transform: uppercase; }
        .rm-title { font-size: 19px; font-weight: 600; margin: 10px 0 10px; }
        .rm-text { font-size: 14px; line-height: 1.65; color: var(--text-secondary); margin: 0 0 8px; }
        .rm-extra { color: var(--text-primary); }
        .rm-btn {
          display: inline-flex; align-items: center; gap: 5px; margin-top: 6px;
          background: none; border: none; color: var(--gold); font-size: 13px; cursor: pointer; padding: 0;
          font-family: inherit;
        }

        /* Capabilities */
        .sh-cap-grid { display: grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap: 16px; margin-top: 40px; }
        .sh-cap-card {
          background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 24px;
          text-decoration: none; color: inherit; display: block;
          transition: border-color 0.15s ease, transform 0.15s ease, background 0.15s ease;
        }
        .sh-cap-card:hover { border-color: var(--gold); transform: translateY(-3px); background: var(--surface-2); }
        .sh-cap-icon {
          width: 38px; height: 38px; border-radius: 8px; background: var(--gold-soft); color: var(--gold);
          display: flex; align-items: center; justify-content: center; margin-bottom: 16px;
        }
        .sh-cap-title { font-size: 15.5px; font-weight: 600; margin: 0 0 8px; display: flex; align-items: center; justify-content: space-between; gap: 8px; }
        .sh-cap-title svg { opacity: 0; transform: translateX(-4px); transition: opacity 0.15s ease, transform 0.15s ease; flex-shrink: 0; }
        .sh-cap-card:hover .sh-cap-title svg { opacity: 1; transform: translateX(0); }
        .sh-cap-desc { font-size: 13.5px; color: var(--text-secondary); line-height: 1.6; margin: 0; }

        /* Final CTA */
        .sh-cta {
          text-align: center; padding: 90px 32px; border-top: 1px solid var(--border-soft);
          background: var(--surface-1);
        }
        .sh-cta h2 { font-size: 30px; font-weight: 600; margin: 0 0 24px; }

        .sh-footer {
          padding: 40px 32px 30px; border-top: 1px solid var(--border-soft);
          display: flex; flex-direction: column; align-items: center; gap: 16px; text-align: center;
        }
        .sh-footer-nav { display: flex; gap: 22px; flex-wrap: wrap; justify-content: center; }
        .sh-footer-nav a { color: var(--text-secondary); text-decoration: none; font-size: 13px; }
        .sh-footer-nav a:hover { color: var(--gold); }
        .sh-footer-copy { font-size: 12px; color: var(--text-faint); font-family: 'IBM Plex Mono', monospace; }

        @media (max-width: 760px) {
          .sh-hero { min-height: 500px; padding: 106px 24px 72px; }
          .sh-h1 { font-size: clamp(34px, 10vw, 46px); }
          .sh-stats, .sh-why-grid, .sh-cap-grid { grid-template-columns: 1fr; }
          .sh-pipeline { grid-template-columns: 1fr 1fr; row-gap: 28px; }
        }
      `}</style>

      {showSplash && <Splash onFinish={() => setShowSplash(false)} />}

      <TopBar variant="public" onProfileClick={() => navigate('/dashboard')} />

      <section className="sh-hero">
        <div className="sh-hero-bg sh-mono" aria-hidden="true" />

        <div className="sh-hero-video-slot" aria-hidden="true">
          <video autoPlay muted loop playsInline preload="metadata">
            <source src={heroSecurityVideo} type="video/mp4" />
          </video>
        </div>
        <div className="sh-hero-video-overlay" aria-hidden="true" />

        <div className="sh-hero-inner">
          <span className="sh-eyebrow sh-mono">CRYPTOGRAPHIC DISCOVERY &amp; RISK PLATFORM</span>
          <h1 className="sh-h1 sh-display">Every cipher in your enterprise, mapped and graded before it's a liability.</h1>
          <p className="sh-hero-sub">
            SEMICOLON discovers, analyzes, and visualizes every cryptographic asset in your
            organization — certificates, keys, and algorithms — and flags what won't survive
            a quantum-capable adversary.
          </p>
          <div className="sh-hero-actions">
            <Link to="/login" className="sh-btn-primary">Sign in <ArrowRight size={15} /></Link>
            <a href="#about" className="sh-btn-secondary">See how it works</a>
          </div>
        </div>
      </section>

      <section className="sh-section" id="glimpse">
        <span className="sh-eyebrow sh-mono">{scanned ? 'FROM YOUR SCAN' : 'NOTHING SCANNED YET'}</span>
        
        <div className="sh-stats">
          <div className="sh-stat-box">
            <p className="sh-stat-label">Findings</p>
            <p className="sh-stat-value sh-display">{demoStats.total}</p>
          </div>
          <div className="sh-stat-box">
            <p className="sh-stat-label">Flagged quantum-vulnerable</p>
            <p className="sh-stat-value sh-display" style={{ color: demoStats.quantumVulnerable > 0 ? 'var(--crimson)' : 'inherit' }}>{demoStats.quantumVulnerable}</p>
          </div>
          <div className="sh-stat-box">
            <p className="sh-stat-label">PQC algorithms referenced</p>
            <p className="sh-stat-value sh-display">{demoStats.pqcCount}</p>
          </div>
        </div>
        <p className="sh-stat-note">
          {scanned
            ? `From your most recent scan${demoStats.pqcList ? ` (${demoStats.pqcList})` : ''}.`
            : 'Zero until a scan runs '}{' '}
          <Link to="/dashboard#sec-upload" style={{ color: 'var(--gold)' }}>
            {scanned ? 'Run another scan →' : 'Run your first scan →'}
          </Link>
        </p>
      </section>

      <section className="sh-section" id="about">
        <span className="sh-eyebrow sh-mono">WHY SEMICOLON</span>
        <div className="sh-why-grid">
          <ReadMoreBlock
            eyebrow="The problem"
            title="Nobody has one list"
            short="Certificates, keys, and algorithms pile up across teams, tools, and years — most enterprises can't produce a single, current inventory of their own cryptography."
            long="Weak algorithms stay in production because no one flagged them. Certificates expire without warning because no one owned the renewal. SSH keys from departed employees stay valid because no one tracked them. This isn't negligence — it's the natural result of cryptography being everyone's responsibility and no one's job."
          />
          <ReadMoreBlock
            eyebrow="The solution"
            title="One engine, one inventory"
            short="SEMICOLON scans infrastructure and codebases automatically, builds a live cryptographic inventory, and grades every asset against current and post-quantum standards."
            long="Discovery runs continuously, not as a one-time audit. Every certificate, key, and protocol gets mapped to the services that depend on it, so a fix in one place doesn't silently break another."
          />
          <ReadMoreBlock
            eyebrow="The impact"
            title="Fix it before it's urgent"
            short="Security teams get a prioritized, visual risk dashboard instead of a spreadsheet — so quantum migration becomes a plan, not a scramble."
            long="For a security or compliance team, that means a standing, auditable picture of cryptographic posture across an enterprise — the difference between finding a weak algorithm during a routine review versus during an incident."
          />
        </div>
      </section>

      <section className="sh-section" id="capabilities">
        <span className="sh-eyebrow sh-mono">CAPABILITIES</span>
        <h2 className="sh-display" style={{ fontSize: 30, margin: '10px 0 0' }}>Everything discovery and analysis needs</h2>
        <div className="sh-cap-grid">
          {CAPABILITIES.map((cap) => {
            const Icon = cap.icon;
            return (
              <Link className="sh-cap-card" key={cap.title} to={cap.to}>
                <div className="sh-cap-icon"><Icon size={18} /></div>
                <h3 className="sh-cap-title">{cap.title} <ArrowRight size={14} /></h3>
                <p className="sh-cap-desc">{cap.desc}</p>
              </Link>
            );
          })}
        </div>
      </section>

      <section className="sh-section" id="scans">
        <span className="sh-eyebrow sh-mono">HOW IT WORKS</span>
        <h2 className="sh-display" style={{ fontSize: 30, margin: '10px 0 0' }}>One pipeline, four stops.</h2>
        <div className="sh-pipeline">
          {PIPELINE.map((step, i) => {
            const Icon = step.icon;
            return (
              <div className="sh-pipeline-step" key={step.title}>
                <span className="sh-pipeline-num">{String(i + 1).padStart(2, '0')}</span>
                <div className="sh-pipeline-icon"><Icon size={18} /></div>
                <h3>{step.title}</h3>
                <p>{step.desc}</p>
              </div>
            );
          })}
        </div>
      </section>

      <section className="sh-cta">
        <h2 className="sh-display">See your own cryptographic blind spots.</h2>
        <Link to="/login" className="sh-btn-primary">Sign in to Semicolon <ArrowRight size={15} /></Link>
      </section>

      <footer className="sh-footer">
        <nav className="sh-footer-nav sh-mono">
          <Link to="/dashboard#sec-upload">Dashboard</Link>
          <Link to="/remediator">PQC Remediation</Link>
          <Link to="/mosca-timeline">Mosca Timeline</Link>
          <Link to="/compliance-reports">Compliance Reports</Link>
          <Link to="/news">News</Link>
          <Link to="/references">References</Link>
          <Link to="/login">Sign in</Link>
        </nav>
        <p className="sh-footer-copy">SEMICOLON — cryptographic discovery, risk analysis, and quantum-readiness for the enterprise</p>
      </footer>
    </div>
  );
}

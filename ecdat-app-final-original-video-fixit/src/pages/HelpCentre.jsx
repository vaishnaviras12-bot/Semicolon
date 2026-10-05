import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { ArrowLeft, ChevronDown, Mail } from 'lucide-react';

const FAQ_SECTIONS = [
  {
    title: 'Getting started',
    items: [
      { q: 'How do I run my first scan?', a: 'From the Dashboard, use "Upload file" to scan a specific file, or "Run live scan" to scan your connected network endpoints. Results appear automatically once the scan finishes.' },
      { q: 'What file types can I upload?', a: 'Source code (Python, Java, JavaScript/TypeScript, C/C++), Dockerfiles, and certificates (PEM, CRT, CER, DER, P12, PFX).' },
    ],
  },
  {
    title: 'Understanding results',
    items: [
      { q: 'What do the risk bands mean?', a: 'Critical and High mean the cryptography is broken or seriously weak and should be prioritized. Moderate and Low need attention but aren\u2019t urgent. Safe means no action is currently needed.' },
      { q: 'What\u2019s the difference between confidence and risk?', a: 'Confidence (0.70\u20130.95) is how sure the detector is that a finding is real. Risk band is how urgent that finding is. A finding can be high-confidence and low-risk, or low-confidence and high-risk \u2014 they\u2019re independent.' },
      { q: 'Why isn\u2019t AES-256 flagged as quantum-vulnerable?', a: 'AES-256 is only weakened by Grover\u2019s algorithm, not broken outright the way RSA and ECC are by Shor\u2019s algorithm. It stays effectively secure at 256-bit key length even against a quantum computer.' },
    ],
  },
  {
    title: 'Reminders & re-scanning',
    items: [
      { q: 'How do reminders work?', a: 'Semicolon reminds you to re-scan a file automatically after 7 days, or immediately if you flag that you\u2019ve changed its code \u2014 whichever comes first.' },
      { q: 'Can I change the reminder interval?', a: 'Not yet from the interface \u2014 this is on the roadmap for Account settings.' },
    ],
  },
  {
    title: 'Account',
    items: [
      { q: 'How do I change my name or email?', a: 'Open your profile menu in the top bar and go to Account settings \u2014 profile details are editable there.' },
      { q: 'How do I log out?', a: 'Open your profile menu in the top bar and select Log out.' },
    ],
  },
];

function FaqItem({ q, a }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="hc-item">
      <button className="hc-question" onClick={() => setOpen((o) => !o)} aria-expanded={open}>
        {q}
        <ChevronDown size={15} style={{ transform: open ? 'rotate(180deg)' : 'none', transition: 'transform 0.15s' }} />
      </button>
      {open && <p className="hc-answer">{a}</p>}
    </div>
  );
}

export default function HelpCentre() {
  const navigate = useNavigate();
  return (
    <div className="hc-page">
      <style>{`
        .hc-page {
          --bg: #0a0d12; --surface-1: #12161d; --surface-2: #171c25;
          --border-soft: #1b2129; --text-primary: #e8eaef; --text-secondary: #8a93a3;
          --text-faint: #545e6e; --gold: #c9a227;
          background: var(--bg); color: var(--text-primary); min-height: 100vh;
          font-family: 'Switzer', system-ui, sans-serif;
        }
        .hc-page *, .hc-page *::before, .hc-page *::after { box-sizing: border-box; }
        .hc-wrap { max-width: 720px; margin: 0 auto; padding: 40px 32px 100px; }
        .hc-back { display: inline-flex; align-items: center; gap: 6px; background: none; border: none; color: var(--text-secondary); font-size: 13px; cursor: pointer; padding: 0; margin-bottom: 28px; font-family: inherit; }
        .hc-back:hover { color: var(--gold); }
        .hc-title { font-family: 'Clash Display', sans-serif; font-size: 28px; font-weight: 600; margin: 0 0 8px; }
        .hc-sub { font-size: 13.5px; color: var(--text-secondary); margin: 0 0 36px; }
        .hc-section-title { font-size: 12px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--gold); margin: 32px 0 4px; }
        .hc-item { border-bottom: 1px solid var(--border-soft); }
        .hc-question {
          width: 100%; text-align: left; background: none; border: none; cursor: pointer; font-family: inherit;
          font-size: 14px; color: var(--text-primary); padding: 14px 0; display: flex; align-items: center; justify-content: space-between; gap: 12px;
        }
        .hc-answer { font-size: 13.5px; color: var(--text-secondary); line-height: 1.65; margin: 0 0 16px; padding-right: 24px; }
        .hc-contact {
          margin-top: 40px; background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px;
          padding: 20px; display: flex; align-items: center; gap: 14px;
        }
        .hc-contact svg { color: var(--gold); flex-shrink: 0; }
        .hc-contact p { margin: 0; font-size: 13.5px; color: var(--text-secondary); }
        .hc-contact b { color: var(--text-primary); }
      `}</style>

      <div className="hc-wrap">
        <button className="hc-back" onClick={() => navigate(-1)}><ArrowLeft size={14} /> Back</button>
        <h1 className="hc-title">Help centre</h1>
        <p className="hc-sub">Answers to common questions about scanning, results, and your account.</p>

        {FAQ_SECTIONS.map((section) => (
          <div key={section.title}>
            <p className="hc-section-title">{section.title}</p>
            {section.items.map((item) => <FaqItem key={item.q} q={item.q} a={item.a} />)}
          </div>
        ))}

        <div className="hc-contact">
          <Mail size={20} />
          <p>Can't find what you need? Contact us for assistance.</p>
        </div>
      </div>
    </div>
  );
}

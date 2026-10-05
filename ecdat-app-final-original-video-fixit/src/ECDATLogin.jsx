import React, { useState } from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { Mail, Lock, Eye, EyeOff, ShieldCheck, ArrowRight, Loader2, CheckCircle2, ArrowLeft, User } from 'lucide-react';
import { useAuth, nameFromEmail } from './context/AuthContext.jsx';
import { forgotPasswordApi } from './api/index.js';

// Real post-quantum / legacy algorithm identifiers — floated in the lattice
// panel so the visual is literally built from this product's subject matter.
const ALGO_TAGS = [
  { name: 'ML-KEM-768', status: 'ready' },
  { name: 'ML-DSA-65', status: 'ready' },
  { name: 'SLH-DSA', status: 'ready' },
  { name: 'RSA-2048', status: 'risk' },
  { name: 'ECDSA P-256', status: 'risk' },
  { name: 'AES-256-GCM', status: 'ready' },
];

// Hand-placed isometric blocks + the chain links connecting them. This is
// the signature element now: a staircase of isometric cubes reads as
// blockchain blocks being appended, with gold "verified" blocks linked by
// pulsing chain lines and a dashed line to the next, pending block.
const CUBES = [
  { cx: 90,  cy: 430, s: 42, warm: true },
  { cx: 172, cy: 392, s: 42, warm: true },
  { cx: 254, cy: 352, s: 44, warm: true },
  { cx: 336, cy: 314, s: 44, warm: true },
  { cx: 416, cy: 274, s: 38, warm: false },
  { cx: 118, cy: 288, s: 24, warm: false },
  { cx: 486, cy: 196, s: 28, warm: false },
  { cx: 528, cy: 340, s: 22, warm: false },
  { cx: 58,  cy: 176, s: 20, warm: false },
  { cx: 388, cy: 116, s: 24, warm: false },
];
const CHAIN_LINKS = [
  { from: 0, to: 1, pending: false },
  { from: 1, to: 2, pending: false },
  { from: 2, to: 3, pending: false },
  { from: 3, to: 4, pending: true },
];
function isoCube(cx, cy, s, warm) {
  const w = s, h = s * 0.5, d = s * 0.9;
  const T = `${cx},${cy - h}`, R = `${cx + w},${cy}`;
  const B = `${cx},${cy + h}`, L = `${cx - w},${cy}`;
  const Bd = `${cx},${cy + h + d}`, Ld = `${cx - w},${cy + d}`, Rd = `${cx + w},${cy + d}`;
  return {
    top: `${T} ${R} ${B} ${L}`,
    left: `${L} ${B} ${Bd} ${Ld}`,
    right: `${R} ${B} ${Bd} ${Rd}`,
    warm,
  };
}

export default function ECDATLogin() {
  const navigate = useNavigate();
  const location = useLocation();
  const redirectTo = location.state?.from || '/dashboard';
  const { login, register } = useAuth();
  const [mode, setMode] = useState('signin'); // 'signin' | 'signup' | 'signup-profile' | 'reset' | 'reset-sent'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [errors, setErrors] = useState({});
  const [submitting, setSubmitting] = useState(false);

  const validEmail = (v) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);

  const handleSubmit = async (e) => {
    e.preventDefault();
    const next = {};
    if (mode === 'signup-profile') {
      if (!fullName.trim()) next.fullName = 'Enter your name.';
      setErrors(next);
      if (Object.keys(next).length) return;
      setSubmitting(true);
      try {
        await register(fullName.trim(), email, password);
        navigate(redirectTo);
      } catch (err) {
        setErrors({ form: err.message || 'Registration failed' });
      } finally {
        setSubmitting(false);
      }
      return;
    }

    if (!validEmail(email)) next.email = 'Enter a valid work email address.';
    if ((mode === 'signin' || mode === 'signup') && password.length < 1) next.password = 'Enter your password.';
    setErrors(next);
    if (Object.keys(next).length) return;

    if (mode === 'signup') {
      setMode('signup-profile');
      return;
    }
    if (mode === 'reset') {
      setSubmitting(true);
      try {
        await forgotPasswordApi(email);
        navigate('/reset-password', { state: { email: email.trim().toLowerCase() } });
      } catch (err) {
        setErrors({ form: err.message || "We couldn't send the code right now. Please try again later." });
      } finally {
        setSubmitting(false);
      }
      return;
    }

    // Sign in mode
    setSubmitting(true);
    try {
      await login(email, password);
      navigate(redirectTo);
    } catch (err) {
      setErrors({ form: err.message || 'Invalid email or password' });
    } finally {
      setSubmitting(false);
    }
  };

  const switchMode = (next) => {
    setErrors({});
    setMode(next);
  };

  return (
    <div className="ecdat-root">
      <style>{`

        .ecdat-root {
          --ink: #0a0d12;
          --ink-2: #0d1118;
          --surface: #12161d;
          --surface-2: #171c25;
          --hairline: #262e3a;
          --hairline-soft: #1b2129;
          --text: #e8eaef;
          --text-muted: #8a93a3;
          --text-faint: #545e6e;
          --gold: #c9a227;
          --gold-soft: rgba(201, 162, 39, 0.14);
          --crimson: #c1503a;
          --teal: #3fb8af;

          font-family: 'Inter', system-ui, sans-serif;
          color: var(--text);
          background: var(--ink);
          min-height: 100vh;
          width: 100%;
          display: flex;
          align-items: stretch;
          box-sizing: border-box;
        }
        .ecdat-root *, .ecdat-root *::before, .ecdat-root *::after { box-sizing: border-box; }

        .ecdat-mono { font-family: 'IBM Plex Mono', monospace; }
        .ecdat-display { font-family: 'Space Grotesk', 'Inter', sans-serif; }

        /* ---------- Left: lattice panel ---------- */
        .ecdat-lattice-panel {
          position: relative;
          flex: 1.15 1 0;
          min-width: 0;
          background:
            radial-gradient(circle at 20% 15%, #10151d 0%, var(--ink) 55%),
            var(--ink-2);
          overflow: hidden;
          display: flex;
          flex-direction: column;
          justify-content: space-between;
          padding: 40px;
          border-right: 1px solid var(--hairline-soft);
        }
        .ecdat-lattice-svg { position: absolute; inset: 0; width: 100%; height: 100%; opacity: 0.95; }
        .ecdat-chain-link {
          stroke: var(--gold); stroke-width: 1.5; opacity: 0.55;
          animation: ecdat-edge-pulse 5s ease-in-out infinite;
        }
        .ecdat-chain-link.pending { stroke: var(--hairline); stroke-dasharray: 5 5; opacity: 0.45; animation: none; }
        .ecdat-cube .face { stroke-width: 1.2; }
        .ecdat-cube .face-top { fill: var(--ink-2); stroke: var(--hairline); }
        .ecdat-cube .face-left { fill: #06080c; stroke: var(--hairline-soft); }
        .ecdat-cube .face-right { fill: #0d121a; stroke: var(--hairline-soft); }
        .ecdat-cube.warm .face-top { fill: rgba(201, 162, 39, 0.16); stroke: var(--gold); }
        .ecdat-cube.warm .face-left { fill: #16130a; stroke: rgba(201, 162, 39, 0.35); }
        .ecdat-cube.warm .face-right { fill: #1c1810; stroke: rgba(201, 162, 39, 0.45); }

        @keyframes ecdat-edge-pulse {
          0%, 100% { opacity: 0.12; }
          50% { opacity: 0.75; }
        }

        .ecdat-tag {
          position: absolute;
          font-size: 11px;
          letter-spacing: 0.04em;
          padding: 4px 9px;
          border-radius: 3px;
          border: 1px solid var(--hairline);
          background: rgba(13, 17, 24, 0.82);
          backdrop-filter: blur(2px);
          white-space: nowrap;
          animation: ecdat-tag-drift 9s ease-in-out infinite;
        }
        .ecdat-tag.ready { color: var(--teal); border-color: rgba(63,184,175,0.35); }
        .ecdat-tag.risk { color: var(--crimson); border-color: rgba(193,80,58,0.35); }

        @keyframes ecdat-tag-drift {
          0%, 100% { transform: translateY(0px); opacity: 0.85; }
          50% { transform: translateY(-6px); opacity: 1; }
        }

        .ecdat-brandrow { position: relative; z-index: 2; display: flex; align-items: center; gap: 10px; }
        .ecdat-seal {
          width: 34px; height: 34px; border-radius: 999px;
          border: 1px solid var(--gold);
          display: flex; align-items: center; justify-content: center;
          color: var(--gold);
          flex-shrink: 0;
        }
        .ecdat-wordmark { font-size: 15px; font-weight: 600; letter-spacing: 0.08em; }
        .ecdat-wordmark span { color: var(--text-muted); font-weight: 500; }

        .ecdat-lattice-copy {
          position: relative; z-index: 2; max-width: 420px;
          background: rgba(10, 13, 18, 0.72);
          backdrop-filter: blur(3px);
          border-radius: 10px;
          padding: 16px 18px;
          margin: -34px -18px 0;
        }
        .ecdat-eyebrow {
          font-size: 11px; letter-spacing: 0.16em; color: var(--gold);
          text-transform: uppercase; margin-bottom: 14px; display: block;
        }
        .ecdat-headline {
          font-size: 30px; line-height: 1.25; font-weight: 600; letter-spacing: -0.01em;
          margin: 0 0 14px 0;
        }
        .ecdat-sub { font-size: 14px; line-height: 1.6; color: var(--text-muted); margin: 0; }

        .ecdat-lattice-footer {
          position: relative; z-index: 2;
          display: flex; gap: 22px; padding-top: 22px; border-top: 1px solid var(--hairline-soft);
          font-size: 11px; color: var(--text-faint); letter-spacing: 0.03em;
        }

        /* ---------- Right: form panel ---------- */
        .ecdat-form-panel {
          flex: 1 1 0;
          min-width: 0;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 40px 32px;
          background: var(--ink);
        }
        .ecdat-form-card { width: 100%; max-width: 380px; }

        .ecdat-form-head { margin-bottom: 30px; }
        .ecdat-form-eyebrow {
          font-size: 11px; letter-spacing: 0.14em; text-transform: uppercase;
          color: var(--text-faint); margin-bottom: 10px;
        }
        .ecdat-form-title { font-size: 22px; font-weight: 600; margin: 0 0 6px 0; letter-spacing: -0.01em; }
        .ecdat-form-desc { font-size: 13.5px; color: var(--text-muted); margin: 0; line-height: 1.5; }

        .ecdat-field { margin-bottom: 16px; }
        .ecdat-field label {
          display: block; font-size: 12px; font-weight: 500; color: var(--text-muted);
          margin-bottom: 7px; letter-spacing: 0.01em;
        }
        .ecdat-input-wrap {
          position: relative; display: flex; align-items: center;
          background: var(--surface-2);
          border: 1px solid var(--hairline);
          border-radius: 6px;
          transition: border-color 0.15s ease, box-shadow 0.15s ease;
        }
        .ecdat-input-wrap:focus-within {
          border-color: var(--gold);
          box-shadow: 0 0 0 3px var(--gold-soft);
        }
        .ecdat-input-wrap.error { border-color: var(--crimson); }
        .ecdat-input-wrap svg { margin-left: 12px; color: var(--text-faint); flex-shrink: 0; }
        .ecdat-input-wrap input {
          flex: 1; min-width: 0; background: transparent; border: none; outline: none;
          padding: 11px 12px; font-size: 14px; color: var(--text); font-family: inherit;
        }
        .ecdat-input-wrap input::placeholder { color: var(--text-faint); }
        .ecdat-eye-btn {
          background: none; border: none; padding: 8px 11px; cursor: pointer;
          color: var(--text-faint); display: flex; align-items: center;
        }
        .ecdat-eye-btn:hover { color: var(--text-muted); }
        .ecdat-error-msg { font-size: 12px; color: var(--crimson); margin-top: 6px; }

        .ecdat-row-between { display: flex; justify-content: space-between; align-items: center; margin: -4px 0 20px 0; }
        .ecdat-check-label { display: flex; align-items: center; gap: 7px; font-size: 12.5px; color: var(--text-muted); cursor: pointer; user-select: none; }
        .ecdat-check-label input { accent-color: var(--gold); }
        .ecdat-link {
          background: none; border: none; padding: 0; cursor: pointer;
          font-size: 12.5px; color: var(--gold); font-family: inherit;
        }
        .ecdat-link:hover { text-decoration: underline; }
        .ecdat-back-link {
          display: inline-flex; align-items: center; gap: 6px;
          background: none; border: none; padding: 0; cursor: pointer;
          font-size: 12.5px; color: var(--text-muted); font-family: inherit; margin-bottom: 22px;
        }
        .ecdat-back-link:hover { color: var(--text); }

        .ecdat-submit {
          width: 100%; display: flex; align-items: center; justify-content: center; gap: 8px;
          background: var(--gold); color: #191308; border: none; border-radius: 6px;
          padding: 12px 16px; font-size: 14px; font-weight: 600; cursor: pointer;
          font-family: inherit; transition: filter 0.15s ease, transform 0.05s ease;
        }
        .ecdat-submit:hover { filter: brightness(1.08); }
        .ecdat-submit:active { transform: translateY(1px); }
        .ecdat-submit:disabled { opacity: 0.75; cursor: progress; }
        .ecdat-spin { animation: ecdat-spin 0.8s linear infinite; }
        @keyframes ecdat-spin { to { transform: rotate(360deg); } }

        .ecdat-form-msg {
          font-size: 12.5px; color: var(--text-muted); background: var(--surface-2);
          border: 1px solid var(--hairline); border-radius: 6px; padding: 10px 12px; margin-bottom: 18px;
        }

        .ecdat-divider { display: flex; align-items: center; gap: 12px; margin: 24px 0 18px 0; }
        .ecdat-divider::before, .ecdat-divider::after { content: ''; flex: 1; height: 1px; background: var(--hairline); }
        .ecdat-divider span { font-size: 11px; color: var(--text-faint); letter-spacing: 0.06em; }

        .ecdat-footnote { font-size: 11.5px; color: var(--text-faint); text-align: center; line-height: 1.6; }
        .ecdat-footnote b { color: var(--text-muted); font-weight: 500; }

        .ecdat-success-icon { color: var(--teal); margin-bottom: 18px; }

        @media (max-width: 900px) {
          .ecdat-root { flex-direction: column; }
          .ecdat-lattice-panel { flex: none; min-height: 220px; border-right: none; border-bottom: 1px solid var(--hairline-soft); padding: 28px 24px; }
          .ecdat-headline { font-size: 22px; }
          .ecdat-sub { display: none; }
          .ecdat-lattice-footer { display: none; }
          .ecdat-form-panel { padding: 32px 22px 48px; }
        }
        @media (prefers-reduced-motion: reduce) {
          .ecdat-chain-link, .ecdat-tag, .ecdat-spin { animation: none !important; }
        }
      `}</style>

      {/* ---------------- Left panel: the lattice / seal signature ---------------- */}
      <div className="ecdat-lattice-panel">
        <svg className="ecdat-lattice-svg" viewBox="0 0 600 500" preserveAspectRatio="xMidYMid slice">
          {CHAIN_LINKS.map((link, i) => {
            const a = CUBES[link.from], b = CUBES[link.to];
            return (
              <line
                key={i}
                x1={a.cx} y1={a.cy} x2={b.cx} y2={b.cy}
                className={`ecdat-chain-link ${link.pending ? 'pending' : ''}`}
                style={link.pending ? undefined : { animationDelay: `${i * 0.8}s` }}
              />
            );
          })}
          {CUBES.map((c, i) => {
            const p = isoCube(c.cx, c.cy, c.s, c.warm);
            return (
              <g key={i} className={`ecdat-cube ${c.warm ? 'warm' : ''}`}>
                <polygon points={p.left} className="face face-left" />
                <polygon points={p.right} className="face face-right" />
                <polygon points={p.top} className="face face-top" />
              </g>
            );
          })}
        </svg>

        {ALGO_TAGS.map((tag, i) => (
          <span
            key={tag.name}
            className={`ecdat-tag ${tag.status} ecdat-mono`}
            style={{
              left: `${[66, 86, 63, 84, 65, 88][i]}%`,
              top: `${[16, 34, 54, 68, 74, 50][i]}%`,
              animationDelay: `${i * 1.1}s`,
            }}
          >
            {tag.name}
          </span>
        ))}

        <div className="ecdat-brandrow">
          <div className="ecdat-seal"><ShieldCheck size={17} strokeWidth={1.75} /></div>
          <div className="ecdat-wordmark ecdat-mono">SEMICOLON</div>
        </div>

        <div className="ecdat-lattice-copy">
          <span className="ecdat-eyebrow ecdat-mono">CRYPTOGRAPHIC DISCOVERY &amp; RISK PLATFORM</span>
          <h1 className="ecdat-headline ecdat-display">
            Every cipher in your enterprise, mapped and graded before it's a liability.
          </h1>
          <p className="ecdat-sub">
            SEMICOLON crawls networks, endpoints, and code to build a live inventory of every
            algorithm, key, and certificate in use — and flags what won't survive a
            quantum-capable adversary.
          </p>
        </div>

        <div className="ecdat-lattice-footer ecdat-mono">
          <span>3,482 SCANNED</span>
          <span>212 QUANTUM-AT-RISK</span>
          <span>SESSION AES-256-GCM</span>
        </div>
      </div>

      {/* ---------------- Right panel: the actual form ---------------- */}
      <div className="ecdat-form-panel">
        <div className="ecdat-form-card">
          {mode === 'reset-sent' ? (
            <div>
              <div className="ecdat-success-icon"><CheckCircle2 size={30} strokeWidth={1.75} /></div>
              <h2 className="ecdat-form-title ecdat-display">Check your inbox</h2>
              <p className="ecdat-form-desc" style={{ marginBottom: 26 }}>
                If <b style={{ color: 'var(--text)' }}>{email}</b> matches a Semicolon account, a reset
                link is on its way. It expires in 15 minutes.
              </p>
              <button type="button" className="ecdat-back-link" onClick={() => switchMode('signin')}>
                <ArrowLeft size={14} /> Back to sign in
              </button>
            </div>
          ) : (
            <>
              {(mode === 'reset' || mode === 'signup') && (
                <button type="button" className="ecdat-back-link" onClick={() => switchMode('signin')}>
                  <ArrowLeft size={14} /> Back to sign in
                </button>
              )}
              {mode === 'signup-profile' && (
                <button type="button" className="ecdat-back-link" onClick={() => switchMode('signup')}>
                  <ArrowLeft size={14} /> Back
                </button>
              )}

              <div className="ecdat-form-head">
                <div className="ecdat-form-eyebrow ecdat-mono">
                  {mode === 'signin' && 'AUTHORIZED PERSONNEL ONLY'}
                  {mode === 'signup' && 'CREATE ACCOUNT'}
                  {mode === 'signup-profile' && 'ALMOST DONE'}
                  {mode === 'reset' && 'RESET PASSWORD'}
                </div>
                <h2 className="ecdat-form-title ecdat-display">
                  {mode === 'signin' && 'Sign in to Semicolon'}
                  {mode === 'signup' && 'Create your account'}
                  {mode === 'signup-profile' && 'Tell us about you'}
                  {mode === 'reset' && 'Reset your password'}
                </h2>
                <p className="ecdat-form-desc">
                  {mode === 'signin' && 'Use your organization credentials to reach the discovery dashboard.'}
                  {mode === 'signup' && 'Set up access with your work email and a password.'}
                  {mode === 'signup-profile' && 'This name is what shows on your findings, reports, and profile.'}
                  {mode === 'reset' && "Enter the email on your account and we'll email you a 6-digit code."}
                </p>
              </div>

              {errors.form && <div className="ecdat-form-msg">{errors.form}</div>}

              <form onSubmit={handleSubmit} noValidate>
                {mode === 'signup-profile' ? (
                  <div className="ecdat-field">
                    <label htmlFor="ecdat-name">Full name</label>
                    <div className={`ecdat-input-wrap ${errors.fullName ? 'error' : ''}`}>
                      <User size={16} />
                      <input
                        id="ecdat-name"
                        type="text"
                        placeholder="Jane Doe"
                        value={fullName}
                        onChange={(e) => setFullName(e.target.value)}
                        autoComplete="name"
                        autoFocus
                      />
                    </div>
                    {errors.fullName && <div className="ecdat-error-msg">{errors.fullName}</div>}
                  </div>
                ) : (
                  <div className="ecdat-field">
                    <label htmlFor="ecdat-email">Work email</label>
                    <div className={`ecdat-input-wrap ${errors.email ? 'error' : ''}`}>
                      <Mail size={16} />
                      <input
                        id="ecdat-email"
                        type="email"
                        placeholder="you@organization.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        autoComplete="email"
                      />
                    </div>
                    {errors.email && <div className="ecdat-error-msg">{errors.email}</div>}
                  </div>
                )}

                {(mode === 'signin' || mode === 'signup') && (
                  <div className="ecdat-field">
                    <label htmlFor="ecdat-password">Password</label>
                    <div className={`ecdat-input-wrap ${errors.password ? 'error' : ''}`}>
                      <Lock size={16} />
                      <input
                        id="ecdat-password"
                        type={showPassword ? 'text' : 'password'}
                        placeholder="••••••••••••"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                      />
                      <button
                        type="button"
                        className="ecdat-eye-btn"
                        onClick={() => setShowPassword((s) => !s)}
                        aria-label={showPassword ? 'Hide password' : 'Show password'}
                      >
                        {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                    {errors.password && <div className="ecdat-error-msg">{errors.password}</div>}
                  </div>
                )}

                {mode === 'signin' && (
                  <div className="ecdat-row-between">
                    <label className="ecdat-check-label">
                      <input type="checkbox" /> Keep me signed in
                    </label>
                    <button type="button" className="ecdat-link" onClick={() => switchMode('reset')}>
                      Forgot password?
                    </button>
                  </div>
                )}

                <button type="submit" className="ecdat-submit" disabled={submitting}>
                  {submitting ? (
                    <>
                      <Loader2 size={16} className="ecdat-spin" /> {mode === 'signup-profile' ? 'Creating account…' : 'Verifying…'}
                    </>
                  ) : (
                    <>
                      {mode === 'signin' && 'Sign in'}
                      {mode === 'signup' && 'Continue'}
                      {mode === 'signup-profile' && 'Create account'}
                      {mode === 'reset' && 'Send 6-digit code'}
                      <ArrowRight size={16} />
                    </>
                  )}
                </button>
              </form>

              <div className="ecdat-divider"><span>SECURITY</span></div>
              {mode === 'signin' && (
                <p className="ecdat-footnote">
                  All sessions are logged and encrypted end-to-end.<br />
                  Don't have an account? <button type="button" className="ecdat-link" onClick={() => switchMode('signup')}>Create one</button>
                </p>
              )}
              {mode === 'signup' && (
                <p className="ecdat-footnote">
                  All sessions are logged and encrypted end-to-end.<br />
                  Already have an account? <button type="button" className="ecdat-link" onClick={() => switchMode('signin')}>Sign in</button>
                </p>
              )}
              {(mode === 'signup-profile' || mode === 'reset') && (
                <p className="ecdat-footnote">
                  All sessions are logged and encrypted end-to-end.
                </p>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}

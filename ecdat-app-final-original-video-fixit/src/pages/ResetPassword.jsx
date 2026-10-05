import React, { useRef, useState, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { Lock, Mail, Eye, EyeOff, ShieldCheck, CheckCircle2, ArrowRight, Loader2, AlertTriangle, ArrowLeft } from 'lucide-react';
import { resetPasswordApi, forgotPasswordApi } from '../api/index.js';

const OTP_LEN = 6;
const RESEND_SECONDS = 60;

export default function ResetPassword() {
  const navigate = useNavigate();
  const location = useLocation();

  const [email, setEmail] = useState(location.state?.email || '');
  const [digits, setDigits] = useState(Array(OTP_LEN).fill(''));
  const inputRefs = useRef([]);
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [success, setSuccess] = useState(false);
  const [errors, setErrors] = useState({});
  const [info, setInfo] = useState(location.state?.email ? 'We emailed a 6-digit code to your registered address.' : '');
  const [cooldown, setCooldown] = useState(location.state?.email ? RESEND_SECONDS : 0);

  const otp = digits.join('');

  useEffect(() => {
    if (cooldown <= 0) return;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  const setDigit = (i, v) => {
    const d = v.replace(/\D/g, '').slice(-1);
    setDigits((prev) => { const n = [...prev]; n[i] = d; return n; });
    if (d && i < OTP_LEN - 1) inputRefs.current[i + 1]?.focus();
  };
  const onKeyDown = (i, e) => {
    if (e.key === 'Backspace' && !digits[i] && i > 0) inputRefs.current[i - 1]?.focus();
  };
  const onPaste = (e) => {
    const pasted = e.clipboardData.getData('text').replace(/\D/g, '').slice(0, OTP_LEN);
    if (!pasted) return;
    e.preventDefault();
    setDigits(Array.from({ length: OTP_LEN }, (_, i) => pasted[i] || ''));
    inputRefs.current[Math.min(pasted.length, OTP_LEN - 1)]?.focus();
  };

  const handleResend = async () => {
    if (cooldown > 0 || !email) return;
    setErrors({});
    try {
      await forgotPasswordApi(email);
      setInfo('A new code has been sent. Older codes no longer work.');
      setCooldown(RESEND_SECONDS);
      setDigits(Array(OTP_LEN).fill(''));
      inputRefs.current[0]?.focus();
    } catch (err) {
      setErrors({ form: err.message || "We couldn't send the code right now." });
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const next = {};
    if (!/^\S+@\S+\.\S+$/.test(email)) next.email = 'Enter the email address of your account.';
    if (otp.length !== OTP_LEN) next.otp = 'Enter the full 6-digit code.';
    if (password.length < 6) next.password = 'Password must be at least 6 characters.';
    if (password !== confirmPassword) next.confirmPassword = 'Passwords do not match.';
    setErrors(next);
    if (Object.keys(next).length > 0) return;

    setSubmitting(true);
    try {
      await resetPasswordApi(email.trim().toLowerCase(), otp, password);
      setSuccess(true);
    } catch (err) {
      setErrors({ form: err.message || 'Invalid or expired code. Request a new one.' });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="reset-root">
      <style>{`
        .reset-root {
          --ink: #0a0d12;
          --surface: #12161d;
          --surface-2: #171c25;
          --border: #262e3a;
          --text: #e8eaef;
          --text-muted: #8a93a3;
          --gold: #c9a227;
          --gold-hover: #dbb332;
          --crimson: #c1503a;
          --teal: #3fb8af;

          font-family: 'Inter', system-ui, sans-serif;
          color: var(--text);
          background: var(--ink);
          min-height: 100vh;
          width: 100%;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 24px;
          box-sizing: border-box;
        }

        .reset-card {
          width: 100%;
          max-width: 440px;
          background: var(--surface);
          border: 1px solid var(--border);
          border-radius: 14px;
          padding: 36px 32px;
          box-shadow: 0 20px 50px rgba(0, 0, 0, 0.6);
        }

        .reset-brand {
          display: flex;
          align-items: center;
          gap: 10px;
          color: var(--gold);
          font-weight: 700;
          font-size: 16px;
          letter-spacing: 0.05em;
          margin-bottom: 24px;
        }

        .reset-title {
          font-size: 22px;
          font-weight: 700;
          margin: 0 0 8px;
          color: #ffffff;
        }

        .reset-desc {
          font-size: 13.5px;
          color: var(--text-muted);
          margin: 0 0 24px;
          line-height: 1.5;
        }

        .reset-field {
          margin-bottom: 20px;
        }

        .reset-field label {
          display: block;
          font-size: 12px;
          font-weight: 600;
          color: var(--text-muted);
          margin-bottom: 6px;
          text-transform: uppercase;
          letter-spacing: 0.04em;
        }

        .reset-input-wrap {
          position: relative;
        }

        .reset-input-icon {
          position: absolute;
          left: 12px;
          top: 50%;
          transform: translateY(-50%);
          color: var(--text-muted);
        }

        .reset-input-toggle {
          position: absolute;
          right: 12px;
          top: 50%;
          transform: translateY(-50%);
          color: var(--text-muted);
          background: none;
          border: none;
          cursor: pointer;
          padding: 0;
        }

        .reset-input {
          width: 100%;
          background: var(--surface-2);
          border: 1px solid var(--border);
          border-radius: 8px;
          padding: 11px 40px 11px 40px;
          color: var(--text);
          font-size: 14px;
          font-family: inherit;
          transition: border-color 0.15s ease;
        }

        .reset-input:focus {
          outline: none;
          border-color: var(--gold);
        }

        .reset-error {
          font-size: 12px;
          color: var(--crimson);
          margin-top: 6px;
          display: flex;
          align-items: center;
          gap: 6px;
        }

        .reset-banner-error {
          background: rgba(193, 80, 58, 0.12);
          border: 1px solid rgba(193, 80, 58, 0.3);
          color: #f87171;
          border-radius: 8px;
          padding: 12px 14px;
          font-size: 13px;
          margin-bottom: 20px;
          display: flex;
          align-items: center;
          gap: 10px;
          line-height: 1.4;
        }

        .reset-btn {
          width: 100%;
          padding: 12px;
          border-radius: 8px;
          border: 1px solid var(--gold);
          background: var(--gold);
          color: #0d1118;
          font-weight: 700;
          font-size: 14px;
          cursor: pointer;
          display: flex;
          align-items: center;
          justify-content: center;
          gap: 8px;
          transition: filter 0.15s ease;
        }

        .reset-btn:hover {
          filter: brightness(1.08);
        }

        .reset-btn:disabled {
          opacity: 0.6;
          cursor: not-allowed;
        }

        .reset-otp-row { display: flex; gap: 8px; justify-content: space-between; }
        .reset-otp-box {
          width: 100%; min-width: 0; aspect-ratio: 1 / 1.15; text-align: center;
          font-size: 22px; font-weight: 700; font-family: ui-monospace, monospace;
          background: var(--surface-2); border: 1px solid var(--border); border-radius: 8px;
          color: var(--text);
        }
        .reset-otp-box:focus { outline: none; border-color: var(--gold); }
        .reset-resend {
          background: none; border: none; padding: 0; margin-top: 10px; cursor: pointer;
          color: var(--gold); font-size: 12.5px; font-weight: 600; font-family: inherit;
        }
        .reset-resend:disabled { color: var(--text-muted); cursor: default; }
        .reset-banner-info {
          background: rgba(63, 184, 175, 0.1); border: 1px solid rgba(63, 184, 175, 0.3);
          color: var(--teal); border-radius: 8px; padding: 12px 14px; font-size: 13px;
          margin-bottom: 20px; display: flex; align-items: center; gap: 10px; line-height: 1.4;
        }

        .reset-success-card {
          text-align: center;
        }

        .reset-success-icon {
          width: 56px;
          height: 56px;
          border-radius: 50%;
          background: rgba(63, 184, 175, 0.15);
          color: var(--teal);
          display: flex;
          align-items: center;
          justify-content: center;
          margin: 0 auto 16px;
        }

        .reset-back-link {
          display: inline-flex;
          align-items: center;
          gap: 8px;
          margin-top: 20px;
          font-size: 13.5px;
          color: var(--gold);
          text-decoration: none;
          font-weight: 600;
        }

        .reset-back-link:hover {
          text-decoration: underline;
        }
      `}</style>

      <div className="reset-card">
        <div className="reset-brand">
          <ShieldCheck size={22} /> ECDAT PLATFORM
        </div>

        {success ? (
          <div className="reset-success-card">
            <div className="reset-success-icon">
              <CheckCircle2 size={32} />
            </div>
            <h1 className="reset-title">Password Reset Complete</h1>
            <p className="reset-desc">
              Your password has been successfully updated. You can now return to the login screen and sign in with your new credentials.
            </p>
            <button className="reset-btn" onClick={() => navigate('/login')}>
              Return to Login <ArrowRight size={16} />
            </button>
          </div>
        ) : (
          <>
            <h1 className="reset-title">Reset Your Password</h1>
            <p className="reset-desc">
              Enter the 6-digit code we emailed you and choose a new password.
            </p>

            {errors.form && (
              <div className="reset-banner-error">
                <AlertTriangle size={18} />
                <span>{errors.form}</span>
              </div>
            )}

            {info && !errors.form && (
              <div className="reset-banner-info">
                <CheckCircle2 size={18} />
                <span>{info}</span>
              </div>
            )}

            <form onSubmit={handleSubmit}>
              <div className="reset-field">
                <label>Account Email</label>
                <div className="reset-input-wrap">
                  <Mail size={16} className="reset-input-icon" />
                  <input
                    type="email"
                    className="reset-input"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                  />
                </div>
                {errors.email && <div className="reset-error">{errors.email}</div>}
              </div>

              <div className="reset-field">
                <label>6-Digit Code</label>
                <div className="reset-otp-row" onPaste={onPaste}>
                  {digits.map((d, i) => (
                    <input
                      key={i}
                      ref={(el) => (inputRefs.current[i] = el)}
                      className="reset-otp-box"
                      inputMode="numeric"
                      autoComplete={i === 0 ? 'one-time-code' : 'off'}
                      maxLength={1}
                      value={d}
                      onChange={(e) => setDigit(i, e.target.value)}
                      onKeyDown={(e) => onKeyDown(i, e)}
                      aria-label={`Digit ${i + 1}`}
                    />
                  ))}
                </div>
                {errors.otp && <div className="reset-error">{errors.otp}</div>}
                <button type="button" className="reset-resend" onClick={handleResend} disabled={cooldown > 0}>
                  {cooldown > 0 ? `Resend code in ${cooldown}s` : 'Resend code'}
                </button>
              </div>

              <div className="reset-field">
                <label>New Password</label>
                <div className="reset-input-wrap">
                  <Lock size={16} className="reset-input-icon" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    className="reset-input"
                    placeholder="At least 6 characters"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                  />
                  <button
                    type="button"
                    className="reset-input-toggle"
                    onClick={() => setShowPassword(!showPassword)}
                  >
                    {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                </div>
                {errors.password && <div className="reset-error">{errors.password}</div>}
              </div>

              <div className="reset-field">
                <label>Confirm New Password</label>
                <div className="reset-input-wrap">
                  <Lock size={16} className="reset-input-icon" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    className="reset-input"
                    placeholder="Repeat new password"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    required
                  />
                </div>
                {errors.confirmPassword && <div className="reset-error">{errors.confirmPassword}</div>}
              </div>

              <button className="reset-btn" type="submit" disabled={submitting}>
                {submitting ? (
                  <>
                    <Loader2 size={16} className="spin" /> Resetting Password...
                  </>
                ) : (
                  <>
                    Reset Password <ArrowRight size={16} />
                  </>
                )}
              </button>

              <div style={{ textAlign: 'center', marginTop: 16 }}>
                <Link to="/login" className="reset-back-link">
                  <ArrowLeft size={16} /> Back to Sign In
                </Link>
              </div>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

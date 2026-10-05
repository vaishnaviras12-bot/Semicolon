import React, { useState, useEffect, useMemo } from 'react';

const VARIANTS = ['cubes', 'particles', 'rings'];

// Small, self-contained abstract backdrops — no heavy 3D library, just
// CSS-driven motion, so this stays fast and dependency-free.
const PARTICLES = Array.from({ length: 26 }, (_, i) => ({
  x: (i * 37) % 100,
  y: (i * 53) % 100,
  d: 3 + (i % 5),
  delay: (i % 10) * 0.3,
}));

const CUBES = [
  { x: 30, y: 40, s: 34 }, { x: 55, y: 30, s: 26 }, { x: 70, y: 55, s: 30 },
  { x: 42, y: 62, s: 22 }, { x: 20, y: 65, s: 18 },
];
function isoPoints(cx, cy, s) {
  const w = s, h = s * 0.5, d = s * 0.85;
  const T = `${cx},${cy - h}`, R = `${cx + w},${cy}`, B = `${cx},${cy + h}`, L = `${cx - w},${cy}`;
  const Bd = `${cx},${cy + h + d}`, Ld = `${cx - w},${cy + d}`, Rd = `${cx + w},${cy + d}`;
  return { top: `${T} ${R} ${B} ${L}`, left: `${L} ${B} ${Bd} ${Ld}`, right: `${R} ${B} ${Bd} ${Rd}` };
}

export default function Splash({ onFinish, duration = 1400 }) {
  const variant = useMemo(() => VARIANTS[Math.floor(Math.random() * VARIANTS.length)], []);
  const [leaving, setLeaving] = useState(false);

  useEffect(() => {
    const t1 = setTimeout(() => setLeaving(true), Math.max(duration - 320, 0));
    const t2 = setTimeout(() => onFinish && onFinish(), duration);
    return () => { clearTimeout(t1); clearTimeout(t2); };
  }, [duration, onFinish]);

  return (
    <div className={`sentinel-splash ${leaving ? 'leaving' : ''}`}>
      <style>{`
        .sentinel-splash {
          position: fixed; inset: 0; z-index: 999;
          background: #14181f;
          display: flex; align-items: center; justify-content: center;
          overflow: hidden;
          opacity: 1; transition: opacity 0.3s ease;
        }
        .sentinel-splash.leaving { opacity: 0; }
        .splash-bg { position: absolute; inset: 0; opacity: 0.5; }
        .splash-word {
          position: relative; z-index: 2;
          font-family: 'Clash Display', sans-serif; font-weight: 600;
          font-size: clamp(28px, 6vw, 56px); letter-spacing: 0.14em;
          color: #e8eaef;
          animation: splash-fade-in 0.6s ease;
        }
        @keyframes splash-fade-in {
          from { opacity: 0; letter-spacing: 0.3em; }
          to { opacity: 1; letter-spacing: 0.14em; }
        }
        .splash-particle {
          position: absolute; width: 3px; height: 3px; border-radius: 999px;
          background: #c9a227; animation: splash-drift ease-in-out infinite;
        }
        @keyframes splash-drift {
          0%, 100% { transform: translateY(0); opacity: 0.25; }
          50% { transform: translateY(-14px); opacity: 0.8; }
        }
        .splash-ring {
          position: absolute; top: 50%; left: 50%; border-radius: 999px;
          border: 1px solid rgba(201,162,39,0.4); transform: translate(-50%,-50%);
          animation: splash-pulse 2.6s ease-in-out infinite;
        }
        @keyframes splash-pulse {
          0% { opacity: 0.7; transform: translate(-50%,-50%) scale(0.6); }
          100% { opacity: 0; transform: translate(-50%,-50%) scale(1.4); }
        }
        .splash-cube-face { stroke-width: 1; }
        .splash-cube-top { fill: rgba(201,162,39,0.10); stroke: rgba(201,162,39,0.4); }
        .splash-cube-left { fill: rgba(255,255,255,0.02); stroke: rgba(255,255,255,0.08); }
        .splash-cube-right { fill: rgba(255,255,255,0.04); stroke: rgba(255,255,255,0.08); }
      `}</style>

      <div className={`splash-bg splash-${variant}`}>
        {variant === 'particles' &&
          PARTICLES.map((p, i) => (
            <span
              key={i}
              className="splash-particle"
              style={{ left: `${p.x}%`, top: `${p.y}%`, animationDuration: `${p.d}s`, animationDelay: `${p.delay}s` }}
            />
          ))}
        {variant === 'rings' &&
          [0, 1, 2, 3].map((i) => (
            <span
              key={i}
              className="splash-ring"
              style={{ width: 80 + i * 90, height: 80 + i * 90, animationDelay: `${i * 0.5}s` }}
            />
          ))}
        {variant === 'cubes' && (
          <svg viewBox="0 0 100 100" preserveAspectRatio="xMidYMid slice" style={{ width: '100%', height: '100%' }}>
            {CUBES.map((c, i) => {
              const p = isoPoints(c.x, c.y, c.s / 5);
              return (
                <g key={i}>
                  <polygon points={p.left} className="splash-cube-face splash-cube-left" />
                  <polygon points={p.right} className="splash-cube-face splash-cube-right" />
                  <polygon points={p.top} className="splash-cube-face splash-cube-top" />
                </g>
              );
            })}
          </svg>
        )}
      </div>

      <div className="splash-word">SEMICOLON</div>
    </div>
  );
}

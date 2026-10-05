import React, { useState, useRef, useEffect } from 'react';
import { useNavigate, useLocation, Link } from 'react-router-dom';
import { ArrowRight } from 'lucide-react';
import Splash from './Splash.jsx';
import ProfileMenu from './ProfileMenu.jsx';
import { useAuth } from '../context/AuthContext.jsx';

const NAV_LINKS = [
  {
    key: 'about', label: 'About Us', href: '#about',
    panel: {
      title: 'Built for the harvest-now-decrypt-later era',
      desc: 'SEMICOLON discovers, scores, and tracks the cryptography your organization already depends on — before a quantum-capable adversary can act on what was recorded today.',
      cta: { label: 'Read more', href: '#about' },
    },
  },
  {
    key: 'service', label: 'Service', href: '#capabilities',
    panel: {
      title: 'What the service does',
      desc: 'Discover every certificate, key, and algorithm in use, score each one for quantum risk, simulate the breach window, and ship a real migration patch.',
      links: [
        { label: 'Discover assets', to: '/dashboard#sec-upload' },
        { label: 'Score quantum risk', to: '/dashboard#sec-pqc' },
        { label: 'Simulate the breach window', to: '/mosca-timeline' },
        { label: 'Remediate with a real patch', to: '/remediator' },
      ],
    },
  },
  {
    key: 'new-scan', label: 'New Scan', to: '/dashboard#sec-upload',
    panel: {
      title: 'Run a new scan',
      desc: 'Upload a codebase, certificate, or config file — or run a live network scan — and get a full cryptographic inventory in seconds.',
      cta: { label: 'Go to scan', to: '/dashboard#sec-upload' },
    },
  },
  {
    key: 'recent-scans', label: 'Recent Scans', to: '/dashboard#sec-recent',
    panel: {
      title: 'Recent Scans',
      desc: 'Every file SEMICOLON has scanned recently.',
      cta: { label: 'View Recent Scans', to: '/dashboard#sec-recent' },
    },
  },
  {
    key: 'blog', label: 'Blog', to: '/news',
    panel: {
      title: 'From the blog',
      desc: 'Notes on post-quantum migration, HNDL exposure, and what\u2019s actually shipped vs. still experimental across the PQC ecosystem.',
      cta: { label: 'Read the blog', to: '/news' },
    },
  },
  {
    key: 'references', label: 'References', to: '/references',
    panel: {
      title: 'References',
      desc: 'The NIST standards, CNSA milestones, and source material behind every recommendation SEMICOLON makes.',
      cta: { label: 'View references', to: '/references' },
    },
  },
];

export default function TopBar({ variant = 'public', onProfileClick }) {
  const navigate = useNavigate();
  const location = useLocation();
  const { user } = useAuth();
  const [splashing, setSplashing] = useState(false);
  const [openKey, setOpenKey] = useState(null);
  const wrapRef = useRef(null);

  useEffect(() => {
    function onClickOutside(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpenKey(null);
    }
    function onKeyDown(e) {
      if (e.key === 'Escape') setOpenKey(null);
    }
    document.addEventListener('mousedown', onClickOutside);
    document.addEventListener('keydown', onKeyDown);
    return () => {
      document.removeEventListener('mousedown', onClickOutside);
      document.removeEventListener('keydown', onKeyDown);
    };
  }, []);

  const handleLogoClick = (e) => {
    e.preventDefault();
    setSplashing(true);
  };

  const handleNavClick = (e, item) => {
    if (item.panel) {
      e.preventDefault();
      setOpenKey((k) => (k === item.key ? null : item.key));
    }
  };

  const goPanelLink = (link) => {
    setOpenKey(null);
    if (link.to) {
      navigate(link.to);
    } else if (link.href) {
      if (location.pathname === '/') {
        document.getElementById(link.href.replace('#', ''))?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      } else {
        navigate(`/${link.href}`);
      }
    }
  };

  return (
    <>
      {splashing && (
        <Splash
          duration={1100}
          onFinish={() => {
            setSplashing(false);
            navigate('/');
          }}
        />
      )}
      <header className="stb-bar" ref={wrapRef}>
        <style>{`
          .stb-bar {
            position: sticky; top: 0; z-index: 30;
            display: flex; align-items: center; justify-content: space-between;
            padding: 22px 44px; background: rgba(10,13,18,0.9); backdrop-filter: blur(10px);
            border-bottom: 1px solid #1b2129;
            font-family: 'Switzer', sans-serif;
          }
          .stb-logo {
            font-family: 'Clash Display', sans-serif; font-weight: 700; font-size: 23px;
            letter-spacing: 0.09em; color: #e8eaef; text-decoration: none; cursor: pointer;
          }
          .stb-nav { display: flex; align-items: center; gap: 34px; position: relative; }
          .stb-link-wrap { position: relative; }
          .stb-link {
            font-size: 15.5px; color: #8a93a3; text-decoration: none; background: none; border: none;
            font-family: inherit; cursor: pointer;
            transition: color 0.15s ease; position: relative; padding: 6px 0;
          }
          .stb-link:hover { color: #c9a227; }
          .stb-link.active { color: #e8eaef; }
          .stb-link.active::after {
            content: ''; position: absolute; left: 0; right: 0; bottom: 0px; height: 2px; background: #c9a227; border-radius: 2px;
          }
          .stb-link.open { color: #c9a227; }
          .stb-signin-btn {
            font-size: 15px; font-weight: 600; color: #191308; background: #c9a227;
            padding: 11px 24px; border-radius: 7px; text-decoration: none;
          }
          .stb-signin-btn:hover { filter: brightness(1.08); }

          .stb-panel {
            position: absolute; top: calc(100% + 18px); left: 50%; transform: translateX(-50%) translateY(-8px);
            width: 320px; z-index: 40; background: #12161d; border: 1px solid #262e3a; border-radius: 12px;
            padding: 18px 20px; box-shadow: 0 20px 50px -12px rgba(0,0,0,0.55);
            opacity: 0; pointer-events: none; max-height: 0; overflow: hidden;
            transition: opacity 0.22s ease, transform 0.22s ease, max-height 0.22s ease;
          }
          .stb-panel.open {
            opacity: 1; pointer-events: auto; transform: translateX(-50%) translateY(0); max-height: 340px;
          }
          .stb-panel-title { font-family: 'Clash Display', sans-serif; font-size: 14.5px; color: #e8eaef; margin: 0 0 8px; font-weight: 600; }
          .stb-panel-desc { font-size: 12.5px; color: #8a93a3; line-height: 1.55; margin: 0 0 12px; }
          .stb-panel-links { display: flex; flex-direction: column; gap: 2px; margin-bottom: 4px; }
          .stb-panel-link {
            display: flex; align-items: center; justify-content: space-between; gap: 8px;
            font-size: 12.5px; color: #c2c7d1; background: none; border: none; text-align: left;
            padding: 8px 8px; border-radius: 6px; cursor: pointer; font-family: inherit; width: 100%;
          }
          .stb-panel-link:hover { background: #171c25; color: #c9a227; }
          .stb-panel-cta {
            display: inline-flex; align-items: center; gap: 6px; font-size: 12.5px; font-weight: 600;
            color: #c9a227; background: none; border: none; cursor: pointer; font-family: inherit; padding: 0;
          }
          @media (max-width: 900px) {
            .stb-nav { display: none; }
          }
        `}</style>

        <a href="/" className="stb-logo" onClick={handleLogoClick}>SEMICOLON</a>

        <nav className="stb-nav">
          {NAV_LINKS.map((item) => {
            const isActive = item.to && location.pathname === item.to.split('#')[0];
            const isOpen = openKey === item.key;
            return (
              <div className="stb-link-wrap" key={item.key}>
                {item.to ? (
                  <Link
                    to={item.to}
                    className={`stb-link ${isActive ? 'active' : ''} ${isOpen ? 'open' : ''}`}
                    onClick={(e) => handleNavClick(e, item)}
                  >
                    {item.label}
                  </Link>
                ) : (
                  <a
                    href={item.href}
                    className={`stb-link ${isOpen ? 'open' : ''}`}
                    onClick={(e) => handleNavClick(e, item)}
                  >
                    {item.label}
                  </a>
                )}

                {item.panel && (
                  <div className={`stb-panel ${isOpen ? 'open' : ''}`}>
                    <p className="stb-panel-title">{item.panel.title}</p>
                    <p className="stb-panel-desc">{item.panel.desc}</p>
                    {item.panel.links && (
                      <div className="stb-panel-links">
                        {item.panel.links.map((link) => (
                          <button key={link.label} className="stb-panel-link" onClick={() => goPanelLink(link)}>
                            {link.label} <ArrowRight size={12} />
                          </button>
                        ))}
                      </div>
                    )}
                    {item.panel.cta && (
                      <button className="stb-panel-cta" onClick={() => goPanelLink(item.panel.cta)}>
                        {item.panel.cta.label} <ArrowRight size={13} />
                      </button>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </nav>

        <div>
          {user ? <ProfileMenu /> : <Link to="/login" className="stb-signin-btn">Sign in</Link>}
        </div>
      </header>
    </>
  );
}

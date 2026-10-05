import React, { useState, useRef, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { Activity, Settings, HelpCircle, History, LogOut } from 'lucide-react';
import { useAuth, initials } from '../context/AuthContext.jsx';

export default function ProfileMenu() {
  const navigate = useNavigate();
  const { user, logout } = useAuth();
  const [open, setOpen] = useState(false);
  const wrapRef = useRef(null);

  useEffect(() => {
    function onClickOutside(e) {
      if (wrapRef.current && !wrapRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener('mousedown', onClickOutside);
    return () => document.removeEventListener('mousedown', onClickOutside);
  }, []);

  if (!user) return null;

  const go = (path) => { setOpen(false); navigate(path); };
  const handleLogout = () => { setOpen(false); logout(); navigate('/'); };

  return (
    <div className="pm-wrap" ref={wrapRef}>
      <style>{`
        .pm-wrap { position: relative; }
        .pm-trigger {
          display: flex; align-items: center; gap: 8px; background: none; border: none;
          cursor: pointer; font-family: inherit; padding: 2px;
        }
        .pm-avatar {
          width: 30px; height: 30px; border-radius: 999px; background: var(--gold-soft, rgba(201,162,39,0.14));
          color: var(--gold, #c9a227); display: flex; align-items: center; justify-content: center;
          font-size: 11px; font-weight: 600; font-family: 'IBM Plex Mono', monospace; flex-shrink: 0;
        }
        .pm-avatar.lg { width: 38px; height: 38px; font-size: 13px; }
        .pm-name { font-size: 13px; color: var(--text-primary, #e8eaef); }
        .pm-panel {
          position: absolute; top: calc(100% + 10px); right: 0; width: 260px; z-index: 50;
          background: var(--surface-1, #12161d); border: 1px solid var(--border, #262e3a);
          border-radius: 10px; box-shadow: 0 12px 32px rgba(0,0,0,0.4); padding: 8px;
        }
        .pm-header { display: flex; align-items: center; gap: 10px; padding: 10px 8px 12px; border-bottom: 1px solid var(--border-soft, #1b2129); margin-bottom: 6px; }
        .pm-header-name { font-size: 13.5px; font-weight: 600; margin: 0; color: var(--text-primary, #e8eaef); }
        .pm-header-email { font-size: 11.5px; color: var(--text-faint, #545e6e); margin: 2px 0 0; word-break: break-all; }
        .pm-item {
          display: flex; align-items: center; gap: 10px; width: 100%; text-align: left;
          background: none; border: none; cursor: pointer; font-family: inherit;
          font-size: 13px; color: var(--text-secondary, #8a93a3); padding: 9px 8px; border-radius: 6px;
        }
        .pm-item:hover { background: var(--surface-2, #171c25); color: var(--text-primary, #e8eaef); }
        .pm-item.danger { color: var(--crimson, #c1503a); }
        .pm-item.danger:hover { background: rgba(193,80,58,0.12); }
        .pm-divider { height: 1px; background: var(--border-soft, #1b2129); margin: 6px 4px; }
      `}</style>

      <button className="pm-trigger" onClick={() => setOpen((o) => !o)} aria-label="Open profile menu">
        <span className="pm-avatar">{initials(user.name)}</span>
        <span className="pm-name">{user.name}</span>
      </button>

      {open && (
        <div className="pm-panel">
          <div className="pm-header">
            <span className="pm-avatar lg">{initials(user.name)}</span>
            <div>
              <p className="pm-header-name">{user.name}</p>
              <p className="pm-header-email">{user.email}</p>
            </div>
          </div>
          <button className="pm-item" onClick={() => go('/activity')}><Activity size={15} /> Profile activity</button>
          <button className="pm-item" onClick={() => go('/settings')}><Settings size={15} /> Account settings</button>
          <button className="pm-item" onClick={() => go('/help')}><HelpCircle size={15} /> Help centre</button>
          <button className="pm-item" onClick={() => go('/dashboard#sec-recent')}><History size={15} /> Recent Scans</button>
          <div className="pm-divider" />
          <button className="pm-item danger" onClick={handleLogout}><LogOut size={15} /> Log out</button>
        </div>
      )}
    </div>
  );
}

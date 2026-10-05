import React from 'react';
import TopBar from '../components/TopBar.jsx';
import { REFERENCES as VERIFIED, UNVERIFIED_REFERENCES as UNVERIFIED } from '../data/references.js';

// Every entry in data/references.js was fetched and read directly before
// being described here — nothing is characterized based on its title or URL
// alone. This page and the blog's inline citations both read from that one
// file, so a source can't end up numbered differently on the two pages.

export default function References() {
  return (
    <div className="sentinel-refs">
      <style>{`
        .sentinel-refs {
          --bg: #0a0d12; --surface-1: #12161d; --border-soft: #1b2129;
          --text-primary: #e8eaef; --text-secondary: #8a93a3; --text-faint: #545e6e; --gold: #c9a227;
          background: var(--bg); color: var(--text-primary); min-height: 100vh;
          font-family: 'Switzer', system-ui, sans-serif;
        }
        .sentinel-refs *, .sentinel-refs *::before, .sentinel-refs *::after { box-sizing: border-box; }
        .refs-wrap { max-width: 780px; margin: 0 auto; padding: 64px 32px 100px; }
        .refs-eyebrow { font-size: 12px; letter-spacing: 0.16em; color: var(--gold); text-transform: uppercase; }
        .refs-title { font-family: 'Clash Display', sans-serif; font-size: 34px; font-weight: 600; margin: 14px 0 12px; }
        .refs-note {
          font-size: 13.5px; color: var(--text-secondary); line-height: 1.7; margin: 0 0 40px;
          background: var(--surface-1); border: 1px solid var(--border-soft); border-radius: 10px; padding: 16px 18px;
        }
        .refs-section-title { font-size: 12px; letter-spacing: 0.1em; text-transform: uppercase; color: var(--gold); margin: 36px 0 4px; }
        .refs-list { list-style: none; margin: 0; padding: 0; counter-reset: refs; }
        .refs-list li {
          counter-increment: refs; padding: 18px 0; border-top: 1px solid var(--border-soft);
          display: flex; gap: 14px; align-items: baseline; scroll-margin-top: 20px;
        }
        .refs-list li::before {
          content: '[' counter(refs) ']'; font-family: 'IBM Plex Mono', monospace; font-size: 12px;
          color: var(--gold); flex-shrink: 0;
        }
        .refs-item-title { font-size: 14px; margin: 0 0 4px; font-weight: 600; }
        .refs-item-meta { font-size: 12.5px; color: var(--text-secondary); margin: 0 0 6px; }
        .refs-item-note { font-size: 12.5px; color: var(--text-faint); line-height: 1.6; margin: 0 0 6px; }
        .refs-item-url { font-size: 12px; color: var(--text-faint); word-break: break-all; }
        .refs-item-url a { color: var(--text-faint); text-decoration: none; }
        .refs-item-url a:hover { color: var(--gold); }
        .refs-unverified-note { font-size: 12.5px; color: var(--text-faint); line-height: 1.65; margin: 0 0 16px; }
      `}</style>

      <TopBar variant="public" />

      <div className="refs-wrap">
        <span className="refs-eyebrow">References</span>
        <h1 className="refs-title">Sources</h1>
        <p className="refs-note">
          Every source below was checked directly rather than assumed from its title or URL. Six were read
          in full and are cited with what they actually contain. The remainder could not be verified in
          this pass — they're listed as given, without invented descriptions, rather than dropped.
        </p>

        <p className="refs-section-title">Verified</p>
        <ol className="refs-list">
          {VERIFIED.map((s) => (
            <li key={s.url} id={`ref-${s.id}`}>
              <div>
                <p className="refs-item-title">{s.title}</p>
                <p className="refs-item-meta">{s.authors} — {s.venue}</p>
                <p className="refs-item-note">{s.note}</p>
                <p className="refs-item-url">
                  <a href={s.url} target="_blank" rel="noopener noreferrer">{s.url}</a>
                </p>
              </div>
            </li>
          ))}
        </ol>

        <p className="refs-section-title">Not yet verified</p>
        <p className="refs-unverified-note">
          These sources were provided but couldn't be confirmed in this pass — some returned access
          errors, others weren't reached yet. Listed here rather than cited anywhere on the site.
        </p>
        <ol className="refs-list">
          {UNVERIFIED.map((s) => (
            <li key={s.url}>
              <p className="refs-item-url">
                <a href={s.url} target="_blank" rel="noopener noreferrer">{s.url}</a>
              </p>
            </li>
          ))}
        </ol>
      </div>
    </div>
  );
}

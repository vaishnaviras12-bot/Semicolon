import React from 'react';

// ForceGraph2D (canvas), jsPDF, and JSZip are all real failure surfaces —
// bad data, a missing browser API, or a blocked download can throw during
// render or in an effect. Without a boundary, one throw unmounts the entire
// React tree and the user sees a blank white page with no way back.
export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // Local-only by design: nothing is sent to an external service.
    // eslint-disable-next-line no-console
    console.error('Semicolon UI error:', error, info?.componentStack);
  }

  render() {
    if (!this.state.error) return this.props.children;

    return (
      <div role="alert" style={{
        minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: '#0a0d12', color: '#e8eaef', fontFamily: "'Switzer', system-ui, sans-serif", padding: 24,
      }}>
        <div style={{
          maxWidth: 460, textAlign: 'center', background: '#12161d', border: '1px solid #262e3a',
          borderRadius: 12, padding: '36px 30px',
        }}>
          <p style={{ fontFamily: "'IBM Plex Mono', monospace", fontSize: 11, letterSpacing: '0.14em', color: '#c9a227', margin: '0 0 12px' }}>
            SOMETHING WENT WRONG
          </p>
          <h1 style={{ fontFamily: "'Clash Display', sans-serif", fontSize: 24, fontWeight: 600, margin: '0 0 12px' }}>
            This view hit an unexpected error.
          </h1>
          <p style={{ fontSize: 13.5, color: '#8a93a3', lineHeight: 1.6, margin: '0 0 22px' }}>
            Your scan data isn't lost — it lives in memory for this session. Reloading the page
            usually clears it. If it keeps happening, the details are in the browser console.
          </p>
          <button
            onClick={() => window.location.assign('/')}
            style={{
              background: '#c9a227', color: '#191308', border: 'none', borderRadius: 7,
              padding: '11px 22px', fontSize: 14, fontWeight: 600, cursor: 'pointer', fontFamily: 'inherit',
            }}
          >
            Back to home
          </button>
        </div>
      </div>
    );
  }
}

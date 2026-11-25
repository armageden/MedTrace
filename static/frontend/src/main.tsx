import React from 'react';
import ReactDOM from 'react-dom/client';
import './index.css';
import { App } from './App';

interface ErrorBoundaryState {
  error: Error | null;
}

export class AppErrorBoundary extends React.Component<{ children: React.ReactNode }, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  render() {
    if (this.state.error) {
      return (
        <div role="alert" style={{ padding: 24, fontFamily: 'sans-serif', color: 'var(--mt-danger-text, #bf2600)' }}>
          <h2 style={{ margin: '0 0 8px' }}>MedTrace UI encountered an unexpected rendering error</h2>
          <p style={{ margin: '0 0 12px', color: 'var(--mt-text-secondary, #42526e)' }}>
            {this.state.error.message}
          </p>
          <button
            type="button"
            onClick={() => window.location.reload()}
            className="mt-btn"
            style={{ padding: '6px 14px', border: '1px solid var(--mt-border, #dfe1e6)' }}
          >
            Reload Workspace
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

const rootEl = document.getElementById('root');
if (rootEl) {
  ReactDOM.createRoot(rootEl).render(
    <React.StrictMode>
      <AppErrorBoundary>
        <App />
      </AppErrorBoundary>
    </React.StrictMode>
  );
}

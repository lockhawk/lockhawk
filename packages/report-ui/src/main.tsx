import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App.js';
import { loadScanResult } from './data.js';
import './index.css';

async function bootstrap(): Promise<void> {
  const root = createRoot(document.getElementById('root')!);
  try {
    const result = await loadScanResult();
    root.render(
      <StrictMode>
        <App result={result} />
      </StrictMode>,
    );
  } catch {
    root.render(
      <div className="boot-error">
        <h1>No scan data</h1>
        <p>This report was opened without an embedded scan result.</p>
      </div>,
    );
  }
}

void bootstrap();

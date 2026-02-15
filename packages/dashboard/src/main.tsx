import React from 'react';
import ReactDOM from 'react-dom/client';
import BlindKeyDashboard from './Dashboard';
import { detectMode } from './api/index';
import './index.css';

// Detect mode (local vs docker) before rendering so the client
// is ready synchronously when components mount.
detectMode().then(() => {
  ReactDOM.createRoot(document.getElementById('root')!).render(
    <React.StrictMode>
      <BlindKeyDashboard />
    </React.StrictMode>
  );
});

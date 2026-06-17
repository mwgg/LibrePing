import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
// Self-hosted fonts (no external CDN, keeping the dashboard dependency-free at
// runtime): Fraunces for editorial display, IBM Plex Sans for body, IBM Plex
// Mono for metrics/IDs/coordinates.
import "@fontsource-variable/fraunces";
import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/500.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./index.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);

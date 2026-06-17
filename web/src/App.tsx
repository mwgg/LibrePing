import { useMemo, useState } from "react";
import { Identity, loadOrCreate, recoveryPhrase, restoreFromPhrase } from "./identity";
import Services from "./Services";
import GlobalMap from "./GlobalMap";
import Overview from "./Overview";
import About from "./About";

type Tab = "overview" | "services" | "map" | "about";

export default function App() {
  const [id, setId] = useState<Identity>(() => loadOrCreate());

  // ?owner=… makes this a read-only view of someone else's services. If it
  // matches our own key, we keep edit controls.
  const urlOwner = useMemo(() => new URLSearchParams(window.location.search).get("owner") ?? "", []);
  const owner = urlOwner || id.owner;
  const editable = !urlOwner || urlOwner === id.owner;

  const [tab, setTab] = useState<Tab>("services");
  const [showAccount, setShowAccount] = useState(false);

  const tabs: { key: Tab; label: string }[] = [
    { key: "overview", label: "Overview" },
    { key: "services", label: editable ? "My services" : "Services" },
    { key: "map", label: "Global map" },
    { key: "about", label: "About" },
  ];

  return (
    <>
      <header>
        <div className="brand">
          <img className="brand-mark" src="/logo.svg" alt="" width={30} height={30} />
          <div className="brand-text">
            <h1>
              Libre<span className="lp-mark">Ping</span>
            </h1>
            <span className="tagline">decentralized uptime</span>
          </div>
        </div>
        <nav className="tabs">
          {tabs.map((t) => (
            <button key={t.key} className={tab === t.key ? "active" : ""} onClick={() => setTab(t.key)}>
              {t.label}
            </button>
          ))}
        </nav>
        <button className="account-btn" onClick={() => setShowAccount((v) => !v)}>
          {editable ? "● Account" : "Viewing shared"}
        </button>
      </header>

      {showAccount && (
        <AccountPanel id={id} owner={owner} editable={editable} onRestore={setId} onClose={() => setShowAccount(false)} />
      )}

      {tab === "map" ? (
        <GlobalMap />
      ) : (
        <div className="content">
          {tab === "overview" ? (
            <Overview owner={owner} />
          ) : tab === "about" ? (
            <About onGetStarted={() => setTab("services")} />
          ) : (
            <Services id={id} owner={owner} editable={editable} />
          )}
        </div>
      )}
    </>
  );
}

function AccountPanel({
  id,
  owner,
  editable,
  onRestore,
  onClose,
}: {
  id: Identity;
  owner: string;
  editable: boolean;
  onRestore: (id: Identity) => void;
  onClose: () => void;
}) {
  const [phrase, setPhrase] = useState("");
  const [restoreInput, setRestoreInput] = useState("");
  const dashboardLink = `${window.location.origin}${window.location.pathname}?owner=${owner}`;

  return (
    <div className="account">
      <h2>Your account</h2>
      <button className="btn btn-ghost btn-sm account-close" onClick={onClose}>
        ✕
      </button>

      <div className="account-row">
        <b>Shareable dashboard</b>
        <input readOnly value={dashboardLink} onFocus={(e) => e.target.select()} />
        <span className="muted note">
          Bookmark this to view your services from any device or hub (read-only without your key).
        </span>
      </div>

      {editable && (
        <>
          <div className="account-row">
            <b>Recovery phrase</b>
            {!phrase && (
              <button className="btn btn-sm" onClick={() => setPhrase(recoveryPhrase(id))}>
                Reveal 24 words
              </button>
            )}
            {phrase && <code className="phrase">{phrase}</code>}
            {phrase && <span className="muted note">Write these down. They restore your account on another device.</span>}
          </div>
          <div className="account-row">
            <b>Restore account</b>
            <input
              placeholder="paste recovery phrase…"
              value={restoreInput}
              onChange={(e) => setRestoreInput(e.target.value)}
            />
            <button
              className="btn btn-sm"
              onClick={() => {
                if (restoreInput.trim()) onRestore(restoreFromPhrase(restoreInput));
              }}
            >
              Restore
            </button>
          </div>
        </>
      )}
    </div>
  );
}

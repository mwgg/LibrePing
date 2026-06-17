// About is the public explainer: what LibrePing is, how it works, what a visitor
// gets without hosting anything, and how self-hosters join. It doubles as the
// indexable landing content for people who find a hub via search.
const REPO = "https://github.com/mwgg/LibrePing";
const SELF_HOST = "https://github.com/mwgg/LibrePing/blob/main/SELF_HOSTING.md";

export default function About({ onGetStarted }: { onGetStarted: () => void }) {
  return (
    <div className="container about">
      <section className="about-hero">
        <h1>
          Decentralized uptime monitoring, <span className="lp-mark">from everywhere</span>.
        </h1>
        <p className="about-lede">
          LibrePing checks whether websites and services are online from many locations around the
          world at once, and shows where they are reachable from on a live map. It is open source and
          has no central company and no single server — independent operators run the nodes and they
          federate directly with each other.
        </p>
        <div className="about-cta">
          <button className="btn btn-primary" onClick={onGetStarted}>
            Monitor a service — free, no signup
          </button>
          <a className="btn" href={REPO} target="_blank" rel="noreferrer">
            View on GitHub
          </a>
        </div>
      </section>

      <section className="panel about-section">
        <h2>How it works</h2>
        <div className="about-grid">
          <div className="feature">
            <h3>Probes measure</h3>
            <p>
              Lightweight agents run checks — HTTP, TCP, DNS, TLS certificate, ICMP ping, traceroute —
              from their location and <b>cryptographically sign</b> every result.
            </p>
          </div>
          <div className="feature">
            <h3>Hubs federate</h3>
            <p>
              Hubs collect results and gossip them across a peer-to-peer mesh. There is no central
              server; hubs share results, monitors, and alerts directly with each other.
            </p>
          </div>
          <div className="feature">
            <h3>Everything is verified</h3>
            <p>
              Every hub independently checks the signature on everything it receives, so no one can
              forge a measurement or tamper with a monitor. Trust comes from many probes agreeing.
            </p>
          </div>
          <div className="feature">
            <h3>It converges</h3>
            <p>
              Results spread until the whole network sees the same picture. Any hub is just an entry
              point — pick one, or run your own, and you get the same global view.
            </p>
          </div>
        </div>
      </section>

      <section className="panel about-section">
        <h2>What you get — no server, no signup</h2>
        <ul className="about-list">
          <li>
            <b>Multi-location checks.</b> See your service from many countries at once and catch
            outages that only affect some regions.
          </li>
          <li>
            <b>A live geographic map</b> of where your service is reachable from, plus uptime and
            latency history per monitor.
          </li>
          <li>
            <b>Encrypted alerts</b> — ntfy, Discord, Slack, or a raw webhook — when a service goes
            down, confirmed from multiple locations. Your destination is sealed so only the hubs that
            notify you can read it.
          </li>
          <li>
            <b>No account.</b> Your browser creates a key that <i>is</i> your identity — bookmark your
            dashboard link, save a recovery phrase, done. Nothing to sign up for.
          </li>
        </ul>
        <div className="about-cta">
          <button className="btn btn-primary" onClick={onGetStarted}>
            Add your first monitor
          </button>
        </div>
      </section>

      <section className="panel about-section">
        <h2>Run a node — strengthen the network</h2>
        <p className="muted">
          The more people run probes, the better the coverage for everyone. If you have a spare VPS or
          NAS, you can join in minutes with Docker.
        </p>
        <div className="about-grid">
          <div className="feature">
            <h3>Run a probe</h3>
            <p>
              The light option: lend a vantage point from your location. No domain or public IP
              needed — it makes outbound connections to a hub and contributes signed measurements.
            </p>
          </div>
          <div className="feature">
            <h3>Run a hub</h3>
            <p>
              Host your own dashboard and federate with the mesh — store results, gossip with peers,
              and become an entry point others can use.
            </p>
          </div>
        </div>
        <div className="about-cta">
          <a className="btn btn-primary" href={SELF_HOST} target="_blank" rel="noreferrer">
            Self-hosting guide
          </a>
          <a className="btn" href={REPO} target="_blank" rel="noreferrer">
            Source on GitHub
          </a>
        </div>
      </section>

      <section className="panel about-section">
        <h2>Honest about the limits</h2>
        <p className="muted">
          An open network is Sybil-prone, so trust comes from corroboration across independent probes,
          not gatekeeping. A probe's location is self-declared (auto-detected from its IP, overridable)
          — IP geolocation is a convenience, not proof, and there is no proof-of-location. We say so
          plainly rather than overclaim.
        </p>
      </section>

      <p className="about-foot muted">
        LibrePing is free software (AGPL-3.0). Source, docs, and issues on{" "}
        <a href={REPO} target="_blank" rel="noreferrer">
          GitHub
        </a>
        .
      </p>
    </div>
  );
}

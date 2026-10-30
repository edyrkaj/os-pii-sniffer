import { useEffect, useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { listen } from "@tauri-apps/api/event";
import {
  PII_TYPES,
  previewSnapshot,
  type ActivityEvent,
  type PiiType,
  type ServiceEvent,
  type Snapshot,
} from "./types";

type Tab = "activity" | "services" | "rules";
type ResultFilter = "all" | "pii" | "clean" | "skipped";

const previewMode = window.location.hash === "#preview";

function App() {
  const [snap, setSnap] = useState<Snapshot | null>(previewMode ? previewSnapshot() : null);
  const [tab, setTab] = useState<Tab>("activity");
  const [filter, setFilter] = useState<PiiType | "all">("all");
  const [resultFilter, setResultFilter] = useState<ResultFilter>("pii");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [host, setHost] = useState("");

  useEffect(() => {
    if (previewMode || !("__TAURI_INTERNALS__" in window)) {
      return;
    }
    const stops: Array<() => void> = [];
    let cancelled = false;
    invoke<Snapshot>("snapshot")
      .then((next) => {
        if (!cancelled) {
          setSnap(next);
        }
      })
      .catch((reason: unknown) => setError(String(reason)));
    listen<ActivityEvent>("activity", (event) => {
      setSnap((current) =>
        current
          ? { ...current, events: [event.payload, ...current.events].slice(0, 200) }
          : current,
      );
    }).then((stop) => {
      stops.push(stop);
    });
    listen<ServiceEvent[]>("services", (event) => {
      setSnap((current) => (current ? { ...current, services: event.payload } : current));
    }).then((stop) => {
      stops.push(stop);
    });
    return () => {
      cancelled = true;
      for (const stop of stops) {
        stop();
      }
    };
  }, []);

  async function run<T>(work: () => Promise<T> | T) {
    setError(null);
    setBusy(true);
    try {
      return await work();
    } catch (reason) {
      setError(String(reason));
      return undefined;
    } finally {
      setBusy(false);
    }
  }

  if (!snap) {
    return (
      <main className="app">
        <h1>PII Sniffer</h1>
        <p>Loading local activity…</p>
        {error ? <p className="error">{error}</p> : null}
      </main>
    );
  }

  const events = snap.events.filter((event) => {
    if (resultFilter === "pii" && event.findings.length === 0) {
      return false;
    }
    if (resultFilter === "clean" && event.action !== "clean") {
      return false;
    }
    if (resultFilter === "skipped" && event.action !== "skipped") {
      return false;
    }
    if (filter === "all") {
      return true;
    }
    return event.findings.some((finding) => finding.piiType === filter);
  });

  const piiServiceCount = snap.services.filter((service) => service.piiCount > 0).length;

  return (
    <main className="app">
      <header className="top">
        <div>
          <p className="eyebrow">Local GDPR guard</p>
          <h1>PII Sniffer</h1>
          <p className="lede">
            Outbound uploads that use the system proxy are scanned on this Mac. Cleartext
            personal data is replaced before it is forwarded. The original value is not stored.
          </p>
        </div>
        <section className="protection" aria-label="Protection">
          <button
            className={snap.protectionOn ? "quiet" : "primary"}
            disabled={busy}
            onClick={() =>
              run(async () => {
                if (previewMode) {
                  setSnap({
                    ...snap,
                    protectionOn: !snap.protectionOn,
                    proxyInstalled: !snap.protectionOn,
                  });
                  return;
                }
                const next = await invoke<Snapshot>("set_protection", { on: !snap.protectionOn });
                setSnap(next);
              })
            }
          >
            {busy ? "Waiting for macOS…" : snap.protectionOn ? "Turn protection off" : "Turn protection on"}
          </button>
          <div className="chips">
            <span className={snap.protectionOn ? "chip on" : "chip"}>
              {snap.protectionOn ? "Protection on" : "Protection off"}
            </span>
            <span className={snap.certTrusted ? "chip on" : "chip"}>
              {snap.certTrusted ? "Certificate trusted" : "Certificate not trusted"}
            </span>
            <span className={snap.proxyInstalled ? "chip on" : "chip"}>
              {snap.proxyInstalled ? "System proxy installed" : "System proxy off"}
            </span>
          </div>
          {previewMode ? <p className="rule-note">Preview mode uses sample rows.</p> : null}
        </section>
      </header>

      {snap.notice ? (
        <div className="notice">
          <p>{snap.notice}</p>
          {snap.pendingRestore ? (
            <button
              className="linkish"
              onClick={() =>
                run(async () => {
                  const next = await invoke<Snapshot>("restore_network");
                  setSnap(next);
                })
              }
            >
              Restore network settings
            </button>
          ) : null}
        </div>
      ) : null}
      {error ? <p className="error">{error}</p> : null}

      <nav className="tabs">
        <button className={tab === "activity" ? "active" : ""} onClick={() => setTab("activity")}>
          Activity
        </button>
        <button className={tab === "services" ? "active" : ""} onClick={() => setTab("services")}>
          Services{piiServiceCount > 0 ? ` (${piiServiceCount} PII)` : ""}
        </button>
        <button className={tab === "rules" ? "active" : ""} onClick={() => setTab("rules")}>
          Rules
        </button>
      </nav>

      {tab === "activity" ? (
        <section>
          <div className="toolbar">
            <label>
              Result{" "}
              <select
                value={resultFilter}
                onChange={(event) => setResultFilter(event.target.value as ResultFilter)}
              >
                <option value="pii">PII found</option>
                <option value="all">All scans</option>
                <option value="clean">Clean scans</option>
                <option value="skipped">Skipped</option>
              </select>
            </label>
            <label>
              Type{" "}
              <select value={filter} onChange={(event) => setFilter(event.target.value as PiiType | "all")}>
                <option value="all">All types</option>
                {PII_TYPES.map((type) => (
                  <option key={type.id} value={type.id}>
                    {type.label}
                  </option>
                ))}
              </select>
            </label>
            <button
              onClick={() =>
                run(async () => {
                  if (previewMode) {
                    setSnap({
                      ...snap,
                      events: snap.events.map((event) => ({ ...event, seen: true })),
                    });
                    return;
                  }
                  const next = await invoke<Snapshot>("mark_all_seen");
                  setSnap(next);
                })
              }
            >
              Mark all seen
            </button>
          </div>
          <table>
            <thead>
              <tr>
                <th>When</th>
                <th>Process</th>
                <th>Upload</th>
                <th>Result</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {events.length === 0 ? (
                <tr>
                  <td className="empty" colSpan={5}>
                    {resultFilter === "pii"
                      ? "No PII findings yet. Switch to All scans or open Services to see traffic."
                      : "No matching uploads yet."}
                  </td>
                </tr>
              ) : (
                events.map((event) => (
                  <tr key={event.id} className={event.alert && !event.seen ? "alert" : ""}>
                    <td>{event.timestamp.replace("T", " ").replace("Z", " UTC")}</td>
                    <td>{event.processName}</td>
                    <td>
                      <div className="mono">
                        {event.method} {event.host}
                        {event.path}
                      </div>
                      {event.findings.map((finding) => (
                        <span className="token" key={`${event.id}-${finding.fieldPath}-${finding.piiType}`}>
                          {finding.piiType} {finding.fieldPath} {finding.token}
                        </span>
                      ))}
                      {event.detail ? <div>{event.detail}</div> : null}
                    </td>
                    <td>{event.action}</td>
                    <td>
                      {event.alert && !event.seen ? (
                        <button
                          className="linkish"
                          onClick={() =>
                            run(async () => {
                              if (previewMode) {
                                setSnap({
                                  ...snap,
                                  events: snap.events.map((item) =>
                                    item.id === event.id ? { ...item, seen: true } : item,
                                  ),
                                });
                                return;
                              }
                              const next = await invoke<Snapshot>("mark_seen", { id: event.id });
                              setSnap(next);
                            })
                          }
                        >
                          Mark seen
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
          <p className="gap-note">
            Google and other pinned browser suites are bypassed by default so everyday browsing
            keeps working. HTTP/3 can still bypass this proxy. Apps that ignore the system proxy
            are not visible. “Encrypted” means the field itself is ciphertext, not that the
            connection uses HTTPS.
          </p>
        </section>
      ) : null}

      {tab === "services" ? (
        <section>
          <p className="rule-note">
            Every host the proxy sees is listed here. Rows with PII counts link to inspected
            uploads that contained cleartext personal data.
          </p>
          <table>
            <thead>
              <tr>
                <th>Host</th>
                <th>Process</th>
                <th>Mode</th>
                <th>Connects</th>
                <th>Scans</th>
                <th>PII</th>
                <th>Last seen</th>
              </tr>
            </thead>
            <tbody>
              {snap.services.length === 0 ? (
                <tr>
                  <td className="empty" colSpan={7}>
                    No scanned services yet. Turn protection on and use an app that respects the
                    system proxy.
                  </td>
                </tr>
              ) : (
                snap.services.map((service) => (
                  <tr
                    key={`${service.host}:${service.processName}`}
                    className={service.piiCount > 0 ? "alert" : ""}
                  >
                    <td className="mono">{service.host}</td>
                    <td>{service.processName}</td>
                    <td>{service.lastMode}</td>
                    <td>{service.connectCount}</td>
                    <td>{service.scannedCount}</td>
                    <td>
                      {service.piiCount > 0 ? (
                        <button
                          className="linkish"
                          onClick={() => {
                            setFilter("all");
                            setResultFilter("pii");
                            setTab("activity");
                          }}
                        >
                          {service.piiCount} found
                        </button>
                      ) : (
                        "0"
                      )}
                    </td>
                    <td>{service.lastSeen.replace("T", " ").replace("Z", " UTC")}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </section>
      ) : null}

      {tab === "rules" ? (
        <section className="rules">
          <p className="rule-note">
            Mask replaces cleartext before the upload continues. Alert beeps and highlights the
            row. Values that are already masked, or that are field ciphertext, are forwarded
            unchanged.
          </p>
          {PII_TYPES.map((type) => {
            const rule = snap.rules[type.id];
            return (
              <article className="rule" key={type.id}>
                <div>
                  <h2>{type.label}</h2>
                  <p>{type.hint}</p>
                </div>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={rule.mask}
                    onChange={(event) => updateRule(snap, type.id, event.target.checked, rule.alert)}
                  />
                  Mask
                </label>
                <label className="switch">
                  <input
                    type="checkbox"
                    checked={rule.alert}
                    onChange={(event) => updateRule(snap, type.id, rule.mask, event.target.checked)}
                  />
                  Alert
                </label>
              </article>
            );
          })}
          <section className="bypass">
            <h2>Bypass hosts</h2>
            <p>
              Exact hosts or wildcards such as *.google.com are tunneled without inspection, and
              are also added to the macOS proxy bypass list while protection is on.
            </p>
            <form
              onSubmit={(event) => {
                event.preventDefault();
                const value = host.trim();
                if (!value) {
                  return;
                }
                run(async () => {
                  if (previewMode) {
                    setSnap({ ...snap, bypassHosts: [...snap.bypassHosts, value.toLowerCase()] });
                    setHost("");
                    return;
                  }
                  const next = await invoke<Snapshot>("add_bypass", { host: value });
                  setSnap(next);
                  setHost("");
                });
              }}
            >
              <input
                aria-label="Bypass host"
                value={host}
                placeholder="*.google.com"
                onChange={(event) => setHost(event.target.value)}
              />
              <button type="submit">Add host</button>
            </form>
            <ul className="host-list">
              {snap.bypassHosts.map((item) => (
                <li key={item}>
                  <span className="mono">{item}</span>
                  <button
                    className="linkish"
                    onClick={() =>
                      run(async () => {
                        if (previewMode) {
                          setSnap({
                            ...snap,
                            bypassHosts: snap.bypassHosts.filter((entry) => entry !== item),
                          });
                          return;
                        }
                        const next = await invoke<Snapshot>("remove_bypass", { host: item });
                        setSnap(next);
                      })
                    }
                  >
                    Remove
                  </button>
                </li>
              ))}
            </ul>
          </section>
        </section>
      ) : null}
    </main>
  );

  function updateRule(current: Snapshot, piiType: PiiType, mask: boolean, alert: boolean) {
    run(async () => {
      if (previewMode) {
        const rules = { ...current.rules };
        rules[piiType] = { mask, alert };
        setSnap({ ...current, rules });
        return;
      }
      const next = await invoke<Snapshot>("set_rule", { piiType, mask, alert });
      setSnap(next);
    });
  }
}

export default App;

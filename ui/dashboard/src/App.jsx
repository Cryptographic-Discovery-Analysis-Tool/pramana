import React, { useCallback, useEffect, useMemo, useState } from 'react'
import Controls from './Controls.jsx'
import Ledger from './Ledger.jsx'
import Closure from './Closure.jsx'
import Coverage from './Coverage.jsx'
import Recommend from './Recommend.jsx'
import EvidenceCard from './EvidenceCard.jsx'
import Graph from './Graph.jsx'
import Sector from './Sector.jsx'
import Suppliers from './Suppliers.jsx'
import { apiFetch } from './api.js'

// Presentation only. Every band, window and deadline shown here is computed by
// the ledger and arrives over the API already decided; nothing in this bundle
// thresholds, weights or re-derives anything. If a number appears on screen
// that was calculated in JavaScript, that is a bug.

const TABS = [
  ['ledger', 'Ledger'],
  ['sector', 'Sector view'],
  ['closure', 'Closure queue'],
  ['recommend', 'Move to'],
  ['coverage', 'Coverage'],
  ['graph', 'Evidence graph'],
  ['suppliers', 'Suppliers'],
]

export default function App() {
  const [meta, setMeta] = useState(null)
  const [policy, setPolicy] = useState({
    scenario: 'Z_central',
    capture: 'SINCE_CONFIRMED',
    since: '',
    accept_inferred: false,
    rollout_y_days: 365,
    as_of: '2026-09-18',
    profile: 'NIST_L3',
  })
  const [tab, setTab] = useState('ledger')
  const [data, setData] = useState({ ledger: null, closure: null, coverage: null })
  const [recommendations, setRecommendations] = useState(null)
  const [graph, setGraph] = useState(null)
  const [fixture, setFixture] = useState(true)

  // P21: the banner is only true when the API is actually serving the
  // hand-built fixture; `ecdat assemble` output is real scan evidence.
  useEffect(() => {
    apiFetch('api/health')
      .then((r) => r.json())
      .then((h) => setFixture(h.fixture !== false))
      .catch(() => {})
  }, [])
  const [selected, setSelected] = useState(null)
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)

  // India sector-specific compliance view (SIH26164).
  const [sectors, setSectors] = useState(null)
  const [sector, setSector] = useState('bfsi')
  const [includeGlobal, setIncludeGlobal] = useState(false)
  const [sectorReport, setSectorReport] = useState(null)

  const query = useMemo(() => {
    const q = new URLSearchParams({
      scenario: policy.scenario,
      capture: policy.capture,
      accept_inferred: String(policy.accept_inferred),
      rollout_y_days: String(policy.rollout_y_days),
    })
    if (policy.capture === 'SINCE_DATE' && policy.since) q.set('since', policy.since)
    if (policy.as_of) q.set('as_of', policy.as_of)
    return q.toString()
  }, [policy])

  useEffect(() => {
    Promise.all([
      apiFetch('api/scenarios').then((r) => r.json()),
      apiFetch('api/profiles').then((r) => r.json()),
    ])
      .then(([scenarios, profiles]) => setMeta({ ...scenarios, ...profiles }))
      .catch((e) => setError(String(e)))
  }, [])

  // Recommendations depend only on the profile: what to move to is a function
  // of what the key does, not of when Z is.
  useEffect(() => {
    apiFetch(`api/recommendations?profile=${policy.profile}`)
      .then((r) => r.json())
      .then(setRecommendations)
      .catch((e) => setError(String(e)))
  }, [policy.profile])

  // The graph is a cross-surface view, not a per-scenario one -- it does not
  // depend on Z or policy, so it is fetched once.
  useEffect(() => {
    apiFetch('api/graph')
      .then((r) => r.json())
      .then(setGraph)
      .catch((e) => setError(String(e)))
  }, [])

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    Promise.all(
      ['ledger', 'closure', 'coverage'].map((name) =>
        apiFetch(`api/${name}?${query}`).then(async (r) => {
          if (!r.ok) throw new Error(`${name}: ${(await r.json()).detail ?? r.status}`)
          return r.json()
        })
      )
    )
      .then(([ledger, closure, coverage]) => {
        if (!cancelled) setData({ ledger, closure, coverage })
      })
      .catch((e) => !cancelled && setError(String(e.message ?? e)))
      .finally(() => !cancelled && setLoading(false))
    return () => {
      cancelled = true
    }
  }, [query])

  useEffect(() => {
    apiFetch('api/sectors')
      .then((r) => r.json())
      .then(setSectors)
      .catch((e) => setError(String(e)))
  }, [])

  useEffect(() => {
    if (tab !== 'sector') return
    let cancelled = false
    const q = new URLSearchParams(query)
    q.set('sector', sector)
    q.set('include_global', String(includeGlobal))
    apiFetch(`api/sector-report?${q.toString()}`)
      .then((r) => {
        if (!r.ok) throw new Error(`sector-report: ${r.status}`)
        return r.json()
      })
      .then((body) => !cancelled && setSectorReport(body))
      .catch((e) => !cancelled && setError(String(e.message ?? e)))
    return () => {
      cancelled = true
    }
  }, [tab, sector, includeGlobal, query])

  const openRecord = useCallback(
    (recordId) => {
      setSelected({ loading: true })
      apiFetch(`api/records/${encodeURIComponent(recordId)}?${query}`)
        .then((r) => r.json())
        .then(setSelected)
        .catch((e) => setSelected({ error: String(e) }))
    },
    [query]
  )

  // A plain <a href> cannot carry an Authorization header, and /api/export
  // now needs the EXPORTER role (P17) -- so the download is driven from
  // here instead: fetch through apiFetch(), then hand the browser a
  // blob URL to save exactly the way a direct link download would.
  const exportQuery = useMemo(() => {
    const q = new URLSearchParams(query)
    q.delete('scenario')
    return q.toString()
  }, [query])

  const [exporting, setExporting] = useState(false)
  const runExport = useCallback(async () => {
    setExporting(true)
    setError(null)
    try {
      const r = await apiFetch(`api/export?${exportQuery}`)
      if (!r.ok) throw new Error(`export: ${(await r.json()).detail ?? r.status}`)
      const blob = await r.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'pramana-cbom.json'
      a.click()
      URL.revokeObjectURL(url)
    } catch (e) {
      setError(String(e.message ?? e))
    } finally {
      setExporting(false)
    }
  }, [exportQuery])

  const scenario = meta?.scenarios?.find((s) => s.id === policy.scenario)

  return (
    <div className="app">
      <Controls
        meta={meta}
        policy={policy}
        onChange={setPolicy}
        onExport={runExport}
        exporting={exporting}
        scenario={scenario}
      />

      <main className="main">
        {fixture ? (
          <div className="banner">
            <strong>Fixture data.</strong> No sensor has run. These rows are
            constructed evidence used to exercise every band &mdash; nothing
            here was observed on a real network.
          </div>
        ) : (
          <div className="banner">
            <strong>Scan data.</strong> Rows assembled from adapter runs; data
            classes are as declared by the operator.
          </div>
        )}

        <div className="tabs">
          {TABS.map(([id, label]) => (
            <button
              key={id}
              className={tab === id ? 'active' : ''}
              onClick={() => setTab(id)}
            >
              {label}
              {id === 'closure' && data.closure ? ` (${data.closure.tasks.length})` : ''}
            </button>
          ))}
        </div>

        {error && <p className="bad">{error}</p>}
        {loading && <p className="muted">Recalculating…</p>}

        {tab === 'ledger' && data.ledger && (
          <Ledger data={data.ledger} onSelect={openRecord} />
        )}
        {tab === 'sector' && (
          <Sector
            sectors={sectors}
            sector={sector}
            onSectorChange={setSector}
            includeGlobal={includeGlobal}
            onIncludeGlobalChange={setIncludeGlobal}
            data={sectorReport}
          />
        )}
        {tab === 'closure' && data.closure && <Closure data={data.closure} />}
        {tab === 'recommend' && recommendations && <Recommend data={recommendations} />}
        {tab === 'coverage' && data.coverage && <Coverage data={data.coverage} />}
        {tab === 'graph' && graph && <Graph data={graph} />}
        {tab === 'suppliers' && <Suppliers sectors={sectors} />}
      </main>

      {selected && <EvidenceCard record={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

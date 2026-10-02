import React, { useCallback, useState } from 'react'
import { apiFetch } from './api.js'

// Supplier/vendor CBOM intake (SIH26164: India DST roadmap makes vendor CBOM
// submission mandatory from FY2027-28; RBI's Q-SAFE committee evaluates banks
// via CBOMs). Presentation only -- every provenance field, correlation
// status and quantum-vulnerable flag shown here arrives already decided from
// POST /api/suppliers/import (supplier/intake.py + supplier/correlate.py +
// supplier/report.py). This component never re-derives an epistemic state,
// never guesses at a conflict, and never picks which family is
// quantum-vulnerable -- it only renders what the API said.

const STATUS_GLYPH = {
  CORROBORATED: '✓',
  CONFLICTING: '✕',
  DECLARED_ONLY: '›',
  OBSERVED_ONLY: '‹',
}

const StatusBadge = ({ value }) => (
  <span className={`band band-supplier-${value}`}>
    <span className="glyph">{STATUS_GLYPH[value] ?? '·'}</span>
    {value.replaceAll('_', ' ').toLowerCase()}
  </span>
)

const SignatureBadge = ({ value }) => (
  <span className={`status status-${value === 'VERIFIED' ? 'KNOWN' : value === 'INVALID' ? 'CONFLICTING' : 'UNKNOWN'}`}>
    signature: {value.toLowerCase()}
  </span>
)

export default function Suppliers({ sectors }) {
  const [supplier, setSupplier] = useState('')
  const [cbomText, setCbomText] = useState('')
  const [sector, setSector] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [report, setReport] = useState(null)

  const onFile = useCallback((event) => {
    const file = event.target.files?.[0]
    if (!file) return
    const reader = new FileReader()
    reader.onload = () => setCbomText(String(reader.result ?? ''))
    reader.readAsText(file)
  }, [])

  const runImport = useCallback(async () => {
    setBusy(true)
    setError(null)
    try {
      const resp = await apiFetch('api/suppliers/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          supplier,
          cbom_json: cbomText,
          sector: sector || null,
        }),
      })
      const body = await resp.json()
      if (!resp.ok) throw new Error(body.detail ?? `${resp.status}`)
      setReport(body)
    } catch (e) {
      setError(String(e.message ?? e))
      setReport(null)
    } finally {
      setBusy(false)
    }
  }, [supplier, cbomText, sector])

  return (
    <>
      <div className="card" style={{ marginBottom: 16 }}>
        <h4>Import a supplier CBOM</h4>
        <p className="small">
          Everything a supplier declares is recorded as <strong>DECLARED</strong>,
          never KNOWN -- it is their claim about their own product, not
          something we observed ourselves. It is validated against the
          bundled CycloneDX 1.6 schema, its JSF signature (if any) is
          verified, and every field carries the supplier name, the file's
          SHA-256, and the import time as provenance.
        </p>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div className="field">
            <label>Supplier name</label>
            <input
              type="text"
              value={supplier}
              placeholder="e.g. Acme Networking Corp"
              onChange={(e) => setSupplier(e.target.value)}
            />
          </div>
          <div className="field">
            <label>CycloneDX CBOM (.json)</label>
            <input type="file" accept=".json,application/json" onChange={onFile} />
          </div>
          <div className="field">
            <label>Sector lens (optional)</label>
            <select value={sector} onChange={(e) => setSector(e.target.value)}>
              <option value="">— none —</option>
              {(sectors?.sectors ?? []).map((s) => (
                <option key={s.key} value={s.key}>
                  {s.label}
                </option>
              ))}
            </select>
          </div>
          <div>
            <button
              disabled={busy || !supplier.trim() || !cbomText.trim()}
              onClick={runImport}
            >
              {busy ? 'Importing…' : 'Import and correlate'}
            </button>
          </div>
        </div>
      </div>

      {error && <p className="bad">{error}</p>}

      {report && (
        <>
          <div className="card" style={{ marginBottom: 16 }}>
            <h4>Provenance</h4>
            <table>
              <tbody>
                <tr>
                  <td className="small faint">Supplier</td>
                  <td className="small">{report.provenance.supplier}</td>
                </tr>
                <tr>
                  <td className="small faint">File SHA-256</td>
                  <td className="small mono">{report.provenance.file_sha256}</td>
                </tr>
                <tr>
                  <td className="small faint">Imported at</td>
                  <td className="small">{report.provenance.imported_at}</td>
                </tr>
                <tr>
                  <td className="small faint">Signature</td>
                  <td className="small">
                    <SignatureBadge value={report.provenance.signature_status} />
                    {report.provenance.signature_key_id ? ` (keyId=${report.provenance.signature_key_id})` : ''}
                  </td>
                </tr>
                <tr>
                  <td className="small faint">CBOM serial / version</td>
                  <td className="small mono">
                    {report.provenance.cbom_serial_number ?? '—'} / {report.provenance.cbom_version ?? '—'}
                  </td>
                </tr>
                <tr>
                  <td className="small faint">Producing tool</td>
                  <td className="small">
                    {report.provenance.source_tool} {report.provenance.source_tool_version}
                  </td>
                </tr>
              </tbody>
            </table>
          </div>

          <div className="counts">
            <div className="count">
              <span className="n">{report.declared_count}</span>
              <span className="small">declared</span>
            </div>
            <div className="count">
              <span className="n">{report.corroborated_count}</span>
              <StatusBadge value="CORROBORATED" />
            </div>
            <div className="count">
              <span className="n">{report.conflicting_count}</span>
              <StatusBadge value="CONFLICTING" />
            </div>
            <div className="count">
              <span className="n">{report.declared_only_count}</span>
              <StatusBadge value="DECLARED_ONLY" />
            </div>
            <div className="count">
              <span className="n">{report.observed_only_count}</span>
              <StatusBadge value="OBSERVED_ONLY" />
            </div>
          </div>

          {report.quantum_vulnerable.length > 0 && (
            <div className="card" style={{ marginBottom: 16 }}>
              <h4>Declared crypto that is quantum-vulnerable</h4>
              <p className="small faint">Family classification: data/crypto_families.yaml (shor_broken).</p>
              {report.quantum_vulnerable.map((q) => (
                <div key={q.bom_ref} className="small">
                  <span className="badge">quantum-vulnerable</span> {q.name} &mdash; {q.family}
                </div>
              ))}
            </div>
          )}

          {report.sector && (
            <div className="card" style={{ marginBottom: 16 }}>
              <h4>Sector obligations: {report.sector}</h4>
              <p className="small">
                Cited policy keys applying to this sector (data/sector_profiles.yaml):{' '}
                {report.sector_obligation_policy_keys.length
                  ? report.sector_obligation_policy_keys.join(', ')
                  : 'none'}
              </p>
            </div>
          )}

          <table>
            <thead>
              <tr>
                <th>Status</th>
                <th>Supplier component</th>
                <th>Our asset</th>
                <th>Declared</th>
                <th>Observed</th>
                <th>Reason</th>
              </tr>
            </thead>
            <tbody>
              {report.correlations.map((c, i) => (
                <tr key={i}>
                  <td>
                    <StatusBadge value={c.status} />
                  </td>
                  <td className="small mono">{c.supplier_component_name || '—'}</td>
                  <td className="small mono">{c.our_asset_id || '—'}</td>
                  <td className="small">{c.declared_value ?? '—'}</td>
                  <td className="small">{c.observed_value ?? '—'}</td>
                  <td className="small faint" title={c.reason}>
                    {c.reason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </>
  )
}

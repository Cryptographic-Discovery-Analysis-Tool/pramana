import React from 'react'

// India sector-specific compliance views (SIH26164). Presentation only: every
// status, deadline and citation here arrives already decided from
// /api/sector-report (risk/sector.py) -- this component sorts and colours,
// it never computes a band or a deadline itself.

const GLYPH = {
  overdue: '✕',
  at_risk: '●',
  on_track: '✓',
  no_deadline: '·',
}

export const SectorStatus = ({ value }) => (
  <span className={`band band-sector-${value}`}>
    <span className="glyph">{GLYPH[value] ?? '·'}</span>
    {value.replace('_', ' ')}
  </span>
)

const STATUS_RANK = { overdue: 3, at_risk: 2, on_track: 1, no_deadline: 0 }

export default function Sector({
  sectors,
  sector,
  onSectorChange,
  includeGlobal,
  onIncludeGlobalChange,
  data,
}) {
  const profile = sectors?.sectors?.find((s) => s.key === sector)

  return (
    <>
      <div className="card" style={{ marginBottom: 16 }}>
        <h4>Sector lens</h4>
        <p className="small">
          Pick the sector your organisation belongs to. Every policy shown is
          one a cited source says applies to that sector --{' '}
          <code>data/sector_profiles.yaml</code>.
        </p>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center', flexWrap: 'wrap' }}>
          <select value={sector} onChange={(e) => onSectorChange(e.target.value)}>
            {(sectors?.sectors ?? []).map((s) => (
              <option key={s.key} value={s.key}>
                {s.label}
              </option>
            ))}
          </select>
          <label className="small" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            <input
              type="checkbox"
              checked={includeGlobal}
              onChange={(e) => onIncludeGlobalChange(e.target.checked)}
            />
            also show global (non-India) deadlines
          </label>
        </div>
        {profile && (
          <p className="small faint" style={{ marginTop: 8 }} title={profile.quote}>
            Why this sector: {profile.citation}
          </p>
        )}
      </div>

      {!data && <p className="muted">Loading sector report…</p>}

      {data && (
        <>
          <div className="counts">
            {['overdue', 'at_risk', 'on_track', 'no_deadline'].map((status) =>
              data.counts?.[status] ? (
                <div className="count" key={status}>
                  <span className="n">{data.counts[status]}</span>
                  <SectorStatus value={status} />
                </div>
              ) : null
            )}
          </div>

          <table>
            <thead>
              <tr>
                <th>Asset</th>
                <th>Status</th>
                <th>Nearest obligation</th>
                <th>Undated obligations</th>
              </tr>
            </thead>
            <tbody>
              {[...data.assets]
                .sort((a, b) => STATUS_RANK[b.status] - STATUS_RANK[a.status])
                .map((asset) => (
                  <tr key={asset.asset_id}>
                    <td className="mono small">{asset.asset_id}</td>
                    <td>
                      <SectorStatus value={asset.status} />
                    </td>
                    <td className="small" title={asset.reason}>
                      {asset.reason}
                    </td>
                    <td className="small">
                      {asset.obligations.length === 0 ? (
                        <span className="faint">—</span>
                      ) : (
                        asset.obligations.map((o) => (
                          <div key={o.policy} title={o.quote}>
                            <span className="badge">obligation, no deadline</span> {o.policy}
                          </div>
                        ))
                      )}
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

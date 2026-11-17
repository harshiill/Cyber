import { useState } from 'react'
import FilterButtons from './FilterButtons'
import { InfoTip } from './ui'

const RISK_BADGE = {
  CRITICAL: { background: '#ef4444', color: '#fff' },
  HIGH:     { background: '#f97316', color: '#fff' },
  MEDIUM:   { background: '#eab308', color: '#000' },
  LOW:      { background: '#22c55e', color: '#fff' },
}

function RiskBadge({ score, level }) {
  const style = RISK_BADGE[level] || RISK_BADGE.LOW
  return (
    <span style={{
      ...style, fontSize: 9, fontWeight: 700, padding: '2px 6px',
      borderRadius: 'var(--radius-full)', fontFamily: 'var(--font-mono)',
    }}>
      {level} {score != null ? score : ''}
    </span>
  )
}

function Row({ alert, selected, onSelect }) {
  const isAtk = alert.is_attack
  const sel = selected === alert.id
  // Confidence in the decision shown (falls back for older alerts without the field).
  const conf = alert.confidence != null
    ? alert.confidence
    : (alert.ml_available === false ? null : (isAtk ? alert.attack_prob : 1 - alert.attack_prob))
  const hasExplanation = Array.isArray(alert.explanation) && alert.explanation.length > 0
  return (
    <>
      <tr
        onClick={() => onSelect(alert.id)}
        style={{
          cursor: 'pointer',
          background: sel
            ? (isAtk ? 'var(--threat-light)' : 'var(--benign-light)')
            : (isAtk ? '#fff5f5' : '#f0fdf4'),
          borderLeft: `3px solid ${isAtk ? 'var(--threat)' : 'var(--benign)'}`,
          outline: sel ? `1px solid ${isAtk ? 'var(--threat-border)' : 'var(--benign-border)'}` : 'none',
          transition: 'background .12s',
        }}
      >
        <td style={{ padding: '7px 10px' }}>
          <span className={`badge badge--${isAtk ? 'attack' : 'benign'}`}>
            {alert.prediction === 'Unclassified' ? 'UNCLASSIFIED' : alert.prediction === 'Anomaly' ? 'ANOMALY' : isAtk ? 'ATTACK' : 'BENIGN'}
          </span>
        </td>
        <td className="mono" style={{ padding: '7px 6px', fontSize: 10, color: 'var(--text-muted)' }}>{alert.src_ip ?? 'Not recorded'}</td>
        <td className="mono" style={{ padding: '7px 6px', fontSize: 10, color: 'var(--text-muted)' }}>{alert.dst_ip ? `${alert.dst_ip}:${alert.dst_port}` : 'Not recorded'}</td>
        <td style={{ padding: '7px 6px', fontSize: 11, fontWeight: 700, color: isAtk ? 'var(--threat)' : 'var(--benign)' }}>
          {conf == null ? '—' : `${(conf * 100).toFixed(1)}%`}
        </td>
        <td style={{ padding: '7px 6px' }}>
          {alert.risk_level
            ? <RiskBadge score={alert.risk_score} level={alert.risk_level} />
            : <span style={{ color: 'var(--text-faint)', fontSize: 9 }}>—</span>
          }
        </td>
        <td style={{ padding: '7px 6px', fontSize: 10, color: 'var(--text-muted)' }}>{alert.attack_type ?? alert.prediction ?? '—'}</td>
        <td className="mono" style={{ padding: '7px 10px', fontSize: 9, color: 'var(--text-xfaint)' }}>{alert.timestamp}</td>
      </tr>
      {sel && hasExplanation && (
        <tr style={{ background: sel ? (isAtk ? 'var(--threat-light)' : 'var(--benign-light)') : 'transparent' }}>
          <td colSpan={7} style={{ padding: '4px 24px 10px', borderLeft: `3px solid ${isAtk ? 'var(--threat)' : 'var(--benign)'}` }}>
            <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--text-faint)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
              Why:
            </span>
            <ul style={{ margin: '4px 0 0', paddingLeft: 16 }}>
              {alert.explanation.map((line, i) => (
                <li key={i} style={{ fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.6 }}>{line}</li>
              ))}
            </ul>
          </td>
        </tr>
      )}
    </>
  )
}

export default function AlertTable({ alerts, selectedId, onSelect, onClear }) {
  const [filter, setFilter] = useState('all')
  const visible = alerts.filter(a =>
    filter === 'all'    ? true :
    filter === 'attack' ? a.is_attack :
    !a.is_attack && a.prediction !== 'Unclassified'
  )
  return (
    <div className="surface panel" style={{ overflow: 'hidden' }}>
      <div className="panel-header">
        <span className="label">
          Alert Log {alerts.length > 0 && (
            <span style={{ color: 'var(--text-faint)', fontWeight: 500, marginLeft: 6 }}>({alerts.length})</span>
          )}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <FilterButtons active={filter} onChange={setFilter} />
          {onClear && alerts.length > 0 && (
            <button onClick={onClear} title="Clear all alerts from the buffer"
              style={{ padding: '3px 10px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)',
                border: '1px solid var(--border)', borderRadius: 5, background: 'var(--surface)', cursor: 'pointer' }}>
              Clear
            </button>
          )}
        </div>
      </div>
      <div style={{ overflowY: 'auto', maxHeight: 220 }}>
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Type</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Source</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Destination</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>
                <InfoTip text="The model's confidence in the decision shown (Attack or Benign). P(attack) ≥ threshold triggers an alert.">Confidence</InfoTip>
              </th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Risk</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Attack Type</th>
              <th className="label" style={{ padding: '0 10px 8px', textAlign: 'left', borderBottom: '1px solid var(--border-subtle)' }}>Time</th>
            </tr>
          </thead>
          <tbody>
            {visible.map(a => <Row key={a.id} alert={a} selected={selectedId} onSelect={onSelect} />)}
          </tbody>
        </table>
        {visible.length === 0 && (
          <p style={{ textAlign: 'center', color: 'var(--text-faint)', padding: 24, fontSize: 12 }}>
            No alerts yet.
          </p>
        )}
      </div>
    </div>
  )
}

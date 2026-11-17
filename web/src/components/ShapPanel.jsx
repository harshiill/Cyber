import { useState, useEffect } from 'react'
import http from '../api/http'
import AlertExplanation from './AlertExplanation'

function FeatureBar({ label, value, direction, scale = 0.5 }) {
  const abs   = Math.abs(value)
  const pct   = Math.min((abs / scale) * 100, 100)
  const color = direction === 'positive'
    ? 'linear-gradient(90deg, var(--threat), #f97316)'
    : 'linear-gradient(90deg, var(--accent), #60a5fa)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 7 }}>
      <span className="mono" style={{ fontSize: 9, color: 'var(--text-muted)', width: 130, textAlign: 'right', flexShrink: 0,
        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={label}>{label}</span>
      <div style={{ flex: 1, height: 10, background: 'var(--border-subtle)', borderRadius: 4, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 4 }} />
      </div>
      <span className="mono" style={{ fontSize: 9, width: 40, textAlign: 'right', fontWeight: 700,
        color: direction === 'positive' ? 'var(--threat)' : 'var(--accent)', flexShrink: 0 }}>
        {value > 0 ? '+' : ''}{value.toFixed(2)}
      </span>
    </div>
  )
}

function DirectionLegend() {
  return (
    <div style={{ display: 'flex', gap: 14, marginBottom: 10 }}>
      <span style={{ fontSize: 9, color: 'var(--threat)', fontWeight: 700 }}>■ toward Attack</span>
      <span style={{ fontSize: 9, color: 'var(--accent)', fontWeight: 700 }}>■ toward Benign</span>
    </div>
  )
}

export default function ShapPanel({ selectedId, onClose }) {
  const [shap, setShap] = useState(null)
  const [lime, setLime] = useState(null)
  const [shapLoading, setShapLoading] = useState(Boolean(selectedId))
  const [limeLoading, setLimeLoading] = useState(Boolean(selectedId))
  const [shapErr, setShapErr] = useState(null)
  const [limeErr, setLimeErr] = useState(null)
  const [typeExp, setTypeExp] = useState(null)
  const [typeLoading, setTypeLoading] = useState(Boolean(selectedId))
  const [feedbackSaved, setFeedbackSaved] = useState(false)

  // Fetch both SHAP (fast) and LIME (slow) when the selected alert changes.
  useEffect(() => {
    if (!selectedId) return

    http.get(`/explain/${selectedId}/type`)
      .then(r => setTypeExp(r.data))
      .catch(() => setTypeExp(null))
      .finally(() => setTypeLoading(false))

    http.get(`/explain/${selectedId}`)
      .then(r => setShap(r.data))
      .catch(e => setShapErr(e.response?.data?.detail || 'SHAP unavailable.'))
      .finally(() => setShapLoading(false))

    http.get(`/explain/${selectedId}/lime`)
      .then(r => setLime(r.data))
      .catch(e => setLimeErr(e.response?.data?.detail || 'LIME unavailable.'))
      .finally(() => setLimeLoading(false))
  }, [selectedId])

  const limeScale = lime?.rules
    ? Math.max(0.001, ...lime.rules.map(r => Math.abs(r.lime_weight)))
    : 0.5

  const pred = shap || lime  // either source carries prediction + attack_prob

  return (
    <div className="surface" style={{ borderTop: '1px solid var(--border)', maxHeight: 360, overflowY: 'auto' }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '12px 22px 0', flexWrap: 'wrap' }}>
        <span className="label">XAI Explanation — SHAP vs LIME</span>

        {pred && (
          <span style={{ padding: '3px 10px', borderRadius: 'var(--radius-full)',
            background: pred.prediction === 'Attack' ? 'var(--threat-light)' : 'var(--benign-light)',
            color:      pred.prediction === 'Attack' ? 'var(--threat)'       : 'var(--benign)',
            fontSize: 9, fontWeight: 700,
            border: `1px solid ${pred.prediction === 'Attack' ? 'var(--threat-border)' : '#bbf7d0'}`,
            fontFamily: 'var(--font-mono)' }}>
            {pred.prediction} — {((pred.prediction === 'Attack' ? pred.attack_prob : 1 - pred.attack_prob) * 100).toFixed(1)}%
          </span>
        )}

        {pred?.predicted_type && pred.prediction === 'Attack' && (
          <span title="Predicted attack category from the secondary type classifier"
            style={{ padding: '3px 10px', borderRadius: 'var(--radius-full)', fontSize: 9, fontWeight: 700,
              background: 'var(--threat-light)', color: 'var(--threat)', border: '1px solid var(--threat-border)',
              fontFamily: 'var(--font-mono)' }}>
            Attack type: {pred.predicted_type}
            {pred.predicted_type_conf != null ? ` (${(pred.predicted_type_conf * 100).toFixed(0)}%)` : ''}
          </span>
        )}

        {selectedId && (
          <a href={`/api/alerts/${selectedId}/report.pdf`} target="_blank" rel="noreferrer"
            title="Download a one-page PDF report for this alert"
            style={{ marginLeft: 'auto', padding: '3px 10px', fontSize: 10, fontWeight: 700,
              background: 'var(--accent-light)', color: 'var(--accent)',
              border: '1px solid var(--accent-border)', borderRadius: 5,
              textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: 5 }}>
            ⬇ PDF Report
          </a>
        )}

        {selectedId && (
          <button onClick={() => onClose?.()} title="Close explanation"
            style={{ marginLeft: selectedId ? 8 : 'auto', width: 22, height: 22, display: 'inline-flex',
              alignItems: 'center', justifyContent: 'center', border: '1px solid var(--border)', borderRadius: 5,
              background: 'transparent', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, lineHeight: 1, flexShrink: 0 }}>
            ✕
          </button>
        )}
      </div>

      {!selectedId && (
        <p style={{ fontSize: 12, color: 'var(--text-faint)', padding: '12px 22px' }}>
          Select an alert row to inspect its SHAP and LIME explanations side by side.
        </p>
      )}

      {selectedId && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border-subtle)', marginTop: 12 }}>

          {/* SHAP column */}
          <div style={{ background: 'var(--surface)', padding: '14px 22px' }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
              <span style={{ fontSize: 12, fontWeight: 700 }}>SHAP</span>
              <span style={{ fontSize: 9, color: 'var(--text-xfaint)', fontStyle: 'italic' }}>exact · instant</span>
            </div>
            <DirectionLegend />
            {shapLoading && <p style={{ fontSize: 11, color: 'var(--text-faint)' }}>Loading SHAP…</p>}
            {shapErr && <p style={{ fontSize: 11, color: 'var(--threat)' }}>{shapErr}</p>}
            {shap && !shapLoading && shap.features.map(f => (
              <FeatureBar key={f.feature} label={f.feature} value={f.shap_value} direction={f.direction} />
            ))}
          </div>

          {/* LIME column */}
          <div style={{ background: 'var(--surface)', padding: '14px 22px' }}>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 10 }}>
              <span style={{ fontSize: 12, fontWeight: 700 }}>LIME</span>
              <span style={{ fontSize: 9, color: 'var(--text-xfaint)', fontStyle: 'italic' }}>
                local · approximate{lime?.elapsed_seconds ? ` · ${lime.elapsed_seconds}s` : ''}
              </span>
            </div>
            <DirectionLegend />
            {limeLoading && <p style={{ fontSize: 11, color: 'var(--text-faint)' }}>Running LIME (~5–10s)…</p>}
            {limeErr && <p style={{ fontSize: 11, color: 'var(--threat)' }}>{limeErr}</p>}
            {lime && !limeLoading && lime.rules.map((r, i) => (
              <FeatureBar key={i} label={r.description} value={r.lime_weight} direction={r.direction} scale={limeScale} />
            ))}
          </div>
        </div>
      )}

      {/* Why this attack type? (secondary type classifier, SHAP + LIME) */}
      {selectedId && (typeLoading || typeExp?.available) && (
        <div style={{ borderTop: '1px solid var(--border)' }}>
          <div style={{ padding: '12px 22px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span className="label">Why this attack type?</span>
            {typeExp?.available && (
              <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--threat)', fontFamily: 'var(--font-mono)' }}>
                {typeExp.predicted_type} ({(typeExp.confidence * 100).toFixed(0)}%)
              </span>
            )}
          </div>
          {typeLoading && !typeExp?.available && (
            <p style={{ fontSize: 11, color: 'var(--text-faint)', padding: '8px 22px' }}>Explaining the attack type (~5-10s)…</p>
          )}
          {typeExp?.available && (() => {
            const sScale = Math.max(0.001, ...(typeExp.shap || []).map(f => Math.abs(f.value)))
            const lScale = Math.max(0.001, ...(typeExp.lime || []).map(r => Math.abs(r.weight)))
            return (
              <>
                <p style={{ fontSize: 9, color: 'var(--text-faint)', padding: '4px 22px 0' }}>
                  Red supports the predicted type · blue argues against it
                </p>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border-subtle)', marginTop: 8 }}>
                  <div style={{ background: 'var(--surface)', padding: '12px 22px' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 8 }}>SHAP — features for {typeExp.predicted_type}</div>
                    {(typeExp.shap || []).map(f => (
                      <FeatureBar key={f.feature} label={f.feature} value={f.value} direction={f.direction} scale={sScale} />
                    ))}
                  </div>
                  <div style={{ background: 'var(--surface)', padding: '12px 22px' }}>
                    <div style={{ fontSize: 11, fontWeight: 700, marginBottom: 8 }}>LIME — rules for {typeExp.predicted_type}</div>
                    {(typeExp.lime || []).map((r, i) => (
                      <FeatureBar key={i} label={r.description} value={r.weight} direction={r.direction} scale={lScale} />
                    ))}
                  </div>
                </div>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7, padding: '10px 22px', margin: 0 }}>
                  {typeExp.narrative}
                </p>
              </>
            )
          })()}
        </div>
      )}

      {/* Plain-English narratives */}
      {selectedId && (shap?.summary || lime?.summary) && (
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border-subtle)' }}>
          <div style={{ background: 'var(--surface)', padding: '14px 22px' }}>
            <span className="label">Plain English (SHAP)</span>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.75, whiteSpace: 'pre-wrap', margin: '6px 0 0' }}>
              {shap?.summary || '—'}
            </p>
          </div>
          <div style={{ background: 'var(--surface)', padding: '14px 22px' }}>
            <span className="label">Plain English (LIME)</span>
            <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.75, whiteSpace: 'pre-wrap', margin: '6px 0 0' }}>
              {lime?.summary || (limeLoading ? 'Running LIME…' : '—')}
            </p>
          </div>
        </div>
      )}

      {/* Feedback */}
      {selectedId && (
        <>
          <AlertExplanation
            alert={{ id: selectedId, explanation: shap?.summary ? [shap.summary] : [] }}
            onFeedback={() => setFeedbackSaved(true)}
          />
          {feedbackSaved && (
            <div style={{
              margin: '0 22px 12px',
              padding: '6px 12px', borderRadius: 6, fontSize: 11, fontWeight: 600,
              background: 'var(--benign-light)', color: 'var(--benign)',
              border: '1px solid #bbf7d0', display: 'inline-flex', alignItems: 'center', gap: 6,
            }}>
              ✓ Feedback saved
            </div>
          )}
        </>
      )}
    </div>
  )
}

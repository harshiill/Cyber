import { useState } from 'react'
import TopBar from '../components/TopBar'
import { useModel } from '../hooks/useModel'
import http from '../api/http'
import { InfoTip } from '../components/ui'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer, CartesianGrid,
} from 'recharts'

const SAMPLE_TYPES = [
  { id: 'attack',  label: 'Attack sample' },
  { id: 'benign',  label: 'Benign sample' },
  { id: 'random',  label: 'Random' },
]

function FeatureBar({ feature, value, direction, maxAbs }) {
  const isPos   = direction === 'positive'
  const barPct  = Math.min(100, (Math.abs(value) / (maxAbs || 1)) * 100)
  const barColor = isPos ? '#dc2626' : '#2563eb'
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 11, color: 'var(--text)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{feature}</span>
        <span style={{ fontSize: 10, color: barColor, fontFamily: 'var(--font-mono)' }}>
          {isPos ? '+' : ''}{value.toFixed(4)}
        </span>
      </div>
      <div style={{ height: 6, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${barPct}%`, background: barColor, borderRadius: 3 }} />
      </div>
    </div>
  )
}

function LimeRule({ description, weight, direction }) {
  const isPos   = direction === 'positive'
  const barColor = isPos ? '#dc2626' : '#2563eb'
  const barPct  = Math.min(100, Math.abs(weight) * 200)
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', flex: 1, paddingRight: 8, wordBreak: 'break-all' }}>{description}</span>
        <span style={{ fontSize: 10, color: barColor, fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
          {isPos ? '+' : ''}{weight.toFixed(4)}
        </span>
      </div>
      <div style={{ height: 5, background: 'var(--border)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${barPct}%`, background: barColor, borderRadius: 3 }} />
      </div>
    </div>
  )
}

function DirectionLegend() {
  return (
    <div style={{ marginBottom: 8 }}>
      <span style={{ fontSize: 10, color: '#dc2626', fontWeight: 600 }}>■ Pushes toward Attack</span>
      <span style={{ fontSize: 10, color: '#2563eb', fontWeight: 600, marginLeft: 12 }}>■ Pushes toward Benign</span>
    </div>
  )
}

function PredBadge({ prediction, prob }) {
  const isAttack = prediction?.toUpperCase() === 'ATTACK'
  const conf = isAttack ? prob : 1 - prob   // confidence in the decision shown
  return (
    <span style={{ padding: '3px 10px', borderRadius: 99, fontSize: 11, fontWeight: 700,
      background: isAttack ? 'var(--threat-light)' : 'var(--benign-light)',
      color: isAttack ? 'var(--threat)' : 'var(--benign)',
      border: `1px solid ${isAttack ? 'var(--threat-border)' : '#bbf7d0'}` }}>
      {prediction} · {(conf * 100).toFixed(1)}%
    </span>
  )
}

function SampleExplorer() {
  const [sampleType, setSampleType] = useState('attack')
  const [rowIndex, setRowIndex]     = useState('')
  const [selectedDataset, setDataset] = useState(null)
  const { modelInfo } = useModel()
  const dataset = selectedDataset || modelInfo?.dataset || '2017'
  const [loading, setLoading]       = useState(false)
  const [data, setData]             = useState(null)
  const [err, setErr]               = useState(null)

  async function generate() {
    setLoading(true); setErr(null); setData(null)
    try {
      const url = `/explain/sample?type=${sampleType}&dataset=${dataset}` +
        (rowIndex !== '' ? `&index=${rowIndex}` : '')
      const r = await http.get(url)
      setData(r.data)
    } catch (e) {
      setErr(e.response?.data?.detail || 'Explanation failed.')
    } finally {
      setLoading(false)
    }
  }

  const shapMax = data ? Math.max(...(data.shap_features || []).map(f => Math.abs(f.shap_value)), 0.001) : 1
  const limeMax = data ? Math.max(...(data.lime_features || []).map(f => Math.abs(f.lime_weight)), 0.001) : 1

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '12px 24px', flexShrink: 0 }}>
        <p style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 8 }}>
          Pick an attack or benign sample, or enter a specific row number to re-test the same flow and check consistency — both SHAP and LIME run.
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}
            title="Which dataset to sample from. The matching model is loaded automatically.">
            {['2017', '2018'].map(d => (
              <button key={d} onClick={() => setDataset(d)}
                style={{ padding: '4px 12px', fontSize: 11, fontWeight: 600, cursor: 'pointer', border: 'none',
                  background: dataset === d ? 'var(--accent)' : 'transparent',
                  color: dataset === d ? '#fff' : 'var(--text-muted)' }}>
                CIC-IDS{d}
              </button>
            ))}
          </div>

          <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
            {SAMPLE_TYPES.map(s => (
              <button key={s.id} onClick={() => setSampleType(s.id)} disabled={rowIndex !== ''}
                title={rowIndex !== '' ? 'Clear the row number to use a random sample' : ''}
                style={{ padding: '4px 12px', fontSize: 11, fontWeight: 600,
                  cursor: rowIndex !== '' ? 'default' : 'pointer', border: 'none',
                  opacity: rowIndex !== '' ? 0.5 : 1,
                  background: sampleType === s.id ? 'var(--accent)' : 'transparent',
                  color: sampleType === s.id ? '#fff' : 'var(--text-muted)' }}>
                {s.label}
              </button>
            ))}
          </div>

          <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>or row #</span>
          <input type="number" min={0} value={rowIndex} placeholder="any"
            onChange={e => setRowIndex(e.target.value)}
            style={{ width: 90, padding: '4px 8px', fontSize: 11, border: '1px solid var(--border)',
              borderRadius: 5, background: 'var(--surface)', color: 'var(--text)', fontFamily: 'var(--font-mono)' }} />

          <button onClick={generate} disabled={loading}
            style={{ padding: '5px 18px', background: loading ? 'var(--border)' : 'var(--accent)',
              color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 11,
              cursor: loading ? 'default' : 'pointer' }}>
            {loading ? 'Generating… (~10s)' : 'Generate Explanation'}
          </button>
          {data && <PredBadge prediction={data.prediction} prob={data.attack_prob} />}
          {data && (
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>
              Row <strong style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>#{data.row_index}</strong>
              {data.dataset_size ? ` of ${data.dataset_size.toLocaleString()}` : ''} · true label:{' '}
              <strong style={{ color: data.true_label === 'Attack' ? 'var(--threat)' : 'var(--benign)' }}>{data.true_label}</strong>
            </span>
          )}
          {err && <span style={{ fontSize: 11, color: 'var(--threat)' }}>{err}</span>}
        </div>
      </div>

      {!data && !loading && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-faint)', fontSize: 13 }}>
          Select a sample type and click "Generate Explanation".<br />
          <span style={{ fontSize: 11 }}>LIME takes ~10 seconds — both methods run together.</span>
        </div>
      )}
      {loading && (
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--text-faint)', fontSize: 13 }}>
          Running SHAP + LIME… this takes ~10 seconds.
        </div>
      )}

      {data && (
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'auto' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border)', flexShrink: 0 }}>
            <div style={{ background: 'var(--bg)', padding: 20 }}>
              <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>SHAP Explanation</p>
              <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 16 }}>
                SHapley Additive exPlanations — exact feature contributions
              </p>
              <DirectionLegend />
              {data.shap_features?.length > 0
                ? data.shap_features.map((f, i) => (
                    <FeatureBar key={i} feature={f.feature} value={f.shap_value} direction={f.direction} maxAbs={shapMax} />
                  ))
                : <p style={{ color: 'var(--text-faint)', fontSize: 12 }}>No SHAP data.</p>
              }
            </div>
            <div style={{ background: 'var(--bg)', padding: 20 }}>
              <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>LIME Explanation</p>
              <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 16 }}>
                Local Interpretable Model-agnostic Explanations — rule-based conditions
              </p>
              <DirectionLegend />
              {data.lime_features?.length > 0
                ? data.lime_features.map((f, i) => (
                    <LimeRule key={i} description={f.description} weight={f.lime_weight} direction={f.direction} maxAbs={limeMax} />
                  ))
                : <p style={{ color: 'var(--text-faint)', fontSize: 12 }}>No LIME data.</p>
              }
            </div>
          </div>

          {(data.shap_narrative || data.lime_narrative) && (
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border)', flexShrink: 0 }}>
              {data.shap_narrative && (
                <div style={{ background: 'var(--surface)', padding: '16px 20px', borderTop: '1px solid var(--border)' }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Plain English (SHAP)</p>
                  <p style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.8, whiteSpace: 'pre-wrap', margin: 0 }}>
                    {data.shap_narrative}
                  </p>
                </div>
              )}
              {data.lime_narrative && (
                <div style={{ background: 'var(--surface)', padding: '16px 20px', borderTop: '1px solid var(--border)' }}>
                  <p style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>Plain English (LIME)</p>
                  <p style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.8, whiteSpace: 'pre-wrap', margin: 0 }}>
                    {data.lime_narrative}
                  </p>
                </div>
              )}
            </div>
          )}

          {data.attack_type && (() => {
            const at = data.attack_type
            const sMax = Math.max(0.001, ...(at.shap || []).map(f => Math.abs(f.value)))
            return (
              <div style={{ flexShrink: 0, borderTop: '2px solid var(--border)' }}>
                <div style={{ background: 'var(--surface)', padding: '14px 20px 6px', display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <span style={{ fontSize: 13, fontWeight: 700 }}>Why this attack type?</span>
                  <span style={{ padding: '3px 10px', borderRadius: 99, fontSize: 11, fontWeight: 700,
                    background: 'var(--threat-light)', color: 'var(--threat)', border: '1px solid var(--threat-border)' }}>
                    {at.predicted_type} · {(at.confidence * 100).toFixed(0)}%
                  </span>
                  <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>red supports this type · blue argues against</span>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 1, background: 'var(--border)' }}>
                  <div style={{ background: 'var(--bg)', padding: 20 }}>
                    <p style={{ fontSize: 12, fontWeight: 700, marginBottom: 12 }}>SHAP — features for {at.predicted_type}</p>
                    {(at.shap || []).length > 0
                      ? at.shap.map((f, i) => <FeatureBar key={i} feature={f.feature} value={f.value} direction={f.direction} maxAbs={sMax} />)
                      : <p style={{ color: 'var(--text-faint)', fontSize: 12 }}>No SHAP data.</p>}
                  </div>
                  <div style={{ background: 'var(--bg)', padding: 20 }}>
                    <p style={{ fontSize: 12, fontWeight: 700, marginBottom: 12 }}>LIME — rules for {at.predicted_type}</p>
                    {(at.lime || []).length > 0
                      ? at.lime.map((r, i) => <LimeRule key={i} description={r.description} weight={r.weight} direction={r.direction} />)
                      : <p style={{ color: 'var(--text-faint)', fontSize: 12 }}>No LIME data.</p>}
                  </div>
                </div>
                {at.narrative && (
                  <div style={{ background: 'var(--surface)', padding: '14px 20px' }}>
                    <p style={{ fontSize: 12, color: 'var(--text)', lineHeight: 1.8, margin: 0 }}>{at.narrative}</p>
                  </div>
                )}
              </div>
            )
          })()}
        </div>
      )}
    </div>
  )
}

function GlobalImportance() {
  const [n, setN]           = useState(200)
  const [loading, setLoading] = useState(false)
  const [data, setData]     = useState(null)
  const [err, setErr]       = useState(null)
  const [topK, setTopK]     = useState(15)

  async function generate() {
    setLoading(true); setErr(null); setData(null)
    try {
      const r = await http.get(`/explain/global?n_samples=${n}`)
      setData(r.data)
    } catch (e) {
      setErr(e.response?.data?.detail || 'Global SHAP failed.')
    } finally {
      setLoading(false)
    }
  }

  const top   = data ? data.features.slice(0, topK) : []
  const chart = top.map(f => ({ ...f, label: f.feature.length > 28 ? f.feature.slice(0, 26) + '…' : f.feature }))

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '12px 24px', flexShrink: 0 }}>
        <p style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 8 }}>
          Mean(|SHAP|) over a random sample — tells you which features the model relies on overall, not per-prediction.
        </p>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
          <span className="label">Sample size:</span>
          <input type="number" min={50} max={2000} step={50} value={n}
            onChange={e => setN(Math.max(50, Math.min(2000, +e.target.value || 200)))}
            style={{ width: 80, padding: '4px 8px', fontSize: 11, border: '1px solid var(--border)', borderRadius: 5,
              background: 'var(--surface)', color: 'var(--text)', fontFamily: 'var(--font-mono)' }} />

          <span className="label">Top features:</span>
          <input type="number" min={5} max={30} step={1} value={topK}
            onChange={e => setTopK(Math.max(5, Math.min(30, +e.target.value || 15)))}
            style={{ width: 60, padding: '4px 8px', fontSize: 11, border: '1px solid var(--border)', borderRadius: 5,
              background: 'var(--surface)', color: 'var(--text)', fontFamily: 'var(--font-mono)' }} />

          <button onClick={generate} disabled={loading}
            style={{ padding: '5px 18px', background: loading ? 'var(--border)' : 'var(--accent)',
              color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 11,
              cursor: loading ? 'default' : 'pointer' }}>
            {loading ? 'Computing…' : 'Compute Global Importance'}
          </button>

          {data && (
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>
              {data.n_samples?.toLocaleString()} samples ({data.n_attack} attack / {data.n_benign} benign) · CIC-IDS{data.dataset}
            </span>
          )}
          {err && <span style={{ fontSize: 11, color: 'var(--threat)' }}>{err}</span>}
        </div>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: '24px 32px' }}>
        {!data && !loading && (
          <p style={{ color: 'var(--text-faint)', fontSize: 13, textAlign: 'center', marginTop: 80 }}>
            Click "Compute Global Importance" to aggregate SHAP across the dataset.
          </p>
        )}
        {loading && (
          <p style={{ color: 'var(--text-faint)', fontSize: 13, textAlign: 'center', marginTop: 80 }}>
            Running SHAP across {n.toLocaleString()} samples… this can take 10–60s.
          </p>
        )}

        {data && (
          <>
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 20 }}>
              <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                <InfoTip text="Mean absolute SHAP value across the sample. Bigger = the model relies on this feature more, regardless of which class it pushes toward.">
                  Top {topK} Features by Mean(|SHAP|)
                </InfoTip>
              </p>
              <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                Color = average direction this feature pushes the prediction (red = attack, blue = benign)
              </p>
              <ResponsiveContainer width="100%" height={Math.max(220, topK * 26)}>
                <BarChart data={chart} layout="vertical" margin={{ left: 10, right: 60, top: 4, bottom: 4 }}>
                  <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" horizontal={false} />
                  <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-faint)' }}
                    tickFormatter={v => v.toFixed(3)} />
                  <YAxis type="category" dataKey="label" width={200}
                    tick={{ fontSize: 10, fill: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} />
                  <Tooltip
                    formatter={(v, _, p) => [
                      v.toFixed(5),
                      `Mean |SHAP| · pushes ${p.payload.direction === 'attack' ? 'toward Attack' : 'toward Benign'}`,
                    ]}
                    contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }} />
                  <Bar dataKey="mean_abs_shap" radius={[0, 4, 4, 0]}>
                    {chart.map((d, i) => (
                      <Cell key={i} fill={d.direction === 'attack' ? '#dc2626' : '#2563eb'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>

            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
              <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 14 }}>
                <InfoTip text="Mean(|SHAP|) computed only on benign samples vs only on attack samples. A feature that lights up only on attacks is a strong attack-class signal.">
                  Per-class Importance
                </InfoTip>
              </p>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid var(--border)', textAlign: 'left' }}>
                    <th style={{ padding: '8px 6px', color: 'var(--text-muted)', fontWeight: 700 }}>#</th>
                    <th style={{ padding: '8px 6px', color: 'var(--text-muted)', fontWeight: 700 }}>Feature</th>
                    <th style={{ padding: '8px 6px', color: 'var(--text-muted)', fontWeight: 700, textAlign: 'right' }}>|SHAP|</th>
                    <th style={{ padding: '8px 6px', color: '#059669', fontWeight: 700, textAlign: 'right' }}>On Benign</th>
                    <th style={{ padding: '8px 6px', color: '#dc2626', fontWeight: 700, textAlign: 'right' }}>On Attack</th>
                    <th style={{ padding: '8px 6px', color: 'var(--text-muted)', fontWeight: 700 }}>Direction</th>
                  </tr>
                </thead>
                <tbody>
                  {top.map((f, i) => (
                    <tr key={f.feature} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                      <td style={{ padding: '7px 6px', color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>{i + 1}</td>
                      <td style={{ padding: '7px 6px', color: 'var(--text)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>{f.feature}</td>
                      <td style={{ padding: '7px 6px', textAlign: 'right', fontFamily: 'var(--font-mono)' }}>{f.mean_abs_shap.toFixed(5)}</td>
                      <td style={{ padding: '7px 6px', textAlign: 'right', fontFamily: 'var(--font-mono)', color: '#059669' }}>{f.benign_impact.toFixed(5)}</td>
                      <td style={{ padding: '7px 6px', textAlign: 'right', fontFamily: 'var(--font-mono)', color: '#dc2626' }}>{f.attack_impact.toFixed(5)}</td>
                      <td style={{ padding: '7px 6px' }}>
                        <span style={{ fontSize: 10, fontWeight: 700,
                          color: f.direction === 'attack' ? '#dc2626' : '#2563eb' }}>
                          {f.direction === 'attack' ? '→ Attack' : '→ Benign'}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </>
        )}
      </div>
    </div>
  )
}

const TABS = [
  { id: 'sample',   label: 'Sample Explorer' },
  { id: 'global',   label: 'Global Importance' },
]

export default function ExplainPage() {
  const [tab, setTab] = useState('sample')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <TopBar />

      <div style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '10px 24px 0',
        flexShrink: 0, display: 'flex', alignItems: 'flex-end', gap: 4 }}>
        <span style={{ fontSize: 14, fontWeight: 700, marginRight: 18, paddingBottom: 8 }}>XAI Insights</span>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            style={{ padding: '8px 16px', fontSize: 11, fontWeight: 700, cursor: 'pointer',
              border: 'none', background: 'transparent',
              color: tab === t.id ? 'var(--accent)' : 'var(--text-muted)',
              borderBottom: tab === t.id ? '2px solid var(--accent)' : '2px solid transparent',
              marginBottom: -1 }}>
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'sample'  && <SampleExplorer />}
      {tab === 'global'  && <GlobalImportance />}
    </div>
  )
}

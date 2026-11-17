import { useState } from 'react'
import TopBar from '../components/TopBar'
import http from '../api/http'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer,
  LineChart, Line, ReferenceLine, Legend, CartesianGrid,
} from 'recharts'
import { PageHeader, MetricCard, InfoTip } from '../components/ui'
import { useModel } from '../hooks/useModel'

const METRIC_DEFS = [
  { key: 'accuracy',    label: 'Accuracy',    color: '#2563eb',
    info: 'Fraction of all predictions that were correct.' },
  { key: 'precision',   label: 'Precision',   color: '#059669',
    info: 'Of flows flagged as attacks, how many really were attacks. Low = many false alarms.' },
  { key: 'recall',      label: 'Recall',      color: '#dc2626',
    info: 'Of all real attacks, how many the model caught. Low = attacks slip through.' },
  { key: 'f1',          label: 'F1-Score',    color: '#7c3aed',
    info: 'Harmonic mean of precision and recall — best single number on imbalanced data.' },
  { key: 'roc_auc',     label: 'ROC-AUC',     color: '#d97706',
    info: 'Probability the model ranks a random attack above a random benign flow. 0.5 = random, 1.0 = perfect.' },
  { key: 'specificity', label: 'Specificity', color: '#0891b2',
    info: 'Of all real benign flows, how many were correctly identified.' },
]

/* Heatmap cell — intensity is count / max(cell_in_row), so each row scales independently
   and the dominant cell on each row stands out regardless of class imbalance. */
function HeatCell({ value, total, rowMax, label, kind }) {
  const pct = total > 0 ? (value / total) * 100 : 0
  const intensity = rowMax > 0 ? value / rowMax : 0
  // green for correct, red for errors; alpha scales with intensity within row
  const baseRGB = kind === 'correct' ? '5, 150, 105' : '220, 38, 38'
  const alpha   = 0.18 + 0.72 * intensity
  return (
    <div style={{
      background: `rgba(${baseRGB}, ${alpha})`,
      border: `1px solid rgba(${baseRGB}, ${0.4 + 0.4 * intensity})`,
      borderRadius: 6, padding: '20px 10px', textAlign: 'center',
      transition: 'transform 0.15s', cursor: 'default',
      display: 'flex', flexDirection: 'column', justifyContent: 'center',
    }}>
      <p style={{ fontSize: 10, color: 'rgba(255,255,255,0.85)', marginBottom: 4, fontWeight: 600, letterSpacing: 0.2 }}>
        {label}
      </p>
      <p style={{ fontSize: 24, fontWeight: 800, color: '#fff', fontFamily: 'var(--font-mono)', lineHeight: 1.1 }}>
        {value?.toLocaleString() ?? '—'}
      </p>
      <p style={{ fontSize: 10, color: 'rgba(255,255,255,0.7)', marginTop: 3, fontFamily: 'var(--font-mono)' }}>
        {pct.toFixed(2)}%
      </p>
    </div>
  )
}

const DATASETS = ['2017', '2018']

export default function EvaluatePage() {
  const [loading, setLoading]   = useState(false)
  const [data, setData]         = useState(null)
  const [thrData, setThrData]   = useState(null)
  const [thrLoading, setThrLoading] = useState(false)
  const [err, setErr]           = useState(null)
  const [selectedDataset, setDataset] = useState(null)
  const [threshold, setThreshold] = useState(0.5)
  const { modelInfo } = useModel()
  const dataset = selectedDataset || modelInfo?.dataset || '2017'

  // Explanation-validation state (independent of the detection eval above)
  const [xLoading, setXLoading] = useState(false)
  const [xData, setXData]       = useState(null)
  const [xErr, setXErr]         = useState(null)
  const [xN, setXN]             = useState(24)

  async function runXaiValidation() {
    setXLoading(true); setXErr(null); setXData(null)
    try {
      const r = await http.post('/evaluate/explanations', { dataset, n: xN, k: 3 })
      setXData(r.data)
    } catch (e) {
      setXErr(e.response?.data?.detail || 'Explanation validation failed.')
    } finally {
      setXLoading(false)
    }
  }

  async function runEval() {
    setLoading(true); setErr(null); setData(null); setThrData(null); setThreshold(0.5)
    try {
      const r = await http.post('/evaluate', { dataset })
      setData(r.data)
    } catch (e) {
      setErr(e.response?.data?.detail || 'Evaluation failed.')
    } finally {
      setLoading(false)
    }
  }

  async function recomputeAtThreshold(t) {
    setThreshold(t)
    if (!data) return
    setThrLoading(true)
    try {
      const r = await http.post(`/evaluate/threshold?threshold=${t}`)
      setThrData(r.data)
    } catch (e) {
      setErr(e.response?.data?.detail || 'Threshold recompute failed.')
    } finally {
      setThrLoading(false)
    }
  }

  // Use threshold-overridden values if available
  const view = thrData ? { ...data, ...thrData } : data
  const trainDs = modelInfo?.dataset
  const isCross = trainDs && dataset && trainDs !== dataset

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <TopBar />
      <div style={{ flex: 1, padding: '32px 40px', overflowY: 'auto', maxWidth: 1000, width: '100%', margin: '0 auto' }}>

        <PageHeader
          title="Model Evaluation"
          subtitle="Run the active model against a holdout split, or against a different dataset entirely (cross-dataset generalisation test). Adjust the decision threshold to see the precision/recall trade-off live."
        >
          {modelInfo?.model_file && (
            <span style={{ fontSize: 10, color: 'var(--text-faint)', fontFamily: 'var(--font-mono)' }}>
              Trained on: <strong style={{ color: 'var(--text-muted)' }}>CIC-IDS{trainDs || '?'}{modelInfo?.metadata?.data_source === 'sample' ? ' demonstration sample' : ''}</strong>
            </span>
          )}
        </PageHeader>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12, flexWrap: 'wrap' }}>
          <span className="label">Test on:</span>
          <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
            {DATASETS.map(d => (
              <button key={d} onClick={() => setDataset(d)}
                style={{ padding: '5px 14px', fontSize: 11, fontWeight: 600, cursor: 'pointer', border: 'none',
                  background: dataset === d ? 'var(--accent)' : 'transparent',
                  color: dataset === d ? '#fff' : 'var(--text-muted)' }}>
                CIC-IDS{d}
              </button>
            ))}
          </div>

          <button onClick={runEval} disabled={loading}
            style={{ padding: '7px 22px', background: loading ? 'var(--border)' : 'var(--accent)',
              color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 12,
              cursor: loading ? 'default' : 'pointer' }}>
            {loading ? 'Evaluating…' : 'Run Evaluation'}
          </button>

          {data && (
            <span style={{ fontSize: 11, color: 'var(--text-faint)' }}>
              {data.test_samples?.toLocaleString()} samples
              {data.cross_dataset ? ' · full set (cross-dataset)' : ' · 20% holdout split'}
            </span>
          )}
        </div>

        {isCross && (
          <p style={{ fontSize: 11, color: 'var(--amber)', background: 'var(--amber-light)',
            border: '1px solid var(--amber-border)', borderRadius: 6, padding: '8px 12px', marginBottom: 16 }}>
            <strong>Cross-dataset:</strong> testing CIC-IDS{trainDs}-trained model on CIC-IDS{dataset}.
            Expect lower scores — this measures generalisation to unseen attack distributions.
          </p>
        )}

        {err && <p style={{ color: 'var(--threat)', fontSize: 12, marginBottom: 16 }}>{err}</p>}

        {!data && !loading && (
          <p style={{ color: 'var(--text-faint)', fontSize: 13 }}>
            Click "Run Evaluation" to compute metrics.
          </p>
        )}

        {data && view && (
          <>
            {/* Threshold slider */}
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
              padding: '14px 18px', marginBottom: 20 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8, flexWrap: 'wrap' }}>
                <span className="label">
                  <InfoTip text="The probability cutoff above which a flow is flagged as an attack. Lower = more sensitive (catches more attacks but more false alarms). Higher = more conservative.">
                    Decision threshold
                  </InfoTip>
                </span>
                <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--accent)', fontFamily: 'var(--font-mono)' }}>
                  {threshold.toFixed(2)}
                </span>
                {thrLoading && <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>recomputing…</span>}
                <button onClick={() => recomputeAtThreshold(0.5)}
                  style={{ marginLeft: 'auto', padding: '3px 10px', fontSize: 10, fontWeight: 600,
                    border: '1px solid var(--border)', borderRadius: 5, background: 'var(--surface)', color: 'var(--text-muted)',
                    cursor: 'pointer' }}>
                  Reset to 0.50
                </button>
              </div>
              <input type="range" min={0.05} max={0.95} step={0.01} value={threshold}
                onChange={e => setThreshold(+e.target.value)}
                onMouseUp={e => recomputeAtThreshold(+e.target.value)}
                onTouchEnd={e => recomputeAtThreshold(+e.target.value)}
                style={{ width: '100%' }} />
              <p style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 6, lineHeight: 1.5 }}>
                Drag the slider, then release to recompute precision/recall/F1 at that threshold.
                Useful for tuning the model toward higher recall (catch all attacks) or higher precision (fewer false alarms).
              </p>
            </div>

            {/* Metric cards */}
            <div style={{ display: 'flex', gap: 10, marginBottom: 24, flexWrap: 'wrap' }}>
              {METRIC_DEFS.map(m => (
                <MetricCard key={m.key}
                  label={m.label}
                  value={view[m.key] != null ? `${(view[m.key] * 100).toFixed(2)}%` : '—'}
                  color={m.color} accent info={m.info} />
              ))}
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                  <InfoTip text="Counts of correct vs incorrect predictions. Diagonal = correct. Off-diagonal = mistakes (FP = false alarm, FN = missed attack). Color intensity scales with the per-row count.">
                    Confusion Matrix
                  </InfoTip>
                </p>
                <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                  Rows = true class · Columns = predicted · darker = larger share of that row
                </p>
                {(() => {
                  const total = (view.tp || 0) + (view.tn || 0) + (view.fp || 0) + (view.fn || 0)
                  const benignRowMax = Math.max(view.tn || 0, view.fp || 0)
                  const attackRowMax = Math.max(view.fn || 0, view.tp || 0)
                  const colHeader = { fontSize: 10, color: 'var(--text-faint)', fontWeight: 600, textAlign: 'center', padding: '0 0 4px' }
                  const rowHeader = { fontSize: 10, color: 'var(--text-faint)', fontWeight: 600, writingMode: 'vertical-rl', transform: 'rotate(180deg)', textAlign: 'center', alignSelf: 'center' }
                  return (
                    <div style={{ display: 'grid', gridTemplateColumns: '18px 1fr 1fr', gap: 6 }}>
                      <div />
                      <div style={colHeader}>Predicted Benign</div>
                      <div style={colHeader}>Predicted Attack</div>

                      <div style={rowHeader}>True Benign</div>
                      <HeatCell value={view.tn} total={total} rowMax={benignRowMax} label="True Negative"  kind="correct" />
                      <HeatCell value={view.fp} total={total} rowMax={benignRowMax} label="False Positive" kind="error" />

                      <div style={rowHeader}>True Attack</div>
                      <HeatCell value={view.fn} total={total} rowMax={attackRowMax} label="False Negative" kind="error" />
                      <HeatCell value={view.tp} total={total} rowMax={attackRowMax} label="True Positive"  kind="correct" />
                    </div>
                  )
                })()}
                <div style={{ marginTop: 14, display: 'flex', gap: 16, justifyContent: 'center', flexWrap: 'wrap' }}>
                  {[
                    { label: 'FPR', value: view.fpr, hint: 'False Positive Rate' },
                    { label: 'FNR', value: view.fnr, hint: 'False Negative Rate' },
                  ].map(m => m.value != null && (
                    <span key={m.label} style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }} title={m.hint}>
                      {m.label}: <strong>{(m.value * 100).toFixed(2)}%</strong>
                    </span>
                  ))}
                </div>
              </div>

              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 16 }}>Summary</p>
                {[
                  { label: 'True Positives (attacks caught)', value: view.tp?.toLocaleString() },
                  { label: 'True Negatives (benign correct)', value: view.tn?.toLocaleString() },
                  { label: 'False Positives (false alarms)',  value: view.fp?.toLocaleString() },
                  { label: 'False Negatives (missed attacks)', value: view.fn?.toLocaleString() },
                  { label: 'Test samples',                    value: data.test_samples?.toLocaleString() },
                ].map(r => (
                  <div key={r.label} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border)', padding: '7px 0', fontSize: 12 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{r.label}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text)' }}>{r.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* ROC + PR curves */}
            {(data.roc_curve?.length > 0 || data.pr_curve?.length > 0) && (
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
                {data.roc_curve?.length > 0 && (
                  <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                    <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                      <InfoTip text="True positive rate vs false positive rate at every threshold. The closer the curve hugs the top-left corner, the better. The dashed diagonal is random-guessing.">
                        ROC Curve
                      </InfoTip>
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                      AUC = {data.roc_auc?.toFixed(4)} · 1.0 is perfect, 0.5 is random
                    </p>
                    <ResponsiveContainer width="100%" height={240}>
                      <LineChart data={data.roc_curve} margin={{ top: 8, right: 12, left: -10, bottom: 4 }}>
                        <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" />
                        <XAxis type="number" dataKey="fpr" domain={[0, 1]}
                          tickFormatter={v => v.toFixed(1)} tick={{ fontSize: 10, fill: 'var(--text-faint)' }}
                          label={{ value: 'False Positive Rate', position: 'insideBottom', offset: -2, fontSize: 10, fill: 'var(--text-faint)' }} />
                        <YAxis dataKey="tpr" domain={[0, 1]} tickFormatter={v => v.toFixed(1)}
                          tick={{ fontSize: 10, fill: 'var(--text-faint)' }}
                          label={{ value: 'TPR', angle: -90, position: 'insideLeft', fontSize: 10, fill: 'var(--text-faint)' }} />
                        <Tooltip
                          formatter={(v, n) => [v.toFixed(4), n === 'tpr' ? 'TPR' : 'FPR']}
                          contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }} />
                        <ReferenceLine segment={[{ x: 0, y: 0 }, { x: 1, y: 1 }]} stroke="var(--text-xfaint)" strokeDasharray="4 4" />
                        <Line type="monotone" dataKey="tpr" stroke="var(--accent)" strokeWidth={2.2} dot={false} isAnimationActive={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}

                {data.pr_curve?.length > 0 && (
                  <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                    <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                      <InfoTip text="Precision vs recall at every threshold. More informative than ROC for imbalanced data — the closer to the top-right, the better.">
                        Precision–Recall Curve
                      </InfoTip>
                    </p>
                    <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                      Better than ROC when classes are imbalanced
                    </p>
                    <ResponsiveContainer width="100%" height={240}>
                      <LineChart data={data.pr_curve} margin={{ top: 8, right: 12, left: -10, bottom: 4 }}>
                        <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" />
                        <XAxis type="number" dataKey="recall" domain={[0, 1]}
                          tickFormatter={v => v.toFixed(1)} tick={{ fontSize: 10, fill: 'var(--text-faint)' }}
                          label={{ value: 'Recall', position: 'insideBottom', offset: -2, fontSize: 10, fill: 'var(--text-faint)' }} />
                        <YAxis dataKey="precision" domain={[0, 1]} tickFormatter={v => v.toFixed(1)}
                          tick={{ fontSize: 10, fill: 'var(--text-faint)' }}
                          label={{ value: 'Precision', angle: -90, position: 'insideLeft', fontSize: 10, fill: 'var(--text-faint)' }} />
                        <Tooltip
                          formatter={(v, n) => [v.toFixed(4), n]}
                          contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }} />
                        <Line type="monotone" dataKey="precision" stroke="#7c3aed" strokeWidth={2.2} dot={false} isAnimationActive={false} />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                )}
              </div>
            )}

            {/* Confidence histogram */}
            {data.confidence_histogram?.length > 0 && (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 24 }}>
                <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                  <InfoTip text="How confident the model is on each test sample, separated by true class. Ideally benign flows score near 0 and attacks score near 1, with little overlap. Overlap is where false positives and missed attacks come from.">
                    Confidence Distribution
                  </InfoTip>
                </p>
                <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                  X-axis = predicted attack probability · Bars = how many flows of each true class fell into that bucket
                </p>
                <ResponsiveContainer width="100%" height={220}>
                  <BarChart data={data.confidence_histogram} margin={{ top: 8, right: 12, left: -10, bottom: 4 }}>
                    <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" />
                    <XAxis dataKey="bin" tick={{ fontSize: 8, fill: 'var(--text-faint)' }}
                      interval={1} />
                    <YAxis tick={{ fontSize: 10, fill: 'var(--text-faint)' }}
                      label={{ value: 'Count (log)', angle: -90, position: 'insideLeft', fontSize: 10, fill: 'var(--text-faint)' }}
                      scale="log" domain={[1, 'auto']} allowDataOverflow />
                    <Tooltip
                      contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }}
                      formatter={(v, n) => [v.toLocaleString(), n === 'benign' ? 'Benign' : 'Attack']} />
                    <Legend wrapperStyle={{ fontSize: 11 }} />
                    <Bar dataKey="benign" fill="#059669" name="Benign" />
                    <Bar dataKey="attack" fill="#dc2626" name="Attack" />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}

            {data.attack_breakdown?.length > 0 && (
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 16 }}>Detection by Attack Type</p>
                <ResponsiveContainer width="100%" height={Math.max(160, data.attack_breakdown.length * 28)}>
                  <BarChart data={data.attack_breakdown} layout="vertical" margin={{ left: 10, right: 40 }}>
                    <XAxis type="number" domain={[0, 1]} tickFormatter={v => `${(v*100).toFixed(0)}%`}
                      tick={{ fontSize: 10, fill: 'var(--text-faint)' }} />
                    <YAxis type="category" dataKey="attack" width={160}
                      tick={{ fontSize: 10, fill: 'var(--text-muted)' }} />
                    <Tooltip
                      formatter={(v, _, p) => [`${(v*100).toFixed(2)}% (${p.payload.count?.toLocaleString()} samples)`, 'Accuracy']}
                      contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }} />
                    <Bar dataKey="accuracy" radius={[0, 4, 4, 0]}>
                      {data.attack_breakdown.map((d, i) => (
                        <Cell key={i} fill={d.accuracy >= 0.95 ? '#059669' : d.accuracy >= 0.80 ? '#d97706' : '#dc2626'} />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </>
        )}

        {/* ── Explanation Validation (SHAP vs LIME) ───────────────────── */}
        <div style={{ marginTop: 40, paddingTop: 28, borderTop: '1px solid var(--border)' }}>
          <PageHeader
            title="Explanation Validation"
            subtitle="Compares SHAP and LIME on a held-out sample and measures agreement and feature influence. These checks do not prove an explanation is correct."
          />

          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16, flexWrap: 'wrap' }}>
            <span className="label">Sample size:</span>
            <div style={{ display: 'flex', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
              {[12, 24, 40].map(v => (
                <button key={v} onClick={() => setXN(v)}
                  style={{ padding: '5px 14px', fontSize: 11, fontWeight: 600, cursor: 'pointer', border: 'none',
                    background: xN === v ? 'var(--accent)' : 'transparent',
                    color: xN === v ? '#fff' : 'var(--text-muted)' }}>
                  {v}
                </button>
              ))}
            </div>
            <button onClick={runXaiValidation} disabled={xLoading}
              style={{ padding: '7px 22px', background: xLoading ? 'var(--border)' : 'var(--accent)',
                color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 12,
                cursor: xLoading ? 'default' : 'pointer' }}>
              {xLoading ? 'Validating…' : 'Validate Explanations'}
            </button>
            <span style={{ fontSize: 10, color: 'var(--text-faint)' }}>
              Runs SHAP + LIME on each flow on CIC-IDS{dataset} — LIME is slow, so this takes a moment.
            </span>
          </div>

          {xErr && <p style={{ color: 'var(--threat)', fontSize: 12, marginBottom: 16 }}>{xErr}</p>}

          {!xData && !xLoading && (
            <p style={{ color: 'var(--text-faint)', fontSize: 13 }}>
              Click "Validate Explanations" to measure explanation faithfulness, concentration and SHAP↔LIME consistency.
            </p>
          )}

          {xData && (
            <>
              <div style={{ display: 'flex', gap: 10, marginBottom: 24, flexWrap: 'wrap' }}>
                <MetricCard label="SHAP Faithfulness (ρ)"
                  value={xData.model_faithfulness.spearman != null ? xData.model_faithfulness.spearman.toFixed(2) : '—'}
                  color="#2563eb" accent
                  info="Rank correlation between SHAP's feature importances and the Random Forest's own built-in importances. High = SHAP highlights the features the model genuinely relies on, so the explanations reflect the real model. 1.0 = perfect alignment." />
                <MetricCard label="Explanation Concentration"
                  value={`${(xData.concentration.topk_pct * 100).toFixed(0)}%`}
                  color="#7c3aed" accent
                  info={`On average the top-${xData.k} features carry this share of the total SHAP attribution weight (out of all features). Higher = each decision rests on a small, interpretable set of features.`} />
                <MetricCard label="Local Accuracy"
                  value={xData.local_accuracy.passes ? '✓ Verified' : '✗ Failed'}
                  color={xData.local_accuracy.passes ? '#059669' : '#dc2626'} accent
                  sub={`error ${xData.local_accuracy.mean_recon_error.toExponential(1)}`}
                  info="SHAP's core guarantee (local accuracy): the base value plus the feature contributions should reconstruct the model's exact output. A near-zero reconstruction error proves the explanation is mathematically faithful to this model's prediction." />
                <MetricCard label="SHAP↔LIME Direction"
                  value={`${(xData.agreement.directional_rate * 100).toFixed(0)}%`}
                  color="#0891b2" accent
                  info="When SHAP and LIME surface the same feature, how often they agree on its direction (pushing toward attack vs benign). Direction agreement is the meaningful cross-method signal; exact ranking agreement is known to be low (the XAI 'disagreement problem')." />
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, marginBottom: 24 }}>
                {/* Concentration */}
                <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                  <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                    <InfoTip text="How much of each decision is captured as we accumulate the most important features. A steep rise means a few features explain most of the decision — the hallmark of a concise, interpretable explanation.">
                      Explanation Concentration
                    </InfoTip>
                  </p>
                  <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                    Cumulative share of SHAP attribution weight
                  </p>
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart
                      data={[
                        { name: 'Top 1',         pct: xData.concentration.top1_pct },
                        { name: `Top ${xData.k}`, pct: xData.concentration.topk_pct },
                        { name: 'All features',  pct: 1 },
                      ]}
                      margin={{ top: 8, right: 12, left: -10, bottom: 4 }}>
                      <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" />
                      <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
                      <YAxis domain={[0, 1]} tickFormatter={v => `${(v * 100).toFixed(0)}%`}
                        tick={{ fontSize: 10, fill: 'var(--text-faint)' }} />
                      <Tooltip
                        formatter={v => [`${(v * 100).toFixed(1)}%`, 'Coverage']}
                        contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }} />
                      <Bar dataKey="pct" radius={[4, 4, 0, 0]}>
                        <Cell fill="#a78bfa" /><Cell fill="#7c3aed" /><Cell fill="#4c1d95" />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>

                {/* Timing */}
                <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                  <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                    <InfoTip text="Average time to generate one explanation with each method. SHAP (TreeExplainer) is typically far faster than LIME, which trains a local surrogate model per sample.">
                      SHAP vs LIME — explanation time
                    </InfoTip>
                  </p>
                  <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                    Average milliseconds per explanation
                  </p>
                  <ResponsiveContainer width="100%" height={200}>
                    <BarChart
                      data={[
                        { name: 'SHAP', ms: xData.timing.shap_avg_ms },
                        { name: 'LIME', ms: xData.timing.lime_avg_ms },
                      ]}
                      layout="vertical" margin={{ top: 8, right: 40, left: 10, bottom: 4 }}>
                      <CartesianGrid stroke="var(--border-subtle)" strokeDasharray="3 3" />
                      <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-faint)' }}
                        label={{ value: 'ms', position: 'insideBottom', offset: -2, fontSize: 10, fill: 'var(--text-faint)' }} />
                      <YAxis type="category" dataKey="name" width={50}
                        tick={{ fontSize: 11, fill: 'var(--text-muted)' }} />
                      <Tooltip
                        formatter={v => [`${v.toLocaleString()} ms`, 'Avg']}
                        contentStyle={{ background: 'var(--surface)', border: '1px solid var(--border)', fontSize: 11 }} />
                      <Bar dataKey="ms" radius={[0, 4, 4, 0]}>
                        <Cell fill="#2563eb" />
                        <Cell fill="#d97706" />
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* Cross-method agreement (honest framing) */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20, marginBottom: 24 }}>
                <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                  <InfoTip text="SHAP and LIME are built on different principles, so their exact feature rankings often differ — a well-documented effect known as the 'disagreement problem'. The trustworthy signal is whether they agree on the direction of the features they both surface.">
                    SHAP vs LIME — cross-method consistency
                  </InfoTip>
                </p>
                <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                  Two independent explanation methods compared on the same flows
                </p>
                <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
                  {[
                    { label: 'Direction agreement', value: `${(xData.agreement.directional_rate * 100).toFixed(0)}%`, strong: true },
                    { label: `Top-${xData.k} overlap (Jaccard)`, value: `${(xData.agreement.mean_jaccard * 100).toFixed(0)}%` },
                    { label: 'Same #1 feature', value: `${(xData.agreement.top1_match_rate * 100).toFixed(0)}%` },
                    { label: `Avg shared / top-${xData.k}`, value: `${xData.agreement.mean_overlap}` },
                  ].map(m => (
                    <div key={m.label}>
                      <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 4 }}>{m.label}</p>
                      <p style={{ fontSize: 20, fontWeight: 700, fontFamily: 'var(--font-mono)',
                        color: m.strong ? 'var(--accent)' : 'var(--text-muted)' }}>{m.value}</p>
                    </div>
                  ))}
                </div>
                <p style={{ fontSize: 10, color: 'var(--text-faint)', marginTop: 12, lineHeight: 1.5 }}>
                  Exact ranking overlap is expected to be low — SHAP and LIME use different mechanisms.
                  The two methods agreeing on <em>direction</em> is the meaningful corroboration.
                </p>
              </div>

              {/* Per-sample table */}
              <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, padding: 20 }}>
                <p style={{ fontSize: 13, fontWeight: 700, marginBottom: 4 }}>
                  Per-sample breakdown ({xData.n_samples} flows)
                </p>
                <p style={{ fontSize: 10, color: 'var(--text-faint)', marginBottom: 14 }}>
                  Overlap = shared features in the top-{xData.k} · Coverage = share of decision in the top-{xData.k} · ✓ = SHAP and LIME agree on the #1 feature
                </p>
                <div style={{ overflowX: 'auto' }}>
                  <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                    <thead>
                      <tr style={{ textAlign: 'left', color: 'var(--text-faint)', fontWeight: 600 }}>
                        {['Prediction', 'Correct', 'P(attack)', 'Top SHAP feature', 'Top LIME feature', 'Overlap', 'Coverage', 'Top-1'].map(h => (
                          <th key={h} style={{ padding: '6px 8px', borderBottom: '1px solid var(--border)' }}>{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {xData.samples.map((s, i) => (
                        <tr key={i} style={{ borderBottom: '1px solid var(--border-subtle)' }}>
                          <td style={{ padding: '6px 8px', fontWeight: 700,
                            color: s.prediction === 'ATTACK' ? 'var(--threat)' : 'var(--safe, #059669)' }}>
                            {s.prediction}
                          </td>
                          <td style={{ padding: '6px 8px' }}>{s.correct ? '✓' : '✗'}</td>
                          <td style={{ padding: '6px 8px', fontFamily: 'var(--font-mono)' }}>{(s.attack_prob * 100).toFixed(1)}%</td>
                          <td style={{ padding: '6px 8px', color: 'var(--text-muted)' }}>{(s.shap_top[0] || '—').trim()}</td>
                          <td style={{ padding: '6px 8px', color: 'var(--text-muted)' }}>{(s.lime_top[0] || '—').trim()}</td>
                          <td style={{ padding: '6px 8px', fontFamily: 'var(--font-mono)' }}>{s.overlap}/{xData.k}</td>
                          <td style={{ padding: '6px 8px', fontFamily: 'var(--font-mono)' }}>{(s.topk_coverage * 100).toFixed(0)}%</td>
                          <td style={{ padding: '6px 8px' }}>{s.top1_match ? '✓' : '·'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  )
}

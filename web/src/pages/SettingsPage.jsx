import { useState } from 'react'
import TopBar from '../components/TopBar'
import { PageHeader, InfoTip } from '../components/ui'
import { useModel } from '../hooks/useModel'
import http from '../api/http'

function StatusDot({ ok, label }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11,
      color: ok ? 'var(--benign)' : 'var(--text-muted)', fontWeight: 600 }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%',
        background: ok ? 'var(--benign)' : 'var(--text-xfaint)' }} />
      {label}
    </span>
  )
}

function InfoRow({ label, value, info }) {
  return (
    <div style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0',
      borderBottom: '1px solid var(--border-subtle)', fontSize: 12 }}>
      <span style={{ color: 'var(--text-muted)' }}>
        {info ? <InfoTip text={info}>{label}</InfoTip> : label}
      </span>
      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--text)' }}>{value}</span>
    </div>
  )
}

export default function SettingsPage() {
  const { models, modelInfo, loading, refresh } = useModel()
  const [selected, setSelected] = useState('')
  const [msg, setMsg]           = useState(null)

  async function loadModel() {
    if (!selected) return
    try {
      await http.post('/model/load', { filename: selected })
      setMsg({ ok: true, text: `Loaded: ${selected}` })
      refresh()
    } catch (e) {
      setMsg({ ok: false, text: e.response?.data?.detail || 'Load failed.' })
    }
  }

  const meta = modelInfo?.metadata || {}

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh' }}>
      <TopBar />
      <div style={{ flex: 1, padding: '32px 40px', overflowY: 'auto', maxWidth: 800, width: '100%', margin: '0 auto' }}>

        <PageHeader
          title="Settings"
          subtitle="Active model overview and model selection."
        />

        {/* Active model card */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
          padding: 24, marginBottom: 24, textAlign: 'left' }}>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
            <div>
              <p className="label" style={{ marginBottom: 4 }}>Active Model</p>
              <p style={{ fontSize: 16, fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
                {modelInfo?.model_file || 'No model loaded'}
              </p>
            </div>
            <StatusDot ok={modelInfo?.loaded} label={modelInfo?.loaded ? 'Loaded' : 'No model'} />
          </div>

          {modelInfo?.loaded && (
            <>
              <InfoRow label="Dataset"
                value={modelInfo.dataset ? `CIC-IDS ${modelInfo.dataset}` : '—'}
                info="Which CIC-IDS dataset this model was trained on." />
              <InfoRow label="Features used"
                value={modelInfo.feature_count || '—'}
                info="Number of network-flow features the model considers per prediction." />
              {meta.accuracy != null && (
                <InfoRow label="Test accuracy"
                  value={`${(meta.accuracy * 100).toFixed(2)}%`}
                  info="Accuracy on the held-out 20% test set when this model was trained." />
              )}
              {meta.precision != null && (
                <InfoRow label="Precision"
                  value={`${(meta.precision * 100).toFixed(2)}%`}
                  info="Of flows flagged as attacks, fraction that actually were." />
              )}
              {meta.recall != null && (
                <InfoRow label="Recall"
                  value={`${(meta.recall * 100).toFixed(2)}%`}
                  info="Of all real attacks, fraction caught by this model." />
              )}
              {meta.f1 != null && (
                <InfoRow label="F1-Score"
                  value={`${(meta.f1 * 100).toFixed(2)}%`}
                  info="Harmonic mean of precision and recall." />
              )}
              {meta.train_samples != null && (
                <InfoRow label="Training samples"
                  value={meta.train_samples.toLocaleString()} />
              )}
              {meta.data_source && <InfoRow label="Training data" value={meta.data_source === 'sample' ? 'Demonstration sample' : 'Full dataset'} />}
              {meta.training_mode && (
                <InfoRow label="Training mode" value={meta.training_mode} />
              )}
              {meta.created_date && (
                <InfoRow label="Trained on"
                  value={new Date(meta.created_date).toLocaleString()}
                  info="When this model was originally trained." />
              )}
              {meta.last_used && (
                <InfoRow label="Last loaded"
                  value={new Date(meta.last_used).toLocaleString()}
                  info="When this model was most recently activated by the API." />
              )}
            </>
          )}

        </div>

        {/* Model loader */}
        <div style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8,
          padding: 24, textAlign: 'left' }}>
          <p className="label" style={{ marginBottom: 4 }}>Switch Model</p>
          <p style={{ fontSize: 11, color: 'var(--text-faint)', marginBottom: 14, lineHeight: 1.6 }}>
            Load a different saved model into the API. The dashboard, classifier, and evaluator
            will use the new model immediately.
          </p>
          {loading ? (
            <p style={{ color: 'var(--text-faint)', fontSize: 12 }}>Loading models…</p>
          ) : Object.keys(models).length === 0 ? (
            <p style={{ color: 'var(--text-faint)', fontSize: 12 }}>
              No models found. Train one from the <a href="/train" style={{ color: 'var(--accent)' }}>Train</a> page.
            </p>
          ) : (
            <div style={{ display: 'flex', gap: 8 }}>
              <select value={selected} onChange={e => setSelected(e.target.value)}
                style={{ flex: 1, padding: '8px 12px', borderRadius: 6, border: '1px solid var(--border)',
                  fontFamily: 'var(--font-mono)', fontSize: 12, background: 'var(--surface)', color: 'var(--text)' }}>
                <option value="">Select model…</option>
                {Object.entries(models).map(([file, m]) => (
                  <option key={file} value={file}>
                    {m.display_name || file}
                    {m.accuracy != null && ` — ${(m.accuracy * 100).toFixed(1)}%`}
                  </option>
                ))}
              </select>
              <button onClick={loadModel} disabled={!selected}
                style={{ padding: '8px 22px', background: selected ? 'var(--accent)' : 'var(--border)',
                  color: '#fff', border: 'none', borderRadius: 6, fontWeight: 700, fontSize: 12,
                  cursor: selected ? 'pointer' : 'default' }}>
                Load
              </button>
            </div>
          )}
          {msg && (
            <p style={{ marginTop: 10, fontSize: 12,
              color: msg.ok ? 'var(--benign)' : 'var(--threat)' }}>{msg.text}</p>
          )}
        </div>
      </div>
    </div>
  )
}

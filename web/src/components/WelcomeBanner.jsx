import { useNavigate } from 'react-router-dom'

const STEPS = [
  {
    id:    'preprocess',
    title: 'Preprocess a dataset',
    desc:  'Load CIC-IDS CSVs and extract the top features. Run from the CLI: cd nids_xai && python main.py → option 1.',
    cta:   null,
  },
  {
    id:    'train',
    title: 'Train a model',
    desc:  'Pick a dataset and training mode, then click Start. Standard mode takes about a minute.',
    cta:   { label: 'Train Now', path: '/train' },
  },
  {
    id:    'classify',
    title: 'Try the classifier',
    desc:  'Upload a CICFlowMeter-format CSV and see per-flow predictions plus SHAP explanations.',
    cta:   { label: 'Classify CSV', path: '/classify' },
  },
  {
    id:    'evaluate',
    title: 'Evaluate the model',
    desc:  'Compute precision, recall, F1, ROC and PR curves on the holdout set or a different dataset.',
    cta:   { label: 'Evaluate', path: '/evaluate' },
  },
  {
    id:    'monitor',
    title: 'Start live monitoring',
    desc:  'Live capture uses network rules; ML classification requires validated flow features.',
    cta:   null,
  },
]

export default function WelcomeBanner({ modelLoaded, hasAlerts }) {
  const nav = useNavigate()

  // Don't show once the user is actively monitoring (alerts present)
  if (hasAlerts) return null

  // Truncated guide once a model is loaded — just nudge toward monitoring
  const showFull = !modelLoaded

  return (
    <div style={{
      background: 'var(--surface)', border: '1px solid var(--border)',
      borderRadius: 12, padding: 24, margin: '16px 24px',
      boxShadow: 'var(--shadow-sm)',
    }}>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 12, marginBottom: 6 }}>
        <h3 style={{ fontSize: 16, fontWeight: 700, color: 'var(--text)', margin: 0 }}>
          {modelLoaded ? 'Ready to monitor' : 'Welcome — let\'s get you started'}
        </h3>
        {modelLoaded && (
          <span style={{ fontSize: 11, color: 'var(--benign)', fontWeight: 600 }}>
            ● Model loaded
          </span>
        )}
      </div>

      <p style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: showFull ? 18 : 8 }}>
        {modelLoaded
          ? 'Play the loaded dataset above to demonstrate detection, or start capture for live rule alerts.'
          : 'NIDS-XAI flags network attacks in real time and explains every alert with SHAP and LIME. To use it, you need a trained model first.'}
      </p>

      {showFull && (
        <ol style={{ paddingLeft: 0, listStyle: 'none', counterReset: 'step', margin: 0 }}>
          {STEPS.map((s, i) => (
            <li key={s.id} style={{
              counterIncrement: 'step',
              display: 'flex', alignItems: 'flex-start', gap: 14,
              padding: '10px 0', borderBottom: i < STEPS.length - 1 ? '1px solid var(--border-subtle)' : 'none',
            }}>
              <span style={{
                flexShrink: 0, width: 22, height: 22, borderRadius: '50%',
                background: 'var(--accent-light)', color: 'var(--accent)',
                fontSize: 11, fontWeight: 700, display: 'flex',
                alignItems: 'center', justifyContent: 'center',
              }}>
                {i + 1}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <p style={{ fontSize: 12, fontWeight: 600, color: 'var(--text)' }}>{s.title}</p>
                <p style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.6, marginTop: 2 }}>{s.desc}</p>
              </div>
              {s.cta && (
                <button onClick={() => nav(s.cta.path)} style={{
                  flexShrink: 0, padding: '5px 14px', fontSize: 11, fontWeight: 700,
                  background: 'var(--accent)', color: '#fff',
                  border: 'none', borderRadius: 6, cursor: 'pointer',
                }}>
                  {s.cta.label}
                </button>
              )}
            </li>
          ))}
        </ol>
      )}
    </div>
  )
}
